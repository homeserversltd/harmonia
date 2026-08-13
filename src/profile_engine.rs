use crate::*;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self};
use std::path::{Path, PathBuf};
use std::time::Instant;

enum LoadedModule {
    Sidecar(ModuleManifest),
    Ladder(LadderManifest),
}

impl LoadedModule {
    fn id(&self) -> &str {
        match self {
            Self::Sidecar(module) => &module.id,
            Self::Ladder(manifest) => &manifest.id,
        }
    }

    fn version(&self) -> Option<&str> {
        match self {
            Self::Sidecar(_) => None,
            Self::Ladder(manifest) => Some(&manifest.version),
        }
    }
}

#[derive(Debug, Clone)]
struct GroupProbeObservation {
    module_id: String,
    ok: bool,
    tool: String,
    permutation: String,
    signal: String,
}

#[derive(Debug, Clone)]
struct GroupSelection {
    group_id: String,
    winner: String,
    losers: Vec<String>,
    observations: Vec<GroupProbeObservation>,
}

const APPLIANCE_CONFIG_PATH: &str = "/etc/appliance/config.json";

#[derive(Default)]
struct DeviceModulePolicy {
    disabled_modules: BTreeSet<String>,
}

fn read_device_module_policy() -> Result<DeviceModulePolicy, String> {
    let path = Path::new(APPLIANCE_CONFIG_PATH);
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(DeviceModulePolicy::default()),
        Err(err) => return Err(format!("appliance-config-read-failed {}: {err}", path.display())),
    };
    let config: serde_json::Value = serde_json::from_str(&text)
        .map_err(|err| format!("appliance-config-parse-failed {}: {err}", path.display()))?;
    let disabled_modules = config
        .get("harmonia")
        .and_then(|harmonia| harmonia.get("disabled_modules"))
        .and_then(serde_json::Value::as_array)
        .map(|modules| {
            modules
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok(DeviceModulePolicy { disabled_modules })
}

pub(crate) fn default_pinned_lock_path(profile: &Profile) -> PathBuf {
    PathBuf::from("/etc/harmonia/locks")
        .join(&profile.id)
        .join("pinned-artifacts.json")
}

pub(crate) fn load_profile(path: &Path) -> io::Result<Profile> {
    let text = fs::read_to_string(path)?;
    let profile: Profile = serde_json::from_str(&text).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("profile-parse-failed {}: {err}", path.display()),
        )
    })?;
    // Profiles evolve independently from the installed engine. Keep parsing
    // backward-compatible; consumers that execute package work require
    // package_authority at that operation boundary.
    if let Some(package_authority) = profile.package_authority.as_ref() {
        package_authority
            .backend()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    }
    Ok(profile)
}

pub(crate) fn load_module(path: &Path) -> Result<ModuleManifest, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("module-read-failed {}: {e}", path.display()))?;
    let raw: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("module-parse-failed {}: {e}", path.display()))?;
    for field in [
        "steps",
        "tool",
        "command",
        "action",
        "actions",
        "args",
        "cwd",
        "apply_only",
    ] {
        if raw.get(field).is_some() {
            return Err(format!(
                "module-sidecar-behavior-field-rejected {} field={}",
                path.display(),
                field
            ));
        }
    }
    serde_json::from_value(raw).map_err(|e| format!("module-parse-failed {}: {e}", path.display()))
}

fn load_profile_module(module_root: &Path, module_id: &str) -> Result<LoadedModule, String> {
    let module_dir = module_root.join(module_id);
    let manifest_path = module_dir.join("manifest.json");
    if manifest_path.exists() && is_ladder_manifest(&manifest_path) {
        return load_ladder_manifest(&manifest_path).map(LoadedModule::Ladder);
    }
    let sidecar_path = module_dir.join("sidecar.json");
    if sidecar_path.exists() {
        return load_module(&sidecar_path).map(LoadedModule::Sidecar);
    }
    load_module(&sidecar_path).map(LoadedModule::Sidecar)
}

fn resolve_group_selections(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    disabled_modules: &BTreeSet<String>,
) -> Result<BTreeMap<String, GroupSelection>, String> {
    let mut groups: BTreeMap<String, Vec<(String, LadderManifest)>> = BTreeMap::new();
    for module_id in &profile.modules {
        if disabled_modules.contains(module_id) {
            continue;
        }
        let module = match load_profile_module(module_root, module_id) {
            Ok(LoadedModule::Ladder(manifest)) => manifest,
            Ok(LoadedModule::Sidecar(_)) | Err(_) => continue,
        };
        let Some(group_id) = module.group.as_ref().map(|group| group.group_id.clone()) else {
            continue;
        };
        if validate_ladder(&module).is_err() {
            continue;
        }
        groups
            .entry(group_id)
            .or_default()
            .push((module_id.clone(), module));
    }

    let mut selections = BTreeMap::new();
    for (group_id, mut members) in groups {
        if members.len() < 2 {
            continue;
        }
        members.sort_by(|(left_id, left), (right_id, right)| {
            left.group
                .as_ref()
                .map(|group| group.group_order)
                .unwrap_or(i64::MAX)
                .cmp(
                    &right
                        .group
                        .as_ref()
                        .map(|group| group.group_order)
                        .unwrap_or(i64::MAX),
                )
                .then_with(|| left_id.cmp(right_id))
        });
        let group_receipt_dir = receipt_dir.join("groups").join(&group_id);
        let mut observations = Vec::new();
        let mut live_winners = Vec::new();
        for (module_id, manifest) in &members {
            let group = manifest.group.as_ref().expect("grouped manifest");
            let probe_dir = group_receipt_dir.join("probes").join(module_id);
            let outcome = execute_group_live_probe(manifest, &probe_dir)?;
            let signal = if outcome.ok {
                "probe-live".to_string()
            } else {
                outcome.message.clone()
            };
            if outcome.ok {
                live_winners.push(module_id.clone());
            }
            observations.push(GroupProbeObservation {
                module_id: module_id.clone(),
                ok: outcome.ok,
                tool: group.live_probe.tool.clone(),
                permutation: group.live_probe.permutation.clone(),
                signal,
            });
        }
        let winner = live_winners
            .first()
            .cloned()
            .unwrap_or_else(|| members[0].0.clone());
        let losers: Vec<String> = members
            .iter()
            .map(|(module_id, _)| module_id.clone())
            .filter(|module_id| module_id != &winner)
            .collect();
        let selection = GroupSelection {
            group_id: group_id.clone(),
            winner: winner.clone(),
            losers: losers.clone(),
            observations,
        };
        write_group_selection_receipt(receipt_dir, &selection)?;
        selections.insert(group_id, selection);
    }
    Ok(selections)
}

fn group_loser_winners(selections: &BTreeMap<String, GroupSelection>) -> BTreeMap<String, String> {
    let mut losers = BTreeMap::new();
    for selection in selections.values() {
        for loser in &selection.losers {
            losers.insert(loser.clone(), selection.winner.clone());
        }
    }
    losers
}

fn caduceus_commands_for_profile(
    profile: &Profile,
    module_root: &Path,
) -> Result<Vec<String>, String> {
    caduceus_commands_for_profile_with_policy(profile, module_root, &BTreeSet::new())
}

fn caduceus_commands_for_profile_with_policy(
    profile: &Profile,
    module_root: &Path,
    disabled_modules: &BTreeSet<String>,
) -> Result<Vec<String>, String> {
    let mut commands = Vec::new();
    for module_id in &profile.modules {
        if disabled_modules.contains(module_id) {
            continue;
        }
        let Ok(LoadedModule::Ladder(module)) = load_profile_module(module_root, module_id) else {
            continue;
        };
        for command in module.caduceus_commands {
            if !commands.contains(&command) {
                commands.push(command);
            }
        }
    }
    Ok(commands)
}

fn compose_caduceus_commands(
    profile: &Profile,
    module_root: &Path,
    manifest: &mut LadderManifest,
) -> Result<(), String> {
    compose_caduceus_commands_with_policy(profile, module_root, manifest, &BTreeSet::new())
}

fn compose_caduceus_commands_with_policy(
    profile: &Profile,
    module_root: &Path,
    manifest: &mut LadderManifest,
    disabled_modules: &BTreeSet<String>,
) -> Result<(), String> {
    let is_caduceus = manifest.ladder.iter().any(|step| {
        step.tool == "service-runtime"
            && step.args.get("component").and_then(|value| value.as_str()) == Some("caduceus")
    });
    if !is_caduceus {
        return Ok(());
    }
    let commands =
        caduceus_commands_for_profile_with_policy(profile, module_root, disabled_modules)?;
    for step in &mut manifest.ladder {
        if step.tool == "service-runtime" && step.permutation == "converge" {
            step.args
                .insert("caduceus_commands".to_string(), json!(commands));
        }
    }
    Ok(())
}

fn write_group_selection_receipt(
    receipt_dir: &Path,
    selection: &GroupSelection,
) -> Result<(), String> {
    fs::create_dir_all(receipt_dir.join("groups")).map_err(|e| e.to_string())?;
    write_json(
        &receipt_dir
            .join("groups")
            .join(format!("{}-selection.json", selection.group_id)),
        &json!({
            "schema": "harmonia.group.selection.v1",
            "group_id": selection.group_id,
            "probes_observed": selection.observations.iter().map(|probe| json!({
                "module_id": probe.module_id,
                "ok": probe.ok,
                "tool": probe.tool,
                "permutation": probe.permutation,
                "signal": probe.signal,
            })).collect::<Vec<_>>(),
            "winner": selection.winner,
            "losers": selection.losers,
        }),
    )
}

pub(crate) fn run_profile_engine(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
) -> Result<(), String> {
    run_profile_engine_with_preflight(
        profile,
        module_root,
        receipt_dir,
        mode,
        false,
        None,
        None,
    )
}

pub(crate) fn run_profile_engine_with_preflight(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
    skip_preflight: bool,
    mut completed_preflight: Option<ModuleExecution>,
    suite_debt: Option<&str>,
) -> Result<(), String> {
    let apply = mode.is_software_apply();
    let invocation = mode.invocation();
    let run_started = Instant::now();
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let mut events = File::create(receipt_dir.join("events.jsonl")).map_err(|e| e.to_string())?;
    event(
        &mut events,
        "engine-start",
        true,
        &format!("profile {}", profile.id),
    )?;
    let run_id = run_id_from_stamp();
    let mut ok = true;
    let mut suite_ok = true;
    let mut changed = false;
    let mut first_missing_signal = "none".to_string();
    let mut module_count = 0usize;
    let mut operation_count = 0usize;
    let device_module_policy = read_device_module_policy()?;

    let harmonia_root = harmonia_root_from_module_root(module_root);

    let mut group_losers = BTreeMap::new();
    let mut final_result = None;
    crate::bands::walk(|band| {
        match band {
            crate::bands::Band::RenewSelf => {
            run_profile_hotfixes(profile, receipt_dir, invocation);

            if let Some(suite_debt) = suite_debt {
                ok = false;
                suite_ok = false;
                first_missing_signal = suite_debt.to_string();
                event(&mut events, "profile-suite-spine-debt", false, suite_debt)?;
            }

            if skip_preflight {
                event(
                    &mut events,
                    "engine-preflight-skipped",
                    true,
                    "already completed by update suite",
                )?;
                if let Some(preflight) = completed_preflight.take() {
                    operation_count += preflight.operation_count;
                    if preflight.changed {
                        changed = true;
                    }
                    if !preflight.ok {
                        let preflight_signal = preflight
                            .first_missing_signal
                            .unwrap_or_else(|| "harmonia-engine-preflight-failed".to_string());
                        event(
                            &mut events,
                            "engine-preflight-honest-staleness",
                            false,
                            &preflight_signal,
                        )?;
                        ok = false;
                        if first_missing_signal == "none" {
                            first_missing_signal = preflight_signal;
                        }
                    }
                }
            } else {
                // Engine-plane self-update is automatic in every profile run. It has its
                // own receipt and never derives from, nor widens, module hard consent.
                let preflight = run_engine_preflight(module_root, receipt_dir, apply, invocation)?;
                operation_count += preflight.operation_count;
                if preflight.changed {
                    changed = true;
                }
                if !preflight.ok {
                    let preflight_signal = preflight
                        .first_missing_signal
                        .unwrap_or_else(|| "harmonia-engine-preflight-failed".to_string());
                    event(
                        &mut events,
                        "engine-preflight-honest-staleness",
                        false,
                        &preflight_signal,
                    )?;
                    if apply {
                        ok = false;
                        first_missing_signal = preflight_signal;
                    }
                }
            }

            if profile.modules.is_empty() {
                ok = false;
                first_missing_signal = "profile-modules-empty".to_string();
                event(
                    &mut events,
                    "profile-modules",
                    false,
                    "profile module spine is empty",
                )?;
            }

            }
            crate::bands::Band::PullSource => {
                // Rolling-update source acquisition already ran in today's prelude.
            }
            crate::bands::Band::StageProfile => {
                // Rolling-update profile materialization already ran in today's prelude.
            }
            crate::bands::Band::Compare => {
            let group_selections = resolve_group_selections(
                profile,
                module_root,
                receipt_dir,
                &device_module_policy.disabled_modules,
            )?;
            group_losers = group_loser_winners(&group_selections);

            }
            crate::bands::Band::InstallPackages => {
                // Today's module executor interleaves package, binary, service,
                // file, and proposal work. Movement A enters it exactly once.
            for module_id in &profile.modules {
                if device_module_policy.disabled_modules.contains(module_id) {
                    module_count += 1;
                    let signal = "module-disabled-by-device";
                    append_profile_ledger_entry(
                        receipt_dir,
                        profile,
                        ProfileLedgerEntry {
                            run_id: &run_id,
                            module_id,
                            ok: true,
                            changed: false,
                            operation_count: 0,
                            first_missing_signal: signal,
                            receipt_dir,
                            module_version: None,
                        },
                    )?;
                    event(
                        &mut events,
                        "module-skipped",
                        true,
                        &format!("{module_id} {signal}"),
                    )?;
                    continue;
                }
                let module = match load_profile_module(module_root, module_id) {
                    Ok(m) => m,
                    Err(err) => {
                        ok = false;
                        if first_missing_signal == "none" {
                            first_missing_signal = format!("module-missing-{module_id}");
                        }
                        event(&mut events, "module-load", false, &err)?;
                        append_profile_ledger_entry(
                            receipt_dir,
                            profile,
                            ProfileLedgerEntry {
                                run_id: &run_id,
                                module_id,
                                ok: false,
                                changed: false,
                                operation_count: 0,
                                first_missing_signal: &format!("module-missing-{module_id}"),
                                receipt_dir,
                                module_version: None,
                            },
                        )?;
                        continue;
                    }
                };
                module_count += 1;
                event(&mut events, "module-start", true, module.id())?;
                if let Some(winner) = group_losers.get(module.id()) {
                    let signal = format!("group-lost-to:{winner}");
                    append_profile_ledger_entry(
                        receipt_dir,
                        profile,
                        ProfileLedgerEntry {
                            run_id: &run_id,
                            module_id: module.id(),
                            ok: true,
                            changed: false,
                            operation_count: 0,
                            first_missing_signal: &signal,
                            receipt_dir,
                            module_version: module.version(),
                        },
                    )?;
                    event(
                        &mut events,
                        "module-skipped",
                        true,
                        &format!("{} {signal}", module.id()),
                    )?;
                    continue;
                }
                let execution_result = match &module {
                    LoadedModule::Sidecar(sidecar) => execute_profile_module(
                        sidecar,
                        module_root,
                        receipt_dir,
                        mode.software_authorization(),
                        &harmonia_root,
                        invocation,
                    ),
                    LoadedModule::Ladder(manifest) => {
                        let module_dir = receipt_dir.join("modules").join(&manifest.id);
                        let mut manifest = manifest.clone();
                        compose_caduceus_commands_with_policy(
                            profile,
                            module_root,
                            &mut manifest,
                            &device_module_policy.disabled_modules,
                        )?;
                        execute_ladder_manifest(
                            &manifest,
                            &module_dir,
                            mode.software_authorization(),
                            profile.package_authority.as_ref(),
                            invocation,
                        )
                    }
                };
                let execution = match execution_result {
                    Ok(execution) => execution,
                    Err(err) => {
                        ok = false;
                        if first_missing_signal == "none" {
                            first_missing_signal = err.clone();
                        }
                        event(&mut events, "module-rejected", false, &err)?;
                        append_profile_ledger_entry(
                            receipt_dir,
                            profile,
                            ProfileLedgerEntry {
                                run_id: &run_id,
                                module_id: module.id(),
                                ok: false,
                                changed: false,
                                operation_count: 0,
                                first_missing_signal: &err,
                                receipt_dir,
                                module_version: module.version(),
                            },
                        )?;
                        continue;
                    }
                };
                operation_count += execution.operation_count;
                if execution.changed {
                    changed = true;
                }
                let module_signal = execution.first_missing_signal.as_deref().unwrap_or("none");
                if !execution.ok {
                    ok = false;
                    if first_missing_signal == "none" {
                        first_missing_signal = execution
                            .first_missing_signal
                            .clone()
                            .unwrap_or_else(|| format!("module-failed-{module_id}"));
                    }
                }
                append_profile_ledger_entry(
                    receipt_dir,
                    profile,
                    ProfileLedgerEntry {
                        run_id: &run_id,
                        module_id: module.id(),
                        ok: execution.ok,
                        changed: execution.changed,
                        operation_count: execution.operation_count,
                        first_missing_signal: module_signal,
                        receipt_dir,
                        module_version: module.version(),
                    },
                )?;
                event(
                    &mut events,
                    "module-complete",
                    execution.ok,
                    &format!("{} operations={}", module.id(), execution.operation_count),
                )?;
            }

            }
            crate::bands::Band::RatchetBinaries => {
                // Fronted by the indivisible module walk above.
            }
            crate::bands::Band::RestartServices => {
                // Fronted by the indivisible module walk above.
            }
            crate::bands::Band::BackfillFiles => {
                // Fronted by the indivisible module walk above.
            }
            crate::bands::Band::ProposeEdits => {
                // Existing hotfix/proposal ordering remains in renew-self.
            }
            crate::bands::Band::ReportHome => {
            write_engine_run_receipt_with_duration(
                receipt_dir,
                profile,
                apply,
                ok,
                changed,
                module_count,
                operation_count,
                &first_missing_signal,
                module_root,
                suite_ok,
                run_started.elapsed().as_millis(),
            )?;
            println!("schema=harmonia.run_profile.v1");
            hyalos::forward_receipt(
                "schema=harmonia.run_profile.v1",
                &format!("schema=harmonia.run_profile.v1 ok={}", ok),
                Some(serde_json::json!({"schema": "harmonia.run_profile.v1", "ok": ok})),
                Some(ok),
            );
            println!("ok={}", ok);
            println!("changed={}", changed);
            println!("profile_id={}", profile.id);
            println!("module_count={}", module_count);
            println!("operation_count={}", operation_count);
            println!("first_missing_signal={}", first_missing_signal);
            println!("receipt_dir={}", receipt_dir.display());
                // A report-only sweep is a census, not a systemd failure: its written
                // aggregate receipt carries all drift/blocker/failure truth. Hard runs
                // return failure only after that receipt has been emitted.
                final_result = Some(if ok || !apply {
                    Ok(())
                } else {
                    Err(first_missing_signal.clone())
                });
            }
        }
        Ok(())
    })?;
    final_result.unwrap_or_else(|| Err("band-walk-report-home-missing".to_string()))
}

const DEFAULT_HARMONIA_SOURCE_REPO: &str = "https://github.com/homeserversltd/harmonia.git";
const DEFAULT_HARMONIA_INSTALL_BIN: &str = "/usr/local/bin/harmonia";

pub(crate) fn ensure_engine_config_for_rolling() -> Result<(), String> {
    let engine_path = engine_config_path();
    if engine_path.exists() {
        return Ok(());
    }
    let ratchet_lock = engine_path
        .parent()
        .map(|parent| parent.join("engine-ratchet-lock.json"))
        .unwrap_or_else(|| PathBuf::from("/etc/harmonia/engine-ratchet-lock.json"));
    write_json_value_atomic(
        &engine_path,
        &json!({
            "source_repo_url": DEFAULT_HARMONIA_SOURCE_REPO,
            "branch": "main",
            "source_dir": SOURCE_ROOT,
            "install_bin": DEFAULT_HARMONIA_INSTALL_BIN,
            "enabled": true,
            "ratchet_lock": ratchet_lock,
        }),
    )
}

pub(crate) fn normalize_engine_branch_upstream() -> Result<(), String> {
    if preserve_existing_lane_or_default(&subscription_path()) != "upstream" {
        return Ok(());
    }
    let engine_path = engine_config_path();
    if !engine_path.exists() {
        return Ok(());
    }
    let text = fs::read_to_string(&engine_path)
        .map_err(|e| format!("engine-config-read-failed {}: {e}", engine_path.display()))?;
    let mut engine: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("engine-config-parse-failed {}: {e}", engine_path.display()))?;
    let object = engine.as_object_mut().ok_or_else(|| {
        format!(
            "engine-config-parse-failed {}: root-not-object",
            engine_path.display()
        )
    })?;
    if object.get("branch").and_then(serde_json::Value::as_str) != Some("main") {
        object.insert("branch".to_string(), json!("main"));
        write_json_value_atomic(&engine_path, &engine)?;
    }
    Ok(())
}

pub(crate) fn sync_profile_from_source(
    source_root: &Path,
    profile_id: &str,
    installed_module_root: &Path,
    receipt_dir: &Path,
    git_bearer: &str,
) -> Result<(), String> {
    let installed_root = installed_module_root
        .parent()
        .ok_or_else(|| format!("{profile_id}-config-root-missing"))?;
    molt(
        source_root,
        profile_id,
        installed_root,
        receipt_dir,
        MoltMode::Copy,
    )?;
    let profile = load_profile(&source_root.join(format!("profiles/{profile_id}/index.json")))
        .map_err(|e| format!("{profile_id}-profile-source-read-failed: {e}"))?;
    let modules = profile
        .modules
        .iter()
        .map(|id| {
            let module_dir = source_root
                .join(format!("profiles/{profile_id}/modules"))
                .join(id);
            Ok(SubscriptionModuleUpdate {
                id: id.clone(),
                version: installed_module_version(&module_dir)
                    .unwrap_or_else(|| "sidecar".to_string()),
                tree_sha256: module_tree_sha256(&module_dir)?,
                received_at_run_id: run_id_from_stamp(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let head = tools::command::capture_with_cwd_as_bearer(
        "git",
        &["rev-parse", "HEAD"],
        source_root.to_str(),
        git_bearer,
    );
    if !head.ok {
        return Err(format!("{profile_id}-source-head-failed {}", head.stderr));
    }
    update_subscription_record(
        &subscription_path(),
        SubscriptionUpdate {
            lane: preserve_existing_lane_or_default(&subscription_path()),
            source: source_root.display().to_string(),
            ref_name: head.stdout.trim().to_string(),
            selected_profile: profile.id,
            engine_version_received: VERSION.to_string(),
            modules,
        },
    )?;
    Ok(())
}

fn rolling_update_run<F>(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
    suite_debt: Option<String>,
    lock_path: PathBuf,
    materialize_receipt: fn(&Path, &str) -> Result<PathBuf, String>,
    try_acquire_lock: fn(&Path) -> Result<ConvergenceLockGuard, ConvergenceLockBusy>,
    prelude: F,
) -> Result<(), String>
where
    F: FnOnce(&Path) -> Result<(), String>,
{
    let apply = mode.is_software_apply();
    let run_id = run_id_from_stamp();
    let effective_receipt_dir = materialize_receipt(receipt_dir, &run_id)?;
    fs::create_dir_all(&effective_receipt_dir).map_err(|e| e.to_string())?;
    let run = || {
        // The engine plane remains independent of update apply; it owns its
        // currentness ratchet and one re-exec guard without widening software
        // authority into configuration or identity.
        let preflight = run_engine_preflight(module_root, &effective_receipt_dir, apply, mode.invocation())?;
        if !apply {
            prelude(&effective_receipt_dir)?;
            return run_profile_engine_with_preflight(
                profile,
                module_root,
                &effective_receipt_dir,
                mode,
                true,
                Some(preflight),
                suite_debt.as_deref(),
            );
        }
        let plan = crate::update_set::derive_plan(profile, module_root, None)?;
        let saved = crate::update_set::snapshot(&plan.targets)?;
        let service_states = crate::update_set::snapshot_services(&plan)?;
        let transaction = (|| -> Result<(), String> {
            prelude(&effective_receipt_dir)?;
            let profile_path = module_root
                .parent()
                .ok_or_else(|| format!("{}-profile-root-missing", profile.id))?
                .join("index.json");
            let refreshed_profile = load_profile(&profile_path).map_err(|e| e.to_string())?;
            run_profile_engine_with_preflight(
                &refreshed_profile,
                module_root,
                &effective_receipt_dir,
                mode,
                true,
                Some(preflight),
                suite_debt.as_deref(),
            )
        })();
        if let Err(error) = transaction {
            let artifact_rollback = crate::update_set::restore(&saved);
            let service_rollback = crate::update_set::restore_services(&service_states);
            let rollback_ok = artifact_rollback.is_ok() && service_rollback.is_ok();
            let verdict = if rollback_ok {
                "failed-rolled-back"
            } else {
                "failed-rollback-incomplete"
            };
            crate::update_set::update_set_receipt(
                &effective_receipt_dir,
                &plan.gui_face,
                verdict,
                Some(&plan.gui_member),
                Some(&error),
            )?;
            return Err(error);
        }
        crate::update_set::update_set_receipt(
            &effective_receipt_dir,
            &plan.gui_face,
            "ok",
            None,
            None,
        )?;
        Ok(())
    };
    if apply {
        match try_acquire_lock(&lock_path) {
            Ok(_guard) => run(),
            Err(ConvergenceLockBusy) => {
                write_convergence_skipped_receipt(
                    &effective_receipt_dir,
                    profile,
                    apply,
                    "lock-held",
                    &lock_path,
                    receipt_dir,
                )?;
                emit_convergence_skipped_stdout(&effective_receipt_dir, "lock-held", &profile.id);
                Ok(())
            }
        }
    } else {
        run()
    }
}

pub(crate) fn rolling_update_from_certificate(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
) -> Result<(), String> {
    let apply_software = mode.is_software_apply();
    rolling_update_run(
        profile,
        module_root,
        receipt_dir,
        mode,
        enforce_update_suite(profile, module_root)?,
        engine_run_lock_path(),
        materialize_tv_receipt_dir,
        try_acquire_homeconsole_update_lock,
        |effective_receipt_dir| {
            if !apply_software {
                return Ok(());
            }
            let engine = load_engine_plane_config(&engine_config_path())?
                .ok_or_else(|| "engine-self-possession-unconfigured".to_string())?;
            sync_profile_from_source(
                &engine.source_dir,
                &profile.id,
                module_root,
                effective_receipt_dir,
                &engine.git_bearer,
            )
        },
    )
}

pub(crate) fn homeconsole_update(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.identity != "homeconsole" {
        return Err(format!(
            "homeconsole-update requires homeconsole/homeconsole profile, got {}/{}",
            profile.id, profile.identity
        ));
    }
    let suite_debt = enforce_update_suite(profile, module_root)?;
    rolling_update_run(
        profile,
        module_root,
        receipt_dir,
        mode,
        suite_debt,
        homeconsole_update_lock_path(),
        materialize_homeconsole_receipt_dir,
        try_acquire_homeconsole_update_lock,
        |effective_receipt_dir| {
            let engine = load_engine_plane_config(&engine_config_path())?
                .ok_or_else(|| "engine-self-possession-unconfigured".to_string())?;
            sync_homeconsole_profile_as_bearer(
                &engine.source_dir,
                module_root,
                effective_receipt_dir,
                &engine.git_bearer,
            )
        },
    )
}

pub(crate) fn homeconsole_module_root() -> std::path::PathBuf {
    Path::new("profiles/homeconsole/modules").to_path_buf()
}

pub(crate) fn lawful_module_manifest_exists(module_dir: &Path) -> bool {
    (module_dir.join("index.rs").exists() && module_dir.join("sidecar.json").exists())
        || module_dir.join("manifest.json").exists()
}

pub(crate) fn enforce_update_suite(
    profile: &Profile,
    module_root: &Path,
) -> Result<Option<String>, String> {
    Ok(profile.modules.iter().find_map(|module_id| {
        (!lawful_module_manifest_exists(&module_root.join(module_id))).then(|| {
            format!(
                "profile-module-manifest-missing module_root={} module_id={module_id}",
                module_root.display(),
            )
        })
    }))
}

pub(crate) fn homeserver_update(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
) -> Result<(), String> {
    if profile.id != "homeserver" || profile.identity != "homeserver" {
        return Err(format!(
            "homeserver-update requires homeserver/homeserver profile, got {}/{}",
            profile.id, profile.identity
        ));
    }
    let suite_debt = enforce_update_suite(profile, module_root)?;
    rolling_update_run(
        profile,
        module_root,
        receipt_dir,
        mode,
        suite_debt,
        homeserver_update_lock_path(),
        materialize_homeserver_receipt_dir,
        try_acquire_homeserver_update_lock,
        |effective_receipt_dir| {
            let engine = load_engine_plane_config(&engine_config_path())?
                .ok_or_else(|| "engine-self-possession-unconfigured".to_string())?;
            sync_homeserver_profile_as_bearer(
                &engine.source_dir,
                module_root,
                effective_receipt_dir,
                &engine.git_bearer,
            )
        },
    )
}

pub(crate) fn tv_update(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
) -> Result<(), String> {
    if profile.id != "tv" || profile.identity != "arch-tv" {
        return Err(format!(
            "tv-update requires tv/arch-tv profile, got {}/{}",
            profile.id, profile.identity
        ));
    }
    let suite_debt = enforce_update_suite(profile, module_root)?;
    rolling_update_run(
        profile,
        module_root,
        receipt_dir,
        mode,
        suite_debt,
        tv_update_lock_path(),
        materialize_tv_receipt_dir,
        try_acquire_tv_update_lock,
        |effective_receipt_dir| {
            let engine = load_engine_plane_config(&engine_config_path())?
                .ok_or_else(|| "engine-self-possession-unconfigured".to_string())?;
            sync_tv_profile_as_bearer(
                &engine.source_dir,
                module_root,
                effective_receipt_dir,
                &engine.git_bearer,
            )
        },
    )
}

pub(crate) fn profile_update(profile: &Profile, module_root: &Path, receipt_dir: &Path, mode: UpdateMode) -> Result<(), String> {
    let suite_debt = enforce_update_suite(profile, module_root)?;
    let profile_id = profile.id.clone();
    rolling_update_run(profile, module_root, receipt_dir, mode, suite_debt, profile_update_lock_path(&profile_id)?, materialize_profile_receipt_dir, try_acquire_homeconsole_update_lock, |effective_receipt_dir| {
        let engine = load_engine_plane_config(&engine_config_path())?.ok_or_else(|| "engine-self-possession-unconfigured".to_string())?;
        sync_profile_from_source(&engine.source_dir, &profile_id, module_root, effective_receipt_dir, &engine.git_bearer)
    })
}

pub(crate) fn normalize_homeserver_engine_branch() -> Result<(), String> {
    normalize_engine_branch_upstream()
}

pub(crate) fn sync_homeserver_profile(
    source_root: &Path,
    installed_module_root: &Path,
    receipt_dir: &Path,
) -> Result<(), String> {
    sync_homeserver_profile_as_bearer(source_root, installed_module_root, receipt_dir, "owner")
}

fn sync_homeserver_profile_as_bearer(
    source_root: &Path,
    installed_module_root: &Path,
    receipt_dir: &Path,
    git_bearer: &str,
) -> Result<(), String> {
    sync_profile_from_source(
        source_root,
        "homeserver",
        installed_module_root,
        receipt_dir,
        git_bearer,
    )
}

pub(crate) fn sync_homeconsole_profile(
    source_root: &Path,
    installed_module_root: &Path,
    receipt_dir: &Path,
) -> Result<(), String> {
    sync_homeconsole_profile_as_bearer(source_root, installed_module_root, receipt_dir, "owner")
}

fn sync_homeconsole_profile_as_bearer(
    source_root: &Path,
    installed_module_root: &Path,
    receipt_dir: &Path,
    git_bearer: &str,
) -> Result<(), String> {
    sync_profile_from_source(
        source_root,
        "homeconsole",
        installed_module_root,
        receipt_dir,
        git_bearer,
    )
}

pub(crate) fn sync_tv_profile(
    source_root: &Path,
    installed_module_root: &Path,
    receipt_dir: &Path,
) -> Result<(), String> {
    sync_tv_profile_as_bearer(source_root, installed_module_root, receipt_dir, "owner")
}

fn sync_tv_profile_as_bearer(
    source_root: &Path,
    installed_module_root: &Path,
    receipt_dir: &Path,
    git_bearer: &str,
) -> Result<(), String> {
    sync_profile_from_source(
        source_root,
        "tv",
        installed_module_root,
        receipt_dir,
        git_bearer,
    )
}

pub(crate) fn homeserver_module_root() -> PathBuf {
    Path::new("profiles/homeserver/modules").to_path_buf()
}

pub(crate) fn tv_module_root() -> PathBuf {
    Path::new("profiles/tv/modules").to_path_buf()
}

pub(crate) fn command_capture(program: &str, args: &[&str]) -> CmdResult {
    tools::command::capture(program, args)
}

#[allow(dead_code)]
pub(crate) fn command_capture_with_timeout(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
) -> CmdResult {
    tools::command::capture_with_timeout(program, args, timeout_secs)
}

pub(crate) fn command_capture_with_cwd(
    program: &str,
    args: &[&str],
    cwd: Option<&str>,
) -> CmdResult {
    tools::command::capture_with_cwd(program, args, cwd)
}

pub(crate) fn harmonia_root_from_module_root(module_root: &Path) -> PathBuf {
    module_root
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod profile_authority_tests {
    use super::*;

    #[test]
    fn homeserver_caduceus_runtime_composes_firewall_commands_exactly_once() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile = load_profile(&root.join("profiles/homeserver/index.json")).unwrap();
        let module_root = root.join("profiles/homeserver/modules");
        let existing = caduceus_commands_for_profile(&profile, &module_root).unwrap();
        let mut caduceus =
            load_ladder_manifest(&module_root.join("caduceus/manifest.json")).unwrap();

        compose_caduceus_commands(&profile, &module_root, &mut caduceus).unwrap();

        let runtime = caduceus
            .ladder
            .iter()
            .find(|step| step.tool == "service-runtime" && step.permutation == "converge")
            .expect("homeserver caduceus service-runtime step");
        let commands = runtime.args["caduceus_commands"]
            .as_array()
            .expect("composed caduceus commands array");
        for command in [
            "caduceus.network.firewall.read",
            "caduceus.network.firewall.put",
            "caduceus.network.firewall.delete",
        ] {
            assert_eq!(
                commands
                    .iter()
                    .filter(|value| value.as_str() == Some(command))
                    .count(),
                1,
                "{command} must appear exactly once in service-runtime args"
            );
        }
        for command in existing {
            assert_eq!(
                commands
                    .iter()
                    .filter(|value| value.as_str() == Some(command.as_str()))
                    .count(),
                1,
                "existing composed command {command} must remain exactly once"
            );
        }
    }

    #[test]
    fn module_root_yields_absolute_installed_harmonia_root() {
        assert_eq!(
            harmonia_root_from_module_root(Path::new("/etc/harmonia/profiles/tv/modules")),
            PathBuf::from("/etc/harmonia")
        );
    }

    #[test]
    fn module_root_yields_relative_repo_harmonia_root() {
        assert_eq!(
            harmonia_root_from_module_root(Path::new("profiles/tv/modules")),
            PathBuf::from("")
        );
    }

    #[test]
    fn command_timeout_kills_sleeping_child() {
        let result = command_capture_with_timeout("/usr/bin/sh", &["-c", "sleep 2"], 1);
        assert!(!result.ok);
        assert!(
            result.stderr.contains("command-timeout-after-1s"),
            "{}",
            result.stderr
        );
        assert!(
            result.stderr.contains("/usr/bin/sh -c sleep 2"),
            "{}",
            result.stderr
        );
    }
}
