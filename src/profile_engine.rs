use crate::*;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self};
use std::path::{Path, PathBuf};

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

pub(crate) fn default_pinned_lock_path(profile: &Profile) -> PathBuf {
    PathBuf::from("/etc/harmonia/locks")
        .join(&profile.id)
        .join("pinned-artifacts.json")
}

pub(crate) fn load_profile(path: &Path) -> io::Result<Profile> {
    let text = fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("profile-parse-failed {}: {err}", path.display()),
        )
    })
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
) -> Result<BTreeMap<String, GroupSelection>, String> {
    let mut groups: BTreeMap<String, Vec<(String, LadderManifest)>> = BTreeMap::new();
    for module_id in &profile.modules {
        let module = match load_profile_module(module_root, module_id) {
            Ok(LoadedModule::Ladder(manifest)) => manifest,
            Ok(LoadedModule::Sidecar(_)) | Err(_) => continue,
        };
        validate_ladder(&module)
            .map_err(|err| format!("module-invalid {}", err.first_missing_signal()))?;
        if let Some(group) = &module.group {
            groups
                .entry(group.group_id.clone())
                .or_default()
                .push((module_id.clone(), module));
        }
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

pub(crate) fn profile_module_failure_is_terminal(module_id: &str) -> bool {
    module_id == "harmonia-runtime"
}

pub(crate) fn run_profile_engine(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    apply: bool,
) -> Result<(), String> {
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
    let mut changed = false;
    let mut first_missing_signal = "none".to_string();
    let mut module_count = 0usize;
    let mut operation_count = 0usize;

    let harmonia_root = harmonia_root_from_module_root(module_root);

    let preflight = run_engine_preflight(module_root, receipt_dir, apply)?;
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

    let group_selections = resolve_group_selections(profile, module_root, receipt_dir)?;
    let group_losers = group_loser_winners(&group_selections);

    for module_id in &profile.modules {
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
                if profile_module_failure_is_terminal(module_id) {
                    event(&mut events, "module-terminal-stop", false, module_id)?;
                    break;
                }
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
            LoadedModule::Sidecar(sidecar) => {
                execute_profile_module(sidecar, module_root, receipt_dir, apply, &harmonia_root)
            }
            LoadedModule::Ladder(manifest) => {
                validate_ladder(manifest)
                    .map_err(|err| format!("module-invalid {}", err.first_missing_signal()))?;
                let module_dir = receipt_dir.join("modules").join(&manifest.id);
                execute_ladder_manifest(manifest, &module_dir, apply)
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
                if profile_module_failure_is_terminal(module.id()) {
                    event(&mut events, "module-terminal-stop", false, module.id())?;
                    break;
                }
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
        if !execution.ok && profile_module_failure_is_terminal(module.id()) {
            event(&mut events, "module-terminal-stop", false, module.id())?;
            break;
        }
    }

    write_engine_run_receipt(
        receipt_dir,
        profile,
        apply,
        ok,
        changed,
        module_count,
        operation_count,
        &first_missing_signal,
        module_root,
    )?;
    println!("schema=harmonia.run_profile.v1");
    println!("ok={}", ok);
    println!("changed={}", changed);
    println!("profile_id={}", profile.id);
    println!("module_count={}", module_count);
    println!("operation_count={}", operation_count);
    println!("first_missing_signal={}", first_missing_signal);
    println!("receipt_dir={}", receipt_dir.display());
    if ok {
        Ok(())
    } else {
        Err(first_missing_signal)
    }
}

pub(crate) fn homeconsole_update(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    apply: bool,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.identity != "homeconsole" {
        return Err(format!(
            "homeconsole-update requires homeconsole/homeconsole profile, got {}/{}",
            profile.id, profile.identity
        ));
    }
    enforce_homeconsole_update_suite(profile, module_root)?;
    let run_id = run_id_from_stamp();
    let effective_receipt_dir = materialize_homeconsole_receipt_dir(receipt_dir, &run_id)?;
    fs::create_dir_all(&effective_receipt_dir).map_err(|e| e.to_string())?;
    if apply {
        let lock_path = homeconsole_update_lock_path();
        match try_acquire_homeconsole_update_lock(&lock_path) {
            Ok(_guard) => run_profile_engine(profile, module_root, &effective_receipt_dir, apply),
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
        run_profile_engine(profile, module_root, &effective_receipt_dir, apply)
    }
}

pub(crate) fn homeconsole_module_root() -> std::path::PathBuf {
    Path::new("profiles/homeconsole/modules").to_path_buf()
}

pub(crate) fn lawful_module_manifest_exists(module_dir: &Path) -> bool {
    (module_dir.join("index.rs").exists() && module_dir.join("sidecar.json").exists())
        || module_dir.join("manifest.json").exists()
}

pub(crate) fn module_ids_from_profile_modules(module_root: &Path) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    for module_id in [
        "identity",
        "arch-keyring-maintenance",
        "system-packages",
        "keyman-runtime",
        "homeconsole-sync-runtime",
        "rust-build-toolchain",
        "arcadia-gui-runtime",
        "local-ai-runtime",
        "pinned-artifacts-runtime",
        "homeconsole-update-runtime",
        "homeconsole-caduceus-public-lever",
    ] {
        let module_dir = module_root.join(module_id);
        if lawful_module_manifest_exists(&module_dir) {
            found.push(module_id.to_string());
        }
    }
    Ok(found)
}

pub(crate) fn enforce_homeconsole_update_suite(
    profile: &Profile,
    module_root: &Path,
) -> Result<(), String> {
    let expected = module_ids_from_profile_modules(module_root)?;
    if profile.modules == expected {
        Ok(())
    } else {
        Err(format!(
            "homeconsole-update-suite-spine-mismatch module_root={} expected={} got={}",
            module_root.display(),
            expected.join(","),
            profile.modules.join(",")
        ))
    }
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
