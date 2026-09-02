use super::Band;
use crate::tools::ladder::{LadderManifest, ProjectedRoutineChild, ValidatedStep};
use crate::tools::routine::execute_validated_step;
use crate::ModuleExecution;
use crate::{validate_group, OperationOutcome};
use crate::{
    LoadedModule, PackageAuthority, Profile, ProfileProjection, SoftwareApplyAuthorization,
    UpdateMode,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::path::Path;

pub(crate) fn execute_command_precondition(step: &ValidatedStep, precondition: &crate::tools::ladder::CommandPrecondition, manifest: &LadderManifest, module_dir: &Path) -> Result<OperationOutcome, String> {
    let argv: Vec<&str> = precondition.args.iter().map(String::as_str).collect();
    let result = crate::tools::command::capture_with_options(&precondition.program, &argv, crate::tools::command::CaptureOptions::new().cwd(precondition.cwd.as_deref()).timeout_secs(precondition.timeout_secs.unwrap_or(crate::tools::command::DEFAULT_TIMEOUT_SECS)));
    crate::write_json(&module_dir.join(format!("{}-precondition.json", step.step_id)), &serde_json::json!({"schema":"harmonia.command_precondition.v1","module":manifest.id,"step_id":step.step_id,"state":if result.ok {"satisfied"} else {"blocked"},"program":precondition.program,"args":precondition.args,"cwd":precondition.cwd,"timeout_secs":precondition.timeout_secs.unwrap_or(crate::tools::command::DEFAULT_TIMEOUT_SECS),"raw_command_ran":false,"probe":result,"probe_error":if result.ok {"none".to_string()} else {format!("exit_code={} stderr={}",result.code,result.stderr)},"first_missing_signal":if result.ok {"none"} else {"command-precondition-blocked"}}))?;
    Ok(OperationOutcome { ok:result.ok, changed:false, skipped:false, message:format!("command precondition {}",precondition.program), command:Some(result) })
}

pub(crate) fn enter(enter: &mut impl FnMut(Band) -> Result<(), String>) -> Result<(), String> {
    enter(Band::Compare)
}

// owner api

/// Execute the complete Compare band lifecycle for one projected module.
/// Selection, preconditions, authority gating, failure policy, and accumulation
/// intentionally live here rather than in the ladder compatibility executor.
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_manifest_band(
    manifest: &LadderManifest,
    module_dir: &Path,
    auth: Option<&SoftwareApplyAuthorization>,
    pa: Option<&PackageAuthority>,
    key: Option<&crate::tools::files::InvocationKey>,
    mode_apply: bool,
    routine_states: &mut BTreeMap<String, crate::ModuleWalkState>,
    projected_steps: &[ValidatedStep],
    projected_routines: &BTreeMap<String, Vec<ProjectedRoutineChild>>,
) -> Result<ModuleExecution, String> {
    crate::atoms::attest::prepare_receipt_parent(module_dir)?;
    let mut result = ModuleExecution {
        ok: true,
        changed: false,
        operation_count: 0,
        first_missing_signal: None,
        placements: Vec::new(),
    };
    for step in projected_steps {
        if step.tool == "routine" {
            let children = projected_routines
                .get(&step.step_id)
                .ok_or_else(|| "routine-step-missing".to_string())?;
            if !children
                .iter()
                .any(|child| child.band == crate::bands::Band::Compare)
            {
                continue;
            }
        } else if crate::tools::routine::placement_for_step(step)? != crate::bands::Band::Compare {
            continue;
        }
        if let Some(precondition) = if step.tool == "routine" {
            None
        } else {
            crate::tools::routine::command_precondition(&step.args)?
        } {
            result.operation_count += 1;
            let probe = crate::bands::compare::execute_command_precondition(
                step,
                &precondition,
                manifest,
                module_dir,
            )?;
            if !probe.ok {
                result.ok = false;
                let detail = probe
                    .command
                    .as_ref()
                    .map(|r| format!("exit_code={} stderr={}", r.code, r.stderr))
                    .unwrap_or_else(|| probe.message.clone());
                let signal = format!(
                    "step_id={} state=blocked probe_error={detail}",
                    step.step_id
                );
                result.first_missing_signal.get_or_insert(signal);
                result.placements.push(serde_json::json!({"step_id":step.step_id,"tool":step.tool,"permutation":step.permutation,"band":"Compare","status":"blocked","module":manifest.id}));
                break;
            }
        }
        result.operation_count += 1;
        let outcome = if step.tool == "routine" {
            crate::tools::routine::execute_routine(
                step,
                manifest,
                module_dir,
                auth,
                pa,
                mode_apply,
                key,
                Some(routine_states),
                crate::bands::Band::Compare,
                projected_routines
                    .get(&step.step_id)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            )?
        } else {
            crate::tools::routine::execute_validated_step(
                step, manifest, module_dir, auth, pa, false, key, None,
            )?
        };
        if step.tool == "routine" {
            let routine = routine_states
                .get(&step.step_id)
                .ok_or_else(|| "routine-state-missing".to_string())?;
            for child in projected_routines
                .get(&step.step_id)
                .map(Vec::as_slice)
                .unwrap_or(&[])
            {
                if child.band != crate::bands::Band::Compare {
                    continue;
                }
                let receipt = routine
                    .children
                    .iter()
                    .find(|r| r.get("name").and_then(Value::as_str) == Some(child.name.as_str()))
                    .ok_or_else(|| format!("routine-child-receipt-missing-{}", child.name))?;
                result.placements.push(serde_json::json!({"step_id":child.name,"tool":child.tool,"permutation":child.permutation,"band":"Compare","status":receipt.get("state").and_then(Value::as_str).unwrap_or("failed"),"ok":receipt.get("ok").and_then(Value::as_bool).unwrap_or(false),"changed":receipt.get("changed").and_then(Value::as_bool).unwrap_or(false),"module":manifest.id,"routine":step.step_id}));
            }
        } else {
            result.placements.push(serde_json::json!({"step_id":step.step_id,"tool":step.tool,"permutation":step.permutation,"band":"Compare","status":if outcome.ok {"completed"} else {"failed"},"module":manifest.id}));
        }
        result.changed |= outcome.changed;
        if !outcome.ok {
            result.ok = false;
            result.first_missing_signal.get_or_insert_with(|| {
                format!("step_id={} defect={}", step.step_id, outcome.message)
            });
            if step.on_failure == crate::tools::ladder::OnFailure::Stop {
                break;
            }
        }
    }
    Ok(result)
}

use crate::receipts::event;
pub(crate) fn execute_manifest_modules(
    profile: &Profile,
    receipt_dir: &Path,
    mode: &UpdateMode,
    mode_apply: bool,
    disabled_modules: &BTreeSet<String>,
    projection: &ProfileProjection,
    states: &mut BTreeMap<String, ModuleExecution>,
    routines: &mut BTreeMap<String, BTreeMap<String, crate::ModuleWalkState>>,
    halted: &mut BTreeSet<String>,
    module_count: &mut usize,
    operation_count: &mut usize,
    changed: &mut bool,
    ok: &mut bool,
    first_missing_signal: &mut String,
    events: &mut File,
) -> Result<(), String> {
    let beam = beam_receipt(None, crate::atoms::ask::beam::DEFAULT_DOOR_URL)?;
    let beam_value = serde_json::to_value(&beam)
        .map_err(|error| format!("beam-receipt-serialize-failed: {error}"))?;
    crate::write_json(&receipt_dir.join("beam.json"), &beam_value)?;
    if matches!(beam.first_missing_signal, "beam-lock-malformed" | "beam-door-malformed") {
        *ok = false;
        if *first_missing_signal == "none" {
            *first_missing_signal = beam.first_missing_signal.to_string();
        }
        for module_id in &profile.modules {
            halted.insert(module_id.clone());
            let state = states.entry(module_id.clone()).or_insert(ModuleExecution {
                ok: false,
                changed: false,
                operation_count: 0,
                first_missing_signal: Some(beam.first_missing_signal.to_string()),
                placements: Vec::new(),
            });
            state.ok = false;
            state
                .first_missing_signal
                .get_or_insert_with(|| beam.first_missing_signal.to_string());
        }
        return Ok(());
    }
    if !matches!(
        beam.first_missing_signal,
        "none" | "beam-door-unreachable" | "beam-lock-absent"
    ) {
        *ok = false;
        if *first_missing_signal == "none" {
            *first_missing_signal = beam.first_missing_signal.to_string();
        }
    }
    for module_id in &profile.modules {
        if disabled_modules.contains(module_id) || halted.contains(module_id) {
            continue;
        }
        let Some(projected) = projection.modules.get(module_id) else {
            let err = projection
                .errors
                .get(module_id)
                .cloned()
                .unwrap_or_else(|| format!("module-not-in-projection-{module_id}"));
            let state = states.entry(module_id.clone()).or_insert(ModuleExecution {
                ok: true,
                changed: false,
                operation_count: 0,
                first_missing_signal: None,
                placements: Vec::new(),
            });
            state.ok = false;
            state.first_missing_signal.get_or_insert(err.clone());
            halted.insert(module_id.clone());
            *ok = false;
            if *first_missing_signal == "none" {
                *first_missing_signal = err.clone();
            }
            event(events, "module-rejected", false, &err)?;
            continue;
        };
        *module_count = profile.modules.len();
        let result = match &projected.loaded {
            LoadedModule::Ladder(manifest) => execute_manifest_band(
                manifest,
                &receipt_dir.join("modules").join(module_id),
                mode.software_authorization(),
                profile.package_authority.as_ref(),
                mode.invocation(),
                mode_apply,
                routines.entry(module_id.clone()).or_default(),
                &projected.steps,
                &projected.routines,
            ),
            LoadedModule::Sidecar(_) => Err("module-sidecar-not-band-executable".to_string()),
        };
        let state = states.entry(module_id.clone()).or_insert(ModuleExecution {
            ok: true,
            changed: false,
            operation_count: 0,
            first_missing_signal: None,
            placements: Vec::new(),
        });
        match result {
            Ok(part) => {
                state.operation_count += part.operation_count;
                state.changed |= part.changed;
                state.placements.extend(part.placements);
                *operation_count += part.operation_count;
                *changed |= part.changed;
                if !part.ok {
                    state.ok = false;
                    state.first_missing_signal = state
                        .first_missing_signal
                        .take()
                        .or(part.first_missing_signal);
                    *ok = false;
                    halted.insert(module_id.clone());
                    if *first_missing_signal == "none" {
                        *first_missing_signal = state
                            .first_missing_signal
                            .clone()
                            .unwrap_or_else(|| format!("module-failed-{module_id}"));
                    }
                }
                event(
                    events,
                    "module-band",
                    part.ok,
                    &format!("{} band=Compare steps={}", module_id, part.operation_count),
                )?;
            }
            Err(err) => {
                state.ok = false;
                state.first_missing_signal.get_or_insert(err.clone());
                halted.insert(module_id.clone());
                *ok = false;
                if *first_missing_signal == "none" {
                    *first_missing_signal = err.clone();
                }
                event(events, "module-rejected", false, &err)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn execute_group_live_probe_validated(
    manifest: &LadderManifest,
    step: &ValidatedStep,
    receipt_dir: &Path,
) -> Result<OperationOutcome, String> {
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
    execute_validated_step(step, manifest, receipt_dir, None, None, false, None, None)
}
pub(crate) fn execute_group_live_probe(
    manifest: &LadderManifest,
    receipt_dir: &Path,
) -> Result<OperationOutcome, String> {
    let Some(group) = &manifest.group else {
        return Err(format!("module-{}-has-no-group", manifest.id));
    };
    let step = validate_group(group, &manifest.constants)
        .map_err(|err| format!("module-invalid {}", err.first_missing_signal()))?;
    execute_group_live_probe_validated(manifest, &step, receipt_dir)
}


// Arcadia fast-check ownership: preserve the legacy CLI surface while keeping
// source comparison and SHA probes in the Compare band.
use serde_json::json;
use std::time::Instant;
use crate::{CmdResult, hyalos};
use crate::{write_command_receipt, write_json};


pub(crate) fn homeconsole_arcadia_check(
    profile: &Profile,
    receipt_dir: &Path,
    repo: &str,
    branch: &str,
    current_sha_file: &Path,
    upstream_sha_file: Option<&Path>,
    insecure_tls: bool,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.identity != "homeconsole" {
        return Err(format!(
            "homeconsole-arcadia-check requires homeconsole/homeconsole profile, got {}/{}",
            profile.id, profile.identity
        ));
    }
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
    let started = Instant::now();
    let current_sha = fs::read_to_string(current_sha_file)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let refspec = format!("refs/heads/{branch}");
    let file_upstream = upstream_sha_file
        .and_then(|path| fs::read_to_string(path).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| is_hex_sha(s));
    let remote = if file_upstream.is_some() {
        CmdResult {
            ok: true,
            code: 0,
            stdout: file_upstream.clone().unwrap_or_default(),
            stderr: String::new(),
        }
    } else {
        git_ls_remote(repo, &refspec, insecure_tls)
    };
    let upstream_sha = if let Some(sha) = file_upstream {
        Some(sha)
    } else {
        remote
            .stdout
            .split_whitespace()
            .next()
            .map(|s| s.to_string())
            .filter(|s| is_hex_sha(s))
    };
    let ok = remote.ok && upstream_sha.is_some() && current_sha.is_some();
    let first_missing_signal = if !remote.ok {
        "upstream-sha-unreadable"
    } else if upstream_sha.is_none() {
        "upstream-sha-missing"
    } else if current_sha.is_none() {
        "current-sha-missing"
    } else {
        "none"
    };
    let update_available = match (&current_sha, &upstream_sha) {
        (Some(current), Some(upstream)) => current != upstream,
        _ => false,
    };
    let elapsed_ms = started.elapsed().as_millis();
    write_command_receipt(receipt_dir, "arcadia-upstream-sha", &remote)?;
    write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema": "harmonia.arcadia_fast_check.v1",
            "ok": ok,
            "mutation": false,
            "profile_id": profile.id,
            "profile_family": profile.identity,
            "repo": repo,
            "branch": branch,
            "current_sha_file": current_sha_file,
            "current_sha": current_sha,
            "upstream_sha": upstream_sha,
            "update_available": update_available,
            "first_missing_signal": first_missing_signal,
            "elapsed_ms": elapsed_ms,
        }),
    )?;
    println!("schema=harmonia.arcadia_fast_check.v1");
    hyalos::forward_receipt(
        "schema=harmonia.arcadia_fast_check.v1",
        &format!("schema=harmonia.arcadia_fast_check.v1 ok={}", ok),
        Some(serde_json::json!({"schema": "harmonia.arcadia_fast_check.v1", "ok": ok})),
        Some(ok),
    );
    println!("ok={}", ok);
    println!("update_available={}", update_available);
    println!(
        "current_sha={}",
        current_sha.as_deref().unwrap_or("unknown")
    );
    println!(
        "upstream_sha={}",
        upstream_sha.as_deref().unwrap_or("unknown")
    );
    println!("first_missing_signal={}", first_missing_signal);
    println!("elapsed_ms={}", elapsed_ms);
    println!("receipt_dir={}", receipt_dir.display());
    if ok {
        Ok(())
    } else {
        Err(first_missing_signal.to_string())
    }
}

pub(crate) fn git_ls_remote(repo: &str, refspec: &str, insecure_tls: bool) -> CmdResult {
    crate::tools::git_artifact::ls_remote(repo, refspec, insecure_tls)
}

pub(crate) fn is_hex_sha(s: &str) -> bool {
    s.len() >= 7 && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct BeamLockProjection {
    pub caduceus_sha: String,
    pub env_sha: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct BeamDoorProjection {
    pub caduceus_sha: String,
    pub env_sha: String,
    pub profile: String,
    pub gui_face: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct BeamCompareReceipt {
    pub schema: &'static str,
    pub state: &'static str,
    pub converged: bool,
    pub lock: Option<BeamLockProjection>,
    pub door: Option<BeamDoorProjection>,
    pub first_divergent_member: Option<&'static str>,
    pub first_missing_signal: &'static str,
}

pub(crate) fn compare_beam(
    lock: Option<crate::atoms::ask::beam::BeamLock>,
    door: Result<crate::atoms::ask::beam::BeamDoor, String>,
) -> BeamCompareReceipt {
    let Some(lock) = lock else {
        return BeamCompareReceipt {
            schema: "harmonia.beam-compare.v1",
            state: "pre-declaration",
            converged: false,
            lock: None,
            door: None,
            first_divergent_member: None,
            first_missing_signal: "beam-lock-absent",
        };
    };
    let lock_projection = BeamLockProjection {
        caduceus_sha: lock.caduceus_sha.clone(),
        env_sha: lock.env_sha.clone(),
    };
    let door = match door {
        Ok(door) => door,
        Err(signal) => {
            return BeamCompareReceipt {
                schema: "harmonia.beam-compare.v1",
                state: "divergent",
                converged: false,
                lock: Some(lock_projection),
                door: None,
                first_divergent_member: None,
                first_missing_signal: if signal == "beam-door-unreachable" {
                    "beam-door-unreachable"
                } else {
                    "beam-door-malformed"
                },
            };
        }
    };
    let member = if lock.caduceus_sha != door.caduceus_sha {
        Some("caduceus_sha")
    } else if lock.env_sha != door.env_sha {
        Some("env_sha")
    } else {
        None
    };
    let door_projection = BeamDoorProjection {
        caduceus_sha: door.caduceus_sha,
        env_sha: door.env_sha,
        profile: door.profile,
        gui_face: door.gui_face,
    };
    BeamCompareReceipt {
        schema: "harmonia.beam-compare.v1",
        state: if member.is_some() { "divergent" } else { "aligned" },
        converged: member.is_none(),
        lock: Some(lock_projection),
        door: Some(door_projection),
        first_divergent_member: member,
        first_missing_signal: if member == Some("caduceus_sha") {
            "beam-divergent-caduceus_sha"
        } else if member == Some("env_sha") {
            "beam-divergent-env_sha"
        } else {
            "none"
        },
    }
}

pub(crate) fn beam_receipt(
    lock_path: Option<&Path>,
    door_url: &str,
) -> Result<BeamCompareReceipt, String> {
    let lock = match lock_path {
        Some(path) => match crate::atoms::ask::beam::read_lock_path(path) {
            Ok(lock) => lock,
            Err(_) => {
                return Ok(BeamCompareReceipt {
                    schema: "harmonia.beam-compare.v1",
                    state: "divergent",
                    converged: false,
                    lock: None,
                    door: None,
                    first_divergent_member: None,
                    first_missing_signal: "beam-lock-malformed",
                });
            }
        },
        None => match crate::atoms::ask::beam::read_embedded_lock() {
            Ok(lock) => Some(lock),
            Err(_) => {
                return Ok(BeamCompareReceipt {
                    schema: "harmonia.beam-compare.v1",
                    state: "divergent",
                    converged: false,
                    lock: None,
                    door: None,
                    first_divergent_member: None,
                    first_missing_signal: "beam-lock-malformed",
                });
            }
        },
    };
    Ok(compare_beam(lock, crate::atoms::ask::beam::fetch_door(door_url)))
}

#[cfg(test)]
mod beam_tests {
    use super::*;

    fn lock() -> crate::atoms::ask::beam::BeamLock {
        crate::atoms::ask::beam::BeamLock {
            schema: "harmonia.beam-lock.v1".into(),
            caduceus_sha: "a".repeat(40),
            env_sha: "b".repeat(64),
            minted_from: crate::atoms::ask::beam::MintedFrom {
                harmonia_sha: "c".repeat(40),
                caduceus_release_tag: "d".repeat(40),
            },
        }
    }

    fn door() -> crate::atoms::ask::beam::BeamDoor {
        crate::atoms::ask::beam::BeamDoor {
            schema: "caduceus.beam.v1".into(),
            ok: true,
            service: "caduceus".into(),
            caduceus_sha: "a".repeat(40),
            env_sha: "b".repeat(64),
            profile: "p".into(),
            gui_face: Some("g".into()),
            syzygy_sha: None,
        }
    }

    #[test]
    fn aligned_state() {
        let receipt = compare_beam(Some(lock()), Ok(door()));
        assert_eq!(receipt.state, "aligned");
        assert_eq!(receipt.first_missing_signal, "none");
    }

    #[test]
    fn divergent_state() {
        let mut beam_door = door();
        beam_door.env_sha = "e".repeat(64);
        let receipt = compare_beam(Some(lock()), Ok(beam_door));
        assert_eq!(receipt.first_divergent_member, Some("env_sha"));
        assert_eq!(receipt.first_missing_signal, "beam-divergent-env_sha");
    }

    #[test]
    fn unreachable_door_is_divergent_without_member() {
        let receipt = compare_beam(Some(lock()), Err("beam-door-unreachable".into()));
        assert_eq!(receipt.state, "divergent");
        assert_eq!(receipt.first_divergent_member, None);
        assert_eq!(receipt.first_missing_signal, "beam-door-unreachable");
    }

    #[test]
    fn pre_declaration_state() {
        let receipt = compare_beam(None, Err("beam-door-unreachable".into()));
        assert_eq!(receipt.state, "pre-declaration");
        assert_eq!(receipt.first_missing_signal, "beam-lock-absent");
    }

    #[test]
    fn exact_caduceus_beam_json_is_aligned() {
        let raw = r#"{"schema":"caduceus.beam.v1","ok":true,"service":"caduceus","profile":"homeserver","caduceus_sha":"1ddb41af4f123db22ce8cc6037d24a79d582f84c","env_sha":"e8dd9084adebbde87f73f2d57c9551ab31ce9e1ee6b3492a7a23f190d64cfc3c","gui_face":"Coronatio","syzygy_sha":null}"#;
        let door = crate::atoms::ask::beam::parse_door(raw).unwrap();
        let lock = crate::atoms::ask::beam::BeamLock { schema: "harmonia.beam-lock.v1".into(), caduceus_sha: "1ddb41af4f123db22ce8cc6037d24a79d582f84c".into(), env_sha: "e8dd9084adebbde87f73f2d57c9551ab31ce9e1ee6b3492a7a23f190d64cfc3c".into(), minted_from: crate::atoms::ask::beam::MintedFrom { harmonia_sha: "c".repeat(40), caduceus_release_tag: "d".repeat(40) } };
        let receipt = compare_beam(Some(lock), Ok(door));
        assert_eq!(receipt.state, "aligned");
        assert!(receipt.converged);
        assert_eq!(receipt.first_missing_signal, "none");
    }

    #[test]
    fn projections_have_exact_serialized_keys() {
        let lock_keys = serde_json::to_value(BeamLockProjection {
            caduceus_sha: "a".into(),
            env_sha: "b".into(),
        })
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
        assert_eq!(lock_keys, vec!["caduceus_sha", "env_sha"]);

        let door_keys = serde_json::to_value(BeamDoorProjection {
            caduceus_sha: "a".into(),
            env_sha: "b".into(),
            profile: "p".into(),
            gui_face: Some("g".into()),
        })
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
        assert_eq!(
            door_keys,
            vec!["caduceus_sha", "env_sha", "gui_face", "profile"]
        );
    }
}
