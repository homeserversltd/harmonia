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
    projection: &mut ProfileProjection,
    carrier: Option<&crate::atoms::r#do::transaction::RunCarrierRef>,
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
    let mut beam = beam_receipt(None, crate::atoms::ask::beam::DEFAULT_DOOR_URL)?;
    // Developer mode is never inferred from engine configuration. Source
    // policy and locators come only from the profile certificate.
    let developer_mode = false;
    let beam_authorization = authorize_beam(&mut beam, mode_apply, developer_mode);
    if let Some(authorization) = beam_authorization.as_ref() {
        match projection.authorize_beam_convergence(
            authorization,
            receipt_dir,
            crate::atoms::ask::beam::DEFAULT_DOOR_URL,
        ) {
            Ok(true) => {
                if let Some(carrier) = carrier {
                    let mut value = carrier.borrow_mut();
                    let Some(transaction) = value.sealed_projection.as_mut() else {
                        return Err("stage-profile-transaction-missing".to_string());
                    };
                    transaction.authorize_caduceus_source(authorization)?;
                    value.projection = Some(projection.clone());
                }
            }
            Ok(false) => {
                projection.beam_finalization = None;
                beam.authorization = BeamAuthorizationReceipt::None;
                beam.first_missing_signal = "beam-convergence-lane-absent";
            }
            Err(signal @ ("beam-convergence-lane-absent" | "beam-convergence-lane-ambiguous")) => {
                projection.beam_finalization = None;
                beam.authorization = BeamAuthorizationReceipt::None;
                beam.first_missing_signal = signal;
            }
            Err(error) => return Err(error.to_string()),
        }
    } else {
        projection.beam_finalization = None;
    }
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
        "none"
            | "beam-door-unreachable"
            | "beam-lock-absent"
            | "beam-divergent-caduceus_sha"
            | "beam-divergent-env_sha"
            | "beam-convergence-lane-absent"
            | "beam-convergence-lane-ambiguous"
            | "beam-flag-absent"
            | "beam-flag-unresolvable"
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
pub(crate) struct BeamResolvedFrom {
    pub version: String,
    pub flagged_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct BeamCompareReceipt {
    pub schema: &'static str,
    pub state: &'static str,
    pub converged: bool,
    pub lock: Option<BeamLockProjection>,
    pub lock_source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_from: Option<BeamResolvedFrom>,
    pub door: Option<BeamDoorProjection>,
    pub first_divergent_member: Option<&'static str>,
    pub first_missing_signal: &'static str,
    pub authorization: BeamAuthorizationReceipt,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum BeamAuthorizationReceipt {
    None,
    TripleLadder,
    HeldDeveloperMode,
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
            lock_source: "literal",
            resolved_from: None,
            door: None,
            first_divergent_member: None,
            first_missing_signal: "beam-lock-absent",
            authorization: BeamAuthorizationReceipt::None,
        };
    };
    let lock_projection = BeamLockProjection {
        caduceus_sha: lock.caduceus_sha().expect("legacy beam lock").to_owned(),
        env_sha: lock.env_sha().expect("legacy beam lock").to_owned(),
    };
    let door = match door {
        Ok(door) => door,
        Err(signal) => {
            return BeamCompareReceipt {
                schema: "harmonia.beam-compare.v1",
                state: "divergent",
                converged: false,
                lock: Some(lock_projection),
                lock_source: "literal",
                resolved_from: None,
                door: None,
                first_divergent_member: None,
                first_missing_signal: if signal == "beam-door-unreachable" {
                    "beam-door-unreachable"
                } else {
                    "beam-door-malformed"
                },
                authorization: BeamAuthorizationReceipt::None,
            };
        }
    };
    let member = if lock.caduceus_sha().expect("legacy beam lock") != door.caduceus_sha {
        Some("caduceus_sha")
    } else if lock.env_sha().expect("legacy beam lock") != door.env_sha {
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
        lock_source: "literal",
        resolved_from: None,
        door: Some(door_projection),
        first_divergent_member: member,
        first_missing_signal: if member == Some("caduceus_sha") {
            "beam-divergent-caduceus_sha"
        } else if member == Some("env_sha") {
            "beam-divergent-env_sha"
        } else {
            "none"
        },
        authorization: BeamAuthorizationReceipt::None,
    }
}

pub(crate) fn authorize_beam(
    receipt: &mut BeamCompareReceipt,
    apply: bool,
    developer_mode: bool,
) -> Option<crate::atoms::ask::beam::BeamConvergenceAuthorization> {
    let lock = receipt.lock.as_ref()?;
    let divergent = !receipt.converged && receipt.first_divergent_member.is_some();
    let authorization = crate::atoms::ask::beam::authorize_convergence(
        &lock.caduceus_sha,
        receipt.first_divergent_member,
        divergent,
        apply,
        developer_mode,
    );
    receipt.authorization = if developer_mode && divergent {
        BeamAuthorizationReceipt::HeldDeveloperMode
    } else if divergent && !developer_mode {
        BeamAuthorizationReceipt::TripleLadder
    } else {
        BeamAuthorizationReceipt::None
    };
    authorization
}

pub(crate) fn finalize_beam_after_health(
    authorization: Option<&crate::atoms::ask::beam::BeamConvergenceAuthorization>,
    receipt_dir: &Path,
    door_url: &str,
) -> Result<(), String> {
    let mut receipt = None;
    for attempt in 0..5 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        let observed = beam_receipt(None, door_url)?;
        let converged = observed.converged;
        receipt = Some(observed);
        if converged {
            break;
        }
    }
    let mut receipt = receipt.expect("beam finalization performs five-read loop");
    receipt.authorization = authorization.map_or(BeamAuthorizationReceipt::None, |held| {
        held.receipt_authorization()
    });
    let value = serde_json::to_value(&receipt)
        .map_err(|error| format!("beam-receipt-serialize-failed: {error}"))?;
    crate::write_json(&receipt_dir.join("beam-after.json"), &value)
}
pub(crate) fn beam_receipt(
    lock_path: Option<&Path>,
    door_url: &str,
) -> Result<BeamCompareReceipt, String> {
    let lock = match lock_path { Some(path) => crate::atoms::ask::beam::read_lock_path(path), None => crate::atoms::ask::beam::read_embedded_lock().map(Some) };
    let lock = match lock {
        Ok(Some(slot @ crate::atoms::ask::beam::BeamLock::Slot { .. })) => match crate::atoms::ask::beam::resolve_slot(&slot) {
            Ok(resolved) => { let mut receipt = compare_beam(Some(resolved.lock), crate::atoms::ask::beam::fetch_door(door_url)); receipt.lock_source = "slot-resolved"; receipt.resolved_from = Some(BeamResolvedFrom { version: resolved.version, flagged_at: resolved.flagged_at }); return Ok(receipt); }
            Err(signal) => return Ok(BeamCompareReceipt { schema:"harmonia.beam-compare.v1", state:"pre-declaration", converged:false, lock:None, lock_source:"slot-resolved", resolved_from:None, door:None, first_divergent_member:None, first_missing_signal: if signal=="beam-flag-absent" { "beam-flag-absent" } else { "beam-flag-unresolvable" }, authorization:BeamAuthorizationReceipt::None }),
        },
        Ok(lock) => lock,
        Err(_) => return Ok(BeamCompareReceipt { schema:"harmonia.beam-compare.v1", state:"divergent", converged:false, lock:None, lock_source:"literal", resolved_from:None, door:None, first_divergent_member:None, first_missing_signal:"beam-lock-malformed", authorization:BeamAuthorizationReceipt::None }),
    };
    Ok(compare_beam(lock, crate::atoms::ask::beam::fetch_door(door_url)))
}

#[cfg(test)]
mod beam_tests {
    use super::*;

    fn lock() -> crate::atoms::ask::beam::BeamLock {
        crate::atoms::ask::beam::BeamLock::Legacy {
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


    fn slot_lock(registry_base: &str) -> crate::atoms::ask::beam::BeamLock {
        crate::atoms::ask::beam::BeamLock::Slot {
            schema: crate::atoms::ask::beam::SLOT_SCHEMA.into(),
            component: "caduceus".into(),
            resolve: "latest-flagged-release".into(),
            registry_base: registry_base.into(),
        }
    }

    fn fake_registry(
        responses: Vec<(String, u16, Vec<u8>)>,
    ) -> (String, std::thread::JoinHandle<Vec<String>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut paths = Vec::new();
            for (expected, status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 8192];
                let size = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..size]);
                let path = request.split_whitespace().nth(1).unwrap().to_string();
                assert_eq!(path, expected);
                paths.push(path);
                write!(stream, "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                stream.write_all(&body).unwrap();
            }
            paths
        });
        (format!("http://{address}"), handle)
    }

    fn write_slot(path: &std::path::Path, registry: &str) {
        let lock = slot_lock(&format!("{registry}/api/packages/HOMESERVERSLTD/generic"));
        std::fs::write(path, serde_json::to_vec(&lock).unwrap()).unwrap();
    }

    fn flag(source: &str, env: &str, flagged_at: &str) -> Vec<u8> {
        serde_json::json!({
            "schema": "estate.release-flag.v1", "component": "caduceus",
            "source_sha": source, "env_sha": env, "sha256": "e".repeat(64),
            "flagged_at": flagged_at, "pipeline_url": "https://ci"
        }).to_string().into_bytes()
    }

    #[test]
    fn slot_selects_newest_flagged_release_and_fetches_door_after_resolution() {
        let a = "a".repeat(40);
        let b = "b".repeat(40);
        let c = "c".repeat(40);
        let env_a = "1".repeat(64);
        let env_c = "3".repeat(64);
        let listing = serde_json::json!([
            {"name":"caduceus", "version": &a, "created_at":"2026-01-03T00:00:00Z"},
            {"name":"caduceus", "version": &b, "created_at":"2026-01-02T00:00:00Z"},
            {"name":"caduceus", "version": &c, "created_at":"2026-01-01T00:00:00Z"}
        ]).to_string().into_bytes();
        let door = serde_json::json!({
            "schema":"caduceus.beam.v1", "ok":true, "service":"caduceus",
            "caduceus_sha":c, "env_sha":env_c, "profile":"homeserver"
        }).to_string().into_bytes();
        let (registry, server) = fake_registry(vec![
            ("/api/v1/packages/HOMESERVERSLTD?type=generic&q=caduceus&limit=50&page=1".into(), 200, listing),
            (format!("/api/packages/HOMESERVERSLTD/generic/caduceus/{a}/release.flag"), 200, flag(&a, &env_a, "2026-02-01T00:00:00Z")),
            (format!("/api/packages/HOMESERVERSLTD/generic/caduceus/{b}/release.flag"), 404, Vec::new()),
            (format!("/api/packages/HOMESERVERSLTD/generic/caduceus/{c}/release.flag"), 200, flag(&c, &env_c, "2026-03-01T00:00:00Z")),
            ("/beam".into(), 200, door),
        ]);
        let temp = tempfile::tempdir().unwrap();
        let lock_path = temp.path().join("beam.json");
        write_slot(&lock_path, &registry);
        let receipt = beam_receipt(Some(&lock_path), &format!("{registry}/beam")).unwrap();
        let paths = server.join().unwrap();
        assert_eq!(paths.len(), 5);
        assert_eq!(receipt.state, "aligned");
        assert_eq!(receipt.lock_source, "slot-resolved");
        assert_eq!(receipt.lock.as_ref().unwrap().caduceus_sha, c);
        assert_eq!(receipt.lock.as_ref().unwrap().env_sha, env_c);
        assert_eq!(receipt.resolved_from.unwrap().flagged_at, "2026-03-01T00:00:00Z");
    }

    #[test]
    fn slot_filters_invalid_entries_and_traverses_listing_pages() {
        let newest = "a".repeat(40);
        let older = "b".repeat(40);
        let env_newest = "1".repeat(64);
        let env_older = "2".repeat(64);
        let mut page_one = vec![
            serde_json::json!({"name":"caduceus-staff", "version":"f".repeat(40), "created_at":""}),
            serde_json::json!({"name":"caduceus", "version":"not-hex", "created_at":""}),
            serde_json::json!({"name":"caduceus", "version": &older, "created_at":""}),
            serde_json::json!({"name":"caduceus", "version": &newest, "created_at":"2026-02-01T00:00:00Z"}),
        ];
        for index in 0..46 {
            page_one.push(serde_json::json!({
                "name": format!("irrelevant-{index}"),
                "version": format!("not-a-version-{index}"),
                "created_at": ""
            }));
        }
        let listing = serde_json::to_vec(&page_one).unwrap();
        let door = serde_json::json!({
            "schema":"caduceus.beam.v1", "ok":true, "service":"caduceus",
            "caduceus_sha":newest, "env_sha":env_newest, "profile":"homeserver"
        }).to_string().into_bytes();
        let (registry, server) = fake_registry(vec![
            ("/api/v1/packages/HOMESERVERSLTD?type=generic&q=caduceus&limit=50&page=1".into(), 200, listing),
            ("/api/v1/packages/HOMESERVERSLTD?type=generic&q=caduceus&limit=50&page=2".into(), 200, b"[]".to_vec()),
            (format!("/api/packages/HOMESERVERSLTD/generic/caduceus/{newest}/release.flag"), 200, flag(&newest, &env_newest, "2026-03-01T00:00:00Z")),
            (format!("/api/packages/HOMESERVERSLTD/generic/caduceus/{older}/release.flag"), 200, flag(&older, &env_older, "2026-02-01T00:00:00Z")),
            ("/beam".into(), 200, door),
        ]);
        let temp = tempfile::tempdir().unwrap();
        let lock_path = temp.path().join("beam.json");
        write_slot(&lock_path, &registry);
        let receipt = beam_receipt(Some(&lock_path), &format!("{registry}/beam")).unwrap();
        assert_eq!(server.join().unwrap().len(), 5);
        assert_eq!(receipt.state, "aligned");
        assert_eq!(receipt.lock_source, "slot-resolved");
        assert_eq!(receipt.lock.as_ref().unwrap().caduceus_sha, newest);
        assert_eq!(receipt.lock.as_ref().unwrap().env_sha, env_newest);
        assert_eq!(receipt.resolved_from.unwrap().version, newest);
    }

    #[test]
    fn slot_with_zero_valid_flags_is_predeclaration_and_flag_absent() {
        let a = "a".repeat(40);
        let listing = serde_json::json!([{"name":"caduceus", "version": &a, "created_at":"2026-01-01T00:00:00Z"}]).to_string().into_bytes();
        let (registry, server) = fake_registry(vec![
            ("/api/v1/packages/HOMESERVERSLTD?type=generic&q=caduceus&limit=50&page=1".into(), 200, listing),
            (format!("/api/packages/HOMESERVERSLTD/generic/caduceus/{a}/release.flag"), 404, Vec::new()),
        ]);
        let temp = tempfile::tempdir().unwrap();
        let lock_path = temp.path().join("beam.json");
        write_slot(&lock_path, &registry);
        let receipt = beam_receipt(Some(&lock_path), &format!("{registry}/beam")).unwrap();
        assert_eq!(server.join().unwrap().len(), 2);
        assert_eq!(receipt.state, "pre-declaration");
        assert_eq!(receipt.first_missing_signal, "beam-flag-absent");
        assert!(receipt.door.is_none());
    }

    #[test]
    fn malformed_flag_is_predeclaration_and_flag_unresolvable() {
        let a = "a".repeat(40);
        let listing = serde_json::json!([{"name":"caduceus", "version": &a, "created_at":"2026-01-01T00:00:00Z"}]).to_string().into_bytes();
        let (registry, server) = fake_registry(vec![
            ("/api/v1/packages/HOMESERVERSLTD?type=generic&q=caduceus&limit=50&page=1".into(), 200, listing),
            (format!("/api/packages/HOMESERVERSLTD/generic/caduceus/{a}/release.flag"), 200, b"not-json".to_vec()),
        ]);
        let temp = tempfile::tempdir().unwrap();
        let lock_path = temp.path().join("beam.json");
        write_slot(&lock_path, &registry);
        let receipt = beam_receipt(Some(&lock_path), &format!("{registry}/beam")).unwrap();
        assert_eq!(server.join().unwrap().len(), 2);
        assert_eq!(receipt.state, "pre-declaration");
        assert_eq!(receipt.first_missing_signal, "beam-flag-unresolvable");
        assert!(receipt.door.is_none());
    }

    #[test]
    fn aligned_state() {
        let receipt = compare_beam(Some(lock()), Ok(door()));
        assert_eq!(receipt.state, "aligned");
        assert_eq!(receipt.first_missing_signal, "none");
    }

    #[test]
    fn aligned_authorization_is_none() {
        let mut receipt = compare_beam(Some(lock()), Ok(door()));
        assert!(authorize_beam(&mut receipt, true, false).is_none());
        assert_eq!(receipt.authorization, BeamAuthorizationReceipt::None);
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
    fn divergent_nondeveloper_is_triple_ladder_even_in_observe() {
        let mut receipt = compare_beam(Some(lock()), Ok({ let mut d = door(); d.env_sha = "e".repeat(64); d }));
        assert!(authorize_beam(&mut receipt, false, false).is_none());
        assert_eq!(receipt.authorization, BeamAuthorizationReceipt::TripleLadder);
    }

    #[test]
    fn predeclaration_is_none() {
        let mut receipt = compare_beam(None, Err("beam-door-unreachable".into()));
        assert!(authorize_beam(&mut receipt, false, false).is_none());
        assert_eq!(receipt.authorization, BeamAuthorizationReceipt::None);
    }

    #[test]
    fn divergent_developer_is_held_even_in_observe() {
        let mut receipt = compare_beam(Some(lock()), Ok({ let mut d = door(); d.env_sha = "e".repeat(64); d }));
        assert!(authorize_beam(&mut receipt, false, true).is_none());
        assert_eq!(receipt.authorization, BeamAuthorizationReceipt::HeldDeveloperMode);
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
        let raw = r#"{"schema":"caduceus.beam.v1","ok":true,"service":"caduceus","profile":"homeserver","caduceus_sha":"1ddb41af4f123db22ce8cc6037d24a79d582f84c","env_sha":"237777c45ef88dee8f2426e564bf0c8754f21856d64383f848ca4d4ffa85091d","gui_face":"Coronatio","syzygy_sha":null}"#;
        let door = crate::atoms::ask::beam::parse_door(raw).unwrap();
        let lock = crate::atoms::ask::beam::BeamLock::Legacy { schema: "harmonia.beam-lock.v1".into(), caduceus_sha: "1ddb41af4f123db22ce8cc6037d24a79d582f84c".into(), env_sha: "237777c45ef88dee8f2426e564bf0c8754f21856d64383f848ca4d4ffa85091d".into(), minted_from: crate::atoms::ask::beam::MintedFrom { harmonia_sha: "c".repeat(40), caduceus_release_tag: "d".repeat(40) } };
        let receipt = compare_beam(Some(lock), Ok(door));
        assert_eq!(receipt.state, "aligned");
        assert!(receipt.converged);
        assert_eq!(receipt.first_missing_signal, "none");
    }

    #[cfg(feature = "test-facade")]
    #[test]
    fn facade_fetches_locked_caduceus_and_commits_authorized_beam_transaction() {
        use serde_json::json;
        use sha2::{Digest, Sha256};
        use std::{
            collections::BTreeMap,
            fs,
            io::{Read, Write},
            net::TcpListener,
            thread,
        };

        let temp = tempfile::tempdir().unwrap();
        let receipt_dir = temp.path().join("receipts");
        fs::create_dir_all(&receipt_dir).unwrap();
        let installed = temp.path().join("installed");
        let destination = temp.path().join("destination");
        let lock = lock();
        let lock_sha = lock.caduceus_sha().unwrap().to_owned();
        let old_sha = "0123456789abcdef0123456789abcdef01234567";
        fs::write(&installed, format!("caduceus.liveness.v1{old_sha}")).unwrap();
        let artifact = format!("caduceus.liveness.v1{lock_sha}").into_bytes();
        let artifact_sha = format!("{:x}", Sha256::digest(&artifact));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let registry = format!("http://{address}");
        let server_lock_sha = lock_sha.clone();
        let server_artifact = artifact.clone();
        let server_artifact_sha = artifact_sha.clone();
        let server = thread::spawn(move || {
            let requests = [
                (
                    format!("/caduceus/{server_lock_sha}/manifest.json"),
                    format!(r#"{{"schema":"estate.artifact.manifest.v1","component":"caduceus","source_sha":"{server_lock_sha}","target":"x86_64","sha256":"{server_artifact_sha}","built_at":"now","pipeline_url":"https://ci"}}"#).into_bytes(),
                ),
                (format!("/caduceus/{server_lock_sha}/artifact"), server_artifact),
                (
                    "/health".to_string(),
                    b"ok".to_vec(),
                ),
            ];
            for (path, body) in requests {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 4096];
                let n = stream.read(&mut request).unwrap();
                assert!(String::from_utf8_lossy(&request[..n]).starts_with(&format!("GET {path} ")));
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                stream.write_all(&body).unwrap();
            }
        });

        let divergent_door = { let mut door = door(); door.env_sha = "e".repeat(64); door };
        let mut beam = compare_beam(Some(lock), Ok(divergent_door));
        let authorization = authorize_beam(&mut beam, true, false).unwrap();
        assert_eq!(beam.authorization, BeamAuthorizationReceipt::TripleLadder);
        assert_eq!(authorization.caduceus_sha(), lock_sha);

        let args: BTreeMap<String, Value> = [
            ("component", json!("caduceus")), ("registry_base", json!(&registry)),
            ("source_build_sha", json!(lock_sha)), ("artifact_name", json!("artifact")),
            ("destination", json!(&destination)), ("installed_binary", json!(&installed)),
        ].into_iter().map(|(key, value)| (key.into(), value)).collect();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome = crate::tools::fetch_artifact::execute(&args, &receipt_dir, true, Some(&invocation)).unwrap();
        assert!(outcome.changed);
        assert!(crate::atoms::ask::fetch_artifact::destination_identity(&destination, &lock_sha));

        let plan = crate::atoms::r#do::transaction::UpdatePlan {
            targets: Vec::new(), services: Vec::new(), gui_face: Some("Coronatio".into()), gui_member: Some("face".into()),
            caduceus_count: 1, pinned_members: Some(vec!["caduceus".into(), "sbin".into(), "face".into()]),
            member_modules: BTreeMap::new(),
        };
        let mut transaction = crate::atoms::r#do::transaction::seal_projection(&plan, "profile", "identity", "source-head").unwrap();
        transaction.authorize_caduceus_source(&authorization).unwrap();
        for child in 0..transaction.sealed.children.len() {
            crate::atoms::r#do::transaction::apply_projection(&mut transaction, child, &invocation).unwrap();
        }
        let receipt = crate::atoms::r#do::transaction::commit_projection(&mut transaction).unwrap();
        assert_eq!(receipt.state, crate::atoms::r#do::transaction::TransactionState::Committed);
        assert_eq!(receipt.children[0].source_sha.as_deref(), Some(lock_sha.as_str()));
        assert_eq!(receipt.children[1].source_sha, None);
        assert_eq!(receipt.children[2].source_sha, None);

        let manifest: crate::tools::ladder::LadderManifest = serde_json::from_value(json!({"schema":"harmonia.module.ladder.v1","id":"restart","version":"1","ladder":[{"step_id":"health-proof-routine","tool":"routine","permutation":"execute","steps":[{"name":"health-proof","tool":"check-health","permutation":"probe","args":{"component":"caduceus","url":format!("{registry}/health")}}]}]})).unwrap();
        let step = crate::tools::routine::ValidatedStep { step_id: "health-proof-routine".into(), tool: "routine".into(), permutation: "execute".into(), args: BTreeMap::new(), on_failure: crate::tools::ladder::OnFailure::Stop };
        let child = crate::tools::routine::ProjectedRoutineChild { name: "health-proof".into(), tool: "check-health".into(), permutation: "probe".into(), args: [("component".into(), json!("caduceus")), ("url".into(), json!(format!("{registry}/health")))].into_iter().collect(), on_failure: crate::tools::ladder::OnFailure::Stop, band: crate::bands::Band::RestartServices };
        let mut states = BTreeMap::new();
        crate::bands::restart_services::execute_manifest_band(&manifest, &receipt_dir, None, None, Some(&invocation), true, None, &mut states, &[step], &[("health-proof-routine".into(), vec![child])].into_iter().collect()).unwrap();
        server.join().unwrap();
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
