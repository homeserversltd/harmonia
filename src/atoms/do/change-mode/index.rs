//! Typed no-follow mode actuator.
use crate::atoms::comparison::ActionAuthorization;
use crate::atoms::r#do::InvocationKey;
use crate::atoms::{Drift, Receipt};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub path: PathBuf,
    pub mode: Option<u32>,
    pub no_follow: bool,
}
pub(crate) fn change(a: &ActionAuthorization, i: &InvocationKey, p: &Plan) -> Result<(), String> {
    let mode = p.mode.ok_or("change-mode-mode-missing")?;
    if !p.no_follow {
        return Err("change-mode-no-follow-required".into());
    };
    let observation = crate::atoms::ask::change_mode::probe(&p.path, mode)?;
    if !observation.preimage.present {
        return Err("change-mode-path-absent".into());
    }
    if observation.preimage.kind == Some(crate::atoms::ask::FsKind::Symlink) {
        return Err("change-mode-symlink-refused".into());
    };
    fs::set_permissions(&p.path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("change-mode-failed: {e}"))?;
    let _ = (a, i);
    Ok(())
}

/// One declared metadata target in the public files manifest grammar.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MetadataFileSpec {
    pub path: String,
    pub owner: String,
    pub group: String,
    pub mode: u32,
}

fn valid_metadata_preimage(preimage: &crate::atoms::ask::FsPreimage) -> Result<(), String> {
    if !preimage.present {
        return Err(format!("files-metadata-target-absent {}", preimage.path.display()));
    }
    match preimage.kind {
        Some(crate::atoms::ask::FsKind::File | crate::atoms::ask::FsKind::Directory) => Ok(()),
        Some(crate::atoms::ask::FsKind::Symlink) => {
            Err(format!("files-metadata-symlink-refused {}", preimage.path.display()))
        }
        _ => Err(format!("files-metadata-target-kind-refused {}", preimage.path.display())),
    }
}

fn metadata_state(observation: &crate::atoms::ask::change_mode::Observation) -> Value {
    let identity = observation
        .path_inode
        .map(|identity| json!({"device":identity.device,"inode":identity.inode}));
    json!({
        "path":observation.path,
        "exists":observation.preimage.present,
        "kind":format!("{:?}", observation.preimage.kind),
        "mode":observation.prior_mode,
        "identity":identity,
    })
}

/// Typed metadata action for one target. Comparison alone controls whether the
/// ActionAuthorization reaches the existing change-mode actuator.
pub(crate) fn reconcile(
    plan: &Plan,
    apply: bool,
    invocation: Option<&InvocationKey>,
    receipt_log: &Path,
) -> Result<Value, String> {
    let desired_mode = plan.mode;
    let mut observed_before = None;
    let mut compared_different = None;
    let mut movement_attempted = false;
    let run = crate::atoms::comparison::execute_once(
        "change-mode",
        || {
            let observation = crate::atoms::ask::change_mode::probe(
                &plan.path,
                desired_mode.unwrap_or_default(),
            )?;
            observed_before = Some(observation.clone());
            valid_metadata_preimage(&observation.preimage)?;
            Ok(observation)
        },
        |observation| {
            let decision = if observation.prior_mode == desired_mode {
                crate::atoms::comparison::DiffDecision::Empty
            } else {
                crate::atoms::comparison::DiffDecision::Different
            };
            compared_different =
                Some(decision == crate::atoms::comparison::DiffDecision::Different);
            decision
        },
        |authorization, _observation| -> Result<bool, String> {
            if !apply {
                return Ok(false);
            }
            let invocation =
                invocation.ok_or_else(|| "change-mode-invocation-key-missing".to_string())?;
            movement_attempted = true;
            change(&authorization, invocation, plan)?;
            Ok(true)
        },
    );
    let (observation, decision, attempted) = match run {
        Ok(crate::atoms::comparison::ComparisonRun::Current {
            observation,
            decision,
        }) => (observation, decision, false),
        Ok(crate::atoms::comparison::ComparisonRun::Moved {
            observation,
            decision,
            movement,
        }) => (observation, decision, movement),
        Err(error) => {
            let (after, readback_blocker) = if movement_attempted {
                match crate::atoms::ask::change_mode::probe(
                    &plan.path,
                    desired_mode.unwrap_or_default(),
                ) {
                    Ok(after) => {
                        let blocker = valid_metadata_preimage(&after.preimage).err();
                        (Some(after), blocker)
                    }
                    Err(error) => (None, Some(error)),
                }
            } else {
                (None, None)
            };
            let observed_state = observed_before.as_ref().map(metadata_state);
            let final_state = after.as_ref().map(metadata_state);
            let changed = match (observed_before.as_ref(), after.as_ref()) {
                (Some(before), Some(after)) => Some(before.prior_mode != after.prior_mode),
                (_, _) if !movement_attempted => Some(false),
                _ => None,
            };
            let changed_value = changed.map_or(Value::Null, |changed| json!(changed));
            let diff_decision = match compared_different {
                Some(true) => "Different",
                Some(false) => "Empty",
                None => "blocked",
            };
            let movement = if movement_attempted {
                "attempted"
            } else {
                "none"
            };
            let proof = if compared_different.is_some() {
                "metadata-action-failed"
            } else {
                "metadata-observation-blocked"
            };
            let desired_state = json!({"mode":desired_mode});
            let evidence = json!({
                "observed_state":observed_state.clone(),
                "desired_state":desired_state.clone(),
                "diff_decision":diff_decision,
                "movement":movement,
                "changed":changed_value.clone(),
                "final_state":final_state.clone(),
                "blocker":error.clone(),
                "readback_blocker":readback_blocker.clone(),
            });
            let receipt = Receipt {
                atom: "change-mode".into(),
                ok: false,
                drift: Drift::Current,
                message: format!("path={} metadata-failure={evidence}", plan.path.display()),
            };
            crate::atoms::attest::attest(receipt_log, &receipt, &[])?;
            return Ok(json!({
                "atom":"change-mode", "ok":false,
                "observed_state":observed_state,
                "desired_state":desired_state,
                "diff_decision":diff_decision, "movement":movement,
                "final_state":final_state, "proof":proof, "blocker":error,
                "readback_blocker":readback_blocker,
                "changed":changed_value,
            }));
        }
    };
    let after = crate::atoms::ask::change_mode::probe(&plan.path, desired_mode.unwrap_or_default());
    let (after_observation, after_error) = match after {
        Ok(after) => {
            let error = valid_metadata_preimage(&after.preimage).err();
            (Some(after), error)
        }
        Err(error) => (None, Some(error)),
    };
    let final_mode = after_observation
        .as_ref()
        .and_then(|after| after.prior_mode);
    let before_mode = observation.prior_mode;
    let changed = after_observation
        .as_ref()
        .map(|after| before_mode != after.prior_mode);
    let different = decision == crate::atoms::comparison::DiffDecision::Different;
    let mut blocker = after_error.unwrap_or_else(|| "none".into());
    if apply && different && blocker == "none" && final_mode != desired_mode {
        blocker = "change-mode-act-did-not-converge".into();
    }
    let ok = blocker == "none";
    let movement = if !different {
        "none"
    } else if attempted {
        "attempted"
    } else {
        "report-only"
    };
    let diff_decision = if different { "Different" } else { "Empty" };
    let proof = if !ok && attempted {
        "metadata-action-failed"
    } else if !ok {
        "metadata-observation-blocked"
    } else if different && !apply {
        "report-only"
    } else if different {
        "metadata-readback"
    } else {
        "current"
    };
    let observed_state = metadata_state(&observation);
    let final_state = after_observation.as_ref().map(metadata_state);
    let receipt = Receipt {
        atom: "change-mode".into(),
        ok,
        drift: Drift::Current,
        message: format!(
            "path={} observed_mode={:?} desired_mode={:?} diff={} movement={} changed={:?} final_mode={:?} blocker={}",
            plan.path.display(), before_mode, desired_mode, diff_decision, movement, changed, final_mode, blocker
        ),
    };
    crate::atoms::attest::attest(receipt_log, &receipt, &[])?;
    Ok(json!({
        "atom":"change-mode", "ok":ok, "changed":changed,
        "observed_state":observed_state,
        "desired_state":{"mode":desired_mode},
        "diff_decision":diff_decision, "movement":movement,
        "final_state":final_state, "proof":proof, "blocker":blocker,
    }))
}

/// Dispatch the public metadata step through the two typed filesystem atoms.
/// Compatibility JSON is a projection of their centrally attested receipts.
pub(crate) fn converge_metadata(
    specs: &[MetadataFileSpec],
    receipt_dir: &Path,
    receipt_name: &str,
    apply: bool,
    invocation: Option<&InvocationKey>,
) -> Result<crate::OperationOutcome, String> {
    if specs.is_empty() {
        return Err("files-metadata-files-empty".into());
    }
    let receipt_log = receipt_dir.join("atoms.jsonl");
    let mut observed = Vec::new();
    let mut changed = false;
    let mut changed_unknown = false;
    let mut ok = true;
    let mut any_different = false;
    let mut comparison_blocked = false;
    let mut movement_attempted = false;
    let mut action_failed = false;
    let mut first_blocker = "none".to_string();
    for spec in specs {
        let path = PathBuf::from(&spec.path);
        if !path.is_absolute() {
            return Err(format!("files-metadata-path-must-be-absolute {}", path.display()));
        }
        let uid = crate::atoms::files::resolve_uid(&spec.owner)?;
        let gid = crate::atoms::files::resolve_gid(&spec.group)?;
        let owner = crate::atoms::r#do::change_owner::reconcile(
            &crate::atoms::r#do::change_owner::Plan {
                path: path.clone(), uid: Some(uid), gid: Some(gid), no_follow: true,
            },
            apply, invocation, &receipt_log,
        )?;
        let mode = reconcile(
            &Plan { path: path.clone(), mode: Some(spec.mode), no_follow: true },
            apply, invocation, &receipt_log,
        )?;
        for item in [&owner, &mode] {
            ok &= item.get("ok").and_then(Value::as_bool).unwrap_or(false);
            match item.get("changed") {
                Some(Value::Bool(true)) => changed = true,
                Some(Value::Bool(false)) => {}
                _ => changed_unknown = true,
            }
            any_different |= item.get("diff_decision").and_then(Value::as_str) == Some("Different");
            comparison_blocked |=
                item.get("diff_decision").and_then(Value::as_str) == Some("blocked");
            movement_attempted |= item.get("movement").and_then(Value::as_str) == Some("attempted");
            action_failed |=
                item.get("proof").and_then(Value::as_str) == Some("metadata-action-failed");
            if first_blocker == "none" {
                if let Some(blocker) = item.get("blocker").and_then(Value::as_str).filter(|blocker| *blocker != "none") {
                    first_blocker = blocker.to_string();
                }
            }
        }
        observed.push(json!({
            "path":spec.path,
            "owner":owner.get("observed_state"),
            "mode":mode.get("observed_state"),
            "desired":{"owner":spec.owner,"group":spec.group,"uid":uid,"gid":gid,"mode":spec.mode},
            "diff":{"owner":owner.get("diff_decision"),"mode":mode.get("diff_decision")},
            "movement":{"owner":owner.get("movement"),"mode":mode.get("movement")},
            "final_state":{"owner":owner.get("final_state"),"mode":mode.get("final_state")},
            "receipts":[owner,mode],
        }));
    }
    let movement = if movement_attempted {
        "attempted"
    } else {
        "none"
    };
    let diff_decision = if any_different {
        "Different"
    } else if comparison_blocked {
        "blocked"
    } else {
        "Empty"
    };
    let proof = if !ok && action_failed {
        "metadata-action-failed"
    } else if !ok {
        "metadata-observation-blocked"
    } else if any_different && !apply {
        "report-only"
    } else if any_different {
        "metadata-readback"
    } else {
        "current"
    };
    let changed_projection = if changed {
        json!(true)
    } else if changed_unknown {
        Value::Null
    } else {
        json!(false)
    };
    let projection = json!({
        "schema":"harmonia.files.metadata.v1", "ok":ok, "changed":changed_projection,
        "observed_state":observed.iter().map(|entry| json!({"path":entry["path"],"owner":entry["owner"],"mode":entry["mode"]})).collect::<Vec<_>>(),
        "desired_state":specs,
        "diff_decision":diff_decision,
        "diff":observed.iter().map(|entry| entry["diff"].clone()).collect::<Vec<_>>(),
        "movement":movement,
        "final_state":observed.iter().map(|entry| entry["final_state"].clone()).collect::<Vec<_>>(),
        "proof":proof, "blocker":first_blocker,
    });
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
    let file_name = if receipt_name.ends_with(".json") { receipt_name.to_string() } else { format!("{receipt_name}.json") };
    crate::atoms::attest::write_json_atomic(&receipt_dir.join(file_name), &projection)?;
    Ok(crate::OperationOutcome {
        ok, changed, skipped:!apply || !any_different,
        message:format!("files metadata diff={diff_decision} movement={movement}"), command:None,
    })
}
