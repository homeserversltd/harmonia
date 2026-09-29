//! Authorized filesystem mutation owners for symlink convergence.

use crate::atoms::comparison::ActionAuthorization;
use crate::atoms::files::{
    resolve_gid, resolve_uid, symlink_diff_decision, validate_receipt_name,
    validate_symlink_converge_args, SymlinkComparisonObservation, SymlinkConflictPolicy,
    SymlinkConvergeRequest, SymlinkPathIdentity, SymlinkSourceIdentity,
};
use crate::atoms::r#do::InvocationKey;
use serde_json::json;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

fn receipt(a: &ActionAuthorization, i: &InvocationKey, _message: String) -> Result<(), String> {
    let _ = (a, i);
    Ok(())
}
pub(crate) fn stage(
    a: &ActionAuthorization,
    i: &InvocationKey,
    source: &Path,
    target: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<PathBuf, String> {
    let parent = target
        .parent()
        .ok_or_else(|| "symlink-converge-target-parent-missing".to_string())?;
    let name = target
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("link");
    for attempt in 0..100u32 {
        let candidate = parent.join(format!(
            ".{name}.harmonia-symlink-converge-{}-{attempt}",
            std::process::id()
        ));
        match std::os::unix::fs::symlink(source, &candidate) {
            Ok(()) => {
                if uid.is_some() || gid.is_some() {
                    if let Err(error) = crate::atoms::r#do::change_owner::change(
                        a,
                        i,
                        &crate::atoms::r#do::change_owner::Plan {
                            path: candidate.clone(),
                            uid,
                            gid,
                            no_follow: true,
                        },
                    ) {
                        let _ = remove_file(a, i, &candidate);
                        return Err(error);
                    }
                }
                receipt(a, i, format!("staged symlink {}", candidate.display()))?;
                return Ok(candidate);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(format!(
                    "symlink-converge-stage-failed {}: {e}",
                    candidate.display()
                ))
            }
        }
    }
    Err("symlink-converge-stage-name-exhausted".into())
}
fn renameat2(
    a: &ActionAuthorization,
    i: &InvocationKey,
    left: &Path,
    right: &Path,
    flags: libc::c_uint,
    message: &str,
) -> Result<(), String> {
    let l = CString::new(left.as_os_str().as_bytes())
        .map_err(|_| "symlink-converge-rename-path-invalid".to_string())?;
    let r = CString::new(right.as_os_str().as_bytes())
        .map_err(|_| "symlink-converge-rename-path-invalid".to_string())?;
    #[cfg(target_os = "linux")]
    let rc = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            l.as_ptr(),
            libc::AT_FDCWD,
            r.as_ptr(),
            flags,
        )
    };
    #[cfg(not(target_os = "linux"))]
    let rc = -1;
    if rc != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    receipt(
        a,
        i,
        format!("{message} {} {}", left.display(), right.display()),
    )
}
pub(crate) fn exchange(
    a: &ActionAuthorization,
    i: &InvocationKey,
    left: &Path,
    right: &Path,
) -> Result<(), String> {
    renameat2(a, i, left, right, libc::RENAME_EXCHANGE, "exchanged").map_err(|error| {
        format!(
            "symlink-converge-exchange-failed {}: {error}",
            right.display()
        )
    })
}
pub(crate) fn rename_noreplace(
    a: &ActionAuthorization,
    i: &InvocationKey,
    left: &Path,
    right: &Path,
) -> Result<(), String> {
    renameat2(a, i, left, right, libc::RENAME_NOREPLACE, "promoted")
        .map_err(|error| format!("symlink-converge-create-raced {}: {error}", right.display()))
}
pub(crate) fn remove_file(
    a: &ActionAuthorization,
    i: &InvocationKey,
    path: &Path,
) -> Result<(), String> {
    fs::remove_file(path).map_err(|e| e.to_string())?;
    receipt(a, i, format!("removed file {}", path.display()))
}
pub(crate) fn remove_dir(
    a: &ActionAuthorization,
    i: &InvocationKey,
    path: &Path,
) -> Result<(), String> {
    fs::remove_dir(path).map_err(|e| e.to_string())?;
    receipt(a, i, format!("removed directory {}", path.display()))
}
pub(crate) fn sync_parent(
    a: &ActionAuthorization,
    i: &InvocationKey,
    path: &Path,
) -> Result<(), String> {
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    receipt(a, i, format!("synced directory {}", path.display()))
}

fn promote_staged_symlink(
    authorization: &crate::atoms::comparison::ActionAuthorization,
    invocation: &crate::atoms::r#do::InvocationKey,
    candidate: &Path,
    target: &Path,
    before: &SymlinkPathIdentity,
) -> Result<(), String> {
    if before.kind == "absent" {
        if let Err(error) = rename_noreplace(authorization, invocation, candidate, target) {
            let _ = crate::atoms::r#do::symlink_converge::remove_file(
                authorization,
                invocation,
                candidate,
            );
            return Err(error);
        }
        return Ok(());
    }

    if let Err(error) = exchange(authorization, invocation, candidate, target) {
        let _ =
            crate::atoms::r#do::symlink_converge::remove_file(authorization, invocation, candidate);
        return Err(error);
    }
    let exchanged = crate::atoms::files::observe_symlink_path(candidate);
    let prior_matches = exchanged.as_ref().is_ok_and(|identity| identity == before);
    let directory_still_empty = before.kind != "directory"
        || fs::read_dir(candidate)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(false);
    if !prior_matches || !directory_still_empty {
        let rollback = exchange(authorization, invocation, candidate, target);
        if rollback.is_ok() {
            let _ = crate::atoms::r#do::symlink_converge::remove_file(
                authorization,
                invocation,
                candidate,
            );
        }
        return Err(format!(
            "symlink-converge-target-raced prior_matches={prior_matches} directory_still_empty={directory_still_empty} rollback={}",
            if rollback.is_ok() { "ok" } else { "failed" }
        ));
    }

    let cleanup = if before.kind == "directory" {
        crate::atoms::r#do::symlink_converge::remove_dir(authorization, invocation, candidate)
    } else {
        crate::atoms::r#do::symlink_converge::remove_file(authorization, invocation, candidate)
    };
    cleanup.map_err(|error| {
        format!(
            "symlink-converge-prior-cleanup-failed {}: {error}",
            candidate.display()
        )
    })
}

fn receipt_identity<T: serde::Serialize>(identity: Option<&T>) -> String {
    identity
        .map(|identity| serde_json::to_string(identity).unwrap_or_else(|_| "unavailable".into()))
        .unwrap_or_else(|| "unknown".into())
}

fn write_blocked_receipt(
    request: &SymlinkConvergeRequest,
    receipt_dir: &Path,
    apply: bool,
    desired_uid: Option<u32>,
    desired_gid: Option<u32>,
    blocker: &str,
    before: Option<&SymlinkPathIdentity>,
    source_before: Option<&SymlinkSourceIdentity>,
    action_entered: bool,
    movement_attempted: bool,
) -> Result<(), String> {
    crate::atoms::attest::prepare_receipt_parent(receipt_dir).map_err(|error| {
        format!(
            "symlink-converge-receipt-dir-failed {}: {error}",
            receipt_dir.display()
        )
    })?;
    let movement = if movement_attempted {
        "attempted"
    } else if action_entered && !apply {
        "report-only"
    } else {
        "none"
    };
    let diff = if action_entered {
        "different"
    } else {
        "blocked"
    };
    let changed = if movement_attempted {
        serde_json::Value::Null
    } else {
        json!(false)
    };
    let would_change = if action_entered {
        json!(true)
    } else {
        serde_json::Value::Null
    };
    let typed_receipt = crate::atoms::Receipt {
        atom: "symlink-converge".into(),
        ok: false,
        drift: crate::atoms::Drift::Current,
        message: format!(
            "BLOCKED source={} target={} diff={} movement={} changed={} blocker={} before={} after=unknown source_before={} source_after=unknown",
            request.source.display(),
            request.target.display(),
            diff,
            movement,
            if movement_attempted {
                "unknown"
            } else {
                "false"
            },
            blocker,
            receipt_identity(before),
            receipt_identity(source_before)
        ),
    };
    crate::atoms::attest::attest(&receipt_dir.join("atoms.jsonl"), &typed_receipt, &[])?;
    let receipt = json!({
        "schema": "harmonia.files.symlink_converge.v1",
        "ok": false,
        "apply": apply,
        "changed": changed.clone(),
        "would_change": would_change,
        "source": request.source,
        "target": request.target,
        "required_source_kind": request.required_source_kind,
        "conflict_policy": request.conflict_policy,
        "owner": request.owner,
        "group": request.group,
        "desired_uid": desired_uid,
        "desired_gid": desired_gid,
        "source_before": source_before,
        "source_after": null,
        "source_identity_stable": false,
        "before": before,
        "after": null,
        "final_readlink": null,
        "first_missing_signal": blocker,
        "observed_state": before,
        "desired_state": {"kind":"symlink","link_target":request.source,"uid":desired_uid,"gid":desired_gid},
        "diff_decision": diff,
        "movement": movement,
        "truthful_changed": changed,
    });
    crate::atoms::attest::make_link::write_existing(
        &receipt_dir.join(format!("{}.json", request.receipt_name)),
        &receipt,
    )
}

pub(crate) fn symlink_converge(
    request: &SymlinkConvergeRequest,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<crate::OperationOutcome, String> {
    validate_receipt_name(&request.receipt_name)?;
    let desired_uid = request
        .owner
        .as_deref()
        .map(resolve_uid)
        .transpose()
        .map_err(|error| format!("symlink-converge-owner-resolution-failed: {error}"))?;
    let desired_gid = request
        .group
        .as_deref()
        .map(resolve_gid)
        .transpose()
        .map_err(|error| format!("symlink-converge-group-resolution-failed: {error}"))?;
    let mut action_entered = false;
    let movement_attempted = Cell::new(false);
    let mut observed_before = None;
    let mut observed_source_before = None;
    let mut captured_first_observation = false;
    let central_attested = Cell::new(false);
    let observation_result = crate::atoms::comparison::execute(
        "files",
        || {
            let before = crate::atoms::files::observe_symlink_path(&request.target)?;
            let source = crate::atoms::files::read_symlink_source(
                &request.source,
                request.required_source_kind,
            );
            if !captured_first_observation {
                observed_before = Some(before.clone());
                observed_source_before = source.as_ref().ok().cloned();
                captured_first_observation = true;
            }
            Ok::<_, String>(SymlinkComparisonObservation {
                before,
                source,
                desired_uid,
                desired_gid,
            })
        },
        |observation| symlink_diff_decision(observation, request),
        |authorization, _| {
            action_entered = true;
            let authorization = &authorization;
            symlink_converge_action(
                authorization,
                invocation,
                request,
                receipt_dir,
                apply,
                &central_attested,
                &movement_attempted,
            )
        },
    );
    let observation = match observation_result {
        Ok(observation) => observation,
        Err(error) => {
            if !central_attested.get() {
                write_blocked_receipt(
                    request,
                    receipt_dir,
                    apply,
                    desired_uid,
                    desired_gid,
                    &error,
                    observed_before.as_ref(),
                    observed_source_before.as_ref(),
                    action_entered,
                    movement_attempted.get(),
                )?;
            }
            return Err(error);
        }
    };
    let decision = match observation.decision() {
        crate::atoms::comparison::DiffDecision::Empty => "empty",
        crate::atoms::comparison::DiffDecision::Different => "different",
    };
    let movement = match &observation {
        crate::atoms::comparison::ComparisonRun::Current { .. } => None,
        crate::atoms::comparison::ComparisonRun::Moved { movement, .. } => Some(movement),
    };
    let movement_kind = match movement {
        Some(movement) if movement.changed => "attempted",
        Some(_) if !apply => "report-only",
        Some(_) => "none",
        None => "none",
    };
    let outcome = match &observation {
        crate::atoms::comparison::ComparisonRun::Current { .. } => crate::OperationOutcome {
            ok: true,
            changed: false,
            skipped: !apply,
            message: "symlink converge unchanged".into(),
            command: None,
        },
        crate::atoms::comparison::ComparisonRun::Moved { movement, .. } => movement.clone(),
    };
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
    if !central_attested.get() {
        let observed = observation.observation();
        let before = receipt_identity(Some(&observed.before));
        let after = if decision == "empty" {
            before.clone()
        } else {
            "unknown".into()
        };
        let source_before = receipt_identity(observed.source.as_ref().ok());
        let source_after = if decision == "empty" {
            source_before.clone()
        } else {
            "unknown".into()
        };
        let typed_receipt = crate::atoms::Receipt {
            atom: "symlink-converge".into(),
            ok: outcome.ok,
            drift: crate::atoms::Drift::Current,
            message: format!(
                "source={} target={} diff={} movement={} changed={} blocker={} before={} after={} source_before={} source_after={}",
                request.source.display(),
                request.target.display(),
                decision,
                movement_kind,
                outcome.changed,
                if outcome.ok {
                    "none"
                } else {
                    outcome.message.as_str()
                },
                before,
                after,
                source_before,
                source_after
            ),
        };
        crate::atoms::attest::attest(&receipt_dir.join("atoms.jsonl"), &typed_receipt, &[])?;
        central_attested.set(true);
    }
    let path = receipt_dir.join(format!("{}.json", request.receipt_name));
    let mut receipt = if path.exists() {
        serde_json::from_str(&fs::read_to_string(&path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?
    } else {
        json!({
            "schema": "harmonia.files.symlink_converge.v1",
            "ok": outcome.ok, "apply": apply, "changed": outcome.changed,
            "would_change": false, "source": request.source, "target": request.target,
            "required_source_kind": request.required_source_kind,
            "conflict_policy": request.conflict_policy,
            "owner": request.owner, "group": request.group,
            "desired_uid": desired_uid, "desired_gid": desired_gid,
            "before": observation.observation().before, "after": observation.observation().before,
            "final_readlink": observation.observation().before.link_target,
            "first_missing_signal": "none",
        })
    };
    let object = receipt
        .as_object_mut()
        .ok_or_else(|| "symlink-converge-receipt-not-object".to_string())?;
    let observed_preimage = observed_before
        .as_ref()
        .ok_or_else(|| "symlink-converge-pre-action-observation-missing".to_string())?;
    object.insert(
        "observed_state".into(),
        serde_json::to_value(observed_preimage).map_err(|e| e.to_string())?,
    );
    object.insert(
        "desired_state".into(),
        json!({"kind":"symlink","link_target":request.source,"uid":desired_uid,"gid":desired_gid}),
    );
    object.insert("diff_decision".into(), json!(decision));
    object.insert(
        "movement".into(),
        movement
            .map(|m| json!({"ok":m.ok,"changed":m.changed,"skipped":m.skipped,"message":m.message}))
            .unwrap_or_else(|| json!("none")),
    );
    object.insert("truthful_changed".into(), json!(outcome.changed));
    crate::atoms::attest::make_link::write_existing(&path, &receipt)?;
    Ok(outcome)
}

fn symlink_converge_action(
    authorization: &crate::atoms::comparison::ActionAuthorization,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
    request: &SymlinkConvergeRequest,
    receipt_dir: &Path,
    apply: bool,
    central_attested: &Cell<bool>,
    movement_attempted: &Cell<bool>,
) -> Result<crate::OperationOutcome, String> {
    validate_receipt_name(&request.receipt_name)?;
    let mut declared_args = BTreeMap::new();
    declared_args.insert("source".to_string(), json!(request.source));
    declared_args.insert("target".to_string(), json!(request.target));
    declared_args.insert(
        "required_source_kind".to_string(),
        json!(request.required_source_kind),
    );
    declared_args.insert(
        "conflict_policy".to_string(),
        json!(request.conflict_policy),
    );
    if let Some(owner) = &request.owner {
        declared_args.insert("owner".to_string(), json!(owner));
    }
    if let Some(group) = &request.group {
        declared_args.insert("group".to_string(), json!(group));
    }
    validate_symlink_converge_args(&declared_args)?;

    let before = crate::atoms::files::observe_symlink_path(&request.target)?;
    let source_before =
        crate::atoms::files::read_symlink_source(&request.source, request.required_source_kind);
    let source_before_receipt = source_before.as_ref().ok().cloned();
    let desired_uid = request
        .owner
        .as_deref()
        .map(resolve_uid)
        .transpose()
        .map_err(|error| format!("symlink-converge-owner-resolution-failed: {error}"))?;
    let desired_gid = request
        .group
        .as_deref()
        .map(resolve_gid)
        .transpose()
        .map_err(|error| format!("symlink-converge-group-resolution-failed: {error}"))?;

    let finish = |ok: bool,
                  changed: bool,
                  would_change: bool,
                  blocker: &str,
                  after: Option<&SymlinkPathIdentity>,
                  source_after: Option<&SymlinkSourceIdentity>|
     -> Result<crate::OperationOutcome, String> {
        crate::atoms::attest::prepare_receipt_parent(receipt_dir).map_err(|error| {
            format!(
                "symlink-converge-receipt-dir-failed {}: {error}",
                receipt_dir.display()
            )
        })?;
        let typed_receipt = crate::atoms::Receipt {
            atom: "symlink-converge".into(),
            ok,
            drift: crate::atoms::Drift::Current,
            message: format!(
                "source={} target={} diff=different movement={} changed={} blocker={} before={} after={} source_before={} source_after={}",
                request.source.display(),
                request.target.display(),
                if !apply {
                    "report-only"
                } else if movement_attempted.get() {
                    "attempted"
                } else {
                    "none"
                },
                changed,
                if ok { "none" } else { blocker },
                receipt_identity(Some(&before)),
                receipt_identity(after),
                receipt_identity(source_before_receipt.as_ref()),
                receipt_identity(source_after)
            ),
        };
        crate::atoms::attest::attest(&receipt_dir.join("atoms.jsonl"), &typed_receipt, &[])?;
        central_attested.set(true);
        crate::atoms::attest::make_link::write_existing(
            &receipt_dir.join(format!("{}.json", request.receipt_name)),
            &json!({
                "schema": "harmonia.files.symlink_converge.v1",
                "ok": ok,
                "apply": apply,
                "changed": changed,
                "would_change": would_change,
                "source": request.source,
                "target": request.target,
                "required_source_kind": request.required_source_kind,
                "conflict_policy": request.conflict_policy,
                "owner": request.owner,
                "group": request.group,
                "desired_uid": desired_uid,
                "desired_gid": desired_gid,
                "source_before": source_before_receipt.as_ref(),
                "source_after": source_after,
                "source_identity_stable": source_before_receipt.as_ref().zip(source_after).map(|(a, b)| a == b).unwrap_or(false),
                "before": before,
                "after": after,
                "final_readlink": after.and_then(|identity| identity.link_target.as_ref()),
                "first_missing_signal": blocker,
            }),
        )?;
        Ok(crate::OperationOutcome {
            ok,
            changed,
            skipped: !apply,
            message: format!(
                "{blocker} source={} target={}",
                request.source.display(),
                request.target.display()
            ),
            command: None,
        })
    };
    let finish_after_observation = |ok: bool,
                                    changed: bool,
                                    would_change: bool,
                                    blocker: &str,
                                    source_after: Option<&SymlinkSourceIdentity>|
     -> Result<crate::OperationOutcome, String> {
        match crate::atoms::files::observe_symlink_path(&request.target) {
            Ok(after) => finish(
                ok,
                changed,
                would_change,
                blocker,
                Some(&after),
                source_after,
            ),
            Err(error) => {
                let blocker =
                    format!("{blocker}; symlink-converge-target-observation-failed: {error}");
                finish(false, changed, would_change, &blocker, None, source_after)
            }
        }
    };

    let source_before = match source_before {
        Ok(identity) => identity,
        Err(blocker) => return finish_after_observation(false, false, false, &blocker, None),
    };
    let ownership_current = desired_uid.map_or(true, |uid| before.uid == Some(uid))
        && desired_gid.map_or(true, |gid| before.gid == Some(gid));
    let exact_link = before.kind == "symlink"
        && before.link_target.as_deref() == Some(request.source.as_path())
        && ownership_current;
    if exact_link {
        let source_after = match crate::atoms::files::read_symlink_source(
            &request.source,
            request.required_source_kind,
        ) {
            Ok(identity) => identity,
            Err(blocker) => {
                return finish_after_observation(false, false, false, &blocker, None);
            }
        };
        let after = match crate::atoms::files::observe_symlink_path(&request.target) {
            Ok(after) => after,
            Err(blocker) => {
                return finish(false, false, false, &blocker, None, Some(&source_after))
            }
        };
        let target_stable = after.kind == "symlink"
            && after.link_target.as_deref() == Some(request.source.as_path())
            && desired_uid.map_or(true, |uid| after.uid == Some(uid))
            && desired_gid.map_or(true, |gid| after.gid == Some(gid));
        let source_stable = source_before == source_after;
        let stable = target_stable && source_stable;
        return finish(
            stable,
            false,
            false,
            if stable {
                "none"
            } else if !source_stable {
                "symlink-converge-source-changed-during-readback"
            } else {
                "symlink-converge-target-changed-during-readback"
            },
            Some(&after),
            Some(&source_after),
        );
    }

    let conflict_blocker = match before.kind.as_str() {
        "regular-file" if request.conflict_policy != SymlinkConflictPolicy::ReplaceRegularFile => {
            Some("symlink-converge-target-regular-file-refused")
        }
        "directory" if request.conflict_policy != SymlinkConflictPolicy::ReplaceEmptyDirectory => {
            Some("symlink-converge-target-directory-refused")
        }
        "other" => Some("symlink-converge-target-kind-refused"),
        _ => None,
    };
    if let Some(blocker) = conflict_blocker {
        let source_after =
            crate::atoms::files::read_symlink_source(&request.source, request.required_source_kind)
                .ok();
        return finish_after_observation(false, false, true, blocker, source_after.as_ref());
    }
    if before.kind == "directory"
        && fs::read_dir(&request.target)
            .map_err(|error| {
                format!(
                    "symlink-converge-target-directory-read-failed {}: {error}",
                    request.target.display()
                )
            })?
            .next()
            .is_some()
    {
        let source_after =
            crate::atoms::files::read_symlink_source(&request.source, request.required_source_kind)
                .ok();
        return finish_after_observation(
            false,
            false,
            true,
            "symlink-converge-target-directory-not-empty-refused",
            source_after.as_ref(),
        );
    }
    if !apply {
        let after = match crate::atoms::files::observe_symlink_path(&request.target) {
            Ok(after) => after,
            Err(blocker) => return finish(false, false, true, &blocker, None, None),
        };
        let source_after = match crate::atoms::files::read_symlink_source(
            &request.source,
            request.required_source_kind,
        ) {
            Ok(source_after) => source_after,
            Err(blocker) => return finish(false, false, true, &blocker, Some(&after), None),
        };
        let stable = source_before == source_after;
        return finish(
            stable,
            false,
            true,
            if stable {
                "none"
            } else {
                "symlink-converge-source-changed-during-readback"
            },
            Some(&after),
            Some(&source_after),
        );
    }

    let invocation = invocation.ok_or("symlink-converge-invocation-missing")?;

    let parent = request.target.parent().ok_or_else(|| {
        format!(
            "symlink-converge-target-parent-missing {}",
            request.target.display()
        )
    })?;
    if !parent.is_dir() {
        return finish_after_observation(
            false,
            false,
            true,
            "symlink-converge-target-parent-missing",
            Some(&source_before),
        );
    }
    let source_pre_stage = match crate::atoms::files::read_symlink_source(
        &request.source,
        request.required_source_kind,
    ) {
        Ok(identity) => identity,
        Err(blocker) => {
            return finish_after_observation(false, false, true, &blocker, None);
        }
    };
    if source_pre_stage != source_before {
        return finish_after_observation(
            false,
            false,
            true,
            "symlink-converge-source-changed-before-stage",
            Some(&source_pre_stage),
        );
    }
    movement_attempted.set(true);
    let candidate = match stage(
        authorization,
        invocation,
        &request.source,
        &request.target,
        desired_uid,
        desired_gid,
    ) {
        Ok(candidate) => candidate,
        Err(blocker) => {
            return finish_after_observation(false, false, true, &blocker, Some(&source_before))
        }
    };
    let source_pre_promote = match crate::atoms::files::read_symlink_source(
        &request.source,
        request.required_source_kind,
    ) {
        Ok(identity) => identity,
        Err(blocker) => {
            let _ = crate::atoms::r#do::symlink_converge::remove_file(
                authorization,
                invocation,
                &candidate,
            );
            return finish_after_observation(false, false, true, &blocker, None);
        }
    };
    if source_pre_promote != source_before {
        let _ = crate::atoms::r#do::symlink_converge::remove_file(
            authorization,
            invocation,
            &candidate,
        );
        return finish_after_observation(
            false,
            false,
            true,
            "symlink-converge-source-changed-before-promote",
            Some(&source_pre_promote),
        );
    }
    if let Err(blocker) = promote_staged_symlink(
        authorization,
        invocation,
        &candidate,
        &request.target,
        &before,
    ) {
        match crate::atoms::files::observe_symlink_path(&request.target) {
            Ok(after) => {
                return finish(
                    false,
                    after != before,
                    true,
                    &blocker,
                    Some(&after),
                    Some(&source_before),
                )
            }
            Err(observation_error) => {
                let blocker = format!(
                    "{blocker}; symlink-converge-target-observation-failed: {observation_error}"
                );
                write_blocked_receipt(
                    request,
                    receipt_dir,
                    apply,
                    desired_uid,
                    desired_gid,
                    &blocker,
                    Some(&before),
                    Some(&source_before),
                    true,
                    true,
                )?;
                central_attested.set(true);
                return Err(blocker);
            }
        }
    }
    if let Err(error) =
        crate::atoms::r#do::symlink_converge::sync_parent(authorization, invocation, parent)
    {
        let blocker = format!("symlink-converge-parent-sync-failed: {error}");
        return finish_after_observation(false, true, true, &blocker, Some(&source_before));
    }
    let after = match crate::atoms::files::observe_symlink_path(&request.target) {
        Ok(identity) => identity,
        Err(blocker) => return finish(false, true, true, &blocker, None, Some(&source_before)),
    };
    let source_after = match crate::atoms::files::read_symlink_source(
        &request.source,
        request.required_source_kind,
    ) {
        Ok(identity) => identity,
        Err(blocker) => return finish(false, true, true, &blocker, Some(&after), None),
    };
    let final_ok = after.kind == "symlink"
        && after.link_target.as_deref() == Some(request.source.as_path())
        && desired_uid.map_or(true, |uid| after.uid == Some(uid))
        && desired_gid.map_or(true, |gid| after.gid == Some(gid))
        && source_before == source_after;
    finish(
        final_ok,
        true,
        true,
        if final_ok {
            "none"
        } else {
            "symlink-converge-final-readback-failed"
        },
        Some(&after),
        Some(&source_after),
    )
}
