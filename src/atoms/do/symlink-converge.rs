//! Authorized filesystem mutation owners for symlink convergence.

use crate::atoms::comparison::ActionAuthorization;
use crate::atoms::files::{
    resolve_gid, resolve_uid, symlink_diff_decision, validate_receipt_name,
    validate_symlink_converge_args, SymlinkComparisonObservation, SymlinkConflictPolicy,
    SymlinkConvergeRequest, SymlinkPathIdentity, SymlinkSourceIdentity,
};
use crate::atoms::r#do::InvocationKey;
use serde_json::json;
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
    let observation = crate::atoms::comparison::execute(
        "files",
        || {
            Ok::<_, String>(SymlinkComparisonObservation {
                before: crate::atoms::files::observe_symlink_path(&request.target)?,
                source: crate::atoms::files::read_symlink_source(
                    &request.source,
                    request.required_source_kind,
                ),
                desired_uid,
                desired_gid,
            })
        },
        |observation| symlink_diff_decision(observation, request),
        |authorization, _| {
            let authorization = &authorization;
            symlink_converge_action(authorization, invocation, request, receipt_dir, apply)
        },
    )?;
    let decision = match observation.decision() {
        crate::atoms::comparison::DiffDecision::Empty => "empty",
        crate::atoms::comparison::DiffDecision::Different => "different",
    };
    let movement = match &observation {
        crate::atoms::comparison::ComparisonRun::Current { .. } => None,
        crate::atoms::comparison::ComparisonRun::Moved { movement, .. } => Some(movement),
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
    let path = receipt_dir.join(format!("{}.json", request.receipt_name));
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
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
    object.insert(
        "observed_state".into(),
        serde_json::to_value(&observation.observation().before).map_err(|e| e.to_string())?,
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
    crate::atoms::attest::write_json_atomic(&path, &receipt)?;
    Ok(outcome)
}

fn symlink_converge_action(
    authorization: &crate::atoms::comparison::ActionAuthorization,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
    request: &SymlinkConvergeRequest,
    receipt_dir: &Path,
    apply: bool,
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
                  after: &SymlinkPathIdentity,
                  source_after: Option<&SymlinkSourceIdentity>|
     -> Result<crate::OperationOutcome, String> {
        crate::atoms::attest::prepare_receipt_parent(receipt_dir).map_err(|error| {
            format!(
                "symlink-converge-receipt-dir-failed {}: {error}",
                receipt_dir.display()
            )
        })?;
        crate::atoms::attest::write_json_atomic(
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
                "final_readlink": after.link_target,
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

    let source_before = match source_before {
        Ok(identity) => identity,
        Err(blocker) => {
            let after = crate::atoms::files::observe_symlink_path(&request.target)
                .unwrap_or_else(|_| before.clone());
            return finish(false, false, false, &blocker, &after, None);
        }
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
                let after = crate::atoms::files::observe_symlink_path(&request.target)
                    .unwrap_or_else(|_| before.clone());
                return finish(false, false, false, &blocker, &after, None);
            }
        };
        let after = crate::atoms::files::observe_symlink_path(&request.target)
            .unwrap_or_else(|_| before.clone());
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
            &after,
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
        let after = crate::atoms::files::observe_symlink_path(&request.target)
            .unwrap_or_else(|_| before.clone());
        let source_after =
            crate::atoms::files::read_symlink_source(&request.source, request.required_source_kind)
                .ok();
        return finish(false, false, true, blocker, &after, source_after.as_ref());
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
        let after = crate::atoms::files::observe_symlink_path(&request.target)
            .unwrap_or_else(|_| before.clone());
        let source_after =
            crate::atoms::files::read_symlink_source(&request.source, request.required_source_kind)
                .ok();
        return finish(
            false,
            false,
            true,
            "symlink-converge-target-directory-not-empty-refused",
            &after,
            source_after.as_ref(),
        );
    }
    if !apply {
        let after = crate::atoms::files::observe_symlink_path(&request.target)
            .unwrap_or_else(|_| before.clone());
        let source_after = crate::atoms::files::read_symlink_source(
            &request.source,
            request.required_source_kind,
        )?;
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
            &after,
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
        return finish(
            false,
            false,
            true,
            "symlink-converge-target-parent-missing",
            &before,
            Some(&source_before),
        );
    }
    let source_pre_stage = match crate::atoms::files::read_symlink_source(
        &request.source,
        request.required_source_kind,
    ) {
        Ok(identity) => identity,
        Err(blocker) => {
            let after = crate::atoms::files::observe_symlink_path(&request.target)
                .unwrap_or_else(|_| before.clone());
            return finish(false, false, true, &blocker, &after, None);
        }
    };
    if source_pre_stage != source_before {
        let after = crate::atoms::files::observe_symlink_path(&request.target)
            .unwrap_or_else(|_| before.clone());
        return finish(
            false,
            false,
            true,
            "symlink-converge-source-changed-before-stage",
            &after,
            Some(&source_pre_stage),
        );
    }
    let candidate = match stage(
        authorization,
        invocation,
        &request.source,
        &request.target,
        desired_uid,
        desired_gid,
    ) {
        Ok(candidate) => candidate,
        Err(blocker) => return finish(false, false, true, &blocker, &before, Some(&source_before)),
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
            let after = crate::atoms::files::observe_symlink_path(&request.target)
                .unwrap_or_else(|_| before.clone());
            return finish(false, false, true, &blocker, &after, None);
        }
    };
    if source_pre_promote != source_before {
        let _ = crate::atoms::r#do::symlink_converge::remove_file(
            authorization,
            invocation,
            &candidate,
        );
        let after = crate::atoms::files::observe_symlink_path(&request.target)
            .unwrap_or_else(|_| before.clone());
        return finish(
            false,
            false,
            true,
            "symlink-converge-source-changed-before-promote",
            &after,
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
        let after = crate::atoms::files::observe_symlink_path(&request.target)
            .unwrap_or_else(|_| before.clone());
        return finish(
            false,
            after != before,
            true,
            &blocker,
            &after,
            Some(&source_before),
        );
    }
    if let Err(error) =
        crate::atoms::r#do::symlink_converge::sync_parent(authorization, invocation, parent)
    {
        let after = crate::atoms::files::observe_symlink_path(&request.target)
            .unwrap_or_else(|_| before.clone());
        return finish(
            false,
            true,
            true,
            &format!("symlink-converge-parent-sync-failed: {error}"),
            &after,
            Some(&source_before),
        );
    }
    let after = match crate::atoms::files::observe_symlink_path(&request.target) {
        Ok(identity) => identity,
        Err(blocker) => return finish(false, true, true, &blocker, &before, Some(&source_before)),
    };
    let source_after = match crate::atoms::files::read_symlink_source(
        &request.source,
        request.required_source_kind,
    ) {
        Ok(identity) => identity,
        Err(blocker) => return finish(false, true, true, &blocker, &after, None),
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
        &after,
        Some(&source_after),
    )
}
