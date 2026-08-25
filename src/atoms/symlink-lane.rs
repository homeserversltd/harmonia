//! Extracted symlink lane compatibility seat.

use std::path::Path;

// Operation-semantic symlink actuator seat owned by the files tool.
pub(crate) fn make_link(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: crate::atoms::r#do::InvocationKey,
    target: &Path,
    link: &Path,
) -> Result<(), String> {
    crate::atoms::r#do::make_link::symlink(authorization, invocation, target, link)
}

use serde_json::json;
use std::collections::BTreeMap;
use std::fs::{self, File};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

use crate::atoms::comparison::ActionAuthorization;
use crate::atoms::files::{
    resolve_gid, resolve_uid, validate_receipt_name, validate_symlink_converge_args,
    SymlinkConflictPolicy, SymlinkConvergeRequest, SymlinkPathIdentity, SymlinkSourceIdentity,
    SymlinkSourceKind,
};

fn observe_symlink_path(path: &Path) -> Result<SymlinkPathIdentity, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            let kind = if file_type.is_symlink() {
                "symlink"
            } else if file_type.is_file() {
                "regular-file"
            } else if file_type.is_dir() {
                "directory"
            } else {
                "other"
            };
            let link_target = if file_type.is_symlink() {
                Some(fs::read_link(path).map_err(|error| {
                    format!(
                        "symlink-converge-readlink-failed {}: {error}",
                        path.display()
                    )
                })?)
            } else {
                None
            };
            Ok(SymlinkPathIdentity {
                kind: kind.to_string(),
                link_target,
                mode: Some(metadata.permissions().mode() & 0o7777),
                uid: Some(metadata.uid()),
                gid: Some(metadata.gid()),
                device: Some(metadata.dev()),
                inode: Some(metadata.ino()),
                size: Some(metadata.size()),
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(SymlinkPathIdentity {
            kind: "absent".to_string(),
            link_target: None,
            mode: None,
            uid: None,
            gid: None,
            device: None,
            inode: None,
            size: None,
        }),
        Err(error) => Err(format!(
            "symlink-converge-target-observation-failed {}: {error}",
            path.display()
        )),
    }
}

#[cfg(not(unix))]
fn observe_symlink_path(_path: &Path) -> Result<SymlinkPathIdentity, String> {
    Err("symlink-converge-unsupported".to_string())
}

#[cfg(unix)]
fn read_symlink_source(
    path: &Path,
    required_kind: SymlinkSourceKind,
) -> Result<SymlinkSourceIdentity, String> {
    let file = crate::atoms::attest::open_nofollow_read(path).map_err(|error| {
        format!(
            "symlink-converge-source-open-failed {}: {error}",
            path.display()
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        format!(
            "symlink-converge-source-readback-failed {}: {error}",
            path.display()
        )
    })?;
    match required_kind {
        SymlinkSourceKind::RegularExecutable => {
            if !metadata.file_type().is_file() {
                return Err(format!(
                    "symlink-converge-source-kind-mismatch {} expected=regular-executable",
                    path.display()
                ));
            }
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(format!(
                    "symlink-converge-source-not-executable {}",
                    path.display()
                ));
            }
        }
    }
    Ok(SymlinkSourceIdentity {
        kind: "regular-executable".to_string(),
        mode: metadata.permissions().mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        change_seconds: metadata.ctime(),
        change_nanoseconds: metadata.ctime_nsec(),
    })
}

#[cfg(not(unix))]
fn read_symlink_source(
    _path: &Path,
    _required_kind: SymlinkSourceKind,
) -> Result<SymlinkSourceIdentity, String> {
    Err("symlink-converge-unsupported".to_string())
}

#[cfg(unix)]
fn stage_symlink(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: crate::atoms::r#do::InvocationKey,
    source: &Path,
    target: &Path,
    _uid: Option<u32>,
    _gid: Option<u32>,
) -> Result<PathBuf, String> {
    crate::atoms::r#do::symlink_converge::stage(
        authorization,
        invocation,
        source,
        target,
        _uid,
        _gid,
    )
}

#[cfg(not(unix))]
fn stage_symlink(
    _authorization: crate::atoms::comparison::ActionAuthorization,
    _invocation: crate::atoms::r#do::InvocationKey,
    _source: &Path,
    _target: &Path,
    _uid: Option<u32>,
    _gid: Option<u32>,
) -> Result<PathBuf, String> {
    Err("symlink-converge-unsupported".to_string())
}

#[cfg(target_os = "linux")]
fn exchange_paths(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: crate::atoms::r#do::InvocationKey,
    left: &Path,
    right: &Path,
) -> Result<(), String> {
    crate::atoms::r#do::symlink_converge::exchange(authorization, invocation, left, right).map_err(
        |error| {
            format!(
                "symlink-converge-exchange-failed {}: {error}",
                right.display()
            )
        },
    )
}
#[cfg(target_os = "linux")]
fn rename_noreplace(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: crate::atoms::r#do::InvocationKey,
    left: &Path,
    right: &Path,
) -> Result<(), String> {
    crate::atoms::r#do::symlink_converge::rename_noreplace(authorization, invocation, left, right)
        .map_err(|error| format!("symlink-converge-create-raced {}: {error}", right.display()))
}

#[cfg(not(target_os = "linux"))]
fn exchange_paths(
    _authorization: crate::atoms::comparison::ActionAuthorization,
    _invocation: crate::atoms::r#do::InvocationKey,
    _left: &Path,
    _right: &Path,
) -> Result<(), String> {
    Err("symlink-converge-exchange-unsupported".to_string())
}

#[cfg(not(target_os = "linux"))]
fn rename_noreplace(
    _authorization: crate::atoms::comparison::ActionAuthorization,
    _invocation: crate::atoms::r#do::InvocationKey,
    _left: &Path,
    _right: &Path,
) -> Result<(), String> {
    Err("symlink-converge-noreplace-unsupported".to_string())
}

fn promote_staged_symlink(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: crate::atoms::r#do::InvocationKey,
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

    if let Err(error) = exchange_paths(authorization, invocation, candidate, target) {
        let _ =
            crate::atoms::r#do::symlink_converge::remove_file(authorization, invocation, candidate);
        return Err(error);
    }
    let exchanged = observe_symlink_path(candidate);
    let prior_matches = exchanged.as_ref().is_ok_and(|identity| identity == before);
    let directory_still_empty = before.kind != "directory"
        || fs::read_dir(candidate)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(false);
    if !prior_matches || !directory_still_empty {
        let rollback = exchange_paths(authorization, invocation, candidate, target);
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

#[derive(Debug, Clone)]
struct SymlinkComparisonObservation {
    before: SymlinkPathIdentity,
    source: Result<SymlinkSourceIdentity, String>,
    desired_uid: Option<u32>,
    desired_gid: Option<u32>,
}

fn symlink_diff_decision(
    observation: &SymlinkComparisonObservation,
    request: &SymlinkConvergeRequest,
) -> crate::atoms::comparison::DiffDecision {
    let ownership_current = observation
        .desired_uid
        .map_or(true, |uid| observation.before.uid == Some(uid))
        && observation
            .desired_gid
            .map_or(true, |gid| observation.before.gid == Some(gid));
    let exact = observation.before.kind == "symlink"
        && observation.before.link_target.as_deref() == Some(request.source.as_path())
        && ownership_current
        && observation.source.is_ok();
    if exact {
        crate::atoms::comparison::DiffDecision::Empty
    } else {
        crate::atoms::comparison::DiffDecision::Different
    }
}

pub(crate) fn symlink_converge(
    request: &SymlinkConvergeRequest,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
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
                before: observe_symlink_path(&request.target)?,
                source: read_symlink_source(&request.source, request.required_source_kind),
                desired_uid,
                desired_gid,
            })
        },
        |observation| symlink_diff_decision(observation, request),
        |authorization, _| {
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
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
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

    let before = observe_symlink_path(&request.target)?;
    let source_before = read_symlink_source(&request.source, request.required_source_kind);
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
            let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
            return finish(false, false, false, &blocker, &after, None);
        }
    };
    let ownership_current = desired_uid.map_or(true, |uid| before.uid == Some(uid))
        && desired_gid.map_or(true, |gid| before.gid == Some(gid));
    let exact_link = before.kind == "symlink"
        && before.link_target.as_deref() == Some(request.source.as_path())
        && ownership_current;
    if exact_link {
        let source_after = match read_symlink_source(&request.source, request.required_source_kind)
        {
            Ok(identity) => identity,
            Err(blocker) => {
                let after =
                    observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
                return finish(false, false, false, &blocker, &after, None);
            }
        };
        let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
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
        let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
        let source_after = read_symlink_source(&request.source, request.required_source_kind).ok();
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
        let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
        let source_after = read_symlink_source(&request.source, request.required_source_kind).ok();
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
        let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
        let source_after = read_symlink_source(&request.source, request.required_source_kind)?;
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
    let source_pre_stage = match read_symlink_source(&request.source, request.required_source_kind)
    {
        Ok(identity) => identity,
        Err(blocker) => {
            let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
            return finish(false, false, true, &blocker, &after, None);
        }
    };
    if source_pre_stage != source_before {
        let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
        return finish(
            false,
            false,
            true,
            "symlink-converge-source-changed-before-stage",
            &after,
            Some(&source_pre_stage),
        );
    }
    let candidate = match stage_symlink(
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
    let source_pre_promote =
        match read_symlink_source(&request.source, request.required_source_kind) {
            Ok(identity) => identity,
            Err(blocker) => {
                let _ = crate::atoms::r#do::symlink_converge::remove_file(
                    authorization,
                    invocation,
                    &candidate,
                );
                let after =
                    observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
                return finish(false, false, true, &blocker, &after, None);
            }
        };
    if source_pre_promote != source_before {
        let _ = crate::atoms::r#do::symlink_converge::remove_file(
            authorization,
            invocation,
            &candidate,
        );
        let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
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
        let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
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
        let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
        return finish(
            false,
            true,
            true,
            &format!("symlink-converge-parent-sync-failed: {error}"),
            &after,
            Some(&source_before),
        );
    }
    let after = match observe_symlink_path(&request.target) {
        Ok(identity) => identity,
        Err(blocker) => return finish(false, true, true, &blocker, &before, Some(&source_before)),
    };
    let source_after = match read_symlink_source(&request.source, request.required_source_kind) {
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

pub(crate) fn validated_symlink(
    receipt_dir: &Path,
    name: &str,
    source: &Path,
    target: &Path,
    validator_program: &str,
    validator_args: &[String],
    reload_program: Option<&str>,
    reload_args: &[String],
    timeout_secs: u64,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<crate::OperationOutcome, String> {
    crate::atoms::r#do::make_symlink::execute(
        crate::atoms::r#do::make_symlink::ValidatedFileSymlinkRequest {
            receipt_dir,
            name,
            desired_source: source,
            source,
            target,
            validator_program,
            validator_args,
            reload_program,
            reload_args,
            timeout_secs,
            apply,
        },
        invocation,
    )
}
