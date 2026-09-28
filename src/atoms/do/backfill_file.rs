//! Authorized backfill mutation orchestration.
#![allow(dead_code)]
pub(crate) use crate::atoms::ask::backfill_file::{
    resolve_ownership, BackfillFileMovement, BackfillFileObservation, BackfillFileOutcome,
    BackupPolicy, DeclaredOwnership, HotfixFileBackfillOutcome,
};

pub(crate) struct BackfillFileRequest<'a> {
    pub path: &'a Path,
    pub declared_bytes: &'a [u8],
    pub mode: Option<u32>,
    pub ownership: DeclaredOwnership,
    pub backup: BackupPolicy<'a>,
    pub invocation: Option<&'a atoms::r#do::InvocationKey>,
}
use crate::atoms::files::{
    reject_ssh_path, resolve_gid, resolve_uid, source_mode, validate_receipt_name, validate_specs,
    FileConvergenceEntry, FileConvergenceOutcome, FileConvergenceRequest,
};
use crate::atoms::r#do::make_dir::create_dir_all as make_dir;
use crate::atoms::{self, Drift, Receipt};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
pub(crate) fn execute(request: BackfillFileRequest<'_>) -> Result<BackfillFileOutcome, String> {
    crate::atoms::ask::backfill_file::validate_target(request.path)?;
    let backup_path = match request.backup {
        BackupPolicy::Observed(path) => Some(path),
        BackupPolicy::None => None,
    };
    let run = crate::atoms::declaration::execute(
        "backfill-file",
        "backfill-file",
        || {
            crate::atoms::ask::backfill_file::probe::file(
                request.path,
                request.declared_bytes,
                request.mode,
                request.ownership,
                backup_path,
            )
        },
        |observation| {
            if observation.current() {
                crate::atoms::comparison::DiffDecision::Empty
            } else {
                crate::atoms::comparison::DiffDecision::Different
            }
        },
        |authorization, observation| {
            let authorization = &authorization;
            let Some(invocation) = request.invocation else {
                return Ok(BackfillFileMovement::default());
            };
            mutation::place(
                authorization,
                &invocation,
                request.path,
                request.declared_bytes,
                request.mode,
                request.ownership,
                mutation::BackfillFileAction {
                    bytes: !observation.bytes_equal,
                    mode: !observation.mode_equal,
                    owner: !observation.owner_equal || !observation.group_equal,
                    created: !observation.existed,
                    backup_to: match request.backup {
                        BackupPolicy::Observed(path)
                            if observation.existed
                                && (!observation.bytes_equal
                                    || !observation.mode_equal
                                    || !observation.owner_equal
                                    || !observation.group_equal) =>
                        {
                            Some(path)
                        }
                        BackupPolicy::None | BackupPolicy::Observed(_) => None,
                    },
                    backup_exists: observation.backup_exists,
                    existing_target_needs_change: observation.existed
                        && (!observation.bytes_equal
                            || !observation.mode_equal
                            || !observation.owner_equal
                            || !observation.group_equal),
                },
            )
        },
    )?;
    let movement = match &run {
        crate::atoms::comparison::ComparisonRun::Current { .. } => BackfillFileMovement::default(),
        crate::atoms::comparison::ComparisonRun::Moved { movement, .. } => movement.clone(),
    };
    let observation = if movement.changed() {
        let post_action = crate::atoms::ask::backfill_file::probe::file(
            request.path,
            request.declared_bytes,
            request.mode,
            request.ownership,
            backup_path,
        )
        .map_err(|_| format!("backfill-file-readback-failed {}", request.path.display()))?;
        if !post_action.current() {
            return Err(format!(
                "backfill-file-readback-failed {}",
                request.path.display()
            ));
        }
        post_action
    } else {
        run.observation().clone()
    };
    let drift = if observation.current() {
        Drift::Current
    } else {
        Drift::File {
            expected_sha256: atoms::file_sha256(request.declared_bytes),
            actual_sha256: if observation.regular {
                crate::atoms::ask::file_if_present(request.path)?
                    .map(|observation| atoms::file_sha256(&observation.bytes))
            } else {
                None
            },
        }
    };
    let receipt = receipt::receipt(request.path, drift, &movement);
    let hotfix_receipt = receipt::hotfix_receipt(request.path, movement.changed());
    Ok(BackfillFileOutcome {
        observation,
        movement,
        receipt,
        hotfix_receipt,
    })
}

pub(crate) fn observe_predicate(
    predicate: Option<&serde_json::Value>,
    payload: Option<&serde_json::Value>,
) -> Result<(bool, serde_json::Value), String> {
    crate::atoms::ask::backfill_file::probe::predicate(predicate, payload)
}

pub fn declaration() -> Result<Option<&'static crate::atoms::declaration::Declaration>, String> {
    crate::atoms::declaration::get("backfill-file")
}

mod mutation {
    use super::*;
    use crate::atoms::comparison::ActionAuthorization;

    pub(super) struct BackfillFileAction<'a> {
        pub bytes: bool,
        pub mode: bool,
        pub owner: bool,
        pub created: bool,
        pub backup_to: Option<&'a Path>,
        pub backup_exists: bool,
        pub existing_target_needs_change: bool,
    }

    pub(super) fn place(
        authorization: &ActionAuthorization,
        invocation: &atoms::r#do::InvocationKey,
        path: &Path,
        declared_bytes: &[u8],
        declared_mode: Option<u32>,
        ownership: DeclaredOwnership,
        action: BackfillFileAction<'_>,
    ) -> Result<BackfillFileMovement, String> {
        if action.existing_target_needs_change && action.backup_exists {
            let path = action.backup_to.expect("backup path for existing target");
            return Err(format!("backfill-file-backup-exists {}", path.display()));
        }
        let result = atoms::r#do::write_file::file_write(
            authorization,
            invocation,
            path,
            declared_bytes,
            atoms::r#do::write_file::FileWriteOptions {
                write_bytes: action.bytes,
                mode: if action.bytes {
                    declared_mode
                } else {
                    action.mode.then_some(declared_mode).flatten()
                },
                uid: if action.bytes {
                    ownership.uid
                } else {
                    action.owner.then_some(ownership.uid).flatten()
                },
                gid: if action.bytes {
                    ownership.gid
                } else {
                    action.owner.then_some(ownership.gid).flatten()
                },
                backup_to: action.backup_to,
            },
        )?;
        Ok(BackfillFileMovement {
            bytes: action.bytes,
            mode: action.mode,
            owner: action.owner,
            created: action.created,
            backed_up: result.backed_up,
        })
    }
}

mod receipt {
    use super::*;

    pub(super) fn receipt(path: &Path, drift: Drift, movement: &BackfillFileMovement) -> Receipt {
        Receipt {
            atom: "backfill-file".into(),
            ok: true,
            drift,
            message: format!(
                "path={}; bytes={}; mode={}; owner={}; created={}; backed_up={}",
                path.display(),
                movement.bytes,
                movement.mode,
                movement.owner,
                movement.created,
                movement
                    .backed_up
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default()
            ),
        }
    }

    pub(super) fn hotfix_receipt(path: &Path, changed: bool) -> HotfixFileBackfillOutcome {
        HotfixFileBackfillOutcome {
            ok: true,
            changed,
            target_path: path.to_path_buf(),
            movement: "atomic-file-backfill".into(),
        }
    }
}

use crate::atoms::files::{
    classify_target, ownership_equal, target_mode, ManagedFilesRequest, TargetClass,
};
use sha2::{Digest, Sha256};

use crate::atoms::ask::write_file::ManagedFileObservation;

#[derive(Debug, Clone, Copy)]
enum ManagedFileMovement {
    ReportOnly,
    ContentModeAndOwnership,
    Ownership,
}

impl ManagedFileMovement {
    fn as_str(self) -> &'static str {
        match self {
            Self::ReportOnly => "report-only",
            Self::ContentModeAndOwnership => "atomic-write-chmod-chown",
            Self::Ownership => "chown",
        }
    }
}

pub(crate) fn converge_managed_files(
    request: &ManagedFilesRequest<'_>,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<crate::OperationOutcome, String> {
    validate_receipt_name(request.receipt_name)?;
    let classes = request
        .files
        .iter()
        .map(|file| classify_target(Path::new(&file.path)))
        .collect::<Vec<_>>();
    if let Some(reason) = classes.iter().find_map(|class| match class {
        TargetClass::Refused(reason) => Some(reason.clone()),
        _ => None,
    }) {
        return Err(reason);
    }
    let apply = apply
        && classes
            .iter()
            .all(|class| matches!(class, TargetClass::Software));
    for file in request.files {
        reject_ssh_path(Path::new(&file.path))?;
    }
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
    let mut drift = Vec::new();
    let mut written = Vec::new();
    let mut changed = false;
    let mut entries: Vec<crate::atoms::attest::write_file::ManagedFileEntry> = Vec::new();
    let desired_uid = request.owner.map(resolve_uid).transpose()?;
    let desired_gid = request.group.map(resolve_gid).transpose()?;
    for file in request.files {
        let desired = file.content.as_bytes();
        let run = match crate::atoms::comparison::execute_mode(
            "files",
            || {
                let path = PathBuf::from(&file.path);
                let mode = file.mode.unwrap_or(0o644);
                crate::atoms::ask::write_file::managed(
                    &path,
                    desired,
                    mode,
                    desired_uid,
                    desired_gid,
                )
            },
            |observation| {
                if observation.file_changed() {
                    crate::atoms::comparison::DiffDecision::Different
                } else {
                    crate::atoms::comparison::DiffDecision::Empty
                }
            },
            |authorization, observation| {
                let authorization = &authorization;
                if !apply || !observation.target_exists_before {
                    return Ok(ManagedFileMovement::ReportOnly);
                }
                let key = invocation.ok_or("managed-file-invocation-missing")?;
                if !observation.parent_is_dir {
                    let parent = observation
                        .path
                        .parent()
                        .ok_or("managed-file-parent-missing")?;
                    make_dir(authorization, key, parent)?;
                }
                if !observation.content_equal || !observation.mode_equal {
                    crate::atoms::r#do::write_file::atomic_write_bytes_with_ownership(
                        authorization,
                        key,
                        &observation.path,
                        desired,
                        Some(observation.mode),
                        desired_uid,
                        desired_gid,
                    )?;
                } else if !observation.owner_equal || !observation.group_equal {
                    crate::atoms::r#do::change_owner::change(
                        authorization,
                        key,
                        &crate::atoms::r#do::change_owner::Plan {
                            path: observation.path.clone(),
                            uid: desired_uid,
                            gid: desired_gid,
                            no_follow: true,
                        },
                    )?;
                }
                let readback = crate::atoms::ask::write_file::managed(
                    &observation.path,
                    desired,
                    observation.mode,
                    desired_uid,
                    desired_gid,
                )?;
                if !readback.owner_equal || !readback.group_equal {
                    return Err(format!(
                        "managed-file-owner-readback-failed {}",
                        observation.path.display()
                    ));
                }
                Ok(if !observation.content_equal || !observation.mode_equal {
                    ManagedFileMovement::ContentModeAndOwnership
                } else {
                    ManagedFileMovement::Ownership
                })
            },
            apply,
        ) {
            Ok(run) => run,
            Err(error) => {
                let safe_name = file
                    .path
                    .replace('/', "_")
                    .trim_start_matches('_')
                    .to_string();
                let per_file = receipt_dir.join(format!(
                    "{}-{}.json",
                    request.receipt_name.trim_end_matches(".json"),
                    safe_name
                ));
                crate::atoms::attest::write_file::write_managed_error(
                    receipt_dir,
                    &per_file,
                    crate::atoms::attest::write_file::ManagedError {
                        module: request.module_id.to_string(),
                        path: file.path.clone(),
                        apply,
                        error: error.clone(),
                    },
                )?;
                return Err(error);
            }
        };
        let observation = run.observation();
        let file_changed = observation.file_changed();
        let target_absent = !observation.target_exists_before;
        let target_exists_before = observation.target_exists_before;
        let mode = observation.mode;
        let content_equal = observation.content_equal;
        let mode_equal = observation.mode_equal;
        let owner_equal = observation.owner_equal;
        let group_equal = observation.group_equal;
        let diff_decision = match run.decision() {
            crate::atoms::comparison::DiffDecision::Empty => "empty",
            crate::atoms::comparison::DiffDecision::Different => "different",
        };
        let movement = match &run {
            crate::atoms::comparison::ComparisonRun::Current { .. } => "none",
            crate::atoms::comparison::ComparisonRun::Moved { movement, .. } => movement.as_str(),
        };
        let report_only_drift = file_changed && !target_absent && !apply;
        let truthful_changed = matches!(
            &run,
            crate::atoms::comparison::ComparisonRun::Moved {
                movement: ManagedFileMovement::ContentModeAndOwnership
                    | ManagedFileMovement::Ownership,
                ..
            }
        );
        if file_changed && truthful_changed {
            written.push(file.path.clone());
            changed = true;
        } else if file_changed {
            drift.push(file.path.clone());
        }
        entries.push(crate::atoms::attest::write_file::ManagedFileEntry {
            path: file.path.clone(),
            target_exists_before,
            state: "observed".into(),
            mode,
            content_equal_before: content_equal,
            mode_equal_before: mode_equal,
            owner: request.owner.map(str::to_string),
            group: request.group.map(str::to_string),
            owner_equal_before: owner_equal,
            group_equal_before: group_equal,
            changed: truthful_changed,
            drift_detected: file_changed,
            written: truthful_changed,
            observed_state: crate::atoms::attest::write_file::observed_state(target_exists_before, content_equal, mode_equal, owner_equal, group_equal),
            desired_state: json!({"content_sha256": format!("{:x}", Sha256::digest(desired)), "mode": mode, "uid": desired_uid, "gid": desired_gid}),
            diff_decision: diff_decision.into(),
            movement: movement.into(),
            truthful_changed,
        });
        // A successful empty observation is already represented by the final
        // run receipt. Keep per-file receipts for drift, movement, and
        // observation/actuation failures only; do not spray no-op files.
        if !matches!(
            run,
            crate::atoms::comparison::ComparisonRun::Current {
                decision: crate::atoms::comparison::DiffDecision::Empty,
                ..
            }
        ) {
            let safe_name = file
                .path
                .replace('/', "_")
                .trim_start_matches('_')
                .to_string();
            let per_file = receipt_dir.join(format!(
                "{}-{}.json",
                request.receipt_name.trim_end_matches(".json"),
                safe_name
            ));
            crate::atoms::attest::write_file::write_managed_file(
                receipt_dir,
                &per_file,
                crate::atoms::attest::write_file::ManagedFile {
                    module: request.module_id.to_string(),
                    path: file.path.clone(),
                    mode,
                    owner: request.owner.map(str::to_string),
                    group: request.group.map(str::to_string),
                    owner_equal_before: owner_equal,
                    group_equal_before: group_equal,
                    apply,
                    target_exists_before,
                    state: if report_only_drift {
                        "drift-reported"
                    } else {
                        "observed"
                    }
                    .into(),
                    changed: truthful_changed,
                    drift_detected: file_changed,
                    written: truthful_changed,
                    desired_content_sha256: format!("{:x}", Sha256::digest(desired)),
                    desired_uid,
                    desired_gid,
                    diff_decision: diff_decision.into(),
                    movement: movement.into(),
                    truthful_changed,
                    first_missing_signal: if target_absent {
                        file.path.as_str()
                    } else if report_only_drift {
                        request.first_missing_signal
                    } else {
                        "none"
                    }
                    .into(),
                },
                crate::atoms::attest::write_file::observed_state(
                    target_exists_before,
                    content_equal,
                    mode_equal,
                    owner_equal,
                    group_equal,
                ),
            )?;
        }
    }
    let absent_target = entries
        .iter()
        .find(|entry| !entry.target_exists_before)
        .map(|entry| entry.path.as_str());
    let ok = absent_target.is_none();
    let receipt = receipt_dir.join(if request.receipt_name.ends_with(".json") {
        request.receipt_name.to_string()
    } else {
        format!("{}.json", request.receipt_name)
    });
    let aggregate_signal = if let Some(path) = absent_target {
        path.to_string()
    } else if !drift.is_empty() {
        request.first_missing_signal.to_string()
    } else {
        "none".to_string()
    };
    crate::atoms::attest::write_file::write_managed_files(
        receipt_dir,
        &receipt,
        crate::atoms::attest::write_file::ManagedFiles {
            schema: request.schema.to_string(),
            module: request.module_id.to_string(),
            ok,
            drift,
            written,
            owner: request.owner.map(str::to_string),
            group: request.group.map(str::to_string),
            apply,
            changed,
            entries,
            first_missing_signal: aggregate_signal,
        },
    )?;
    Ok(crate::OperationOutcome {
        ok,
        changed,
        skipped: !apply && !request.files.is_empty(),
        message: format!("{} managed files checked", request.files.len()),
        command: None,
    })
}
