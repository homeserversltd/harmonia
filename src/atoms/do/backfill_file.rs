//! Authorized backfill mutation orchestration.
#![allow(dead_code)]
pub(crate) use crate::atoms::ask::backfill_file::{
    resolve_ownership, BackfillFileMovement, BackfillFileObservation, BackfillFileOutcome,
    BackfillFileRequest, BackupPolicy, DeclaredOwnership, HotfixFileBackfillOutcome,
};
use crate::atoms::{self, Drift, Receipt};
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
            let Some(invocation) = request.invocation else {
                return Ok(BackfillFileMovement::default());
            };
            mutation::place(
                authorization,
                invocation,
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
            actual_sha256: observation
                .regular
                .then(|| std::fs::read(request.path).ok())
                .flatten()
                .map(|bytes| atoms::file_sha256(&bytes)),
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
        authorization: ActionAuthorization,
        invocation: atoms::r#do::InvocationKey,
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
        let result = atoms::r#do::file_write(
            authorization,
            invocation,
            path,
            declared_bytes,
            atoms::r#do::FileWriteOptions {
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
