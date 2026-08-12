use super::*;
use crate::tools::comparison::ActionAuthorization;

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
