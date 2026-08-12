use super::*;
use crate::tools::comparison::ActionAuthorization;

pub(super) fn place(
    authorization: ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    path: &Path,
    declared_bytes: &[u8],
    declared_mode: Option<u32>,
    ownership: DeclaredOwnership,
    backup: BackupPolicy<'_>,
    observation: &PlaceFileObservation,
) -> Result<PlaceFileMovement, String> {
    let created = !observation.existed;
    let bytes = !observation.bytes_equal;
    let mode = !observation.mode_equal;
    let owner = !observation.owner_equal || !observation.group_equal;
    let backup_to = match backup {
        BackupPolicy::To(path) if observation.existed && (bytes || mode) => Some(path),
        BackupPolicy::None | BackupPolicy::To(_) => None,
    };
    let result = atoms::r#do::file_write(
        authorization,
        invocation,
        path,
        declared_bytes,
        atoms::r#do::FileWriteOptions {
            write_bytes: bytes,
            mode: if bytes {
                declared_mode.or(observation.mode)
            } else {
                mode.then_some(declared_mode).flatten()
            },
            uid: if bytes {
                ownership.uid
            } else {
                (!observation.owner_equal)
                    .then_some(ownership.uid)
                    .flatten()
            },
            gid: if bytes {
                ownership.gid
            } else {
                (!observation.group_equal)
                    .then_some(ownership.gid)
                    .flatten()
            },
            backup_to,
        },
    )?;
    Ok(PlaceFileMovement {
        bytes,
        mode,
        owner,
        created,
        backed_up: result.backed_up,
    })
}
