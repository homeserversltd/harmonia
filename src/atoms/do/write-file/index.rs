use crate::atoms::comparison::ActionAuthorization;
use crate::atoms::projectio;
use crate::atoms::r#do::InvocationKey;
use std::path::{Path, PathBuf};

pub(crate) struct FileWriteOptions<'a> {
    pub write_bytes: bool,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub backup_to: Option<&'a Path>,
}

pub(crate) struct FileWriteResult {
    pub backed_up: Option<PathBuf>,
}

pub(crate) fn file_write(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    path: &Path,
    bytes: &[u8],
    options: FileWriteOptions<'_>,
) -> Result<FileWriteResult, String> {
    let backed_up = if let Some(backup) = options.backup_to {
        if let Some(parent) = backup.parent() {
            projectio::act_make_dir(authorization, parent).map_err(|error| {
                format!("file-write-backup-parent-create-failed {}: {error}", parent.display())
            })?;
        }
        projectio::act_copy(authorization, path, backup, None, None, None).map_err(|error| {
            format!("file-write-backup-failed {} -> {}: {error}", path.display(), backup.display())
        })?;
        Some(backup.to_path_buf())
    } else {
        None
    };
    if options.write_bytes {
        put(authorization, path, bytes, options.mode, options.uid, options.gid)
            .map_err(|error| format!("file-write-promote-failed {}: {error}", path.display()))?;
    } else {
        if let Some(mode) = options.mode {
            projectio::act_mode(authorization, path, mode)
                .map_err(|error| format!("file-write-mode-set-failed {}: {error}", path.display()))?;
        }
        if options.uid.is_some() || options.gid.is_some() {
            let metadata = std::fs::symlink_metadata(path)
                .map_err(|error| format!("file-write-owner-set-failed {}: {error}", path.display()))?;
            if metadata.file_type().is_symlink() {
                return Err(format!("file-write-owner-set-failed {}: symlink target refused", path.display()));
            }
            projectio::act_owner(authorization, path, options.uid.unwrap_or(!0), options.gid.unwrap_or(!0))
                .map_err(|error| format!("file-write-owner-set-failed {}: {error}", path.display()))?;
        }
    }
    let _ = invocation;
    Ok(FileWriteResult { backed_up })
}

// act_put preserves existing metadata when unnamed; an absent file used to be
// created with 0666 under the service's 022 umask.
fn put(
    authorization: &ActionAuthorization,
    path: &Path,
    bytes: &[u8],
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> std::io::Result<()> {
    let mode = match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(mode.unwrap_or(0o644)),
        _ => mode,
    };
    projectio::act_put(authorization, path, bytes, mode, uid, gid)
}

/// Stage bytes for a caller-owned scratch name without recording that name.
pub(crate) fn file_write_scratch(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    path: &Path,
    bytes: &[u8],
    mode: Option<u32>,
) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| format!("file-write-parent-missing {}", path.display()))?;
    let name = path.file_name().and_then(|value| value.to_str()).unwrap_or("file");
    let temp = parent.join(format!(".{name}.harmonia-atom-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos()));
    let result = (|| {
        projectio::act_scratch_write_new(authorization, &temp, bytes, mode.unwrap_or(0o644))
            .map_err(|error| format!("file-write-temp-write-failed {}: {error}", temp.display()))?;
        projectio::act_rename(authorization, &temp, path, true, true)
            .map_err(|error| format!("file-write-promote-failed {} -> {}: {error}", temp.display(), path.display()))?;
        projectio::act_sync(authorization, parent)
            .map_err(|error| format!("file-write-parent-sync-failed {}: {error}", parent.display()))
    })();
    if result.is_err() {
        let _ = projectio::act_scratch_remove(authorization, &temp);
    }
    let _ = invocation;
    result
}

/// Authorized managed-file transactional writer. The comparison kernel supplies
/// both capabilities; dry-run paths never enter this function.
pub(crate) fn atomic_write_bytes_with_ownership(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    target: &Path,
    bytes: &[u8],
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), String> {
    let _ = invocation;
    put(authorization, target, bytes, mode, uid, gid)
        .map_err(|error| format!("files-atomic-promote-failed {}: {error}", target.display()))
}
