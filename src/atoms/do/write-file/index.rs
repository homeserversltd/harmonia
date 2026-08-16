use crate::atoms::r#do::{apply, InvocationKey};
use crate::atoms::{Drift, Receipt};
use crate::tools::comparison::ActionAuthorization;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
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
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    path: &Path,
    bytes: &[u8],
    options: FileWriteOptions<'_>,
) -> Result<FileWriteResult, String> {
    let backed_up = if let Some(backup) = options.backup_to {
        if let Some(parent) = backup.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "file-write-backup-parent-create-failed {}: {error}",
                    parent.display()
                )
            })?;
        }
        fs::copy(path, backup).map_err(|error| {
            format!(
                "file-write-backup-failed {} -> {}: {error}",
                path.display(),
                backup.display()
            )
        })?;
        Some(backup.to_path_buf())
    } else {
        None
    };
    if options.write_bytes {
        atomic_file_write(path, bytes, options.mode, options.uid, options.gid)?;
    } else {
        if let Some(mode) = options.mode {
            set_mode(path, mode)?;
        }
        set_ownership(path, options.uid, options.gid)?;
    }
    apply(
        authorization,
        invocation,
        Receipt {
            atom: "do".into(),
            ok: true,
            drift: Drift::Current,
            message: "file write complete".into(),
        },
    )?;
    Ok(FileWriteResult { backed_up })
}

fn atomic_file_write(
    path: &Path,
    bytes: &[u8],
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("file-write-parent-missing {}", path.display()))?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("file");
    let temp = parent.join(format!(
        ".{name}.harmonia-atom-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)
            .map_err(|error| {
                format!("file-write-temp-create-failed {}: {error}", temp.display())
            })?;
        file.write_all(bytes)
            .map_err(|error| format!("file-write-temp-write-failed {}: {error}", temp.display()))?;
        file.sync_all()
            .map_err(|error| format!("file-write-temp-sync-failed {}: {error}", temp.display()))?;
        drop(file);
        if let Some(mode) = mode {
            set_mode(&temp, mode)?;
        }
        set_ownership(&temp, uid, gid)?;
        fs::rename(&temp, path).map_err(|error| {
            format!(
                "file-write-promote-failed {} -> {}: {error}",
                temp.display(),
                path.display()
            )
        })?;
        let directory = OpenOptions::new()
            .read(true)
            .open(parent)
            .map_err(|error| {
                format!(
                    "file-write-parent-open-failed {}: {error}",
                    parent.display()
                )
            })?;
        directory.sync_all().map_err(|error| {
            format!(
                "file-write-parent-sync-failed {}: {error}",
                parent.display()
            )
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}


/// Authorized managed-file transactional writer. The comparison kernel supplies
/// both capabilities; dry-run paths never enter this function.
pub(crate) fn atomic_write_bytes_with_ownership(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    target: &Path,
    bytes: &[u8],
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), String> {
    let parent = target
        .parent()
        .ok_or_else(|| format!("files-target-parent-missing {}", target.display()))?;
    let temp = parent.join(format!(
        ".{}.harmonia-tmp-{}",
        target.file_name().and_then(|name| name.to_str()).unwrap_or("file"),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)
            .map_err(|e| format!("files-temp-create-failed {}: {e}", temp.display()))?;
        file.write_all(bytes)
            .map_err(|e| format!("files-temp-write-failed {}: {e}", temp.display()))?;
        file.sync_all()
            .map_err(|e| format!("files-temp-sync-failed {}: {e}", temp.display()))?;
        drop(file);
        if let Some(mode) = mode { managed_set_mode(&temp, mode)?; }
        managed_set_ownership(&temp, uid, gid)?;
        fs::rename(&temp, target).map_err(|e| format!("files-atomic-promote-failed {} -> {}: {e}", temp.display(), target.display()))?;
        let directory = OpenOptions::new().read(true).open(parent)
            .map_err(|e| format!("files-parent-open-failed {}: {e}", parent.display()))?;
        directory.sync_all().map_err(|e| format!("files-parent-sync-failed {}: {e}", parent.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
        let _ = OpenOptions::new().read(true).open(parent).and_then(|directory| directory.sync_all());
    }
    result?;
    apply(authorization, invocation, Receipt { atom: "do".into(), ok: true, drift: Drift::Current, message: "managed file write complete".into() }).map(|_| ())
}

#[cfg(unix)]
fn managed_set_mode(path: &Path, mode: u32) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| format!("files-mode-set-failed {}: {e}", path.display()))
}
#[cfg(not(unix))]
fn managed_set_mode(_path: &Path, _mode: u32) -> Result<(), String> { Ok(()) }
#[cfg(unix)]
fn managed_set_ownership(path: &Path, uid: Option<u32>, gid: Option<u32>) -> Result<(), String> {
    if uid.is_none() && gid.is_none() { return Ok(()); }
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)
        .map_err(|e| format!("files-owner-open-failed {}: {e}", path.display()))?;
    let uid = uid.map_or(!0 as libc::uid_t, |value| value as libc::uid_t);
    let gid = gid.map_or(!0 as libc::gid_t, |value| value as libc::gid_t);
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(format!("files-owner-set-failed {}: {}", path.display(), std::io::Error::last_os_error()));
    }
    Ok(())
}
#[cfg(not(unix))]
fn managed_set_ownership(_path: &Path, _uid: Option<u32>, _gid: Option<u32>) -> Result<(), String> { Ok(()) }

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("file-write-mode-set-failed {}: {error}", path.display()))
}
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn set_ownership(path: &Path, uid: Option<u32>, gid: Option<u32>) -> Result<(), String> {
    if uid.is_none() && gid.is_none() {
        return Ok(());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("file-write-owner-open-failed {}: {error}", path.display()))?;
    let uid = uid.map_or(!0 as libc::uid_t, |value| value as libc::uid_t);
    let gid = gid.map_or(!0 as libc::gid_t, |value| value as libc::gid_t);
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(format!(
            "file-write-owner-set-failed {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}
#[cfg(not(unix))]
fn set_ownership(_path: &Path, _uid: Option<u32>, _gid: Option<u32>) -> Result<(), String> {
    Ok(())
}
