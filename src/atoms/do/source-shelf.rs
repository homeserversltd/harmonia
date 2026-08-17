//! Typed filesystem mutations owned by the source-shelf transaction.
use crate::atoms::r#do::{apply, InvocationKey};
use crate::atoms::{Drift, Receipt};
use crate::atoms::comparison::ActionAuthorization;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::Path;

fn receipt(message: String) -> Receipt { Receipt { atom: "do".into(), ok: true, drift: Drift::Current, message } }

pub(crate) fn mkdir_all(a: ActionAuthorization, i: InvocationKey, path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| e.to_string())?;
    apply(a, i, receipt(format!("source-shelf mkdir {}", path.display()))).map(|_| ())
}

pub(crate) fn copy(a: ActionAuthorization, i: InvocationKey, source: &Path, target: &Path, mode: Option<u32>, uid: Option<u32>, gid: Option<u32>) -> Result<(), String> {
    let bytes = fs::read(source).map_err(|e| format!("files-source-read-failed {}: {e}", source.display()))?;
    atomic_write(a, i, target, &bytes, mode, uid, gid)
}

pub(crate) fn rename(a: ActionAuthorization, i: InvocationKey, from: &Path, to: &Path) -> Result<(), String> { crate::atoms::r#do::rename::rename(a, i, from, to) }

pub(crate) fn copy_raw(a: ActionAuthorization, i: InvocationKey, source: &Path, target: &Path, mode: Option<u32>, uid: Option<u32>, gid: Option<u32>) -> Result<(), String> { copy(a, i, source, target, mode, uid, gid) }

fn atomic_write(a: ActionAuthorization, i: InvocationKey, target: &Path, bytes: &[u8], mode: Option<u32>, uid: Option<u32>, gid: Option<u32>) -> Result<(), String> {
    let parent = target.parent().ok_or_else(|| format!("files-target-parent-missing {}", target.display()))?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let temp = parent.join(format!(".{}.harmonia-tmp-{}", target.file_name().and_then(|name| name.to_str()).unwrap_or("file"), nonce));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new().create_new(true).write(true).open(&temp)
            .map_err(|e| format!("files-temp-create-failed {}: {e}", temp.display()))?;
        file.write_all(bytes).map_err(|e| format!("files-temp-write-failed {}: {e}", temp.display()))?;
        file.sync_all().map_err(|e| format!("files-temp-sync-failed {}: {e}", temp.display()))?;
        drop(file);
        if let Some(mode) = mode { set_mode(&temp, mode)?; }
        set_ownership(&temp, uid, gid)?;
        fs::rename(&temp, target).map_err(|e| format!("files-atomic-promote-failed {} -> {}: {e}", temp.display(), target.display()))?;
        sync_directory(parent)?;
        apply(a, i, receipt(format!("source-shelf copy {}", target.display())))?;
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&temp); let _ = sync_directory(parent); }
    result
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path).map_err(|e| format!("files-mode-metadata-failed {}: {e}", path.display()))?.permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions).map_err(|e| format!("files-mode-set-failed {}: {e}", path.display()))
}
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> { Ok(()) }

#[cfg(unix)]
fn set_ownership(path: &Path, uid: Option<u32>, gid: Option<u32>) -> Result<(), String> {
    if uid.is_none() && gid.is_none() { return Ok(()); }
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)
        .map_err(|e| format!("managed-file-owner-open-failed {}: {e}", path.display()))?;
    let uid = uid.map_or(!0 as libc::uid_t, |value| value as libc::uid_t);
    let gid = gid.map_or(!0 as libc::gid_t, |value| value as libc::gid_t);
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(format!("managed-file-owner-set-failed {}: {}", path.display(), std::io::Error::last_os_error()));
    }
    Ok(())
}
#[cfg(not(unix))]
fn set_ownership(_path: &Path, _uid: Option<u32>, _gid: Option<u32>) -> Result<(), String> { Ok(()) }

fn sync_directory(path: &Path) -> Result<(), String> {
    fs::File::open(path).and_then(|directory| directory.sync_all()).map_err(|error| format!("source-shelf-sweep-directory-sync-failed {}: {error}", path.display()))
}

pub(crate) fn remove_file(a: ActionAuthorization, i: InvocationKey, path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
        Ok(m) if m.file_type().is_dir() => return Err(format!("source-shelf-remove-file-directory {}", path.display())),
        Ok(_) => {}
    }
    crate::atoms::r#do::remove_file::remove_file_with_policy(a, i, path, crate::atoms::r#do::remove_file::RemovePolicy { no_follow: true, collision_refuse: true, rollback_exact: true })
}

pub(crate) fn remove_tree(a: ActionAuthorization, i: InvocationKey, path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
        Ok(m) if !m.file_type().is_dir() => return remove_file(a, i, path),
        Ok(_) => {}
    }
    fs::remove_dir_all(path).map_err(|e| e.to_string())?;
    apply(a, i, receipt(format!("source-shelf remove tree {}", path.display()))).map(|_| ())
}
