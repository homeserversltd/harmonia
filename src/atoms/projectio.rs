//! Atomic, witnessed projection of bytes and concrete Unix metadata.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct OwnerAcceptance(());

pub(crate) fn owner_acceptance(
    _operator_hand: crate::interactables::OperatorHand,
) -> OwnerAcceptance {
    OwnerAcceptance(())
}

/// Witness for engine-maintained state; this is not an operator declaration grant.
pub(crate) fn state_acceptance() -> OwnerAcceptance {
    OwnerAcceptance(())
}

#[derive(Debug, Serialize)]
pub(crate) struct Receipt {
    pub struck_bytes: Vec<u8>,
    pub struck_sha256: String,
    pub backup_path: PathBuf,
    pub before_sha256: String,
    pub target_sha256: String,
    pub readback_sha256: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

pub(crate) struct Request<'a> {
    pub target: &'a Path,
    pub desired_bytes: &'a [u8],
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub backup_path: &'a Path,
    pub witness: OwnerAcceptance,
}

/// Request for engine-maintained local state. Unlike a declaration, this
/// state may be created on first completion; an existing file's concrete
/// ownership and mode are carried forward unchanged.
pub(crate) struct StateRequest<'a> {
    pub target: &'a Path,
    pub desired_bytes: &'a [u8],
    pub backup_path: &'a Path,
    pub witness: OwnerAcceptance,
}

#[derive(Debug, Serialize)]
pub(crate) struct StateReceipt {
    pub created: bool,
    pub target: PathBuf,
    pub backup_path: Option<PathBuf>,
    pub before_sha256: Option<String>,
    pub target_sha256: String,
    pub readback_sha256: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn io_error(operation: &str, path: &Path, error: impl std::fmt::Display) -> String {
    format!("projectio-{operation} {}: {error}", path.display())
}
fn create_temp(dir: &Path, name: &str) -> Result<(File, PathBuf), String> {
    let pid = std::process::id();
    for sequence in 0..1000u32 {
        let path = dir.join(format!(".projectio-{pid}-{sequence}-{name}"));
        match OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((file, path)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io_error("temp-create", &path, error)),
        }
    }
    Err(format!("projectio-temp-create-exhausted {}", dir.display()))
}

pub(crate) fn strike(request: Request<'_>) -> Result<Receipt, String> {
    let Request {
        target,
        desired_bytes,
        mode,
        uid,
        gid,
        backup_path,
        witness,
    } = request;
    let _witness = witness;
    let target_metadata =
        fs::symlink_metadata(target).map_err(|e| io_error("target-stat", target, e))?;
    if !target_metadata.file_type().is_file() {
        return Err(format!(
            "projectio-target-not-regular-file {}",
            target.display()
        ));
    }
    let before_bytes = fs::read(target).map_err(|e| io_error("target-read", target, e))?;
    let backup_parent = backup_path
        .parent()
        .ok_or_else(|| format!("projectio-backup-parent-missing {}", backup_path.display()))?;
    fs::create_dir_all(backup_parent)
        .map_err(|e| io_error("backup-directory", backup_parent, e))?;
    let mut backup = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(backup_path)
        .map_err(|e| io_error("backup-create", backup_path, e))?;
    backup
        .write_all(&before_bytes)
        .map_err(|e| io_error("backup-write", backup_path, e))?;
    backup
        .sync_all()
        .map_err(|e| io_error("backup-sync", backup_path, e))?;
    drop(backup);
    let target_dir = target
        .parent()
        .ok_or_else(|| format!("projectio-target-parent-missing {}", target.display()))?;
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("target");
    let (mut temp, temp_path) = create_temp(target_dir, name)?;
    let result = (|| {
        temp.write_all(desired_bytes)
            .map_err(|e| io_error("temp-write", &temp_path, e))?;
        let fd = temp.as_raw_fd();
        if unsafe { libc::fchown(fd, uid as libc::uid_t, gid as libc::gid_t) } != 0 {
            return Err(io_error(
                "temp-chown",
                &temp_path,
                std::io::Error::last_os_error(),
            ));
        }
        if unsafe { libc::fchmod(fd, mode as libc::mode_t) } != 0 {
            return Err(io_error(
                "temp-chmod",
                &temp_path,
                std::io::Error::last_os_error(),
            ));
        }
        temp.sync_all()
            .map_err(|e| io_error("temp-sync", &temp_path, e))?;
        drop(temp);
        fs::rename(&temp_path, target).map_err(|e| io_error("rename", target, e))?;
        let parent = File::open(target_dir).map_err(|e| io_error("parent-open", target_dir, e))?;
        parent
            .sync_all()
            .map_err(|e| io_error("parent-sync", target_dir, e))?;
        let readback = fs::read(target).map_err(|e| io_error("readback", target, e))?;
        let metadata =
            fs::symlink_metadata(target).map_err(|e| io_error("readback-stat", target, e))?;
        let readback_sha256 = sha256(&readback);
        let struck_sha256 = sha256(desired_bytes);
        if readback != desired_bytes {
            return Err(format!("projectio-readback-mismatch {}", target.display()));
        }
        if metadata.mode() & 0o7777 != mode & 0o7777
            || metadata.uid() != uid
            || metadata.gid() != gid
        {
            return Err(format!(
                "projectio-readback-metadata-mismatch {}",
                target.display()
            ));
        }
        Ok(Receipt {
            struck_bytes: desired_bytes.to_vec(),
            struck_sha256,
            backup_path: backup_path.to_path_buf(),
            before_sha256: sha256(&before_bytes),
            target_sha256: readback_sha256.clone(),
            readback_sha256,
            mode,
            uid,
            gid,
        })
    })();
    if temp_path.exists() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}


/// Atomically write local engine state without treating it as a declaration.
/// The target is the only state path this operation knows about; callers must
/// supply a scratch target in tests rather than redirecting declaration reads.
pub(crate) fn write_state(request: StateRequest<'_>) -> Result<StateReceipt, String> {
    let StateRequest { target, desired_bytes, backup_path, witness } = request;
    let _witness = witness;
    let existing = match fs::symlink_metadata(target) {
        Ok(metadata) if metadata.file_type().is_file() => Some(metadata),
        Ok(_) => return Err(format!("projectio-state-target-not-regular-file {}", target.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(io_error("state-target-stat", target, error)),
    };
    let (mode, uid, gid) = if let Some(metadata) = existing.as_ref() {
        (metadata.mode() & 0o7777, metadata.uid(), metadata.gid())
    } else {
        #[cfg(unix)]
        let owner = (unsafe { libc::geteuid() }, unsafe { libc::getegid() });
        #[cfg(not(unix))]
        let owner = (0, 0);
        (0o644, owner.0, owner.1)
    };
    let before_bytes = if existing.is_some() {
        Some(fs::read(target).map_err(|e| io_error("state-target-read", target, e))?)
    } else { None };
    let written_backup = if let Some(bytes) = before_bytes.as_ref() {
        let parent = backup_path.parent().ok_or_else(|| format!("projectio-state-backup-parent-missing {}", backup_path.display()))?;
        fs::create_dir_all(parent).map_err(|e| io_error("state-backup-directory", parent, e))?;
        let mut backup = OpenOptions::new().write(true).create_new(true).open(backup_path)
            .map_err(|e| io_error("state-backup-create", backup_path, e))?;
        backup.write_all(bytes).map_err(|e| io_error("state-backup-write", backup_path, e))?;
        backup.sync_all().map_err(|e| io_error("state-backup-sync", backup_path, e))?;
        Some(backup_path.to_path_buf())
    } else { None };
    let target_dir = target.parent().ok_or_else(|| format!("projectio-state-target-parent-missing {}", target.display()))?;
    let name = target.file_name().and_then(|x| x.to_str()).unwrap_or("state");
    let (mut temp, temp_path) = create_temp(target_dir, name)?;
    let result = (|| {
        temp.write_all(desired_bytes).map_err(|e| io_error("state-temp-write", &temp_path, e))?;
        let fd = temp.as_raw_fd();
        if unsafe { libc::fchown(fd, uid as libc::uid_t, gid as libc::gid_t) } != 0 {
            return Err(io_error("state-temp-chown", &temp_path, std::io::Error::last_os_error()));
        }
        if unsafe { libc::fchmod(fd, mode as libc::mode_t) } != 0 {
            return Err(io_error("state-temp-chmod", &temp_path, std::io::Error::last_os_error()));
        }
        temp.sync_all().map_err(|e| io_error("state-temp-sync", &temp_path, e))?;
        drop(temp);
        fs::rename(&temp_path, target).map_err(|e| io_error("state-rename", target, e))?;
        File::open(target_dir).map_err(|e| io_error("state-parent-open", target_dir, e))?.sync_all()
            .map_err(|e| io_error("state-parent-sync", target_dir, e))?;
        let readback = fs::read(target).map_err(|e| io_error("state-readback", target, e))?;
        let metadata = fs::symlink_metadata(target).map_err(|e| io_error("state-readback-stat", target, e))?;
        if readback != desired_bytes || metadata.mode() & 0o7777 != mode || metadata.uid() != uid || metadata.gid() != gid {
            return Err(format!("projectio-state-readback-mismatch {}", target.display()));
        }
        let readback_sha256 = sha256(&readback);
        Ok(StateReceipt {
            created: existing.is_none(), target: target.to_path_buf(), backup_path: written_backup.clone(),
            before_sha256: before_bytes.as_deref().map(sha256), target_sha256: readback_sha256.clone(),
            readback_sha256, mode, uid, gid,
        })
    })();
    if temp_path.exists() { let _ = fs::remove_file(&temp_path); }
    result
}
