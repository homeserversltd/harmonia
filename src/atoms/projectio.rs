//! Atomic, witnessed projection of bytes and concrete Unix metadata.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
pub(crate) struct OwnerAcceptance(());

pub(crate) fn owner_acceptance(
    _operator_hand: crate::interactables::OperatorHand,
) -> OwnerAcceptance {
    OwnerAcceptance(())
}

/// Capability for the engine's private non-declaration state file.
/// It is distinct from operator-facing projection acceptance.
#[derive(Debug)]
pub(crate) struct EngineStateWitness(());

pub(crate) fn engine_state_witness() -> EngineStateWitness {
    EngineStateWitness(())
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

static ENGINE_STATE_BACKUP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn engine_state_backup_path(target: &Path) -> PathBuf {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    let sequence = ENGINE_STATE_BACKUP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(
        ".projectio-engine-state-{}-{sequence}-{name}.backup",
        std::process::id()
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
}

fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    }
}

struct StrikeAttempt {
    result: Result<Receipt, String>,
    target_identity: Option<FileIdentity>,
}

fn strike_with_tracking(request: Request<'_>) -> StrikeAttempt {
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
    let target_metadata = match fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) => {
            return StrikeAttempt {
                result: Err(io_error("target-stat", target, error)),
                target_identity: None,
            }
        }
    };
    if !target_metadata.file_type().is_file() {
        return StrikeAttempt {
            result: Err(format!(
                "projectio-target-not-regular-file {}",
                target.display()
            )),
            target_identity: None,
        };
    }
    let mut target_identity = Some(file_identity(&target_metadata));
    let result = (|| {
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
            target_identity = fs::symlink_metadata(target)
                .ok()
                .map(|metadata| file_identity(&metadata));
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
    })();
    StrikeAttempt {
        result,
        target_identity,
    }
}

pub(crate) fn strike(request: Request<'_>) -> Result<Receipt, String> {
    strike_with_tracking(request).result
}

fn restore_created_engine_state(
    target: &Path,
    backup_path: &Path,
    target_identity: Option<FileIdentity>,
) -> Result<(), String> {
    let mut errors = Vec::new();
    match target_identity {
        Some(identity) => match fs::symlink_metadata(target) {
            Ok(metadata) if file_identity(&metadata) == identity => {
                if let Err(error) = fs::remove_file(target) {
                    errors.push(io_error("state-restore-target", target, error));
                }
            }
            Ok(_) => errors.push(format!(
                "projectio-state-restore-target-changed {}",
                target.display()
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => errors.push(io_error("state-restore-target-stat", target, error)),
        },
        None => errors.push(format!(
            "projectio-state-restore-target-identity-unavailable {}",
            target.display()
        )),
    }
    match fs::read(backup_path) {
        Ok(bytes) if bytes.is_empty() => {
            if let Err(error) = fs::remove_file(backup_path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    errors.push(io_error("state-restore-backup", backup_path, error));
                }
            }
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => errors.push(io_error("state-restore-backup-read", backup_path, error)),
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}


/// Replace engine-maintained state through the Projectio membrane.
pub(crate) fn write_engine_state(
    target: &Path,
    desired_bytes: &[u8],
    witness: EngineStateWitness,
) -> Result<Receipt, String> {
    let _witness = witness;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| io_error("state-directory", parent, e))?;
    }

    let mut target_was_created = false;
    let metadata = match fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(target)
            {
                Ok(file) => {
                    drop(file);
                    target_was_created = true;
                    fs::symlink_metadata(target)
                        .map_err(|e| io_error("state-stat", target, e))?
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    fs::symlink_metadata(target)
                        .map_err(|e| io_error("state-stat", target, e))?
                }
                Err(error) => return Err(io_error("state-create", target, error)),
            }
        }
        Err(error) => return Err(io_error("state-stat", target, error)),
    };
    if !metadata.file_type().is_file() {
        return Err(format!(
            "projectio-target-not-regular-file {}",
            target.display()
        ));
    }

    let backup = engine_state_backup_path(target);
    let attempt = strike_with_tracking(Request {
        target,
        desired_bytes,
        mode: metadata.mode() as u32 & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
        backup_path: &backup,
        witness: OwnerAcceptance(()),
    });
    match attempt.result {
        Ok(receipt) => Ok(receipt),
        Err(error) if target_was_created => {
            match restore_created_engine_state(target, &backup, attempt.target_identity) {
                Ok(()) => Err(error),
                Err(restore_error) => Err(format!("{error}; {restore_error}")),
            }
        }
        Err(error) => Err(error),
    }
}
