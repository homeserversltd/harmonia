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
