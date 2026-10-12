//! Atomic, witnessed projection of bytes and concrete Unix metadata.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
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

fn recognized_temp_owner(name: &str, target_name: &str) -> Option<u32> {
    let (body, backup) = if let Some(body) = name.strip_prefix(".projectio-engine-state-") {
        (body.strip_suffix(".backup")?, true)
    } else if let Some(body) = name.strip_prefix(".projectio-") {
        (body, false)
    } else {
        return None;
    };
    let mut fields = body.splitn(3, '-');
    let pid = fields.next()?;
    let sequence = fields.next()?;
    let filename = fields.next()?;
    if pid.is_empty()
        || sequence.is_empty()
        || !pid.bytes().all(|byte| byte.is_ascii_digit())
        || !sequence.bytes().all(|byte| byte.is_ascii_digit())
        || filename != target_name
        || (backup && !name.ends_with(".backup"))
    {
        return None;
    }
    pid.parse::<u32>().ok().filter(|pid| *pid != 0)
}

fn process_owns_live_temp(pid: u32) -> bool {
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Remove only regular, exact Projectio temporary forms for one managed target.
/// Live PID owners and caller-owned backups are never touched.
pub(crate) fn cleanup_stale_temporaries_for_target(target: &Path) -> Result<usize, String> {
    let Some(parent) = target.parent().filter(|parent| !parent.as_os_str().is_empty()) else {
        return Ok(0);
    };
    let Some(target_name) = target.file_name().and_then(|name| name.to_str()) else {
        return Ok(0);
    };
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(io_error("temp-cleanup-read", parent, error)),
    };
    let mut removed = 0usize;
    for entry in entries {
        let entry = entry.map_err(|error| io_error("temp-cleanup-entry", parent, error))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
        let Some(pid) = recognized_temp_owner(&name, target_name) else { continue };
        let path = entry.path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => metadata,
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(io_error("temp-cleanup-stat", &path, error)),
        };
        if process_owns_live_temp(pid) {
            continue;
        }
        let current = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => metadata,
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(io_error("temp-cleanup-recheck", &path, error)),
        };
        if file_identity(&metadata) != file_identity(&current) {
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => removed += 1,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error("temp-cleanup-remove", &path, error)),
        }
    }
    Ok(removed)
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
    target_replaced: bool,
    backup_created: bool,
}

fn strike_with_tracking(
    request: Request<'_>,
    expected_target_identity: Option<FileIdentity>,
) -> StrikeAttempt {
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
                target_replaced: false,
                backup_created: false,
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
            target_replaced: false,
            backup_created: false,
        };
    }
    let observed_target_identity = file_identity(&target_metadata);
    if expected_target_identity.is_some_and(|expected| expected != observed_target_identity) {
        return StrikeAttempt {
            result: Err(format!("projectio-target-identity-changed {}", target.display())),
            target_identity: Some(observed_target_identity),
            target_replaced: false,
            backup_created: false,
        };
    }
    let mut target_identity = Some(observed_target_identity);
    let mut target_replaced = false;
    let mut backup_created = false;
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
        backup_created = true;
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
            let before_rename = fs::symlink_metadata(target)
                .map_err(|e| io_error("target-recheck", target, e))?;
            if !before_rename.file_type().is_file()
                || file_identity(&before_rename) != observed_target_identity
            {
                return Err(format!("projectio-target-identity-changed {}", target.display()));
            }
            fs::rename(&temp_path, target).map_err(|e| io_error("rename", target, e))?;
            target_replaced = true;
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
        target_replaced,
        backup_created,
    }
}

pub(crate) fn strike(request: Request<'_>) -> Result<Receipt, String> {
    strike_with_tracking(request, None).result
}

fn remove_engine_state_backup(path: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error("state-backup-stat", path, error)),
    };
    if !metadata.file_type().is_file() {
        return Err(format!("projectio-state-backup-not-regular {}", path.display()));
    }
    fs::remove_file(path).map_err(|error| io_error("state-backup-remove", path, error))?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io_error("state-backup-parent-sync", parent, error))?;
    }
    Ok(())
}

fn read_engine_state_target(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error("state-verify-stat", path, error))?;
    if !metadata.file_type().is_file() {
        return Err(format!("projectio-state-verify-target-not-regular {}", path.display()));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|error| io_error("state-verify-open", path, error))?;
    let opened = file
        .metadata()
        .map_err(|error| io_error("state-verify-fstat", path, error))?;
    if !opened.file_type().is_file() || file_identity(&opened) != file_identity(&metadata) {
        return Err(format!("projectio-state-verify-target-changed {}", path.display()));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| io_error("state-verify-read", path, error))?;
    Ok(bytes)
}

fn verify_engine_state(target: &Path, bytes: &[u8], metadata: &fs::Metadata) -> Result<(), String> {
    let current = fs::symlink_metadata(target).map_err(|error| io_error("state-verify-stat", target, error))?;
    if !current.file_type().is_file()
        || current.mode() & 0o7777 != metadata.mode() & 0o7777
        || current.uid() != metadata.uid()
        || current.gid() != metadata.gid()
    {
        return Err(format!("projectio-state-restore-identity-mismatch {}", target.display()));
    }
    let actual = read_engine_state_target(target)?;
    if actual != bytes {
        return Err(format!("projectio-state-restore-bytes-mismatch {}", target.display()));
    }
    Ok(())
}

fn restore_existing_engine_state(
    target: &Path,
    backup_path: &Path,
    original_bytes: &[u8],
    original_metadata: &fs::Metadata,
    target_identity: Option<FileIdentity>,
    backup_created: bool,
    target_replaced: bool,
) -> Result<(), String> {
    let expected_identity = target_identity.ok_or_else(|| {
        format!("projectio-state-restore-target-identity-unavailable {}", target.display())
    })?;
    let current = fs::symlink_metadata(target)
        .map_err(|error| io_error("state-restore-target-stat", target, error))?;
    if !current.file_type().is_file() || file_identity(&current) != expected_identity {
        return Err(format!("projectio-state-restore-target-changed {}", target.display()));
    }
    if !target_replaced {
        verify_engine_state(target, original_bytes, original_metadata)?;
        if backup_created {
            remove_engine_state_backup(backup_path)?;
        }
        return Ok(());
    }
    let parent = target.parent().filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| format!("projectio-state-restore-parent-missing {}", target.display()))?;
    let target_name = target.file_name().and_then(|name| name.to_str())
        .ok_or_else(|| format!("projectio-state-restore-name-invalid {}", target.display()))?;
    let (mut temp, temp_path) = create_temp(parent, target_name)?;
    let result = (|| {
        temp.write_all(&original_bytes).map_err(|error| io_error("state-restore-write", &temp_path, error))?;
        if unsafe { libc::fchown(temp.as_raw_fd(), original_metadata.uid(), original_metadata.gid()) } != 0 {
            return Err(io_error("state-restore-owner", &temp_path, std::io::Error::last_os_error()));
        }
        temp.set_permissions(fs::Permissions::from_mode(original_metadata.mode() & 0o7777))
            .map_err(|error| io_error("state-restore-mode", &temp_path, error))?;
        temp.sync_all().map_err(|error| io_error("state-restore-sync", &temp_path, error))?;
        drop(temp);
        let before_rename = fs::symlink_metadata(target)
            .map_err(|error| io_error("state-restore-target-recheck", target, error))?;
        if !before_rename.file_type().is_file() || file_identity(&before_rename) != expected_identity {
            return Err(format!("projectio-state-restore-target-changed {}", target.display()));
        }
        fs::rename(&temp_path, target).map_err(|error| io_error("state-restore-rename", target, error))?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io_error("state-restore-parent-sync", parent, error))?;
        verify_engine_state(target, &original_bytes, original_metadata)?;
        remove_engine_state_backup(backup_path)
    })();
    if temp_path.exists() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn restore_created_engine_state(
    target: &Path,
    backup_path: &Path,
    target_identity: Option<FileIdentity>,
    backup_created: bool,
) -> Result<(), String> {
    match target_identity {
        Some(identity) => match fs::symlink_metadata(target) {
            Ok(metadata) if metadata.file_type().is_file() && file_identity(&metadata) == identity => {
                fs::remove_file(target).map_err(|error| io_error("state-restore-target", target, error))?;
            }
            Ok(_) => return Err(format!("projectio-state-restore-target-changed {}", target.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error("state-restore-target-stat", target, error)),
        },
        None => return Err(format!("projectio-state-restore-target-identity-unavailable {}", target.display())),
    }
    if let Some(parent) = target.parent() {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io_error("state-restore-parent-sync", parent, error))?;
    }
    match fs::symlink_metadata(target) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return Err(format!("projectio-state-restore-target-remains {}", target.display())),
        Err(error) => return Err(io_error("state-restore-target-recheck", target, error)),
    }
    if backup_created {
        remove_engine_state_backup(backup_path)?;
    }
    Ok(())
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
    cleanup_stale_temporaries_for_target(target)?;

    let mut target_was_created = false;
    let metadata = match fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match OpenOptions::new().write(true).create_new(true).open(target) {
                Ok(file) => {
                    drop(file);
                    target_was_created = true;
                    fs::symlink_metadata(target).map_err(|e| io_error("state-stat", target, e))?
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    fs::symlink_metadata(target).map_err(|e| io_error("state-stat", target, e))?
                }
                Err(error) => return Err(io_error("state-create", target, error)),
            }
        }
        Err(error) => return Err(io_error("state-stat", target, error)),
    };
    if !metadata.file_type().is_file() {
        return Err(format!("projectio-target-not-regular-file {}", target.display()));
    }
    let original_identity = file_identity(&metadata);
    let original_bytes = if target_was_created {
        Vec::new()
    } else {
        read_engine_state_target(target)?
    };
    let observed = fs::symlink_metadata(target).map_err(|e| io_error("state-stat-recheck", target, e))?;
    if !observed.file_type().is_file() || file_identity(&observed) != original_identity {
        return Err(format!("projectio-state-target-changed {}", target.display()));
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
    }, Some(original_identity));
    match attempt.result {
        Ok(receipt) => {
            remove_engine_state_backup(&backup)?;
            Ok(receipt)
        }
        Err(error) if target_was_created => {
            match restore_created_engine_state(
                target,
                &backup,
                attempt.target_identity,
                attempt.backup_created,
            ) {
                Ok(()) => Err(error),
                Err(restore_error) => Err(format!("{error}; {restore_error}")),
            }
        }
        Err(error) => {
            match restore_existing_engine_state(
                target,
                &backup,
                &original_bytes,
                &metadata,
                attempt.target_identity,
                attempt.backup_created,
                attempt.target_replaced,
            ) {
                Ok(()) => Err(error),
                Err(restore_error) => Err(format!("{error}; {restore_error}")),
            }
        }
    }
}
