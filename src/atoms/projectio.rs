//! Atomic, witnessed projection of bytes and concrete Unix metadata.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

// Name and metadata acts use Compare's known-good witness.
fn check_act_path(path: &Path) -> std::io::Result<()> {
    if path.components().any(|part| part == std::path::Component::ParentDir) {
        return Err(std::io::Error::other(format!("projectio-path-dotdot-refused {}", path.display())));
    }
    Ok(())
}

fn act_mismatch(act: &str, path: &Path) -> std::io::Error {
    std::io::Error::other(format!("projectio-readback-{act}-mismatch {}", path.display()))
}

pub(crate) fn act_mode(
    _authorization: &crate::atoms::comparison::ActionAuthorization,
    path: &Path, mode: u32,
) -> std::io::Result<()> {
    check_act_path(path)?;
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() {
        return Err(std::io::Error::other(format!("projectio-mode-symlink-refused {}", path.display())));
    }
    let changed = before.mode() & 0o7777 != mode & 0o7777;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    let matches = fs::symlink_metadata(path)
        .is_ok_and(|after| !after.file_type().is_symlink() && after.mode() & 0o7777 == mode & 0o7777);
    if changed { crate::atoms::touch::record_lane(path, "known-good"); }
    if !matches { return Err(act_mismatch("mode", path)); }
    Ok(())
}

pub(crate) fn act_owner(
    _authorization: &crate::atoms::comparison::ActionAuthorization,
    path: &Path, uid: libc::uid_t, gid: libc::gid_t,
) -> std::io::Result<()> {
    check_act_path(path)?;
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let before = fs::symlink_metadata(path)?;
    let changed = (uid != !0 && before.uid() != uid) || (gid != !0 && before.gid() != gid);
    if unsafe { libc::lchown(c.as_ptr(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let matches = fs::symlink_metadata(path)
        .is_ok_and(|after| (uid == !0 || after.uid() == uid) && (gid == !0 || after.gid() == gid));
    if changed { crate::atoms::touch::record_lane(path, "known-good"); }
    if !matches { return Err(act_mismatch("owner", path)); }
    Ok(())
}

pub(crate) fn act_rename(
    _authorization: &crate::atoms::comparison::ActionAuthorization,
    from: &Path, to: &Path, scratch_from: bool, scratch_to: bool,
) -> std::io::Result<()> {
    check_act_path(from)?;
    check_act_path(to)?;
    fs::rename(from, to)?;
    let to_readback = fs::symlink_metadata(to);
    let from_readback = fs::symlink_metadata(from);
    let matches = to_readback.is_ok()
        && matches!(from_readback, Err(ref e) if e.kind() == std::io::ErrorKind::NotFound);
    if !scratch_to { crate::atoms::touch::record_lane(to, "known-good"); }
    if !scratch_from { crate::atoms::touch::record_lane(from, "known-good"); }
    if !matches { return Err(act_mismatch("rename", to)); }
    Ok(())
}

pub(crate) fn act_remove(
    _authorization: &crate::atoms::comparison::ActionAuthorization,
    path: &Path, scratch: bool,
) -> std::io::Result<()> {
    check_act_path(path)?;
    fs::remove_file(path)?;
    let readback = fs::symlink_metadata(path);
    let matches = matches!(readback, Err(ref e) if e.kind() == std::io::ErrorKind::NotFound);
    if !scratch { crate::atoms::touch::record_lane(path, "known-good"); }
    if !matches { return Err(act_mismatch("remove", path)); }
    Ok(())
}

pub(crate) fn act_make_dir(
    _authorization: &crate::atoms::comparison::ActionAuthorization, path: &Path,
) -> std::io::Result<()> {
    check_act_path(path)?;
    let mut missing = Vec::new();
    for candidate in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        match fs::symlink_metadata(candidate) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => missing.push(candidate.to_path_buf()),
            Err(_) => break,
        }
    }
    fs::create_dir_all(path)?;
    let matches = fs::metadata(path).is_ok_and(|after| after.is_dir());
    for directory in missing { crate::atoms::touch::record_made_directory(&directory, "known-good"); }
    if !matches { return Err(act_mismatch("make-dir", path)); }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn act_make_dir_new(
    _auth: &crate::atoms::comparison::ActionAuthorization, path: &Path,
) -> std::io::Result<()> {
    check_act_path(path)?;
    fs::create_dir(path)?;
    crate::atoms::touch::record_made_directory(path, "known-good");
    let matches = fs::symlink_metadata(path)
        .is_ok_and(|after| after.is_dir() && !after.file_type().is_symlink());
    if !matches { return Err(act_mismatch("make-dir-new", path)); }
    Ok(())
}

// The seated link act: scratch staging and ownership, then promotion.
pub(crate) fn act_link_stage(
    _authorization: &crate::atoms::comparison::ActionAuthorization, source: &Path, candidate: &Path,
) -> std::io::Result<()> {
    check_act_path(candidate)?;
    std::os::unix::fs::symlink(source, candidate)?;
    if !fs::read_link(candidate).is_ok_and(|actual| actual == source) {
        return Err(act_mismatch("link", candidate));
    }
    Ok(())
}

pub(crate) fn act_scratch_owner(
    _authorization: &crate::atoms::comparison::ActionAuthorization,
    path: &Path, uid: libc::uid_t, gid: libc::gid_t,
) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    check_act_path(path)?;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let _before = fs::symlink_metadata(path)?;
    if unsafe { libc::lchown(c.as_ptr(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if !fs::symlink_metadata(path).is_ok_and(|after|
        (uid == !0 || after.uid() == uid) && (gid == !0 || after.gid() == gid)) {
        return Err(act_mismatch("owner", path));
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) enum LinkPromotion { Rename, Exchange, NoReplace }

fn renameat2_raw(candidate: &Path, target: &Path, flags: libc::c_uint) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let left = std::ffi::CString::new(candidate.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let right = std::ffi::CString::new(target.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    #[cfg(target_os = "linux")]
    let rc = unsafe { libc::renameat2(libc::AT_FDCWD, left.as_ptr(), libc::AT_FDCWD, right.as_ptr(), flags) };
    #[cfg(not(target_os = "linux"))]
    let rc = { let _ = (left, right, flags); -1 };
    if rc != 0 { return Err(std::io::Error::last_os_error()); }
    Ok(())
}

pub(crate) fn act_link_promote(
    _authorization: &crate::atoms::comparison::ActionAuthorization,
    source: &Path, candidate: &Path, target: &Path, how: LinkPromotion, scratch: bool,
) -> std::io::Result<()> {
    check_act_path(candidate)?;
    check_act_path(target)?;
    match how {
        LinkPromotion::Rename => fs::rename(candidate, target)?,
        LinkPromotion::Exchange => renameat2_raw(candidate, target, libc::RENAME_EXCHANGE)?,
        LinkPromotion::NoReplace => renameat2_raw(candidate, target, libc::RENAME_NOREPLACE)?,
    }
    let matches = fs::read_link(target).is_ok_and(|actual| actual == source);
    if !scratch { crate::atoms::touch::record_lane(target, "known-good"); }
    if !matches { return Err(act_mismatch("link", target)); }
    Ok(())
}

pub(crate) fn act_exchange_back(
    _authorization: &crate::atoms::comparison::ActionAuthorization, candidate: &Path, target: &Path, scratch: bool,
) -> std::io::Result<()> {
    check_act_path(candidate)?;
    check_act_path(target)?;
    renameat2_raw(candidate, target, libc::RENAME_EXCHANGE)?;
    let matches = fs::symlink_metadata(candidate).is_ok() && fs::symlink_metadata(target).is_ok();
    if !scratch { crate::atoms::touch::record_lane(target, "known-good"); }
    if !matches { return Err(act_mismatch("link", target)); }
    Ok(())
}

// The seated remove-tree act, including empty directories and scratch names.
#[derive(Clone, Copy)]
pub(crate) enum RemoveTree { Empty, Tree }

pub(crate) fn act_remove_tree(
    _authorization: &crate::atoms::comparison::ActionAuthorization,
    path: &Path, how: RemoveTree, scratch: bool,
) -> std::io::Result<()> {
    check_act_path(path)?;
    let result = match how {
        RemoveTree::Empty => fs::remove_dir(path),
        RemoveTree::Tree => (|| {
            let m = fs::symlink_metadata(path)?;
            if m.is_dir() && !m.file_type().is_symlink() { fs::remove_dir_all(path) }
            else { fs::remove_file(path) }
        })(),
    };
    if let Err(error) = result {
        if matches!(how, RemoveTree::Tree) && !scratch {
            crate::atoms::touch::record_lane(path, "known-good");
        }
        return Err(error);
    }
    let matches = matches!(fs::symlink_metadata(path), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound);
    if !scratch { crate::atoms::touch::record_lane(path, "known-good"); }
    if !matches { return Err(act_mismatch("remove-tree", path)); }
    Ok(())
}

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

struct KnownGoodWitness<'a>(&'a crate::atoms::comparison::ActionAuthorization);
enum ProjectionWitness<'a> {
    Owner(OwnerAcceptance),
    Engine(EngineStateWitness),
    KnownGood(KnownGoodWitness<'a>),
}
impl ProjectionWitness<'_> {
    fn lane(&self) -> &'static str {
        match self {
            Self::Owner(_) => "interactable",
            Self::Engine(_) => "self",
            Self::KnownGood(witness) => { let _ = witness.0; "known-good" },
        }
    }
}
impl<'a> From<OwnerAcceptance> for ProjectionWitness<'a> {
    fn from(witness: OwnerAcceptance) -> Self { Self::Owner(witness) }
}
impl<'a> From<EngineStateWitness> for ProjectionWitness<'a> {
    fn from(witness: EngineStateWitness) -> Self { Self::Engine(witness) }
}
impl<'a> From<KnownGoodWitness<'a>> for ProjectionWitness<'a> {
    fn from(witness: KnownGoodWitness<'a>) -> Self { Self::KnownGood(witness) }
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

pub(crate) struct Request<'a, W = OwnerAcceptance> {
    pub target: &'a Path,
    pub desired_bytes: &'a [u8],
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub backup_path: &'a Path,
    pub witness: W,
}

pub(crate) struct AbsentCreationRequest<'a, W = OwnerAcceptance> {
    pub target: &'a Path,
    pub desired_bytes: &'a [u8],
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub witness: W,
}

#[derive(Debug, Serialize)]
pub(crate) struct AbsentCreationReceipt {
    pub struck_sha256: String,
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

fn recognized_temp_owner(name: &str, target_name: &str) -> Option<u32> {
    if let Some(body) = name.strip_prefix(".projectio-absent-") {
        let (pid, sequence) = body.split_once('-')?;
        if !pid.is_empty() && !sequence.is_empty() && pid.bytes().all(|b| b.is_ascii_digit())
            && sequence.bytes().all(|b| b.is_ascii_digit()) {
            return pid.parse::<u32>().ok().filter(|pid| *pid != 0);
        }
        return None;
    }
    let (body, backup) = if let Some(body) = name.strip_prefix(".projectio-engine-state-") {
        (body.strip_suffix(".backup")?, true)
    } else if let Some(body) = name.strip_prefix(".projectio-known-good-") {
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

fn same_preimage_metadata(current: &fs::Metadata, expected: &fs::Metadata) -> bool {
    current.file_type().is_file()
        && file_identity(current) == file_identity(expected)
        && current.len() == expected.len()
        && current.mode() == expected.mode()
        && current.uid() == expected.uid()
        && current.gid() == expected.gid()
        && current.mtime() == expected.mtime()
        && current.mtime_nsec() == expected.mtime_nsec()
        && current.ctime() == expected.ctime()
        && current.ctime_nsec() == expected.ctime_nsec()
}

fn verify_preimage(target: &Path, bytes: &[u8], metadata: &fs::Metadata) -> Result<(), String> {
    let stale = || format!("projectio-target-preimage-changed {}", target.display());
    let mut file = OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(target).map_err(|error| io_error("preimage-open", target, error))?;
    let before = file.metadata().map_err(|error| io_error("preimage-stat", target, error))?;
    if !same_preimage_metadata(&before, metadata) { return Err(stale()); }
    let mut observed = Vec::new();
    (&mut file).take((bytes.len() as u64).saturating_add(1)).read_to_end(&mut observed)
        .map_err(|error| io_error("preimage-read", target, error))?;
    let after = file.metadata().map_err(|error| io_error("preimage-recheck", target, error))?;
    let named = fs::symlink_metadata(target)
        .map_err(|error| io_error("preimage-path-recheck", target, error))?;
    if observed != bytes || !same_preimage_metadata(&after, metadata)
        || !same_preimage_metadata(&named, metadata)
    { return Err(stale()); }
    Ok(())
}

struct StrikeAttempt {
    result: Result<Receipt, String>,
    target_identity: Option<FileIdentity>,
    target_replaced: bool,
    backup_created: bool,
}

fn strike_with_tracking<'a, W: Into<ProjectionWitness<'a>>>(
    request: Request<'_, W>,
    expected_target_identity: Option<FileIdentity>,
    expected_preimage: Option<(&[u8], &fs::Metadata)>,
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
    let witness = witness.into();
    let lane = witness.lane();
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
        let before_bytes = if let Some((bytes, metadata)) = expected_preimage {
            verify_preimage(target, bytes, metadata)?;
            bytes.to_vec()
        } else {
            fs::read(target).map_err(|e| io_error("target-read", target, e))?
        };
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
        if lane == "interactable" { crate::atoms::touch::record_lane(backup_path, lane); }
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
            if let Some((bytes, metadata)) = expected_preimage {
                verify_preimage(target, bytes, metadata)?;
            }
            fs::rename(&temp_path, target).map_err(|e| io_error("rename", target, e))?;
            target_replaced = true;
            crate::atoms::touch::record_lane(target, lane);
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
    strike_with_tracking(request, None, None).result
}

/// Keep a caller's read/modify/write bound to its observed preimage inside the
/// primitive, including the final recheck after backup and temporary preparation.
pub(crate) fn strike_if_current(
    request: Request<'_>, bytes: &[u8], metadata: &fs::Metadata,
) -> Result<Receipt, String> {
    strike_with_tracking(request, Some(file_identity(metadata)), Some((bytes, metadata))).result
}

fn stat_at_nofollow(directory: &File, name: &std::ffi::CString) -> Result<libc::stat, std::io::Error> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(stat)
}

fn stat_identity(stat: &libc::stat) -> FileIdentity {
    FileIdentity {
        dev: stat.st_dev as u64,
        ino: stat.st_ino as u64,
    }
}

fn create_temp_at(
    directory: &File,
    parent: &Path,
) -> Result<(File, PathBuf, std::ffi::CString), String> {
    let pid = std::process::id();
    for sequence in 0..1000u32 {
        let name = format!(".projectio-absent-{pid}-{sequence}");
        let name_c = std::ffi::CString::new(name.as_bytes())
            .map_err(|error| format!("projectio-absent-temp-name-invalid {name:?}: {error}"))?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd >= 0 {
            return Ok((
                unsafe { File::from_raw_fd(fd) },
                parent.join(name),
                name_c,
            ));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(io_error("absent-temp-create", &parent.join(name), error));
        }
    }
    Err(format!("projectio-absent-temp-create-exhausted {}", parent.display()))
}

fn unlink_owned_staged_file(
    directory: &File,
    name: &std::ffi::CString,
    identity: FileIdentity,
    path: &Path,
    operation: &str,
) -> Result<(), String> {
    match stat_at_nofollow(directory, name) {
        Ok(stat)
            if stat.st_mode & libc::S_IFMT == libc::S_IFREG
                && stat_identity(&stat) == identity =>
        {
            if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(io_error(operation, path, std::io::Error::last_os_error()));
            }
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(operation, path, error)),
    }
}

/// Create a genuinely absent target after an owner hand, without a placeholder
/// or a replace-capable rename. The staged file and final entry share a parent.
pub(crate) fn create_absent(
    request: AbsentCreationRequest<'_>,
) -> Result<AbsentCreationReceipt, String> {
    create_absent_with_witness(request)
}

fn create_absent_with_witness<'a, W: Into<ProjectionWitness<'a>>>(
    request: AbsentCreationRequest<'_, W>,
) -> Result<AbsentCreationReceipt, String> {
    let AbsentCreationRequest {
        target,
        desired_bytes,
        mode,
        uid,
        gid,
        witness,
    } = request;
    let witness = witness.into();
    let lane = witness.lane();
    let parent = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| format!("projectio-target-parent-missing {}", target.display()))?;
    let target_name = target
        .file_name()
        .ok_or_else(|| format!("projectio-target-name-missing {}", target.display()))?;
    let target_name = std::ffi::CString::new(target_name.as_encoded_bytes())
        .map_err(|error| format!("projectio-target-name-invalid {}: {error}", target.display()))?;

    match fs::symlink_metadata(target) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return Err(format!("projectio-absent-target-already-exists {}", target.display())),
        Err(error) => return Err(io_error("absent-target-stat", target, error)),
    }
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| io_error("absent-parent-stat", parent, error))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.file_type().is_dir() {
        return Err(format!("projectio-absent-parent-not-directory {}", parent.display()));
    }
    let mut directory_options = OpenOptions::new();
    directory_options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let directory = directory_options
        .open(parent)
        .map_err(|error| io_error("absent-parent-open", parent, error))?;
    let opened_parent = directory
        .metadata()
        .map_err(|error| io_error("absent-parent-fstat", parent, error))?;
    if !opened_parent.is_dir() || file_identity(&opened_parent) != file_identity(&parent_metadata) {
        return Err(format!("projectio-absent-parent-changed {}", parent.display()));
    }
    match stat_at_nofollow(&directory, &target_name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return Err(format!("projectio-absent-target-already-exists {}", target.display())),
        Err(error) => return Err(io_error("absent-target-stat-at", target, error)),
    }

    let (mut staged, staged_path, staged_name) = create_temp_at(&directory, parent)?;
    let staged_identity = staged
        .metadata()
        .map(|metadata| file_identity(&metadata))
        .map_err(|error| io_error("absent-temp-stat", &staged_path, error))?;
    let mut promoted = false;
    let result = (|| {
        staged
            .write_all(desired_bytes)
            .map_err(|error| io_error("absent-temp-write", &staged_path, error))?;
        if unsafe { libc::fchown(staged.as_raw_fd(), uid as libc::uid_t, gid as libc::gid_t) } != 0 {
            return Err(io_error(
                "absent-temp-chown",
                &staged_path,
                std::io::Error::last_os_error(),
            ));
        }
        if unsafe { libc::fchmod(staged.as_raw_fd(), mode as libc::mode_t) } != 0 {
            return Err(io_error(
                "absent-temp-chmod",
                &staged_path,
                std::io::Error::last_os_error(),
            ));
        }
        staged
            .sync_all()
            .map_err(|error| io_error("absent-temp-sync", &staged_path, error))?;
        let staged_metadata = staged
            .metadata()
            .map_err(|error| io_error("absent-temp-fstat", &staged_path, error))?;
        if !staged_metadata.is_file()
            || file_identity(&staged_metadata) != staged_identity
            || staged_metadata.mode() & 0o7777 != mode & 0o7777
            || staged_metadata.uid() != uid
            || staged_metadata.gid() != gid
        {
            return Err(format!("projectio-absent-temp-metadata-mismatch {}", staged_path.display()));
        }
        drop(staged);
        let staged_path_stat = stat_at_nofollow(&directory, &staged_name)
            .map_err(|error| io_error("absent-temp-path-stat", &staged_path, error))?;
        if staged_path_stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat_identity(&staged_path_stat) != staged_identity
        {
            return Err(format!("projectio-absent-temp-path-changed {}", staged_path.display()));
        }

        #[cfg(target_os = "linux")]
        {
            let promoted_result = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    directory.as_raw_fd(),
                    staged_name.as_ptr(),
                    directory.as_raw_fd(),
                    target_name.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            if promoted_result != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    return Err(format!("projectio-absent-target-already-exists {}", target.display()));
                }
                return Err(io_error("absent-promote-noreplace", target, error));
            }
            promoted = true;
            crate::atoms::touch::record_lane(target, lane);
        }
        #[cfg(not(target_os = "linux"))]
        {
            return Err("projectio-absent-noreplace-unsupported".into());
        }

        directory
            .sync_all()
            .map_err(|error| io_error("absent-parent-sync", parent, error))?;
        let target_fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                target_name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if target_fd < 0 {
            return Err(io_error("absent-readback-open", target, std::io::Error::last_os_error()));
        }
        let mut readback_file = unsafe { File::from_raw_fd(target_fd) };
        let readback_metadata = readback_file
            .metadata()
            .map_err(|error| io_error("absent-readback-fstat", target, error))?;
        if !readback_metadata.is_file() || file_identity(&readback_metadata) != staged_identity {
            return Err(format!("projectio-absent-readback-identity-mismatch {}", target.display()));
        }
        let mut readback = Vec::new();
        readback_file
            .read_to_end(&mut readback)
            .map_err(|error| io_error("absent-readback-read", target, error))?;
        let after_read = readback_file
            .metadata()
            .map_err(|error| io_error("absent-readback-fstat", target, error))?;
        if readback != desired_bytes {
            return Err(format!("projectio-absent-readback-mismatch {}", target.display()));
        }
        if after_read.mode() & 0o7777 != mode & 0o7777
            || after_read.uid() != uid
            || after_read.gid() != gid
            || file_identity(&after_read) != staged_identity
        {
            return Err(format!("projectio-absent-readback-metadata-mismatch {}", target.display()));
        }
        let path_stat = stat_at_nofollow(&directory, &target_name)
            .map_err(|error| io_error("absent-readback-stat", target, error))?;
        if path_stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat_identity(&path_stat) != staged_identity
        {
            return Err(format!("projectio-absent-readback-path-changed {}", target.display()));
        }
        let readback_sha256 = sha256(&readback);
        Ok(AbsentCreationReceipt {
            struck_sha256: sha256(desired_bytes),
            backup_path: None,
            before_sha256: None,
            target_sha256: readback_sha256.clone(),
            readback_sha256,
            mode,
            uid,
            gid,
        })
    })();

    match result {
        Ok(receipt) => Ok(receipt),
        Err(error) => {
            let mut cleanup_failures = Vec::new();
            if promoted {
                if let Err(cleanup) = unlink_owned_staged_file(
                    &directory,
                    &target_name,
                    staged_identity,
                    target,
                    "absent-created-target-cleanup",
                ) {
                    cleanup_failures.push(cleanup);
                }
            }
            if let Err(cleanup) = unlink_owned_staged_file(
                &directory,
                &staged_name,
                staged_identity,
                &staged_path,
                "absent-temp-cleanup",
            ) {
                cleanup_failures.push(cleanup);
            }
            if (!cleanup_failures.is_empty() || promoted)
                && directory.sync_all().is_err()
            {
                cleanup_failures.push(io_error(
                    "absent-cleanup-parent-sync",
                    parent,
                    std::io::Error::last_os_error(),
                ));
            }
            if cleanup_failures.is_empty() {
                Err(error)
            } else {
                Err(format!("{error}; {}", cleanup_failures.join("; ")))
            }
        }
    }
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

pub(crate) fn act_strike(
    auth: &crate::atoms::comparison::ActionAuthorization,
    target: &Path, bytes: &[u8], mode: u32, uid: u32, gid: u32,
) -> Result<Receipt, String> {
    check_act_path(target).map_err(|e| e.to_string())?;
    let metadata = fs::symlink_metadata(target).map_err(|e| io_error("target-stat", target, e))?;
    if !metadata.file_type().is_file() {
        return Err(format!("projectio-target-not-regular-file {}", target.display()));
    }
    let original_bytes = read_engine_state_target(target)?;
    let sequence = ENGINE_STATE_BACKUP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = target.file_name().and_then(|n| n.to_str()).unwrap_or("target");
    let backup = target.parent().unwrap_or_else(|| Path::new(".")).join(format!(
        ".projectio-known-good-{}-{sequence}-{name}.backup", std::process::id()
    ));
    let attempt = strike_with_tracking(Request {
        target, desired_bytes: bytes, mode, uid, gid, backup_path: &backup,
        witness: KnownGoodWitness(auth),
    }, Some(file_identity(&metadata)), Some((&original_bytes, &metadata)));
    let outcome = attempt.result.and_then(|receipt| {
        remove_engine_state_backup(&backup)?;
        Ok(receipt)
    });
    match outcome {
        Ok(receipt) => Ok(receipt),
        Err(error) => match restore_existing_engine_state(
            target, &backup, &original_bytes, &metadata, attempt.target_identity,
            attempt.backup_created, attempt.target_replaced,
        ) {
            Ok(()) => Err(error),
            Err(restore_error) => Err(format!("{error}; {restore_error}")),
        },
    }
}

pub(crate) fn act_create(
    auth: &crate::atoms::comparison::ActionAuthorization,
    target: &Path, bytes: &[u8], mode: u32, uid: u32, gid: u32,
) -> Result<AbsentCreationReceipt, String> {
    check_act_path(target).map_err(|e| e.to_string())?;
    create_absent_with_witness(AbsentCreationRequest {
        target, desired_bytes: bytes, mode, uid, gid, witness: KnownGoodWitness(auth),
    })
}

#[allow(dead_code)]
pub(crate) struct RollbackWitness(());

/// Only a sealed Snapshot mints one, so a failed observation never does.
#[allow(dead_code)]
pub(crate) fn rollback_witness(
    _sealed: &crate::atoms::r#do::ritual::Snapshot,
    _key: &crate::atoms::r#do::InvocationKey,
) -> RollbackWitness { RollbackWitness(()) }

/// A scratch name belongs to the act, not to the touch collector.
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(crate) enum ScratchWitness<'a> {
    KnownGood(&'a crate::atoms::comparison::ActionAuthorization),
    Engine(&'a EngineStateWitness),
    Rollback(&'a RollbackWitness),
}
#[allow(dead_code)]
impl<'a> From<&'a RollbackWitness> for ScratchWitness<'a> {
    fn from(w: &'a RollbackWitness) -> Self { Self::Rollback(w) }
}
#[allow(dead_code)]
impl<'a> From<&'a crate::atoms::comparison::ActionAuthorization> for ScratchWitness<'a> {
    fn from(w: &'a crate::atoms::comparison::ActionAuthorization) -> Self { Self::KnownGood(w) }
}
#[allow(dead_code)]
impl<'a> From<&'a EngineStateWitness> for ScratchWitness<'a> {
    fn from(w: &'a EngineStateWitness) -> Self { Self::Engine(w) }
}
#[allow(dead_code)]
impl ScratchWitness<'_> {
    fn hold(self) { match self { Self::KnownGood(w) => { let _ = w; }, Self::Engine(w) => { let _ = w; }, Self::Rollback(w) => { let _ = w; } } }
}

/// A caller's authority accompanies held-descriptor mutations.
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(crate) enum PenWitness<'a> {
    Owner(&'a OwnerAcceptance),
    Engine(&'a EngineStateWitness),
    KnownGood(&'a crate::atoms::comparison::ActionAuthorization),
    Rollback(&'a RollbackWitness),
}
#[allow(dead_code)]
impl<'a> From<&'a RollbackWitness> for PenWitness<'a> {
    fn from(w: &'a RollbackWitness) -> Self { Self::Rollback(w) }
}
#[allow(dead_code)]
impl<'a> From<&'a OwnerAcceptance> for PenWitness<'a> {
    fn from(w: &'a OwnerAcceptance) -> Self { Self::Owner(w) }
}
#[allow(dead_code)]
impl<'a> From<&'a EngineStateWitness> for PenWitness<'a> {
    fn from(w: &'a EngineStateWitness) -> Self { Self::Engine(w) }
}
#[allow(dead_code)]
impl<'a> From<&'a crate::atoms::comparison::ActionAuthorization> for PenWitness<'a> {
    fn from(w: &'a crate::atoms::comparison::ActionAuthorization) -> Self { Self::KnownGood(w) }
}
#[allow(dead_code)]
impl PenWitness<'_> {
    fn lane(self) -> &'static str {
        match self {
            Self::Owner(w) => { let _ = w; "interactable" },
            Self::Engine(w) => { let _ = w; "self" },
            Self::KnownGood(w) => { let _ = w; "known-good" },
            Self::Rollback(w) => { let _ = w; "known-good" },
        }
    }
}

#[allow(dead_code)]
fn pen_name(name: &std::ffi::OsStr) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "projectio-invalid-component"));
    }
    std::ffi::CString::new(bytes).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
}
#[allow(dead_code)]
fn pen_check(record: Option<&Path>) -> std::io::Result<()> {
    if let Some(path) = record { check_act_path(path)?; }
    Ok(())
}
#[allow(dead_code)]
fn pen_record(record: Option<&Path>, lane: &'static str) {
    if let Some(path) = record { crate::atoms::touch::record_lane(path, lane); }
}
#[allow(dead_code)]
fn pen_error(act: &str, record: Option<&Path>) -> std::io::Error {
    act_mismatch(act, record.unwrap_or_else(|| Path::new("<fd>")))
}

#[allow(dead_code)]
pub(crate) fn act_fd_owner<'a>(w: impl Into<PenWitness<'a>>, file: &File, uid: libc::uid_t, gid: libc::gid_t, record: Option<&Path>) -> std::io::Result<()> {
    pen_check(record)?;
    let lane = w.into().lane();
    let before = file.metadata()?;
    let changed = (uid != !0 && before.uid() != uid) || (gid != !0 && before.gid() != gid);
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 { return Err(std::io::Error::last_os_error()); }
    if changed { pen_record(record, lane); }
    let after = file.metadata()?;
    if (uid != !0 && after.uid() != uid) || (gid != !0 && after.gid() != gid) { return Err(pen_error("fd-owner", record)); }
    Ok(())
}
#[allow(dead_code)]
pub(crate) fn act_fd_mode<'a>(w: impl Into<PenWitness<'a>>, file: &File, mode: u32, record: Option<&Path>) -> std::io::Result<()> {
    pen_check(record)?;
    let lane = w.into().lane();
    let changed = file.metadata()?.mode() & 0o7777 != mode & 0o7777;
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 { return Err(std::io::Error::last_os_error()); }
    if changed { pen_record(record, lane); }
    if file.metadata()?.mode() & 0o7777 != mode & 0o7777 { return Err(pen_error("fd-mode", record)); }
    Ok(())
}
#[allow(dead_code)]
pub(crate) fn act_fd_write<'a>(w: impl Into<PenWitness<'a>>, file: &File, bytes: &[u8], record: Option<&Path>) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    pen_check(record)?;
    let lane = w.into().lane();
    let length = libc::off_t::try_from(bytes.len()).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "projectio-write-length-overflow"))?;
    // Linux pwrite appends on an O_APPEND descriptor, ignoring its offset.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 { return Err(std::io::Error::last_os_error()); }
    if flags & libc::O_APPEND != 0 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "projectio-fd-write-append-refused")); }
    let mut offset = 0;
    while offset < bytes.len() {
        match file.write_at(&bytes[offset..], offset as u64) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "projectio-fd-write-zero")),
            Ok(n) => offset += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    if unsafe { libc::ftruncate(file.as_raw_fd(), length) } != 0 { return Err(std::io::Error::last_os_error()); }
    file.sync_all()?;
    pen_record(record, lane);
    if !file.metadata().is_ok_and(|m| m.is_file() && m.len() == bytes.len() as u64) { return Err(pen_error("fd-write", record)); }
    let mut buffer = [0u8; 8192];
    let mut offset = 0;
    loop {
        let want = (bytes.len() - offset).min(buffer.len()).max(1);
        match file.read_at(&mut buffer[..want], offset as u64) {
            Ok(0) if offset == bytes.len() => break,
            Ok(0) => return Err(pen_error("fd-write", record)),
            Ok(n) if offset + n <= bytes.len() && buffer[..n] == bytes[offset..offset + n] => offset += n,
            Ok(_) => return Err(pen_error("fd-write", record)),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(pen_error("fd-write", record)),
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn act_at_open_write<'a>(w: impl Into<PenWitness<'a>>, dir: &File, name: &std::ffi::OsStr) -> std::io::Result<File> {
    let name = pen_name(name)?;
    let _ = w.into().lane();
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 { return Err(std::io::Error::last_os_error()); }
    let file = unsafe { File::from_raw_fd(fd) };
    if !file.metadata()?.is_file() { return Err(pen_error("open-write-at", None)); }
    Ok(file)
}

#[allow(dead_code)]
fn cleanup_created_at(dir: &File, name: &std::ffi::CString, file: &File, directory: bool) {
    if let (Ok(opened), Ok(named)) = (file.metadata(), stat_at_nofollow(dir, name)) {
        if file_identity(&opened) == stat_identity(&named) {
            let _ = unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), if directory { libc::AT_REMOVEDIR } else { 0 }) };
        }
    }
}

#[allow(dead_code)]
pub(crate) fn act_at_make_dir<'a>(w: impl Into<PenWitness<'a>>, dir: &File, name: &std::ffi::OsStr, mode: u32, record: Option<&Path>) -> std::io::Result<File> {
    pen_check(record)?; let name = pen_name(name)?; let lane = w.into().lane();
    // Keep the new directory openable before applying a possibly restrictive final mode.
    if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) } != 0 { return Err(std::io::Error::last_os_error()); }
    if let Some(path) = record { crate::atoms::touch::record_made_directory(path, lane); }
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 { return Err(std::io::Error::last_os_error()); }
    let file = unsafe { File::from_raw_fd(fd) };
    let result = (|| {
        if file.metadata()?.uid() != unsafe { libc::geteuid() } {
            return Err(std::io::Error::other(format!("projectio-made-directory-substituted {}", record.unwrap_or_else(|| Path::new("<fd>")).display())));
        }
        if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 { return Err(std::io::Error::last_os_error()); }
        let actual = file.metadata()?;
        let named = stat_at_nofollow(dir, &name)?;
        if !actual.is_dir() || actual.mode() & 0o7777 != mode & 0o7777 || file_identity(&actual) != stat_identity(&named) { return Err(pen_error("make-dir-at", record)); }
        Ok(())
    })();
    if let Err(error) = result {
        cleanup_created_at(dir, &name, &file, true);
        return Err(error);
    }
    Ok(file)
}
#[allow(dead_code)]
pub(crate) fn act_at_create_new<'a>(w: impl Into<PenWitness<'a>>, dir: &File, name: &std::ffi::OsStr, mode: u32, record: Option<&Path>) -> std::io::Result<File> {
    pen_check(record)?; let name = pen_name(name)?; let lane = w.into().lane();
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, mode as libc::mode_t) };
    if fd < 0 { return Err(std::io::Error::last_os_error()); }
    let file = unsafe { File::from_raw_fd(fd) };
    pen_record(record, lane);
    let result = (|| {
        if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 { return Err(std::io::Error::last_os_error()); }
        let actual = file.metadata()?; let named = stat_at_nofollow(dir, &name)?;
        if !actual.is_file() || actual.mode() & 0o7777 != mode & 0o7777 || file_identity(&actual) != stat_identity(&named) { return Err(pen_error("create-at", record)); }
        Ok(())
    })();
    if let Err(error) = result {
        cleanup_created_at(dir, &name, &file, false);
        return Err(error);
    }
    Ok(file)
}
#[allow(dead_code)]
pub(crate) fn act_at_unlink<'a>(w: impl Into<PenWitness<'a>>, dir: &File, name: &std::ffi::OsStr, directory: bool, record: Option<&Path>) -> std::io::Result<()> {
    pen_check(record)?; let name = pen_name(name)?; let lane = w.into().lane();
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), if directory { libc::AT_REMOVEDIR } else { 0 }) } != 0 { return Err(std::io::Error::last_os_error()); }
    pen_record(record, lane);
    if !matches!(stat_at_nofollow(dir, &name), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound) { return Err(pen_error("unlink-at", record)); }
    Ok(())
}
#[allow(dead_code)]
pub(crate) fn act_at_rename<'a>(w: impl Into<PenWitness<'a>>, from_dir: &File, from_name: &std::ffi::OsStr, to_dir: &File, to_name: &std::ffi::OsStr, how: LinkPromotion, record_to: Option<&Path>, record_from: Option<&Path>) -> std::io::Result<()> {
    pen_check(record_to)?; pen_check(record_from)?; let from_name = pen_name(from_name)?; let to_name = pen_name(to_name)?; let lane = w.into().lane();
    let before = stat_at_nofollow(from_dir, &from_name)?;
    let other = if matches!(how, LinkPromotion::Exchange) { Some(stat_at_nofollow(to_dir, &to_name)?) } else { None };
    // POSIX rename of two names for the same inode succeeds without a mutation.
    if matches!(how, LinkPromotion::Rename)
        && stat_at_nofollow(to_dir, &to_name).is_ok_and(|s| stat_identity(&s) == stat_identity(&before)) {
        return Ok(());
    }
    let flags = match how { LinkPromotion::Rename => 0, LinkPromotion::Exchange => libc::RENAME_EXCHANGE, LinkPromotion::NoReplace => libc::RENAME_NOREPLACE };
    if unsafe { libc::renameat2(from_dir.as_raw_fd(), from_name.as_ptr(), to_dir.as_raw_fd(), to_name.as_ptr(), flags) } != 0 { return Err(std::io::Error::last_os_error()); }
    pen_record(record_to, lane); pen_record(record_from, lane);
    let to_ok = stat_at_nofollow(to_dir, &to_name).is_ok_and(|s| stat_identity(&s) == stat_identity(&before));
    let from_ok = match other { Some(s) => stat_at_nofollow(from_dir, &from_name).is_ok_and(|a| stat_identity(&a) == stat_identity(&s)), None => matches!(stat_at_nofollow(from_dir, &from_name), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound) };
    if !to_ok || !from_ok { return Err(pen_error("rename-at", record_to)); }
    Ok(())
}
#[allow(dead_code)]
pub(crate) fn act_at_link<'a>(w: impl Into<PenWitness<'a>>, from_dir: &File, from_name: &std::ffi::OsStr, to_dir: &File, to_name: &std::ffi::OsStr, record: Option<&Path>) -> std::io::Result<()> {
    pen_check(record)?; let from_name = pen_name(from_name)?; let to_name = pen_name(to_name)?; let lane = w.into().lane();
    if unsafe { libc::linkat(from_dir.as_raw_fd(), from_name.as_ptr(), to_dir.as_raw_fd(), to_name.as_ptr(), 0) } != 0 { return Err(std::io::Error::last_os_error()); }
    pen_record(record, lane);
    let a = stat_at_nofollow(from_dir, &from_name)?; let b = stat_at_nofollow(to_dir, &to_name)?;
    if stat_identity(&a) != stat_identity(&b) { return Err(pen_error("link-at", record)); }
    Ok(())
}
#[allow(dead_code)]
pub(crate) fn act_fd_link<'a>(w: impl Into<PenWitness<'a>>, file: &File, to_dir: &File, to_name: &std::ffi::OsStr, record: Option<&Path>) -> std::io::Result<()> {
    pen_check(record)?; let to_name = pen_name(to_name)?; let lane = w.into().lane();
    let source = std::ffi::CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).expect("fd path contains no NUL");
    let before = file.metadata()?;
    if unsafe { libc::linkat(libc::AT_FDCWD, source.as_ptr(), to_dir.as_raw_fd(), to_name.as_ptr(), libc::AT_SYMLINK_FOLLOW) } != 0 { return Err(std::io::Error::last_os_error()); }
    pen_record(record, lane);
    if stat_identity(&stat_at_nofollow(to_dir, &to_name)?) != file_identity(&before) { return Err(pen_error("fd-link", record)); }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn act_scratch_make_dir_new_mode<'a>(w: impl Into<ScratchWitness<'a>>, path: &Path, mode: u32) -> std::io::Result<()> {
    w.into().hold(); check_act_path(path)?; fs::create_dir(path)?;
    let dir = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
    if dir.metadata()?.uid() != unsafe { libc::geteuid() } {
        return Err(std::io::Error::other(format!("projectio-made-directory-substituted {}", path.display())));
    }
    if unsafe { libc::fchmod(dir.as_raw_fd(), mode as libc::mode_t) } != 0 { return Err(std::io::Error::last_os_error()); }
    let opened = dir.metadata()?; let named = fs::symlink_metadata(path)?;
    if !opened.is_dir() || opened.mode() & 0o7777 != mode & 0o7777 || file_identity(&opened) != file_identity(&named) { return Err(act_mismatch("scratch-make-dir", path)); }
    Ok(())
}
#[allow(dead_code)]
pub(crate) fn act_scratch_rename_new<'a>(w: impl Into<ScratchWitness<'a>>, from: &Path, to: &Path) -> std::io::Result<()> {
    w.into().hold(); check_act_path(from)?; check_act_path(to)?;
    let before = fs::symlink_metadata(from)?;
    renameat2_raw(from, to, libc::RENAME_NOREPLACE)?;
    if !fs::symlink_metadata(to).is_ok_and(|m| file_identity(&m) == file_identity(&before)) || !matches!(fs::symlink_metadata(from), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound) { return Err(act_mismatch("scratch-rename", to)); }
    Ok(())
}
#[allow(dead_code)]
pub(crate) fn act_scratch_symlink<'a>(w: impl Into<ScratchWitness<'a>>, text: &Path, path: &Path) -> std::io::Result<()> {
    w.into().hold(); check_act_path(path)?; std::os::unix::fs::symlink(text, path)?;
    if !fs::read_link(path).is_ok_and(|actual| actual == text) { return Err(act_mismatch("scratch-symlink", path)); }
    Ok(())
}
#[allow(dead_code)]
pub(crate) fn act_scratch_temp_dir<'a>(w: impl Into<ScratchWitness<'a>>, parent: &Path, prefix: &std::ffi::OsStr) -> std::io::Result<PathBuf> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    w.into().hold(); check_act_path(parent)?; let _ = pen_name(prefix)?;
    let mut leaf = prefix.as_bytes().to_vec(); leaf.extend_from_slice(b"XXXXXX");
    let template = parent.join(std::ffi::OsString::from_vec(leaf)); check_act_path(&template)?;
    let mut bytes = std::ffi::CString::new(template.as_os_str().as_bytes()).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?.into_bytes_with_nul();
    if unsafe { libc::mkdtemp(bytes.as_mut_ptr().cast()) }.is_null() { return Err(std::io::Error::last_os_error()); }
    bytes.pop(); let made = PathBuf::from(std::ffi::OsString::from_vec(bytes));
    let meta = fs::symlink_metadata(&made)?;
    if !meta.is_dir() || meta.mode() & 0o7777 != 0o700 { return Err(act_mismatch("scratch-temp-dir", &made)); }
    Ok(made)
}

// Create each missing rung separately: partial success must not lose its touch.
fn make_directories(path: &Path, record: bool) -> std::io::Result<Vec<PathBuf>> {
    check_act_path(path)?;
    if path.as_os_str().is_empty() { return Ok(Vec::new()); }
    let mut missing = Vec::new();
    for p in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        match fs::metadata(p) {
            Ok(m) if m.is_dir() => break,
            Ok(_) => return Err(std::io::Error::new(std::io::ErrorKind::NotADirectory, "projectio-parent-not-directory")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => missing.push(p.to_path_buf()),
            Err(e) => return Err(e),
        }
    }
    let mut made = Vec::new();
    for p in missing.iter().rev() {
        match fs::create_dir(p) {
            Ok(()) => {
                if record { crate::atoms::touch::record_made_directory(p, "self"); }
                made.push(p.clone());
                if !fs::metadata(p).is_ok_and(|m| m.is_dir()) { return Err(act_mismatch("make-dir", p)); }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && fs::metadata(p).is_ok_and(|m| m.is_dir()) => {},
            Err(e) => return Err(e),
        }
    }
    if !fs::metadata(path).is_ok_and(|m| m.is_dir()) { return Err(act_mismatch("make-dir", path)); }
    Ok(made)
}

#[allow(dead_code)]
pub(crate) fn act_scratch_make_dir<'a>(w: impl Into<ScratchWitness<'a>>, path: &Path) -> std::io::Result<Vec<PathBuf>> {
    w.into().hold(); make_directories(path, false)
}
#[allow(dead_code)]
pub(crate) fn act_scratch_make_dir_new<'a>(w: impl Into<ScratchWitness<'a>>, path: &Path) -> std::io::Result<()> {
    w.into().hold(); check_act_path(path)?; fs::create_dir(path)?;
    if !fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) { return Err(act_mismatch("make-dir", path)); }
    Ok(())
}
fn set_act_mode(path: &Path, mode: u32, record: bool) -> std::io::Result<()> {
    check_act_path(path)?;
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() { return Err(std::io::Error::other(format!("projectio-mode-symlink-refused {}", path.display()))); }
    let changed = before.mode() & 0o7777 != mode & 0o7777;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    if record && changed { crate::atoms::touch::record_lane(path, "self"); }
    if !fs::symlink_metadata(path).is_ok_and(|m| !m.file_type().is_symlink() && m.mode() & 0o7777 == mode & 0o7777) { return Err(act_mismatch("mode", path)); }
    Ok(())
}
#[allow(dead_code)]
pub(crate) fn act_scratch_mode<'a>(w: impl Into<ScratchWitness<'a>>, path: &Path, mode: u32) -> std::io::Result<()> {
    w.into().hold(); set_act_mode(path, mode, false)
}
#[allow(dead_code)]
pub(crate) fn act_scratch_chown<'a>(w: impl Into<ScratchWitness<'a>>, path: &Path, uid: libc::uid_t, gid: libc::gid_t) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    w.into().hold(); check_act_path(path)?;
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() { return Err(std::io::Error::other(format!("projectio-owner-symlink-refused {}", path.display()))); }
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    if unsafe { libc::lchown(c.as_ptr(), uid, gid) } != 0 { return Err(std::io::Error::last_os_error()); }
    if !fs::symlink_metadata(path).is_ok_and(|m| !m.file_type().is_symlink() && (uid == !0 || m.uid() == uid) && (gid == !0 || m.gid() == gid)) { return Err(act_mismatch("owner", path)); }
    Ok(())
}
/// Change the owner of the scratch link itself, never its target.
#[allow(dead_code)]
pub(crate) fn act_scratch_link_owner<'a>(w: impl Into<ScratchWitness<'a>>, path: &Path, uid: libc::uid_t, gid: libc::gid_t) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    w.into().hold();
    check_act_path(path)?;
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_symlink() { return Err(std::io::Error::other(format!("projectio-owner-not-symlink-refused {}", path.display()))); }
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    if unsafe { libc::lchown(c.as_ptr(), uid, gid) } != 0 { return Err(std::io::Error::last_os_error()); }
    if !fs::symlink_metadata(path).is_ok_and(|after| after.file_type().is_symlink()
        && after.dev() == before.dev() && after.ino() == before.ino()
        && (uid == !0 || after.uid() == uid) && (gid == !0 || after.gid() == gid)) {
        return Err(act_mismatch("link-owner", path));
    }
    Ok(())
}

/// Restore a mode under the sealed rollback witness, recording real changes.
#[allow(dead_code)]
pub(crate) fn rollback_mode(_w: &RollbackWitness, path: &Path, mode: u32) -> std::io::Result<()> {
    check_act_path(path)?;
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() { return Err(std::io::Error::other(format!("projectio-mode-symlink-refused {}", path.display()))); }
    let changed = before.mode() & 0o7777 != mode & 0o7777;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    let matches = fs::symlink_metadata(path).is_ok_and(|after| !after.file_type().is_symlink()
        && after.dev() == before.dev() && after.ino() == before.ino()
        && after.mode() & 0o7777 == mode & 0o7777);
    if changed { crate::atoms::touch::record_lane(path, "known-good"); }
    if !matches { return Err(act_mismatch("mode", path)); }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn act_scratch_write_new<'a>(w: impl Into<ScratchWitness<'a>>, path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    w.into().hold(); check_act_path(path)?;
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?; f.set_permissions(fs::Permissions::from_mode(mode))?; f.sync_all()?;
    if !file_readback(path, bytes, mode) { return Err(act_mismatch("write", path)); }
    Ok(())
}
fn file_readback(path: &Path, bytes: &[u8], mode: u32) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && m.mode() & 0o7777 == mode & 0o7777)
        && fs::read(path).is_ok_and(|b| b == bytes)
}
fn remove_act(path: &Path, kind: u8, record: bool) -> std::io::Result<()> {
    check_act_path(path)?;
    let result = match kind {
        0 => fs::remove_file(path),
        1 => fs::remove_dir(path),
        _ => { let m = fs::symlink_metadata(path)?; if m.is_dir() { fs::remove_dir_all(path) } else { fs::remove_file(path) } },
    };
    // remove_dir_all may have removed part of the tree before failing.
    if kind == 2 && result.is_err() && record { crate::atoms::touch::record_lane(path, "self"); }
    result?;
    if record { crate::atoms::touch::record_lane(path, "self"); }
    if !matches!(fs::symlink_metadata(path), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound) { return Err(act_mismatch("remove", path)); }
    Ok(())
}
#[allow(dead_code)]
pub(crate) fn act_scratch_remove<'a>(w: impl Into<ScratchWitness<'a>>, path: &Path) -> std::io::Result<()> { w.into().hold(); remove_act(path, 0, false) }
#[allow(dead_code)]
pub(crate) fn act_scratch_remove_dir<'a>(w: impl Into<ScratchWitness<'a>>, path: &Path) -> std::io::Result<()> { w.into().hold(); remove_act(path, 1, false) }
#[allow(dead_code)]
pub(crate) fn act_scratch_remove_tree<'a>(w: impl Into<ScratchWitness<'a>>, path: &Path) -> std::io::Result<()> { w.into().hold(); remove_act(path, 2, false) }

#[allow(dead_code)]
pub(crate) fn engine_make_dir(_w: &EngineStateWitness, path: &Path) -> std::io::Result<()> { make_directories(path, true).map(|_| ()) }
#[allow(dead_code)]
pub(crate) fn engine_mode(_w: &EngineStateWitness, path: &Path, mode: u32) -> std::io::Result<()> { set_act_mode(path, mode, true) }

// Write and sync an unrecorded sibling, then make the fully formed inode visible.
fn engine_write(target: &Path, bytes: &[u8], mode: u32, exclusive: bool) -> std::io::Result<()> {
    check_act_path(target)?;
    if !exclusive { cleanup_stale_temporaries_for_target(target).map_err(std::io::Error::other)?; }
    let parent = target.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let name = target.file_name().and_then(|n| n.to_str()).unwrap_or("target");
    let (mut temp, temp_path) = create_temp(parent, name).map_err(std::io::Error::other)?;
    let result = (|| {
        temp.write_all(bytes)?;
        temp.set_permissions(fs::Permissions::from_mode(mode))?;
        temp.sync_all()?;
        if exclusive { renameat2_raw(&temp_path, target, libc::RENAME_NOREPLACE)?; }
        else { fs::rename(&temp_path, target)?; }
        crate::atoms::touch::record_lane(target, "self");
        File::open(parent)?.sync_all()?;
        if !file_readback(target, bytes, mode) { return Err(act_mismatch("write", target)); }
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&temp_path); }
    result
}
#[allow(dead_code)]
pub(crate) fn engine_create_new(_w: &EngineStateWitness, target: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> { engine_write(target, bytes, mode, true) }
#[allow(dead_code)]
pub(crate) fn engine_put(_w: &EngineStateWitness, target: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> { engine_write(target, bytes, mode, false) }
#[allow(dead_code)]
pub(crate) fn engine_put_owned(_w: &EngineStateWitness, target: &Path, bytes: &[u8], mode: u32, uid: u32, gid: u32) -> std::io::Result<()> {
    check_act_path(target)?;
    cleanup_stale_temporaries_for_target(target).map_err(std::io::Error::other)?;
    put_file(target, bytes, mode, Some(uid), Some(gid), false, Some("self"))
}
#[allow(dead_code)]
pub(crate) fn engine_open_lock(_w: &EngineStateWitness, path: &Path) -> std::io::Result<File> {
    check_act_path(path)?;
    let (file, created) = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(f) => (f, true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (OpenOptions::new().write(true).custom_flags(libc::O_NOFOLLOW).open(path)?, false),
        Err(e) => return Err(e),
    };
    if created { crate::atoms::touch::record_lane(path, "self"); }
    let opened = file.metadata()?;
    if !opened.is_file() || !fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && file_identity(&m) == file_identity(&opened)) { return Err(act_mismatch("lock", path)); }
    Ok(file)
}
#[allow(dead_code)]
pub(crate) fn engine_rename(_w: &EngineStateWitness, from: &Path, to: &Path, scratch_from: bool, scratch_to: bool) -> std::io::Result<()> {
    check_act_path(from)?; check_act_path(to)?;
    let before = fs::symlink_metadata(from)?;
    // POSIX rename is a no-op if both names already identify the same inode.
    if fs::symlink_metadata(to).is_ok_and(|m| file_identity(&m) == file_identity(&before)) {
        return Ok(());
    }
    fs::rename(from, to)?;
    if !scratch_to { crate::atoms::touch::record_lane(to, "self"); }
    if !scratch_from { crate::atoms::touch::record_lane(from, "self"); }
    if !fs::symlink_metadata(to).is_ok_and(|m| file_identity(&m) == file_identity(&before)) || !matches!(fs::symlink_metadata(from), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound) { return Err(act_mismatch("rename", to)); }
    Ok(())
}
#[allow(dead_code)]
pub(crate) fn engine_remove(_w: &EngineStateWitness, path: &Path, scratch: bool) -> std::io::Result<()> { remove_act(path, 0, !scratch) }
#[allow(dead_code)]
pub(crate) fn engine_remove_if(_w: &EngineStateWitness, path: &Path, expected: &[u8], scratch: bool) -> std::io::Result<()> {
    remove_if_claimed(path, expected, scratch, "self")
}

#[allow(dead_code)]
fn remove_if_claimed(path: &Path, expected: &[u8], scratch: bool, lane: &'static str) -> std::io::Result<()> {
    check_act_path(path)?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let name = path.file_name().and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "projectio-remove-if-invalid-name"))?;
    let claim = loop {
        let sequence = ENGINE_STATE_BACKUP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let claim = parent.join(format!(".projectio-{}-{sequence}-{name}", std::process::id()));
        match renameat2_raw(path, &claim, libc::RENAME_NOREPLACE) {
            Ok(()) => break claim,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    };
    // Only the claimed name is inspected or removed; a replacement at path is never touched.
    let checked = (|| -> std::io::Result<FileIdentity> {
        let metadata = fs::symlink_metadata(&claim)?;
        if !metadata.file_type().is_file() {
            return Err(std::io::Error::other(format!("projectio-remove-if-not-regular {}", path.display())));
        }
        let bytes = read_engine_state_target(&claim).map_err(std::io::Error::other)?;
        if bytes != expected {
            return Err(std::io::Error::other(format!("projectio-remove-if-refused {}", path.display())));
        }
        verify_preimage(&claim, expected, &metadata).map_err(std::io::Error::other)?;
        Ok(file_identity(&metadata))
    })();
    let identity = match checked {
        Ok(identity) => identity,
        Err(error) => {
            if let Err(restore) = renameat2_raw(&claim, path, libc::RENAME_NOREPLACE) {
                return Err(std::io::Error::other(format!("{error}; projectio-remove-if-put-back {} -> {}: {restore}; claim retained", claim.display(), path.display())));
            }
            return Err(error);
        }
    };
    fs::remove_file(&claim).map_err(|e| std::io::Error::new(e.kind(), format!("projectio-remove-if-claim-remove {} (target {}): {e}", claim.display(), path.display())))?;
    if !scratch { crate::atoms::touch::record_lane(path, lane); }
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(metadata) if file_identity(&metadata) != identity => Ok(()),
        Ok(_) => Err(act_mismatch("remove-if", path)),
        Err(e) => Err(e),
    }
}
#[allow(dead_code)]
pub(crate) fn engine_remove_dir(_w: &EngineStateWitness, path: &Path, scratch: bool) -> std::io::Result<()> { remove_act(path, 1, !scratch) }
#[allow(dead_code)]
pub(crate) fn engine_remove_tree(_w: &EngineStateWitness, path: &Path, scratch: bool) -> std::io::Result<()> { remove_act(path, 2, !scratch) }

// Read a regular file without following a final symlink, and keep its metadata.
#[allow(dead_code)]
fn read_regular(path: &Path) -> std::io::Result<(Vec<u8>, fs::Metadata)> {
    check_act_path(path)?;
    let mut file = OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() { return Err(std::io::Error::other("projectio-source-not-regular")); }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok((bytes, metadata))
}

#[allow(dead_code)]
fn put_file(target: &Path, bytes: &[u8], mode: u32, uid: Option<u32>, gid: Option<u32>, exclusive: bool, record: Option<&'static str>) -> std::io::Result<()> {
    check_act_path(target)?;
    let parent = target.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let name = target.file_name().and_then(|n| n.to_str()).unwrap_or("target");
    let (mut temp, temp_path) = create_temp(parent, name).map_err(std::io::Error::other)?;
    let result = (|| {
        temp.write_all(bytes)?;
        if uid.is_some() || gid.is_some() {
            if unsafe { libc::fchown(temp.as_raw_fd(), uid.unwrap_or(!0), gid.unwrap_or(!0)) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        temp.set_permissions(fs::Permissions::from_mode(mode))?;
        temp.sync_all()?;
        let staged = temp.metadata()?;
        if exclusive { renameat2_raw(&temp_path, target, libc::RENAME_NOREPLACE)?; }
        else { fs::rename(&temp_path, target)?; }
        if let Some(lane) = record { crate::atoms::touch::record_lane(target, lane); }
        File::open(parent)?.sync_all()?;
        let (actual, metadata) = read_regular(target)?;
        if actual != bytes || file_identity(&metadata) != file_identity(&staged)
            || metadata.mode() & 0o7777 != mode & 0o7777
            || uid.is_some_and(|u| metadata.uid() != u)
            || gid.is_some_and(|g| metadata.gid() != g) {
            return Err(act_mismatch("put", target));
        }
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&temp_path); }
    result
}

// Unlike create_dir_all, each successful mkdir is recorded before readback.
#[allow(dead_code)]
fn witnessed_directories(path: &Path, lane: &'static str) -> std::io::Result<()> {
    check_act_path(path)?;
    let mut missing = Vec::new();
    for p in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        match fs::symlink_metadata(p) {
            Ok(m) if m.is_dir() => break,
            Ok(_) => return Err(std::io::Error::other(format!("projectio-parent-not-directory {}", p.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => missing.push(p.to_path_buf()),
            Err(e) => return Err(e),
        }
    }
    for p in missing.iter().rev() {
        match fs::create_dir(p) {
            Ok(()) => crate::atoms::touch::record_made_directory(p, lane),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()) => continue,
            Err(e) => return Err(e),
        }
        if !fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()) { return Err(act_mismatch("make-dir", p)); }
    }
    if !fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) { return Err(act_mismatch("make-dir", path)); }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn rollback_put(_w: &RollbackWitness, target: &Path, bytes: &[u8], mode: u32, uid: u32, gid: u32) -> std::io::Result<()> {
    check_act_path(target)?;
    put_file(target, bytes, mode, Some(uid), Some(gid), false, Some("known-good"))
}
#[allow(dead_code)]
pub(crate) fn rollback_remove(_w: &RollbackWitness, path: &Path, scratch: bool) -> std::io::Result<()> {
    check_act_path(path)?;
    fs::remove_file(path)?;
    if !scratch { crate::atoms::touch::record_lane(path, "known-good"); }
    if !matches!(fs::symlink_metadata(path), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound) { return Err(act_mismatch("remove", path)); }
    Ok(())
}
#[allow(dead_code)]
pub(crate) fn rollback_make_dir(_w: &RollbackWitness, path: &Path) -> std::io::Result<()> { witnessed_directories(path, "known-good") }

#[allow(dead_code)]
pub(crate) fn rollback_symlink(w: &RollbackWitness, text: &Path, path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    check_act_path(path)?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let temp = loop {
        let sequence = ENGINE_STATE_BACKUP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp = parent.join(format!(".projectio-link-{}-{sequence}", std::process::id()));
        check_act_path(&temp)?;
        match std::os::unix::fs::symlink(text, &temp) {
            Ok(()) => break temp,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    };
    let result = (|| {
        let c = std::ffi::CString::new(temp.as_os_str().as_bytes()).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        if unsafe { libc::lchown(c.as_ptr(), uid, gid) } != 0 { return Err(std::io::Error::last_os_error()); }
        let staged = fs::symlink_metadata(&temp)?;
        if !staged.file_type().is_symlink() || (uid != !0 && staged.uid() != uid) || (gid != !0 && staged.gid() != gid) || fs::read_link(&temp)? != text { return Err(act_mismatch("symlink-stage", &temp)); }
        fs::rename(&temp, path)?;
        crate::atoms::touch::record_lane(path, "known-good");
        let actual = fs::symlink_metadata(path)?;
        if !actual.file_type().is_symlink() || file_identity(&actual) != file_identity(&staged) || (uid != !0 && actual.uid() != uid) || (gid != !0 && actual.gid() != gid) || fs::read_link(path)? != text { return Err(act_mismatch("symlink", path)); }
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&temp); }
    let _ = w;
    result
}
#[allow(dead_code)]
pub(crate) fn rollback_rename(_w: &RollbackWitness, from: &Path, to: &Path, scratch_from: bool, scratch_to: bool) -> std::io::Result<()> {
    check_act_path(from)?; check_act_path(to)?;
    let before = fs::symlink_metadata(from)?;
    if fs::symlink_metadata(to).is_ok_and(|m| file_identity(&m) == file_identity(&before)) { return Ok(()); }
    fs::rename(from, to)?;
    if !scratch_to { crate::atoms::touch::record_lane(to, "known-good"); }
    if !scratch_from { crate::atoms::touch::record_lane(from, "known-good"); }
    if !fs::symlink_metadata(to).is_ok_and(|m| file_identity(&m) == file_identity(&before)) || !matches!(fs::symlink_metadata(from), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound) { return Err(act_mismatch("rename", to)); }
    Ok(())
}
#[allow(dead_code)]
pub(crate) fn owner_make_dir(_w: &OwnerAcceptance, path: &Path) -> std::io::Result<()> { witnessed_directories(path, "interactable") }
#[allow(dead_code)]
pub(crate) fn owner_mode(_w: &OwnerAcceptance, path: &Path, mode: u32) -> std::io::Result<()> {
    check_act_path(path)?;
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path)?;
    let before = file.metadata()?;
    let changed = before.mode() & 0o7777 != mode & 0o7777;
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 { return Err(std::io::Error::last_os_error()); }
    if changed { crate::atoms::touch::record_lane(path, "interactable"); }
    if !fs::symlink_metadata(path).is_ok_and(|m| !m.file_type().is_symlink() && file_identity(&m) == file_identity(&before) && m.mode() & 0o7777 == mode & 0o7777) { return Err(act_mismatch("mode", path)); }
    Ok(())
}
#[allow(dead_code)]
pub(crate) fn owner_chown(_w: &OwnerAcceptance, path: &Path, uid: libc::uid_t, gid: libc::gid_t) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    check_act_path(path)?;
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() { return Err(std::io::Error::other(format!("projectio-owner-symlink-refused {}", path.display()))); }
    let changed = (uid != !0 && before.uid() != uid) || (gid != !0 && before.gid() != gid);
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    if unsafe { libc::lchown(c.as_ptr(), uid, gid) } != 0 { return Err(std::io::Error::last_os_error()); }
    if changed { crate::atoms::touch::record_lane(path, "interactable"); }
    if !fs::symlink_metadata(path).is_ok_and(|m| !m.file_type().is_symlink() && file_identity(&m) == file_identity(&before) && (uid == !0 || m.uid() == uid) && (gid == !0 || m.gid() == gid)) { return Err(act_mismatch("owner", path)); }
    Ok(())
}
#[allow(dead_code)]
pub(crate) fn owner_remove_if_current(_w: &OwnerAcceptance, path: &Path, expected: &[u8], scratch: bool) -> std::io::Result<()> { remove_if_claimed(path, expected, scratch, "interactable") }

#[allow(dead_code)]
pub(crate) fn act_put(_auth: &crate::atoms::comparison::ActionAuthorization, target: &Path, bytes: &[u8], mode: Option<u32>, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()> {
    check_act_path(target)?;
    let existing = match fs::symlink_metadata(target) {
        Ok(m) if m.is_file() => Some(m),
        Ok(_) => return Err(std::io::Error::other("projectio-target-not-regular-file")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let mode = mode.or_else(|| existing.as_ref().map(|m| m.mode() & 0o7777))
        .ok_or_else(|| std::io::Error::other("projectio-put-absent-needs-mode"))?;
    let uid = uid.unwrap_or_else(|| existing.as_ref().map(|m| m.uid()).unwrap_or_else(|| unsafe { libc::geteuid() }));
    let gid = gid.unwrap_or_else(|| existing.as_ref().map(|m| m.gid()).unwrap_or_else(|| unsafe { libc::getegid() }));
    put_file(target, bytes, mode, Some(uid), Some(gid), existing.is_none(), Some("known-good"))
}

#[allow(dead_code)]
pub(crate) fn act_copy(auth: &crate::atoms::comparison::ActionAuthorization, source: &Path, target: &Path, mode: Option<u32>, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()> {
    check_act_path(source)?; check_act_path(target)?;
    let (bytes, metadata) = read_regular(source)?;
    act_put(auth, target, &bytes, Some(mode.unwrap_or(metadata.mode() & 0o7777)), uid, gid)
}

#[allow(dead_code)]
pub(crate) fn act_scratch_copy<'a>(w: impl Into<ScratchWitness<'a>>, source: &Path, target: &Path, mode: Option<u32>) -> std::io::Result<()> {
    w.into().hold(); check_act_path(source)?; check_act_path(target)?;
    let (bytes, metadata) = read_regular(source)?;
    put_file(target, &bytes, mode.unwrap_or(metadata.mode() & 0o7777), None, None, true, None)
}

/// A tree promoted later by act_rename records only the promoted root.
#[allow(dead_code)]
pub(crate) fn act_scratch_copy_tree<'a>(w: impl Into<ScratchWitness<'a>>, source_dir: &Path, target_dir: &Path) -> std::io::Result<()> {
    let w = w.into(); w.hold(); check_act_path(source_dir)?; check_act_path(target_dir)?;
    let metadata = fs::symlink_metadata(source_dir)?;
    if !metadata.is_dir() { return Err(std::io::Error::other("projectio-source-not-directory")); }
    fs::create_dir(target_dir)?;
    for entry in fs::read_dir(source_dir)? {
        let entry = entry?;
        let source = entry.path(); let target = target_dir.join(entry.file_name());
        let m = fs::symlink_metadata(&source)?;
        if m.file_type().is_symlink() {
            let text = fs::read_link(&source)?;
            std::os::unix::fs::symlink(&text, &target)?;
            if fs::read_link(&target)? != text { return Err(act_mismatch("link", &target)); }
        } else if m.is_dir() {
            act_scratch_copy_tree(w, &source, &target)?;
        } else if m.is_file() {
            act_scratch_copy(w, &source, &target, Some(m.mode() & 0o7777))?;
        } else { return Err(std::io::Error::other("projectio-source-not-regular")); }
    }
    let dir = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC).open(target_dir)?;
    dir.set_permissions(fs::Permissions::from_mode(metadata.mode() & 0o7777))?;
    dir.sync_all()?;
    let opened = dir.metadata()?;
    if !fs::symlink_metadata(target_dir).is_ok_and(|m| m.is_dir() && m.mode() & 0o7777 == metadata.mode() & 0o7777 && file_identity(&m) == file_identity(&opened)) { return Err(act_mismatch("tree", target_dir)); }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn act_exchange_files(_auth: &crate::atoms::comparison::ActionAuthorization, candidate: &Path, target: &Path) -> std::io::Result<()> {
    check_act_path(candidate)?; check_act_path(target)?;
    let a = fs::symlink_metadata(candidate)?; let b = fs::symlink_metadata(target)?;
    if !a.is_file() || !b.is_file() { return Err(std::io::Error::other("projectio-exchange-not-regular")); }
    renameat2_raw(candidate, target, libc::RENAME_EXCHANGE)?;
    crate::atoms::touch::record_lane(target, "known-good");
    if !fs::symlink_metadata(candidate).is_ok_and(|m| m.is_file() && file_identity(&m) == file_identity(&b))
        || !fs::symlink_metadata(target).is_ok_and(|m| m.is_file() && file_identity(&m) == file_identity(&a)) { return Err(act_mismatch("exchange", target)); }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn act_remove_if_current(_auth: &crate::atoms::comparison::ActionAuthorization, path: &Path, expected: &[u8], scratch: bool) -> std::io::Result<()> {
    remove_if_claimed(path, expected, scratch, "known-good")
}

#[allow(dead_code)]
fn xattr_read(path: &std::ffi::CStr, name: &std::ffi::CStr) -> std::io::Result<Option<Vec<u8>>> {
    loop {
        let size = unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENODATA) { return Ok(None); }
            return Err(e);
        }
        let mut value = vec![0u8; size as usize];
        let n = unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), value.as_mut_ptr().cast(), value.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ERANGE) { continue; }
            if e.raw_os_error() == Some(libc::ENODATA) { return Ok(None); }
            return Err(e);
        }
        value.truncate(n as usize); return Ok(Some(value));
    }
}

#[allow(dead_code)]
fn xattr_change(path: &Path, name: &std::ffi::OsStr, value: Option<&[u8]>) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    check_act_path(path)?;
    let p = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let n = std::ffi::CString::new(name.as_bytes()).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let before = xattr_read(&p, &n)?;
    if before.as_deref() == value { return Ok(()); }
    let rc = match value {
        Some(v) => unsafe { libc::lsetxattr(p.as_ptr(), n.as_ptr(), v.as_ptr().cast(), v.len(), 0) },
        None => unsafe { libc::lremovexattr(p.as_ptr(), n.as_ptr()) },
    };
    if rc != 0 { return Err(std::io::Error::last_os_error()); }
    crate::atoms::touch::record_lane(path, "known-good");
    if xattr_read(&p, &n)?.as_deref() != value { return Err(act_mismatch("xattr", path)); }
    Ok(())
}
#[allow(dead_code)]
pub(crate) fn act_xattr_set(_auth: &crate::atoms::comparison::ActionAuthorization, path: &Path, name: &std::ffi::OsStr, value: &[u8]) -> std::io::Result<()> { xattr_change(path, name, Some(value)) }
#[allow(dead_code)]
pub(crate) fn act_xattr_remove(_auth: &crate::atoms::comparison::ActionAuthorization, path: &Path, name: &std::ffi::OsStr) -> std::io::Result<()> { xattr_change(path, name, None) }

#[allow(dead_code)]
pub(crate) fn act_sync<'a>(w: impl Into<ScratchWitness<'a>>, path: &Path) -> std::io::Result<()> {
    w.into().hold(); check_act_path(path)?;
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path)?;
    let before = file.metadata()?;
    if !before.is_file() && !before.is_dir() { return Err(std::io::Error::other("projectio-sync-not-file-or-directory")); }
    file.sync_all()?;
    if !fs::symlink_metadata(path).is_ok_and(|m| file_identity(&m) == file_identity(&before)) { return Err(act_mismatch("sync", path)); }
    Ok(())
}

/// Replace engine-maintained state through the Projectio membrane.
pub(crate) fn write_engine_state(
    target: &Path,
    desired_bytes: &[u8],
    witness: EngineStateWitness,
) -> Result<Receipt, String> {
    check_act_path(target).map_err(|e| e.to_string())?;
    if let Some(parent) = target.parent() {
        engine_make_dir(&witness, parent).map_err(|e| io_error("state-directory", parent, e))?;
    }
    cleanup_stale_temporaries_for_target(target)?;

    let mut target_was_created = false;
    let metadata = match fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match OpenOptions::new().write(true).create_new(true).open(target) {
                Ok(file) => {
                    crate::atoms::touch::record_lane(target, "self");
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
        witness,
    }, Some(original_identity), None);
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
