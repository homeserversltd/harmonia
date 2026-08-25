//! One single-act tool that brings one file to its declared bytes and metadata.
#![allow(dead_code)]

use crate::atoms::files::{
    classify_request, observed_ownership, reject_ssh_path, resolve_gid, resolve_uid,
    same_file_bytes, source_mode, target_mode, unified_file_diff, validate_receipt_name,
    validate_specs, write_convergence_receipt, write_partial_failure_receipt,
    write_unified_diff_receipt, FileConvergenceEntry, FileConvergenceOutcome,
    FileConvergenceRequest, TargetClass, UnifiedFileDiff,
};
use crate::atoms::{self, Drift, Receipt};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy)]
pub(crate) struct DeclaredOwnership {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum BackupPolicy<'a> {
    None,
    To(&'a Path),
}

pub(crate) struct PlaceFileRequest<'a> {
    pub path: &'a Path,
    pub declared_bytes: &'a [u8],
    pub mode: Option<u32>,
    pub ownership: DeclaredOwnership,
    pub backup: BackupPolicy<'a>,
    pub invocation: Option<&'a atoms::r#do::InvocationKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlaceFileObservation {
    pub existed: bool,
    pub regular: bool,
    pub bytes_equal: bool,
    pub mode: Option<u32>,
    pub mode_equal: bool,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub owner_equal: bool,
    pub group_equal: bool,
}

impl PlaceFileObservation {
    fn current(&self) -> bool {
        self.regular && self.bytes_equal && self.mode_equal && self.owner_equal && self.group_equal
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct PlaceFileMovement {
    pub bytes: bool,
    pub mode: bool,
    pub owner: bool,
    pub created: bool,
    pub backed_up: Option<PathBuf>,
}

impl PlaceFileMovement {
    pub(crate) fn changed(&self) -> bool {
        self.bytes || self.mode || self.owner || self.created
    }
}

#[derive(Debug)]
pub(crate) struct PlaceFileOutcome {
    pub observation: PlaceFileObservation,
    pub movement: PlaceFileMovement,
    pub receipt: Receipt,
}

pub(crate) fn execute(request: PlaceFileRequest<'_>) -> Result<PlaceFileOutcome, String> {
    execute_with_authority(request, Authority::Machine)
}

pub(crate) fn execute_with_operator_hand(
    request: PlaceFileRequest<'_>,
    operator_hand: crate::interactables::OperatorHand,
) -> Result<PlaceFileOutcome, String> {
    execute_with_authority(request, Authority::OperatorHand(operator_hand))
}

enum Authority {
    Machine,
    OperatorHand(crate::interactables::OperatorHand),
}

fn execute_with_authority(
    request: PlaceFileRequest<'_>,
    authority: Authority,
) -> Result<PlaceFileOutcome, String> {
    match crate::atoms::files::classify_target(request.path) {
        crate::atoms::files::TargetClass::Refused(reason) => return Err(reason),
        crate::atoms::files::TargetClass::Config
            if request.invocation.is_some() && matches!(authority, Authority::Machine) =>
        {
            return Err("configuration-actuator-authority-refused".into())
        }
        _ => {}
    }
    if let Ok(metadata) = std::fs::symlink_metadata(request.path) {
        if !metadata.file_type().is_file() {
            return Err(format!(
                "place-file-target-collision-{} {}",
                collision_kind(&metadata),
                request.path.display()
            ));
        }
    }
    let run = crate::atoms::comparison::execute_mode(
        "place-file",
        || {
            probe::file(
                request.path,
                request.declared_bytes,
                request.mode,
                request.ownership,
            )
        },
        |observation| {
            if observation.current() {
                crate::atoms::comparison::DiffDecision::Empty
            } else {
                crate::atoms::comparison::DiffDecision::Different
            }
        },
        |authorization, observation| {
            let authorization = &authorization;
            let Some(invocation) = request.invocation else {
                return Ok(PlaceFileMovement::default());
            };
            mutation::place(
                authorization,
                invocation,
                request.path,
                request.declared_bytes,
                request.mode,
                request.ownership,
                request.backup,
                observation,
            )
        },
        request.invocation.is_some(),
    )?;
    let observation = run.observation().clone();
    let movement = match run {
        crate::atoms::comparison::ComparisonRun::Current { .. } => PlaceFileMovement::default(),
        crate::atoms::comparison::ComparisonRun::Moved { movement, .. } => movement,
    };
    let drift = if observation.current() {
        Drift::Current
    } else {
        Drift::File {
            expected_sha256: atoms::file_sha256(request.declared_bytes),
            actual_sha256: observation
                .regular
                .then(|| std::fs::read(request.path).ok())
                .flatten()
                .map(|bytes| atoms::file_sha256(&bytes)),
        }
    };
    let receipt = receipt::receipt(request.path, drift, &movement);
    Ok(PlaceFileOutcome {
        observation,
        movement,
        receipt,
    })
}

pub fn declaration() -> Result<Option<&'static crate::atoms::declaration::Declaration>, String> {
    crate::atoms::declaration::get("place-file")
}

/// Strict metadata request. Unlike the compatibility request above, all metadata
/// is explicit and xattrs are compared by name and value without following links.
pub(crate) struct StrictPlaceFileRequest<'a> {
    pub path: &'a Path,
    pub declared_bytes: &'a [u8],
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub xattrs: &'a BTreeMap<Vec<u8>, Vec<u8>>,
    pub backup: BackupPolicy<'a>,
    pub invocation: &'a atoms::r#do::InvocationKey,
    pub fail_after_action: bool,
}

#[derive(Clone)]
struct StrictPreimage {
    existed: bool,
    bytes: Vec<u8>,
    mode: u32,
    uid: u32,
    gid: u32,
    xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
}

#[cfg(unix)]
fn strict_xattrs(path: &Path) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, String> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let n = unsafe { libc::llistxattr(c.as_ptr(), std::ptr::null_mut(), 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut names = vec![0u8; n as usize];
    if n > 0
        && unsafe { libc::llistxattr(c.as_ptr(), names.as_mut_ptr() as *mut _, names.len()) } < 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut out = BTreeMap::new();
    for name in names.split(|b| *b == 0).filter(|n| !n.is_empty()) {
        let cn = std::ffi::CString::new(name).map_err(|e| e.to_string())?;
        let z = unsafe { libc::lgetxattr(c.as_ptr(), cn.as_ptr(), std::ptr::null_mut(), 0) };
        if z < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut value = vec![0u8; z as usize];
        if z > 0
            && unsafe {
                libc::lgetxattr(
                    c.as_ptr(),
                    cn.as_ptr(),
                    value.as_mut_ptr() as *mut _,
                    value.len(),
                )
            } < 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        out.insert(name.to_vec(), value);
    }
    Ok(out)
}
#[cfg(not(unix))]
fn strict_xattrs(_path: &Path) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, String> {
    Ok(BTreeMap::new())
}

#[cfg(unix)]
fn strict_set_xattrs(path: &Path, wanted: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let current = strict_xattrs(path)?;
    for name in current.keys().filter(|n| !wanted.contains_key(*n)) {
        let cn = std::ffi::CString::new(name.as_slice()).map_err(|e| e.to_string())?;
        if unsafe { libc::lremovexattr(c.as_ptr(), cn.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    for (name, value) in wanted {
        let cn = std::ffi::CString::new(name.as_slice()).map_err(|e| e.to_string())?;
        if unsafe {
            libc::lsetxattr(
                c.as_ptr(),
                cn.as_ptr(),
                value.as_ptr() as *const _,
                value.len(),
                0,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    Ok(())
}
#[cfg(not(unix))]
fn strict_set_xattrs(_path: &Path, _wanted: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<(), String> {
    Ok(())
}

fn strict_preimage(path: &Path) -> Result<StrictPreimage, String> {
    match fs::symlink_metadata(path) {
        Ok(m) if !m.file_type().is_file() => Err(format!(
            "place-file-target-collision-{} {}",
            collision_kind(&m),
            path.display()
        )),
        Ok(m) => Ok(StrictPreimage {
            existed: true,
            bytes: fs::read(path).map_err(|e| e.to_string())?,
            mode: m.permissions().mode() & 0o7777,
            #[cfg(unix)]
            uid: m.uid(),
            #[cfg(not(unix))]
            uid: 0,
            #[cfg(unix)]
            gid: m.gid(),
            #[cfg(not(unix))]
            gid: 0,
            xattrs: strict_xattrs(path)?,
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StrictPreimage {
            existed: false,
            bytes: Vec::new(),
            mode: 0,
            uid: 0,
            gid: 0,
            xattrs: BTreeMap::new(),
        }),
        Err(e) => Err(e.to_string()),
    }
}
fn collision_kind(m: &fs::Metadata) -> &'static str {
    if m.file_type().is_symlink() {
        "symlink"
    } else if m.is_dir() {
        "directory"
    } else {
        "non-regular"
    }
}
fn strict_restore(path: &Path, old: &StrictPreimage) -> Result<(), String> {
    if old.existed {
        fs::write(path, &old.bytes).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            fs::set_permissions(path, fs::Permissions::from_mode(old.mode))
                .map_err(|e| e.to_string())?;
            let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
                .map_err(|e| e.to_string())?;
            if unsafe { libc::chown(c.as_ptr(), old.uid, old.gid) } != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            };
        }
        strict_set_xattrs(path, &old.xattrs)
    } else {
        match fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_file() => fs::remove_file(path).map_err(|e| e.to_string()),
            Ok(_) => Err("place-file-rollback-collision".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}

pub(crate) fn execute_strict(
    request: StrictPlaceFileRequest<'_>,
) -> Result<PlaceFileOutcome, String> {
    let old = strict_preimage(request.path)?;
    let desired_equal = old.existed
        && old.bytes == request.declared_bytes
        && old.mode == request.mode
        && old.uid == request.uid
        && old.gid == request.gid
        && old.xattrs == *request.xattrs;
    if desired_equal {
        return execute(PlaceFileRequest {
            path: request.path,
            declared_bytes: request.declared_bytes,
            mode: Some(request.mode),
            ownership: DeclaredOwnership {
                uid: Some(request.uid),
                gid: Some(request.gid),
            },
            backup: request.backup,
            invocation: Some(request.invocation),
        });
    }
    let result: Result<PlaceFileOutcome, String> = (|| {
        let out = execute(PlaceFileRequest {
            path: request.path,
            declared_bytes: request.declared_bytes,
            mode: Some(request.mode),
            ownership: DeclaredOwnership {
                uid: Some(request.uid),
                gid: Some(request.gid),
            },
            backup: request.backup,
            invocation: Some(request.invocation),
        })?;
        strict_set_xattrs(request.path, request.xattrs)?;
        if request.fail_after_action {
            return Err("place-file-injected-post-action-failure".into());
        }
        let now = strict_preimage(request.path)?;
        if !now.existed
            || now.bytes != request.declared_bytes
            || now.mode != request.mode
            || now.uid != request.uid
            || now.gid != request.gid
            || now.xattrs != *request.xattrs
        {
            return Err("place-file-readback-mismatch".into());
        }
        Ok(out)
    })();
    match result {
        Ok(v) => Ok(v),
        Err(e) => {
            let rollback = strict_restore(request.path, &old);
            match rollback {
                Ok(()) => Err(format!("{e}; exact-rollback=ok")),
                Err(r) => Err(format!("{e}; exact-rollback=failed:{r}")),
            }
        }
    }
}

mod probe {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    pub(super) fn file(
        path: &Path,
        declared_bytes: &[u8],
        declared_mode: Option<u32>,
        ownership: DeclaredOwnership,
    ) -> Result<PlaceFileObservation, String> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(format!(
                    "place-file-metadata-failed {}: {error}",
                    path.display()
                ))
            }
        };
        let existed = metadata.is_some();
        let regular = metadata
            .as_ref()
            .is_some_and(|metadata| metadata.file_type().is_file());
        let bytes_equal = regular
            && std::fs::read(path)
                .map(|bytes| bytes == declared_bytes)
                .map_err(|error| format!("place-file-read-failed {}: {error}", path.display()))?;
        let mode = if regular {
            crate::atoms::files::target_mode(path)?
        } else {
            None
        };
        #[cfg(unix)]
        let (uid, gid) = metadata
            .as_ref()
            .map(|metadata| (Some(metadata.uid()), Some(metadata.gid())))
            .unwrap_or((None, None));
        #[cfg(not(unix))]
        let (uid, gid) = (None, None);
        Ok(PlaceFileObservation {
            existed,
            regular,
            bytes_equal,
            mode,
            mode_equal: regular && declared_mode.map_or(true, |wanted| mode == Some(wanted)),
            uid,
            gid,
            owner_equal: regular && ownership.uid.map_or(true, |wanted| uid == Some(wanted)),
            group_equal: regular && ownership.gid.map_or(true, |wanted| gid == Some(wanted)),
        })
    }
}

mod mutation {
    use super::*;
    use crate::atoms::comparison::ActionAuthorization;

    pub(super) fn place(
        authorization: &ActionAuthorization,
        invocation: &atoms::r#do::InvocationKey,
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
            BackupPolicy::To(path) if observation.existed && (bytes || mode || owner) => Some(path),
            BackupPolicy::None | BackupPolicy::To(_) => None,
        };
        let result = atoms::r#do::write_file::file_write(
            authorization,
            invocation,
            path,
            declared_bytes,
            atoms::r#do::write_file::FileWriteOptions {
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
}

mod receipt {
    use super::*;

    pub(super) fn receipt(path: &Path, drift: Drift, movement: &PlaceFileMovement) -> Receipt {
        Receipt {
            atom: "place-file".into(),
            ok: true,
            drift,
            message: format!(
                "path={}; bytes={}; mode={}; owner={}; created={}; backed_up={}",
                path.display(),
                movement.bytes,
                movement.mode,
                movement.owner,
                movement.created,
                movement
                    .backed_up
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default()
            ),
        }
    }
}

#[cfg(test)]
mod authority_tests {
    use super::*;

    #[test]
    fn machine_invocation_refuses_config_target_with_exact_signal() {
        let root = std::env::temp_dir().join(format!(
            "harmonia-place-file-authority-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("config_deploy:interactable/target.conf");
        let source = root.join("source.conf");
        std::fs::write(&source, b"desired").unwrap();
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, b"current").unwrap();
        let result = execute(PlaceFileRequest {
            path: &target,
            declared_bytes: b"desired",
            mode: None,
            ownership: DeclaredOwnership {
                uid: None,
                gid: None,
            },
            backup: BackupPolicy::None,
            invocation: Some(crate::atoms::r#do::InvocationKey::for_apply()),
        });
        assert_eq!(
            result.unwrap_err(),
            "configuration-actuator-authority-refused"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"current");
        std::fs::remove_dir_all(root).unwrap();
    }
}

// Managed-file convergence ownership lives with the place-file do seat.
pub fn converge_files(
    request: &FileConvergenceRequest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<FileConvergenceOutcome, String> {
    if apply {
        return Err("software-authorization-required".into());
    }
    converge_files_authorized(request, receipt_dir, None, None)
}

pub(crate) fn converge_files_with_invocation(
    request: &FileConvergenceRequest,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<FileConvergenceOutcome, String> {
    if apply {
        return Err("software-authorization-required".into());
    }
    converge_files_authorized(request, receipt_dir, None, invocation)
}

pub(crate) fn converge_files_authorized(
    request: &FileConvergenceRequest,
    receipt_dir: &Path,
    authorization: Option<&crate::SoftwareApplyAuthorization>,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<FileConvergenceOutcome, String> {
    converge_files_authorized_with_config_policy(
        request,
        receipt_dir,
        authorization,
        invocation,
        false,
    )
}

pub(crate) fn converge_files_authorized_with_config_policy(
    request: &FileConvergenceRequest,
    receipt_dir: &Path,
    authorization: Option<&crate::SoftwareApplyAuthorization>,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
    allow_config_proposal: bool,
) -> Result<FileConvergenceOutcome, String> {
    if request.files.is_empty() {
        return Err("files-converge-empty-request".to_string());
    }
    validate_receipt_name(&request.receipt_name)?;
    validate_specs(&request.files)?;
    let classes = classify_request(request)?;
    let held = !allow_config_proposal
        && classes
            .iter()
            .any(|class| matches!(class, TargetClass::Config));
    let apply = authorization.is_some()
        && !held
        && classes
            .iter()
            .all(|class| matches!(class, TargetClass::Software));
    // InvocationKey is an actuator bearer, never an observation/proposal bearer.
    let actuation_invocation = apply.then_some(invocation).flatten();
    for spec in &request.files {
        reject_ssh_path(&request.target_root.join(&spec.relative_path))?;
    }
    let desired_uid = request
        .owner
        .as_deref()
        .map(resolve_uid)
        .transpose()
        .map_err(|error| format!("files-converge-owner-resolution-failed: {error}"))?;
    let desired_gid = request
        .group
        .as_deref()
        .map(resolve_gid)
        .transpose()
        .map_err(|error| format!("files-converge-group-resolution-failed: {error}"))?;
    let ownership_source = if desired_uid.is_some() || desired_gid.is_some() {
        "declared"
    } else {
        "ambient"
    };

    let mut entries = Vec::new();
    let mut missing = Vec::new();
    let mut missing_target_birth_debts = Vec::new();
    let mut written = 0usize;
    let mut backed_up = 0usize;

    for spec in &request.files {
        let source = request.source_root.join(&spec.relative_path);
        let target = request.target_root.join(&spec.relative_path);
        let relative_path = spec.relative_path.to_string_lossy().to_string();
        let source_exists = source.is_file();
        let target_exists_before = fs::symlink_metadata(&target).is_ok();
        if !source_exists {
            missing.push(relative_path.clone());
            entries.push(FileConvergenceEntry {
                relative_path,
                source,
                target,
                source_exists,
                target_exists_before,
                content_equal_before: false,
                mode_equal_before: false,
                target_exists_after: target_exists_before,
                content_equal_after: false,
                mode_equal_after: false,
                changed: false,
                backed_up_to: None,
                final_mode: spec.mode,
                ownership_source: ownership_source.to_string(),
                observed_uid_before: None,
                observed_gid_before: None,
                observed_uid_after: None,
                observed_gid_after: None,
                ownership_changed: false,
                observed_uid: None,
                observed_gid: None,
                diff: None,
                diff_omitted: None,
            });
            continue;
        }

        if !target_exists_before {
            missing_target_birth_debts.push(relative_path.clone());
            let file_diff = unified_file_diff(&source, &target)?;
            if let Some(diff) = file_diff.text.as_deref() {
                write_unified_diff_receipt(
                    receipt_dir,
                    &request.receipt_name,
                    &relative_path,
                    diff,
                )?;
            }
            entries.push(FileConvergenceEntry {
                relative_path,
                source,
                target,
                source_exists,
                target_exists_before: false,
                content_equal_before: false,
                mode_equal_before: false,
                target_exists_after: false,
                content_equal_after: false,
                mode_equal_after: false,
                changed: false,
                backed_up_to: None,
                final_mode: spec
                    .mode
                    .or_else(|| source_mode(&request.source_root.join(&spec.relative_path)).ok()),
                ownership_source: ownership_source.to_string(),
                observed_uid_before: None,
                observed_gid_before: None,
                observed_uid_after: None,
                observed_gid_after: None,
                ownership_changed: false,
                observed_uid: None,
                observed_gid: None,
                diff: file_diff.text,
                diff_omitted: file_diff.omitted,
            });
            continue;
        }

        let content_equal_before = if target.is_file() {
            match same_file_bytes(&source, &target) {
                Ok(equal) => equal,
                Err(signal) => {
                    write_partial_failure_receipt(
                        receipt_dir,
                        request,
                        apply,
                        request.files.len(),
                        written,
                        backed_up,
                        &missing,
                        &entries,
                        &signal,
                    )?;
                    return Err(signal);
                }
            }
        } else {
            false
        };
        let final_mode = spec.mode.or_else(|| source_mode(&source).ok());
        let mode_equal_before = if target_exists_before {
            target_mode(&target)? == final_mode
        } else {
            false
        };
        let (observed_uid_before, observed_gid_before) = observed_ownership(&target)?;
        let ownership_changed = desired_uid
            .map(|uid| observed_uid_before != Some(uid))
            .unwrap_or(false)
            || desired_gid
                .map(|gid| observed_gid_before != Some(gid))
                .unwrap_or(false);
        let content_changed = !content_equal_before || !mode_equal_before;
        let entry_changed = content_changed || ownership_changed;
        let file_diff = if !content_equal_before {
            unified_file_diff(&source, &target)?
        } else {
            UnifiedFileDiff::default()
        };
        if let Some(diff) = file_diff.text.as_deref() {
            write_unified_diff_receipt(receipt_dir, &request.receipt_name, &relative_path, diff)?;
        }
        let desired_bytes = fs::read(&source)
            .map_err(|error| format!("files-source-read-failed {}: {error}", source.display()))?;
        let backup_path = receipt_dir.join("backups").join(&spec.relative_path);
        if !apply {
            // Observe/compare/propose is a terminal lane: no actuator call and no
            // InvocationKey may cross into a mutation-capable descendant.
            entries.push(FileConvergenceEntry {
                relative_path,
                source,
                target,
                source_exists,
                target_exists_before,
                content_equal_before,
                mode_equal_before,
                target_exists_after: target_exists_before,
                content_equal_after: content_equal_before,
                mode_equal_after: mode_equal_before,
                changed: entry_changed,
                backed_up_to: None,
                final_mode,
                ownership_source: ownership_source.to_string(),
                observed_uid_before,
                observed_gid_before,
                observed_uid_after: observed_uid_before,
                observed_gid_after: observed_gid_before,
                ownership_changed,
                observed_uid: observed_uid_before,
                observed_gid: observed_gid_before,
                diff: file_diff.text,
                diff_omitted: file_diff.omitted,
            });
            continue;
        }
        let place = crate::place_file::execute(crate::place_file::PlaceFileRequest {
            path: &target,
            declared_bytes: &desired_bytes,
            mode: final_mode,
            ownership: crate::place_file::DeclaredOwnership {
                uid: desired_uid,
                gid: desired_gid,
            },
            backup: if request.backup_existing && content_changed {
                crate::place_file::BackupPolicy::To(&backup_path)
            } else {
                crate::place_file::BackupPolicy::None
            },
            invocation: actuation_invocation,
        });
        let (backed_up_to, wrote_content, truthful_changed) = match place {
            Ok(outcome) => {
                let _typed_receipt = outcome.receipt;
                let changed = outcome.movement.changed();
                (
                    outcome.movement.backed_up,
                    outcome.movement.bytes || outcome.movement.mode,
                    changed,
                )
            }
            Err(signal) => {
                write_partial_failure_receipt(
                    receipt_dir,
                    request,
                    apply,
                    request.files.len(),
                    written,
                    backed_up,
                    &missing,
                    &entries,
                    &signal,
                )?;
                return Err(signal);
            }
        };
        if backed_up_to.is_some() {
            backed_up += 1;
        }
        if wrote_content {
            written += 1;
        }

        let target_exists_after = target.exists();
        let content_equal_after = if target_exists_after {
            same_file_bytes(&source, &target)?
        } else {
            false
        };
        let mode_equal_after = if target_exists_after {
            target_mode(&target)? == final_mode
        } else {
            false
        };
        let (observed_uid_after, observed_gid_after) = observed_ownership(&target)?;
        let ownership_equal_after = desired_uid
            .map(|uid| observed_uid_after == Some(uid))
            .unwrap_or(true)
            && desired_gid
                .map(|gid| observed_gid_after == Some(gid))
                .unwrap_or(true);
        if apply
            && (!target_exists_after
                || !content_equal_after
                || !mode_equal_after
                || !ownership_equal_after)
        {
            let signal = format!(
                "files-converge-post-write-readback-failed {}",
                target.display()
            );
            let mut failure_entries = entries.clone();
            failure_entries.push(FileConvergenceEntry {
                relative_path: relative_path.clone(),
                source: source.clone(),
                target: target.clone(),
                source_exists,
                target_exists_before,
                content_equal_before,
                mode_equal_before,
                target_exists_after,
                content_equal_after,
                mode_equal_after,
                changed: truthful_changed,
                backed_up_to: backed_up_to.clone(),
                final_mode,
                ownership_source: ownership_source.to_string(),
                observed_uid_before,
                observed_gid_before,
                observed_uid_after,
                observed_gid_after,
                ownership_changed,
                observed_uid: observed_uid_after,
                observed_gid: observed_gid_after,
                diff: file_diff.text.clone(),
                diff_omitted: file_diff.omitted.clone(),
            });
            write_partial_failure_receipt(
                receipt_dir,
                request,
                apply,
                request.files.len(),
                written,
                backed_up,
                &missing,
                &failure_entries,
                &signal,
            )?;
            return Err(signal);
        }

        entries.push(FileConvergenceEntry {
            relative_path,
            source,
            target,
            source_exists,
            target_exists_before,
            content_equal_before,
            mode_equal_before,
            target_exists_after,
            content_equal_after,
            mode_equal_after,
            changed: entry_changed,
            backed_up_to,
            final_mode,
            ownership_source: ownership_source.to_string(),
            observed_uid_before,
            observed_gid_before,
            observed_uid_after,
            observed_gid_after,
            ownership_changed,
            observed_uid: observed_uid_after,
            observed_gid: observed_gid_after,
            diff: file_diff.text,
            diff_omitted: file_diff.omitted,
        });
    }

    let ok = held || (missing.is_empty() && missing_target_birth_debts.is_empty());
    let changed = !held && entries.iter().any(|entry| entry.changed);
    let ownership_changed = !held && entries.iter().any(|entry| entry.ownership_changed);
    let outcome = FileConvergenceOutcome {
        ok,
        changed,
        ownership_changed,
        checked: request.files.len(),
        written,
        backed_up,
        missing,
        missing_target_birth_debts,
        entries,
        message: if ok {
            format!(
                "{} files {} from {} to {}",
                request.files.len(),
                if apply { "converged" } else { "planned" },
                request.source_root.display(),
                request.target_root.display()
            )
        } else {
            "files convergence incomplete".to_string()
        },
    };
    write_convergence_receipt(receipt_dir, request, &outcome, apply, held)?;
    Ok(outcome)
}

pub(crate) fn hard_stamp_interactable(
    id: &str,
    source: &Path,
    target: &Path,
    mode: Option<u32>,
    owner: Option<&str>,
    group: Option<&str>,
    backup_root: &Path,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
    operator_hand: crate::interactables::OperatorHand,
) -> Result<serde_json::Value, String> {
    crate::atoms::files::validate_interactable_target(target)?;
    if !source.is_file() {
        return Err(format!(
            "interactable-reference-source-missing {}",
            source.display()
        ));
    }
    let metadata = fs::symlink_metadata(target).map_err(|error| {
        format!(
            "interactable-target-birth-debt {}: {error}",
            target.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "interactable-target-not-regular-file {}",
            target.display()
        ));
    }
    let desired_uid = owner.map(crate::atoms::files::resolve_uid).transpose()?;
    let desired_gid = group.map(crate::atoms::files::resolve_gid).transpose()?;
    let desired_bytes = fs::read(source).map_err(|error| {
        format!(
            "interactable-reference-source-read-failed {}: {error}",
            source.display()
        )
    })?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().to_string())
        .unwrap_or_else(|_| "0".to_string());
    let backup = backup_root.join(id).join(format!(
        "{}-{}",
        stamp,
        target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("target")
    ));
    let place = crate::place_file::execute_with_operator_hand(
        crate::place_file::PlaceFileRequest {
            path: target,
            declared_bytes: &desired_bytes,
            mode: mode.or_else(|| crate::atoms::files::source_mode(source).ok()),
            ownership: crate::place_file::DeclaredOwnership {
                uid: desired_uid,
                gid: desired_gid,
            },
            backup: crate::place_file::BackupPolicy::To(&backup),
            invocation,
        },
        operator_hand,
    )?;
    let changed = place.movement.changed();
    let backed_up_to = place.movement.backed_up;
    let before_sha256 = backed_up_to
        .as_ref()
        .map(|path| {
            fs::read(path)
                .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
                .map_err(|error| error.to_string())
        })
        .transpose()?;
    let reference_sha256 = format!("{:x}", Sha256::digest(&desired_bytes));
    let target_sha256 = format!(
        "{:x}",
        Sha256::digest(fs::read(target).map_err(|error| error.to_string())?)
    );
    if target_sha256 != reference_sha256 {
        return Err(format!(
            "interactable-hard-stamp-readback-failed {}",
            target.display()
        ));
    }
    Ok(json!({
        "schema": "harmonia.interactables.hard_stamp.receipt.v1",
        "ok": true,
        "id": id,
        "kind": "hard-stamp",
        "backup_path": backed_up_to,
        "backed_up_to": backed_up_to,
        "before_sha256": before_sha256,
        "reference_sha256": reference_sha256,
        "target_sha256": target_sha256,
        "target": target,
        "reference_source": source,
        "changed": changed,
    }))
}
