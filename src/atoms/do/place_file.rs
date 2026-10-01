//! One single-act tool that brings one file to its declared bytes and metadata.
use crate::atoms::files::{
    classify_request, observed_ownership, reject_ssh_path, resolve_gid, resolve_uid,
    same_file_bytes, source_mode, target_mode, unified_file_diff, validate_receipt_name,
    validate_specs, convergence_receipt_projection, write_convergence_projection,
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
    pub before_observation: PlaceFileObservation,
    pub diff_decision: crate::atoms::comparison::DiffDecision,
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

pub(crate) fn execute_estate_owned_declared_sudoers_fragment(
    request: PlaceFileRequest<'_>,
) -> Result<PlaceFileOutcome, String> {
    execute_estate_owned_declared_sudoers_fragment_at(request, Path::new("/etc/sudoers.d"))
}

pub(crate) fn execute_estate_owned_validated_pam_sudo(
    request: PlaceFileRequest<'_>,
    receipt_dir: &Path,
) -> Result<PlaceFileOutcome, String> {
    let target = Path::new("/etc/pam.d/sudo");
    let backup = receipt_dir.join("backups/pam-sudo/sudo");
    let backup_is_receipt_local = matches!(
        request.backup,
        BackupPolicy::To(path) if path == backup.as_path()
    );
    if request.path != target
        || request.mode != Some(0o644)
        || request.ownership.uid != Some(0)
        || request.ownership.gid != Some(0)
        || !backup_is_receipt_local
    {
        return Err("validated-pam-sudo-forced-clobber-contract-refused".into());
    }
    execute_with_authority(request, Authority::EstateOwnedValidatedPamSudo)
}

fn execute_estate_owned_declared_sudoers_fragment_at(
    request: PlaceFileRequest<'_>,
    target_root: &Path,
) -> Result<PlaceFileOutcome, String> {
    if request.path.parent() != Some(target_root)
        || request.mode != Some(0o440)
        || request.ownership.uid != Some(0)
        || request.ownership.gid != Some(0)
        || !matches!(request.backup, BackupPolicy::None)
    {
        return Err("declared-sudoers-forced-clobber-contract-refused".into());
    }
    execute_with_authority(request, Authority::EstateOwnedDeclaredSudoers)
}

pub(crate) fn execute_xenia_rendered_guest_unit(
    request: PlaceFileRequest<'_>,
    xenia_id: &str,
) -> Result<PlaceFileOutcome, String> {
    let target_root = Path::new("/etc/systemd/system");
    let unit_stem = PathBuf::from(xenia_id);
    let expected_name = format!("{xenia_id}.service");
    let expected_path = target_root.join(&expected_name);
    if xenia_id.is_empty()
        || xenia_id.contains('/')
        || unit_stem.to_str() != Some(xenia_id)
        || unit_stem.file_name().and_then(|name| name.to_str()) != Some(xenia_id)
        || request.path.parent() != Some(target_root)
        || request.path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str())
        || request.path != expected_path.as_path()
        || request.mode != Some(0o644)
        || request.ownership.uid != Some(0)
        || request.ownership.gid != Some(0)
    {
        return Err("xenia-rendered-guest-unit-contract-refused".into());
    }
    if let Ok(metadata) = fs::symlink_metadata(request.path) {
        if metadata.file_type().is_file() {
            let marker = format!("X-Xenia-Id={xenia_id}");
            let bytes = fs::read(request.path)
                .map_err(|_| "xenia-rendered-guest-unit-collision-refused".to_string())?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| "xenia-rendered-guest-unit-collision-refused".to_string())?;
            if !text.lines().any(|line| line == marker) {
                return Err("xenia-rendered-guest-unit-collision-refused".into());
            }
        }
    }
    execute_with_authority(request, Authority::XeniaRenderedGuestUnit)
}

enum Authority {
    Machine,
    OperatorHand(crate::interactables::OperatorHand),
    EstateOwnedDeclaredSudoers,
    EstateOwnedValidatedPamSudo,
    XeniaRenderedGuestUnit,
}

fn execute_with_authority(
    request: PlaceFileRequest<'_>,
    authority: Authority,
) -> Result<PlaceFileOutcome, String> {
    let force_atomic_replace_on_change =
        matches!(&authority, Authority::EstateOwnedValidatedPamSudo);
    match crate::atoms::files::classify_target(request.path) {
        crate::atoms::files::TargetClass::Refused(reason) => return Err(reason),
        crate::atoms::files::TargetClass::Config
            if request.invocation.is_some() && matches!(&authority, Authority::Machine) =>
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
    let mut before_observation = None;
    let run = crate::atoms::comparison::execute_mode(
        "place-file",
        || {
            let observation = probe::file(
                request.path,
                request.declared_bytes,
                request.mode,
                request.ownership,
            )?;
            if before_observation.is_none() {
                before_observation = Some(observation.clone());
            }
            Ok(observation)
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
                force_atomic_replace_on_change,
            )
        },
        request.invocation.is_some(),
    )?;
    let before_observation =
        before_observation.ok_or_else(|| "place-file-initial-observation-missing".to_string())?;
    let diff_decision = run.decision();
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
    let receipt = receipt::receipt(
        request.path,
        drift,
        &before_observation,
        &observation,
        diff_decision,
        request.declared_bytes,
        request.mode,
        request.ownership,
        &movement,
    );
    Ok(PlaceFileOutcome {
        before_observation,
        diff_decision,
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
        force_atomic_replace_on_change: bool,
    ) -> Result<PlaceFileMovement, String> {
        let created = !observation.existed;
        let bytes = !observation.bytes_equal;
        let mode = !observation.mode_equal;
        let owner = !observation.owner_equal || !observation.group_equal;
        let backup_to = match backup {
            BackupPolicy::To(path) if observation.existed && (bytes || mode || owner) => Some(path),
            BackupPolicy::None | BackupPolicy::To(_) => None,
        };
        let write_bytes = bytes || (force_atomic_replace_on_change && (mode || owner));
        let result = atoms::r#do::write_file::file_write(
            authorization,
            invocation,
            path,
            declared_bytes,
            atoms::r#do::write_file::FileWriteOptions {
                write_bytes,
                mode: if write_bytes {
                    declared_mode.or(observation.mode)
                } else {
                    mode.then_some(declared_mode).flatten()
                },
                uid: if write_bytes {
                    ownership.uid
                } else {
                    (!observation.owner_equal)
                        .then_some(ownership.uid)
                        .flatten()
                },
                gid: if write_bytes {
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

    fn observation_fields(prefix: &str, observation: &PlaceFileObservation) -> String {
        format!(
            "{prefix}_exists={} {prefix}_regular={} {prefix}_bytes_equal={} {prefix}_mode={:?} {prefix}_mode_equal={} {prefix}_uid={:?} {prefix}_gid={:?} {prefix}_owner_equal={} {prefix}_group_equal={}",
            observation.existed,
            observation.regular,
            observation.bytes_equal,
            observation.mode,
            observation.mode_equal,
            observation.uid,
            observation.gid,
            observation.owner_equal,
            observation.group_equal,
        )
    }

    pub(super) fn receipt(
        path: &Path,
        drift: Drift,
        before: &PlaceFileObservation,
        after: &PlaceFileObservation,
        diff_decision: crate::atoms::comparison::DiffDecision,
        declared_bytes: &[u8],
        declared_mode: Option<u32>,
        ownership: DeclaredOwnership,
        movement: &PlaceFileMovement,
    ) -> Receipt {
        Receipt {
            atom: "place-file".into(),
            ok: true,
            drift,
            message: format!(
                "path={}; diff_decision={:?}; {}; {}; desired_bytes_sha256={}; desired_bytes_len={}; desired_mode={:?}; desired_uid={:?}; desired_gid={:?}; movement_bytes={}; movement_mode={}; movement_owner={}; movement_created={}; backed_up={}",
                path.display(),
                diff_decision,
                observation_fields("before", before),
                observation_fields("after", after),
                atoms::file_sha256(declared_bytes),
                declared_bytes.len(),
                declared_mode,
                ownership.uid,
                ownership.gid,
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
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let result = execute(PlaceFileRequest {
            path: &target,
            declared_bytes: b"desired",
            mode: None,
            ownership: DeclaredOwnership {
                uid: None,
                gid: None,
            },
            backup: BackupPolicy::None,
            invocation: Some(&invocation),
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
pub(crate) fn write_compatibility_projection(
    path: &Path,
    projection: &serde_json::Value,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        crate::atoms::attest::prepare_receipt_parent(parent)?;
    }
    crate::atoms::attest::write_json_atomic(path, projection)
}

fn observation_projection(observation: &PlaceFileObservation) -> serde_json::Value {
    json!({
        "exists":observation.existed,
        "regular":observation.regular,
        "bytes_equal":observation.bytes_equal,
        "mode":observation.mode,
        "mode_equal":observation.mode_equal,
        "uid":observation.uid,
        "gid":observation.gid,
        "owner_equal":observation.owner_equal,
        "group_equal":observation.group_equal,
    })
}

fn movement_projection(movement: &PlaceFileMovement) -> serde_json::Value {
    json!({
        "bytes":movement.bytes,
        "mode":movement.mode,
        "owner":movement.owner,
        "created":movement.created,
        "backed_up":movement.backed_up,
    })
}

pub(crate) fn write_compatibility_projection_after_attest(
    receipt_dir: &Path,
    path: &Path,
    receipt: &Receipt,
    projection: &serde_json::Value,
) -> Result<(), String> {
    crate::atoms::attest::attest(&receipt_dir.join("atoms.jsonl"), receipt, &[])?;
    write_compatibility_projection(path, projection)
}

/// Convert typed placement evidence into the stable compatibility fields only
/// after its central atom receipt has been written.
pub(crate) fn write_place_file_compatibility_projection(
    receipt_dir: &Path,
    path: &Path,
    outcome: &PlaceFileOutcome,
    projection: &serde_json::Value,
) -> Result<(), String> {
    let mut projection = projection.clone();
    let object = projection
        .as_object_mut()
        .ok_or_else(|| "place-file-compatibility-projection-not-object".to_string())?;
    object.insert(
        "observed_state".into(),
        observation_projection(&outcome.before_observation),
    );
    object.insert(
        "final_state".into(),
        observation_projection(&outcome.observation),
    );
    let diff_decision = match outcome.diff_decision {
        crate::atoms::comparison::DiffDecision::Empty => "Empty",
        crate::atoms::comparison::DiffDecision::Different => "Different",
    };
    object.insert("diff_decision".into(), json!(diff_decision));
    let movement_key = if object.contains_key("movement") {
        "movement_details"
    } else {
        "movement"
    };
    object.insert(movement_key.into(), movement_projection(&outcome.movement));
    object.insert("receipt".into(), json!(outcome.receipt));
    write_compatibility_projection_after_attest(
        receipt_dir,
        path,
        &outcome.receipt,
        &projection,
    )
}

pub(crate) fn write_compile_fragments_no_claim_projection(
    receipt_dir: &Path,
    target: &Path,
    selected_appliance: &str,
) -> Result<(), String> {
    let receipt = Receipt {
        atom: "place-file".into(),
        ok: true,
        drift: Drift::Current,
        message: "compile-fragments-no-claim".into(),
    };
    let projection = json!({
        "schema":"harmonia.compile-fragments.receipt.v1",
        "ok":true,
        "changed":false,
        "skipped":true,
        "artifact":"no-claim",
        "target":target,
        "selected_appliance":selected_appliance,
        "bytes":0,
    });
    write_compatibility_projection_after_attest(
        receipt_dir,
        &receipt_dir.join("compile-fragments.json"),
        &receipt,
        &projection,
    )
}

pub(crate) fn write_compile_fragments_config_projection(
    receipt_dir: &Path,
    target: &Path,
    selected_appliance: &str,
    bytes: usize,
    outcome: &FileConvergenceOutcome,
    config_state: &str,
    skipped: bool,
) -> Result<(), String> {
    let message = format!("compile-fragments-config-{config_state}");
    let receipt = Receipt {
        atom: "place-file".into(),
        ok: outcome.ok,
        drift: Drift::Current,
        message,
    };
    let projection = json!({
        "schema":"harmonia.compile-fragments.receipt.v1",
        "ok":outcome.ok,
        "changed":outcome.changed,
        "ownership_changed":outcome.ownership_changed,
        "skipped":skipped,
        "config_state":config_state,
        "recognition_ok":outcome.ok,
        "target":target,
        "selected_appliance":selected_appliance,
        "bytes":bytes,
    });
    write_compatibility_projection_after_attest(
        receipt_dir,
        &receipt_dir.join("compile-fragments.json"),
        &receipt,
        &projection,
    )
}

pub(crate) fn write_compile_fragments_place_file_projection(
    receipt_dir: &Path,
    target: &Path,
    selected_appliance: &str,
    bytes: usize,
    outcome: &PlaceFileOutcome,
    skipped: bool,
) -> Result<(), String> {
    let projection = json!({
        "schema":"harmonia.compile-fragments.receipt.v1",
        "ok":outcome.receipt.ok,
        "changed":outcome.movement.changed(),
        "skipped":skipped,
        "target":target,
        "selected_appliance":selected_appliance,
        "bytes":bytes,
    });
    write_place_file_compatibility_projection(
        receipt_dir,
        &receipt_dir.join("compile-fragments.json"),
        outcome,
        &projection,
    )
}

pub(crate) struct FilesSummaryProjection {
    pub name: String,
    pub schema: String,
    pub ok: bool,
    pub apply: bool,
    pub config_state: String,
    pub config_surfaces: serde_json::Value,
    pub module: String,
    pub source_dir: PathBuf,
    pub target_dir: PathBuf,
    pub checked_file_count: usize,
    pub written_file_count: usize,
    pub backed_up_file_count: usize,
    pub changed: bool,
    pub ownership_changed: bool,
    pub missing: Vec<String>,
    pub authority: String,
    pub waybar_contract: serde_json::Value,
    pub first_missing_signal: String,
    pub score: Option<serde_json::Value>,
    pub reference_id: Option<serde_json::Value>,
}

/// Write the managed-files summary as an atom-owned compatibility projection.
/// The aggregate typed receipt is centrally attested before the JSON view lands.
pub(crate) fn write_files_summary_compatibility_projection(
    receipt_dir: &Path,
    summary: FilesSummaryProjection,
) -> Result<(), String> {
    let receipt = Receipt {
        atom: "place-file".into(),
        ok: summary.ok,
        drift: Drift::Current,
        message: format!(
            "files-summary checked={} written={} backed_up={} changed={} ownership_changed={} config_state={}",
            summary.checked_file_count,
            summary.written_file_count,
            summary.backed_up_file_count,
            summary.changed,
            summary.ownership_changed,
            summary.config_state,
        ),
    };
    let mut projection = json!({
        "schema":summary.schema,
        "ok":summary.ok,
        "apply":summary.apply,
        "config_state":summary.config_state,
        "config_surfaces":summary.config_surfaces,
        "module":summary.module,
        "source_dir":summary.source_dir,
        "target_dir":summary.target_dir,
        "checked_file_count":summary.checked_file_count,
        "written_file_count":summary.written_file_count,
        "backed_up_file_count":summary.backed_up_file_count,
        "changed":summary.changed,
        "ownership_changed":summary.ownership_changed,
        "missing":summary.missing,
        "authority":summary.authority,
        "waybar_contract":summary.waybar_contract,
        "first_missing_signal":summary.first_missing_signal,
    });
    let object = projection
        .as_object_mut()
        .ok_or_else(|| "files-summary-compatibility-projection-not-object".to_string())?;
    if let Some(score) = summary.score {
        object.insert("score".into(), score);
    }
    if let Some(reference_id) = summary.reference_id {
        object.insert("reference_id".into(), reference_id);
    }
    write_compatibility_projection_after_attest(
        receipt_dir,
        &receipt_dir.join(format!("{}.json", summary.name)),
        &receipt,
        &projection,
    )
}

/// Run the declared hotfix file step through the typed place-file atom and
/// return the established files-tool receipt as an attested projection.
pub(crate) fn hotfix_file_backfill(
    path: &Path,
    declared_bytes: &[u8],
    mode: Option<u32>,
    ownership: DeclaredOwnership,
    owner: Option<&str>,
    apply: bool,
    invocation: Option<&atoms::r#do::InvocationKey>,
    receipt_dir: &Path,
    step_id: &str,
) -> Result<crate::OperationOutcome, String> {
    let compatibility_path = receipt_dir.join(format!("{step_id}.json"));
    let expected_sha256 = atoms::file_sha256(declared_bytes);
    let mut execute_started = false;
    let result = (|| {
        crate::atoms::ask::backfill_file::validate_target(path)?;
        match crate::atoms::files::classify_target(path) {
            crate::atoms::files::TargetClass::Refused(reason) => return Err(reason),
            crate::atoms::files::TargetClass::Config => {
                return Err(format!(
                    "configuration-actuator-authority-refused {}",
                    path.display()
                ));
            }
            crate::atoms::files::TargetClass::Software => {}
        }
        if apply && invocation.is_none() {
            return Err("hotfix-file-backfill-invocation-key-missing".into());
        }
        let actuator_invocation = apply.then_some(invocation).flatten();
        execute_started = true;
        execute(PlaceFileRequest {
            path,
            declared_bytes,
            mode,
            ownership,
            backup: BackupPolicy::None,
            invocation: actuator_invocation,
        })
    })();
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(error) => {
            let actual_sha256 = fs::symlink_metadata(path)
                .ok()
                .filter(|metadata| metadata.file_type().is_file())
                .and_then(|_| fs::read(path).ok())
                .map(|bytes| atoms::file_sha256(&bytes));
            let refused = !execute_started;
            let movement = if !apply {
                "none"
            } else if refused {
                "refused"
            } else {
                "attempted"
            };
            let receipt = Receipt {
                atom: "place-file".into(),
                ok: false,
                drift: Drift::File {
                    expected_sha256: expected_sha256.clone(),
                    actual_sha256,
                },
                message: format!("path={} blocker={error}", path.display()),
            };
            let projection = json!({
                "schema":"harmonia.tool_receipt.v1",
                "operation_id":step_id,
                "tool":"files",
                "action":"hotfix-file-backfill",
                "ok":false,
                "changed":null,
                "skipped":!apply || refused,
                "message":error.clone(),
                "command":null,
                "first_missing_signal":error.clone(),
                "observed_state":null,
                "desired_state":{
                    "path":path,
                    "bytes_sha256":expected_sha256,
                    "bytes":declared_bytes.len(),
                    "mode":mode,
                    "owner":owner,
                    "uid":ownership.uid,
                    "gid":ownership.gid,
                },
                "diff_decision":"blocked",
                "movement":movement,
                "final_state":null,
                "truthful_changed":null,
                "proof":"place-file-action-failed",
                "blocker":error.clone(),
                "receipt":receipt,
            });
            write_compatibility_projection_after_attest(
                receipt_dir,
                &compatibility_path,
                &receipt,
                &projection,
            )?;
            return Err(error);
        }
    };
    let changed = outcome.movement.changed();
    let different = if apply {
        changed
    } else {
        !outcome.observation.current()
    };
    let diff_decision = if different { "Different" } else { "Empty" };
    let movement = if !apply || !different {
        if different { "report-only" } else { "none" }
    } else {
        "attempted"
    };
    let proof = if !outcome.receipt.ok {
        "place-file-action-failed"
    } else if different && !apply {
        "report-only"
    } else if different {
        "place-file-readback"
    } else {
        "current"
    };
    let projection = json!({
        "schema":"harmonia.tool_receipt.v1",
        "operation_id":step_id,
        "tool":"files",
        "action":"hotfix-file-backfill",
        "ok":outcome.receipt.ok,
        "changed":changed,
        "skipped":!apply || !different,
        "message":outcome.receipt.message,
        "command":null,
        "first_missing_signal":"none",
        "movement":movement,
        "desired_state":{
            "path":path,
            "bytes_sha256":expected_sha256,
            "bytes":declared_bytes.len(),
            "mode":mode,
            "owner":owner,
            "uid":ownership.uid,
            "gid":ownership.gid,
        },
        "diff_decision":diff_decision,
        "final_state":observation_projection(&outcome.observation),
        "truthful_changed":changed,
        "proof":proof,
        "blocker":"none",
    });
    write_place_file_compatibility_projection(
        receipt_dir,
        &compatibility_path,
        &outcome,
        &projection,
    )?;
    Ok(crate::OperationOutcome {
        ok: outcome.receipt.ok,
        changed,
        skipped: !apply || !different,
        message: outcome.receipt.message,
        command: None,
    })
}

pub(crate) fn same_root_directory_sync(
    source_root: &Path,
    target_root: &Path,
    receipt_dir: &Path,
    step_id: &str,
    apply: bool,
    allowed: bool,
) -> Result<Option<crate::OperationOutcome>, String> {
    if !allowed || source_root != target_root {
        return Ok(None);
    }
    let observed = crate::atoms::comparison::execute(
        "directory-sync",
        || {
            let source = source_root.canonicalize().map_err(|error| {
                format!("directory-sync-source-root-observation-failed: {error}")
            })?;
            let target = target_root.canonicalize().map_err(|error| {
                format!("directory-sync-target-root-observation-failed: {error}")
            })?;
            if !source.is_dir() || !target.is_dir() {
                return Err("directory-sync-same-root-not-directory".to_string());
            }
            Ok::<_, String>((source, target))
        },
        |(source, target)| {
            if source == target {
                crate::atoms::comparison::DiffDecision::Empty
            } else {
                crate::atoms::comparison::DiffDecision::Different
            }
        },
        |_, _| Err::<(), String>("directory-sync-same-root-drift".into()),
    );
    let (observed_state, diff_decision, ok, blocker): (serde_json::Value, &str, bool, String) = match observed {
        Ok(crate::atoms::comparison::ComparisonRun::Current { observation, decision }) => (
            json!({"source_root":observation.0,"target_root":observation.1,"same_root":true}),
            if decision == crate::atoms::comparison::DiffDecision::Empty { "empty" } else { "different" },
            decision == crate::atoms::comparison::DiffDecision::Empty,
            if decision == crate::atoms::comparison::DiffDecision::Empty { "none" } else { "directory-sync-same-root-drift" }.to_string(),
        ),
        Ok(crate::atoms::comparison::ComparisonRun::Moved { .. }) => (
            json!({"source_root":source_root,"target_root":target_root,"same_root":false}),
            "different", false, "directory-sync-same-root-unexpected-movement".to_string(),
        ),
        Err(error) => (
            json!({"source_root":source_root,"target_root":target_root,"same_root":false}),
            "blocked", false, error,
        ),
    };
    let outcome = crate::OperationOutcome {
        ok,
        changed: false,
        skipped: !apply,
        message: if ok {
            format!("directory-sync same-root verified {}", source_root.display())
        } else {
            blocker.to_string()
        },
        command: None,
    };
    let receipt = Receipt {
        atom: "place-file".into(),
        ok,
        drift: Drift::Current,
        message: format!("directory-sync diff={diff_decision} movement=none changed=false blocker={blocker}"),
    };
    crate::atoms::attest::attest(&receipt_dir.join("atoms.jsonl"), &receipt, &[])?;
    write_compatibility_projection(
        &receipt_dir.join(format!("{step_id}.json")),
        &json!({
            "schema":"harmonia.tool_receipt.v1", "operation_id":step_id,
            "tool":"files", "action":"directory-sync", "ok":ok,
            "changed":false, "skipped":!apply, "message":outcome.message,
            "command":null, "first_missing_signal":blocker,
            "observed_state":observed_state,
            "desired_state":{"directory_sync":"verified"},
            "diff_decision":diff_decision, "movement":"none", "truthful_changed":false,
        }),
    )?;
    Ok(Some(outcome))
}

fn partial_convergence_outcome(
    checked: usize,
    written: usize,
    backed_up: usize,
    missing: &[String],
    entries: &[FileConvergenceEntry],
    signal: &str,
) -> FileConvergenceOutcome {
    FileConvergenceOutcome {
        ok: false,
        changed: entries.iter().any(|entry| entry.changed) || written > 0 || backed_up > 0,
        ownership_changed: entries.iter().any(|entry| entry.ownership_changed),
        config_state: None,
        checked,
        written,
        backed_up,
        missing: missing.to_vec(),
        entries: entries.to_vec(),
        message: signal.to_string(),
    }
}

fn attest_place_file_failure(receipt_dir: &Path, signal: &str) -> Result<Receipt, String> {
    let receipt = Receipt {
        atom: "place-file".into(),
        ok: false,
        drift: Drift::Current,
        message: signal.to_string(),
    };
    crate::atoms::attest::attest(&receipt_dir.join("atoms.jsonl"), &receipt, &[])?;
    Ok(receipt)
}

fn write_convergence_projection_after_attest(
    receipt_dir: &Path,
    request: &FileConvergenceRequest,
    outcome: &FileConvergenceOutcome,
    apply: bool,
    config_state: Option<crate::atoms::files::ConfigConvergenceState>,
    typed_receipts: &[Receipt],
) -> Result<(), String> {
    let projection = convergence_receipt_projection(
        request,
        outcome,
        apply,
        config_state,
        typed_receipts,
    );
    write_convergence_projection(receipt_dir, request, &projection)
}

pub(crate) fn converge_files_authorized(
    request: &FileConvergenceRequest,
    receipt_dir: &Path,
    authorization: Option<&crate::SoftwareApplyAuthorization>,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<FileConvergenceOutcome, String> {
    converge_files_authorized_with_interactable_policy(
        request,
        receipt_dir,
        authorization,
        invocation,
        crate::atoms::files::InteractablePolicy::Default,
    )
}

pub(crate) fn converge_declared_sudoers_fragments_authorized(
    request: &FileConvergenceRequest,
    receipt_dir: &Path,
    authorization: Option<&crate::SoftwareApplyAuthorization>,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<FileConvergenceOutcome, String> {
    converge_declared_sudoers_fragments_authorized_at(
        request,
        receipt_dir,
        authorization,
        invocation,
        Path::new("/etc/sudoers.d"),
    )
}

pub(crate) fn converge_declared_sudoers_fragments_authorized_at(
    request: &FileConvergenceRequest,
    receipt_dir: &Path,
    authorization: Option<&crate::SoftwareApplyAuthorization>,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
    target_root: &Path,
) -> Result<FileConvergenceOutcome, String> {
    if authorization.is_some() && invocation.is_none() {
        return Err("declared-sudoers-forced-clobber-invocation-required".into());
    }
    let exact_fragment_set = request.target_root == target_root
        && !request.backup_existing
        && request.owner.as_deref() == Some("root")
        && request.group.as_deref() == Some("root")
        && request.files.iter().all(|file| {
            file.mode == Some(0o440)
                && file.relative_path.components().count() == 1
                && file.relative_path.file_name().is_some()
        });
    if !exact_fragment_set {
        return Err("declared-sudoers-forced-clobber-contract-refused".into());
    }
    converge_files_authorized_with_policy(
        request,
        receipt_dir,
        authorization,
        invocation,
        ConvergencePolicy::EstateOwnedDeclaredSudoers(target_root.to_path_buf()),
    )
}

enum ConvergencePolicy {
    Interactable(crate::atoms::files::InteractablePolicy),
    EstateOwnedDeclaredSudoers(PathBuf),
}

pub(crate) fn converge_files_authorized_with_interactable_policy(
    request: &FileConvergenceRequest,
    receipt_dir: &Path,
    authorization: Option<&crate::SoftwareApplyAuthorization>,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
    interactable_policy: crate::atoms::files::InteractablePolicy,
) -> Result<FileConvergenceOutcome, String> {
    converge_files_authorized_with_policy(
        request,
        receipt_dir,
        authorization,
        invocation,
        ConvergencePolicy::Interactable(interactable_policy),
    )
}

fn converge_files_authorized_with_policy(
    request: &FileConvergenceRequest,
    receipt_dir: &Path,
    authorization: Option<&crate::SoftwareApplyAuthorization>,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
    policy: ConvergencePolicy,
) -> Result<FileConvergenceOutcome, String> {
    if request.files.is_empty() {
        return Err("files-converge-empty-request".to_string());
    }
    validate_receipt_name(&request.receipt_name)?;
    validate_specs(&request.files)?;
    let classes = classify_request(request)?;
    let has_config = classes
        .iter()
        .any(|class| matches!(class, TargetClass::Config));
    let config_state = match &policy {
        ConvergencePolicy::Interactable(interactable_policy) if has_config => {
            Some(match interactable_policy {
                crate::atoms::files::InteractablePolicy::Default => {
                    crate::atoms::files::ConfigConvergenceState::ProposalEligible
                }
                crate::atoms::files::InteractablePolicy::SuppressInteractable => {
                    crate::atoms::files::ConfigConvergenceState::InteractableExempt
                }
            })
        }
        _ => None,
    };
    let apply = authorization.is_some()
        && match &policy {
            // This variant is constructed only after the dedicated sudoers
            // contract gate has matched the exact target and metadata shape.
            ConvergencePolicy::EstateOwnedDeclaredSudoers(_) => true,
            ConvergencePolicy::Interactable(_) => classes
                .iter()
                .all(|class| matches!(class, TargetClass::Software)),
        };
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
    let mut typed_receipts = Vec::new();
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

        if !target_exists_before
            && !matches!(&policy, ConvergencePolicy::EstateOwnedDeclaredSudoers(_))
        {
            missing.push(target.display().to_string());
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
                    let receipt = attest_place_file_failure(receipt_dir, &signal)?;
                    typed_receipts.push(receipt);
                    let outcome = partial_convergence_outcome(
                        request.files.len(),
                        written,
                        backed_up,
                        &missing,
                        &entries,
                        &signal,
                    );
                    write_convergence_projection_after_attest(
                        receipt_dir,
                        request,
                        &outcome,
                        apply,
                        config_state,
                        &typed_receipts,
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
        let place_request = crate::place_file::PlaceFileRequest {
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
        };
        let place = match &policy {
            ConvergencePolicy::EstateOwnedDeclaredSudoers(target_root) => {
                execute_estate_owned_declared_sudoers_fragment_at(place_request, target_root)
            }
            _ => crate::place_file::execute(place_request),
        };
        let (backed_up_to, wrote_content, truthful_changed) = match place {
            Ok(outcome) => {
                let receipt = outcome.receipt;
                crate::atoms::attest::attest(
                    &receipt_dir.join("atoms.jsonl"),
                    &receipt,
                    &[],
                )?;
                typed_receipts.push(receipt);
                let changed = outcome.movement.changed();
                (
                    outcome.movement.backed_up,
                    outcome.movement.bytes || outcome.movement.mode,
                    changed,
                )
            }
            Err(signal) => {
                let receipt = attest_place_file_failure(receipt_dir, &signal)?;
                typed_receipts.push(receipt);
                let outcome = partial_convergence_outcome(
                    request.files.len(),
                    written,
                    backed_up,
                    &missing,
                    &entries,
                    &signal,
                );
                write_convergence_projection_after_attest(
                    receipt_dir,
                    request,
                    &outcome,
                    apply,
                    config_state,
                    &typed_receipts,
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
            let outcome = partial_convergence_outcome(
                request.files.len(),
                written,
                backed_up,
                &missing,
                &failure_entries,
                &signal,
            );
            write_convergence_projection_after_attest(
                receipt_dir,
                request,
                &outcome,
                apply,
                config_state,
                &typed_receipts,
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

    let ok = missing.is_empty();
    let changed = entries.iter().any(|entry| entry.changed);
    let ownership_changed = entries.iter().any(|entry| entry.ownership_changed);
    let outcome = FileConvergenceOutcome {
        ok,
        changed,
        ownership_changed,
        config_state,
        checked: request.files.len(),
        written,
        backed_up,
        missing,
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
    write_convergence_projection_after_attest(
        receipt_dir,
        request,
        &outcome,
        apply,
        config_state,
        &typed_receipts,
    )?;
    Ok(outcome)
}

#[cfg(test)]
mod declared_sudoers_convergence_tests {
    use super::*;

    const FRAGMENT: &str = "90-harmonia-fixture";

    fn fixture_request(root: &Path) -> FileConvergenceRequest {
        FileConvergenceRequest {
            source_root: root.join("source"),
            target_root: root.join("sudoers.d"),
            files: vec![crate::atoms::files::FileSpec {
                relative_path: PathBuf::from(FRAGMENT),
                mode: Some(0o440),
            }],
            backup_existing: false,
            receipt_name: "declared-sudoers-fixture".into(),
            owner: Some("root".into()),
            group: Some("root".into()),
        }
    }

    fn assert_contract_refused(request: &FileConvergenceRequest, target_root: &Path) {
        let error = converge_declared_sudoers_fragments_authorized_at(
            request,
            &target_root.join("receipts"),
            None,
            None,
            target_root,
        )
        .unwrap_err();
        assert_eq!(error, "declared-sudoers-forced-clobber-contract-refused");
    }

    #[test]
    fn declared_sudoers_refuses_wrong_target_root() {
        let root = tempfile::tempdir().unwrap();
        let request = fixture_request(root.path());
        let error = converge_declared_sudoers_fragments_authorized(
            &request,
            &root.path().join("receipts"),
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(error, "declared-sudoers-forced-clobber-contract-refused");
    }

    #[test]
    fn declared_sudoers_refuses_backup_existing() {
        let root = tempfile::tempdir().unwrap();
        let mut request = fixture_request(root.path());
        request.backup_existing = true;
        assert_contract_refused(&request, &request.target_root);
    }

    #[test]
    fn declared_sudoers_refuses_non_root_owner_or_group() {
        let root = tempfile::tempdir().unwrap();
        let mut request = fixture_request(root.path());
        request.owner = Some("owner".into());
        assert_contract_refused(&request, &request.target_root);

        request.owner = Some("root".into());
        request.group = Some("owner".into());
        assert_contract_refused(&request, &request.target_root);
    }

    #[test]
    fn declared_sudoers_refuses_non_0440_mode() {
        let root = tempfile::tempdir().unwrap();
        let mut request = fixture_request(root.path());
        request.files[0].mode = Some(0o640);
        assert_contract_refused(&request, &request.target_root);
    }

    #[test]
    fn declared_sudoers_refuses_authorization_without_invocation() {
        let root = tempfile::tempdir().unwrap();
        let request = fixture_request(root.path());
        let mode = crate::UpdateMode::from_apply_flag_with_invocation(true, None);
        let error = converge_declared_sudoers_fragments_authorized_at(
            &request,
            &root.path().join("receipts"),
            mode.software_authorization(),
            None,
            &request.target_root,
        )
        .unwrap_err();
        assert_eq!(error, "declared-sudoers-forced-clobber-invocation-required");
    }

    #[test]
    fn declared_sudoers_observe_only_admits_exact_shape_without_placement() {
        let root = tempfile::tempdir().unwrap();
        let request = fixture_request(root.path());
        fs::create_dir_all(&request.source_root).unwrap();
        fs::create_dir_all(&request.target_root).unwrap();
        fs::write(request.source_root.join(FRAGMENT), b"declared\n").unwrap();
        fs::write(request.target_root.join(FRAGMENT), b"drifted\n").unwrap();

        let outcome = converge_declared_sudoers_fragments_authorized_at(
            &request,
            &root.path().join("receipts"),
            None,
            None,
            &request.target_root,
        )
        .unwrap();

        assert!(outcome.ok);
        assert!(outcome.changed);
        assert_eq!(outcome.written, 0);
        assert_eq!(
            fs::read(request.target_root.join(FRAGMENT)).unwrap(),
            b"drifted\n"
        );
        assert!(!root.path().join("interactables.json").exists());
    }

    #[test]
    fn declared_sudoers_apply_replaces_drift_and_sets_exact_metadata_when_root() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let request = fixture_request(root.path());
        fs::create_dir_all(&request.source_root).unwrap();
        fs::create_dir_all(&request.target_root).unwrap();
        fs::write(request.source_root.join(FRAGMENT), b"declared\n").unwrap();
        fs::write(request.target_root.join(FRAGMENT), b"drifted\n").unwrap();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let mode = crate::UpdateMode::from_apply_flag_with_invocation(true, Some(&invocation));

        let outcome = converge_declared_sudoers_fragments_authorized_at(
            &request,
            &root.path().join("receipts"),
            mode.software_authorization(),
            Some(&invocation),
            &request.target_root,
        )
        .unwrap();

        let target = request.target_root.join(FRAGMENT);
        let metadata = fs::metadata(&target).unwrap();
        assert!(outcome.ok);
        assert!(outcome.changed);
        assert_eq!(outcome.written, 1);
        assert_eq!(fs::read(&target).unwrap(), b"declared\n");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o440);
        assert_eq!(metadata.uid(), 0);
        assert_eq!(metadata.gid(), 0);
        assert!(!root.path().join("interactables.json").exists());
    }
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
            "interactable-target-inspection-failed {}: {error}",
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
