//! One single-act tool that brings one file to its declared bytes and metadata.
#![allow(dead_code)]

use crate::atoms::{self, Drift, Receipt};
use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

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
    pub invocation: Option<atoms::r#do::InvocationKey>,
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
    pub invocation: atoms::r#do::InvocationKey,
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
        authorization: ActionAuthorization,
        invocation: atoms::r#do::InvocationKey,
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
