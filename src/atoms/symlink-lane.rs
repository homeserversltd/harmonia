//! Extracted symlink lane compatibility seat.

use std::path::Path;

// Operation-semantic symlink actuator seat owned by the files tool.
pub(crate) fn make_link(
    authorization: &crate::atoms::comparison::ActionAuthorization,
    invocation: &crate::atoms::r#do::InvocationKey,
    target: &Path,
    link: &Path,
) -> Result<(), String> {
    crate::atoms::r#do::make_link::symlink(authorization, invocation, target, link)
}

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use crate::atoms::comparison::ActionAuthorization;
use crate::atoms::files::{
    SymlinkConvergeRequest, SymlinkPathIdentity, SymlinkSourceIdentity, SymlinkSourceKind,
};

pub(crate) fn observe_symlink_path(path: &Path) -> Result<SymlinkPathIdentity, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            let kind = if file_type.is_symlink() {
                "symlink"
            } else if file_type.is_file() {
                "regular-file"
            } else if file_type.is_dir() {
                "directory"
            } else {
                "other"
            };
            let link_target = if file_type.is_symlink() {
                Some(fs::read_link(path).map_err(|error| {
                    format!(
                        "symlink-converge-readlink-failed {}: {error}",
                        path.display()
                    )
                })?)
            } else {
                None
            };
            Ok(SymlinkPathIdentity {
                kind: kind.to_string(),
                link_target,
                mode: Some(metadata.permissions().mode() & 0o7777),
                uid: Some(metadata.uid()),
                gid: Some(metadata.gid()),
                device: Some(metadata.dev()),
                inode: Some(metadata.ino()),
                size: Some(metadata.size()),
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(SymlinkPathIdentity {
            kind: "absent".to_string(),
            link_target: None,
            mode: None,
            uid: None,
            gid: None,
            device: None,
            inode: None,
            size: None,
        }),
        Err(error) => Err(format!(
            "symlink-converge-target-observation-failed {}: {error}",
            path.display()
        )),
    }
}

#[cfg(not(unix))]
pub(crate) fn observe_symlink_path(_path: &Path) -> Result<SymlinkPathIdentity, String> {
    Err("symlink-converge-unsupported".to_string())
}

#[cfg(unix)]
pub(crate) fn read_symlink_source(
    path: &Path,
    required_kind: SymlinkSourceKind,
) -> Result<SymlinkSourceIdentity, String> {
    let file = crate::atoms::attest::open_nofollow_read(path).map_err(|error| {
        format!(
            "symlink-converge-source-open-failed {}: {error}",
            path.display()
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        format!(
            "symlink-converge-source-readback-failed {}: {error}",
            path.display()
        )
    })?;
    match required_kind {
        SymlinkSourceKind::RegularExecutable => {
            if !metadata.file_type().is_file() {
                return Err(format!(
                    "symlink-converge-source-kind-mismatch {} expected=regular-executable",
                    path.display()
                ));
            }
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(format!(
                    "symlink-converge-source-not-executable {}",
                    path.display()
                ));
            }
        }
    }
    Ok(SymlinkSourceIdentity {
        kind: "regular-executable".to_string(),
        mode: metadata.permissions().mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        change_seconds: metadata.ctime(),
        change_nanoseconds: metadata.ctime_nsec(),
    })
}

#[cfg(not(unix))]
pub(crate) fn read_symlink_source(
    _path: &Path,
    _required_kind: SymlinkSourceKind,
) -> Result<SymlinkSourceIdentity, String> {
    Err("symlink-converge-unsupported".to_string())
}

#[derive(Debug, Clone)]
pub(crate) struct SymlinkComparisonObservation {
    pub(crate) before: SymlinkPathIdentity,
    pub(crate) source: Result<SymlinkSourceIdentity, String>,
    pub(crate) desired_uid: Option<u32>,
    pub(crate) desired_gid: Option<u32>,
}

pub(crate) fn symlink_diff_decision(
    observation: &SymlinkComparisonObservation,
    request: &SymlinkConvergeRequest,
) -> crate::atoms::comparison::DiffDecision {
    let ownership_current = observation
        .desired_uid
        .map_or(true, |uid| observation.before.uid == Some(uid))
        && observation
            .desired_gid
            .map_or(true, |gid| observation.before.gid == Some(gid));
    let exact = observation.before.kind == "symlink"
        && observation.before.link_target.as_deref() == Some(request.source.as_path())
        && ownership_current
        && observation.source.is_ok();
    if exact {
        crate::atoms::comparison::DiffDecision::Empty
    } else {
        crate::atoms::comparison::DiffDecision::Different
    }
}

pub(crate) fn validated_symlink(
    receipt_dir: &Path,
    name: &str,
    source: &Path,
    target: &Path,
    validator_program: &str,
    validator_args: &[String],
    reload_program: Option<&str>,
    reload_args: &[String],
    timeout_secs: u64,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<crate::OperationOutcome, String> {
    crate::atoms::r#do::make_symlink::execute(
        crate::atoms::r#do::make_symlink::ValidatedFileSymlinkRequest {
            receipt_dir,
            name,
            desired_source: source,
            source,
            target,
            validator_program,
            validator_args,
            reload_program,
            reload_args,
            timeout_secs,
            apply,
        },
        invocation,
    )
}
