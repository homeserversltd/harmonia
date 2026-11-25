//! Typed copy-file actuator: explicit authorization, invocation, and mutation inputs.
use crate::atoms::r#do::InvocationKey;
use crate::atoms::{Drift, Receipt};
use crate::atoms::comparison::ActionAuthorization;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub source: PathBuf,
    pub target: PathBuf,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub no_follow: bool,
    pub restore: Option<PathBuf>,
}
pub(crate) fn copy(a: &ActionAuthorization, i: &InvocationKey, p: &Plan) -> Result<(), String> {
    if p.source.as_os_str().is_empty() || p.target.as_os_str().is_empty() {
        return Err("copy-file-input-missing".into());
    };
    if !p.no_follow {
        return Err("copy-file-no-follow-required".into());
    };
    let _path = std::ffi::CString::new(p.target.as_os_str().as_bytes())
        .map_err(|_| "copy-file-owner-path-nul")?;
    let observation = crate::atoms::ask::copy_file::probe(&p.source, &p.target)?;
    let bytes = observation.source.bytes.ok_or_else(|| {
        "copy-file-source-read-failed: source is not a regular file".to_string()
    })?;
    if let Some(parent) = p.target.parent().filter(|p| !p.as_os_str().is_empty()) {
        crate::atoms::projectio::act_make_dir(a, parent)
            .map_err(|e| format!("copy-file-parent-create-failed: {e}"))?;
    }
    let result = match fs::symlink_metadata(&p.target) {
        Ok(metadata) if metadata.file_type().is_file() => {
            crate::atoms::projectio::act_strike(a, &p.target, &bytes,
                p.mode.unwrap_or(metadata.mode() & 0o7777),
                p.uid.unwrap_or(metadata.uid()), p.gid.unwrap_or(metadata.gid())).map(|_| ())
        }
        Ok(_) => Err(format!("projectio-target-not-regular-file {}", p.target.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let parent = p.target.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
            let parent_metadata = fs::metadata(parent).map_err(|e| format!("copy-file-write-failed: {e}"))?;
            let gid = if parent_metadata.mode() & 0o2000 != 0 { parent_metadata.gid() } else { unsafe { libc::getegid() } };
            crate::atoms::projectio::act_create(a, &p.target, &bytes,
                p.mode.unwrap_or(0o644), p.uid.unwrap_or_else(|| unsafe { libc::geteuid() }),
                p.gid.unwrap_or(gid)).map(|_| ())
        }
        Err(e) => Err(e.to_string()),
    };
    result.map_err(|e| format!("copy-file-write-failed: {e}"))?;
    let _ = i;
    Ok(())
}
