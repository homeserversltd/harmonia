//! Typed copy-file actuator: explicit authorization, invocation, and mutation inputs.
use crate::atoms::r#do::InvocationKey;
use crate::atoms::{Drift, Receipt};
use crate::atoms::comparison::ActionAuthorization;
use std::fs;
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
    let observation = crate::atoms::ask::copy_file::probe(&p.source, &p.target)?;
    let bytes = observation.source.bytes.ok_or_else(|| {
        "copy-file-source-read-failed: source is not a regular file".to_string()
    })?;
    if let Some(parent) = p.target.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("copy-file-parent-create-failed: {e}"))?
    };
    fs::write(&p.target, &bytes).map_err(|e| format!("copy-file-write-failed: {e}"))?;
    #[cfg(unix)]
    if let Some(mode) = p.mode {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p.target, fs::Permissions::from_mode(mode))
            .map_err(|e| format!("copy-file-mode-failed: {e}"))?;
    }
    #[cfg(unix)]
    if p.uid.is_some() || p.gid.is_some() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let path = CString::new(p.target.as_os_str().as_bytes())
            .map_err(|_| "copy-file-owner-path-nul")?;
        let uid = p.uid.map_or(!0, |v| v) as libc::uid_t;
        let gid = p.gid.map_or(!0, |v| v) as libc::gid_t;
        if unsafe { libc::lchown(path.as_ptr(), uid, gid) } != 0 {
            return Err(format!(
                "copy-file-owner-failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    let _ = (a, i);
    Ok(())
}
