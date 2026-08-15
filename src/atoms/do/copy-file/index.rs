//! Typed copy-file actuator: explicit authorization, invocation, and mutation inputs.
use crate::atoms::r#do::{apply, InvocationKey};
use crate::atoms::{Drift, Receipt};
use crate::tools::comparison::ActionAuthorization;
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
pub(crate) fn copy(a: ActionAuthorization, i: InvocationKey, p: &Plan) -> Result<(), String> {
    if p.source.as_os_str().is_empty() || p.target.as_os_str().is_empty() {
        return Err("copy-file-input-missing".into());
    };
    if !p.no_follow {
        return Err("copy-file-no-follow-required".into());
    };
    let bytes = fs::read(&p.source).map_err(|e| format!("copy-file-source-read-failed: {e}"))?;
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
    apply(
        a,
        i,
        Receipt {
            atom: "do".into(),
            ok: true,
            drift: Drift::Current,
            message: format!("copy {} -> {}", p.source.display(), p.target.display()),
        },
    )?;
    Ok(())
}
