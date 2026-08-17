//! Typed no-follow mode actuator.
use crate::atoms::r#do::{apply, InvocationKey};
use crate::atoms::{Drift, Receipt};
use crate::atoms::comparison::ActionAuthorization;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub path: PathBuf,
    pub mode: Option<u32>,
    pub no_follow: bool,
}
pub(crate) fn change(a: ActionAuthorization, i: InvocationKey, p: &Plan) -> Result<(), String> {
    let mode = p.mode.ok_or("change-mode-mode-missing")?;
    if !p.no_follow {
        return Err("change-mode-no-follow-required".into());
    };
    let m = fs::symlink_metadata(&p.path).map_err(|e| format!("change-mode-stat-failed: {e}"))?;
    if m.file_type().is_symlink() {
        return Err("change-mode-symlink-refused".into());
    };
    fs::set_permissions(&p.path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("change-mode-failed: {e}"))?;
    apply(
        a,
        i,
        Receipt {
            atom: "do".into(),
            ok: true,
            drift: Drift::Current,
            message: "mode changed".into(),
        },
    )?;
    Ok(())
}
