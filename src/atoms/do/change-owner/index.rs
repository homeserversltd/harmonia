//! Typed lchown owner actuator.
use crate::atoms::r#do::{apply, InvocationKey};
use crate::atoms::{Drift, Receipt};
use crate::atoms::comparison::ActionAuthorization;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub path: PathBuf,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub no_follow: bool,
}
pub(crate) fn change(a: ActionAuthorization, i: InvocationKey, p: &Plan) -> Result<(), String> {
    if p.uid.is_none() && p.gid.is_none() {
        return Err("change-owner-owner-missing".into());
    };
    if !p.no_follow {
        return Err("change-owner-no-follow-required".into());
    };
    let c = CString::new(p.path.as_os_str().as_bytes())
        .map_err(|_| "change-owner-path-nul".to_string())?;
    let u = p.uid.map_or(!0, |v| v) as libc::uid_t;
    let g = p.gid.map_or(!0, |v| v) as libc::gid_t;
    if unsafe { libc::lchown(c.as_ptr(), u, g) } != 0 {
        return Err(format!(
            "change-owner-failed: {}",
            std::io::Error::last_os_error()
        ));
    };
    apply(
        a,
        i,
        Receipt {
            atom: "do".into(),
            ok: true,
            drift: Drift::Current,
            message: "owner changed".into(),
        },
    )?;
    Ok(())
}
