use crate::atoms::r#do::{apply, InvocationKey};
use crate::atoms::{Drift, Receipt};
use crate::tools::comparison::ActionAuthorization;
use std::path::Path;

#[cfg(unix)]
pub(crate) fn symlink(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    target: &Path,
    link: &Path,
) -> Result<(), String> {
    std::os::unix::fs::symlink(target, link).map_err(|error| error.to_string())?;
    apply(
        authorization,
        invocation,
        Receipt {
            atom: "do".into(),
            ok: true,
            drift: Drift::Current,
            message: format!("symlink created {} -> {}", link.display(), target.display()),
        },
    )?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn symlink(
    _authorization: ActionAuthorization,
    _invocation: InvocationKey,
    _target: &Path,
    _link: &Path,
) -> Result<(), String> {
    Err("validated-file-symlink-unsupported".into())
}
