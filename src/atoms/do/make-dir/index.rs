use crate::atoms::r#do::{apply, InvocationKey};
use crate::atoms::{Drift, Receipt};
use crate::atoms::comparison::ActionAuthorization;
use std::fs;
use std::path::Path;

pub(crate) fn create_dir_all(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    path: &Path,
) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| error.to_string())?;
    apply(
        authorization,
        invocation,
        Receipt {
            atom: "do".into(),
            ok: true,
            drift: Drift::Current,
            message: format!("directory created {}", path.display()),
        },
    )?;
    Ok(())
}
