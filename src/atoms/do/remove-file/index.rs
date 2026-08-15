use crate::atoms::r#do::{apply, InvocationKey};
use crate::atoms::{Drift, Receipt};
use crate::tools::comparison::ActionAuthorization;
use std::fs;
use std::path::Path;

pub(crate) fn remove_file(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    path: &Path,
) -> Result<(), String> {
    fs::remove_file(path).map_err(|error| error.to_string())?;
    apply(
        authorization,
        invocation,
        Receipt {
            atom: "do".into(),
            ok: true,
            drift: Drift::Current,
            message: format!("file removed {}", path.display()),
        },
    )?;
    Ok(())
}
