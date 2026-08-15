use crate::atoms::r#do::{apply, InvocationKey};
use crate::atoms::{Drift, Receipt};
use crate::tools::comparison::ActionAuthorization;
use std::fs;
use std::path::Path;

pub(crate) fn rename(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    from: &Path,
    to: &Path,
) -> Result<(), String> {
    fs::rename(from, to).map_err(|error| error.to_string())?;
    apply(
        authorization,
        invocation,
        Receipt {
            atom: "do".into(),
            ok: true,
            drift: Drift::Current,
            message: format!("renamed {} -> {}", from.display(), to.display()),
        },
    )?;
    Ok(())
}
