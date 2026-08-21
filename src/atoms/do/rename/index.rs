use crate::atoms::r#do::InvocationKey;
use crate::atoms::{Drift, Receipt};
use crate::atoms::comparison::ActionAuthorization;
use std::fs;
use std::path::Path;

pub(crate) fn rename(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    from: &Path,
    to: &Path,
) -> Result<(), String> {
    fs::rename(from, to).map_err(|error| error.to_string())?;
    let _ = (authorization, invocation);
    Ok(())
}
