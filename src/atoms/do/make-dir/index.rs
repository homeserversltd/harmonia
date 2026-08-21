use crate::atoms::r#do::InvocationKey;
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
    let _ = (authorization, invocation);
    Ok(())
}
