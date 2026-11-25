use crate::atoms::r#do::InvocationKey;
use crate::atoms::{Drift, Receipt};
use crate::atoms::comparison::ActionAuthorization;

use std::path::Path;

pub(crate) fn rename(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    from: &Path,
    to: &Path,
) -> Result<(), String> {
    crate::atoms::projectio::act_rename(authorization, from, to, false).map_err(|error| error.to_string())?;
    let _ = (authorization, invocation);
    Ok(())
}

pub(crate) fn rename_from_scratch(
    authorization: &ActionAuthorization, invocation: &InvocationKey, from: &Path, to: &Path,
) -> Result<(), String> {
    crate::atoms::projectio::act_rename(authorization, from, to, true).map_err(|error| error.to_string())?;
    let _ = (authorization, invocation);
    Ok(())
}
