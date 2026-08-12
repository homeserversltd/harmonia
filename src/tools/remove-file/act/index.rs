use super::*;
use crate::tools::comparison::ActionAuthorization;

pub(super) fn remove(
    authorization: ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    target: &Path,
) -> Result<bool, String> {
    atoms::r#do::remove_file(authorization, invocation, target)
        .map_err(|error| format!("files-remove-failed {}: {error}", target.display()))?;
    Ok(true)
}
