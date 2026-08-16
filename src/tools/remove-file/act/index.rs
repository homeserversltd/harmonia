use super::*;
use crate::tools::comparison::ActionAuthorization;

pub(super) fn remove(
    authorization: ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    target: &Path,
    policy: atoms::r#do::remove_file::RemovePolicy,
) -> Result<bool, String> {
    atoms::r#do::remove_file::remove_file_with_policy(authorization, invocation, target, policy)
        .map_err(|error| format!("files-remove-failed {}: {error}", target.display()))?;
    Ok(true)
}
