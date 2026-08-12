use super::*;
use crate::tools::comparison::ActionAuthorization;

pub(super) fn remove(
    authorization: ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    target: &Path,
) -> Result<bool, String> {
    atoms::r#do::remove_file(authorization, invocation, target)
        .map_err(|error| format!("files-remove-failed {}: {error}", target.display()))?;
    if atoms::ask::path_kind(target).is_ok_and(|kind| kind.is_some()) {
        return Err(format!(
            "files-remove-post-remove-readback-failed {}",
            target.display()
        ));
    }
    Ok(true)
}
