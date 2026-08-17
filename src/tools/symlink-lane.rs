//! Extracted symlink lane compatibility seat.

use std::path::Path;

// Operation-semantic symlink actuator seat owned by the files tool.
pub(crate) fn make_link(
    authorization: crate::tools::comparison::ActionAuthorization,
    invocation: crate::atoms::r#do::InvocationKey,
    target: &Path,
    link: &Path,
) -> Result<(), String> {
    crate::atoms::r#do::make_link::symlink(authorization, invocation, target, link)
}
