use crate::atoms;
use crate::tools::comparison::ActionAuthorization;
use std::path::Path;
use std::time::Duration;
pub(super) fn build(
    auth: ActionAuthorization,
    key: atoms::r#do::InvocationKey,
    cwd: &Path,
    environment: &[(String, String)],
    timeout_secs: u64,
    bearer: &str,
) -> Result<crate::atoms::CommandObservation, String> {
    crate::atoms::r#do::cargo_build(
        auth,
        key,
        cwd,
        environment,
        bearer,
        Duration::from_secs(timeout_secs),
    )
}
