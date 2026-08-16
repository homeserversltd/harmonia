// Owned do atom for install-package
use crate::atoms;
    use crate::tools::comparison::ActionAuthorization;
    use std::path::Path;

    pub(crate) fn install(
        authorization: ActionAuthorization,
        invocation: atoms::r#do::InvocationKey,
        receipt_dir: &Path,
        packages: &[String],
        conflict_policy: Option<&str>,
        conflict_paths: &[String],
        timeout_secs: u64,
    ) -> Result<atoms::CommandObservation, String> {
        atoms::r#do::package_install(
            authorization,
            invocation,
            receipt_dir,
            packages,
            conflict_policy,
            conflict_paths,
            timeout_secs,
        )
    }
