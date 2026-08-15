use crate::atoms::r#do::InvocationKey;
use crate::tools::comparison::ActionAuthorization;

pub(crate) fn aur_install(
    _authorization: ActionAuthorization,
    _invocation: InvocationKey,
    callback: impl FnOnce() -> Result<crate::OperationOutcome, String>,
) -> Result<crate::OperationOutcome, String> {
    callback()
}
