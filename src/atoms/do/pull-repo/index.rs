use crate::atoms::r#do::InvocationKey;
use crate::tools::comparison::ActionAuthorization;

pub(crate) fn git_pull(
    _authorization: ActionAuthorization,
    _invocation: InvocationKey,
    _request: &crate::tools::git_artifact::Request,
    callback: impl FnOnce() -> crate::tools::git_artifact::Outcome,
) -> crate::tools::git_artifact::Outcome {
    callback()
}

pub(crate) fn git_acquire(
    _authorization: ActionAuthorization,
    _invocation: InvocationKey,
    _plan: &crate::tools::git_artifact::SourcePlan,
    callback: impl FnOnce() -> crate::tools::git_artifact::SourceOutcome,
) -> crate::tools::git_artifact::SourceOutcome {
    callback()
}
