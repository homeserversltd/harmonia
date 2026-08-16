use crate::atoms;
use crate::tools::git_artifact::{Outcome, Request, SourceOutcome, SourcePlan};
pub(crate) fn git_pull(
    authorization: crate::tools::comparison::ActionAuthorization,
    request: &Request,
    invocation: crate::atoms::r#do::InvocationKey,
) -> Outcome {
    atoms::r#do::git_pull(authorization, invocation, request, || {
        crate::atoms::r#do::pull_repo::apply_legacy(request)
    })
}
pub(crate) fn git_acquire(
    authorization: crate::tools::comparison::ActionAuthorization,
    plan: &SourcePlan,
    invocation: crate::atoms::r#do::InvocationKey,
) -> SourceOutcome {
    atoms::r#do::git_acquire(authorization, invocation, plan, || {
        crate::atoms::r#do::pull_repo::acquire_source(plan)
    })
}
