use crate::atoms;
use crate::tools::git_artifact::{self, Outcome, Request, SourceOutcome, SourcePlan};
pub(crate) fn git_pull(
    authorization: crate::tools::comparison::ActionAuthorization,
    request: &Request,
    invocation: crate::atoms::r#do::InvocationKey,
) -> Outcome {
       atoms::r#do::git_pull(authorization, invocation, request, || {
        git_artifact::legacy_apply(request)
    })
}
pub(crate) fn git_acquire(
    authorization: crate::tools::comparison::ActionAuthorization,
    plan: &SourcePlan,
    invocation: crate::atoms::r#do::InvocationKey,
) -> SourceOutcome {
       atoms::r#do::git_acquire(authorization, invocation, plan, || {
        git_artifact::legacy_acquire_source(plan)
    })
}
