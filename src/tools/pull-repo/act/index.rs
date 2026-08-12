use crate::atoms;
use crate::tools::git_artifact::{self, Outcome, Request, SourceOutcome, SourcePlan};
pub(crate) fn git_pull(
    authorization: crate::tools::comparison::ActionAuthorization,
    request: &Request,
) -> Outcome {
    let invocation =
        atoms::r#do::InvocationKey::from_apply_or_timer(true).expect("apply invocation");
    atoms::r#do::git_pull(authorization, invocation, request, || {
        git_artifact::legacy_apply(request)
    })
}
pub(crate) fn git_acquire(
    authorization: crate::tools::comparison::ActionAuthorization,
    plan: &SourcePlan,
) -> SourceOutcome {
    let invocation =
        atoms::r#do::InvocationKey::from_apply_or_timer(true).expect("acquire invocation");
    atoms::r#do::git_acquire(authorization, invocation, plan, || {
        git_artifact::legacy_acquire_source(plan)
    })
}
