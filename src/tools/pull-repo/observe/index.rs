use crate::tools::git_artifact::{self, Outcome, Request, SourceOutcome, SourcePlan};
pub(crate) fn request(request: &Request) -> Option<Outcome> {
    git_artifact::observe_request_current(request)
}
pub(crate) fn plan(request: &Request) -> Outcome {
    git_artifact::legacy_plan(request)
}
pub(crate) fn source(plan: &SourcePlan) -> Option<SourceOutcome> {
    git_artifact::observe_source_current(plan)
}
