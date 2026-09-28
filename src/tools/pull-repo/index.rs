//! Compatibility forwarding for the pull-repo tool.
pub(crate) fn plan(request: &crate::atoms::git_artifact::Request) -> crate::atoms::git_artifact::Outcome {
    crate::atoms::r#do::pull_repo::source_orchestration::plan(request)
}
pub(crate) fn apply(request: &crate::atoms::git_artifact::Request, invocation: &crate::atoms::r#do::InvocationKey) -> crate::atoms::git_artifact::Outcome {
    crate::atoms::r#do::pull_repo::source_orchestration::apply(request, invocation)
}
pub(crate) fn acquire_xenia_clone(entry: &serde_json::Value, destination: std::path::PathBuf, apply: bool) -> crate::atoms::git_artifact::SourceOutcome {
    crate::atoms::r#do::pull_repo::source_orchestration::acquire_xenia_clone(entry, destination, apply)
}
pub(crate) fn acquire_source(plan: &crate::atoms::git_artifact::SourcePlan, invocation: Option<&crate::atoms::r#do::InvocationKey>) -> crate::atoms::git_artifact::SourceOutcome {
    crate::atoms::r#do::pull_repo::source_orchestration::acquire_source(plan, invocation)
}
pub(crate) fn observe_source(plan: &crate::atoms::git_artifact::SourcePlan) -> Option<crate::atoms::git_artifact::SourceOutcome> {
    crate::atoms::ask::pull_repo::observe_source_current(plan)
}
pub(crate) fn attest_source(log: &std::path::Path, value: &crate::atoms::git_artifact::SourceOutcome) -> Result<(), String> {
    crate::atoms::r#do::pull_repo::source_orchestration::attest_source(log, value)
}
pub fn declaration() -> Result<Option<&'static crate::tools::declaration::Declaration>, String> { crate::tools::declaration::get("pull-repo") }
