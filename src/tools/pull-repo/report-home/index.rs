use crate::tools::git_artifact::{Outcome, SourceOutcome};
pub(crate) fn outcome(value: Outcome) -> Outcome {
    value
}
pub(crate) fn source(value: SourceOutcome) -> SourceOutcome {
    value
}

pub(crate) fn attest_source(log: &std::path::Path, value: &SourceOutcome) -> Result<(), String> {
    crate::atoms::attest::attest(
        log,
        &crate::atoms::Receipt {
            atom: "pull-repo".into(),
            ok: value.ok,
            drift: crate::atoms::Drift::Current,
            message: "authoritative receipt=pull-repo.json".into(),
        },
        &[],
    )
}
