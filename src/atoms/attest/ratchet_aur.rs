use std::path::Path;

pub(crate) fn write_pinned_artifacts_receipt(
    path: &Path,
    value: &serde_json::Value,
) -> Result<(), String> {
    crate::write_json(path, value)
}


pub(crate) fn report(log: &Path, verdict: crate::atoms::ask::ratchet_aur::Verdict, outcome: &crate::OperationOutcome) -> Result<(), String> {
    let message = if verdict == crate::atoms::ask::ratchet_aur::Verdict::UpstreamMovedPastPin {
        format!("verdict={}; nudge=bless-new-pin", verdict.as_str())
    } else { format!("verdict={}; outcome={}", verdict.as_str(), outcome.message) };
    crate::atoms::attest::attest(log, &crate::atoms::Receipt { atom: "ratchet-aur-package".into(), ok: outcome.ok, drift: crate::atoms::Drift::Current, message }, &[])
}

pub(crate) fn attest_artifact_lock(log: &Path, observation: &crate::atoms::ask::ratchet_aur::ArtifactLockObservation) -> Result<(), String> {
    crate::atoms::attest::attest(log, &crate::atoms::Receipt { atom: "ratchet-aur-package-observe".into(), ok: observation.ok, drift: crate::atoms::Drift::Current, message: format!("artifact-lock count={}; first_missing_signal={}", observation.artifact_count, observation.first_missing_signal) }, &[])
}
