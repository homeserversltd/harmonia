use super::{ArtifactLockObservation, Verdict};
use crate::atoms;
use crate::OperationOutcome;
use std::path::Path;

pub(super) fn write_pinned_artifacts_receipt(
    path: &Path,
    value: &serde_json::Value,
) -> Result<(), String> {
    crate::write_json(path, value)
}

pub(super) fn attest(
    log: &Path,
    verdict: Verdict,
    outcome: &OperationOutcome,
) -> Result<(), String> {
    let message = if verdict == Verdict::UpstreamMovedPastPin {
        format!("verdict={}; nudge=bless-new-pin", verdict.as_str())
    } else {
        format!("verdict={}; outcome={}", verdict.as_str(), outcome.message)
    };
    atoms::attest::attest(
        log,
        &atoms::Receipt {
            atom: "ratchet-aur-package".into(),
            ok: outcome.ok,
            drift: atoms::Drift::Current,
            message,
        },
        &[],
    )
}

pub(super) fn attest_artifact_lock(
    log: &Path,
    observation: &ArtifactLockObservation,
) -> Result<(), String> {
    atoms::attest::attest(
        log,
        &atoms::Receipt {
            atom: "ratchet-aur-package-observe".into(),
            ok: observation.ok,
            drift: atoms::Drift::Current,
            message: format!(
                "artifact-lock count={}; first_missing_signal={}",
                observation.artifact_count, observation.first_missing_signal
            ),
        },
        &[],
    )
}
