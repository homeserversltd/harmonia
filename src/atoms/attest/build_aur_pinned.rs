use std::path::Path;

pub(crate) fn write_pinned_artifacts_receipt(
    path: &Path,
    value: &serde_json::Value,
) -> Result<(), String> {
    crate::write_json(path, value)
}

pub(crate) fn report(
    log: &Path,
    receipt_path: &Path,
    verdict: &str,
    ok: bool,
    outcome: String,
) -> Result<(), String> {
    let bytes = std::fs::read(receipt_path)
        .map_err(|error| format!("aur-attest-receipt-read-failed: {error}"))?;
    let receipt: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("aur-attest-receipt-parse-failed: {error}"))?;
    let observed = receipt.get("observed_state").cloned().unwrap_or(serde_json::Value::Null);
    let desired = receipt.get("desired_state").cloned().unwrap_or(serde_json::Value::Null);
    let diff = receipt.get("diff_decision").cloned().unwrap_or(serde_json::Value::Null);
    let movement = receipt.get("movement").cloned().unwrap_or(serde_json::Value::Null);
    let first_missing = receipt.get("first_missing_signal").cloned()
        .or_else(|| receipt.get("first_blocker").cloned())
        .unwrap_or_else(|| serde_json::json!("none"));
    let has_drift = verdict == "upstream-moved-past-pin"
        || diff.as_str() == Some("different")
        || first_missing.as_str().is_some_and(|signal| signal != "none");
    let drift = if has_drift {
        crate::atoms::Drift::Unit {
            expected: desired.to_string(),
            actual: observed.to_string(),
        }
    } else {
        crate::atoms::Drift::Current
    };
    crate::atoms::attest::attest(
        log,
        &crate::atoms::Receipt {
            atom: "ratchet-aur-package".into(),
            ok,
            drift,
            message: serde_json::json!({
                "verdict": verdict,
                "outcome": outcome,
                "observed_state": observed,
                "desired_state": desired,
                "diff": diff,
                "movement": movement,
                "first_missing_signal": first_missing,
            }).to_string(),
        },
        &[],
    )
}
