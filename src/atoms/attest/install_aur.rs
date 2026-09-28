//! Typed receipt serialization for current-head AUR installation.
pub(crate) fn write(path: &std::path::Path, value: &serde_json::Value) -> Result<(), String> {
    crate::write_json(path, value)
}

pub(crate) fn report_failure(
    receipt_dir: &std::path::Path,
    receipt_name: &str,
    operation: &str,
    package: &str,
    error: &str,
) -> Result<(), String> {
    let observed = format!("unavailable:{error}");
    let desired = match operation {
        "check" => "upstream-observation-and-lock-comparison",
        "build-pinned" => "pinned-artifact-built-and-verified",
        _ => "declared-aur-operation-complete",
    };
    let first_missing_signal = format!("first_missing_signal=aur-{operation}-failed:{error}");
    crate::atoms::attest::attest(
        &receipt_dir.join(format!("{receipt_name}.attest.jsonl")),
        &crate::atoms::Receipt {
            atom: "ratchet-aur-package".into(),
            ok: false,
            drift: crate::atoms::Drift::Command {
                expected_code: 0,
                actual_code: None,
            },
            message: format!(
                "operation={operation} package={package} observed={observed} desired={desired} diff=unavailable:failed-observation movement=not-attempted {first_missing_signal}"
            ),
        },
        &[],
    )
}
