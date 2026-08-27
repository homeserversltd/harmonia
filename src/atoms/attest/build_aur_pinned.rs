use std::path::Path;

pub(crate) fn write_pinned_artifacts_receipt(
    path: &Path,
    value: &serde_json::Value,
) -> Result<(), String> {
    crate::write_json(path, value)
}

pub(crate) fn report(
    log: &std::path::Path,
    verdict: &str,
    ok: bool,
    message: String,
) -> Result<(), String> {
    let message = if verdict == "upstream-moved-past-pin" {
        format!("verdict={verdict}; nudge=bless-new-pin")
    } else {
        format!("verdict={verdict}; outcome={message}")
    };
    crate::atoms::attest::attest(
        log,
        &crate::atoms::Receipt {
            atom: "ratchet-aur-package".into(),
            ok,
            drift: crate::atoms::Drift::Current,
            message,
        },
        &[],
    )
}
