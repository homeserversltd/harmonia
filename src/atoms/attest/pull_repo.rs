//! Typed receipt writers for the pull-repo atom.
use crate::atoms::git_artifact::{CommandReceipt, SourceAttemptReceipt, SourceReceipt};
use crate::atoms::{self, Drift, Receipt};
use std::path::Path;

pub(crate) fn write_command_receipt(path: &Path, receipt: &CommandReceipt) -> Result<(), String> {
    let value = serde_json::to_value(receipt)
        .map_err(|e| format!("pull-repo-command-receipt-serialize: {e}"))?;
    atoms::attest::write_json_atomic(path, &value)
}

pub(crate) fn write_source_attempt_receipt(
    path: &Path,
    receipt: &SourceAttemptReceipt,
) -> Result<(), String> {
    let value = serde_json::to_value(receipt)
        .map_err(|e| format!("pull-repo-attempt-receipt-serialize: {e}"))?;
    atoms::attest::write_json_atomic(path, &value)
}

pub(crate) fn write_source_receipt(path: &Path, receipt: &SourceReceipt) -> Result<(), String> {
    let value = serde_json::to_value(receipt)
        .map_err(|e| format!("pull-repo-source-receipt-serialize: {e}"))?;
    atoms::attest::write_json_atomic(path, &value)
}

pub(crate) fn write_receipts_with_truth(
    receipt_dir: &Path, name: &str, source: &SourceReceipt, command: &CommandReceipt, ok: bool, changed: bool,
) -> Result<(), String> {
    write_source_receipt(&receipt_dir.join(format!("{name}.json")), source)?;
    write_command_receipt(&receipt_dir.join(format!("{name}.command.json")), command)?;
    for attempt in &source.attempts {
        write_source_attempt_receipt(&receipt_dir.join(format!("{name}.attempt-{}.json", attempt.index)), attempt)?;
    }
    write_bundle_attest(receipt_dir, name, ok, changed)
}

pub(crate) fn write_bundle_attest(
    receipt_dir: &Path, name: &str, ok: bool, changed: bool,
) -> Result<(), String> {
    atoms::attest::attest(
        &receipt_dir.join(format!("{name}.attest.jsonl")),
        &Receipt {
            atom: "pull-repo".into(),
            ok,
            drift: if ok { Drift::Current } else { Drift::File { expected_sha256: "successful-acquisition".into(), actual_sha256: None } },
            message: format!("pull-repo receipt={name}; changed={changed}"),
        },
        &[],
    )
}
