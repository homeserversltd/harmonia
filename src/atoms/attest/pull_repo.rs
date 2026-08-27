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

pub(crate) fn write_receipts(
    receipt_dir: &Path,
    name: &str,
    source: &SourceReceipt,
    command: &CommandReceipt,
) -> Result<(), String> {
    // The typed source receipt is the primary pull-repo receipt. Keep the
    // command and attempt receipts as the typed bundle's supporting records.
    write_source_receipt(&receipt_dir.join(format!("{name}.json")), source)?;
    write_command_receipt(&receipt_dir.join(format!("{name}.command.json")), command)?;
    for attempt in &source.attempts {
        write_source_attempt_receipt(
            &receipt_dir.join(format!("{name}.attempt-{}.json", attempt.index)),
            attempt,
        )?;
    }
    atoms::attest::attest(
        &receipt_dir.join(format!("{name}.attest.jsonl")),
        &Receipt {
            atom: "pull-repo".into(),
            ok: source.served_index.is_some(),
            drift: Drift::Current,
            message: format!("pull-repo receipt={name}"),
        },
        &[],
    )
}
