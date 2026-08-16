// Owned attest atom for set-clock
use crate::{atoms, CmdResult};
use std::path::Path;

pub(crate) fn write_tool_receipt(
    receipt_dir: &Path,
    step_id: &str,
    permutation: &str,
    outcome: &crate::OperationOutcome,
) -> Result<(), String> {
    crate::write_tool_receipt(receipt_dir, step_id, "set-clock", permutation, outcome)
}

pub(crate) fn attest(log: &Path, operation: &str, result: &CmdResult) -> Result<(), String> {
    atoms::attest::attest(
        log,
        &atoms::Receipt {
            atom: "set-clock".into(),
            ok: result.ok,
            drift: atoms::Drift::Current,
            message: format!(
                "operation={operation}; code={}; stdout={}; stderr={}",
                result.code, result.stdout, result.stderr
            ),
        },
        &[],
    )
}
