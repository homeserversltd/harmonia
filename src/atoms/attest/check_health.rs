// Owned attest atom for check-health
use crate::CmdResult;
use std::path::Path;

pub(crate) fn attest(_log: &Path, _result: &CmdResult) -> Result<(), String> {
    // A health query returns its observation and persists nothing.
    Ok(())
}

pub(crate) fn write_proof_receipt(
    dir: &Path,
    name: &str,
    result: &CmdResult,
) -> Result<(), String> {
    crate::write_command_receipt(dir, name, result)
}
