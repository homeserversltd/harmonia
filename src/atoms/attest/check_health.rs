// Owned attest atom for check-health
use crate::CmdResult;
use std::path::Path;

pub(crate) fn attest(log: &Path, result: &CmdResult) -> Result<(), String> {
    crate::atoms::attest::attest(
        log,
        &crate::atoms::Receipt {
            atom: "check-health".into(),
            ok: result.ok,
            drift: crate::atoms::Drift::Current,
            message: format!(
                "code={}; stdout={}; stderr={}",
                result.code, result.stdout, result.stderr
            ),
        },
        &[],
    )
}

pub(crate) fn write_proof_receipt(
    dir: &Path,
    name: &str,
    result: &CmdResult,
) -> Result<(), String> {
    crate::write_command_receipt(dir, name, result)
}
