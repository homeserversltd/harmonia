use crate::{atoms, CmdResult};
use std::path::Path;

pub(super) fn attest(log: &Path, operation: &str, result: &CmdResult) -> Result<(), String> {
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
