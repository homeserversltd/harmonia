use crate::{atoms, CmdResult};
use std::path::Path;

pub(super) fn attest(log: &Path, result: &CmdResult) -> Result<(), String> {
    atoms::attest::attest(
        log,
        &atoms::Receipt {
            atom: "check-health".into(),
            ok: result.ok,
            drift: atoms::Drift::Current,
            message: format!(
                "code={}; stdout={}; stderr={}",
                result.code, result.stdout, result.stderr
            ),
        },
        &[],
    )
}
