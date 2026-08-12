use crate::{atoms, CmdResult};
pub(super) fn attest(unit: &str, log: &std::path::Path, result: &CmdResult) -> Result<(), String> {
    atoms::attest::attest(
        log,
        &atoms::Receipt {
            atom: "enable-unit".into(),
            ok: result.ok,
            drift: atoms::Drift::Current,
            message: format!(
                "unit={unit}; code={}; stdout={}; stderr={}",
                result.code, result.stdout, result.stderr
            ),
        },
        &[],
    )
}
