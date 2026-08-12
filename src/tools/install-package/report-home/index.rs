use crate::atoms;
use std::path::Path;

pub(super) fn attest(log: &Path, message: &str, ok: bool) -> Result<(), String> {
    atoms::attest::attest(
        log,
        &atoms::Receipt {
            atom: "install-package".into(),
            ok,
            drift: atoms::Drift::Current,
            message: message.into(),
        },
        &[],
    )
}
