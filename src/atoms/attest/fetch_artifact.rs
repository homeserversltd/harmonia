use crate::atoms::{Drift, Receipt};
use std::path::Path;

pub(crate) fn attest(log: &Path, ok: bool, changed: bool, message: &str) -> Result<(), String> {
    // Only a successful transition whose observed after-state is Current may
    // use Drift::Current; planned or failed drift must remain visible.
    let after_is_current = message.contains("after=Current");
    crate::atoms::attest::attest(
        log,
        &Receipt {
            atom: "fetch-artifact".into(),
            ok,
            drift: if ok && after_is_current {
                Drift::Current
            } else {
                Drift::File {
                    expected_sha256: "Current".into(),
                    actual_sha256: Some(if after_is_current {
                        "unverified".into()
                    } else {
                        "Drift".into()
                    }),
                }
            },
            message: format!("changed={changed}; {message}"),
        },
        &[],
    )
}
