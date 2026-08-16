// Owned attest atom for install-package
use crate::atoms;
use std::path::Path;

pub(crate) fn write_guard_receipt(
    receipt_dir: &Path,
    name: &str,
    before: &crate::tools::package::PackageObservation,
    movement: &crate::OperationOutcome,
    after: &crate::tools::package::PackageObservation,
) -> Result<(), String> {
    crate::tools::package::write_install_package_guard_receipt(
        receipt_dir,
        name,
        before,
        movement,
        after,
    )
}

pub(crate) fn write_receipts(
    receipt_dir: &Path,
    name: &str,
    observation: &crate::tools::package::PackageObservation,
    decision: crate::tools::comparison::DiffDecision,
    movement: Option<&crate::OperationOutcome>,
    outcome: &crate::OperationOutcome,
) -> Result<(), String> {
    crate::write_json(
        &receipt_dir.join(format!("{name}.comparison.json")),
        &crate::tools::package::package_receipt_fields(
            observation,
            decision,
            movement,
            outcome.changed,
        ),
    )?;
    crate::tools::package::write_package_receipt(receipt_dir, name, "install", outcome)?;
    attest(
        &receipt_dir.join(format!("{name}.attest.jsonl")),
        &outcome.message,
        outcome.ok,
    )
}

pub(crate) fn attest(log: &Path, message: &str, ok: bool) -> Result<(), String> {
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
