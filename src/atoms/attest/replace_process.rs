//! Typed owner for replace-process attestations.
use crate::atoms;
use std::fs;
use std::path::Path;

pub(crate) fn attest(
    receipt_path: &Path,
    atom_log: &Path,
    receipt: &impl serde::Serialize,
) -> Result<Vec<u8>, String> {
    let bytes = serialize_receipt(receipt)?;
    atoms::attest::write_receipt_bytes_atomic(receipt_path, &bytes)?;
    let persisted = fs::read(receipt_path)
        .map_err(|error| format!("replace-process-receipt-readback-failed: {error}"))?;
    if persisted != bytes {
        return Err("replace-process-receipt-bytes-changed".into());
    }
    atoms::attest::attest(
        atom_log,
        &atoms::Receipt {
            atom: "replace-process".into(),
            ok: true,
            drift: atoms::Drift::Current,
            message: format!(
                "durable_receipt={} bytes={} guard_consumed=true",
                receipt_path.display(),
                bytes.len()
            ),
        },
        &[],
    )?;
    Ok(persisted)
}

pub(crate) fn serialize_receipt(receipt: &impl serde::Serialize) -> Result<Vec<u8>, String> {
    serde_json::to_vec(receipt).map_err(|e| e.to_string())
}
