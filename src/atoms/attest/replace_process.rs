//! Typed owner for replace-process attestations.
use crate::atoms;
use std::path::Path;

pub(crate) fn attest(path: &Path, receipt: &atoms::Receipt) -> Result<(), String> {
    atoms::attest::attest(path, receipt, &[])
}

pub(crate) fn serialize_receipt(receipt: &impl serde::Serialize) -> Result<Vec<u8>, String> {
    serde_json::to_vec(receipt).map_err(|e| e.to_string())
}
