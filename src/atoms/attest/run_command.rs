//! Typed command attestation; Ask observes and Attest owns serialization.
use serde::Serialize;
use serde_json::Value;
use std::path::Path;

pub(crate) fn value<P: Serialize, O: Serialize>(
    preimage: &P,
    outcome: &O,
) -> Result<Value, String> {
    serde_json::to_value(serde_json::json!({"preimage": preimage, "outcome": outcome}))
        .map_err(|e| e.to_string())
}

pub(crate) fn write_json<P: Serialize, O: Serialize>(
    path: &Path,
    preimage: &P,
    outcome: &O,
) -> Result<(), String> {
    crate::write_json(path, &value(preimage, outcome)?)
}
