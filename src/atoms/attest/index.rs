//! One-call receipt custody: local appliance stream then Hyalos.
#![allow(dead_code)]
use super::{append_appliance_log, Receipt};
use crate::hyalos;
use std::path::Path;

pub(crate) fn attest(log: &Path, receipt: &Receipt) -> Result<(), String> {
    append_appliance_log(log, receipt)?;
    hyalos::forward_receipt(
        "harmonia.atom",
        &receipt.message,
        Some(serde_json::json!({"atom": receipt.atom, "drift": receipt.drift})),
        Some(receipt.ok),
    );
    Ok(())
}
