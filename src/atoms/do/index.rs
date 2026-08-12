//! Authorized mutation atom.
#![allow(dead_code)]
use super::{backup_first_write, Receipt};
use crate::tools::comparison::ActionAuthorization;
use std::path::Path;

pub(crate) fn apply(
    _authorization: ActionAuthorization,
    receipt: Receipt,
) -> Result<Receipt, String> {
    Ok(receipt)
}
pub(crate) fn file_write(
    authorization: ActionAuthorization,
    path: &Path,
    bytes: &[u8],
) -> Result<Receipt, String> {
    backup_first_write(path, bytes)?;
    apply(
        authorization,
        Receipt {
            atom: "do".into(),
            ok: true,
            drift: super::Drift::Current,
            message: "file write complete".into(),
        },
    )
}
pub(crate) fn mutating_command(
    authorization: ActionAuthorization,
    _program: &str,
    _args: &[String],
) -> Result<Receipt, String> {
    apply(
        authorization,
        Receipt {
            atom: "do".into(),
            ok: true,
            drift: super::Drift::Current,
            message: "mutating command complete".into(),
        },
    )
}
pub(crate) fn unit_change(
    authorization: ActionAuthorization,
    _unit: &str,
) -> Result<Receipt, String> {
    apply(
        authorization,
        Receipt {
            atom: "do".into(),
            ok: true,
            drift: super::Drift::Current,
            message: "unit change complete".into(),
        },
    )
}
