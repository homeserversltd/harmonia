//! Typed receipt writer for the make-dir filesystem ask.
use crate::atoms::ask::make_dir as ask;
use crate::atoms::Receipt;
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone)]
pub(crate) struct Observation {
    pub(crate) ask: ask::Observation,
    pub(crate) projection: Value,
}

#[derive(Debug, Clone)]
pub(crate) struct Outcome {
    pub(crate) ok: bool,
    pub(crate) message: String,
    pub(crate) projection: Value,
}

pub(crate) fn attest(
    receipt_dir: &Path,
    file_name: &str,
    observation: &Observation,
    outcome: &Outcome,
) -> Result<(), String> {
    let value = serde_json::json!({"schema":"harmonia.fs.make_dir.v1","ok":outcome.ok,"observation":observation.projection,"outcome":outcome.projection});
    crate::atoms::attest::write_json_atomic(&receipt_dir.join(file_name), &value)?;
    crate::atoms::attest::attest(
        &receipt_dir.join("harmonia-atoms.log"),
        &Receipt {
            atom: "make-dir".into(),
            ok: outcome.ok,
            drift: crate::atoms::Drift::Current,
            message: outcome.message.clone(),
        },
        &[],
    )
}
