//! Typed receipt writers for write-file filesystem asks.
use crate::atoms::ask::write_file as ask;
use crate::atoms::{Drift, Receipt};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ManagedFileEntry {
    pub path: String,
    pub target_exists_before: bool,
    pub state: String,
    pub mode: u32,
    pub content_equal_before: bool,
    pub mode_equal_before: bool,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub owner_equal_before: bool,
    pub group_equal_before: bool,
    pub changed: bool,
    pub drift_detected: bool,
    pub written: bool,
    pub observed_state: serde_json::Value,
    pub desired_state: serde_json::Value,
    pub diff_decision: String,
    pub movement: String,
    pub truthful_changed: bool,
}
#[derive(Debug, Clone)]
pub(crate) struct ManagedError {
    pub module: String,
    pub path: String,
    pub apply: bool,
    pub error: String,
}
#[derive(Debug, Clone)]
pub(crate) struct ManagedFile {
    pub module: String,
    pub path: String,
    pub mode: u32,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub owner_equal_before: bool,
    pub group_equal_before: bool,
    pub apply: bool,
    pub target_exists_before: bool,
    pub state: String,
    pub changed: bool,
    pub drift_detected: bool,
    pub written: bool,
    pub desired_content_sha256: String,
    pub desired_uid: Option<u32>,
    pub desired_gid: Option<u32>,
    pub diff_decision: String,
    pub movement: String,
    pub truthful_changed: bool,
    pub first_missing_signal: String,
}
#[derive(Debug, Clone)]
pub(crate) struct ManagedFiles {
    pub schema: String,
    pub module: String,
    pub drift: Vec<String>,
    pub missing_target_birth_debts: Vec<String>,
    pub written: Vec<String>,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub apply: bool,
    pub changed: bool,
    pub entries: Vec<ManagedFileEntry>,
    pub first_missing_signal: String,
}

#[derive(Debug, Clone)]
pub(crate) struct Observation {
    pub(crate) ask: ask::Observation,
    pub(crate) projection: serde_json::Value,
}

#[derive(Debug, Clone)]
pub(crate) struct Outcome {
    pub(crate) ok: bool,
    pub(crate) message: String,
    pub(crate) projection: serde_json::Value,
}

pub(crate) fn attest(
    receipt_dir: &Path,
    file_name: &str,
    observation: &Observation,
    outcome: &Outcome,
) -> Result<(), String> {
    let value = serde_json::json!({"schema":"harmonia.fs.write_file.v1","ok":outcome.ok,"observation":observation.projection,"outcome":outcome.projection});
    crate::atoms::attest::write_json_atomic(&receipt_dir.join(file_name), &value)?;
    log(receipt_dir, outcome.ok, &outcome.message)
}
pub(crate) fn write_managed_error(dir: &Path, path: &Path, r: ManagedError) -> Result<(), String> {
    let v = serde_json::json!({"schema":"harmonia.files.managed_file.v1","ok":false,"module":r.module,"path":r.path,"apply":r.apply,"state":"act-error","error":r.error,"first_missing_signal":"managed-file-act-error"});
    write(dir, path, &v, false, "managed-file")
}
pub(crate) fn observed_state(
    target_exists: bool,
    missing_debt: bool,
    content: bool,
    mode: bool,
    owner: bool,
    group: bool,
) -> serde_json::Value {
    serde_json::json!({"target_exists":target_exists,"state":if missing_debt { "missing-target-birth-debt" } else { "observed" },"content_equal":content,"mode_equal":mode,"owner_equal":owner,"group_equal":group})
}

pub(crate) fn write_managed_file(
    dir: &Path,
    path: &Path,
    r: ManagedFile,
    observed: serde_json::Value,
) -> Result<(), String> {
    let ok = r.state != "missing-target-birth-debt";
    let v = serde_json::json!({"schema":"harmonia.files.managed_file.v1","ok":ok,"module":r.module,"path":r.path,"mode":r.mode,"owner":r.owner,"group":r.group,"owner_equal_before":r.owner_equal_before,"group_equal_before":r.group_equal_before,"apply":r.apply,"target_exists_before":r.target_exists_before,"state":r.state,"changed":r.changed,"drift_detected":r.drift_detected,"written":r.written,"observed_state":observed,"desired_state":{"content_sha256":r.desired_content_sha256,"mode":r.mode,"uid":r.desired_uid,"gid":r.desired_gid},"diff_decision":r.diff_decision,"movement":r.movement,"truthful_changed":r.truthful_changed,"first_missing_signal":r.first_missing_signal});
    write(dir, path, &v, ok, "managed-file")
}
pub(crate) fn write_managed_files(dir: &Path, path: &Path, r: ManagedFiles) -> Result<(), String> {
    let ok = r.missing_target_birth_debts.is_empty() || !r.apply;
    let v = serde_json::json!({"schema":r.schema,"ok":ok,"module":r.module,"drift":r.drift,"missing_target_birth_debts":r.missing_target_birth_debts,"written":r.written,"owner":r.owner,"group":r.group,"apply":r.apply,"changed":r.changed,"entries":r.entries,"first_missing_signal":r.first_missing_signal});
    write(dir, path, &v, ok, "managed-files")
}
fn write(
    dir: &Path,
    path: &Path,
    value: &serde_json::Value,
    ok: bool,
    label: &str,
) -> Result<(), String> {
    crate::atoms::attest::write_json_atomic(path, value)?;
    log(dir, ok, &format!("{label} receipt={}", path.display()))
}
fn log(dir: &Path, ok: bool, message: &str) -> Result<(), String> {
    crate::atoms::attest::attest(
        &dir.join("harmonia-atoms.log"),
        &Receipt {
            atom: "write-file".into(),
            ok,
            drift: Drift::Current,
            message: message.into(),
        },
        &[],
    )
}
