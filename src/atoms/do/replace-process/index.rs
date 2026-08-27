//! Forward-only process replacement. This is the sole raw CommandExt::exec owner.
use crate::atoms::r#do::InvocationKey;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::Command;
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub successor: PathBuf,
    pub argv: Vec<String>,
    pub guard_name: String,
    pub guard_value: String,
    pub receipt_path: PathBuf,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Receipt {
    pub schema: String,
    pub successor: String,
    pub successor_canonical: String,
    pub successor_dev: u64,
    pub successor_ino: u64,
    pub argv: Vec<String>,
    pub guard_name: String,
    pub guard_value: String,
    pub receipt_path: String,
    pub synced: bool,
    pub proof: bool,
}
fn validate(p: &Plan) -> Result<(), String> {
    if p.successor.as_os_str().is_empty() {
        return Err("replace-process-successor-missing".into());
    };
    if p.argv.is_empty() {
        return Err("replace-process-argv-missing".into());
    };
    if p.guard_name.is_empty() || p.guard_value.is_empty() {
        return Err("replace-process-guard-missing".into());
    };
    if p.receipt_path.as_os_str().is_empty() {
        return Err("replace-process-receipt-missing".into());
    };
    if std::env::var_os(&p.guard_name).is_some() {
        return Err("replace-process-reentry-refused".into());
    };
    Ok(())
}
fn write_receipt(p: &Plan, proof: bool) -> Result<Receipt, String> {
    validate(p)?;
    let observed = crate::atoms::ask::replace_process::observe(&p.successor)?;
    if observed.kind != crate::atoms::ask::PathKind::RegularFile {
        return Err("replace-process-successor-not-regular-file".into());
    }
    let parent = p
        .receipt_path
        .parent()
        .ok_or("replace-process-receipt-parent")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let receipt = Receipt {
        schema: "harmonia.replace-process.v1".into(),
        successor: p.successor.display().to_string(),
        successor_canonical: observed.canonical.display().to_string(),
        successor_dev: observed.dev,
        successor_ino: observed.ino,
        argv: p.argv.clone(),
        guard_name: p.guard_name.clone(),
        guard_value: p.guard_value.clone(),
        receipt_path: p.receipt_path.display().to_string(),
        synced: true,
        proof,
    };
    let bytes = serde_json::to_vec(&receipt).map_err(|e| e.to_string())?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("replace-process-temp-time: {e}"))?
        .as_nanos();
    let temp = parent.join(format!(".receipt-{}-{}.tmp", std::process::id(), timestamp));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        fs::rename(&temp, &p.receipt_path).map_err(|e| e.to_string())?;
        OpenOptions::new()
            .read(true)
            .open(parent)
            .map_err(|e| e.to_string())?
            .sync_all()
            .map_err(|e| e.to_string())?;
        let persisted = fs::read(&p.receipt_path).map_err(|e| e.to_string())?;
        if persisted != bytes {
            return Err("replace-process-receipt-bytes-changed".into());
        }
        serde_json::from_slice(&persisted)
            .map_err(|e| format!("replace-process-receipt-parse: {e}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

pub(crate) fn compatibility_exec(
    _program: &std::path::Path,
    _args: &[String],
    _guard_name: &str,
    _guard_value: &str,
    invocation: Option<&InvocationKey>,
) -> Result<(), String> {
    let _ = invocation.ok_or("replace-process-explicit-invocation-required")?;
    Err("replace-process-durable-receipt-path-required".into())
}

pub(crate) fn proof(p: &Plan, _i: &InvocationKey) -> Result<Receipt, String> {
    write_receipt(p, true)
}
pub(crate) fn replace(p: &Plan, _i: &InvocationKey) -> Result<(), String> {
    let _ = write_receipt(p, false)?;
    std::env::set_var(&p.guard_name, &p.guard_value);
    let mut c = Command::new(&p.successor);
    c.args(&p.argv);
    let e = std::os::unix::process::CommandExt::exec(&mut c);
    Err(format!("replace-process-exec-failed: {e}"))
}
