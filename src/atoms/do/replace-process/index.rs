//! Forward-only process replacement. This is the sole raw CommandExt::exec owner.
use crate::atoms::r#do::InvocationKey;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub successor: PathBuf,
    pub argv: Vec<String>,
    pub guard_name: String,
    pub guard_value: String,
    pub receipt_path: PathBuf,
    pub rollback_bytes: Option<Vec<u8>>,
    pub rollback_mode: Option<u32>,
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
    let successor_preimage = crate::atoms::ask::replace_process::observe(&p.successor)?;
    let canonical = successor_preimage.canonical.clone();
    let parent = p
        .receipt_path
        .parent()
        .ok_or("replace-process-receipt-parent")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let receipt = Receipt {
        schema: "harmonia.replace-process.v1".into(),
        successor: p.successor.display().to_string(),
        successor_canonical: canonical.display().to_string(),
        successor_dev: successor_preimage.dev,
        successor_ino: successor_preimage.ino,
        argv: p.argv.clone(),
        guard_name: p.guard_name.clone(),
        guard_value: p.guard_value.clone(),
        receipt_path: p.receipt_path.display().to_string(),
        synced: true,
        proof,
    };
    let bytes = crate::atoms::attest::replace_process::serialize_receipt(&receipt)?;
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
pub(crate) fn replace(p: &Plan, invocation: &InvocationKey) -> Result<(), String> {
    replace_with_exec(p, invocation, || {
        let mut command = Command::new(&p.successor);
        command.args(&p.argv);
        let error = std::os::unix::process::CommandExt::exec(&mut command);
        Err(format!("replace-process-exec-failed: {error}"))
    })
}

pub(crate) fn replace_with_exec(
    p: &Plan,
    _invocation: &InvocationKey,
    exec: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    if let Err(error) = write_receipt(p, false) {
        return match rollback_installed(p) {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(format!(
                "{error}; replace-process-rollback-failed: {rollback_error}"
            )),
        };
    }
    std::env::set_var(&p.guard_name, &p.guard_value);
    let result = exec();
    std::env::remove_var(&p.guard_name);
    if let Err(error) = result {
        if let Err(rollback_error) = rollback_installed(p) {
            return Err(format!(
                "{error}; replace-process-rollback-failed: {rollback_error}"
            ));
        }
        return Err(error);
    }
    std::env::remove_var(&p.guard_name);
    Ok(())
}

pub(crate) fn rollback_installed(p: &Plan) -> Result<(), String> {
    if let Some(bytes) = &p.rollback_bytes {
        let parent = p
            .successor
            .parent()
            .ok_or("replace-process-rollback-parent")?;
        let temp = parent.join(format!(".harmonia-rollback-{}.tmp", std::process::id()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)
                .map_err(|e| e.to_string())?;
            file.write_all(bytes).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            #[cfg(unix)]
            if let Some(mode) = p.rollback_mode {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&temp, fs::Permissions::from_mode(mode))
                    .map_err(|e| e.to_string())?;
            }
            fs::rename(&temp, &p.successor).map_err(|e| e.to_string())?;
            OpenOptions::new()
                .read(true)
                .open(parent)
                .map_err(|e| e.to_string())?
                .sync_all()
                .map_err(|e| e.to_string())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    } else {
        match fs::remove_file(&p.successor) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("replace-process-rollback-remove-failed: {error}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{replace, Plan};
    use std::fs;

    #[test]
    fn failed_exec_restores_old_bytes_and_clears_reexec_guard() {
        let root = tempfile::tempdir().unwrap();
        let installed = root.path().join("harmonia");
        let receipts = root.path().join("receipts/replace.json");
        let old = b"old installed engine".to_vec();
        fs::write(&installed, b"not an executable").unwrap();
        let guard = format!("HARMONIA_TEST_REPLACE_GUARD_{}", std::process::id());
        std::env::remove_var(&guard);
        let plan = Plan {
            successor: installed.clone(),
            argv: vec!["test".into()],
            guard_name: guard.clone(),
            guard_value: "1".into(),
            receipt_path: receipts,
            rollback_bytes: Some(old.clone()),
            rollback_mode: Some(0o755),
        };
        let error = replace(&plan, &crate::atoms::r#do::InvocationKey::for_apply()).unwrap_err();
        assert!(error.contains("replace-process-exec-failed"));
        assert_eq!(fs::read(installed).unwrap(), old);
        assert!(std::env::var_os(guard).is_none());
    }
}
