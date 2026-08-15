//! One-call receipt custody: redact, serialize locally, then forward the same redacted value.
#![allow(dead_code)]
#[path = "hyalos.rs"]
pub(crate) mod hyalos;
use super::{append_appliance_log, Receipt};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static JSON_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Persist a JSON receipt through the attest durability membrane.
fn is_backup_path(path: &Path) -> bool {
    path.components().any(|c| c.as_os_str() == "backups")
}

fn make_receipt_tree_readable(path: &Path) -> Result<(), String> {
    let root = Path::new("/var/lib/harmonia/receipts");
    let Ok(relative) = path.strip_prefix(root) else {
        return Ok(());
    };
    if is_backup_path(relative) {
        return Ok(());
    }
    let mut current = root.to_path_buf();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&current, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("receipt-directory-mode-failed {}: {e}", current.display()))?;
        for component in relative.components() {
            current.push(component);
            fs::set_permissions(&current, fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("receipt-directory-mode-failed {}: {e}", current.display()))?;
        }
    }
    Ok(())
}

pub(crate) fn write_json_atomic(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("receipt-parent-missing {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("receipt-parent-create-failed {}: {error}", parent.display()))?;
    make_receipt_tree_readable(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("receipt-name-invalid {}", path.display()))?;
    let sequence = JSON_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(
        ".{name}.harmonia-attest-{}-{sequence}.tmp",
        std::process::id()
    ));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|error| format!("receipt-temp-create-failed {}: {error}", temp.display()))?;
        serde_json::to_writer_pretty(&mut file, value).map_err(|error| {
            format!("receipt-temp-serialize-failed {}: {error}", temp.display())
        })?;
        writeln!(file)
            .map_err(|error| format!("receipt-temp-write-failed {}: {error}", temp.display()))?;
        file.sync_all()
            .map_err(|error| format!("receipt-temp-sync-failed {}: {error}", temp.display()))?;
        drop(file);
        fs::rename(&temp, path).map_err(|error| {
            format!(
                "receipt-atomic-promote-failed {} -> {}: {error}",
                temp.display(),
                path.display()
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if !is_backup_path(path) {
                fs::set_permissions(path, fs::Permissions::from_mode(0o644))
                    .map_err(|error| format!("receipt-mode-failed {}: {error}", path.display()))?;
            }
        }
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("receipt-parent-sync-failed {}: {error}", parent.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

pub(crate) fn redact_secrets(value: &str, secrets: &[String]) -> String {
    secrets.iter().fold(value.to_owned(), |out, secret| {
        if secret.is_empty() {
            out
        } else {
            out.replace(secret, "[REDACTED]")
        }
    })
}
fn redact_receipt(receipt: &Receipt, secrets: &[String]) -> Receipt {
    let mut redacted = receipt.clone();
    let redact = |value: &str| redact_secrets(value, secrets);
    redacted.atom = redact(&redacted.atom);
    redacted.message = redact(&redacted.message);
    redacted.drift = match redacted.drift {
        super::Drift::Current => super::Drift::Current,
        super::Drift::File {
            expected_sha256,
            actual_sha256,
        } => super::Drift::File {
            expected_sha256: redact(&expected_sha256),
            actual_sha256: actual_sha256.as_deref().map(redact),
        },
        super::Drift::Command {
            expected_code,
            actual_code,
        } => super::Drift::Command {
            expected_code,
            actual_code,
        },
        super::Drift::Unit { expected, actual } => super::Drift::Unit {
            expected: redact(&expected),
            actual: redact(&actual),
        },
        super::Drift::Http {
            expected_status,
            actual_status,
        } => super::Drift::Http {
            expected_status,
            actual_status,
        },
    };
    redacted
}
pub(crate) fn attest(
    log: &Path,
    receipt: &Receipt,
    declared_secrets: &[String],
) -> Result<(), String> {
    let redacted = redact_receipt(receipt, declared_secrets);
    append_appliance_log(log, &redacted)?;
    hyalos::forward_receipt(
        "harmonia.atom",
        &redacted.message,
        Some(serde_json::json!({"atom": redacted.atom, "drift": redacted.drift})),
        Some(redacted.ok),
    );
    Ok(())
}
