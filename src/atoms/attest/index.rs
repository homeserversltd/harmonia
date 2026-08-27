//! One-call receipt custody: redact, serialize locally, then forward the same redacted value.
#![allow(dead_code)]
#[path = "build_crate.rs"]
pub(crate) mod build_crate;
#[path = "build_venv.rs"]
pub(crate) mod build_venv;
#[path = "check_health.rs"]
pub(crate) mod check_health;
#[path = "convergence-receipts.rs"]
pub(crate) mod convergence_receipts;
#[path = "hyalos.rs"]
pub(crate) mod hyalos;
#[path = "install_package.rs"]
pub(crate) mod install_package;
#[path = "aur_package.rs"]
pub(crate) mod aur_package;
#[path = "set_clock.rs"]
pub(crate) mod set_clock;
use super::Receipt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static JSON_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static PROPOSAL_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct StalePreimage {
    path: std::path::PathBuf,
    bytes: Vec<u8>,
    mode: u32,
    uid: u32,
    gid: u32,
}


/// Attestation-owned no-follow read handle for source observation.
#[cfg(unix)]
pub(crate) fn open_nofollow_read(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| error.to_string())
}

/// Test fixture permission helper owned by the attestation filesystem seam.
pub(crate) fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        return fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| error.to_string());
    }
    #[cfg(not(unix))]
    { let _ = (path, mode); Ok(()) }
}

pub(crate) fn update_set_receipt(
    dir: &Path,
    face: &str,
    verdict: &str,
    failed: Option<&str>,
    failed_step: Option<&str>,
) -> Result<(), String> {
    let ms = ["caduceus", "agathodaimon", face].into_iter().map(|m| serde_json::json!({"member":m,"status":if verdict=="ok"{"ok"}else if failed==Some(m){"failed"}else{"rolled-back"}})).collect::<Vec<_>>();
    let mut value = serde_json::json!({"schema":"harmonia.update-set.v1","set_name":"appliance-syzygy","gui":face,"set_verdict":verdict,"members":ms});
    if let Some(step) = failed_step {
        value["failed_step"] = serde_json::json!(step);
    }
    write_json_atomic(&dir.join("update-set.json"), &value)
}

pub(crate) fn write_transaction_receipt(
    dir: &Path,
    receipt: &crate::atoms::r#do::transaction::TransactionReceipt,
    failed_step: Option<&str>,
) -> Result<(), String> {
    let mut value = crate::atoms::r#do::transaction::project_update_set_v1(receipt);
    if let Some(step) = failed_step {
        value["failed_step"] = serde_json::json!(step);
    }
    write_json_atomic(&dir.join("update-set.json"), &value)
}

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

#[derive(Debug, Clone, Copy)]
pub(crate) enum ProposalOwnerPolicy {
    CurrentProcess,
}

#[cfg(unix)]
fn proposal_owner(policy: ProposalOwnerPolicy) -> (u32, u32) {
    match policy {
        ProposalOwnerPolicy::CurrentProcess => {
            (unsafe { libc::geteuid() }, unsafe { libc::getegid() })
        }
    }
}

#[cfg(not(unix))]
fn proposal_owner(_policy: ProposalOwnerPolicy) -> (u32, u32) {
    (0, 0)
}

fn proposal_target_kind(path: &Path) -> Result<Option<std::fs::Metadata>, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "proposal-projection-observe-failed {}: {error}",
            path.display()
        )),
    }
}

fn verify_proposal_owner(path: &Path, policy: ProposalOwnerPolicy) -> Result<(), String> {
    let metadata = fs::metadata(path).map_err(|error| {
        format!(
            "proposal-projection-owner-observe-failed {}: {error}",
            path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let (uid, gid) = proposal_owner(policy);
        if (metadata.uid(), metadata.gid()) != (uid, gid) {
            return Err(format!(
                "proposal-projection-owner-mismatch {} expected_uid={} expected_gid={} actual_uid={} actual_gid={}",
                path.display(),
                uid,
                gid,
                metadata.uid(),
                metadata.gid()
            ));
        }
    }
    Ok(())
}

fn capture_stale_preimage(
    path: &Path,
    policy: ProposalOwnerPolicy,
) -> Result<StalePreimage, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.file_type().is_file() {
        return Err(format!("proposal-projection-collision {}", path.display()));
    }
    verify_proposal_owner(path, policy)?;
    if metadata.permissions().mode() & 0o7777 != 0o644 {
        return Err(format!(
            "proposal-projection-mode-mismatch {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        return Ok(StalePreimage {
            path: path.to_path_buf(),
            bytes: fs::read(path).map_err(|e| e.to_string())?,
            mode: metadata.mode() & 0o7777,
            uid: metadata.uid(),
            gid: metadata.gid(),
        });
    }
    #[cfg(not(unix))]
    Ok(StalePreimage {
        path: path.to_path_buf(),
        bytes: fs::read(path).map_err(|e| e.to_string())?,
        mode: 0o644,
        uid: 0,
        gid: 0,
    })
}

fn write_proposal_bytes(
    path: &Path,
    bytes: &[u8],
    policy: ProposalOwnerPolicy,
) -> Result<bool, String> {
    let observed = proposal_target_kind(path)?;
    if let Some(metadata) = &observed {
        if !metadata.file_type().is_file() {
            return Err(format!("proposal-projection-collision {}", path.display()));
        }
        verify_proposal_owner(path, policy)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o7777 != 0o644 {
                return Err(format!(
                    "proposal-projection-mode-mismatch {}",
                    path.display()
                ));
            }
        }
        if fs::read(path).map_err(|error| error.to_string())? == bytes {
            return Ok(false);
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("proposal-projection-parent-missing {}", path.display()))?;
    prepare_receipt_parent(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("proposal-projection-name-invalid {}", path.display()))?;
    let sequence = PROPOSAL_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(
        ".{name}.harmonia-attest-projection-{}-{sequence}",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|error| {
            format!(
                "proposal-projection-temp-create-failed {}: {error}",
                temp.display()
            )
        })?;
    let result = (|| -> Result<(), String> {
        file.write_all(bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        drop(file);
        #[cfg(unix)]
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o644))
            .map_err(|error| error.to_string())?;
        fs::rename(&temp, path).map_err(|error| error.to_string())?;
        verify_proposal_owner(path, policy)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map(|()| true)
}

pub(crate) fn refresh_proposal_projection(
    feed_path: &Path,
    feed_bytes: &[u8],
    records: &[(String, Vec<u8>)],
    policy: ProposalOwnerPolicy,
) -> Result<usize, String> {
    let parent = feed_path
        .parent()
        .ok_or_else(|| format!("proposal-projection-parent-missing {}", feed_path.display()))?;
    prepare_receipt_parent(parent)?;
    let proposal_root = parent.join("proposals");
    if let Some(metadata) = proposal_target_kind(&proposal_root)? {
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(format!(
                "proposal-projection-collision {}",
                proposal_root.display()
            ));
        }
    }
    if let Some(metadata) = proposal_target_kind(feed_path)? {
        if !metadata.file_type().is_file() {
            return Err(format!(
                "proposal-projection-collision {}",
                feed_path.display()
            ));
        }
    }
    prepare_receipt_parent(&proposal_root)?;
    let live = records
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut stale = Vec::new();
    for path in fs::read_dir(&proposal_root)
        .map_err(|error| error.to_string())?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?
    {
        let Some(metadata) = proposal_target_kind(&path)? else {
            continue;
        };
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        if name.starts_with("config-proposal-") && name.ends_with(".json") && !live.contains(name) {
            if !metadata.file_type().is_file() {
                return Err(format!("proposal-projection-collision {}", path.display()));
            }
            verify_proposal_owner(&path, policy)?;
            #[cfg(unix)]
            if metadata.permissions().mode() & 0o7777 != 0o644 {
                return Err(format!(
                    "proposal-projection-mode-mismatch {}",
                    path.display()
                ));
            }
            stale.push(capture_stale_preimage(&path, policy)?);
        }
    }
    let mut writes = write_proposal_bytes(feed_path, feed_bytes, policy)? as usize;
    for (name, bytes) in records {
        writes += write_proposal_bytes(&proposal_root.join(name), bytes, policy)? as usize;
    }
    let mut removed: Vec<&StalePreimage> = Vec::new();
    for preimage in &stale {
        if let Err(error) = fs::remove_file(&preimage.path) {
            let mut message = format!(
                "proposal-stale-remove-failed {}: {error}",
                preimage.path.display()
            );
            for prior in removed.iter().rev() {
                if let Err(restore) = restore_stale_preimage(prior) {
                    message.push_str(&format!(
                        "; proposal-stale-restore-failed {}: {restore}",
                        prior.path.display()
                    ));
                }
            }
            return Err(message);
        }
        removed.push(preimage);
        writes += 1;
    }
    Ok(writes)
}

#[cfg(unix)]
fn restore_stale_preimage(preimage: &StalePreimage) -> Result<(), String> {
    use std::os::unix::fs::{chown, PermissionsExt};
    let parent = preimage
        .path
        .parent()
        .ok_or_else(|| "proposal-stale-restore-parent-missing".to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&preimage.path)
        .map_err(|e| e.to_string())?;
    file.write_all(&preimage.bytes).map_err(|e| e.to_string())?;
    file.set_permissions(fs::Permissions::from_mode(preimage.mode))
        .map_err(|e| e.to_string())?;
    chown(&preimage.path, Some(preimage.uid), Some(preimage.gid)).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    File::open(parent)
        .and_then(|d| d.sync_all())
        .map_err(|e| e.to_string())
}

/// Atomically converge a receipt file to exact bytes, without touching an equal file.
pub(crate) fn write_receipt_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<bool, String> {
    let target = match fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(format!(
                "receipt-observe-failed {}: {error}",
                path.display()
            ))
        }
    };
    let strict_receipt = !is_backup_path(path);
    if let Some(metadata) = &target {
        if !metadata.file_type().is_file() {
            return Err(format!("receipt-collision {}", path.display()));
        }
        if strict_receipt {
            verify_receipt_owner(path)?;
            #[cfg(unix)]
            if metadata.permissions().mode() & 0o7777 != 0o644 {
                return Err(format!("receipt-mode-mismatch {}", path.display()));
            }
        }
        if fs::read(path)
            .map_err(|error| format!("receipt-read-failed {}: {error}", path.display()))?
            == bytes
        {
            return Ok(false);
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("receipt-parent-missing {}", path.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("receipt-name-invalid {}", path.display()))?;
    prepare_receipt_parent(parent)?;
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
        file.write_all(bytes)
            .map_err(|error| format!("receipt-temp-write-failed {}: {error}", temp.display()))?;
        file.sync_all()
            .map_err(|error| format!("receipt-temp-sync-failed {}: {error}", temp.display()))?;
        drop(file);
        if strict_receipt {
            #[cfg(unix)]
            fs::set_permissions(&temp, fs::Permissions::from_mode(0o644))
                .map_err(|error| format!("receipt-temp-mode-failed {}: {error}", temp.display()))?;
            verify_receipt_owner(&temp)?;
        }
        fs::rename(&temp, path).map_err(|error| {
            format!(
                "receipt-atomic-promote-failed {} -> {}: {error}",
                temp.display(),
                path.display()
            )
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("receipt-parent-sync-failed {}: {error}", parent.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map(|()| true)
}

pub(crate) fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    write_receipt_bytes_atomic(path, bytes).map(|_| ())
}

pub(crate) fn write_json_atomic(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("receipt-serialize-failed {}: {error}", path.display()))?;
    bytes.push(b'\n');
    write_receipt_bytes_atomic(path, &bytes).map(|_| ())
}

fn verify_receipt_owner(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("receipt-owner-observe-failed {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let expected = proposal_owner(ProposalOwnerPolicy::CurrentProcess);
        if (metadata.uid(), metadata.gid()) != expected {
            return Err(format!("receipt-owner-mismatch {} expected_uid={} expected_gid={} actual_uid={} actual_gid={}", path.display(), expected.0, expected.1, metadata.uid(), metadata.gid()));
        }
    }
    Ok(())
}

pub(crate) fn prepare_receipt_parent(parent: &Path) -> Result<(), String> {
    fs::create_dir_all(parent)
        .map_err(|error| format!("receipt-parent-create-failed {}: {error}", parent.display()))?;
    make_receipt_tree_readable(parent)
}

pub(crate) fn create_receipt_file(path: &Path) -> Result<File, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("receipt-parent-missing {}", path.display()))?;
    prepare_receipt_parent(parent)?;
    let file = File::create(path)
        .map_err(|error| format!("receipt-file-create-failed {}: {error}", path.display()))?;
    set_receipt_file_mode(path)?;
    Ok(file)
}

#[cfg(unix)]
fn set_receipt_file_mode(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if !is_backup_path(path) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))
            .map_err(|error| format!("receipt-mode-failed {}: {error}", path.display()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_receipt_file_mode(_path: &Path) -> Result<(), String> {
    Ok(())
}

pub(crate) fn append_jsonl_to<W: Write>(
    writer: &mut W,
    value: &serde_json::Value,
) -> Result<(), String> {
    serde_json::to_writer(&mut *writer, value)
        .map_err(|error| format!("receipt-jsonl-serialize-failed: {error}"))?;
    writeln!(writer).map_err(|error| format!("receipt-jsonl-append-failed: {error}"))
}

pub(crate) fn remove_artifact(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("attest-artifact-remove-failed {}: {error}", path.display())),
    }
}

pub(crate) fn copy_artifact(source: &Path, target: &Path) -> Result<(), String> {
    let parent = target.parent().ok_or_else(|| format!("artifact-copy-parent-missing {}", target.display()))?;
    prepare_receipt_parent(parent)?;
    fs::copy(source, target).map_err(|error| format!("artifact-copy-failed {} -> {}: {error}", source.display(), target.display()))?;
    Ok(())
}

/// Open a named fresh event stream through the Attest owner (create/truncate semantics).
pub(crate) fn open_event_stream(path: &Path) -> Result<File, String> {
    let parent = path.parent().ok_or_else(|| format!("event-stream-parent-missing {}", path.display()))?;
    prepare_receipt_parent(parent)?;
    File::create(path).map_err(|error| format!("event-stream-open-failed {}: {error}", path.display()))
}

pub(crate) fn append_appliance_log(path: &Path, receipt: &Receipt) -> Result<(), String> {
    let value = serde_json::to_value(receipt).map_err(|e| format!("attest-serialize: {e}"))?;
    append_jsonl(path, &value).map_err(|e| format!("attest-append: {e}"))
}

pub(crate) fn append_jsonl(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("receipt-parent-missing {}", path.display()))?;
    prepare_receipt_parent(parent)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("receipt-jsonl-open-failed {}: {error}", path.display()))?;
    set_receipt_file_mode(path)?;
    append_jsonl_to(&mut file, value)
}

pub(crate) fn promote_current_link(
    latest_path: &Path,
    target: &Path,
    error_prefix: &str,
    reject_directory: bool,
) -> Result<(), String> {
    if latest_path.exists() {
        if latest_path.is_dir() && !latest_path.is_symlink() {
            if reject_directory {
                return Err(format!(
                    "{error_prefix}-still-directory {}",
                    latest_path.display()
                ));
            }
        } else {
            fs::remove_file(latest_path).map_err(|e| e.to_string())?;
        }
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, latest_path).map_err(|e| {
        format!(
            "{error_prefix}-symlink-failed {} -> {}: {e}",
            target.display(),
            latest_path.display()
        )
    })?;
    #[cfg(not(unix))]
    return Err(format!("{error_prefix}-symlink-unsupported"));
    Ok(())
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
