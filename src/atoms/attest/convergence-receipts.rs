use crate::*;
use serde_json::json;
use std::path::{Path, PathBuf};

pub(crate) const HOME_CONSOLE_UPDATE_RECEIPT_LATEST: &str =
    "/var/lib/harmonia/receipts/homeconsole-update-latest";
pub(crate) const HOME_SERVER_UPDATE_RECEIPT_LATEST: &str =
    "/var/lib/harmonia/receipts/homeserver-update-latest";
pub(crate) const TV_UPDATE_RECEIPT_LATEST: &str = "/var/lib/harmonia/receipts/tv-update-latest";

pub(crate) fn homeconsole_update_receipt_latest() -> PathBuf {
    PathBuf::from(HOME_CONSOLE_UPDATE_RECEIPT_LATEST)
}
pub(crate) fn homeserver_update_receipt_latest() -> PathBuf {
    PathBuf::from(HOME_SERVER_UPDATE_RECEIPT_LATEST)
}
pub(crate) fn tv_update_receipt_latest() -> PathBuf {
    PathBuf::from(TV_UPDATE_RECEIPT_LATEST)
}

pub(crate) fn latest_receipt_stem(path: &Path, fallback_stem: &str) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    if name == "latest" {
        return Some(fallback_stem.to_string());
    }
    name.strip_suffix("-latest").map(|stem| {
        if stem.is_empty() {
            fallback_stem.to_string()
        } else {
            stem.to_string()
        }
    })
}

pub(crate) struct ReceiptParentLock {
    _directory: std::fs::File,
}

pub(crate) fn lock_receipt_parent_exclusive(
    latest_path: &Path,
    error_prefix: &str,
) -> Result<ReceiptParentLock, String> {
    use std::os::fd::AsRawFd;
    let parent = latest_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| format!("{error_prefix}-parentless-path {}", latest_path.display()))?;
    let (parent, _) = validated_receipt_root(parent, error_prefix)?;
    let directory = std::fs::File::open(&parent).map_err(|error| {
        format!("{error_prefix}-parent-open-failed {}: {error}", parent.display())
    })?;
    let result = unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX) };
    if result != 0 {
        return Err(format!(
            "{error_prefix}-parent-lock-failed {}: {}",
            parent.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(ReceiptParentLock { _directory: directory })
}

fn validated_receipt_root(root: &Path, error_prefix: &str) -> Result<(PathBuf, u64), String> {
    if !root.is_absolute() {
        return Err(format!("{error_prefix}-root-not-absolute {}", root.display()));
    }
    let mut component_path = PathBuf::from("/");
    for component in root.components() {
        match component {
            std::path::Component::RootDir => continue,
            std::path::Component::Normal(component) => component_path.push(component),
            _ => return Err(format!("{error_prefix}-canonical-root-invalid")),
        }
        let metadata = std::fs::symlink_metadata(&component_path).map_err(|error| {
            format!(
                "{error_prefix}-root-observe-failed {}: {error}",
                component_path.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(format!(
                "{error_prefix}-root-component-unsafe {}",
                component_path.display()
            ));
        }
    }
    let resolved = std::fs::canonicalize(root).map_err(|error| {
        format!(
            "{error_prefix}-root-resolve-failed {}: {error}",
            root.display()
        )
    })?;
    if resolved != root {
        return Err(format!(
            "{error_prefix}-root-mismatch expected={} got={}",
            root.display(),
            resolved.display()
        ));
    }
    let metadata = std::fs::symlink_metadata(root).map_err(|error| {
        format!(
            "{error_prefix}-root-observe-failed {}: {error}",
            root.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok((root.to_path_buf(), metadata.dev()))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(format!("{error_prefix}-same-device-check-unsupported"))
    }
}

fn process_start_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.rfind(')')?;
    stat[close + 1..]
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

pub(crate) fn current_process_start_ticks() -> Option<u64> {
    process_start_ticks(std::process::id())
}

pub(crate) fn read_regular_json(path: &Path) -> Result<Option<serde_json::Value>, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("receipt-marker-observe-failed {}: {error}", path.display())),
    };
    if !metadata.file_type().is_file() {
        return Err(format!("receipt-marker-not-regular {}", path.display()));
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("receipt-marker-open-failed {}: {error}", path.display()))?;
    use std::os::unix::fs::MetadataExt;
    let opened = file
        .metadata()
        .map_err(|error| format!("receipt-marker-fstat-failed {}: {error}", path.display()))?;
    if !opened.file_type().is_file()
        || opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
    {
        return Err(format!("receipt-marker-changed-during-observation {}", path.display()));
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes)
        .map_err(|error| format!("receipt-marker-read-failed {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| format!("receipt-marker-parse-failed {}: {error}", path.display()))
}

/// Store early refusals without creating a parent or a run directory.
pub(crate) fn write_fixed_refusal_receipt(
    receipt_dir: &Path,
    fallback_stem: &str,
    receipt: &serde_json::Value,
) -> Result<(), String> {
    let parent = receipt_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| "receipt-refusal-parentless-path".to_string())?;
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err(format!("receipt-refusal-parent-not-directory {}", parent.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("receipt-refusal-parent-missing {}", parent.display()))
        }
        Err(error) => {
            return Err(format!("receipt-refusal-parent-observe-failed {}: {error}", parent.display()))
        }
    }
    let run_id = crate::receipts::run_id_from_stamp();
    let recorded_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0);
    let mut stamped = receipt.clone();
    let object = stamped
        .as_object_mut()
        .ok_or_else(|| "receipt-refusal-not-object".to_string())?;
    object.insert("recorded_at".to_string(), json!(recorded_at));
    object.insert("run_id".to_string(), json!(run_id));
    let run_identity = json!({
        "run_id": run_id,
        "profile_id": object.get("profile_id").cloned().unwrap_or(serde_json::Value::Null),
        "identity": object.get("identity").cloned().unwrap_or(serde_json::Value::Null),
        "identity_source": object.get("identity_source").cloned().unwrap_or(serde_json::Value::Null),
    });
    object.insert("run_identity".to_string(), run_identity);
    let _parent_lock = lock_receipt_parent_exclusive(receipt_dir, "receipt-refusal")?;
    let directory = materialize_latest_receipt_dir(receipt_dir, &run_id, fallback_stem, "receipt-refusal")?;
    let destination = directory.join("run.json");
    crate::atoms::attest::write_json_atomic(&destination, &stamped)
}

/// The caller holds the receipt-parent lock. Only a legacy latest alias is
/// unlinked; its target and all existing real-directory contents are untouched.
pub(crate) fn materialize_latest_receipt_dir(
    receipt_dir: &Path,
    _run_id: &str,
    fallback_stem: &str,
    error_prefix: &str,
) -> Result<PathBuf, String> {
    match std::fs::symlink_metadata(receipt_dir) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            if latest_receipt_stem(receipt_dir, fallback_stem).is_none() {
                return Err(format!("{error_prefix}-directory-is-symlink {}", receipt_dir.display()));
            }
            unlink_latest_alias(receipt_dir)?;
        }
        Ok(metadata) if metadata.file_type().is_dir() => return Ok(receipt_dir.to_path_buf()),
        Ok(_) => return Err(format!("{error_prefix}-directory-occupied {}", receipt_dir.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("{error_prefix}-directory-observe-failed: {error}")),
    }
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
    let parent = receipt_dir.parent().unwrap_or_else(|| Path::new("."));
    std::fs::File::open(parent).and_then(|directory| directory.sync_all())
        .map_err(|error| format!("{error_prefix}-parent-sync-failed: {error}"))?;
    Ok(receipt_dir.to_path_buf())
}

fn unlink_latest_alias(path: &Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "receipt-latest-alias-name-invalid".to_string())?;
    // unlink(2) removes the alias itself and never follows its old run target.
    if unsafe { libc::unlink(name.as_ptr()) } != 0 {
        return Err(format!("receipt-latest-alias-unlink-failed {}: {}",
            path.display(), std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Direct receipt writers share the same one-time canonical alias migration.
/// Ordinary artifact paths and symlinks outside this receipt root are not touched.
pub(crate) fn migrate_latest_receipt_ancestor(path: &Path) -> Result<(), String> {
    let root = Path::new("/var/lib/harmonia/receipts");
    let Ok(relative) = path.strip_prefix(root) else { return Ok(()); };
    let Some(std::path::Component::Normal(name)) = relative.components().next() else { return Ok(()); };
    let latest = root.join(name);
    if latest_receipt_stem(&latest, "update").is_none() { return Ok(()); }
    if std::fs::symlink_metadata(&latest).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        let _parent_lock = lock_receipt_parent_exclusive(&latest, "receipt-alias-migration")?;
        materialize_latest_receipt_dir(&latest, "", "update", "receipt-alias-migration")?;
    }
    Ok(())
}

/// Serialize complete presses sharing a fixed receipt directory without a
/// lockfile, per-run directory, or a lock held over unrelated receipt families.
pub(crate) fn lock_receipt_directory(path: &Path) -> Result<ReceiptParentLock, String> {
    use std::os::fd::AsRawFd;
    let directory = std::fs::File::open(path)
        .map_err(|error| format!("receipt-directory-lock-open-failed: {error}"))?;
    if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(format!("receipt-directory-lock-failed: {}", std::io::Error::last_os_error()));
    }
    Ok(ReceiptParentLock { _directory: directory })
}

pub(crate) fn validate_receipt_directory_root(root: &Path) -> Result<PathBuf, String> {
    validated_receipt_root(root, "receipt-directory").map(|(root, _)| root)
}

pub(crate) fn materialize_tv_receipt_dir(
    receipt_dir: &Path,
    run_id: &str,
) -> Result<PathBuf, String> {
    materialize_latest_receipt_dir(receipt_dir, run_id, "tv-update", "tv-update-latest")
}
pub(crate) fn materialize_homeconsole_receipt_dir(
    receipt_dir: &Path,
    run_id: &str,
) -> Result<PathBuf, String> {
    materialize_latest_receipt_dir(
        receipt_dir,
        run_id,
        "homeconsole-update",
        "homeconsole-update-latest",
    )
}
pub(crate) fn materialize_homeserver_receipt_dir(
    receipt_dir: &Path,
    run_id: &str,
) -> Result<PathBuf, String> {
    materialize_latest_receipt_dir(
        receipt_dir,
        run_id,
        "homeserver-update",
        "homeserver-update-latest",
    )
}
pub(crate) fn write_convergence_skipped_receipt(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
    reason: &str,
    lock_path: &Path,
    requested_receipt_dir: &Path,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join("convergence-skipped.json"),
        &json!({
            "schema": "harmonia.convergence.skipped.v1",
            "ok": true,
            "changed": false,
            "mutation": apply,
            "reason": reason,
            "profile_id": profile.id,
            "identity": profile.identity,
            "lock_path": lock_path,
            "requested_receipt_dir": requested_receipt_dir,
            "receipt_dir": receipt_dir,
            "suite_ok": true,
        }),
    )?;
    let mut events = crate::receipts::EventSink;
    event(
        &mut events,
        "convergence-skipped",
        true,
        &format!("reason={reason}"),
    )
}
pub(crate) fn emit_convergence_skipped_stdout(receipt_dir: &Path, reason: &str, profile_id: &str) {
    println!("schema=harmonia.convergence.skipped.v1");
    hyalos::forward_receipt(
        "schema=harmonia.convergence.skipped.v1",
        &format!(
            "schema=harmonia.convergence.skipped.v1 ok=true reason={reason}"
        ),
        Some(serde_json::json!({
            "schema": "harmonia.convergence.skipped.v1",
            "ok": true,
            "changed": false,
            "reason": reason,
            "profile_id": profile_id,
            "first_missing_signal": reason,
        })),
        Some(true),
        None,
    );
    println!("ok=true");
    println!("changed=false");
    println!("profile_id={profile_id}");
    println!("reason={reason}");
    println!("receipt_dir={}", receipt_dir.display());
}
