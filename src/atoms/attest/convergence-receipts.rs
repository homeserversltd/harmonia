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

pub(crate) struct ReceiptDirectory {
    pub(crate) path: PathBuf,
    pub(crate) latest: Option<PathBuf>,
    pub(crate) stem: String,
}

fn receipt_sibling_path(path: &Path, name: &str) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(name),
        _ => PathBuf::from(name),
    }
}

fn latest_receipt_stem(path: &Path, fallback_stem: &str) -> Option<String> {
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

/// Allocate an exclusive per-run sibling for a latest receipt alias. Ordinary
/// receipt paths retain their historical direct-write destination.
pub(crate) fn allocate_receipt_directory(
    receipt_dir: &Path,
    run_id: &str,
    fallback_stem: &str,
) -> Result<ReceiptDirectory, String> {
    let Some(stem) = latest_receipt_stem(receipt_dir, fallback_stem) else {
        return Ok(ReceiptDirectory {
            path: receipt_dir.to_path_buf(),
            latest: None,
            stem: fallback_stem.to_string(),
        });
    };
    let parent = receipt_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    crate::atoms::attest::prepare_receipt_parent(parent)?;
    let mut collision = 0u64;
    loop {
        let suffix = if collision == 0 {
            String::new()
        } else {
            format!("-{collision}")
        };
        let name = format!("{stem}-{run_id}{suffix}");
        let candidate = receipt_sibling_path(receipt_dir, &name);
        match std::fs::create_dir(&candidate) {
            Ok(()) => {
                crate::atoms::attest::prepare_receipt_parent(&candidate)?;
                return Ok(ReceiptDirectory {
                    path: candidate,
                    latest: Some(receipt_dir.to_path_buf()),
                    stem,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                collision = collision
                    .checked_add(1)
                    .ok_or_else(|| "receipt-run-directory-collision-exhausted".to_string())?;
            }
            Err(error) => {
                return Err(format!(
                    "receipt-run-directory-create-failed {}: {error}",
                    candidate.display()
                ));
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn rename_receipt_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let from = std::ffi::CString::new(from.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let to = std::ffi::CString::new(to.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn rename_receipt_noreplace(_from: &Path, _to: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-clobber rename requires Linux renameat2",
    ))
}

#[cfg(unix)]
fn lock_receipt_parent(latest_path: &Path, error_prefix: &str) -> Result<std::fs::File, String> {
    use std::os::fd::AsRawFd;
    let parent = latest_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = std::fs::File::open(parent).map_err(|error| {
        format!(
            "{error_prefix}-parent-open-failed {}: {error}",
            parent.display()
        )
    })?;
    let result = unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX) };
    if result != 0 {
        return Err(format!(
            "{error_prefix}-parent-lock-failed {}: {}",
            parent.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(directory)
}

fn move_displaced_receipt(
    source: &Path,
    latest_path: &Path,
    stem: &str,
    run_id: &str,
    error_prefix: &str,
) -> Result<PathBuf, String> {
    let mut collision = 0u64;
    loop {
        let suffix = if collision == 0 {
            String::new()
        } else {
            format!("-{collision}")
        };
        let name = format!("{stem}-displaced-{run_id}{suffix}");
        let displaced = receipt_sibling_path(latest_path, &name);
        match rename_receipt_noreplace(source, &displaced) {
            Ok(()) => return Ok(displaced),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                collision = collision
                    .checked_add(1)
                    .ok_or_else(|| format!("{error_prefix}-displaced-name-exhausted"))?;
            }
            Err(error) => {
                return Err(format!(
                    "{error_prefix}-displaced-rename-failed {} -> {}: {error}",
                    source.display(),
                    displaced.display()
                ));
            }
        }
    }
}

/// Atomically publish a latest symlink without deleting non-link occupants.
pub(crate) fn promote_receipt_latest(
    latest_path: &Path,
    target: &Path,
    stem: &str,
    run_id: &str,
    error_prefix: &str,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let _parent_lock = lock_receipt_parent(latest_path, error_prefix)?;
        let latest_name = latest_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                format!(
                    "{error_prefix}-latest-name-invalid {}",
                    latest_path.display()
                )
            })?;
        let run_leaf = target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("run");
        let target_parent = target.parent().unwrap_or_else(|| Path::new(""));
        let latest_parent = latest_path.parent().unwrap_or_else(|| Path::new(""));
        let link_target = if target.is_absolute() {
            target.to_path_buf()
        } else if target_parent == latest_parent {
            target
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| target.to_path_buf())
        } else {
            target.to_path_buf()
        };

        let mut temp_collision = 0u64;
        loop {
            let temp_name = format!(".{latest_name}.harmonia-{run_leaf}-{temp_collision}.tmp");
            let temp = receipt_sibling_path(latest_path, &temp_name);
            match symlink(&link_target, &temp) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    temp_collision = temp_collision
                        .checked_add(1)
                        .ok_or_else(|| format!("{error_prefix}-temporary-link-name-exhausted"))?;
                    continue;
                }
                Err(error) => {
                    return Err(format!(
                        "{error_prefix}-symlink-failed {} -> {}: {error}",
                        link_target.display(),
                        temp.display()
                    ));
                }
            }

            let latest_metadata = match std::fs::symlink_metadata(latest_path) {
                Ok(metadata) => Some(metadata),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => {
                    let _ = std::fs::remove_file(&temp);
                    return Err(format!(
                        "{error_prefix}-latest-observe-failed {}: {error}",
                        latest_path.display()
                    ));
                }
            };

            let Some(latest_metadata) = latest_metadata else {
                match rename_receipt_noreplace(&temp, latest_path) {
                    Ok(()) => return Ok(()),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        let _ = std::fs::remove_file(&temp);
                        continue;
                    }
                    Err(error) => {
                        let _ = std::fs::remove_file(&temp);
                        return Err(format!(
                            "{error_prefix}-symlink-promote-failed {} -> {}: {error}",
                            temp.display(),
                            latest_path.display()
                        ));
                    }
                }
            };

            if latest_metadata.file_type().is_symlink() {
                return std::fs::rename(&temp, latest_path).map_err(|error| {
                    let _ = std::fs::remove_file(&temp);
                    format!(
                        "{error_prefix}-latest-link-replace-failed {} -> {}: {error}",
                        temp.display(),
                        latest_path.display()
                    )
                });
            }

            let displaced = match move_displaced_receipt(
                latest_path,
                latest_path,
                stem,
                run_id,
                error_prefix,
            ) {
                Ok(displaced) => displaced,
                Err(error) => {
                    let _ = std::fs::remove_file(&temp);
                    return Err(error);
                }
            };
            match rename_receipt_noreplace(&temp, latest_path) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    let _ = std::fs::remove_file(&temp);
                    return Err(format!(
                        "{error_prefix}-latest-publish-after-displacement-failed {} -> {} (displaced to {}): {error}",
                        temp.display(),
                        latest_path.display(),
                        displaced.display()
                    ));
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (latest_path, target, stem, run_id);
        Err(format!("{error_prefix}-symlink-unsupported"))
    }
}

pub(crate) fn materialize_latest_receipt_dir(
    receipt_dir: &Path,
    run_id: &str,
    fallback_stem: &str,
    error_prefix: &str,
) -> Result<PathBuf, String> {
    let allocated = allocate_receipt_directory(receipt_dir, run_id, fallback_stem)?;
    if let Some(latest_path) = allocated.latest.as_deref() {
        promote_receipt_latest(
            latest_path,
            &allocated.path,
            &allocated.stem,
            run_id,
            error_prefix,
        )
        .map_err(|error| format!("receipt-latest-promotion-failed: {error}"))?;
    }
    Ok(allocated.path)
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
    let mut events = crate::atoms::attest::create_receipt_file(&receipt_dir.join("events.jsonl"))?;
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
        &format!("schema=harmonia.convergence.skipped.v1 ok={}", true),
        Some(serde_json::json!({"schema": "harmonia.convergence.skipped.v1", "ok": true})),
        Some(true),
            None,
);
    println!("ok=true");
    println!("changed=false");
    println!("profile_id={profile_id}");
    println!("reason={reason}");
    println!("receipt_dir={}", receipt_dir.display());
}
