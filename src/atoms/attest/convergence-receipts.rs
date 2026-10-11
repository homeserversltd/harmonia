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

pub(crate) struct ReceiptParentLock {
    _directory: std::fs::File,
}

pub(crate) fn lock_receipt_parent(
    latest_path: &Path,
    error_prefix: &str,
) -> Result<ReceiptParentLock, String> {
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
    Ok(ReceiptParentLock {
        _directory: directory,
    })
}

pub(crate) fn ensure_latest_receipt_replaceable(
    latest_path: &Path,
    error_prefix: &str,
) -> Result<(), String> {
    match std::fs::symlink_metadata(latest_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(format!(
            "{error_prefix}-latest-nonsymlink-occupied {}",
            latest_path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "{error_prefix}-latest-observe-failed {}: {error}",
            latest_path.display()
        )),
    }
}

/// Publish the current target while the caller owns the receipt-parent flock.
pub(crate) fn promote_receipt_latest_locked(
    latest_path: &Path,
    target: &Path,
    _run_id: &str,
    error_prefix: &str,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        ensure_latest_receipt_replaceable(latest_path, error_prefix)?;
        let latest_name = latest_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("{error_prefix}-latest-name-invalid {}", latest_path.display()))?;
        let run_leaf = target.file_name().and_then(|name| name.to_str()).unwrap_or("run");
        let target_parent = target.parent().unwrap_or_else(|| Path::new(""));
        let latest_parent = latest_path.parent().unwrap_or_else(|| Path::new(""));
        let link_target = if target.is_absolute() {
            target.to_path_buf()
        } else if target_parent == latest_parent {
            target.file_name().map(PathBuf::from).unwrap_or_else(|| target.to_path_buf())
        } else {
            target.to_path_buf()
        };
        let parent = latest_path.parent().unwrap_or_else(|| Path::new("."));
        let mut collision = 0u64;
        loop {
            let temp = receipt_sibling_path(
                latest_path,
                &format!(".{latest_name}.harmonia-{run_leaf}-{collision}.tmp"),
            );
            match symlink(&link_target, &temp) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    collision = collision.checked_add(1).ok_or_else(|| {
                        format!("{error_prefix}-temporary-link-name-exhausted")
                    })?;
                    continue;
                }
                Err(error) => {
                    return Err(format!(
                        "{error_prefix}-symlink-failed {} -> {}: {error}",
                        link_target.display(), temp.display()
                    ));
                }
            }
            let latest_exists = match std::fs::symlink_metadata(latest_path) {
                Ok(metadata) if metadata.file_type().is_symlink() => true,
                Ok(_) => {
                    let _ = std::fs::remove_file(&temp);
                    return Err(format!(
                        "{error_prefix}-latest-nonsymlink-occupied {}",
                        latest_path.display()
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => {
                    let _ = std::fs::remove_file(&temp);
                    return Err(format!(
                        "{error_prefix}-latest-observe-failed {}: {error}",
                        latest_path.display()
                    ));
                }
            };
            let promote = if latest_exists {
                std::fs::rename(&temp, latest_path)
            } else {
                rename_receipt_noreplace(&temp, latest_path)
            };
            match promote {
                Ok(()) => {
                    std::fs::File::open(parent)
                        .and_then(|directory| directory.sync_all())
                        .map_err(|error| format!("{error_prefix}-parent-sync-failed: {error}"))?;
                    return Ok(());
                }
                Err(error) if !latest_exists && error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let _ = std::fs::remove_file(&temp);
                    ensure_latest_receipt_replaceable(latest_path, error_prefix)?;
                    continue;
                }
                Err(error) => {
                    let _ = std::fs::remove_file(&temp);
                    return Err(format!(
                        "{error_prefix}-latest-link-promote-failed {} -> {}: {error}",
                        temp.display(), latest_path.display()
                    ));
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (latest_path, target, _run_id);
        Err(format!("{error_prefix}-symlink-unsupported"))
    }
}

/// Compatibility wrapper for callers that do not already hold the parent flock.
pub(crate) fn promote_receipt_latest(
    latest_path: &Path,
    target: &Path,
    _stem: &str,
    run_id: &str,
    error_prefix: &str,
) -> Result<(), String> {
    let _parent_lock = lock_receipt_parent(latest_path, error_prefix)?;
    promote_receipt_latest_locked(latest_path, target, run_id, error_prefix)
}

pub(crate) fn parse_family_run(name: &str, stem: &str) -> Option<(u128, u128, bool)> {
    // Exact family language: ^{literal stem}-(?:run-[0-9]+(?:-[0-9]+)?|displaced-run-[0-9]+(?:-[0-9]+)?)$.
    let name = name.strip_prefix(&format!("{stem}-"))?;
    let (displaced, name) = if let Some(name) = name.strip_prefix("displaced-") {
        (true, name)
    } else {
        (false, name)
    };
    let name = name.strip_prefix("run-")?;
    let mut fields = name.split('-');
    let stamp = fields.next()?;
    if stamp.is_empty() || !stamp.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let collision = match fields.next() {
        Some(value) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
            value.parse::<u128>().ok()?
        }
        Some(_) => return None,
        None => 0,
    };
    if fields.next().is_some() {
        return None;
    }
    Some((stamp.parse().ok()?, collision, displaced))
}

fn latest_target_path(latest_path: &Path) -> Option<PathBuf> {
    let metadata = std::fs::symlink_metadata(latest_path).ok()?;
    if !metadata.file_type().is_symlink() {
        return None;
    }
    let target = std::fs::read_link(latest_path).ok()?;
    let target = if target.is_absolute() {
        target
    } else {
        latest_path.parent().unwrap_or_else(|| Path::new(".")).join(target)
    };
    Some(std::fs::canonicalize(&target).unwrap_or(target))
}

/// Prune an exact receipt family while the caller owns its parent flock.
pub(crate) fn prune_receipt_family_locked(
    latest_path: &Path,
    stem: &str,
    retention: usize,
) -> Result<(), String> {
    let parent = latest_path.parent().unwrap_or_else(|| Path::new("."));
    let entries = std::fs::read_dir(parent)
        .map_err(|error| format!("receipt-family-read-failed {}: {error}", parent.display()))?;
    let mut family = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if !file_type.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Some((stamp, collision, displaced)) = parse_family_run(&name, stem) {
            family.push((stamp, collision, displaced, entry.path()));
        }
    }
    family.sort_by(|left, right| {
        (left.0, left.1, left.2, &left.3).cmp(&(right.0, right.1, right.2, &right.3))
    });
    let latest_target = latest_target_path(latest_path);
    let latest_target = latest_target.as_deref().map(|path| {
        std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    });
    let mut retained = std::collections::BTreeSet::new();
    if let Some(target) = latest_target.as_ref() {
        if let Some((_, _, _, path)) = family.iter().find(|(_, _, _, path)| {
            std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()) == *target
        }) {
            retained.insert(path.clone());
        }
    }
    for (_, _, _, path) in family.iter().rev() {
        if retained.len() >= retention {
            break;
        }
        retained.insert(path.clone());
    }
    for (_, _, _, path) in family {
        if !retained.contains(&path) {
            std::fs::remove_dir_all(&path).map_err(|error| {
                format!("receipt-family-prune-failed {}: {error}", path.display())
            })?;
        }
    }
    Ok(())
}

/// Store early refusals beside a family without creating its parent or a run directory.
pub(crate) fn write_fixed_refusal_receipt(
    receipt_dir: &Path,
    fallback_stem: &str,
    receipt: &serde_json::Value,
) -> Result<(), String> {
    let parent = receipt_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
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
    let stem = latest_receipt_stem(receipt_dir, fallback_stem)
        .unwrap_or_else(|| fallback_stem.to_string());
    let refusal = receipt_sibling_path(receipt_dir, &format!("{stem}-refusal.json"));
    crate::atoms::attest::write_json_atomic(&refusal, receipt)
}

pub(crate) fn materialize_latest_receipt_dir(
    receipt_dir: &Path,
    run_id: &str,
    fallback_stem: &str,
    _error_prefix: &str,
) -> Result<PathBuf, String> {
    // The caller holds the parent flock through run writes, promotion, and pruning.
    Ok(allocate_receipt_directory(receipt_dir, run_id, fallback_stem)?.path)
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
