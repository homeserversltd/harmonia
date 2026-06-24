use crate::*;
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

pub(crate) const HOME_CONSOLE_UPDATE_LOCK_PATH: &str = "/run/harmonia/homeconsole-update.lock";
pub(crate) const HOME_CONSOLE_UPDATE_RECEIPT_LATEST: &str =
    "/var/lib/harmonia/receipts/homeconsole-update-latest";
pub(crate) const HOME_CONSOLE_UPDATE_RECEIPT_LEGACY: &str =
    "/var/lib/harmonia/receipts/homeconsole-latest";

pub(crate) fn homeconsole_update_receipt_latest() -> PathBuf {
    PathBuf::from(HOME_CONSOLE_UPDATE_RECEIPT_LATEST)
}

pub(crate) fn homeconsole_update_receipt_legacy() -> PathBuf {
    PathBuf::from(HOME_CONSOLE_UPDATE_RECEIPT_LEGACY)
}

pub(crate) fn homeconsole_update_lock_path() -> PathBuf {
    std::env::var("HARMONIA_HOME_CONSOLE_UPDATE_LOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(HOME_CONSOLE_UPDATE_LOCK_PATH))
}

#[derive(Debug)]
pub(crate) struct ConvergenceLockBusy;

pub(crate) struct ConvergenceLockGuard {
    _file: std::fs::File,
}

#[cfg(unix)]
pub(crate) fn try_acquire_homeconsole_update_lock(
    lock_path: &Path,
) -> Result<ConvergenceLockGuard, ConvergenceLockBusy> {
    use std::os::unix::io::AsRawFd;

    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent).map_err(|_| ConvergenceLockBusy)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(lock_path)
        .map_err(|_| ConvergenceLockBusy)?;
    let fd = file.as_raw_fd();
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if rc == -1 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock
            || err.raw_os_error() == Some(libc::EWOULDBLOCK)
            || err.raw_os_error() == Some(libc::EAGAIN)
        {
            return Err(ConvergenceLockBusy);
        }
        return Err(ConvergenceLockBusy);
    }
    Ok(ConvergenceLockGuard { _file: file })
}

#[cfg(not(unix))]
pub(crate) fn try_acquire_homeconsole_update_lock(
    _lock_path: &Path,
) -> Result<ConvergenceLockGuard, ConvergenceLockBusy> {
    Err(ConvergenceLockBusy)
}

pub(crate) fn materialize_homeconsole_receipt_dir(
    receipt_dir: &Path,
    run_id: &str,
) -> Result<PathBuf, String> {
    let file_name = receipt_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let use_per_run = matches!(file_name, "latest" | "homeconsole-update-latest")
        || file_name.ends_with("-latest");
    if !use_per_run {
        return Ok(receipt_dir.to_path_buf());
    }
    let parent = receipt_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| receipt_dir.to_path_buf());
    let base = file_name
        .strip_suffix("-latest")
        .filter(|stem| !stem.is_empty())
        .unwrap_or("homeconsole-update");
    let per_run = parent.join(format!("{base}-{run_id}"));
    fs::create_dir_all(&per_run).map_err(|e| e.to_string())?;
    migrate_blocking_receipt_path(receipt_dir, run_id)?;
    refresh_latest_symlink(receipt_dir, &per_run)?;
    Ok(per_run)
}

pub(crate) fn migrate_blocking_receipt_path(latest_path: &Path, run_id: &str) -> Result<(), String> {
    if !latest_path.exists() || latest_path.is_symlink() {
        return Ok(());
    }
    if latest_path.is_dir() {
        let parent = latest_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| latest_path.to_path_buf());
        let migrated = parent.join(format!("homeconsole-update-legacy-{run_id}"));
        fs::rename(latest_path, &migrated).map_err(|e| {
            format!(
                "homeconsole-update-latest-migrate-failed {} -> {}: {e}",
                latest_path.display(),
                migrated.display()
            )
        })?;
        return Ok(());
    }
    fs::remove_file(latest_path).map_err(|e| e.to_string())
}

pub(crate) fn link_legacy_receipt_alias(legacy: &Path, canonical: &Path) -> Result<bool, String> {
    if legacy == canonical {
        return Ok(false);
    }
    if legacy.is_symlink() {
        let target = fs::read_link(legacy).map_err(|e| e.to_string())?;
        if target == canonical {
            return Ok(false);
        }
        fs::remove_file(legacy).map_err(|e| e.to_string())?;
    } else if legacy.exists() {
        let parent = legacy
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| legacy.to_path_buf());
        let migrated = parent.join(format!(
            "homeconsole-latest-legacy-{}",
            run_id_from_stamp()
        ));
        if legacy.is_dir() {
            fs::rename(legacy, &migrated).map_err(|e| e.to_string())?;
        } else {
            fs::remove_file(legacy).map_err(|e| e.to_string())?;
        }
    }
    if !canonical.exists() {
        fs::create_dir_all(canonical).map_err(|e| e.to_string())?;
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(canonical, legacy).map_err(|e| {
            format!(
                "homeconsole-latest-alias-symlink-failed {} -> {}: {e}",
                canonical.display(),
                legacy.display()
            )
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = (legacy, canonical);
        return Err("homeconsole-latest-alias-symlink-unsupported".to_string());
    }
    Ok(true)
}

fn refresh_latest_symlink(latest_path: &Path, target: &Path) -> Result<(), String> {
    if latest_path.exists() {
        if latest_path.is_symlink() {
            fs::remove_file(latest_path).map_err(|e| e.to_string())?;
        } else if latest_path.is_dir() {
            return Err(format!(
                "homeconsole-update-latest-still-directory {}",
                latest_path.display()
            ));
        } else {
            fs::remove_file(latest_path).map_err(|e| e.to_string())?;
        }
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, latest_path).map_err(|e| {
            format!(
                "homeconsole-update-latest-symlink-failed {} -> {}: {e}",
                target.display(),
                latest_path.display()
            )
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = (latest_path, target);
        return Err("homeconsole-update-latest-symlink-unsupported".to_string());
    }
    Ok(())
}

pub(crate) fn write_convergence_skipped_receipt(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
    reason: &str,
    lock_path: &Path,
    requested_receipt_dir: &Path,
) -> Result<(), String> {
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
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
    let mut events = fs::File::create(receipt_dir.join("events.jsonl")).map_err(|e| e.to_string())?;
    event(
        &mut events,
        "convergence-skipped",
        true,
        &format!("reason={reason}"),
    )
}

pub(crate) fn emit_convergence_skipped_stdout(
    receipt_dir: &Path,
    reason: &str,
    profile_id: &str,
) {
    println!("schema=harmonia.convergence.skipped.v1");
    println!("ok=true");
    println!("changed=false");
    println!("profile_id={profile_id}");
    println!("reason={reason}");
    println!("receipt_dir={}", receipt_dir.display());
}