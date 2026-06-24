use crate::*;
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

pub(crate) const HOME_CONSOLE_UPDATE_LOCK_PATH: &str = "/run/harmonia/homeconsole-update.lock";

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
    refresh_latest_symlink(receipt_dir, &per_run)?;
    Ok(per_run)
}

fn refresh_latest_symlink(latest_path: &Path, target: &Path) -> Result<(), String> {
    if latest_path.exists() {
        if latest_path.is_symlink() {
            fs::remove_file(latest_path).map_err(|e| e.to_string())?;
        } else if latest_path.is_dir() {
            return Ok(());
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