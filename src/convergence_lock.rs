use crate::*;
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

pub(crate) const ENGINE_RUN_LOCK_PATH: &str = "/var/lib/harmonia/engine-run.lock";
pub(crate) const HOME_CONSOLE_UPDATE_LOCK_PATH: &str = "/run/harmonia/homeconsole-update.lock";
pub(crate) const HOME_CONSOLE_UPDATE_RECEIPT_LATEST: &str =
    "/var/lib/harmonia/receipts/homeconsole-update-latest";
pub(crate) const HOME_CONSOLE_UPDATE_RECEIPT_LEGACY: &str =
    "/var/lib/harmonia/receipts/homeconsole-latest";
pub(crate) const HOME_SERVER_UPDATE_LOCK_PATH: &str = "/run/harmonia/homeserver-update.lock";
pub(crate) const HOME_SERVER_UPDATE_RECEIPT_LATEST: &str =
    "/var/lib/harmonia/receipts/homeserver-update-latest";
pub(crate) const TV_UPDATE_LOCK_PATH: &str = "/run/harmonia/tv-update.lock";
pub(crate) const TV_UPDATE_RECEIPT_LATEST: &str = "/var/lib/harmonia/receipts/tv-update-latest";
pub(crate) const TV_UPDATE_RECEIPT_LEGACY: &str = "/var/lib/harmonia/receipts/tv-latest";

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

pub(crate) fn homeserver_update_receipt_latest() -> PathBuf {
    PathBuf::from(HOME_SERVER_UPDATE_RECEIPT_LATEST)
}

pub(crate) fn homeserver_update_lock_path() -> PathBuf {
    std::env::var("HARMONIA_HOMESERVER_UPDATE_LOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(HOME_SERVER_UPDATE_LOCK_PATH))
}

pub(crate) fn engine_run_lock_path() -> PathBuf {
    PathBuf::from(ENGINE_RUN_LOCK_PATH)
}

#[derive(Debug)]
pub(crate) enum EngineRunLockFailure {
    Busy,
    Unavailable(String),
}

pub(crate) struct EngineRunLockGuard {
    path: PathBuf,
    _file: std::fs::File,
}

impl Drop for EngineRunLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn engine_run_lock_pid(path: &Path) -> Result<Option<u32>, String> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            let pid = contents
                .trim()
                .strip_prefix("pid=")
                .ok_or_else(|| format!("engine-run-lock-invalid {}", path.display()))?
                .parse::<u32>()
                .map_err(|_| format!("engine-run-lock-invalid {}", path.display()))?;
            if pid == 0 {
                return Err(format!("engine-run-lock-invalid {}", path.display()));
            }
            Ok(Some(pid))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "engine-run-lock-read-failed {}: {error}",
            path.display()
        )),
    }
}

#[cfg(unix)]
fn engine_run_lock_pid_is_live(pid: u32) -> Result<bool, String> {
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(format!(
            "engine-run-lock-pid-probe-failed pid={pid}: {error}"
        )),
    }
}

#[cfg(not(unix))]
fn engine_run_lock_pid_is_live(_pid: u32) -> Result<bool, String> {
    Err("engine-run-lock-pid-probe-unsupported".to_string())
}

pub(crate) fn try_acquire_engine_run_lock() -> Result<EngineRunLockGuard, EngineRunLockFailure> {
    let path = engine_run_lock_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            EngineRunLockFailure::Unavailable(format!(
                "engine-run-lock-parent-create-failed {}: {error}",
                parent.display()
            ))
        })?;
    }
    loop {
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                use std::io::Write;
                writeln!(file, "pid={}", std::process::id()).map_err(|error| {
                    EngineRunLockFailure::Unavailable(format!(
                        "engine-run-lock-write-failed {}: {error}",
                        path.display()
                    ))
                })?;
                file.sync_all().map_err(|error| {
                    EngineRunLockFailure::Unavailable(format!(
                        "engine-run-lock-sync-failed {}: {error}",
                        path.display()
                    ))
                })?;
                return Ok(EngineRunLockGuard { path, _file: file });
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                match engine_run_lock_pid(&path) {
                    Ok(Some(pid))
                        if engine_run_lock_pid_is_live(pid)
                            .map_err(EngineRunLockFailure::Unavailable)? =>
                    {
                        return Err(EngineRunLockFailure::Busy);
                    }
                    Ok(Some(_)) | Err(_) => {
                        fs::remove_file(&path).map_err(|error| {
                            EngineRunLockFailure::Unavailable(format!(
                                "engine-run-lock-stale-remove-failed {}: {error}",
                                path.display()
                            ))
                        })?;
                    }
                    Ok(None) => continue,
                }
            }
            Err(error) => {
                return Err(EngineRunLockFailure::Unavailable(format!(
                    "engine-run-lock-create-failed {}: {error}",
                    path.display()
                )));
            }
        }
    }
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

pub(crate) fn try_acquire_homeserver_update_lock(
    lock_path: &Path,
) -> Result<ConvergenceLockGuard, ConvergenceLockBusy> {
    try_acquire_homeconsole_update_lock(lock_path)
}

pub(crate) fn tv_update_receipt_latest() -> PathBuf {
    PathBuf::from(TV_UPDATE_RECEIPT_LATEST)
}

pub(crate) fn tv_update_receipt_legacy() -> PathBuf {
    PathBuf::from(TV_UPDATE_RECEIPT_LEGACY)
}

pub(crate) fn tv_update_lock_path() -> PathBuf {
    std::env::var("HARMONIA_TV_UPDATE_LOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(TV_UPDATE_LOCK_PATH))
}

pub(crate) fn profile_update_lock_path(profile_id: &str) -> Result<PathBuf, String> {
    if profile_id.is_empty() || !profile_id.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')) {
        return Err(format!("profile-update-lock-profile-id-invalid {profile_id}"));
    }
    Ok(PathBuf::from("/run/harmonia").join(format!("{profile_id}-update.lock")))
}

pub(crate) fn try_acquire_tv_update_lock(
    lock_path: &Path,
) -> Result<ConvergenceLockGuard, ConvergenceLockBusy> {
    try_acquire_homeconsole_update_lock(lock_path)
}

pub(crate) fn materialize_tv_receipt_dir(
    receipt_dir: &Path,
    run_id: &str,
) -> Result<PathBuf, String> {
    let file_name = receipt_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let use_per_run = matches!(file_name, "latest" | "tv-update-latest" | "tv-latest")
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
        .unwrap_or("tv-update");
    let per_run = parent.join(format!("{base}-{run_id}"));
    fs::create_dir_all(&per_run).map_err(|e| e.to_string())?;
    migrate_tv_blocking_receipt_path(receipt_dir, run_id)?;
    refresh_tv_latest_symlink(receipt_dir, &per_run)?;
    Ok(per_run)
}

fn migrate_tv_blocking_receipt_path(latest_path: &Path, run_id: &str) -> Result<(), String> {
    if !latest_path.exists() || latest_path.is_symlink() {
        return Ok(());
    }
    if latest_path.is_dir() {
        let parent = latest_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| latest_path.to_path_buf());
        let migrated = parent.join(format!("tv-update-legacy-{run_id}"));
        fs::rename(latest_path, &migrated).map_err(|e| {
            format!(
                "tv-update-latest-migrate-failed {} -> {}: {e}",
                latest_path.display(),
                migrated.display()
            )
        })?;
        return Ok(());
    }
    fs::remove_file(latest_path).map_err(|e| e.to_string())
}

fn refresh_tv_latest_symlink(latest_path: &Path, target: &Path) -> Result<(), String> {
    if latest_path.exists() {
        fs::remove_file(latest_path).map_err(|e| e.to_string())?;
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, latest_path).map_err(|e| {
        format!(
            "tv-update-latest-symlink-failed {} -> {}: {e}",
            target.display(),
            latest_path.display()
        )
    })?;
    #[cfg(not(unix))]
    return Err("tv-update-latest-symlink-unsupported".to_string());
    Ok(())
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

pub(crate) fn materialize_homeserver_receipt_dir(
    receipt_dir: &Path,
    run_id: &str,
) -> Result<PathBuf, String> {
    let file_name = receipt_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let use_per_run = matches!(file_name, "latest" | "homeserver-update-latest")
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
        .unwrap_or("homeserver-update");
    let per_run = parent.join(format!("{base}-{run_id}"));
    fs::create_dir_all(&per_run).map_err(|e| e.to_string())?;
    migrate_homeserver_blocking_receipt_path(receipt_dir, run_id)?;
    refresh_homeserver_latest_symlink(receipt_dir, &per_run)?;
    Ok(per_run)
}

pub(crate) fn materialize_profile_receipt_dir(receipt_dir: &Path, run_id: &str) -> Result<PathBuf, String> {
    let file_name = receipt_dir.file_name().and_then(|name| name.to_str()).unwrap_or("");
    if file_name != "latest" && !file_name.ends_with("-latest") {
        return Ok(receipt_dir.to_path_buf());
    }
    let parent = receipt_dir.parent().map(Path::to_path_buf).unwrap_or_else(|| receipt_dir.to_path_buf());
    let base = file_name.strip_suffix("-latest").filter(|stem| !stem.is_empty()).unwrap_or("profile-update");
    let per_run = parent.join(format!("{base}-{run_id}"));
    fs::create_dir_all(&per_run).map_err(|e| e.to_string())?;
    if receipt_dir.exists() && !receipt_dir.is_symlink() {
        if receipt_dir.is_dir() {
            let migrated = parent.join(format!("{base}-legacy-{run_id}"));
            fs::rename(receipt_dir, &migrated).map_err(|e| format!("profile-update-latest-migrate-failed {} -> {}: {e}", receipt_dir.display(), migrated.display()))?;
        } else {
            fs::remove_file(receipt_dir).map_err(|e| e.to_string())?;
        }
    }
    if receipt_dir.is_symlink() || receipt_dir.exists() {
        fs::remove_file(receipt_dir).map_err(|e| e.to_string())?;
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(&per_run, receipt_dir).map_err(|e| format!("profile-update-latest-symlink-failed {} -> {}: {e}", per_run.display(), receipt_dir.display()))?;
    #[cfg(not(unix))]
    return Err("profile-update-latest-symlink-unsupported".to_string());
    Ok(per_run)
}

fn migrate_homeserver_blocking_receipt_path(
    latest_path: &Path,
    run_id: &str,
) -> Result<(), String> {
    if !latest_path.exists() || latest_path.is_symlink() {
        return Ok(());
    }
    if latest_path.is_dir() {
        let parent = latest_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| latest_path.to_path_buf());
        let migrated = parent.join(format!("homeserver-update-legacy-{run_id}"));
        fs::rename(latest_path, &migrated).map_err(|e| {
            format!(
                "homeserver-update-latest-migrate-failed {} -> {}: {e}",
                latest_path.display(),
                migrated.display()
            )
        })?;
        return Ok(());
    }
    fs::remove_file(latest_path).map_err(|e| e.to_string())
}

fn refresh_homeserver_latest_symlink(latest_path: &Path, target: &Path) -> Result<(), String> {
    if latest_path.exists() {
        fs::remove_file(latest_path).map_err(|e| e.to_string())?;
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, latest_path).map_err(|e| {
        format!(
            "homeserver-update-latest-symlink-failed {} -> {}: {e}",
            target.display(),
            latest_path.display()
        )
    })?;
    #[cfg(not(unix))]
    return Err("homeserver-update-latest-symlink-unsupported".to_string());
    Ok(())
}

pub(crate) fn migrate_blocking_receipt_path(
    latest_path: &Path,
    run_id: &str,
) -> Result<(), String> {
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
        let migrated = parent.join(format!("homeconsole-latest-legacy-{}", run_id_from_stamp()));
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
    let mut events =
        fs::File::create(receipt_dir.join("events.jsonl")).map_err(|e| e.to_string())?;
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
    );
    println!("ok=true");
    println!("changed=false");
    println!("profile_id={profile_id}");
    println!("reason={reason}");
    println!("receipt_dir={}", receipt_dir.display());
}
