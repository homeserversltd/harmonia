use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

pub(crate) const ENGINE_RUN_LOCK_PATH: &str = "/var/lib/harmonia/engine-run.lock";
pub(crate) const HOME_CONSOLE_UPDATE_LOCK_PATH: &str = "/run/harmonia/homeconsole-update.lock";
pub(crate) const HOME_SERVER_UPDATE_LOCK_PATH: &str = "/run/harmonia/homeserver-update.lock";
pub(crate) const TV_UPDATE_LOCK_PATH: &str = "/run/harmonia/tv-update.lock";

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
pub(crate) fn homeconsole_update_lock_path() -> PathBuf {
    std::env::var("HARMONIA_HOME_CONSOLE_UPDATE_LOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(HOME_CONSOLE_UPDATE_LOCK_PATH))
}
pub(crate) fn homeserver_update_lock_path() -> PathBuf {
    std::env::var("HARMONIA_HOMESERVER_UPDATE_LOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(HOME_SERVER_UPDATE_LOCK_PATH))
}
pub(crate) fn tv_update_lock_path() -> PathBuf {
    std::env::var("HARMONIA_TV_UPDATE_LOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(TV_UPDATE_LOCK_PATH))
}
pub(crate) fn try_acquire_tv_update_lock(
    lock_path: &Path,
) -> Result<ConvergenceLockGuard, ConvergenceLockBusy> {
    try_acquire_homeconsole_update_lock(lock_path)
}
#[cfg(not(unix))]
pub(crate) fn try_acquire_homeconsole_update_lock(
    _lock_path: &Path,
) -> Result<ConvergenceLockGuard, ConvergenceLockBusy> {
    Err(ConvergenceLockBusy)
}
