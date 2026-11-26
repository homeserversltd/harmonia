use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub(crate) const ENGINE_RUN_LOCK_PATH: &str = "/var/lib/harmonia/engine-run.lock";
pub(crate) const HOME_CONSOLE_UPDATE_LOCK_PATH: &str = "/run/harmonia/homeconsole-update.lock";
pub(crate) const HOME_SERVER_UPDATE_LOCK_PATH: &str = "/run/harmonia/homeserver-update.lock";
pub(crate) const HOMETV_UPDATE_LOCK_PATH: &str = "/run/harmonia/hometv-update.lock";

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
    contents: Vec<u8>,
}

impl Drop for EngineRunLockGuard {
    fn drop(&mut self) {
        let witness = crate::atoms::projectio::engine_state_witness();
        let _ = crate::atoms::projectio::engine_remove_if(&witness, &self.path, &self.contents, false);
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
pub(crate) fn engine_run_lock_pid_is_live(pid: u32) -> Result<bool, String> {
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
pub(crate) fn engine_run_lock_pid_is_live(_pid: u32) -> Result<bool, String> {
    Err("engine-run-lock-pid-probe-unsupported".to_string())
}

pub(crate) fn try_acquire_engine_run_lock() -> Result<EngineRunLockGuard, EngineRunLockFailure> {
    let witness = crate::atoms::projectio::engine_state_witness();
    let path = engine_run_lock_path();
    if let Some(parent) = path.parent() {
        crate::atoms::projectio::engine_make_dir(&witness, parent).map_err(|error| {
            EngineRunLockFailure::Unavailable(format!(
                "engine-run-lock-parent-create-failed {}: {error}",
                parent.display()
            ))
        })?;
    }
    loop {
        let contents = format!("pid={}\n", std::process::id()).into_bytes();
        match crate::atoms::projectio::engine_create_new(&witness, &path, &contents, 0o644) {
            Ok(()) => {
                return Ok(EngineRunLockGuard { path, contents });
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                match engine_run_lock_pid(&path) {
                    Ok(Some(pid)) if pid == std::process::id() => {
                        crate::atoms::projectio::engine_remove(&witness, &path, false).map_err(|error| {
                            EngineRunLockFailure::Unavailable(format!(
                                "engine-run-lock-inherited-remove-failed {}: {error}",
                                path.display()
                            ))
                        })?;
                    }
                    Ok(Some(pid))
                        if engine_run_lock_pid_is_live(pid)
                            .map_err(EngineRunLockFailure::Unavailable)? =>
                    {
                        return Err(EngineRunLockFailure::Busy);
                    }
                    Ok(Some(_)) => {
                        crate::atoms::projectio::engine_remove(&witness, &path, false).map_err(|error| {
                            EngineRunLockFailure::Unavailable(format!(
                                "engine-run-lock-stale-remove-failed {}: {error}",
                                path.display()
                            ))
                        })?;
                    }
                    Err(error) => return Err(EngineRunLockFailure::Unavailable(error)),
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
    let witness = crate::atoms::projectio::engine_state_witness();

    if let Some(parent) = lock_path.parent() {
        crate::atoms::projectio::engine_make_dir(&witness, parent).map_err(|_| ConvergenceLockBusy)?;
    }
    let file = crate::atoms::projectio::engine_open_lock(&witness, lock_path)
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
pub(crate) fn hometv_update_lock_path() -> PathBuf {
    if let Some(path) = std::env::var_os("HARMONIA_HOMETV_UPDATE_LOCK") {
        return PathBuf::from(path);
    }
    if let Some(path) = std::env::var_os("HARMONIA_TV_UPDATE_LOCK") {
        return PathBuf::from(path);
    }
    let current = PathBuf::from(HOMETV_UPDATE_LOCK_PATH);
    let legacy = PathBuf::from("/run/harmonia/tv-update.lock");
    if !current.exists() && legacy.exists() { legacy } else { current }
}
pub(crate) fn try_acquire_hometv_update_lock(
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
