//! Authorized mutation atom. Every operation consumes both keys.
#![allow(dead_code)]

use super::Receipt;
use crate::tools::comparison::ActionAuthorization;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: usize = 16 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvocationKey(());

impl InvocationKey {
    pub(crate) fn from_apply_or_timer(apply_or_timer: bool) -> Option<Self> {
        apply_or_timer.then_some(Self(()))
    }
}

pub(crate) enum UnitVerb {
    Start,
    Stop,
    Restart,
    Enable,
    Disable,
}

impl UnitVerb {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Enable => "enable",
            Self::Disable => "disable",
        }
    }
}

pub(crate) fn apply(
    _authorization: ActionAuthorization,
    _invocation: InvocationKey,
    receipt: Receipt,
) -> Result<Receipt, String> {
    Ok(receipt)
}

pub(crate) struct FileWriteOptions<'a> {
    pub write_bytes: bool,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub backup_to: Option<&'a Path>,
}

pub(crate) struct FileWriteResult {
    pub backed_up: Option<PathBuf>,
}

pub(crate) fn file_write(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    path: &Path,
    bytes: &[u8],
    options: FileWriteOptions<'_>,
) -> Result<FileWriteResult, String> {
    let backed_up = if let Some(backup) = options.backup_to {
        if let Some(parent) = backup.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "file-write-backup-parent-create-failed {}: {error}",
                    parent.display()
                )
            })?;
        }
        fs::copy(path, backup).map_err(|error| {
            format!(
                "file-write-backup-failed {} -> {}: {error}",
                path.display(),
                backup.display()
            )
        })?;
        Some(backup.to_path_buf())
    } else {
        None
    };
    if options.write_bytes {
        atomic_file_write(path, bytes, options.mode, options.uid, options.gid)?;
    } else {
        if let Some(mode) = options.mode {
            set_mode(path, mode)?;
        }
        set_ownership(path, options.uid, options.gid)?;
    }
    apply(
        authorization,
        invocation,
        Receipt {
            atom: "do".into(),
            ok: true,
            drift: super::Drift::Current,
            message: "file write complete".into(),
        },
    )?;
    Ok(FileWriteResult { backed_up })
}

fn atomic_file_write(
    path: &Path,
    bytes: &[u8],
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("file-write-parent-missing {}", path.display()))?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("file");
    let temp = parent.join(format!(
        ".{name}.harmonia-atom-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)
            .map_err(|error| {
                format!("file-write-temp-create-failed {}: {error}", temp.display())
            })?;
        file.write_all(bytes)
            .map_err(|error| format!("file-write-temp-write-failed {}: {error}", temp.display()))?;
        file.sync_all()
            .map_err(|error| format!("file-write-temp-sync-failed {}: {error}", temp.display()))?;
        drop(file);
        if let Some(mode) = mode {
            set_mode(&temp, mode)?;
        }
        set_ownership(&temp, uid, gid)?;
        fs::rename(&temp, path).map_err(|error| {
            format!(
                "file-write-promote-failed {} -> {}: {error}",
                temp.display(),
                path.display()
            )
        })?;
        let directory = OpenOptions::new()
            .read(true)
            .open(parent)
            .map_err(|error| {
                format!(
                    "file-write-parent-open-failed {}: {error}",
                    parent.display()
                )
            })?;
        directory.sync_all().map_err(|error| {
            format!(
                "file-write-parent-sync-failed {}: {error}",
                parent.display()
            )
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("file-write-mode-set-failed {}: {error}", path.display()))
}
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn set_ownership(path: &Path, uid: Option<u32>, gid: Option<u32>) -> Result<(), String> {
    if uid.is_none() && gid.is_none() {
        return Ok(());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("file-write-owner-open-failed {}: {error}", path.display()))?;
    let uid = uid.map_or(!0 as libc::uid_t, |value| value as libc::uid_t);
    let gid = gid.map_or(!0 as libc::gid_t, |value| value as libc::gid_t);
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(format!(
            "file-write-owner-set-failed {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}
#[cfg(not(unix))]
fn set_ownership(_path: &Path, _uid: Option<u32>, _gid: Option<u32>) -> Result<(), String> {
    Ok(())
}

pub(crate) fn mutating_command(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    program: &str,
    args: &[String],
) -> Result<Receipt, String> {
    let result = run(program, args);
    apply(
        authorization,
        invocation,
        Receipt {
            atom: "do".into(),
            ok: result.ok,
            drift: super::Drift::Current,
            message: format!(
                "program={program}; args={args:?}; code={:?}; stdout={:?}; stderr={:?}",
                result.code, result.stdout, result.stderr
            ),
        },
    )
}

pub(crate) fn unit_change(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    unit: &str,
    verb: UnitVerb,
) -> Result<Receipt, String> {
    let program = "/usr/bin/systemctl";
    let args = vec![verb.as_str().to_owned(), unit.to_owned()];
    let result = run(program, &args);
    apply(
        authorization,
        invocation,
        Receipt {
            atom: "do".into(),
            ok: result.ok,
            drift: super::Drift::Current,
            message: format!(
                "program={program}; args={args:?}; code={:?}; stdout={:?}; stderr={:?}",
                result.code, result.stdout, result.stderr
            ),
        },
    )
}

struct ResultData {
    ok: bool,
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(program: &str, args: &[String]) -> ResultData {
    let mut child = match Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return ResultData {
                ok: false,
                code: None,
                stdout: String::new(),
                stderr: error.to_string(),
            };
        }
    };
    let out = child
        .stdout
        .take()
        .map(|mut reader| thread::spawn(move || bounded(&mut reader)));
    let err = child
        .stderr
        .take()
        .map(|mut reader| thread::spawn(move || bounded(&mut reader)));
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => {
                timed_out = true;
                let _ = child.kill();
                break child.wait().ok();
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(_) => break None,
        }
    };
    let stdout = out
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    let mut stderr = err
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    if timed_out {
        stderr.push_str("; command timed out");
    }
    ResultData {
        ok: status
            .as_ref()
            .is_some_and(std::process::ExitStatus::success),
        code: status.and_then(|status| status.code()),
        stdout,
        stderr,
    }
}

fn bounded<R: Read>(reader: &mut R) -> String {
    let mut bytes = Vec::new();
    reader
        .take(OUTPUT_LIMIT as u64)
        .read_to_end(&mut bytes)
        .ok();
    String::from_utf8_lossy(&bytes).into_owned()
}
