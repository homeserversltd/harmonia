//! Authorized mutation atom. Every operation consumes both keys.
#![allow(dead_code)]

use super::{CommandObservation, Receipt};
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
    EnableNow,
    DisableNow,
}

impl UnitVerb {
    fn argv(&self) -> &'static [&'static str] {
        match self {
            Self::Start => &["start"],
            Self::Stop => &["stop"],
            Self::Restart => &["restart"],
            Self::Enable => &["enable"],
            Self::Disable => &["disable"],
            Self::EnableNow => &["enable", "--now"],
            Self::DisableNow => &["disable", "--now"],
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

pub(crate) fn create_dir_all(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    path: &Path,
) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| error.to_string())?;
    apply(
        authorization,
        invocation,
        Receipt {
            atom: "do".into(),
            ok: true,
            drift: super::Drift::Current,
            message: format!("directory created {}", path.display()),
        },
    )?;
    Ok(())
}

pub(crate) fn remove_file(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    path: &Path,
) -> Result<(), String> {
    fs::remove_file(path).map_err(|error| error.to_string())?;
    apply(
        authorization,
        invocation,
        Receipt {
            atom: "do".into(),
            ok: true,
            drift: super::Drift::Current,
            message: format!("file removed {}", path.display()),
        },
    )?;
    Ok(())
}

pub(crate) fn rename(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    from: &Path,
    to: &Path,
) -> Result<(), String> {
    fs::rename(from, to).map_err(|error| error.to_string())?;
    apply(
        authorization,
        invocation,
        Receipt {
            atom: "do".into(),
            ok: true,
            drift: super::Drift::Current,
            message: format!("renamed {} -> {}", from.display(), to.display()),
        },
    )?;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn symlink(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    target: &Path,
    link: &Path,
) -> Result<(), String> {
    std::os::unix::fs::symlink(target, link).map_err(|error| error.to_string())?;
    apply(
        authorization,
        invocation,
        Receipt {
            atom: "do".into(),
            ok: true,
            drift: super::Drift::Current,
            message: format!("symlink created {} -> {}", link.display(), target.display()),
        },
    )?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn symlink(
    _authorization: ActionAuthorization,
    _invocation: InvocationKey,
    _target: &Path,
    _link: &Path,
) -> Result<(), String> {
    Err("validated-file-symlink-unsupported".into())
}

pub(crate) fn cargo_build(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    cwd: &Path,
    environment: &[(String, String)],
    bearer: &str,
    _timeout: Duration,
) -> Result<super::CommandObservation, String> {
    let env = environment
        .iter()
        .cloned()
        .collect::<std::collections::BTreeMap<_, _>>();
    let result = crate::tools::command::capture_with_cwd_as_bearer_and_env(
        "cargo",
        &["build", "--release"],
        cwd.to_str(),
        bearer,
        env,
    );
    apply(
        authorization,
        invocation,
        Receipt {
            atom: "do".into(),
            ok: result.ok,
            drift: super::Drift::Current,
            message: format!("cargo build code={}", result.code),
        },
    )?;
    Ok(super::CommandObservation {
        program: "cargo".into(),
        args: vec!["build".into(), "--release".into()],
        ok: result.ok,
        code: Some(result.code),
        stdout: result.stdout,
        stderr: result.stderr,
    })
}

pub(crate) fn command_with_timeout_in_dir(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    program: &str,
    args: &[String],
    cwd: Option<&Path>,
    timeout: Duration,
) -> Result<super::CommandObservation, String> {
    command_with_timeout_in_dir_env(authorization, invocation, program, args, cwd, &[], timeout)
}

pub(crate) fn command_with_timeout_in_dir_env(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    program: &str,
    args: &[String],
    cwd: Option<&Path>,
    environment: &[(String, String)],
    timeout: Duration,
) -> Result<super::CommandObservation, String> {
    let result = run_with_timeout_in_dir_env(program, args, cwd, environment, timeout);
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
    )?;
    Ok(super::CommandObservation {
        program: program.into(),
        args: args.to_vec(),
        ok: result.ok,
        code: result.code,
        stdout: result.stdout,
        stderr: result.stderr,
    })
}

pub(crate) fn command_with_timeout(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    program: &str,
    args: &[String],
    timeout: Duration,
) -> Result<super::CommandObservation, String> {
    let result = run_with_timeout(program, args, timeout);
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
    )?;
    Ok(super::CommandObservation {
        program: program.into(),
        args: args.to_vec(),
        ok: result.ok,
        code: result.code,
        stdout: result.stdout,
        stderr: result.stderr,
    })
}

pub(crate) fn aur_install(
    _authorization: ActionAuthorization,
    _invocation: InvocationKey,
    callback: impl FnOnce() -> Result<crate::OperationOutcome, String>,
) -> Result<crate::OperationOutcome, String> {
    callback()
}

pub(crate) fn aur_build_pinned(
    _authorization: ActionAuthorization,
    _invocation: InvocationKey,
    callback: impl FnOnce() -> Result<crate::OperationOutcome, String>,
) -> Result<crate::OperationOutcome, String> {
    callback()
}

pub(crate) fn git_pull(
    _authorization: ActionAuthorization,
    _invocation: InvocationKey,
    _request: &crate::tools::git_artifact::Request,
    callback: impl FnOnce() -> crate::tools::git_artifact::Outcome,
) -> crate::tools::git_artifact::Outcome {
    callback()
}

pub(crate) fn git_acquire(
    _authorization: ActionAuthorization,
    _invocation: InvocationKey,
    _plan: &crate::tools::git_artifact::SourcePlan,
    callback: impl FnOnce() -> crate::tools::git_artifact::SourceOutcome,
) -> crate::tools::git_artifact::SourceOutcome {
    callback()
}

pub(crate) fn package_install(
    _authorization: ActionAuthorization,
    _invocation: InvocationKey,
    receipt_dir: &Path,
    packages: &[String],
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
    timeout_secs: u64,
) -> Result<CommandObservation, String> {
    let result = crate::tools::package::pacman_mutate_packages_with_options(
        receipt_dir,
        false,
        packages,
        conflict_policy,
        conflict_paths,
        timeout_secs,
    )?;
    Ok(CommandObservation {
        program: crate::tools::package::pacman_program(),
        args: vec!["-S".into(), "--noconfirm".into(), "--needed".into()],
        ok: result.ok,
        code: Some(result.code),
        stdout: result.stdout,
        stderr: result.stderr,
    })
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
    let args = verb
        .argv()
        .iter()
        .map(|arg| (*arg).to_owned())
        .chain(std::iter::once(unit.to_owned()))
        .collect::<Vec<_>>();
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
    run_with_timeout(program, args, COMMAND_TIMEOUT)
}

fn run_with_timeout(program: &str, args: &[String], timeout: Duration) -> ResultData {
    run_with_timeout_in_dir_env(program, args, None, &[], timeout)
}

fn run_with_timeout_in_dir(
    program: &str,
    args: &[String],
    cwd: Option<&Path>,
    timeout: Duration,
) -> ResultData {
    run_with_timeout_in_dir_env(program, args, cwd, &[], timeout)
}

fn run_with_timeout_in_dir_env(
    program: &str,
    args: &[String],
    cwd: Option<&Path>,
    environment: &[(String, String)],
    timeout: Duration,
) -> ResultData {
    let mut command = Command::new(program);
    command.args(args);
    command.envs(environment.iter().map(|(key, value)| (key, value)));
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let mut child = match command
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
    let deadline = Instant::now() + timeout;
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

pub(crate) fn unit_change_scoped(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    unit: &str,
    verb: UnitVerb,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
) -> Result<CommandObservation, String> {
    let mut args = Vec::new();
    if user {
        args.push("--user".into());
        if let Some(target) = target_user.filter(|v| !v.trim().is_empty()) {
            args.push(format!("--machine={target}@.host"));
        }
    }
    args.extend(verb.argv().iter().map(|arg| (*arg).to_owned()));
    args.push(unit.to_owned());
    command_with_timeout(
        authorization,
        invocation,
        "/usr/bin/systemctl",
        &args,
        Duration::from_secs(timeout_secs),
    )
}
