use super::{ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::CmdResult;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const NAME: &str = "command";
pub const DESCRIPTION: &str = "Host command execution primitive with cwd/env/timeout/exit capture; every subprocess produces a command receipt.";
/// The portable system command search path used for manifest programs that do
/// not name an absolute executable.  Root-launched services do not reliably
/// inherit the administrative sbin directories, even though tools such as
/// util-linux's `runuser` are installed there on Debian.
const DEFAULT_SYSTEM_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
pub const PERMUTATIONS: &[ToolPermutation] = &[ToolPermutation::new(
    "capture",
    "capture a host command with optional args/cwd/timeout",
    &[
        ToolArg::required("program", ToolArgKind::String),
        ToolArg::optional("args", ToolArgKind::StringArray),
        ToolArg::optional("cwd", ToolArgKind::String),
        ToolArg::optional("timeout_secs", ToolArgKind::Integer),
    ],
)];
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION, PERMUTATIONS);
pub const DEFAULT_TIMEOUT_SECS: u64 = 900;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub action: String,
    pub target: String,
    pub args: Vec<String>,
}

impl Request {
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            target: NAME.to_string(),
            args: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub ok: bool,
    pub changed: bool,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct CaptureOptions<'a> {
    pub cwd: Option<&'a str>,
    pub env: BTreeMap<String, String>,
    pub redact: BTreeSet<String>,
    pub timeout_secs: u64,
    bearer: Option<Bearer>,
}

#[derive(Debug, Clone)]
struct Bearer {
    uid: u32,
    gid: u32,
    name: String,
    home: String,
}

impl<'a> CaptureOptions<'a> {
    pub fn new() -> Self {
        Self {
            cwd: None,
            env: BTreeMap::new(),
            redact: BTreeSet::new(),
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            bearer: None,
        }
    }
    pub fn cwd(mut self, cwd: Option<&'a str>) -> Self {
        self.cwd = cwd;
        self
    }
    pub fn timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }
    pub fn env(mut self, env: BTreeMap<String, String>) -> Self {
        self.env = env;
        self
    }
    pub fn redact(mut self, redact: BTreeSet<String>) -> Self {
        self.redact = redact;
        self
    }

    fn bearer(mut self, bearer: Bearer) -> Self {
        self.bearer = Some(bearer);
        self
    }
}

pub fn command_request(action: impl Into<String>) -> Request {
    Request::new(action)
}

pub fn capture_request(program: impl Into<String>, args: Vec<String>) -> Request {
    Request {
        action: "capture".to_string(),
        target: program.into(),
        args,
    }
}

pub fn plan(request: &Request) -> Outcome {
    Outcome {
        ok: true,
        changed: false,
        message: format!("{} {} planned for {}", NAME, request.action, request.target),
    }
}

pub(crate) fn capture(program: &str, args: &[&str]) -> CmdResult {
    capture_with_options(program, args, CaptureOptions::new())
}

pub(crate) fn capture_with_timeout(program: &str, args: &[&str], timeout_secs: u64) -> CmdResult {
    capture_with_options(
        program,
        args,
        CaptureOptions::new().timeout_secs(timeout_secs),
    )
}

pub(crate) fn capture_with_cwd(program: &str, args: &[&str], cwd: Option<&str>) -> CmdResult {
    capture_with_options(program, args, CaptureOptions::new().cwd(cwd))
}

/// Execute a filesystem-writing child as the named non-root bearer when the
/// Harmonia parent is privileged.  Root is retained for the parent-side
/// service and file operations; it is never allowed to inherit Git/SSH
/// credential custody into this child.
pub(crate) fn capture_with_cwd_as_bearer(
    program: &str,
    args: &[&str],
    cwd: Option<&str>,
    bearer: &str,
) -> CmdResult {
    capture_with_cwd_as_bearer_and_env(program, args, cwd, bearer, BTreeMap::new())
}

/// Execute a filesystem-writing child with an explicitly scoped environment
/// after the same bearer drop used by Git. Environment assembly is harmless
/// parent-side setup; the child has not read credential material until it has
/// completed setgroups -> setgid -> setuid in `pre_exec`.
pub(crate) fn capture_with_cwd_as_bearer_and_env(
    program: &str,
    args: &[&str],
    cwd: Option<&str>,
    bearer: &str,
    env: BTreeMap<String, String>,
) -> CmdResult {
    if unsafe { libc::geteuid() } != 0 {
        return capture_with_options(program, args, CaptureOptions::new().cwd(cwd).env(env));
    }
    match resolve_non_root_bearer(bearer) {
        Ok(bearer) => capture_with_options(
            program,
            args,
            CaptureOptions::new().cwd(cwd).env(env).bearer(bearer),
        ),
        Err(err) => CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: err,
        },
    }
}

fn resolve_non_root_bearer(bearer: &str) -> Result<Bearer, String> {
    let name = std::ffi::CString::new(bearer).map_err(|_| "git-bearer-invalid-name".to_string())?;
    let passwd = unsafe { libc::getpwnam(name.as_ptr()) };
    if passwd.is_null() {
        return Err(format!("git-bearer-unknown {bearer}"));
    }
    let passwd = unsafe { &*passwd };
    if passwd.pw_uid == 0 {
        return Err(format!("git-bearer-root-refused {bearer}"));
    }
    let home = unsafe { std::ffi::CStr::from_ptr(passwd.pw_dir) }
        .to_str()
        .map_err(|_| format!("git-bearer-home-invalid {bearer}"))?
        .to_string();
    Ok(Bearer {
        uid: passwd.pw_uid,
        gid: passwd.pw_gid,
        name: bearer.to_string(),
        home,
    })
}

#[allow(dead_code)]
pub(crate) fn capture_with_cwd_and_timeout(
    program: &str,
    args: &[&str],
    cwd: Option<&str>,
    timeout_secs: u64,
) -> CmdResult {
    capture_with_options(
        program,
        args,
        CaptureOptions::new().cwd(cwd).timeout_secs(timeout_secs),
    )
}

pub(crate) fn capture_with_env(
    program: &str,
    args: &[&str],
    env: &[(String, String)],
) -> CmdResult {
    let env = env.iter().cloned().collect();
    capture_with_options(program, args, CaptureOptions::new().env(env))
}

pub(crate) fn capture_redacted(program: &str, args: &[&str], redactions: &[String]) -> CmdResult {
    let redact = redactions
        .iter()
        .filter(|v| !v.is_empty())
        .cloned()
        .collect();
    capture_with_options(program, args, CaptureOptions::new().redact(redact))
}

pub(crate) fn capture_with_options(
    program: &str,
    args: &[&str],
    options: CaptureOptions<'_>,
) -> CmdResult {
    let mut cmd = Command::new(program);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if !program.contains('/') && !options.env.contains_key("PATH") {
        cmd.env("PATH", DEFAULT_SYSTEM_PATH);
    }
    if let Some(cwd) = options.cwd {
        cmd.current_dir(Path::new(cwd));
    }
    if let Some(bearer) = options.bearer.as_ref() {
        cmd.env("HOME", &bearer.home)
            .env("USER", &bearer.name)
            .env("LOGNAME", &bearer.name);
        let uid = bearer.uid;
        let gid = bearer.gid;
        unsafe {
            cmd.pre_exec(move || {
                if libc::setgroups(0, std::ptr::null()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setgid(gid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setuid(uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    // The bearer establishes a truthful login baseline. Callers may narrowly
    // add or override it (for example, a declared toolchain environment).
    for (key, value) in &options.env {
        cmd.env(key, value);
    }
    let command_label = format!("{} {}", program, args.join(" "));
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            return CmdResult {
                ok: false,
                code: -1,
                stdout: String::new(),
                stderr: format!("command-spawn-failed: {command_label}: {err}"),
            }
        }
    };
    let timeout_secs = if options.timeout_secs == 0 {
        DEFAULT_TIMEOUT_SECS
    } else {
        options.timeout_secs
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let (stdout, stderr) = read_child_pipes(&mut child);
                return CmdResult {
                    ok: status.success(),
                    code: status.code().unwrap_or(-1),
                    stdout: redact(stdout.trim(), &options.redact),
                    stderr: redact(stderr.trim(), &options.redact),
                };
            }
            Ok(None) if start.elapsed() >= Duration::from_secs(timeout_secs) => {
                let _ = child.kill();
                let _ = child.wait();
                let (stdout, stderr) = read_child_pipes(&mut child);
                let signal = format!("command-timeout-after-{timeout_secs}s: {command_label}");
                let stderr = if stderr.trim().is_empty() {
                    signal
                } else {
                    format!("{}\n{}", stderr.trim(), signal)
                };
                return CmdResult {
                    ok: false,
                    code: -1,
                    stdout: redact(stdout.trim(), &options.redact),
                    stderr: redact(&stderr, &options.redact),
                };
            }
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(err) => {
                let _ = child.kill();
                return CmdResult {
                    ok: false,
                    code: -1,
                    stdout: String::new(),
                    stderr: format!("command-wait-failed: {command_label}: {err}"),
                };
            }
        }
    }
}

fn read_child_pipes(child: &mut std::process::Child) -> (String, String) {
    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut stdout);
    }
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut stderr);
    }
    (stdout, stderr)
}

fn redact(text: &str, redactions: &BTreeSet<String>) -> String {
    redactions.iter().fold(text.to_string(), |acc, secret| {
        acc.replace(secret, "[REDACTED]")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_not_a_valid_git_bearer() {
        assert_eq!(
            resolve_non_root_bearer("root").unwrap_err(),
            "git-bearer-root-refused root"
        );
    }

    #[test]
    fn unknown_git_bearer_fails_closed() {
        assert_eq!(
            resolve_non_root_bearer("harmonia-no-such-bearer").unwrap_err(),
            "git-bearer-unknown harmonia-no-such-bearer"
        );
    }

    #[test]
    fn privileged_child_drops_to_owner_bearer() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let owner = resolve_non_root_bearer("owner").unwrap();
        let result = capture_with_cwd_as_bearer("/usr/bin/id", &["-u"], None, "owner");
        assert!(result.ok, "{}", result.stderr);
        assert_eq!(result.stdout, owner.uid.to_string());
    }

    #[test]
    fn bare_programs_receive_the_portable_system_path() {
        let result = capture("sh", &["-c", "printf %s \"$PATH\""]);
        assert!(result.ok, "{}", result.stderr);
        assert_eq!(result.stdout, DEFAULT_SYSTEM_PATH);
    }

    #[test]
    fn privileged_child_receives_git_ssh_command_only_after_bearer_drop() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let owner = resolve_non_root_bearer("owner").unwrap();
        let mut env = BTreeMap::new();
        env.insert(
            "GIT_SSH_COMMAND".to_string(),
            "ssh -i '/var/lib/harmonia/forgejo-owner' -o IdentitiesOnly=yes".to_string(),
        );
        let result = capture_with_cwd_as_bearer_and_env(
            "/usr/bin/sh",
            &["-c", "printf '%s|%s' \"$(id -u)\" \"$GIT_SSH_COMMAND\""],
            None,
            "owner",
            env,
        );
        assert!(result.ok, "{}", result.stderr);
        assert_eq!(
            result.stdout,
            format!(
                "{}|ssh -i '/var/lib/harmonia/forgejo-owner' -o IdentitiesOnly=yes",
                owner.uid
            )
        );
    }
}
