use crate::CmdResult;
#[cfg(any(test, feature = "test-facade"))]
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const NAME: &str = "command";
pub const DEFAULT_TIMEOUT_SECS: u64 = 900;
const DEFAULT_SYSTEM_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

const TERMINATION_GRACE_SECS: u64 = 3;

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

#[cfg(any(test, feature = "test-facade"))]
thread_local! {
    static TEST_BEARER: RefCell<Option<Bearer>> = const { RefCell::new(None) };
}

#[cfg(any(test, feature = "test-facade"))]
pub(crate) struct TestBearerGuard {
    previous: Option<Bearer>,
}

#[cfg(any(test, feature = "test-facade"))]
impl Drop for TestBearerGuard {
    fn drop(&mut self) {
        TEST_BEARER.with(|slot| {
            *slot.borrow_mut() = self.previous.take();
        });
    }
}

#[cfg(any(test, feature = "test-facade"))]
pub(crate) fn install_test_bearer(name: &str, uid: u32, gid: u32, home: &Path) -> TestBearerGuard {
    let previous = TEST_BEARER.with(|slot| {
        slot.borrow_mut().replace(Bearer {
            uid,
            gid,
            name: name.to_string(),
            home: home.display().to_string(),
        })
    });
    TestBearerGuard { previous }
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

pub(crate) fn authorized_capture(
    authorization: &crate::atoms::comparison::ActionAuthorization,
    invocation: &crate::atoms::r#do::InvocationKey,
    program: &str,
    args: &[String],
    timeout: Duration,
) -> Result<crate::atoms::CommandObservation, String> {
    crate::atoms::r#do::run_command::command_with_timeout(authorization, invocation, program, args, timeout)
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

pub(crate) fn capture_with_cwd_as_bearer_and_timeout(
    program: &str,
    args: &[&str],
    cwd: Option<&str>,
    bearer: &str,
    timeout_secs: u64,
) -> CmdResult {
    if unsafe { libc::geteuid() } != 0 {
        return capture_with_options(
            program,
            args,
            CaptureOptions::new().cwd(cwd).timeout_secs(timeout_secs),
        );
    }
    match resolve_non_root_bearer(bearer) {
        Ok(bearer) => capture_with_options(
            program,
            args,
            CaptureOptions::new()
                .cwd(cwd)
                .timeout_secs(timeout_secs)
                .bearer(bearer),
        ),
        Err(err) => CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: err,
        },
    }
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
    capture_with_cwd_as_bearer_and_env_and_timeout(
        program,
        args,
        cwd,
        bearer,
        env,
        DEFAULT_TIMEOUT_SECS,
    )
}

pub(crate) fn capture_with_cwd_as_bearer_and_env_and_timeout(
    program: &str,
    args: &[&str],
    cwd: Option<&str>,
    bearer: &str,
    env: BTreeMap<String, String>,
    timeout_secs: u64,
) -> CmdResult {
    if unsafe { libc::geteuid() } != 0 {
        return capture_with_options(
            program,
            args,
            CaptureOptions::new()
                .cwd(cwd)
                .env(env)
                .timeout_secs(timeout_secs),
        );
    }
    match resolve_non_root_bearer(bearer) {
        Ok(bearer) => capture_with_options(
            program,
            args,
            CaptureOptions::new()
                .cwd(cwd)
                .env(env)
                .timeout_secs(timeout_secs)
                .bearer(bearer),
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
    #[cfg(any(test, feature = "test-facade"))]
    if let Some(injected) = TEST_BEARER.with(|slot| slot.borrow().as_ref().cloned()) {
        if injected.name != bearer {
            return Err(format!("git-bearer-unknown {bearer}"));
        }
        if injected.uid == 0 {
            return Err(format!("git-bearer-root-refused {bearer}"));
        }
        return Ok(injected);
    }
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

pub(crate) fn user_bus_env_for_bearer(bearer: &str) -> Result<BTreeMap<String, String>, String> {
    let bearer = resolve_non_root_bearer(bearer)?;
    let runtime_dir = format!("/run/user/{}", bearer.uid);
    Ok(BTreeMap::from([
        ("XDG_RUNTIME_DIR".to_string(), runtime_dir.clone()),
        (
            "DBUS_SESSION_BUS_ADDRESS".to_string(),
            format!("unix:path={runtime_dir}/bus"),
        ),
    ]))
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
            .env("LOGNAME", &bearer.name)
            .env("XDG_CONFIG_HOME", Path::new(&bearer.home).join(".config"))
            .env_remove("GIT_CONFIG_GLOBAL")
            .env_remove("GIT_CONFIG_SYSTEM")
            .env_remove("GIT_CONFIG_COUNT")
            .env_remove("GIT_ASKPASS")
            .env_remove("SSH_ASKPASS");
        let uid = bearer.uid;
        let gid = bearer.gid;
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut cmd, move || {
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
    let stdout = child.stdout.take().map(|mut pipe| {
        thread::spawn(move || {
            let mut captured = String::new();
            let _ = pipe.read_to_string(&mut captured);
            captured
        })
    });
    let stderr = child.stderr.take().map(|mut pipe| {
        thread::spawn(move || {
            let mut captured = String::new();
            let _ = pipe.read_to_string(&mut captured);
            captured
        })
    });
    let read_pipes = || {
        (
            stdout
                .and_then(|reader| reader.join().ok())
                .unwrap_or_default(),
            stderr
                .and_then(|reader| reader.join().ok())
                .unwrap_or_default(),
        )
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let (stdout, stderr) = read_pipes();
                return CmdResult {
                    ok: status.success(),
                    code: status.code().unwrap_or(-1),
                    stdout: redact(stdout.trim(), &options.redact),
                    stderr: redact(stderr.trim(), &options.redact),
                };
            }
            Ok(None) if start.elapsed() >= Duration::from_secs(timeout_secs) => {
                let termination = terminate_child(&mut child);
                let (stdout, stderr) = read_pipes();
                let signal = format!(
                    "command-timeout-after-{timeout_secs}s: {command_label}: {termination}"
                );
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
                let termination = terminate_child(&mut child);
                let _ = read_pipes();
                return CmdResult {
                    ok: false,
                    code: -1,
                    stdout: String::new(),
                    stderr: format!("command-wait-failed: {command_label}: {err}: {termination}"),
                };
            }
        }
    }
}

fn terminate_child(child: &mut std::process::Child) -> &'static str {
    // This command primitive does not create a process group, so signal only
    // the directly spawned child rather than guessing at ownership of its
    // descendants.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let grace_start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return "terminated-on-sigterm-within-grace",
            Ok(None) if grace_start.elapsed() >= Duration::from_secs(TERMINATION_GRACE_SECS) => {
                let _ = child.kill();
                let _ = child.wait();
                return "killed-after-sigterm-grace-expired";
            }
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return "killed-after-sigterm-grace-wait-failed";
            }
        }
    }
}

fn redact(text: &str, redactions: &BTreeSet<String>) -> String {
    redactions.iter().fold(text.to_string(), |acc, secret| {
        acc.replace(secret, "[REDACTED]")
    })
}

pub(crate) fn execute_validated_step(
    step: &crate::tools::ladder::ValidatedStep,
    module_dir: &std::path::Path,
    apply: bool,
    active_lane: Option<&str>,
) -> Result<crate::OperationOutcome, String> {
    let program = step
        .args
        .get("program")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let argv: Vec<String> = step
        .args
        .get("args")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();
    let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let requested_lane = step.args.get("lane").and_then(serde_json::Value::as_str);
    let lane_matches = requested_lane.is_none() || requested_lane == active_lane;
    let executed = apply && lane_matches;
    let skipped = !executed;
    let result = if executed {
        capture_with_options(
            program,
            &argv_refs,
            CaptureOptions::new()
                .cwd(step.args.get("cwd").and_then(serde_json::Value::as_str))
                .timeout_secs(
                    step.args
                        .get("timeout_secs")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(DEFAULT_TIMEOUT_SECS),
                ),
        )
    } else {
        crate::CmdResult {
            ok: true,
            code: 0,
            stdout: format!("planned command {}", program),
            stderr: String::new(),
        }
    };
    let advisory = step.args.get("advisory").and_then(serde_json::Value::as_bool).unwrap_or(false);
    crate::write_command_receipt_with_policy(
        module_dir,
        &step.step_id,
        program,
        &argv,
        step.args.get("cwd").and_then(serde_json::Value::as_str),
        &result,
        advisory,
        requested_lane,
        active_lane,
        executed,
        skipped,
    )?;
    Ok(crate::OperationOutcome {
        ok: result.ok || advisory || skipped,
        changed: false,
        skipped: !apply || skipped,
        message: if !apply {
            format!("command planned/report-only {}", program)
        } else if !lane_matches {
            format!("command skipped lane mismatch requested={requested_lane:?} active={active_lane:?}")
        } else {
            format!("command capture {}", program)
        },
        command: Some(result),
    })
}

pub(crate) fn command_capture(program: &str, args: &[&str]) -> CmdResult {
    capture(program, args)
}

#[allow(dead_code)]
pub(crate) fn command_capture_with_timeout(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
) -> CmdResult {
    capture_with_timeout(program, args, timeout_secs)
}

pub(crate) fn command_capture_with_cwd(
    program: &str,
    args: &[&str],
    cwd: Option<&str>,
) -> CmdResult {
    capture_with_cwd(program, args, cwd)
}

pub(crate) fn harmonia_root_from_module_root(module_root: &Path) -> PathBuf {
    module_root
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::capture_with_options;

    #[test]
    fn captures_stdout_larger_than_pipe_buffer() {
        let result = capture_with_options(
            "/usr/bin/sh",
            &["-c", "head -c 131072 /dev/zero | tr \"\\0\" x"],
            super::CaptureOptions::new(),
        );
        assert!(result.ok);
        assert_eq!(result.stdout.len(), 131072);
    }

    #[test]
    fn sleeping_child_times_out() {
        let result = capture_with_options(
            "/usr/bin/sh",
            &["-c", "sleep 2"],
            super::CaptureOptions::new().timeout_secs(1),
        );
        assert!(!result.ok);
        assert!(result.stderr.contains("command-timeout-after-1s"));
    }
}
