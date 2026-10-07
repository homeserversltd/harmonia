use crate::CmdResult;
#[cfg(any(test, feature = "test-facade"))]
use std::collections::HashMap;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
#[cfg(any(test, feature = "test-facade"))]
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const NAME: &str = "command";
pub const DEFAULT_TIMEOUT_SECS: u64 = 900;
const DEFAULT_SYSTEM_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

const TERMINATION_GRACE_SECS: u64 = 3;
const RECEIPT_OUTPUT_LIMIT: usize = 16 * 1024;

pub(crate) struct BoundedOutput {
    pub(crate) text: String,
    pub(crate) discarded: bool,
}

pub(crate) fn read_bounded_output<R: Read>(mut reader: R, limit: usize) -> BoundedOutput {
    let mut bytes = Vec::with_capacity(limit.min(4096));
    let mut chunk = [0u8; 4096];
    let mut discarded = false;
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                let retained = count.min(limit.saturating_sub(bytes.len()));
                bytes.extend_from_slice(&chunk[..retained]);
                if retained < count {
                    discarded = true;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    BoundedOutput {
        text: String::from_utf8_lossy(&bytes).into_owned(),
        discarded,
    }
}

pub(crate) fn format_bounded_output_for_receipt(output: BoundedOutput, limit: usize) -> String {
    let mut text = output.text;
    if output.discarded {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&format!("[output truncated after first {limit} bytes]"));
    }
    text
}

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
    output_limit: Option<usize>,
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
#[derive(Clone)]
enum TestBearerOverride {
    #[cfg(feature = "test-facade")]
    CurrentEffectiveUser,
    Fixed(Bearer),
}

#[cfg(any(test, feature = "test-facade"))]
struct TestBearerScope {
    id: u64,
    value: TestBearerOverride,
}

#[cfg(any(test, feature = "test-facade"))]
#[derive(Default)]
struct TestBearerRegistry {
    next_scope_id: u64,
    by_thread: HashMap<thread::ThreadId, Vec<TestBearerScope>>,
}

#[cfg(any(test, feature = "test-facade"))]
static TEST_BEARER: OnceLock<Mutex<TestBearerRegistry>> = OnceLock::new();

#[cfg(any(test, feature = "test-facade"))]
pub(crate) struct TestBearerGuard {
    thread_id: thread::ThreadId,
    scope_id: u64,
}

#[cfg(any(test, feature = "test-facade"))]
impl Drop for TestBearerGuard {
    fn drop(&mut self) {
        let mut registry = TEST_BEARER
            .get_or_init(|| Mutex::new(TestBearerRegistry::default()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let remove_thread = if let Some(scopes) = registry.by_thread.get_mut(&self.thread_id) {
            if let Some(index) = scopes.iter().position(|scope| scope.id == self.scope_id) {
                scopes.remove(index);
            }
            scopes.is_empty()
        } else {
            false
        };
        if remove_thread {
            registry.by_thread.remove(&self.thread_id);
        }
    }
}

#[cfg(any(test, feature = "test-facade"))]
fn install_test_bearer_override(value: TestBearerOverride) -> TestBearerGuard {
    let thread_id = thread::current().id();
    let mut registry = TEST_BEARER
        .get_or_init(|| Mutex::new(TestBearerRegistry::default()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let scope_id = registry.next_scope_id;
    registry.next_scope_id = registry.next_scope_id.wrapping_add(1);
    registry
        .by_thread
        .entry(thread_id)
        .or_default()
        .push(TestBearerScope {
            id: scope_id,
            value,
        });
    TestBearerGuard {
        thread_id,
        scope_id,
    }
}

#[cfg(any(test, feature = "test-facade"))]
pub(crate) fn install_test_bearer(name: &str, uid: u32, gid: u32, home: &Path) -> TestBearerGuard {
    install_test_bearer_override(TestBearerOverride::Fixed(Bearer {
        uid,
        gid,
        name: name.to_string(),
        home: home.display().to_string(),
    }))
}

#[cfg(feature = "test-facade")]
pub(crate) fn install_test_current_effective_user() -> TestBearerGuard {
    install_test_bearer_override(TestBearerOverride::CurrentEffectiveUser)
}

#[cfg(any(test, feature = "test-facade"))]
fn current_test_bearer_override() -> Option<TestBearerOverride> {
    let thread_id = thread::current().id();
    let registry = TEST_BEARER
        .get_or_init(|| Mutex::new(TestBearerRegistry::default()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    registry
        .by_thread
        .get(&thread_id)
        .and_then(|scopes| scopes.last())
        .map(|scope| scope.value.clone())
}

impl<'a> CaptureOptions<'a> {
    pub fn new() -> Self {
        Self {
            cwd: None,
            env: BTreeMap::new(),
            redact: BTreeSet::new(),
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            output_limit: None,
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
    pub fn output_limit(mut self, output_limit: usize) -> Self {
        self.output_limit = Some(output_limit);
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
    cwd: Option<&str>,
    timeout: Duration,
    attest_log: &Path,
) -> Result<crate::atoms::CommandObservation, String> {
    crate::atoms::r#do::run_command::command_with_timeout_attested(authorization, invocation, program, args, cwd, timeout, attest_log)
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
    let bearer = match resolve_bearer_for_capture(bearer) {
        Ok(bearer) => bearer,
        Err(err) => {
            return CmdResult {
                ok: false,
                code: -1,
                stdout: String::new(),
                stderr: err,
            }
        }
    };
    let mut options = CaptureOptions::new().cwd(cwd).timeout_secs(timeout_secs);
    if let Some(bearer) = bearer {
        options = options.bearer(bearer);
    }
    capture_with_options(program, args, options)
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
    let bearer = match resolve_bearer_for_capture(bearer) {
        Ok(bearer) => bearer,
        Err(err) => {
            return CmdResult {
                ok: false,
                code: -1,
                stdout: String::new(),
                stderr: err,
            }
        }
    };
    let mut options = CaptureOptions::new()
        .cwd(cwd)
        .env(env)
        .timeout_secs(timeout_secs);
    if let Some(bearer) = bearer {
        options = options.bearer(bearer);
    }
    capture_with_options(program, args, options)
}

fn resolve_bearer_for_capture(bearer: &str) -> Result<Option<Bearer>, String> {
    #[cfg(feature = "test-facade")]
    if matches!(
        current_test_bearer_override(),
        Some(TestBearerOverride::CurrentEffectiveUser)
    ) {
        return Ok(None);
    }
    if unsafe { libc::geteuid() } != 0 {
        Ok(None)
    } else {
        resolve_non_root_bearer(bearer).map(Some)
    }
}

fn resolve_non_root_bearer(bearer: &str) -> Result<Bearer, String> {
    let name = std::ffi::CString::new(bearer).map_err(|_| "git-bearer-invalid-name".to_string())?;
    #[cfg(any(test, feature = "test-facade"))]
    if let Some(TestBearerOverride::Fixed(injected)) = current_test_bearer_override() {
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
    // The limit belongs only to command receipts. Internal Git/JSON/
    // expected_stdout captures remain unbounded and keep their old trim behavior.
    let output_limit = options.output_limit;
    let stdout = child.stdout.take().map(|pipe| {
        thread::spawn(move || {
            if let Some(limit) = output_limit {
                format_bounded_output_for_receipt(read_bounded_output(pipe, limit), limit)
            } else {
                let mut pipe = pipe;
                let mut captured = String::new();
                let _ = pipe.read_to_string(&mut captured);
                captured
            }
        })
    });
    let stderr = child.stderr.take().map(|pipe| {
        thread::spawn(move || {
            if let Some(limit) = output_limit {
                format_bounded_output_for_receipt(read_bounded_output(pipe, limit), limit)
            } else {
                let mut pipe = pipe;
                let mut captured = String::new();
                let _ = pipe.read_to_string(&mut captured);
                captured
            }
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
                let (stdout, stderr) = if output_limit.is_some() {
                    // Bounded output is a receipt head: preserve its leading
                    // bytes instead of applying the legacy unbounded trim.
                    (
                        redact(&stdout, &options.redact),
                        redact(&stderr, &options.redact),
                    )
                } else {
                    (
                        redact(stdout.trim(), &options.redact),
                        redact(stderr.trim(), &options.redact),
                    )
                };
                return CmdResult {
                    ok: status.success(),
                    code: status.code().unwrap_or(-1),
                    stdout,
                    stderr,
                };
            }
            Ok(None) if start.elapsed() >= Duration::from_secs(timeout_secs) => {
                let termination = terminate_child(&mut child);
                let (stdout, stderr) = read_pipes();
                let signal = format!(
                    "command-timeout-after-{timeout_secs}s: {command_label}: {termination}"
                );
                let (stdout, stderr) = if output_limit.is_some() {
                    let stderr = if stderr.is_empty() {
                        signal
                    } else {
                        format!("{stderr}\n{signal}")
                    };
                    (
                        redact(&stdout, &options.redact),
                        redact(&stderr, &options.redact),
                    )
                } else {
                    let stderr = if stderr.trim().is_empty() {
                        signal
                    } else {
                        format!("{}\n{}", stderr.trim(), signal)
                    };
                    (
                        redact(stdout.trim(), &options.redact),
                        redact(&stderr, &options.redact),
                    )
                };
                return CmdResult {
                    ok: false,
                    code: -1,
                    stdout,
                    stderr,
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
    source_module_dir: &std::path::Path,
    apply: bool,
    active_lane: Option<&str>,
    module_changed_before_step: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<crate::OperationOutcome, String> {
    let program = step.args.get("program").and_then(serde_json::Value::as_str).unwrap_or("");
    let argv: Vec<String> = step.args.get("args").and_then(serde_json::Value::as_array)
        .map(|items| items.iter().filter_map(serde_json::Value::as_str).map(ToString::to_string).collect())
        .unwrap_or_default();
    let requested_lane = step.args.get("lane").and_then(serde_json::Value::as_str);
    let lane_matches = requested_lane.is_none() || requested_lane == active_lane;
    let timeout = step.args.get("timeout_secs").and_then(serde_json::Value::as_u64).unwrap_or(DEFAULT_TIMEOUT_SECS);
    let cwd = step.args.get("cwd").and_then(serde_json::Value::as_str).map(|value| expand_module_dir(value, source_module_dir));
    let program = expand_module_dir(program, source_module_dir);
    let argv = argv.iter().map(|value| expand_module_dir(value, source_module_dir)).collect::<Vec<_>>();
    let is_act = step.permutation == "act";
    let mut decision = "not-applicable";
    let mut observed_state = serde_json::Value::Null;
    let mut final_observed_state = serde_json::Value::Null;
    let mut desired_state = serde_json::Value::Null;
    let mut result = if is_act {
        let observation = step.args.get("observation").ok_or("observation-missing")?;
        let mut observation_failure = None;
        let same = if observation.get("kind").and_then(serde_json::Value::as_str) == Some("module_changed_before_step") {
            observed_state = serde_json::json!({"kind":"module_changed_before_step","value":module_changed_before_step});
            desired_state = serde_json::json!({"kind":"module_changed_before_step","value":false});
            !module_changed_before_step
        } else {
        let observation_program = observation.get("program").and_then(serde_json::Value::as_str).ok_or("observation-program-missing")?;
        let observation_program = expand_module_dir(observation_program, source_module_dir);
        let observation_args: Vec<String> = observation.get("args").and_then(serde_json::Value::as_array)
            .map(|items| items.iter().filter_map(serde_json::Value::as_str).map(|value| expand_module_dir(value, source_module_dir)).collect()).unwrap_or_default();
        let expected_code = observation.get("expected_exit_code").and_then(serde_json::Value::as_i64).ok_or("observation-expected-exit-code-missing")? as i32;
        let expected_stdout = observation.get("expected_stdout").and_then(serde_json::Value::as_str);
        let observation_cwd = observation.get("cwd").and_then(serde_json::Value::as_str).map(|value| expand_module_dir(value, source_module_dir));
        let probe = capture_with_options(&observation_program, &observation_args.iter().map(String::as_str).collect::<Vec<_>>(), CaptureOptions::new().cwd(observation_cwd.as_deref()).timeout_secs(timeout));
        observed_state = serde_json::json!({"program":observation_program,"args":observation_args,"exit_code":probe.code,"stdout":probe.stdout,"stderr":probe.stderr});
        desired_state = serde_json::json!({"exit_code":expected_code,"stdout":expected_stdout});
        if probe.code < 0 { observation_failure = Some(format!("command-act-observation-failed: {}", probe.stderr)); }
        probe.code >= 0 && probe.code == expected_code
            && expected_stdout.map_or(true, |expected| probe.stdout == expected)
        };
        decision = if observation_failure.is_some() {
            "Blocked"
        } else if same {
            "Empty"
        } else {
            "Different"
        };
        let do_apply = apply && lane_matches;
        if let Some(failure) = observation_failure {
            (Some(crate::CmdResult {ok:false, code:-1, stdout:String::new(), stderr:failure}), false)
        } else if do_apply {
            let outcome = crate::atoms::comparison::execute_once(
                "run-command",
                || Ok::<_, String>(same),
                |current| if *current { crate::atoms::comparison::DiffDecision::Empty } else { crate::atoms::comparison::DiffDecision::Different },
                |authorization, _| {
                    let invocation = invocation.ok_or("invocation-key-missing")?;
                    authorized_capture(&authorization, invocation, &program, &argv, cwd.as_deref(), Duration::from_secs(timeout), &module_dir.join("harmonia-atoms.log"))
                },
            )?;
            match outcome {
                crate::atoms::comparison::ComparisonRun::Current { .. } => (None, false),
                crate::atoms::comparison::ComparisonRun::Moved { movement, .. } => {
                    let mut moved = crate::CmdResult {
                        ok: movement.ok,
                        code: movement.code.unwrap_or(-1),
                        stdout: movement.stdout,
                        stderr: movement.stderr,
                    };
                    if moved.ok {
                        if let Some((final_state, converged)) = observe_after_command(observation, source_module_dir, timeout)? {
                            final_observed_state = final_state.clone();
                            if !converged {
                                moved.ok = false;
                                if final_state.get("exit_code").and_then(serde_json::Value::as_i64).is_some_and(|code| code < 0) {
                                    moved.stderr = final_state.get("stderr").and_then(serde_json::Value::as_str).unwrap_or("command-act-observation-failed").to_string();
                                } else {
                                    moved.stderr = format!("act-did-not-converge: final observation differs after command; {}", moved.stderr);
                                }
                            }
                        }
                    }
                    (Some(moved), true)
                },
            }
        } else {
            (None, false)
        }
    } else {
        decision = "observation";
        let capture_options = CaptureOptions::new()
            .cwd(cwd.as_deref())
            .timeout_secs(timeout);
        let capture_options = if step.permutation == "capture" {
            capture_options.output_limit(RECEIPT_OUTPUT_LIMIT)
        } else {
            capture_options
        };
        let probe = capture_with_options(
            &program,
            &argv.iter().map(String::as_str).collect::<Vec<_>>(),
            capture_options,
        );
        observed_state = serde_json::json!({"exit_code":probe.code,"stdout":probe.stdout,"stderr":probe.stderr});
        (Some(probe), true)
    };
    let command_result = result.0;
    let executed = result.1;
    let skipped = !executed;
    let advisory = !is_act && step.args.get("advisory").and_then(serde_json::Value::as_bool).unwrap_or(false);
    // A command invocation is movement attempted, not proof that the
    // commanded world changed. Do not promote an exit status to a change.
    let comparison_changed = is_act && decision == "Different";
    let changed = is_act
        && executed
        && comparison_changed
        && command_result.as_ref().is_some_and(|result| result.ok);
    if is_act {
        crate::receipts::write_command_comparison_receipt(
            module_dir,
            &step.step_id,
            &observed_state,
            &desired_state,
            decision,
            executed,
            changed,
            &final_observed_state,
            command_result.as_ref(),
        )?;
    } else {
        crate::write_command_receipt_with_policy(
            module_dir, &step.step_id, &program, &argv, cwd.as_deref(), command_result.as_ref().ok_or("command-result-missing")?,
            advisory, requested_lane, active_lane, executed, skipped,
        )?;
    }
    Ok(crate::OperationOutcome {
        ok: command_result.as_ref().is_none_or(|result| result.ok || (!is_act && (advisory || skipped))),
        changed,
        skipped,
        message: if is_act { format!("command act diff={decision} executed={executed}") } else if !apply { format!("command report-only probe {program}") } else { format!("command capture {program}") },
        command: command_result,
    })
}


fn observe_after_command(observation: &serde_json::Value, module_dir: &Path, timeout: u64) -> Result<Option<(serde_json::Value, bool)>, String> {
    if observation.get("kind").and_then(serde_json::Value::as_str) == Some("module_changed_before_step") { return Ok(None); }
    let program = observation.get("program").and_then(serde_json::Value::as_str).ok_or("observation-program-missing")?;
    let program = expand_module_dir(program, module_dir);
    let args = observation.get("args").and_then(serde_json::Value::as_array).map(|items| items.iter().filter_map(serde_json::Value::as_str).map(|value| expand_module_dir(value, module_dir)).collect::<Vec<_>>()).unwrap_or_default();
    let cwd = observation.get("cwd").and_then(serde_json::Value::as_str).map(|value| expand_module_dir(value, module_dir));
    let expected_code = observation.get("expected_exit_code").and_then(serde_json::Value::as_i64).ok_or("observation-expected-exit-code-missing")? as i32;
    let expected_stdout = observation.get("expected_stdout").and_then(serde_json::Value::as_str);
    let probe = capture_with_options(&program, &args.iter().map(String::as_str).collect::<Vec<_>>(), CaptureOptions::new().cwd(cwd.as_deref()).timeout_secs(timeout));
    let converged = probe.code >= 0 && probe.code == expected_code && expected_stdout.map_or(true, |expected| probe.stdout == expected);
    Ok(Some((serde_json::json!({"program":program,"args":args,"exit_code":probe.code,"stdout":probe.stdout,"stderr":probe.stderr}), converged)))
}

fn expand_module_dir(value: &str, module_dir: &Path) -> String {
    value.replace("${module_dir}", &module_dir.display().to_string())
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
