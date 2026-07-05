use super::ToolContract;
use crate::CmdResult;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const NAME: &str = "command";
pub const DESCRIPTION: &str = "Host command execution primitive with cwd/env/timeout/exit capture; every subprocess produces a command receipt.";
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION);
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
}

impl<'a> CaptureOptions<'a> {
    pub fn new() -> Self {
        Self {
            cwd: None,
            env: BTreeMap::new(),
            redact: BTreeSet::new(),
            timeout_secs: DEFAULT_TIMEOUT_SECS,
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
    if let Some(cwd) = options.cwd {
        cmd.current_dir(Path::new(cwd));
    }
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
