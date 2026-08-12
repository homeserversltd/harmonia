//! Authorized mutation atom. Every operation consumes both keys.
#![allow(dead_code)]

use super::{backup_first_write, Receipt};
use crate::tools::comparison::ActionAuthorization;
use std::io::Read;
use std::path::Path;
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

pub(crate) fn file_write(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    path: &Path,
    bytes: &[u8],
) -> Result<Receipt, String> {
    backup_first_write(path, bytes)?;
    apply(
        authorization,
        invocation,
        Receipt {
            atom: "do".into(),
            ok: true,
            drift: super::Drift::Current,
            message: "file write complete".into(),
        },
    )
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
