use crate::atoms::r#do::InvocationKey;
use crate::atoms::{CommandObservation, Drift, Receipt};
use crate::atoms::comparison::ActionAuthorization;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
const OUTPUT_LIMIT: usize = 16 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn command_with_timeout_in_dir(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    program: &str,
    args: &[String],
    cwd: Option<&Path>,
    timeout: Duration,
) -> Result<CommandObservation, String> {
    command_with_timeout_in_dir_env(authorization, invocation, program, args, cwd, &[], timeout)
}

pub(crate) fn command_with_timeout_in_dir_env(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    program: &str,
    args: &[String],
    cwd: Option<&Path>,
    environment: &[(String, String)],
    timeout: Duration,
) -> Result<CommandObservation, String> {
    let _pre_image = crate::atoms::ask::run_command::observe(program, args, cwd)?;
    let result = run_with_timeout_in_dir_env(program, args, cwd, environment, timeout);
    let _ = (authorization, invocation);
    Ok(CommandObservation {
        program: program.into(),
        args: args.to_vec(),
        ok: result.ok,
        code: result.code,
        stdout: result.stdout,
        stderr: result.stderr,
    })
}

pub(crate) fn command_with_timeout(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    program: &str,
    args: &[String],
    timeout: Duration,
) -> Result<CommandObservation, String> {
    let _pre_image = crate::atoms::ask::run_command::observe(program, args, None)?;
    let result = run_with_timeout(program, args, timeout);
    let _ = (authorization, invocation);
    Ok(CommandObservation {
        program: program.into(),
        args: args.to_vec(),
        ok: result.ok,
        code: result.code,
        stdout: result.stdout,
        stderr: result.stderr,
    })
}
pub(crate) fn mutating_command(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    program: &str,
    args: &[String],
) -> Result<Receipt, String> {
    let result = run(program, args);
    Ok(Receipt {
            atom: "do".into(),
            ok: result.ok,
            drift: Drift::Current,
            message: format!(
                "program={program}; args={args:?}; code={:?}; stdout={:?}; stderr={:?}",
                result.code, result.stdout, result.stderr
            ),
        }
    )
}

pub(crate) struct ResultData {
    pub(crate) ok: bool,
    pub(crate) code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

pub(crate) fn run(program: &str, args: &[String]) -> ResultData {
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
