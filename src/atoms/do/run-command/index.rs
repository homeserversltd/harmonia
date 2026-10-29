use crate::atoms::r#do::InvocationKey;
use crate::atoms::{CommandObservation, Drift, Receipt};
use crate::atoms::comparison::ActionAuthorization;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
const OUTPUT_LIMIT: usize = 16 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const STDIN_LIMIT: usize = 4096;

/// Input is bounded and is never included in command attestation.
pub(crate) fn command_with_stdin(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    program: &str,
    args: &[String],
    stdin: Option<Vec<u8>>,
    timeout: Duration,
) -> Result<CommandObservation, String> {
    if stdin.as_ref().is_some_and(|bytes| bytes.len() > STDIN_LIMIT) {
        return Err("run-command-stdin-too-large".into());
    }
    let preimage = crate::atoms::ask::run_command::observe(program, args, None);
    let result = run_with_input(program, args, None, &[], timeout, stdin);
    let _ = (authorization, invocation);
    let outcome = CommandObservation { program: program.into(), args: args.to_vec(),
        ok: result.ok, code: result.code, stdout: result.stdout, stderr: result.stderr };
    let _attestation = crate::atoms::attest::run_command::value(&preimage, &serde_json::json!({"ok":outcome.ok,"code":outcome.code}))?;
    Ok(outcome)
}

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
    let preimage = crate::atoms::ask::run_command::observe(program, args, cwd);
    let result = run_with_timeout_in_dir_env(program, args, cwd, environment, timeout);
    let _ = (authorization, invocation);
    let outcome = CommandObservation {
        program: program.into(),
        args: args.to_vec(),
        ok: result.ok,
        code: result.code,
        stdout: result.stdout,
        stderr: result.stderr,
    };
    let _attestation = crate::atoms::attest::run_command::value(&preimage, &outcome)?;
    Ok(outcome)
}

pub(crate) fn command_with_timeout(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    program: &str,
    args: &[String],
    timeout: Duration,
) -> Result<CommandObservation, String> {
    let preimage = crate::atoms::ask::run_command::observe(program, args, None);
    let result = run_with_timeout_in_dir_env(program, args, None, &[], timeout);
    let _ = (authorization, invocation);
    let outcome = CommandObservation {
        program: program.into(), args: args.to_vec(), ok: result.ok,
        code: result.code, stdout: result.stdout, stderr: result.stderr,
    };
    let _attestation = crate::atoms::attest::run_command::value(&preimage, &outcome)?;
    Ok(outcome)
}

/// The public command ceremony's sole action entry: preserve legacy callers
/// above while this bounded route seals its one action to the run log.
pub(crate) fn command_with_timeout_attested(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    program: &str,
    args: &[String],
    cwd: Option<&str>,
    timeout: Duration,
    attest_log: Option<&Path>,
    bearer: Option<&crate::atoms::command::CommandBearer>,
) -> Result<CommandObservation, String> {
    let path_cwd = cwd.map(Path::new);
    let result = if let Some(bearer) = bearer {
        let command = crate::atoms::command::capture_with_command_bearer_and_limit(
            program,
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            cwd,
            timeout.as_secs(),
            bearer,
            Some(OUTPUT_LIMIT),
        );
        ResultData {
            ok: command.ok,
            code: Some(command.code),
            stdout: command.stdout,
            stderr: command.stderr,
        }
    } else {
        run_with_timeout_in_dir_env(program, args, path_cwd, &[], timeout)
    };
    let _ = (authorization, invocation);
    let outcome = CommandObservation {
        program: program.into(), args: args.to_vec(), ok: result.ok,
        code: result.code, stdout: result.stdout, stderr: result.stderr,
    };
    let receipt = Receipt {
        atom: "run-command".into(),
        ok: outcome.ok,
        drift: Drift::Command { expected_code: 0, actual_code: outcome.code },
        // Never place command output, argv, or environment in the shared
        // attestation log; these can carry credentials or private data.
        message: format!("bounded command action completed={}", outcome.ok),
    };
    crate::atoms::attest::attest(attest_log.unwrap_or_else(||Path::new("harmonia")), &receipt, &[], outcome.ok)?;
    Ok(outcome)
}
pub(crate) fn mutating_command(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    program: &str,
    args: &[String],
) -> Result<Receipt, String> {
    let preimage = crate::atoms::ask::run_command::observe(program, args, None);
    let result = run(program, args);
    let outcome = Receipt {
            atom: "do".into(),
            ok: result.ok,
            drift: Drift::Current,
            message: format!(
                "program={program}; args={args:?}; code={:?}; stdout={:?}; stderr={:?}",
                result.code, result.stdout, result.stderr
            ),
        };
    let _attestation = crate::atoms::attest::run_command::value(&preimage, &outcome)?;
    Ok(outcome)
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
    run_with_input(program, args, cwd, environment, timeout, None)
}

fn run_with_input(
    program: &str,
    args: &[String],
    cwd: Option<&Path>,
    environment: &[(String, String)],
    timeout: Duration,
    stdin: Option<Vec<u8>>,
) -> ResultData {
    let mut command = Command::new(program);
    command.args(args);
    command.envs(environment.iter().map(|(key, value)| (key, value)));
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    if stdin.is_some() { command.stdin(Stdio::piped()); }
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
    let mut input_ok = true;
    if let Some(bytes) = stdin {
        if let Some(mut pipe) = child.stdin.take() {
            use std::os::fd::AsRawFd;
            let fd = pipe.as_raw_fd();
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            input_ok = flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0
                && pipe.write_all(&bytes).is_ok();
        } else {
            input_ok = false;
        }
    }
    let out = child
        .stdout
        .take()
        .map(|reader| thread::spawn(move || bounded(reader)));
    let err = child
        .stderr
        .take()
        .map(|reader| thread::spawn(move || bounded(reader)));
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
        ok: input_ok && status
            .as_ref()
            .is_some_and(std::process::ExitStatus::success),
        code: status.and_then(|status| status.code()),
        stdout,
        stderr,
    }
}

fn bounded(reader: impl Read) -> String {
    let output = crate::atoms::command::read_bounded_output(reader, OUTPUT_LIMIT);
    crate::atoms::command::format_bounded_output_for_receipt(output, OUTPUT_LIMIT)
}
