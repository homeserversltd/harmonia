//! Typed, bounded, non-blocking observation atoms.
#![allow(dead_code)]
use super::{ask_file, CommandObservation, FileObservation, HttpObservation, UnitObservation};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: usize = 16 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(12);

pub(crate) fn file(path: &Path) -> Result<FileObservation, String> {
    ask_file(path)
}

pub(crate) fn file_if_present(path: &Path) -> Result<Option<FileObservation>, String> {
    match File::open(path) {
        Ok(_) => ask_file(path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("ask-file-open: {error}")),
    }
}

pub(crate) fn read_only_command(program: &str, args: &[String]) -> CommandObservation {
    let mut child = match Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return CommandObservation {
                program: program.into(),
                args: args.to_vec(),
                ok: false,
                code: None,
                stdout: String::new(),
                stderr: error.to_string(),
            }
        }
    };
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let out = thread::spawn(move || bounded_read(stdout));
    let err = thread::spawn(move || bounded_read(stderr));
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
    let stdout = out.join().unwrap_or_default();
    let mut stderr = err.join().unwrap_or_default();
    if timed_out {
        stderr = format!(
            "command timed out after {}s; {stderr}",
            COMMAND_TIMEOUT.as_secs()
        );
    }
    CommandObservation {
        program: program.into(),
        args: args.to_vec(),
        ok: status
            .as_ref()
            .is_some_and(std::process::ExitStatus::success),
        code: status.and_then(|s| s.code()),
        stdout,
        stderr,
    }
}

fn bounded_read<R: Read>(mut reader: R) -> String {
    let mut bytes = Vec::with_capacity(OUTPUT_LIMIT.min(4096));
    let mut chunk = [0u8; 4096];
    while bytes.len() < OUTPUT_LIMIT {
        let take = (OUTPUT_LIMIT - bytes.len()).min(chunk.len());
        match reader.read(&mut chunk[..take]) {
            Ok(0) | Err(_) => break,
            Ok(n) => bytes.extend_from_slice(&chunk[..n]),
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

pub(crate) fn unit_state(unit: &str) -> UnitObservation {
    let active = read_only_command("/usr/bin/systemctl", &["is-active".into(), unit.into()]);
    let enabled = read_only_command("/usr/bin/systemctl", &["is-enabled".into(), unit.into()]);
    let show = read_only_command(
        "/usr/bin/systemctl",
        &["show".into(), unit.into(), "-p".into(), "SubState".into()],
    );
    let state = format!(
        "active={:?}; enabled={:?}; show={:?}",
        active.stdout.trim(),
        enabled.stdout.trim(),
        show.stdout.trim()
    );
    UnitObservation {
        unit: unit.into(),
        active: active.ok && active.stdout.trim() == "active",
        enabled: enabled.ok && enabled.stdout.trim() == "enabled",
        state,
        active_query: active,
        enabled_query: enabled,
        show_query: show,
    }
}

pub(crate) fn http_probe(url: &str) -> HttpObservation {
    let result = read_only_command(
        "/usr/bin/curl",
        &[
            "-sS".into(),
            "-o".into(),
            "/dev/null".into(),
            "-w".into(),
            "%{http_code}".into(),
            "--max-time".into(),
            "10".into(),
            url.into(),
        ],
    );
    let status = result.stdout.trim().parse::<u16>().ok().filter(|s| *s != 0);
    HttpObservation {
        url: url.into(),
        reachable: result.ok && status.is_some(),
        status,
    }
}
