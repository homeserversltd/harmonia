use crate::atoms;
use crate::CmdResult;
use std::thread;
use std::time::Duration;

pub(super) fn probe(request: &crate::tools::health::ProbeRequest<'_>) -> CmdResult {
    let mut last = run(request);
    for _ in 0..request.retries {
        if matches(&last, request.expected_contains) {
            return last;
        }
        thread::sleep(Duration::from_secs(1));
        last = run(request);
    }
    if last.ok && !matches(&last, request.expected_contains) {
        last.ok = false;
        last.stderr = request
            .expected_contains
            .map(|needle| format!("health-expected-content-missing: {needle}"))
            .unwrap_or_else(|| last.stderr.clone());
    }
    last
}

fn run(request: &crate::tools::health::ProbeRequest<'_>) -> CmdResult {
    let observed = atoms::ask::read_only_command_with_timeout(
        "/usr/bin/curl",
        &[
            "-fsS".into(),
            "--max-time".into(),
            request.timeout_secs.to_string(),
            request.url.into(),
        ],
        Duration::from_secs(request.timeout_secs.saturating_add(1)),
    );
    CmdResult {
        ok: observed.ok,
        code: observed.code.unwrap_or(-1),
        stdout: observed.stdout,
        stderr: observed.stderr,
    }
}
fn matches(result: &CmdResult, expected: Option<&str>) -> bool {
    result.ok
        && expected
            .map(|needle| result.stdout.contains(needle))
            .unwrap_or(true)
}
