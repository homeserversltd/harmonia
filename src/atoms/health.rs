use crate::CmdResult;
use std::thread;
use std::time::Duration;

const NAME: &str = "health";

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

pub fn health_request(action: impl Into<String>) -> Request {
    Request::new(action)
}
pub fn probe(url: impl Into<String>) -> Request {
    Request {
        action: "probe".to_string(),
        target: url.into(),
        args: Vec::new(),
    }
}
pub fn plan(request: &Request) -> Outcome {
    Outcome {
        ok: true,
        changed: false,
        message: format!("{} {} planned for {}", NAME, request.action, request.target),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ProbeRequest<'a> {
    pub url: &'a str,
    pub retries: usize,
    pub timeout_secs: u64,
    pub expected_contains: Option<&'a str>,
}

impl<'a> ProbeRequest<'a> {
    pub(crate) fn new(url: &'a str) -> Self {
        Self {
            url,
            retries: 5,
            timeout_secs: 3,
            expected_contains: None,
        }
    }
}

pub(crate) fn curl_probe(request: &ProbeRequest<'_>) -> CmdResult {
    let mut last = run_probe(request);
    for _ in 0..request.retries {
        if matches_expected(&last, request.expected_contains) {
            return last;
        }
        thread::sleep(Duration::from_secs(1));
        last = run_probe(request);
    }
    if last.ok && !matches_expected(&last, request.expected_contains) {
        last.ok = false;
        last.stderr = request
            .expected_contains
            .map(|needle| format!("health-expected-content-missing: {needle}"))
            .unwrap_or_else(|| last.stderr.clone());
    }
    last
}
fn run_probe(request: &ProbeRequest<'_>) -> CmdResult {
    let mut curl_args = vec![
        "-fsS".into(),
        "--max-time".into(),
        request.timeout_secs.to_string(),
    ];
    if request.expected_contains.is_none() {
        curl_args.extend(["-o".into(), "/dev/null".into()]);
    }
    curl_args.push(request.url.into());
    let observed = crate::atoms::ask::read_only_command_with_timeout(
        "/usr/bin/curl",
        &curl_args,
        Duration::from_secs(request.timeout_secs.saturating_add(1)),
    );
    CmdResult {
        ok: observed.ok,
        code: observed.code.unwrap_or(-1),
        stdout: observed.stdout,
        stderr: observed.stderr,
    }
}
fn matches_expected(result: &CmdResult, expected: Option<&str>) -> bool {
    result.ok
        && expected
            .map(|needle| result.stdout.contains(needle))
            .unwrap_or(true)
}

pub(crate) fn execute_validated_step(
    step: &crate::ladder::ValidatedStep,
    module_dir: &std::path::Path,
    apply: bool,
) -> Result<crate::OperationOutcome, String> {
    let url = step
        .args
        .get("url")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let result = if apply {
        let mut request = ProbeRequest::new(url);
        request.expected_contains = step
            .args
            .get("expected_contains")
            .and_then(serde_json::Value::as_str);
        request.timeout_secs = step
            .args
            .get("timeout_secs")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(3);
        request.retries = step
            .args
            .get("retries")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as usize;
        curl_probe(&request)
    } else {
        crate::CmdResult {
            ok: true,
            code: 0,
            stdout: format!("planned health probe {}", url),
            stderr: String::new(),
        }
    };
    crate::write_command_receipt(module_dir, &step.step_id, &result)?;
    Ok(crate::OperationOutcome {
        ok: result.ok,
        changed: false,
        skipped: !apply,
        message: format!("health probe {}", url),
        command: Some(result),
    })
}
