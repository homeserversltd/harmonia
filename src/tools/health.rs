use super::{ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::{tools, CmdResult};
use std::thread;
use std::time::Duration;

pub const NAME: &str = "health";
pub const DESCRIPTION: &str =
    "HTTP health probe primitive with curl-backed retry and timeout controls.";
pub const PERMUTATIONS: &[ToolPermutation] = &[ToolPermutation::new(
    "probe",
    "probe an HTTP endpoint with optional expected content and retry controls",
    &[
        ToolArg::required("url", ToolArgKind::String),
        ToolArg::optional("expected_contains", ToolArgKind::String),
        ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ToolArg::optional("retries", ToolArgKind::Integer),
    ],
)];
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION, PERMUTATIONS);

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
    let mut last = tools::command::capture(
        "/usr/bin/curl",
        &[
            "-fsS",
            "--max-time",
            &request.timeout_secs.to_string(),
            request.url,
        ],
    );
    for _ in 0..request.retries {
        if command_matches(&last, request.expected_contains) {
            return last;
        }
        thread::sleep(Duration::from_secs(1));
        last = tools::command::capture(
            "/usr/bin/curl",
            &[
                "-fsS",
                "--max-time",
                &request.timeout_secs.to_string(),
                request.url,
            ],
        );
    }
    if last.ok && !command_matches(&last, request.expected_contains) {
        last.ok = false;
        last.stderr = request
            .expected_contains
            .map(|needle| format!("health-expected-content-missing: {needle}"))
            .unwrap_or_else(|| last.stderr.clone());
    }
    last
}

fn command_matches(result: &CmdResult, expected_contains: Option<&str>) -> bool {
    result.ok
        && expected_contains
            .map(|needle| result.stdout.contains(needle))
            .unwrap_or(true)
}
