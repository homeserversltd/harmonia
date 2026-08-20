use crate::CmdResult;
use std::fs::{self, OpenOptions};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const BODY_EXCERPT_LIMIT: usize = 4096;

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
            return last.result;
        }
        thread::sleep(Duration::from_secs(1));
        last = run_probe(request);
    }
    if last.result.ok && !last.expected_matched {
        last.result.ok = false;
        last.result.stderr = request
            .expected_contains
            .map(|needle| format!("health-expected-content-missing: {needle}"))
            .unwrap_or_else(|| last.result.stderr.clone());
    }
    last.result
}

struct ProbeRun {
    result: CmdResult,
    expected_matched: bool,
}

fn run_probe(request: &ProbeRequest<'_>) -> ProbeRun {
    let mut curl_args = vec![
        "-fsS".into(),
        "--max-time".into(),
        request.timeout_secs.to_string(),
    ];
    let temp_path = request.expected_contains.and_then(|_| {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        (0..100).find_map(|attempt| {
            let path = std::env::temp_dir().join(format!(
                "harmonia-health-probe-{}-{stamp}-{attempt}",
                std::process::id()
            ));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => Some(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(_) => None,
            }
        })
    });
    let temp_path = match (request.expected_contains, temp_path) {
        (None, _) => None,
        (Some(_), Some(path)) => Some(path),
        (Some(_), None) => {
            return ProbeRun {
                result: CmdResult {
                    ok: false,
                    code: -1,
                    stdout: String::new(),
                    stderr: "health-probe-temp-file-create-failed".into(),
                },
                expected_matched: false,
            }
        }
    };
    if let Some(path) = &temp_path {
        curl_args.extend(["-o".into(), path.to_string_lossy().into_owned()]);
    } else {
        curl_args.extend(["-o".into(), "/dev/null".into()]);
    }
    curl_args.push(request.url.into());
    let observed = crate::atoms::ask::read_only_command_with_timeout(
        "/usr/bin/curl",
        &curl_args,
        Duration::from_secs(request.timeout_secs.saturating_add(1)),
    );
    let (stdout, stderr, expected_matched, read_ok) = if let Some(path) = temp_path {
        let body = fs::read(&path);
        let _ = fs::remove_file(&path);
        match body {
            Ok(body) => {
                let expected_matched = body_contains(&body, request.expected_contains);
                (
                    body_excerpt(&body, request.expected_contains),
                    observed.stderr,
                    expected_matched,
                    true,
                )
            }
            Err(error) => (
                String::new(),
                format!(
                    "{}; health-probe-temp-file-read-failed: {error}",
                    observed.stderr
                ),
                false,
                false,
            ),
        }
    } else {
        (String::new(), observed.stderr, true, true)
    };
    ProbeRun {
        result: CmdResult {
            ok: observed.ok && read_ok,
            code: observed.code.unwrap_or(-1),
            stdout,
            stderr,
        },
        expected_matched,
    }
}

fn body_contains(body: &[u8], expected: Option<&str>) -> bool {
    match expected.map(str::as_bytes) {
        None => true,
        Some([]) => true,
        Some(needle) => body.windows(needle.len()).any(|window| window == needle),
    }
}

fn body_excerpt(body: &[u8], expected: Option<&str>) -> String {
    let needle = expected.map(str::as_bytes);
    let match_start = needle.and_then(|needle| {
        if needle.is_empty() {
            Some(0)
        } else {
            body.windows(needle.len())
                .position(|window| window == needle)
        }
    });
    let start = match_start
        .map(|position| position.saturating_sub(BODY_EXCERPT_LIMIT / 2))
        .unwrap_or(0);
    String::from_utf8_lossy(&body[start..body.len().min(start + BODY_EXCERPT_LIMIT)]).into_owned()
}

fn matches_expected(run: &ProbeRun, expected: Option<&str>) -> bool {
    run.result.ok && expected.map(|_| run.expected_matched).unwrap_or(true)
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
