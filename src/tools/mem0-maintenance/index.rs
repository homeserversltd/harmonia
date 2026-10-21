//! Observe/compare/promote one committed source subtree without fetching or receipts.
use crate::atoms::ask::mem0_maintenance as ask;
use crate::atoms::comparison::{DiffDecision, ComparisonRun};
use crate::atoms::r#do::InvocationKey;
use crate::{OperationOutcome, SoftwareApplyAuthorization};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const REQUEST_LIMIT: u64 = 64 * 1024;
const MAX_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Request {
    pub owner: String,
    pub source_root: PathBuf,
    pub subtree: PathBuf,
    pub app_root: PathBuf,
    pub unit: Option<String>,
    pub health_url: Option<String>,
    pub timeout_secs: u64,
    #[serde(default)]
    pub identity_json_pointer: Option<String>,
    #[serde(default)]
    pub promotion_boot_id: Option<String>,
    #[serde(default)]
    pub promotion_monotonic_usec: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Output {
    pub action: String,
    pub ok: bool,
    pub changed: bool,
    pub status: String,
    pub owner: String,
    pub source_root: String,
    pub subtree: String,
    pub app_root: String,
    pub source_head: Option<String>,
    pub source_tree: Option<String>,
    pub recorded_head: Option<String>,
    pub recorded_tree: Option<String>,
    pub diff: String,
    pub predecessor: String,
    pub restart: Option<String>,
    pub health: Option<String>,
    pub runtime_identity: Option<String>,
    pub identity_evidence: Option<String>,
    pub process_main_pid: Option<u32>,
    pub process_start_monotonic_usec: Option<String>,
    pub process_boot_id: Option<String>,
    pub process_cwd_binding: Option<bool>,
    pub process_cmdline_binding: Option<bool>,
    pub promotion_boot_id: Option<String>,
    pub promotion_monotonic_usec: Option<u64>,
    pub first_missing_signal: Option<String>,
}

impl Output {
    fn observation(request: &Request, observation: &ask::Observation, action: &str) -> Self {
        let absent = observation.first_missing_signal.as_deref() == Some("managed-subtree-absent");
        Self {
            action: action.to_owned(),
            ok: !absent,
            changed: observation.changed,
            status: if absent { "unproven".into() } else if observation.changed { "diff".into() } else { "current".into() },
            owner: request.owner.clone(),
            source_root: request.source_root.display().to_string(),
            subtree: request.subtree.display().to_string(),
            app_root: request.app_root.display().to_string(),
            source_head: Some(observation.source_head.clone()),
            source_tree: Some(observation.source_tree.clone()),
            recorded_head: observation.recorded_head.clone(),
            recorded_tree: observation.recorded_tree.clone(),
            diff: if observation.changed { "different" } else { "empty" }.into(),
            predecessor: crate::atoms::r#do::mem0_maintenance::predecessor_path(request).display().to_string(),
            restart: None,
            health: None,
            runtime_identity: None,
            identity_evidence: None,
            process_main_pid: None,
            process_start_monotonic_usec: None,
            process_boot_id: None,
            process_cwd_binding: None,
            process_cmdline_binding: None,
            promotion_boot_id: None,
            promotion_monotonic_usec: None,
            first_missing_signal: observation.first_missing_signal.clone(),
        }
    }

    fn failure(request: Option<&Request>, action: &str, error: &str) -> Self {
        let empty = PathBuf::new();
        Self {
            action: action.to_owned(),
            ok: false,
            changed: false,
            status: "refused".into(),
            owner: request.map(|r| r.owner.clone()).unwrap_or_default(),
            source_root: request.map(|r| r.source_root.display().to_string()).unwrap_or_default(),
            subtree: request.map(|r| r.subtree.display().to_string()).unwrap_or_default(),
            app_root: request.map(|r| r.app_root.display().to_string()).unwrap_or_else(|| empty.display().to_string()),
            source_head: None,
            source_tree: None,
            recorded_head: None,
            recorded_tree: None,
            diff: "unknown".into(),
            predecessor: request.map(|r| crate::atoms::r#do::mem0_maintenance::predecessor_path(r).display().to_string()).unwrap_or_default(),
            restart: None,
            health: None,
            runtime_identity: None,
            identity_evidence: None,
            process_main_pid: None,
            process_start_monotonic_usec: None,
            process_boot_id: None,
            process_cwd_binding: None,
            process_cmdline_binding: None,
            promotion_boot_id: None,
            promotion_monotonic_usec: None,
            first_missing_signal: Some(error.to_owned()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Observe,
    Act,
    ReportHome,
}
impl Action {
    fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Act => "act",
            Self::ReportHome => "report-home",
        }
    }
}

#[derive(Debug)]
struct Cli {
    action: Action,
    request_path: PathBuf,
    apply: bool,
}

fn parse_cli(args: &[String]) -> Result<Cli, String> {
    let action = match args.first().map(String::as_str) {
        Some("observe") => Action::Observe,
        Some("act") => Action::Act,
        Some("report-home") => Action::ReportHome,
        _ => return Err("mem0-maintenance-action-must-be-observe-act-or-report-home".into()),
    };
    let mut request_path = None;
    let mut apply = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--request" if request_path.is_none() && index + 1 < args.len() => {
                let path = PathBuf::from(&args[index + 1]);
                if !path.is_absolute() || !lexical_absolute_path(&path) {
                    return Err("mem0-maintenance-request-path-must-be-absolute-and-normalized".into());
                }
                request_path = Some(path);
                index += 2;
            }
            "--apply" if !apply => {
                apply = true;
                index += 1;
            }
            _ => return Err("mem0-maintenance-cli-arguments-invalid".into()),
        }
    }
    if apply && action != Action::Act {
        return Err("mem0-maintenance-apply-only-valid-for-act".into());
    }
    Ok(Cli {
        action,
        request_path: request_path.ok_or("mem0-maintenance-request-path-required")?,
        apply,
    })
}

pub(crate) fn cli_apply_requested(args: &[String]) -> Result<bool, String> {
    Ok(parse_cli(args).map(|cli| cli.apply).unwrap_or(false))
}

pub(crate) fn invoke_cli(
    args: &[String],
    software: Option<&SoftwareApplyAuthorization>,
    invocation: Option<&InvocationKey>,
) -> Result<(), String> {
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        println!("mem0-maintenance <observe|act|report-home> --request <absJSON> [--apply]\n\
observe reads committed source and installed identity without mutation;\n\
act compares first and requires --apply for a changed promotion;\n\
report-home proves a caller-supplied promotion boundary;\n\
--request names an absolute, normalized JSON request file; --apply is valid only for act.");
        return Ok(());
    }
    let action = args.first().map(String::as_str).unwrap_or("invalid");
    let result = (|| {
        let cli = parse_cli(args)?;
        let request = ask::read_request(&cli.request_path, REQUEST_LIMIT)?;
        validate_request(&request)?;
        run_action(cli.action, &request, cli.apply, software, invocation)
    })();
    match result {
        Ok(output) => {
            println!("{}", serde_json::to_string(&output).map_err(|error| format!("mem0-maintenance-output-serialize-failed: {error}"))?);
            if output.ok { Ok(()) } else { Err(output.first_missing_signal.unwrap_or_else(|| "mem0-maintenance-not-proven".into())) }
        }
        Err(error) => {
            let report = Output::failure(None, action, &error);
            if let Ok(serialized) = serde_json::to_string(&report) { println!("{serialized}"); }
            Err(error)
        }
    }
}

pub fn observe(request: &Request) -> Result<Output, String> {
    validate_request(request)?;
    let observation = ask::observe(request)?;
    Ok(Output::observation(request, &observation, "observe"))
}

fn run_action(
    action: Action,
    request: &Request,
    apply: bool,
    software: Option<&SoftwareApplyAuthorization>,
    invocation: Option<&InvocationKey>,
) -> Result<Output, String> {
    match action {
        Action::Observe => {
            let observation = ask::observe(request)?;
            Ok(Output::observation(request, &observation, "observe"))
        }
        Action::ReportHome => ask::report_home(request),
        Action::Act => {
            let initial = ask::observe(request)?;
            if initial.changed {
                let missing = if request.unit.is_none() {
                    Some("mem0-maintenance-unit-required-before-changed-act")
                } else if request.health_url.is_none() {
                    Some("mem0-maintenance-health-url-required-before-changed-act")
                } else if request.identity_json_pointer.is_none() {
                    Some("process-source-identity-pointer-not-configured")
                } else {
                    None
                };
                if let Some(signal) = missing {
                    let mut output = Output::observation(request, &initial, "act");
                    output.ok = false;
                    output.status = "refused".into();
                    output.first_missing_signal = Some(signal.into());
                    return Ok(output);
                }
            }
            if !apply || !initial.changed {
                let mut output = Output::observation(request, &initial, "act");
                if !apply && initial.changed && output.ok {
                    output.status = "apply-required".into();
                }
                return Ok(output);
            }
            let invocation = invocation.ok_or_else(|| "mem0-maintenance-invocation-key-missing".to_string())?;
            let software = software.ok_or_else(|| "mem0-maintenance-software-authorization-missing".to_string())?;
            let movement = crate::atoms::comparison::execute_once(
                "mem0-maintenance",
                || ask::observe(request),
                |observed| {
                    if observed.changed { DiffDecision::Different } else { DiffDecision::Empty }
                },
                |authorization, observed| {
                    crate::atoms::r#do::mem0_maintenance::promote(&authorization, invocation, software, request, observed)
                },
            )?;
            match movement {
                ComparisonRun::Current { observation, .. } => Ok(Output::observation(request, &observation, "act")),
                ComparisonRun::Moved { observation, movement, .. } => {
                    let mut output = Output::observation(request, &observation, "act");
                    output.ok = movement.ok;
                    output.changed = movement.changed;
                    output.status = movement.status.clone();
                    output.restart = movement.restart.clone();
                    output.health = movement.health.clone();
                    output.runtime_identity = movement.runtime_identity.clone();
                    output.identity_evidence = movement.identity_evidence.clone();
                    output.process_main_pid = movement.process_main_pid;
                    output.process_start_monotonic_usec = movement.process_start_monotonic_usec.clone();
                    output.process_boot_id = movement.process_boot_id.clone();
                    output.process_cwd_binding = movement.process_cwd_binding;
                    output.process_cmdline_binding = movement.process_cmdline_binding;
                    output.promotion_boot_id = movement.promotion_boot_id.clone();
                    output.promotion_monotonic_usec = movement.promotion_monotonic_usec;
                    output.first_missing_signal = movement.first_missing_signal.clone();
                    if movement.changed || !movement.ok {
                        crate::atoms::attest::mem0_maintenance::deed(request, &movement);
                    }
                    Ok(output)
                }
            }
        }
    }
}

pub(crate) fn validate_args(args: &BTreeMap<String, Value>) -> Result<(), String> {
    let text = |key: &str| args.get(key).and_then(Value::as_str).ok_or_else(|| format!("mem0-maintenance-{key}-required"));
    let owner = text("owner")?;
    if owner.is_empty() || owner.len() > 64 || !owner.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')) {
        return Err("mem0-maintenance-owner-invalid".into());
    }
    for key in ["source_root", "app_root"] {
        let value = text(key)?;
        let path = Path::new(value);
        if !path.is_absolute() || !lexical_absolute_path(path) {
            return Err(format!("mem0-maintenance-{key}-must-be-absolute-and-normalized"));
        }
    }
    let subtree = Path::new(text("subtree")?);
    if subtree.is_absolute() || !lexical_relative_path(subtree) || subtree.as_os_str().is_empty() {
        return Err("mem0-maintenance-subtree-must-be-safe-relative-path".into());
    }
    let timeout = args.get("timeout_secs").and_then(Value::as_u64).ok_or("mem0-maintenance-timeout-secs-required")?;
    if timeout == 0 || timeout > MAX_TIMEOUT_SECS {
        return Err("mem0-maintenance-timeout-secs-out-of-range".into());
    }
    for key in ["unit", "health_url", "identity_json_pointer", "promotion_boot_id"] {
        if let Some(value) = args.get(key).filter(|value| !value.is_null()) {
            let value = value.as_str().ok_or_else(|| format!("mem0-maintenance-{key}-must-be-string-or-null"))?;
            if value.trim().is_empty() { return Err(format!("mem0-maintenance-{key}-empty")); }
            match key {
                "unit" if !valid_unit(value) => return Err("mem0-maintenance-unit-must-be-system-service-basename".into()),
                "health_url" if !valid_health_url(value) => return Err("mem0-maintenance-health-url-must-be-http-or-https".into()),
                "identity_json_pointer" if !(value.starts_with('/') && value.len() <= 512) => return Err("mem0-maintenance-identity-json-pointer-invalid".into()),
                "promotion_boot_id" if value.len() > 128 => return Err("mem0-maintenance-promotion-boot-id-over-bound".into()),
                _ => (),
            }
        }
    }
    if let Some(value) = args.get("promotion_monotonic_usec").filter(|value| !value.is_null()) {
        if value.as_u64().is_none() { return Err("mem0-maintenance-promotion-monotonic-usec-must-be-nonnegative-integer-or-null".into()); }
    }
    Ok(())
}

fn validate_request(request: &Request) -> Result<(), String> {
    let values = BTreeMap::from([
        ("owner".into(), Value::String(request.owner.clone())),
        ("source_root".into(), Value::String(request.source_root.display().to_string())),
        ("subtree".into(), Value::String(request.subtree.display().to_string())),
        ("app_root".into(), Value::String(request.app_root.display().to_string())),
        ("unit".into(), request.unit.clone().map(Value::String).unwrap_or(Value::Null)),
        ("health_url".into(), request.health_url.clone().map(Value::String).unwrap_or(Value::Null)),
        ("identity_json_pointer".into(), request.identity_json_pointer.clone().map(Value::String).unwrap_or(Value::Null)),
        ("promotion_boot_id".into(), request.promotion_boot_id.clone().map(Value::String).unwrap_or(Value::Null)),
        ("promotion_monotonic_usec".into(), request.promotion_monotonic_usec.map(Value::from).unwrap_or(Value::Null)),
        ("timeout_secs".into(), Value::from(request.timeout_secs)),
    ]);
    validate_args(&values)
}

fn lexical_absolute_path(path: &Path) -> bool {
    let Some(raw) = path.to_str() else { return false; };
    raw.starts_with('/') && raw != "/" && raw[1..].split('/').all(|part| !part.is_empty() && part != "." && part != "..")
}
fn lexical_relative_path(path: &Path) -> bool {
    let Some(raw) = path.to_str() else { return false; };
    !raw.is_empty() && !raw.starts_with('/') && raw.split('/').all(|part| !part.is_empty() && part != "." && part != "..")
}
fn valid_unit(unit: &str) -> bool {
    unit.ends_with(".service")
        && unit.len() <= 255
        && !unit.contains('/')
        && unit.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@'))
}
fn valid_health_url(url: &str) -> bool {
    if url.len() > 2048 || url.bytes().any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace()) || url.contains('#') || url.contains('\\') {
        return false;
    }
    let rest = url.strip_prefix("http://").or_else(|| url.strip_prefix("https://"));
    let Some(rest) = rest else { return false; };
    let authority = rest.split(|character| character == '/' || character == '?').next().unwrap_or("");
    !authority.is_empty() && !authority.contains('@') && !authority.starts_with('.')
}

pub(crate) fn execute_step(
    step: &crate::tools::routine::ValidatedStep,
    software: Option<&SoftwareApplyAuthorization>,
    invocation: Option<&InvocationKey>,
) -> Result<OperationOutcome, String> {
    execute_step_with_outputs(step, software, invocation).map(|(outcome, _)| outcome)
}

pub(crate) fn execute_step_with_outputs(
    step: &crate::tools::routine::ValidatedStep,
    software: Option<&SoftwareApplyAuthorization>,
    invocation: Option<&InvocationKey>,
) -> Result<(OperationOutcome, BTreeMap<String, Value>), String> {
    let request: Request = serde_json::from_value(Value::Object(step.args.clone().into_iter().collect()))
        .map_err(|error| format!("mem0-maintenance-request-invalid: {error}"))?;
    validate_request(&request)?;
    let apply = software.is_some() && invocation.is_some();
    let output = run_action(Action::Act, &request, apply, software, invocation)?;
    let outcome = OperationOutcome {
        ok: output.ok,
        changed: output.changed,
        skipped: !output.changed,
        message: output.first_missing_signal.clone().unwrap_or_else(|| output.status.clone()),
        command: None,
    };
    let serialized = serde_json::to_value(&output).map_err(|error| format!("mem0-maintenance-output-serialize-failed: {error}"))?;
    let outputs = BTreeMap::from([
        ("source_head".into(), serialized["source_head"].clone()),
        ("source_tree".into(), serialized["source_tree"].clone()),
        ("recorded_head".into(), serialized["recorded_head"].clone()),
        ("recorded_tree".into(), serialized["recorded_tree"].clone()),
        ("promotion_boot_id".into(), serialized["promotion_boot_id"].clone()),
        ("promotion_monotonic_usec".into(), serialized["promotion_monotonic_usec"].clone()),
        ("status".into(), Value::String(output.status)),
    ]);
    Ok((outcome, outputs))
}

