use crate::{CmdResult, OperationOutcome};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const NAME: &str = "household-time";

pub(crate) fn validate_ladder_args(
    permutation: &str,
    args: &BTreeMap<String, Value>,
) -> Result<(), String> {
    let backend = string(args, "backend");
    if !matches!(backend, "caduceus" | "staff") {
        return Err(format!("household-time-backend-invalid-{backend}"));
    }
    if let Some(path) = optional(args, "state_path") {
        validate_state_path(path)?;
    }
    if let Some(timeout) = args.get("timeout_secs").and_then(Value::as_u64) {
        if timeout == 0 || timeout > 60 {
            return Err("household-time-timeout-out-of-range".into());
        }
    }
    match permutation {
        "resolve" => Ok(()),
        "set-timezone" => validate_timezone(string(args, "timezone")),
        "watch-and-set" => validate_state_url(string(args, "state_url")),
        value => Err(format!("household-time-permutation-unsupported-{value}")),
    }
}

pub(crate) fn execute(
    receipt_dir: &Path,
    step_id: &str,
    permutation: &str,
    args: &BTreeMap<String, Value>,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    validate_ladder_args(permutation, args)?;
    crate::set_clock::execute(receipt_dir, step_id, permutation, args, apply, invocation)
}

pub(crate) fn fresh_timezone(text: &str) -> Option<String> {
    let value: Value = serde_json::from_str(text).ok()?;
    let state = value.get("state").unwrap_or(&value);
    let timezone = state.get("timezone")?.as_str()?;
    let valid_until = state.get("valid_until")?.as_str()?;
    validate_timezone(timezone).ok()?;
    (parse_utc(valid_until)? > unix_now()).then(|| timezone.to_string())
}

pub(crate) fn preserved(reason: &str, source: CmdResult) -> CmdResult {
    CmdResult { ok: true, code: 0, stdout: format!("{{\"schema\":\"harmonia.household-time.receipt.v1\",\"changed\":false,\"preserved\":true,\"first_missing_signal\":\"{reason}\"}}"), stderr: source.stderr }
}
pub(crate) fn household_time_bench(
    root: &Path,
    _key: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<serde_json::Value, String> {
    let args = BTreeMap::from([
        ("backend".into(), Value::String("staff".into())),
        ("timezone".into(), Value::String("Etc/UTC".into())),
    ]);
    let outcome = execute(root, "set", "set-timezone", &args, false, None)?;
    let receipt: Value =
        serde_json::from_slice(&std::fs::read(root.join("set.json")).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let typed = outcome.ok && receipt["tool"] == "set-clock" && receipt["action"] == "set-timezone";
    let rejected = validate_ladder_args(
        "resolve",
        &BTreeMap::from([("backend".into(), Value::String("unsafe".into()))]),
    )
    .is_err();
    Ok(
        serde_json::json!({"typed_receipt_written":typed,"unsafe_input_rejected":rejected,"receipt_path":root.join("set.json"),"ok":typed&&rejected}),
    )
}

pub(crate) fn planned(operation: &str) -> CmdResult {
    CmdResult {
        ok: true,
        code: 0,
        stdout: format!("planned household-time {operation}"),
        stderr: String::new(),
    }
}
fn string<'a>(args: &'a BTreeMap<String, Value>, name: &str) -> &'a str {
    args.get(name).and_then(Value::as_str).unwrap_or("")
}
fn optional<'a>(args: &'a BTreeMap<String, Value>, name: &str) -> Option<&'a str> {
    args.get(name).and_then(Value::as_str)
}
fn validate_state_path(path: &str) -> Result<(), String> {
    if path.starts_with('/') && !path.contains("..") && path.ends_with(".json") {
        Ok(())
    } else {
        Err("household-time-state-path-invalid".into())
    }
}
fn validate_state_url(url: &str) -> Result<(), String> {
    if (url.starts_with("http://") || url.starts_with("https://"))
        && !url.contains(char::is_whitespace)
        && !url.contains('?')
        && !url.contains('#')
    {
        Ok(())
    } else {
        Err("household-time-state-url-invalid".into())
    }
}
fn validate_timezone(zone: &str) -> Result<(), String> {
    let parts: Vec<_> = zone.split('/').collect();
    if parts.len() >= 2
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
        })
    {
        Ok(())
    } else {
        Err("household-time-timezone-invalid".into())
    }
}
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
fn parse_utc(value: &str) -> Option<i64> {
    let v = value.strip_suffix('Z')?;
    let (date, time) = v.split_once('T')?;
    let mut d = date.split('-').map(str::parse::<i64>);
    let (y, m, day) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    let mut t = time.split(':').map(str::parse::<i64>);
    let (h, min, s) = (t.next()?.ok()?, t.next()?.ok()?, t.next()?.ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) || h > 23 || min > 59 || s > 59 {
        return None;
    }
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146097 + doe - 719468) * 86400 + h * 3600 + min * 60 + s)
}

pub(crate) fn execute_validated_step(
    step: &crate::tools::ladder::ValidatedStep,
    module_dir: &std::path::Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<crate::OperationOutcome, String> {
    execute(
        module_dir,
        &step.step_id,
        &step.permutation,
        &step.args,
        apply,
        invocation,
    )
}
