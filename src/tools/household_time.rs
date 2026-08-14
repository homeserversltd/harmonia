use super::{ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::{CmdResult, OperationOutcome};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const NAME: &str = "household-time";
pub const DESCRIPTION: &str = "Household timezone fact primitive with typed resolver, watched application, debounce-preserving timezone actuation, and audit receipts.";
pub const PERMUTATIONS: &[ToolPermutation] = &[
    ToolPermutation::new(
        "resolve",
        "resolve and retain one household timezone fact",
        &[
            ToolArg::required("backend", ToolArgKind::String),
            ToolArg::optional("state_path", ToolArgKind::String),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ).in_band(crate::tools::Placement::RestartServices),
    ToolPermutation::new(
        "set-timezone",
        "validate and apply one IANA timezone through the selected backend",
        &[
            ToolArg::required("backend", ToolArgKind::String),
            ToolArg::required("timezone", ToolArgKind::String),
            ToolArg::optional("state_path", ToolArgKind::String),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ).in_band(crate::tools::Placement::RestartServices),
    ToolPermutation::new(
        "watch-and-set",
        "read a fresh resolver fact and apply its validated timezone or preserve the local clock",
        &[
            ToolArg::required("backend", ToolArgKind::String),
            ToolArg::required("state_url", ToolArgKind::String),
            ToolArg::optional("state_path", ToolArgKind::String),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ).in_band(crate::tools::Placement::RestartServices),
];
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION, PERMUTATIONS);

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
    let timeout = args
        .get("timeout_secs")
        .and_then(Value::as_u64)
        .unwrap_or(15);
    let request = crate::set_clock::Request {
        backend: string(args, "backend"),
        operation: permutation,
        timezone: (permutation == "set-timezone").then(|| string(args, "timezone")),
        state_url: (permutation == "watch-and-set").then(|| string(args, "state_url")),
        state_path: optional(args, "state_path"),
        timeout_secs: timeout,
    };
    let result = match permutation {
        "resolve" | "set-timezone" | "watch-and-set" => crate::set_clock::run(&request, apply, invocation)?,
        value => return Err(format!("household-time-permutation-unsupported-{value}")),
    };
    let changed = result.ok && receipt_changed(&result.stdout);
    let outcome = OperationOutcome {
        ok: result.ok,
        changed,
        skipped: !apply,
        message: format!("household-time {permutation}"),
        command: Some(result),
    };
    crate::write_tool_receipt(receipt_dir, step_id, NAME, permutation, &outcome)?;
    crate::set_clock::report_home(
        &receipt_dir.join(format!("{step_id}.attest.jsonl")),
        permutation,
        outcome
            .command
            .as_ref()
            .expect("household-time command result"),
    )?;
    Ok(outcome)
}

pub(crate) fn fresh_timezone(text: &str) -> Option<String> {
    let value: Value = serde_json::from_str(text).ok()?;
    let state = value.get("state").unwrap_or(&value);
    let timezone = state.get("timezone")?.as_str()?;
    let valid_until = state.get("valid_until")?.as_str()?;
    validate_timezone(timezone).ok()?;
    (parse_utc(valid_until)? > unix_now()).then(|| timezone.to_string())
}

fn receipt_changed(text: &str) -> bool {
    serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|v| v.get("changed").and_then(Value::as_bool))
        .unwrap_or(false)
}
pub(crate) fn preserved(reason: &str, source: CmdResult) -> CmdResult {
    CmdResult { ok: true, code: 0, stdout: format!("{{\"schema\":\"harmonia.household-time.receipt.v1\",\"changed\":false,\"preserved\":true,\"first_missing_signal\":\"{reason}\"}}"), stderr: source.stderr }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn rejects_unsafe_semantic_inputs() {
        let mut a = BTreeMap::from([
            ("backend".into(), Value::String("shell".into())),
            ("timezone".into(), Value::String("UTC".into())),
        ]);
        assert!(validate_ladder_args("set-timezone", &a).is_err());
        a.insert("backend".into(), Value::String("staff".into()));
        assert!(validate_ladder_args("set-timezone", &a).is_err());
        a.insert("timezone".into(), Value::String("Etc/UTC".into()));
        assert!(validate_ladder_args("set-timezone", &a).is_ok());
        a.insert("state_path".into(), Value::String("relative.json".into()));
        assert!(validate_ladder_args("set-timezone", &a).is_err());
    }
    #[test]
    fn fresh_state_accepts_only_future_valid_iana_fact() {
        assert_eq!(
            fresh_timezone("{\"timezone\":\"Etc/UTC\",\"valid_until\":\"2999-01-01T00:00:00Z\"}"),
            Some("Etc/UTC".into())
        );
        assert_eq!(
            fresh_timezone("{\"timezone\":\"Etc/UTC\",\"valid_until\":\"2000-01-01T00:00:00Z\"}"),
            None
        );
        assert_eq!(
            fresh_timezone("{\"timezone\":\"UTC\",\"valid_until\":\"2999-01-01T00:00:00Z\"}"),
            None
        );
    }
    #[test]
    fn planned_operation_writes_a_typed_receipt() {
        let root = std::env::temp_dir().join(format!("harmonia-household-time-{}", unix_now()));
        fs::create_dir_all(&root).unwrap();
        let args = BTreeMap::from([
            ("backend".into(), Value::String("staff".into())),
            ("timezone".into(), Value::String("Etc/UTC".into())),
        ]);
        let outcome = execute(&root, "set", "set-timezone", &args, false).unwrap();
        assert!(outcome.ok);
        let receipt: Value =
            serde_json::from_str(&fs::read_to_string(root.join("set.json")).unwrap()).unwrap();
        assert_eq!(receipt["tool"], NAME);
        assert_eq!(receipt["action"], "set-timezone");
        let _ = fs::remove_dir_all(root);
    }
}
