use crate::atoms::command::{authorized_capture, capture_with_options, CaptureOptions, DEFAULT_TIMEOUT_SECS};
use crate::atoms::comparison::{self, ComparisonRun, DiffDecision};
use crate::atoms::r#do::InvocationKey;
use crate::tools::ladder::ValidatedStep;
use crate::{CmdResult, OperationOutcome};
use serde_json::{Map, Value};
use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const STAFF_SCHEMA: &str = include_str!("../../schema/caduceus.staff.v1.json");
const DOOR: &str = "/usr/local/sbin/agathodaimon/cli.py";
const PYTHON: &str = "/usr/bin/python3";
static SEND_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn door() -> PathBuf {
    #[cfg(any(test, feature = "test-facade"))]
    if let Some(path) = std::env::var_os("HARMONIA_TEST_STAFF_DOOR") {
        return PathBuf::from(path);
    }
    PathBuf::from(DOOR)
}

fn timestamp() -> Option<String> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as libc::time_t;
    let mut utc: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::gmtime_r(&seconds, &mut utc) }.is_null() { return None; }
    Some(format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", utc.tm_year + 1900,
        utc.tm_mon + 1, utc.tm_mday, utc.tm_hour, utc.tm_min, utc.tm_sec))
}

fn envelope(intent: &str, id: &str, payload: &Value) -> Option<String> {
    let seat: Value = serde_json::from_str(STAFF_SCHEMA).ok()?;
    let required = seat.pointer("/kernel/required")?.as_array()?;
    let mut object = Map::new();
    for field in required {
        let key = field.as_str()?;
        let value = match key {
            "schema" => seat.get("schema")?.clone(),
            "intent_id" => Value::String(id.into()),
            "transition" => Value::String(intent.into()),
            "version" => Value::String(env!("CARGO_PKG_VERSION").into()),
            "timestamp" => Value::String(timestamp()?),
            _ => return None,
        };
        object.insert(key.into(), value);
    }
    object.insert("payload".into(), payload.clone());
    serde_json::to_string(&object).ok()
}

fn send_id(step: &ValidatedStep, phase: &str) -> String {
    let seq = SEND_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{}-{}-{}-{}", crate::receipts::run_id_from_stamp(), step.step_id, phase, seq)
}

fn result(intent: &str, diff: &str, executed: bool, id: &str, signal: Option<&str>,
          skipped: bool, changed: bool, command: Option<CmdResult>) -> OperationOutcome {
    let mut message = format!("staff ask stop={intent} diff={diff} executed={executed} intent_id={id}");
    if let Some(signal) = signal { message.push(' '); message.push_str(signal); }
    OperationOutcome { ok: signal.is_none(), changed, skipped, message, command }
}

fn observe(step: &ValidatedStep, door: &str, intent: &str, phase: &str, timeout: u64)
    -> (String, Option<CmdResult>) {
    let id = send_id(step, phase);
    let Some(json) = envelope(intent, &id, &step.args["observe"]) else { return (id, None); };
    let mut cmd = capture_with_options(PYTHON, &["-B", door, intent, &json],
        CaptureOptions::new().timeout_secs(timeout).output_limit(usize::MAX));
    // A spawn error can contain argv, including the envelope.
    cmd.stderr = cmd.stderr.replace(&json, "[redacted]");
    (id, Some(cmd))
}

pub(crate) fn execute_validated_step(step: &ValidatedStep, apply: bool, active_lane: Option<&str>,
    invocation: Option<&InvocationKey>) -> Result<OperationOutcome, String> {
    let intent = step.args.get("intent").and_then(Value::as_str).unwrap_or("");
    let door = door();
    if !door.exists() {
        return Ok(result(intent, "Empty", false, "none", None, true, false, None));
    }
    let expected = step.args.get("converged").and_then(|v| v.get("stdout")).and_then(Value::as_str);
    let Some(expected) = expected else {
        return Ok(result(intent, "Blocked", false, "none", Some("staff-ask-receipt-form-unread"), false, false, None));
    };
    let door = door.to_string_lossy();
    let timeout = step.args.get("timeout_secs").and_then(Value::as_u64)
        .filter(|seconds| *seconds != 0).unwrap_or(DEFAULT_TIMEOUT_SECS);
    let (mut id, mut last) = observe(step, &door, intent, "observe", timeout);
    if !last.as_ref().is_some_and(|r| r.ok && r.code == 0) {
        return Ok(result(intent, "Blocked", false, &id, Some("staff-ask-observation-failed"), false, false, last));
    }
    let same = last.as_ref().is_some_and(|r| r.stdout == expected);
    let diff = if same { "Empty" } else { "Different" };
    let lane = step.args.get("lane").and_then(Value::as_str);
    if same || !apply || (lane.is_some() && lane != active_lane) {
        return Ok(result(intent, diff, false, &id, None, false, false, last));
    }
    id = send_id(step, "act");
    let Some(json) = envelope(intent, &id, &step.args["act"]) else {
        return Ok(result(intent, diff, false, &id, Some("staff-ask-act-failed"), false, false, last));
    };
    let argv = vec!["-B".to_string(), door.to_string(), intent.to_string(), json.clone()];
    let attempted = Cell::new(false);
    let action = comparison::execute_once("staff-ask", || Ok::<_, String>(same),
        |same| if *same { DiffDecision::Empty } else { DiffDecision::Different },
        |authorization, _| {
            let key = invocation.ok_or("invocation-key-missing")?;
            attempted.set(true);
            authorized_capture(&authorization, key, PYTHON, &argv, None,
                Duration::from_secs(timeout), None, None)
        });
    let movement = match action {
        Ok(ComparisonRun::Moved { movement, .. }) => movement,
        _ => return Ok(result(intent, diff, attempted.get(), &id, Some("staff-ask-act-failed"), false, false,
            if attempted.get() { None } else { last })),
    };
    last = Some(CmdResult { ok: movement.ok, code: movement.code.unwrap_or(-1),
        stdout: movement.stdout.replace(&json, "[redacted]"),
        stderr: movement.stderr.replace(&json, "[redacted]") });
    if !last.as_ref().is_some_and(|r| r.ok && r.code == 0) {
        return Ok(result(intent, diff, true, &id, Some("staff-ask-act-failed"), false, false, last));
    }
    (id, last) = observe(step, &door, intent, "read-back", timeout);
    if !last.as_ref().is_some_and(|r| r.ok && r.code == 0) {
        return Ok(result(intent, diff, true, &id, Some("staff-ask-observation-failed"), false, false, last));
    }
    if !last.as_ref().is_some_and(|r| r.stdout == expected) {
        return Ok(result(intent, diff, true, &id, Some("staff-ask-act-did-not-converge"), false, false, last));
    }
    Ok(result(intent, diff, true, &id, None, false, true, last))
}
