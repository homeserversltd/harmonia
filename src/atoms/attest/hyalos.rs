use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const HYALOS_PATH: &str = "/api/v1/hyalos/reflect";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const MAX_FORWARD_PAYLOAD_BYTES: usize = 1023;

thread_local! {
    static READ_ONLY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Suppress forwarding for a read invocation, restoring any enclosing scope.
pub(crate) struct ReadGuard(bool);

impl ReadGuard {
    pub(crate) fn enter(read_only: bool) -> Self {
        Self(READ_ONLY.with(|active| active.replace(read_only)))
    }
}

impl Drop for ReadGuard {
    fn drop(&mut self) {
        READ_ONLY.with(|active| active.set(self.0));
    }
}

fn receipt_payload(
    kind: &str,
    message: &str,
    attributes_redacted: Option<Value>,
    ok: Option<bool>,
    correlation_id: Option<&str>,
) -> Value {
    let mut payload = json!({
        "organ": "harmonia",
        "kind": kind,
        "message": message,
    });
    if let Some(attributes) = attributes_redacted {
        payload["attributes_redacted"] = attributes;
    }
    if let Some(value) = ok {
        payload["ok"] = json!(value);
    }
    if let Some(value) = correlation_id {
        payload["correlation_id"] = json!(value);
    }
    payload
}

fn escaped_char_len(character: char) -> usize {
    match character {
        '"' | '\\' | '\u{08}' | '\u{0c}' | '\n' | '\r' | '\t' => 2,
        character if character <= '\u{1f}' => 6,
        character => character.len_utf8(),
    }
}

fn serialized_json_string_len(value: &str) -> usize {
    2 + value.chars().map(escaped_char_len).sum::<usize>()
}

/// Bound one string by its serialized JSON size, keeping UTF-8 scalar and
/// JSON-escape boundaries intact. The suffix makes a shortened value visible.
pub(crate) fn bounded_json_string(value: &str, max_serialized_bytes: usize) -> String {
    if serialized_json_string_len(value) <= max_serialized_bytes {
        return value.to_string();
    }
    if max_serialized_bytes < 2 {
        return String::new();
    }
    let interior_budget = max_serialized_bytes - 2;
    let suffix_budget = if interior_budget >= '…'.len_utf8() {
        '…'.len_utf8()
    } else {
        0
    };
    let prefix_budget = interior_budget - suffix_budget;
    let mut out = String::new();
    let mut used = 0;
    for character in value.chars() {
        let size = escaped_char_len(character);
        if used + size > prefix_budget {
            break;
        }
        out.push(character);
        used += size;
    }
    if suffix_budget > 0 {
        out.push('…');
    }
    out
}

const FORWARD_METADATA_FIELDS: &[&str] = &[
    "schema",
    "target",
    "duration_scope",
    "run_id",
    "module_id",
    "count",
    "profile_id",
    "outcome",
    "ok",
    "first_missing_signal",
    "changed",
    "mutation",
    "mode",
    "identity_source",
    "child",
    "tool",
    "permutation",
    "state",
    "operation_count",
    "module",
    "module_count",
    "duration_ms",
    "degraded",
    "overall_ok",
    "engine_debt_first_missing_signal",
    "module_artifact_debt_first_missing_signal",
];

fn bounded_metadata_attributes(
    attributes: Option<&Value>,
    string_budget: usize,
    ok: Option<bool>,
) -> Option<Value> {
    let mut compact = serde_json::Map::new();
    if let Some(fields) = attributes.and_then(Value::as_object) {
        for field in FORWARD_METADATA_FIELDS {
            if let Some(value) = fields.get(*field) {
                let value = match value {
                    Value::String(text) => {
                        Value::String(bounded_json_string(text, string_budget))
                    }
                    value if value.is_boolean() || value.is_number() || value.is_null() => {
                        value.clone()
                    }
                    // Forward only the callers' named scalar projections, never detail bodies.
                    _ => continue,
                };
                compact.insert((*field).to_string(), value);
            }
        }
    }
    if ok == Some(false) && !compact.contains_key("first_missing_signal") {
        compact.insert(
            "first_missing_signal".into(),
            json!("failure-signal-not-provided"),
        );
    }
    if compact.is_empty() && attributes.is_none() {
        None
    } else {
        Some(Value::Object(compact))
    }
}

fn bounded_compacted_attributes(attributes: Option<&Value>, ok: Option<bool>) -> Value {
    let mut compact = serde_json::Map::new();
    if let Some(fields) = attributes.and_then(Value::as_object) {
        for field in [
            "child",
            "state",
            "outcome",
            "changed",
            "first_missing_signal",
        ] {
            if let Some(value) = fields.get(field) {
                let value = match value {
                    Value::String(text) => {
                        let budget = if field == "first_missing_signal" { 192 } else { 64 };
                        Value::String(bounded_json_string(text, budget))
                    }
                    value if value.is_boolean() || value.is_number() || value.is_null() => {
                        value.clone()
                    }
                    _ => continue,
                };
                compact.insert(field.to_string(), value);
            }
        }
    }
    if ok == Some(false) && !compact.contains_key("first_missing_signal") {
        compact.insert(
            "first_missing_signal".into(),
            json!("failure-signal-not-provided"),
        );
    }
    Value::Object(compact)
}

#[derive(Clone, Debug)]
pub(crate) struct RunProfileFailure {
    pub module: String,
    pub signal: Option<String>,
}

fn try_forward_bounded_payload(payload: Value) -> Option<bool> {
    let Ok(body) = serde_json::to_vec(&payload) else {
        return None;
    };
    if body.len() > MAX_FORWARD_PAYLOAD_BYTES {
        return None;
    }
    let kind = payload.get("kind").and_then(Value::as_str).unwrap_or("unknown");
    Some(forward_serialized_payload(body, kind))
}

/// Forward one run-profile deed while preserving its required typed summary.
/// Failure entries are kept in input order; overflow trims only the tail and
/// reports the exact number omitted. Every candidate is measured after JSON
/// escaping against the complete reflector envelope, including its fixed fields.
pub(crate) fn forward_run_profile_deed(
    run_id: &str,
    profile: &str,
    outcome: &str,
    finished_at: &str,
    duration_ms: u128,
    module_count: usize,
    updated_count: usize,
    failures: &[RunProfileFailure],
) {
    let run_id = bounded_json_string(run_id, 80);
    let profile = bounded_json_string(profile, 80);
    let outcome = if outcome == "ok" { "ok" } else { "failed" };
    let finished_at = bounded_json_string(finished_at, 48);
    let duration_ms = u64::try_from(duration_ms).unwrap_or(u64::MAX);
    let module_count = u64::try_from(module_count).unwrap_or(u64::MAX);
    let updated_count = u64::try_from(updated_count).unwrap_or(u64::MAX);
    let message = bounded_json_string(&format!("profile={profile} outcome={outcome}"), 256);
    let mut included = Vec::new();
    for failure in failures {
        let mut candidate = included.clone();
        candidate.push(json!({
            "module": failure.module,
            "signal": failure.signal,
        }));
        let attributes = json!({
            "run_id": run_id,
            "profile": profile,
            "outcome": outcome,
            "finished_at": finished_at,
            "duration_ms": duration_ms,
            "module_count": module_count,
            "updated_count": updated_count,
            "failures": candidate,
            "failures_more": failures.len() - candidate.len(),
        });
        let payload = receipt_payload(
            "harmonia.run_profile",
            &message,
            Some(attributes),
            Some(outcome == "ok"),
            Some(&run_id),
        );
        let fits = serde_json::to_vec(&payload)
            .is_ok_and(|body| body.len() <= MAX_FORWARD_PAYLOAD_BYTES);
        if !fits {
            break;
        }
        included = candidate;
    }
    let attributes = json!({
        "run_id": run_id,
        "profile": profile,
        "outcome": outcome,
        "finished_at": finished_at,
        "duration_ms": duration_ms,
        "module_count": module_count,
        "updated_count": updated_count,
        "failures": included,
        "failures_more": failures.len() - included.len(),
    });
    let payload = receipt_payload(
        "harmonia.run_profile",
        &message,
        Some(attributes),
        Some(outcome == "ok"),
        Some(&run_id),
    );
    if try_forward_bounded_payload(payload).is_none() {
        // Mandatory scalar fields use fixed, serialized-size bounds; this is
        // only reachable if the fixed envelope itself stops fitting.
        eprintln!("harmonia hyalos post=failed kind=harmonia.run_profile first_missing_signal=run-profile-deed-envelope-overflow");
    }
}

/// Forward selected receipt metadata only when its complete Hyalos JSON
/// envelope, including transport fields, fits the one-line ledger bound.
/// Callers must pass metadata projections, never operational detail receipts.
pub(crate) fn forward_bounded_receipt(
    kind: &str,
    message: &str,
    attributes_redacted: Option<Value>,
    ok: Option<bool>,
    correlation_id: Option<&str>,
) -> bool {
    for string_budget in [384, 192, 96, 48, 24, 12, 8] {
        let bounded_kind = bounded_json_string(kind, string_budget);
        let bounded_message = bounded_json_string(message, string_budget);
        let bounded_attributes =
            bounded_metadata_attributes(attributes_redacted.as_ref(), string_budget, ok);
        let bounded_correlation =
            correlation_id.map(|value| bounded_json_string(value, string_budget));
        let payload = receipt_payload(
            &bounded_kind,
            &bounded_message,
            bounded_attributes.clone(),
            ok,
            bounded_correlation.as_deref(),
        );
        if let Some(delivered) = try_forward_bounded_payload(payload) {
            return delivered;
        }
    }

    let fallback_attributes = Some(bounded_compacted_attributes(attributes_redacted.as_ref(), ok));
    let fallback_payload = receipt_payload(
        &bounded_json_string(kind, 64),
        &bounded_json_string(message, 64),
        fallback_attributes,
        ok,
        correlation_id.map(|value| bounded_json_string(value, 64)).as_deref(),
    );
    if let Some(delivered) = try_forward_bounded_payload(fallback_payload) {
        delivered
    } else {
        // The fixed envelope and capped failure fields fit by construction;
        // retain a bounded local signal if serialization ever violates that invariant.
        eprintln!("harmonia hyalos post=failed kind={:?} first_missing_signal=bounded-forward-payload-overflow", bounded_json_string(kind, 128));
        false
    }
}

/// Forward a receipt to Hyalos without affecting Harmonia's local receipt path.
///
/// This is deliberately best-effort: the caller must never observe transport,
/// serialization, or Hyalos errors.
pub(crate) fn forward_receipt(
    kind: &str,
    message: &str,
    attributes_redacted: Option<Value>,
    ok: Option<bool>,
    correlation_id: Option<&str>,
) {
    let normalized = kind.strip_prefix("schema=harmonia.")
        .and_then(|rest| rest.strip_suffix(".v1"))
        .map(|rest| format!("harmonia.{rest}"));
    let kind = normalized.as_deref().unwrap_or(kind);
    let payload = receipt_payload(kind, message, attributes_redacted, ok, correlation_id);
    let Ok(body) = serde_json::to_vec(&payload) else { return; };
    let _ = forward_serialized_payload(body, kind);
}

fn forward_serialized_payload(body: Vec<u8>, kind: &str) -> bool {
    if READ_ONLY.with(std::cell::Cell::get) {
        return true;
    }
    let deadline = Instant::now() + REQUEST_TIMEOUT;
    let result = match crate::atoms::ask::caduceus_door::base_url() {
        Ok(base) => forward_receipt_inner(base, &body, deadline),
        Err(_) => Err(std::io::Error::other("caduceus-bind-undeclared")),
    };
    if let Err(error) = result {
        let signal = if matches!(error.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) || Instant::now() >= deadline {
            "hyalos-door-timeout"
        } else { "hyalos-door-unavailable" };
        eprintln!("harmonia hyalos post=failed kind={:?} first_missing_signal={signal}", bounded_json_string(kind, 128));
        return false;
    }
    true
}

fn remaining(deadline: Instant) -> std::io::Result<Duration> {
    deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "hyalos-door-timeout"))
}

fn forward_receipt_inner(base: &str, body: &[u8], deadline: Instant) -> std::io::Result<()> {
    let host = base.strip_prefix("http://").expect("resolved HTTP base");
    let port = host.rsplit_once(':').and_then(|(_, port)| port.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| std::io::Error::other("caduceus-bind-undeclared"))?;
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&address, remaining(deadline)?)?;
    let header = format!(
        "POST {HYALOS_PATH} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()
    );
    for mut bytes in [header.as_bytes(), body] {
        while !bytes.is_empty() {
            stream.set_write_timeout(Some(remaining(deadline)?))?;
            let n = stream.write(bytes)?;
            if n == 0 { return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "hyalos-write")); }
            bytes = &bytes[n..];
        }
    }
    let mut status = Vec::new();
    let mut complete = false;
    for _ in 0..128 {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let mut byte = [0];
        if stream.read(&mut byte)? == 0 { break; }
        if byte[0] == b'\n' { complete = true; break; }
        status.push(byte[0]);
    }
    let status = std::str::from_utf8(&status).map_err(|_| std::io::Error::other("hyalos-status-invalid"))?;
    let mut parts = status.split_whitespace();
    let version = parts.next();
    let code = parts.next().and_then(|s| s.parse::<u16>().ok());
    if !complete || !matches!(version, Some("HTTP/1.0" | "HTTP/1.1"))
        || !code.is_some_and(|code| (200..300).contains(&code)) {
        return Err(std::io::Error::other("hyalos-post-refused"));
    }
    Ok(())
}
