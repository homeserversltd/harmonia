//! Change-only Canonical Log Line; queries produce no event and no retained receipt.
use crate::atoms::r#do::mem0_maintenance::Movement;
use crate::tools::mem0_maintenance::Request;
use serde_json::json;

fn bounded_field(value: &str, limit: usize) -> String {
    value.bytes()
        .filter(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'_' | b'-' | b'.' | b'/' | b':'))
        .take(limit)
        .map(char::from)
        .collect()
}

pub(crate) fn deed(request: &Request, movement: &Movement) {
    let signal = movement.first_missing_signal.as_deref().map(|value| bounded_field(value, 160));
    let event = json!({
        "who": bounded_field(&request.owner, 64),
        "verb": "mem0-maintenance-promote",
        "target": bounded_field(&request.subtree.display().to_string(), 160),
        "outcome": if movement.ok { "proven" } else { "failed-or-rolled-back" },
        "changed": movement.changed,
        "process_main_pid": movement.process_main_pid,
        "promotion_boot_id": movement.promotion_boot_id.as_deref().map(|value| bounded_field(value, 64)),
        "promotion_monotonic_usec": movement.promotion_monotonic_usec,
        "duration_ms": movement.duration_ms,
        "first_missing_signal": signal,
    });
    if let Ok(line) = serde_json::to_string(&event) {
        const PREFIX: &str = "mem0_maintenance_event=";
        if line.len() + PREFIX.len() < 1024 { eprintln!("{PREFIX}{line}"); }
    }
}
