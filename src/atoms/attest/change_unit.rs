use crate::atoms::ask::change_unit::Observation;
use crate::atoms::comparison::DiffDecision;
use crate::atoms::systemd::RestartDecision;
use crate::{write_json, CmdResult, OperationOutcome};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

pub(crate) fn comparison_fields(
    observation: &Observation,
    desired_state: Value,
    decision: DiffDecision,
    movement: Option<&OperationOutcome>,
    changed: bool,
) -> Value {
    json!({
        "observed_state": observation,
        "desired_state": desired_state,
        "diff_decision": match decision { DiffDecision::Empty => "empty", DiffDecision::Different => "different" },
        "movement": movement.map(|movement| json!({"ok": movement.ok, "changed": movement.changed, "skipped": movement.skipped, "message": movement.message, "command": movement.command})),
        "changed": changed,
    })
}

pub(crate) fn augment_comparison_receipt(
    receipt_dir: &Path,
    name: &str,
    fields: Value,
) -> Result<(), String> {
    let path = receipt_dir.join(format!("{name}.json"));
    let mut receipt: Value =
        serde_json::from_str(&fs::read_to_string(&path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let receipt = receipt
        .as_object_mut()
        .ok_or_else(|| "systemd-receipt-object-invalid".to_string())?;
    let fields = fields
        .as_object()
        .ok_or_else(|| "systemd-comparison-fields-invalid".to_string())?;
    receipt.extend(fields.clone());
    write_json(&path, &Value::Object(receipt.clone()))
}

pub(crate) fn augment_condition_skip_receipt(
    receipt_dir: &Path,
    name: &str,
    evidence: &Value,
) -> Result<(), String> {
    let path = receipt_dir.join(format!("{name}.json"));
    let mut receipt: Value =
        serde_json::from_str(&fs::read_to_string(&path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let receipt = receipt
        .as_object_mut()
        .ok_or_else(|| "systemd-receipt-object-invalid".to_string())?;
    receipt.insert("ok".into(), Value::Bool(true));
    receipt.insert("changed".into(), Value::Bool(false));
    receipt.insert("skipped".into(), Value::Bool(true));
    receipt.insert(
        "reason".into(),
        Value::String("systemd-unit-condition-unmet".into()),
    );
    receipt.insert(
        "condition_result".into(),
        evidence
            .get("condition_result")
            .cloned()
            .unwrap_or(Value::Null),
    );
    receipt.insert(
        "conditions".into(),
        evidence.get("conditions").cloned().unwrap_or(Value::Null),
    );
    receipt.insert(
        "failed_conditions".into(),
        evidence
            .get("failed_conditions")
            .cloned()
            .unwrap_or(Value::Null),
    );
    receipt.insert("condition_evidence".into(), evidence.clone());
    receipt.insert(
        "raw_is_active_probe".into(),
        evidence
            .get("systemctl_is_active")
            .cloned()
            .unwrap_or(Value::Null),
    );
    receipt.insert(
        "raw_systemd_evidence".into(),
        json!({
            "show": evidence.get("systemctl_show"),
            "status": evidence.get("systemctl_status"),
        }),
    );
    write_json(&path, &Value::Object(receipt.clone()))
}

pub(crate) fn desired_state(action: &str, service_material_changed: bool) -> Value {
    match action {
        "daemon-reload" => json!({"manager_reload_required": service_material_changed}),
        "enable-now" => json!({"enabled": "enabled", "active": "active"}),
        "disable-stop" => json!({"enabled": "disabled", "active": "inactive"}),
        "disable-stop-remove" => json!({"unit_file": "absent"}),
        "restart" => json!({"service_material_changed": service_material_changed}),
        "stop" => {
            json!({"active": "inactive", "service_material_changed": service_material_changed})
        }
        "unit-present" => json!({"observation_only": "unit-present"}),
        "is-active-probe" => json!({"observation_only": "is-active"}),
        other => json!({"action": other}),
    }
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_systemd_receipt(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    service: &str,
    user: bool,
    apply: bool,
    result: &CmdResult,
    enabled_before: Option<&str>,
    active_before: Option<&str>,
    enabled_after: Option<&str>,
    active_after: Option<&str>,
    changed: bool,
    target_user: Option<&str>,
    restart_decision: Option<RestartDecision>,
    service_material_changed: bool,
    attempted: bool,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{}.json", name)),
        &json!({
            "schema": "harmonia.systemd.receipt.v1",
            "name": name,
            "action": action,
            "service": service,
            "scope": if user { "user" } else { "system" },
            "target_user": target_user,
            "systemctl_transport": if user && target_user.is_some() { "machine-user" } else if user { "ambient-user" } else { "system" },
            "apply": apply,
            "ok": result.ok,
            "exit_code": result.code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "enabled_before": enabled_before,
            "active_before": active_before,
            "enabled_after": enabled_after,
            "active_after": active_after,
            "changed": changed,
            "service_material_changed": service_material_changed,
            "decision": if apply && attempted { "executed" } else { "held" },
            "reason": if !result.ok && !attempted {
                if result.stderr.starts_with("systemd-unit-name-invalid-") {
                    "invalid-unit"
                } else if result.stderr.contains("state-read-failed")
                    || result.stderr.contains("observation")
                {
                    "observation-failed"
                } else {
                    "observation-or-validation-failed"
                }
            } else if !apply {
                "plan-only"
            } else if attempted {
                restart_decision
                    .map(|decision| {
                        if result.ok {
                            decision.reason
                        } else {
                            match decision.reason {
                                "service-material-changed" => "service-material-changed-command-failed",
                                "service-material-unchanged" => "service-material-unchanged-command-failed",
                                "unit-not-active" => "unit-not-active-command-failed",
                                "service-state-unknown" => "service-state-unknown-command-failed",
                                _ => "restart-command-failed",
                            }
                        }
                    })
                    .unwrap_or(if result.ok { "state-change-attempted" } else { "systemd-command-failed" })
            } else {
                restart_decision
                    .map(|decision| decision.reason)
                    .unwrap_or("already-current")
            },
            "restart_decision": restart_decision.map(|decision| if decision.execute { "restarted" } else { "skipped" }),
            "restart_reason": restart_decision.map(|decision| decision.reason),
        }),
    )
}

pub(crate) fn annotate_candidate_selection(
    receipt_dir: &Path,
    name: &str,
    candidate_units: &[String],
    selected_service: &str,
) -> Result<(), String> {
    let path = receipt_dir.join(format!("{name}.json"));
    let mut receipt: Value =
        serde_json::from_str(&fs::read_to_string(&path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let object = receipt
        .as_object_mut()
        .ok_or_else(|| "systemd-receipt-object-invalid".to_string())?;
    object.insert("candidate_units".to_string(), json!(candidate_units));
    object.insert("selected_service".to_string(), json!(selected_service));
    write_json(&path, &receipt)
}

pub(crate) fn attest_change_unit(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    service: &str,
    command: &CmdResult,
) -> Result<(), String> {
    if matches!(
        action,
        "enable-now"
            | "disable-stop"
            | "disable-stop-remove"
            | "daemon-reload"
            | "restart"
            | "stop"
            | "enable"
            | "mask"
    ) {
        let path = receipt_dir.join(format!("{name}.json"));
        let receipt: Value = serde_json::from_str(
            &fs::read_to_string(&path)
                .map_err(|error| format!("systemd-attest-receipt-read-failed: {error}"))?,
        )
        .map_err(|error| format!("systemd-attest-receipt-parse-failed: {error}"))?;
        let decision = receipt
            .get("decision")
            .and_then(Value::as_str)
            .ok_or_else(|| "systemd-attest-decision-missing".to_string())?;
        let reason = receipt
            .get("reason")
            .and_then(Value::as_str)
            .ok_or_else(|| "systemd-attest-reason-missing".to_string())?;
        crate::atoms::attest::attest(
            &receipt_dir.join("harmonia-atoms.log"),
            &crate::atoms::Receipt {
                atom: "systemd".into(),
                ok: command.ok,
                drift: crate::atoms::Drift::Current,
                message: format!("service={service}; action={action}; decision={decision}; reason={reason}; code={}", command.code),
            },
            &[],
        )?;
    }
    Ok(())
}

pub(crate) fn write_show_assert_receipt(
    receipt_dir: &Path,
    name: &str,
    service: &str,
    expected: &std::collections::BTreeMap<String, serde_json::Value>,
    observed: &std::collections::BTreeMap<String, String>,
    command: &CmdResult,
    first_divergent: Option<String>,
) -> Result<(), String> {
    let ok = command.ok && first_divergent.is_none();
    write_json(
        &receipt_dir.join(format!("{name}.json")),
        &json!({
            "schema": "harmonia.routine_tool.receipt.v1", "ok": ok, "changed": false,
            "skipped": false, "observation_only": true, "service": service, "expected": expected, "observed": observed,
            "first_divergent": first_divergent, "stdout": command.stdout,
            "stderr": command.stderr, "code": command.code,
        }),
    )
}
