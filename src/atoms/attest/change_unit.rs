use crate::{write_json, CmdResult, OperationOutcome};
use crate::atoms::ask::change_unit::Observation;
use crate::atoms::systemd::RestartDecision;
use crate::atoms::comparison::DiffDecision;
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

pub(crate) fn augment_comparison_receipt(receipt_dir: &Path, name: &str, fields: Value) -> Result<(), String> {
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
    action: &str,
    service: &str,
    command: &CmdResult,
) -> Result<(), String> {
    if matches!(action, "enable-now" | "disable-stop" | "disable-stop-remove") {
        crate::atoms::attest::attest(
            &receipt_dir.join("harmonia-atoms.log"),
            &crate::atoms::Receipt {
                atom: "systemd".into(),
                ok: command.ok,
                drift: crate::atoms::Drift::Current,
                message: format!("service={service}; action={action}; code={}", command.code),
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
