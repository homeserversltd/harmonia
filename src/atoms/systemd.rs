use super::comparison::{self, DiffDecision};
use crate::{write_json, CmdResult, OperationOutcome};
use serde::Serialize;
use serde_json::{json, Value};
use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn validate_candidate_units(
    args: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<(), String> {
    let Some(units) = args
        .get("candidate_units")
        .and_then(serde_json::Value::as_array)
    else {
        return Err("systemd-candidate-units-missing".to_string());
    };
    if units.is_empty() {
        return Err("systemd-candidate-units-empty".to_string());
    }
    for value in units {
        let Some(unit) = value.as_str() else {
            return Err("systemd-candidate-unit-not-string".to_string());
        };
        if !is_unit_basename(unit) {
            return Err(format!("systemd-candidate-unit-invalid-{unit}"));
        }
    }
    Ok(())
}

pub(crate) fn run_permutation(
    receipt_dir: &Path,
    name: &str,
    permutation: &str,
    service: Option<&str>,
    candidate_units: &[String],
    target_user: Option<&str>,
    timeout_secs: u64,
    apply: bool,
    module_changed_before_step: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    run_permutation_with_policy(
        receipt_dir,
        name,
        permutation,
        service,
        candidate_units,
        target_user,
        timeout_secs,
        apply,
        module_changed_before_step,
        None,
        invocation,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_permutation_with_policy(
    receipt_dir: &Path,
    name: &str,
    permutation: &str,
    service: Option<&str>,
    candidate_units: &[String],
    target_user: Option<&str>,
    timeout_secs: u64,
    apply: bool,
    module_changed_before_step: bool,
    restart_policy: Option<&str>,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    if permutation == "enable-first-present-now" {
        return run_enable_first_present_now(
            receipt_dir,
            name,
            candidate_units,
            timeout_secs,
            apply,
            invocation,
        );
    }
    let user = permutation.starts_with("user-");
    let action = permutation.strip_prefix("user-").unwrap_or(permutation);
    if let Some(selected) = service {
        let valid = if matches!(action, "disable-stop" | "disable-stop-remove") {
            is_removable_unit_basename(selected)
        } else {
            is_unit_basename(selected)
        };
        if !valid {
            return Err(format!("systemd-unit-name-invalid-{selected}"));
        }
    }
    if action == "restart" {
        return run_restart(
            receipt_dir,
            name,
            service,
            user,
            target_user,
            timeout_secs,
            apply,
            module_changed_before_step,
            restart_policy,
            invocation,
        );
    }
    run_action(
        receipt_dir,
        name,
        action,
        service,
        user,
        target_user,
        timeout_secs,
        apply,
        module_changed_before_step,
        invocation,
    )
}

fn run_enable_first_present_now(
    receipt_dir: &Path,
    name: &str,
    candidate_units: &[String],
    timeout_secs: u64,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let service = select_first_present_unit(candidate_units, timeout_secs)?;
    let outcome = run_action(
        receipt_dir,
        name,
        "enable-now",
        Some(&service),
        false,
        None,
        timeout_secs,
        apply,
        false,
        invocation,
    )?;
    annotate_candidate_selection(receipt_dir, name, candidate_units, &service)?;
    Ok(OperationOutcome {
        message: format!("systemd enable-first-present-now {service}"),
        ..outcome
    })
}

fn select_first_present_unit(
    candidate_units: &[String],
    timeout_secs: u64,
) -> Result<String, String> {
    first_present_candidate(candidate_units, |unit| {
        let result = systemctl("unit-present", unit, false, None, timeout_secs);
        if result.ok && result.stdout.trim() != "not-found" {
            return Ok(true);
        }
        if result.ok || result.stdout.trim() == "not-found" {
            return Ok(false);
        }
        Err(format!(
            "systemd-candidate-probe-failed-{unit}: {}",
            result.stderr
        ))
    })
}

fn first_present_candidate<F>(
    candidate_units: &[String],
    mut is_present: F,
) -> Result<String, String>
where
    F: FnMut(&str) -> Result<bool, String>,
{
    for unit in candidate_units {
        if is_present(unit)? {
            return Ok(unit.clone());
        }
    }
    Err("systemd-candidate-units-none-present".to_string())
}

fn annotate_candidate_selection(
    receipt_dir: &Path,
    name: &str,
    candidate_units: &[String],
    selected_service: &str,
) -> Result<(), String> {
    let path = receipt_dir.join(format!("{name}.json"));
    let mut receipt: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let object = receipt
        .as_object_mut()
        .ok_or_else(|| "systemd-receipt-object-invalid".to_string())?;
    object.insert("candidate_units".to_string(), json!(candidate_units));
    object.insert("selected_service".to_string(), json!(selected_service));
    write_json(&path, &receipt)
}

fn is_unit_basename(unit: &str) -> bool {
    is_syntactic_unit_basename(unit) && unit.ends_with(".service")
}

fn is_removable_unit_basename(unit: &str) -> bool {
    is_syntactic_unit_basename(unit)
        && [
            ".service",
            ".socket",
            ".target",
            ".device",
            ".mount",
            ".automount",
            ".swap",
            ".path",
            ".timer",
            ".slice",
            ".scope",
            ".busname",
            ".snapshot",
        ]
        .iter()
        .any(|suffix| unit.ends_with(suffix))
}

fn is_syntactic_unit_basename(unit: &str) -> bool {
    let path = Path::new(unit);
    !unit.is_empty()
        && !path.is_absolute()
        && path.components().count() == 1
        && path.file_name().is_some()
        && !unit.chars().any(char::is_whitespace)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RestartDecision {
    execute: bool,
    reason: &'static str,
}

fn decide_restart(service_material_changed: bool) -> RestartDecision {
    if service_material_changed {
        RestartDecision {
            execute: true,
            reason: "service-material-changed",
        }
    } else {
        RestartDecision {
            execute: false,
            reason: "service-material-unchanged",
        }
    }
}

fn decide_restart_for_observation(
    observation: &SystemdObservation,
    material: bool,
    policy: Option<&str>,
) -> RestartDecision {
    match observation.active.as_deref() {
        Some("active") if policy == Some("always") => RestartDecision {
            execute: true,
            reason: "restart-policy-always",
        },
        Some("active") if material => RestartDecision {
            execute: true,
            reason: "service-material-changed",
        },
        Some("active") => RestartDecision {
            execute: false,
            reason: "service-material-unchanged",
        },
        Some("inactive") | Some("failed") | Some("not-found") => RestartDecision {
            execute: true,
            reason: "unit-not-active",
        },
        _ => RestartDecision {
            execute: false,
            reason: "service-state-unknown",
        },
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ServiceStateSnapshot {
    pub name: String,
    pub user: bool,
    pub target_user: Option<String>,
    pub enabled: bool,
    pub active: bool,
}

pub(crate) fn snapshot_service_state(
    name: &str,
    user: bool,
    target_user: Option<&str>,
) -> Result<ServiceStateSnapshot, String> {
    if !is_unit_basename(name) {
        return Err(format!("systemd-unit-name-invalid-{name}"));
    }
    let observation = observe_systemd_state("is-active-probe", name, user, target_user, 30);
    if observation.enabled.is_none() || observation.active.is_none() {
        return Err(format!("systemd-state-readback-failed-{name}"));
    }
    Ok(ServiceStateSnapshot {
        name: name.to_string(),
        user,
        target_user: target_user.map(str::to_string),
        enabled: observation.enabled.as_deref() == Some("enabled"),
        active: observation.active.as_deref() == Some("active"),
    })
}

pub(crate) fn restore_service_state(state_before: &ServiceStateSnapshot) -> Result<(), String> {
    let target_user = state_before.target_user.as_deref();
    for (verb, desired) in [
        (
            if state_before.enabled {
                "enable"
            } else {
                "disable"
            },
            state_before.enabled,
        ),
        (
            if state_before.active { "start" } else { "stop" },
            state_before.active,
        ),
    ] {
        let mut args = systemctl_scope_args(state_before.user, target_user);
        args.extend([verb.to_string(), state_before.name.clone()]);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let result = crate::atoms::command::capture_with_timeout("/usr/bin/systemctl", &refs, 30);
        if !result.ok {
            return Err(format!(
                "systemd-state-restore-{verb}-failed-{}: {}",
                state_before.name, result.stderr
            ));
        }
        let readback = snapshot_service_state(&state_before.name, state_before.user, target_user)?;
        let stood = if verb == "enable" || verb == "disable" {
            readback.enabled == desired
        } else {
            readback.active == desired
        };
        if !stood {
            return Err(format!(
                "systemd-state-restore-readback-mismatch-{}-{verb}",
                state_before.name
            ));
        }
    }
    let final_state = snapshot_service_state(&state_before.name, state_before.user, target_user)?;
    if final_state.enabled != state_before.enabled || final_state.active != state_before.active {
        return Err(format!(
            "systemd-state-restore-final-mismatch-{}",
            state_before.name
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SystemdObservation {
    pub(crate) enabled: Option<String>,
    pub(crate) active: Option<String>,
    pub(crate) load_state: Option<String>,
    pub(crate) unit_file_state: Option<String>,
    pub(crate) needs_reload: Option<String>,
    pub(crate) unit_present: Option<bool>,
    pub(crate) unit_file_exists: bool,
    pub(crate) probe: Option<CmdResult>,
}

#[derive(Clone)]
struct SystemdMovement {
    outcome: OperationOutcome,
    before: SystemdObservation,
    after: SystemdObservation,
}

fn observe_systemd_state(
    action: &str,
    service: &str,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
) -> SystemdObservation {
    // Special legacy permutations use the same settled read-only systemd
    // atoms as the ordinary service lane. The conductor never reaches into
    // a private tool rung.
    let probe = matches!(action, "unit-present" | "is-active-probe")
        .then(|| systemctl(action, service, user, target_user, timeout_secs));
    let unit_present = if action == "unit-present" {
        probe
            .as_ref()
            .map(|result| result.ok && result.stdout.trim() != "not-found")
    } else {
        None
    };
    SystemdObservation {
        enabled: state("is-enabled", service, user, target_user, timeout_secs),
        active: state("is-active", service, user, target_user, timeout_secs),
        load_state: state("load-state", service, user, target_user, timeout_secs),
        unit_file_state: state("unit-file-state", service, user, target_user, timeout_secs),
        needs_reload: state("needs-reload", service, user, target_user, timeout_secs),
        unit_present,
        unit_file_exists: action == "disable-stop-remove"
            && unit_file_path(service).is_some_and(|path| path.exists()),
        probe,
    }
}

fn comparison_fields(
    observation: &SystemdObservation,
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

fn augment_comparison_receipt(receipt_dir: &Path, name: &str, fields: Value) -> Result<(), String> {
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

fn desired_state(action: &str, service_material_changed: bool) -> Value {
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

fn decide_action(
    action: &str,
    observation: &SystemdObservation,
    service_material_changed: bool,
    restart_policy: Option<&str>,
) -> DiffDecision {
    let unit_absent = observation.load_state.as_deref() == Some("not-found")
        || observation.unit_file_state.as_deref() == Some("not-found");
    let different = match action {
        "unit-present" | "is-active-probe" => false,
        "daemon-reload" => service_material_changed,
        "restart" => {
            decide_restart_for_observation(observation, service_material_changed, restart_policy)
                .execute
        }
        "stop" => service_material_changed && !unit_absent,
        "enable" => observation.enabled.as_deref() != Some("enabled"),
        "enable-now" => {
            observation.enabled.as_deref() != Some("enabled")
                || observation.active.as_deref() != Some("active")
        }
        "disable-stop" => {
            !unit_absent
                && (observation.enabled.as_deref() != Some("disabled")
                    || observation.active.as_deref() == Some("active"))
        }
        "disable-stop-remove" => observation.unit_file_exists && !unit_absent,
        _ => true,
    };
    if different {
        DiffDecision::Different
    } else {
        DiffDecision::Empty
    }
}

#[allow(clippy::too_many_arguments)]
fn run_restart(
    receipt_dir: &Path,
    name: &str,
    service: Option<&str>,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
    apply: bool,
    service_material_changed: bool,
    restart_policy: Option<&str>,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    run_action_with_policy(
        receipt_dir,
        name,
        "restart",
        service,
        user,
        target_user,
        timeout_secs,
        apply,
        service_material_changed,
        restart_policy,
        invocation,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_action(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    service: Option<&str>,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
    apply: bool,
    service_material_changed: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    run_action_with_policy(
        receipt_dir,
        name,
        action,
        service,
        user,
        target_user,
        timeout_secs,
        apply,
        service_material_changed,
        None,
        invocation,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_action_with_policy(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    service: Option<&str>,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
    apply: bool,
    service_material_changed: bool,
    restart_policy: Option<&str>,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let service = service.unwrap_or("");
    // Edge-trigger actions are consumed only within this comparison run.
    let edge_triggered = matches!(action, "daemon-reload" | "restart");
    let acted = Cell::new(false);
    let run = comparison::execute(
        "systemd",
        || {
            Ok::<_, String>(observe_systemd_state(
                action,
                service,
                user,
                target_user,
                timeout_secs,
            ))
        },
        |observation| {
            if edge_triggered && acted.get() {
                DiffDecision::Empty
            } else {
                decide_action(
                    action,
                    observation,
                    service_material_changed,
                    restart_policy,
                )
            }
        },
        |authorization, before| {
            let result: Result<CmdResult, String> = if apply {
                let command = if action == "enable-now" {
                    crate::atoms::r#do::unit_change_scoped(
                        authorization,
                        invocation.ok_or("invocation-key-missing")?,
                        service,
                        crate::atoms::r#do::UnitVerb::EnableNow,
                        user,
                        target_user,
                        timeout_secs,
                    )
                    .map(|result| CmdResult {
                        ok: result.ok,
                        code: result.code.unwrap_or(if result.ok { 0 } else { -1 }),
                        stdout: result.stdout,
                        stderr: result.stderr,
                    })
                } else if matches!(action, "disable-stop" | "disable-stop-remove") {
                    crate::atoms::r#do::unit_change_scoped(
                        authorization,
                        invocation.ok_or("invocation-key-missing")?,
                        service,
                        crate::atoms::r#do::UnitVerb::DisableNow,
                        user,
                        target_user,
                        timeout_secs,
                    )
                    .map(|result| CmdResult {
                        ok: result.ok,
                        code: result.code.unwrap_or(if result.ok { 0 } else { -1 }),
                        stdout: result.stdout,
                        stderr: result.stderr,
                    })
                } else {
                    let invocation = invocation.ok_or("invocation-key-missing")?;
                    let verb = match action {
                        "daemon-reload" => crate::atoms::r#do::UnitVerb::DaemonReload,
                        "restart" => crate::atoms::r#do::UnitVerb::Restart,
                        "stop" => crate::atoms::r#do::UnitVerb::Stop,
                        "enable" => crate::atoms::r#do::UnitVerb::Enable,
                        other => return Err(format!("systemd-action-unsupported-{other}")),
                    };
                    crate::atoms::r#do::unit_change_scoped(
                        authorization,
                        invocation,
                        service,
                        verb,
                        user,
                        target_user,
                        timeout_secs,
                    )
                    .map(|result| CmdResult {
                        ok: result.ok,
                        code: result.code.unwrap_or(if result.ok { 0 } else { -1 }),
                        stdout: result.stdout,
                        stderr: result.stderr,
                    })
                };
                if edge_triggered {
                    // Consume the edge even when the command failed, so the
                    // command outcome is returned rather than reclassified.
                    acted.set(true);
                }
                command
            } else {
                if edge_triggered {
                    acted.set(true);
                }
                Ok(CmdResult {
                    ok: true,
                    code: 0,
                    stdout: format!("planned systemd {action} {service}"),
                    stderr: String::new(),
                })
            };
            let result = result?;
            let after = observe_systemd_state(action, service, user, target_user, timeout_secs);
            let restart_decision =
                decide_restart_for_observation(before, service_material_changed, restart_policy);
            let changed = apply
                && result.ok
                && (before.enabled != after.enabled
                    || before.active != after.active
                    || before.unit_file_state != after.unit_file_state
                    || before.unit_file_exists != after.unit_file_exists
                    || (matches!(action, "daemon-reload" | "restart") && service_material_changed)
                    || (action == "restart"
                        && restart_decision.execute
                        && (service_material_changed
                            || restart_policy == Some("always")
                            || restart_decision.reason == "unit-not-active")));
            Ok(SystemdMovement {
                outcome: OperationOutcome {
                    ok: result.ok,
                    changed,
                    skipped: !apply,
                    message: if action == "restart" {
                        restart_decision.reason.to_string()
                    } else {
                        format!(
                            "systemd{} {action} {service}",
                            if user { " --user" } else { "" }
                        )
                    },
                    command: Some(result),
                },
                before: before.clone(),
                after,
            })
        },
    )?;
    let observation = run.observation().clone();
    let decision = run.decision();
    let (outcome, before, after, movement) = match run {
        comparison::ComparisonRun::Current { .. } => {
            let probe = observation.probe.clone().map(|result| {
                if action == "unit-present" {
                    unit_present_result(result, service)
                } else {
                    result
                }
            });
            (
                OperationOutcome {
                    ok: probe.as_ref().is_none_or(|result| result.ok),
                    changed: false,
                    skipped: true,
                    message: if matches!(action, "unit-present" | "is-active-probe") {
                        format!(
                            "systemd{} {action} {service}",
                            if user { " --user" } else { "" }
                        )
                    } else {
                        "converged-quiet".to_string()
                    },
                    command: probe,
                },
                observation.clone(),
                observation,
                None,
            )
        }
        comparison::ComparisonRun::Moved { movement, .. } => {
            let before = movement.before.clone();
            let after = movement.after.clone();
            (
                movement.outcome.clone(),
                before,
                after,
                Some(movement.outcome),
            )
        }
    };
    let restart_decision = (action == "restart")
        .then(|| decide_restart_for_observation(&before, service_material_changed, restart_policy));
    let command = outcome.command.clone().unwrap_or(CmdResult {
        ok: outcome.ok,
        code: if outcome.ok { 0 } else { -1 },
        stdout: outcome.message.clone(),
        stderr: String::new(),
    });
    write_systemd_receipt(
        receipt_dir,
        name,
        action,
        service,
        user,
        apply,
        &command,
        before.enabled.as_deref(),
        before.active.as_deref(),
        after.enabled.as_deref(),
        after.active.as_deref(),
        outcome.changed,
        target_user,
        restart_decision,
        service_material_changed,
    )?;
    augment_comparison_receipt(
        receipt_dir,
        name,
        comparison_fields(
            &before,
            desired_state(action, service_material_changed),
            decision,
            movement.as_ref(),
            outcome.changed,
        ),
    )?;
    if matches!(
        action,
        "enable-now" | "disable-stop" | "disable-stop-remove"
    ) {
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
    Ok(outcome)
}

fn systemctl(
    action: &str,
    service: &str,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
) -> CmdResult {
    let mut args: Vec<String> = systemctl_scope_args(user, target_user);
    match action {
        "unit-present" => {
            args.extend([
                "show".to_string(),
                "--property=LoadState".to_string(),
                "--value".to_string(),
                service.to_string(),
            ]);
        }
        "load-state" => {
            args.extend([
                "show".to_string(),
                "--property=LoadState".to_string(),
                "--value".to_string(),
                service.to_string(),
            ]);
        }
        "unit-file-state" => {
            args.extend([
                "show".to_string(),
                "--property=UnitFileState".to_string(),
                "--value".to_string(),
                service.to_string(),
            ]);
        }
        "needs-reload" => {
            args.extend([
                "show".to_string(),
                "--property=NeedDaemonReload".to_string(),
                "--value".to_string(),
                service.to_string(),
            ]);
        }
        "is-active-probe" => {
            args.extend(["is-active".to_string(), service.to_string()]);
        }
        other => {
            return CmdResult {
                ok: false,
                code: -1,
                stdout: String::new(),
                stderr: format!("systemd-action-unsupported-{other}"),
            }
        }
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    crate::atoms::command::capture_with_timeout("/usr/bin/systemctl", &arg_refs, timeout_secs)
}

fn unit_present_result(mut result: CmdResult, service: &str) -> CmdResult {
    if result.ok && result.stdout.trim() == "not-found" {
        result.ok = false;
        result.code = 1;
        result.stderr = format!("systemd-unit-missing-{service}");
    }
    result
}

fn unit_file_path(service: &str) -> Option<PathBuf> {
    let path = Path::new(service);
    if service.is_empty()
        || path.is_absolute()
        || path.components().count() != 1
        || path.file_name().is_none()
    {
        return None;
    }
    Some(PathBuf::from("/etc/systemd/system").join(path))
}

fn systemctl_scope_args(user: bool, target_user: Option<&str>) -> Vec<String> {
    if !user {
        return Vec::new();
    }
    let mut args = vec!["--user".to_string()];
    if let Some(target_user) = target_user.filter(|value| !value.trim().is_empty()) {
        args.push(format!("--machine={target_user}@.host"));
    }
    args
}

fn state(
    kind: &str,
    service: &str,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
) -> Option<String> {
    if service.is_empty() {
        return None;
    }
    let mut args: Vec<String> = systemctl_scope_args(user, target_user);
    args.extend([kind.to_string(), service.to_string()]);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match kind {
        "load-state" | "unit-file-state" | "needs-reload" => {
            systemctl(kind, service, user, target_user, timeout_secs)
        }
        _ => crate::atoms::command::capture_with_timeout(
            "/usr/bin/systemctl",
            &arg_refs,
            timeout_secs,
        ),
    };
    if result.code == -1 {
        None
    } else {
        Some(result.stdout.trim().to_string())
    }
}

#[allow(clippy::too_many_arguments)]
fn write_systemd_receipt(
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

pub(crate) fn slice4_bench(
    root: &Path,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<serde_json::Value, String> {
    let receipts = root.join("receipts");
    std::fs::create_dir_all(&receipts).map_err(|e| e.to_string())?;
    let out = run_permutation(
        &receipts,
        "bench",
        "disable-stop-remove",
        Some("harmonia-slice4-never.service"),
        &[],
        None,
        1,
        false,
        false,
        invocation,
    )?;
    let receipt = receipts.join("bench.json").exists();
    Ok(
        serde_json::json!({"planned":out.ok,"apply":false,"typed_receipt":receipt,"argv_candidate":"harmonia-slice4-never.service","removal_planned":false,"restart_restrained":true,"no_live_mutation":true,"ok":out.ok && receipt && !out.changed}),
    )
}

pub(crate) fn execute_validated_step(
    step: &crate::ladder::ValidatedStep,
    module_dir: &std::path::Path,
    apply: bool,
    changed: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<crate::OperationOutcome, String> {
    let units: Vec<String> = step
        .args
        .get("candidate_units")
        .and_then(serde_json::Value::as_array)
        .map(|xs| {
            xs.iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();
    run_permutation(
        module_dir,
        &step.step_id,
        &step.permutation,
        step.args.get("service").and_then(serde_json::Value::as_str),
        &units,
        step.args.get("user").and_then(serde_json::Value::as_str),
        step.args
            .get("timeout_secs")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(30),
        apply,
        changed,
        invocation,
    )
}
