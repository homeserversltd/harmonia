use super::comparison::{self, DiffDecision};
use crate::atoms::ask::change_unit;
use crate::atoms::attest::change_unit as attest_change_unit;
use crate::{CmdResult, OperationOutcome};
use std::cell::Cell;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RestartDecision {
    pub(crate) execute: bool,
    pub(crate) reason: &'static str,
}

pub(crate) fn decide_restart(service_material_changed: bool) -> RestartDecision {
    if service_material_changed {
        RestartDecision { execute: true, reason: "service-material-changed" }
    } else {
        RestartDecision { execute: false, reason: "service-material-unchanged" }
    }
}

pub(crate) fn decide_restart_for_observation(
    observation: &change_unit::Observation,
    material: bool,
    policy: Option<&str>,
) -> RestartDecision {
    match observation.active.as_deref() {
        Some("active") if policy == Some("always") => RestartDecision { execute: true, reason: "restart-policy-always" },
        Some("active") if material => RestartDecision { execute: true, reason: "service-material-changed" },
        Some("active") => RestartDecision { execute: false, reason: "service-material-unchanged" },
        Some("inactive") | Some("failed") | Some("not-found") => RestartDecision { execute: true, reason: "unit-not-active" },
        _ => RestartDecision { execute: false, reason: "service-state-unknown" },
    }
}

#[derive(Clone)]
struct SystemdMovement {
    outcome: OperationOutcome,
    before: change_unit::Observation,
    after: change_unit::Observation,
}

fn decide_action(
    action: &str,
    observation: &change_unit::Observation,
    service_material_changed: bool,
    restart_policy: Option<&str>,
) -> DiffDecision {
    let unit_absent = observation.load_state.as_deref() == Some("not-found")
        || observation.unit_file_state.as_deref() == Some("not-found");
    let different = match action {
        "unit-present" | "is-active-probe" => false,
        "daemon-reload" => service_material_changed,
        "restart" => decide_restart_for_observation(observation, service_material_changed, restart_policy).execute,
        "stop" => service_material_changed && !unit_absent,
        "enable" => observation.enabled.as_deref() != Some("enabled"),
        "enable-now" => observation.enabled.as_deref() != Some("enabled") || observation.active.as_deref() != Some("active"),
        "disable-stop" => !unit_absent && (observation.enabled.as_deref() != Some("disabled") || observation.active.as_deref() == Some("active")),
        "disable-stop-remove" => observation.unit_file_exists && !unit_absent,
        _ => true,
    };
    if different { DiffDecision::Different } else { DiffDecision::Empty }
}

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
        if !is_removable_unit_basename(unit) {
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
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
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
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    if permutation == "mask" {
        return run_mask(
            receipt_dir,
            name,
            service.unwrap_or(""),
            timeout_secs,
            apply,
            invocation,
        );
    }
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
            is_removable_unit_basename(selected)
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

fn run_mask(
    receipt_dir: &Path,
    name: &str,
    service: &str,
    timeout_secs: u64,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let before = change_unit::state("is-enabled", service, false, None, timeout_secs);
    let Some(before) = before else {
        let command = CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: "systemd-mask-state-read-failed".into(),
        };
        attest_change_unit::write_systemd_receipt(receipt_dir, name, "mask", service, false, apply, &command,
            None, None, None, None, false, None, None, false)?;
        return Ok(OperationOutcome { ok: false, changed: false, skipped: true,
            message: "systemd-mask-state-read-failed".into(), command: Some(command) });
    };
    if before == "masked" {
        let command = CmdResult { ok: true, code: 0, stdout: "masked".into(), stderr: String::new() };
        attest_change_unit::write_systemd_receipt(receipt_dir, name, "mask", service, false, apply, &command,
            Some(&before), None, Some(&before), None, false, None, None, false)?;
        return Ok(OperationOutcome { ok: true, changed: false, skipped: true,
            message: "converged-quiet".into(), command: Some(command) });
    }
    if !apply {
        let command = CmdResult { ok: true, code: 0,
            stdout: format!("planned systemd mask {service}"), stderr: String::new() };
        attest_change_unit::write_systemd_receipt(receipt_dir, name, "mask", service, false, false, &command,
            Some(&before), None, Some(&before), None, false, None, None, false)?;
        return Ok(OperationOutcome { ok: true, changed: false, skipped: true,
            message: format!("planned systemd mask {service}"), command: Some(command) });
    }
    let run = comparison::execute_with_failure_receipt(
        "systemd-mask",
        || change_unit::state("is-enabled", service, false, None, timeout_secs)
            .ok_or_else(|| "systemd-mask-state-read-failed".to_string()),
        |observed| if observed == "masked" { DiffDecision::Empty } else { DiffDecision::Different },
        |authorization, _observed| {
            let result = crate::atoms::r#do::change_unit::unit_change_scoped(
                &authorization,
                invocation.ok_or("invocation-key-missing")?,
                service,
                crate::atoms::r#do::change_unit::UnitVerb::Mask,
                false,
                None,
                timeout_secs,
            )?;
            Ok(CmdResult { ok: result.ok, code: result.code.unwrap_or(if result.ok { 0 } else { -1 }),
                stdout: result.stdout, stderr: result.stderr })
        },
        |_before, _movement, _after| Ok(()),
    )?;
    let command = match run {
        comparison::ComparisonRun::Current { .. } => CmdResult { ok: true, code: 0, stdout: "masked".into(), stderr: String::new() },
        comparison::ComparisonRun::Moved { movement, .. } => movement,
    };
    attest_change_unit::write_systemd_receipt(receipt_dir, name, "mask", service, false, true, &command,
        Some(&before), None, Some("masked"), None, command.ok && before != "masked", None, None, false)?;
    Ok(OperationOutcome { ok: command.ok, changed: command.ok && before != "masked", skipped: false,
        message: if command.ok { format!("systemd mask {service}") } else { "systemd-mask-command-failed".into() },
        command: Some(command) })
}

fn run_enable_first_present_now(
    receipt_dir: &Path,
    name: &str,
    candidate_units: &[String],
    timeout_secs: u64,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
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
    attest_change_unit::annotate_candidate_selection(receipt_dir, name, candidate_units, &service)?;
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
        let result = change_unit::systemctl("unit-present", unit, false, None, timeout_secs);
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
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
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
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
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
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let service = service.unwrap_or("");
    // Edge-trigger actions are consumed only within this comparison run.
    let edge_triggered = matches!(action, "daemon-reload" | "restart");
    let acted = Cell::new(false);
    let run = comparison::execute(
        "systemd",
        || {
            Ok::<_, String>(change_unit::observe_systemd_state(
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
            let authorization = &authorization;
            let result: Result<CmdResult, String> = if apply {
                let command = if action == "enable-now" {
                    crate::atoms::r#do::change_unit::unit_change_scoped(
                        authorization,
                        invocation.ok_or("invocation-key-missing")?,
                        service,
                        crate::atoms::r#do::change_unit::UnitVerb::EnableNow,
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
                    crate::atoms::r#do::change_unit::unit_change_scoped(
                        authorization,
                        invocation.ok_or("invocation-key-missing")?,
                        service,
                        crate::atoms::r#do::change_unit::UnitVerb::DisableNow,
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
                        "daemon-reload" => crate::atoms::r#do::change_unit::UnitVerb::DaemonReload,
                        "restart" => crate::atoms::r#do::change_unit::UnitVerb::Restart,
                        "stop" => crate::atoms::r#do::change_unit::UnitVerb::Stop,
                        "enable" => crate::atoms::r#do::change_unit::UnitVerb::Enable,
                        other => return Err(format!("systemd-action-unsupported-{other}")),
                    };
                    crate::atoms::r#do::change_unit::unit_change_scoped(
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
            let after = change_unit::observe_systemd_state(action, service, user, target_user, timeout_secs);
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
                    change_unit::unit_present_result(result, service)
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
    attest_change_unit::write_systemd_receipt(
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
    attest_change_unit::augment_comparison_receipt(
        receipt_dir,
        name,
        attest_change_unit::comparison_fields(
            &before,
            attest_change_unit::desired_state(action, service_material_changed),
            decision,
            movement.as_ref(),
            outcome.changed,
        ),
    )?;
    crate::atoms::attest::change_unit::attest_change_unit(receipt_dir, action, service, &command)?;
    Ok(outcome)
}


pub(crate) fn demo(
    root: &Path,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<serde_json::Value, String> {
    let receipts = root.join("receipts");
    std::fs::create_dir_all(&receipts).map_err(|e| e.to_string())?;
    let out = run_permutation(
        &receipts,
        "demo",
        "disable-stop-remove",
        Some("harmonia-demo-never.service"),
        &[],
        None,
        1,
        false,
        false,
        invocation,
    )?;
    let receipt = receipts.join("demo.json").exists();
    Ok(
        serde_json::json!({"planned":out.ok,"apply":false,"typed_receipt":receipt,"argv_candidate":"harmonia-demo-never.service","removal_planned":false,"restart_restrained":true,"no_live_mutation":true,"ok":out.ok && receipt && !out.changed}),
    )
}

pub(crate) fn execute_validated_step(
    step: &crate::tools::ladder::ValidatedStep,
    module_dir: &std::path::Path,
    apply: bool,
    changed: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
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
