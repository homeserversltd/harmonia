use super::{ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::{write_json, CmdResult, OperationOutcome};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

pub const NAME: &str = "systemd";
pub const DESCRIPTION: &str =
    "Systemd unit lifecycle primitive with observed is-enabled/is-active before/after receipts.";
pub const PERMUTATIONS: &[ToolPermutation] = &[
    ToolPermutation::new(
        "daemon-reload",
        "reload the system systemd manager only when this module changed managed material",
        &[ToolArg::optional("timeout_secs", ToolArgKind::Integer)],
    ),
    ToolPermutation::new(
        "enable-now",
        "enable and start a system unit",
        &[
            ToolArg::required("service", ToolArgKind::String),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ),
    ToolPermutation::new(
        "enable-first-present-now",
        "select the first present system unit from an ordered typed candidate list, then enable and start it",
        &[
            ToolArg::required("candidate_units", ToolArgKind::StringArray),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ),
    ToolPermutation::new(
        "unit-present",
        "assert that a system unit is loaded without enabling or starting it",
        &[
            ToolArg::required("service", ToolArgKind::String),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ),
    ToolPermutation::new(
        "disable-stop-remove",
        "disable and stop a system unit, then remove its unit file",
        &[
            ToolArg::required("service", ToolArgKind::String),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ),
    ToolPermutation::new(
        "disable-stop",
        "disable and stop a system unit while preserving its unit file",
        &[
            ToolArg::required("service", ToolArgKind::String),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ),
    ToolPermutation::new(
        "restart",
        "restart a system unit only when this module changed managed material",
        &[
            ToolArg::required("service", ToolArgKind::String),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ),
    ToolPermutation::new(
        "is-active-probe",
        "probe active state for a system unit",
        &[
            ToolArg::required("service", ToolArgKind::String),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ),
    ToolPermutation::new(
        "user-daemon-reload",
        "reload the user systemd manager only when this module changed managed material",
        &[
            ToolArg::optional("user", ToolArgKind::String),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ),
    ToolPermutation::new(
        "user-enable-now",
        "enable and start a user unit",
        &[
            ToolArg::required("service", ToolArgKind::String),
            ToolArg::optional("user", ToolArgKind::String),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ),
    ToolPermutation::new(
        "user-restart",
        "restart a user unit only when this module changed managed material",
        &[
            ToolArg::required("service", ToolArgKind::String),
            ToolArg::optional("user", ToolArgKind::String),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ),
    ToolPermutation::new(
        "user-is-active-probe",
        "probe active state for a user unit",
        &[
            ToolArg::required("service", ToolArgKind::String),
            ToolArg::optional("user", ToolArgKind::String),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ),
];
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION, PERMUTATIONS);

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
) -> Result<OperationOutcome, String> {
    if permutation == "enable-first-present-now" {
        return run_enable_first_present_now(
            receipt_dir,
            name,
            candidate_units,
            timeout_secs,
            apply,
        );
    }
    let user = permutation.starts_with("user-");
    let action = permutation.strip_prefix("user-").unwrap_or(permutation);
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
    )
}

fn run_enable_first_present_now(
    receipt_dir: &Path,
    name: &str,
    candidate_units: &[String],
    timeout_secs: u64,
    apply: bool,
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
    let path = Path::new(unit);
    !unit.is_empty()
        && unit.ends_with(".service")
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
) -> Result<OperationOutcome, String> {
    let service = service.unwrap_or("");
    let active_before = state("is-active", service, user, target_user, timeout_secs);
    let decision = decide_restart(service_material_changed);
    if !decision.execute {
        let result = CmdResult {
            ok: true,
            code: 0,
            stdout: "restart skipped: converged-quiet".to_string(),
            stderr: String::new(),
        };
        write_systemd_receipt(
            receipt_dir,
            name,
            "restart",
            service,
            user,
            apply,
            &result,
            None,
            active_before.as_deref(),
            None,
            active_before.as_deref(),
            false,
            target_user,
            Some(decision),
            service_material_changed,
        )?;
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "converged-quiet".to_string(),
            command: Some(result),
        });
    }
    let result = if apply {
        systemctl("restart", service, user, target_user, timeout_secs)
    } else {
        CmdResult {
            ok: true,
            code: 0,
            stdout: format!("planned systemd restart {service}"),
            stderr: String::new(),
        }
    };
    let active_after = state("is-active", service, user, target_user, timeout_secs);
    let changed = result.ok && apply && service_material_changed;
    write_systemd_receipt(
        receipt_dir,
        name,
        "restart",
        service,
        user,
        apply,
        &result,
        None,
        active_before.as_deref(),
        None,
        active_after.as_deref(),
        changed,
        target_user,
        Some(decision),
        service_material_changed,
    )?;
    Ok(OperationOutcome {
        ok: result.ok,
        changed,
        skipped: !apply,
        message: decision.reason.to_string(),
        command: Some(result),
    })
}

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
) -> Result<OperationOutcome, String> {
    let service = service.unwrap_or("");
    let mutating = matches!(
        action,
        "daemon-reload"
            | "enable-now"
            | "disable-stop"
            | "disable-stop-remove"
            | "restart"
            | "stop"
    );
    let unit_file_before = if action == "disable-stop-remove" {
        unit_file_path(service).is_some_and(|path| path.exists())
    } else {
        false
    };
    let before_enabled = state("is-enabled", service, user, target_user, timeout_secs);
    let before_active = state("is-active", service, user, target_user, timeout_secs);
    let unit_absent_already_satisfied =
        if matches!(action, "disable-stop" | "disable-stop-remove" | "stop") {
            let presence = systemctl("unit-present", service, user, target_user, timeout_secs);
            presence.ok && presence.stdout.trim() == "not-found"
        } else {
            false
        };
    let action_needed = match action {
        "daemon-reload" | "restart" => service_material_changed,
        "stop" => service_material_changed && !unit_absent_already_satisfied,
        "enable-now" => {
            before_enabled.as_deref() != Some("enabled")
                || before_active.as_deref() != Some("active")
        }
        "disable-stop" => {
            !unit_absent_already_satisfied
                && (before_enabled.as_deref() != Some("disabled")
                    || before_active.as_deref() == Some("active"))
        }
        "disable-stop-remove" => unit_file_before && !unit_absent_already_satisfied,
        _ => true,
    };
    let mut result = if apply && unit_absent_already_satisfied {
        CmdResult {
            ok: true,
            code: 0,
            stdout: "unit-absent-already-satisfied".to_string(),
            stderr: String::new(),
        }
    } else if mutating && (!apply || !action_needed) {
        CmdResult {
            ok: true,
            code: 0,
            stdout: if !apply {
                format!("planned systemd {action} {service}")
            } else {
                format!("systemd {action} skipped: converged-quiet")
            },
            stderr: String::new(),
        }
    } else {
        systemctl(action, service, user, target_user, timeout_secs)
    };
    if action == "unit-present" {
        result = unit_present_result(result, service);
    }
    let after_enabled = state("is-enabled", service, user, target_user, timeout_secs);
    let after_active = state("is-active", service, user, target_user, timeout_secs);
    let changed = mutating
        && action_needed
        && apply
        && result.ok
        && (before_enabled != after_enabled || before_active != after_active || unit_file_before);
    write_systemd_receipt(
        receipt_dir,
        name,
        action,
        service,
        user,
        apply,
        &result,
        before_enabled.as_deref(),
        before_active.as_deref(),
        after_enabled.as_deref(),
        after_active.as_deref(),
        changed,
        target_user,
        None,
        service_material_changed,
    )?;
    Ok(OperationOutcome {
        ok: result.ok,
        changed,
        skipped: mutating && (!apply || !action_needed),
        message: if apply && unit_absent_already_satisfied {
            "unit-absent-already-satisfied".to_string()
        } else if mutating && apply && !action_needed {
            "converged-quiet".to_string()
        } else {
            format!(
                "systemd{} {action} {service}",
                if user { " --user" } else { "" }
            )
        },
        command: Some(result),
    })
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
        "daemon-reload" => args.push("daemon-reload".to_string()),
        "enable-now" => {
            args.extend([
                "enable".to_string(),
                "--now".to_string(),
                service.to_string(),
            ]);
        }
        "disable-stop" => return disable_stop(service, user, timeout_secs),
        "disable-stop-remove" => return disable_stop_remove(service, user, timeout_secs),
        "restart" | "stop" => {
            args.extend([action.to_string(), service.to_string()]);
        }
        "unit-present" => {
            args.extend([
                "show".to_string(),
                "--property=LoadState".to_string(),
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
    crate::tools::command::capture_with_timeout("/usr/bin/systemctl", &arg_refs, timeout_secs)
}

fn unit_present_result(mut result: CmdResult, service: &str) -> CmdResult {
    if result.ok && result.stdout.trim() == "not-found" {
        result.ok = false;
        result.code = 1;
        result.stderr = format!("systemd-unit-missing-{service}");
    }
    result
}

fn disable_stop_remove(service: &str, user: bool, timeout_secs: u64) -> CmdResult {
    if user {
        return CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: "systemd-action-unsupported-user-disable-stop-remove".to_string(),
        };
    }
    let Some(unit_file) = unit_file_path(service) else {
        return CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: format!("systemd-unit-name-invalid-{service}"),
        };
    };
    if !unit_file.exists() {
        return CmdResult {
            ok: true,
            code: 0,
            stdout: format!("unit file absent: {}", unit_file.display()),
            stderr: String::new(),
        };
    }

    let mut result = disable_stop(service, user, timeout_secs);
    if !result.ok {
        return result;
    }
    if let Err(err) = fs::remove_file(&unit_file) {
        result.ok = false;
        result.code = -1;
        result.stderr = format!(
            "{}{}systemd-unit-remove-failed {}: {err}",
            result.stderr,
            if result.stderr.is_empty() { "" } else { "\n" },
            unit_file.display(),
        );
        return result;
    }
    if !result.stdout.is_empty() {
        result.stdout.push('\n');
    }
    result
        .stdout
        .push_str(&format!("removed unit file: {}", unit_file.display()));
    result
}

fn disable_stop(service: &str, user: bool, timeout_secs: u64) -> CmdResult {
    if user {
        return CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: "systemd-action-unsupported-user-disable-stop".to_string(),
        };
    }
    let args = ["disable", "--now", service];
    crate::tools::command::capture_with_timeout("/usr/bin/systemctl", &args, timeout_secs)
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
    let result =
        crate::tools::command::capture_with_timeout("/usr/bin/systemctl", &arg_refs, timeout_secs);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ladder::{load_ladder_manifest, validate_ladder};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("harmonia-systemd-{name}-{stamp}"))
    }

    #[test]
    fn user_scope_args_use_machine_transport_when_target_user_declared() {
        assert_eq!(
            systemctl_scope_args(true, Some("owner")),
            vec!["--user".to_string(), "--machine=owner@.host".to_string()]
        );
        assert_eq!(
            systemctl_scope_args(false, Some("owner")),
            Vec::<String>::new()
        );
    }

    #[test]
    fn tv_user_session_manifest_declares_target_user_for_user_systemd_steps() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let manifest = load_ladder_manifest(
            &root.join("profiles/tv/modules/user-session-services/manifest.json"),
        )
        .unwrap();
        let steps = validate_ladder(&manifest).unwrap();
        for step in steps
            .iter()
            .filter(|step| step.permutation.starts_with("user-"))
        {
            assert_eq!(
                step.args.get("user").and_then(|v| v.as_str()),
                Some("owner")
            );
        }
    }

    #[test]
    fn planned_user_systemd_receipt_names_machine_user_transport() {
        let root = temp_root("receipt");
        fs::create_dir_all(&root).unwrap();
        run_action(
            &root,
            "user-daemon-reload",
            "daemon-reload",
            None,
            true,
            Some("owner"),
            30,
            false,
            false,
        )
        .unwrap();
        let receipt: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join("user-daemon-reload.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["scope"], "user");
        assert_eq!(receipt["target_user"], "owner");
        assert_eq!(receipt["systemctl_transport"], "machine-user");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn disable_stop_remove_is_declared_and_dry_run_is_a_clean_absent_unit_plan() {
        assert!(PERMUTATIONS
            .iter()
            .any(|permutation| permutation.name == "disable-stop-remove"));
        let root = temp_root("disable-stop-remove-plan");
        fs::create_dir_all(&root).unwrap();
        let outcome = run_action(
            &root,
            "retire-absent",
            "disable-stop-remove",
            Some("harmonia-never-installed-for-test.service"),
            false,
            None,
            30,
            false,
            false,
        )
        .unwrap();
        assert!(outcome.ok);
        assert!(outcome.skipped);
        assert!(!outcome.changed);
        let receipt: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(root.join("retire-absent.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["action"], "disable-stop-remove");
        assert_eq!(receipt["ok"], true);
        assert_eq!(receipt["apply"], false);
        assert_eq!(receipt["changed"], false);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn retire_unit_file_accepts_only_a_unit_basename() {
        assert_eq!(
            unit_file_path("harmonia.service"),
            Some(PathBuf::from("/etc/systemd/system/harmonia.service"))
        );
        assert_eq!(unit_file_path("../harmonia.service"), None);
        assert_eq!(unit_file_path("/etc/systemd/system/harmonia.service"), None);
    }

    #[test]
    fn unchanged_service_material_skips_restart_and_receipts_the_restraint() {
        let decision = decide_restart(false);
        assert!(!decision.execute);
        assert_eq!(decision.reason, "service-material-unchanged");

        let root = temp_root("restart-skip");
        fs::create_dir_all(&root).unwrap();
        let result = CmdResult {
            ok: true,
            code: 0,
            stdout: "restart skipped by change-driven policy".into(),
            stderr: String::new(),
        };
        write_systemd_receipt(
            &root,
            "service-restart",
            "restart",
            "example.service",
            false,
            true,
            &result,
            None,
            Some("active"),
            None,
            Some("active"),
            false,
            None,
            Some(decision),
            false,
        )
        .unwrap();
        let receipt: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(root.join("service-restart.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["restart_decision"], "skipped");
        assert_eq!(receipt["restart_reason"], "service-material-unchanged");
        assert_eq!(receipt["service_material_changed"], false);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn changed_service_material_restarts_and_receipts_the_change_reason() {
        let decision = decide_restart(true);
        assert!(decision.execute);
        assert_eq!(decision.reason, "service-material-changed");

        let root = temp_root("restart-change");
        fs::create_dir_all(&root).unwrap();
        let result = CmdResult {
            ok: true,
            code: 0,
            stdout: "restarted".into(),
            stderr: String::new(),
        };
        write_systemd_receipt(
            &root,
            "service-restart",
            "restart",
            "example.service",
            false,
            true,
            &result,
            None,
            Some("active"),
            None,
            Some("active"),
            true,
            None,
            Some(decision),
            true,
        )
        .unwrap();
        let receipt: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(root.join("service-restart.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["restart_decision"], "restarted");
        assert_eq!(receipt["restart_reason"], "service-material-changed");
        assert_eq!(receipt["service_material_changed"], true);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unit_state_never_bypasses_the_material_change_gate() {
        let decision = decide_restart(false);
        assert!(!decision.execute);
        assert_eq!(decision.reason, "service-material-unchanged");
    }

    #[test]
    fn material_change_is_the_only_restart_gate() {
        assert!(!decide_restart(false).execute);
        assert!(decide_restart(true).execute);
    }

    #[test]
    fn enable_first_present_now_selects_the_first_available_candidate_in_order() {
        let candidates = vec![
            "systemd-timesyncd.service".to_string(),
            "chronyd.service".to_string(),
            "ntpd.service".to_string(),
        ];
        let mut probed = Vec::new();
        let selected = first_present_candidate(&candidates, |unit| {
            probed.push(unit.to_string());
            Ok(unit == "chronyd.service")
        })
        .unwrap();
        assert_eq!(selected, "chronyd.service");
        assert_eq!(
            probed,
            vec![
                "systemd-timesyncd.service".to_string(),
                "chronyd.service".to_string(),
            ]
        );
    }
}
