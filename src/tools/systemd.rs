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
        "reload the system systemd manager",
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
        "disable-stop-remove",
        "disable and stop a system unit, then remove its unit file",
        &[
            ToolArg::required("service", ToolArgKind::String),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ),
    ToolPermutation::new(
        "restart",
        "restart a system unit",
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
        "reload the user systemd manager",
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
        "restart a user unit",
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

pub(crate) fn run_permutation(
    receipt_dir: &Path,
    name: &str,
    permutation: &str,
    service: Option<&str>,
    target_user: Option<&str>,
    timeout_secs: u64,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let user = permutation.starts_with("user-");
    let action = permutation.strip_prefix("user-").unwrap_or(permutation);
    run_action(
        receipt_dir,
        name,
        action,
        service,
        user,
        target_user,
        timeout_secs,
        apply,
    )
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
) -> Result<OperationOutcome, String> {
    let service = service.unwrap_or("");
    let mutating = matches!(
        action,
        "daemon-reload" | "enable-now" | "disable-stop-remove" | "restart" | "stop"
    );
    let unit_file_before = if action == "disable-stop-remove" {
        unit_file_path(service).is_some_and(|path| path.exists())
    } else {
        false
    };
    let before_enabled = state("is-enabled", service, user, target_user, timeout_secs);
    let before_active = state("is-active", service, user, target_user, timeout_secs);
    let result = if mutating && !apply {
        CmdResult {
            ok: true,
            code: 0,
            stdout: format!("planned systemd {action} {service}"),
            stderr: String::new(),
        }
    } else {
        systemctl(action, service, user, target_user, timeout_secs)
    };
    let after_enabled = state("is-enabled", service, user, target_user, timeout_secs);
    let after_active = state("is-active", service, user, target_user, timeout_secs);
    let changed = mutating
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
    )?;
    Ok(OperationOutcome {
        ok: result.ok,
        changed,
        skipped: mutating && !apply,
        message: format!(
            "systemd{} {action} {service}",
            if user { " --user" } else { "" }
        ),
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
        "disable-stop-remove" => return disable_stop_remove(service, user, timeout_secs),
        "restart" | "stop" => {
            args.extend([action.to_string(), service.to_string()]);
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

    let args = ["disable", "--now", service];
    let mut result =
        crate::tools::command::capture_with_timeout("/usr/bin/systemctl", &args, timeout_secs);
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
}
