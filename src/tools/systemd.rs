use super::{ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::{write_json, CmdResult, OperationOutcome};
use serde_json::json;
use std::path::Path;

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
        &[ToolArg::optional("timeout_secs", ToolArgKind::Integer)],
    ),
    ToolPermutation::new(
        "user-enable-now",
        "enable and start a user unit",
        &[
            ToolArg::required("service", ToolArgKind::String),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ),
    ToolPermutation::new(
        "user-restart",
        "restart a user unit",
        &[
            ToolArg::required("service", ToolArgKind::String),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ),
    ToolPermutation::new(
        "user-is-active-probe",
        "probe active state for a user unit",
        &[
            ToolArg::required("service", ToolArgKind::String),
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
    timeout_secs: u64,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let service = service.unwrap_or("");
    let mutating = matches!(action, "daemon-reload" | "enable-now" | "restart" | "stop");
    let before_enabled = state("is-enabled", service, user, timeout_secs);
    let before_active = state("is-active", service, user, timeout_secs);
    let result = if mutating && !apply {
        CmdResult {
            ok: true,
            code: 0,
            stdout: format!("planned systemd {action} {service}"),
            stderr: String::new(),
        }
    } else {
        systemctl(action, service, user, timeout_secs)
    };
    let after_enabled = state("is-enabled", service, user, timeout_secs);
    let after_active = state("is-active", service, user, timeout_secs);
    let changed =
        mutating && result.ok && (before_enabled != after_enabled || before_active != after_active);
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

fn systemctl(action: &str, service: &str, user: bool, timeout_secs: u64) -> CmdResult {
    let mut args: Vec<&str> = Vec::new();
    if user {
        args.push("--user");
    }
    match action {
        "daemon-reload" => args.push("daemon-reload"),
        "enable-now" => {
            args.extend(["enable", "--now", service]);
        }
        "restart" | "stop" => {
            args.extend([action, service]);
        }
        "is-active-probe" => {
            args.extend(["is-active", service]);
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
    crate::tools::command::capture_with_timeout("/usr/bin/systemctl", &args, timeout_secs)
}

fn state(kind: &str, service: &str, user: bool, timeout_secs: u64) -> Option<String> {
    if service.is_empty() {
        return None;
    }
    let mut args: Vec<&str> = Vec::new();
    if user {
        args.push("--user");
    }
    args.extend([kind, service]);
    let result =
        crate::tools::command::capture_with_timeout("/usr/bin/systemctl", &args, timeout_secs);
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
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{}.json", name)),
        &json!({
            "schema": "harmonia.systemd.receipt.v1",
            "name": name,
            "action": action,
            "service": service,
            "scope": if user { "user" } else { "system" },
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
