use crate::CmdResult;
use std::path::{Path, PathBuf};

fn is_removable_unit_basename(unit: &str) -> bool {
    is_syntactic_unit_basename(unit)
        && [".service", ".socket", ".target", ".device", ".mount", ".automount", ".swap", ".path", ".timer", ".slice", ".scope", ".busname", ".snapshot"]
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

#[derive(Clone, Debug)]
pub(crate) struct ServiceStateSnapshot {
    pub name: String,
    pub user: bool,
    pub target_user: Option<String>,
    pub enabled: bool,
    pub active: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct Observation {
    pub(crate) enabled: Option<String>,
    pub(crate) active: Option<String>,
    pub(crate) load_state: Option<String>,
    pub(crate) unit_file_state: Option<String>,
    pub(crate) needs_reload: Option<String>,
    pub(crate) unit_present: Option<bool>,
    pub(crate) unit_file_exists: bool,
    pub(crate) probe: Option<CmdResult>,
    pub(crate) condition_show: Option<CmdResult>,
    pub(crate) condition_snapshot: Option<ConditionSnapshot>,
    pub(crate) condition_probe_error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ConditionSnapshot {
    pub(crate) load_state: String,
    pub(crate) active_state: String,
    pub(crate) condition_result: String,
    // systemd 257 may return "[unprintable]" here; preserve it, never parse it.
    pub(crate) conditions: String,
    pub(crate) status: Option<CmdResult>,
    pub(crate) failed_conditions: Vec<String>,
}

fn observe_condition_snapshot(
    service: &str,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
    probe: Option<&CmdResult>,
) -> (Option<CmdResult>, Option<ConditionSnapshot>, Option<String>) {
    let show = systemctl("condition-show", service, user, target_user, timeout_secs);
    if !show.ok {
        return (
            Some(show),
            None,
            Some("systemd-condition-show-failed".to_string()),
        );
    }
    let snapshot = match parse_condition_snapshot(&show.stdout) {
        Ok(snapshot) => snapshot,
        Err(error) => return (Some(show), None, Some(error)),
    };
    let inactive_condition_unmet = probe
        .is_some_and(|result| !result.ok && result.code == 3 && result.stdout.trim() == "inactive")
        && snapshot.load_state == "loaded"
        && snapshot.active_state == "inactive"
        && snapshot.condition_result == "no";
    if !inactive_condition_unmet {
        return (Some(show), Some(snapshot), None);
    }
    let mut snapshot = snapshot;
    let status = systemctl("condition-status", service, user, target_user, timeout_secs);
    snapshot.failed_conditions = failed_condition_lines(&status.stdout);
    let status_error = if status.code != 3 {
        Some("systemd-condition-status-unconfirmed".to_string())
    } else if snapshot.failed_conditions.is_empty() {
        Some("systemd-condition-detail-missing".to_string())
    } else {
        None
    };
    snapshot.status = Some(status);
    (Some(show), Some(snapshot), status_error)
}

pub(crate) fn observe_systemd_state(
    action: &str,
    service: &str,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
) -> Observation {
    // Special legacy permutations use the same settled read-only systemd
    // atoms as the ordinary service lane. The conductor never reaches into
    // a private tool rung.
    let probe = matches!(action, "unit-present" | "is-active-probe")
        .then(|| systemctl(action, service, user, target_user, timeout_secs));
    let (condition_show, condition_snapshot, condition_probe_error) = if action == "is-active-probe"
    {
        observe_condition_snapshot(service, user, target_user, timeout_secs, probe.as_ref())
    } else {
        (None, None, None)
    };
    let unit_present = if action == "unit-present" {
        probe
            .as_ref()
            .map(|result| result.ok && result.stdout.trim() != "not-found")
    } else {
        None
    };
    Observation {
        enabled: state("is-enabled", service, user, target_user, timeout_secs),
        active: state("is-active", service, user, target_user, timeout_secs),
        load_state: state("load-state", service, user, target_user, timeout_secs),
        unit_file_state: state("unit-file-state", service, user, target_user, timeout_secs),
        needs_reload: state("needs-reload", service, user, target_user, timeout_secs),
        unit_present,
        unit_file_exists: action == "disable-stop-remove"
            && unit_file_path(service).is_some_and(|path| path.exists()),
        probe,
        condition_show,
        condition_snapshot,
        condition_probe_error,
    }
}

fn parse_condition_snapshot(output: &str) -> Result<ConditionSnapshot, String> {
    let expected = ["LoadState", "ActiveState", "ConditionResult", "Conditions"];
    let mut properties = std::collections::BTreeMap::new();
    for line in output.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err("systemd-condition-show-malformed".to_string());
        };
        if !expected.contains(&key) || value.is_empty() {
            return Err("systemd-condition-show-invalid-property".to_string());
        }
        if properties.insert(key, value).is_some() {
            return Err("systemd-condition-show-duplicate-property".to_string());
        }
    }
    if properties.len() != expected.len() {
        return Err("systemd-condition-show-property-missing".to_string());
    }
    let load_state = properties["LoadState"];
    let active_state = properties["ActiveState"];
    let condition_result = properties["ConditionResult"];
    let conditions = properties["Conditions"];
    if !matches!(
        load_state,
        "stub" | "loaded" | "not-found" | "bad-setting" | "error" | "merged" | "masked"
    ) || !matches!(
        active_state,
        "active" | "reloading" | "inactive" | "failed" | "activating" | "deactivating"
    ) || !matches!(condition_result, "yes" | "no")
        || conditions.trim().is_empty()
    {
        return Err("systemd-condition-show-invalid-value".to_string());
    }
    Ok(ConditionSnapshot {
        load_state: load_state.to_string(),
        active_state: active_state.to_string(),
        condition_result: condition_result.to_string(),
        conditions: conditions.to_string(),
        status: None,
        failed_conditions: Vec::new(),
    })
}

fn failed_condition_lines(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let start = line.find("Condition")?;
            let detail = line[start..].trim();
            let (name, value) = detail.split_once('=')?;
            let name = name.trim();
            let value = value.to_ascii_lowercase();
            (name.starts_with("Condition")
                && name != "ConditionResult"
                && name != "Conditions"
                && ["not met", "not satisfied", "failed", "result=no", "=no"]
                    .iter()
                    .any(|marker| value.contains(marker)))
            .then(|| detail.to_string())
        })
        .collect()
}
pub(crate) fn snapshot_service_state(
    name: &str,
    user: bool,
    target_user: Option<&str>,
) -> Result<ServiceStateSnapshot, String> {
    if !is_removable_unit_basename(name) {
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

pub(crate) fn systemctl(
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
        "condition-show" => args.extend([
            "show".to_string(),
            "--property=ActiveState,ConditionResult,Conditions,LoadState".to_string(),
            service.to_string(),
        ]),
        "condition-status" => args.extend([
            "status".to_string(),
            "--no-pager".to_string(),
            "--lines=0".to_string(),
            "--full".to_string(),
            service.to_string(),
        ]),
        other => {
            return CmdResult {
                ok: false,
                code: -1,
                stdout: String::new(),
                stderr: format!("systemd-action-unsupported-{other}"),
            }
        }
    }
    let result = super::read_only_command_with_timeout(
        &super::systemctl_program(),
        &args,
        std::time::Duration::from_secs(timeout_secs),
    );
    CmdResult {
        ok: result.ok,
        code: result.code.unwrap_or(if result.ok { 0 } else { -1 }),
        stdout: result.stdout,
        stderr: result.stderr,
    }
}

pub(crate) fn unit_present_result(mut result: CmdResult, service: &str) -> CmdResult {
    if result.ok && result.stdout.trim() == "not-found" {
        result.ok = false;
        result.code = 1;
        result.stderr = format!("systemd-unit-missing-{service}");
    }
    result
}

pub(crate) fn unit_file_path(service: &str) -> Option<PathBuf> {
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

pub(crate) fn state(
    kind: &str,
    service: &str,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
) -> Option<String> {
    if service.is_empty() {
        return None;
    }
    let result = super::systemd_state_query(kind, service, user, target_user, timeout_secs);
    if result.code.is_none() {
        None
    } else {
        let value = result.stdout.trim();
        (!value.is_empty()).then(|| value.to_string())
    }
}

pub(crate) fn show_properties(
    service: &str,
    expected: &std::collections::BTreeMap<String, serde_json::Value>,
) -> (CmdResult, std::collections::BTreeMap<String, String>) {
    let mut argv = vec!["show".to_string(), service.to_string()];
    for key in expected.keys() {
        argv.push("-p".to_string());
        argv.push(key.clone());
    }
    argv.push("--no-pager".to_string());
    let result = super::read_only_command_with_timeout(
        &super::systemctl_program(),
        &argv,
        std::time::Duration::from_secs(30),
    );
    let command = CmdResult {
        ok: result.ok,
        code: result.code.unwrap_or(if result.ok { 0 } else { -1 }),
        stdout: result.stdout,
        stderr: result.stderr,
    };
    let mut observed = std::collections::BTreeMap::new();
    for line in command.stdout.lines() {
        if let Some((key, value)) = line.split_once('=') {
            observed.insert(key.to_string(), value.to_string());
        }
    }
    (command, observed)
}
