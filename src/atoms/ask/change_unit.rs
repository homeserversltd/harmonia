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
    }
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
        "/usr/bin/systemctl",
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
        "/usr/bin/systemctl",
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
