// Owned ask atom for install-package
use crate::atoms;
use crate::CmdResult;
use serde::Serialize;
use std::time::Duration;

pub(crate) fn pacman(program: &str, timeout_secs: u64) -> atoms::CommandObservation {
    atoms::ask::read_only_command_with_timeout(
        program,
        &["-Q".to_string()],
        Duration::from_secs(timeout_secs),
    )
}


pub(crate) fn packages(
    program: &str,
    package_names: &[String],
    timeout_secs: u64,
) -> atoms::CommandObservation {
    let mut args = vec!["-Q".to_string()];
    args.extend(package_names.iter().cloned());
    atoms::ask::read_only_command_with_timeout(
        program,
        &args,
        Duration::from_secs(timeout_secs),
    )
}


#[derive(Debug, Clone, Serialize)]
pub(crate) struct PackageObservation {
    pub(crate) observed_state: String,
    pub(crate) desired_state: String,
    pub(crate) current: Option<CmdResult>,
}

pub(crate) fn pacman_update_query_is_empty(result: &CmdResult) -> bool {
    result.stdout.trim().is_empty()
        && (result.code == 0 || (result.code == 1 && result.stderr.trim().is_empty()))
}

pub(crate) fn pacman_observed_state(result: &CmdResult) -> String {
    if pacman_update_query_is_empty(result) {
        if result.code == 1 { "pacman-query-no-pending-exit-1-empty".into() }
        else { "pacman-query-no-pending-exit-0-empty".into() }
    } else if result.ok { result.stdout.clone() } else { format!("probe-failed:{}", result.code) }
}

pub(crate) fn install_observation(
    result: CmdResult, packages: &[String],
) -> PackageObservation {
    let observed_state = if result.ok { result.stdout.clone() } else { format!("probe-failed:{}", result.code) };
    PackageObservation { observed_state, desired_state: format!("packages-present:{}", packages.join(",")), current: Some(result) }
}

pub(crate) fn package_differs(action: &str, packages: &[String], observation: &PackageObservation) -> bool {
    let Some(result) = observation.current.as_ref() else { return true; };
    match action {
        "install" => packages.iter().any(|package| !result.stdout.lines().any(|line| line.split_whitespace().next() == Some(package))),
        "check" | "upgrade" | "update" => !pacman_update_query_is_empty(result),
        _ => true,
    }
}
