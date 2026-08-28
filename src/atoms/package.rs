use crate::CmdResult;
use std::env;
use std::path::Path;

pub(crate) const PACKAGE_PIN_SCOPE_LIMITATION: &str =
    "Harmonia's pin excludes names only from Harmonia-owned package transactions; it cannot stop the operator's own hand or a bare pacman/apt command run outside Harmonia (for example, `pacman -Syu`).";

const HARMONIA_PACMAN_PATH_ENV: &str = "HARMONIA_PACMAN_PATH";
const HARMONIA_PACMAN_CONF_PATH_ENV: &str = "HARMONIA_PACMAN_CONF_PATH";
const HARMONIA_PACMAN_KEY_PATH_ENV: &str = "HARMONIA_PACMAN_KEY_PATH";

pub(crate) fn pacman_program() -> String {
    env::var(HARMONIA_PACMAN_PATH_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "/usr/bin/pacman".to_string())
}

pub(crate) fn pacman_conf_program() -> String {
    env::var(HARMONIA_PACMAN_CONF_PATH_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "/usr/bin/pacman-conf".to_string())
}

pub(crate) fn pacman_key_program() -> String {
    env::var(HARMONIA_PACMAN_KEY_PATH_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "/usr/bin/pacman-key".to_string())
}

pub(crate) fn pacman_available(program: &str) -> bool {
    Path::new(program).exists()
}

pub(crate) fn pacman_conflict_signal(result: &CmdResult) -> Option<String> {
    if result.ok {
        return None;
    }
    let combined = format!("{}\n{}", result.stdout, result.stderr);
    if combined.contains("conflicting files") || combined.contains("exists in filesystem") {
        Some("pacman-package-file-conflict".to_string())
    } else {
        None
    }
}

pub(crate) fn pacman_needs_overwrite_retry(result: &CmdResult) -> bool {
    pacman_conflict_signal(result).is_some()
}

pub(crate) fn pacman_base_args(sync: bool) -> Vec<&'static str> {
    if sync {
        vec!["-Syu", "--noconfirm"]
    } else {
        vec!["-S", "--noconfirm", "--needed"]
    }
}

pub(crate) fn overwrite_allowed_args<'a>(
    base: &[&'a str],
    paths: &'a [String],
) -> Option<Vec<&'a str>> {
    if paths.is_empty() || paths.iter().any(|path| path == "*") {
        return None;
    }
    let mut args = base.to_vec();
    for path in paths {
        args.push("--overwrite");
        args.push(path.as_str());
    }
    Some(args)
}

pub(crate) fn pacman_stdout_indicates_change(stdout: &str) -> bool {
    let lower = stdout.to_ascii_lowercase();
    lower.contains("upgrading")
        || lower.contains("installing")
        || lower.contains("reinstalling")
        || lower.contains("removing")
}



pub(crate) use crate::atoms::ask::install_package::PackageObservation;
pub(crate) use crate::atoms::r#do::install_package::{
    keyring_repair_tool, package_tool_for_backend,
    package_tool_with_policy_for_backend_and_pins,
};
