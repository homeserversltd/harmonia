use super::{command, ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::{write_json, CmdResult, OperationOutcome, PackageBackend};
#[cfg(test)]
use std::cell::RefCell;
use std::env;
use std::path::Path;

pub const NAME: &str = "package";
pub const DESCRIPTION: &str = "System package manager primitive for pacman check, install, upgrade, and keyring repair permutations.";
pub const PERMUTATIONS: &[ToolPermutation] = &[
    ToolPermutation::new(
        "check",
        "check package database/update state without mutation",
        &[ToolArg::optional("packages", ToolArgKind::StringArray)],
    ),
    ToolPermutation::new(
        "install",
        "install declared packages using pacman --needed semantics",
        &[
            ToolArg::required("packages", ToolArgKind::StringArray),
            ToolArg::optional("conflict_policy", ToolArgKind::String),
            ToolArg::optional("conflict_paths", ToolArgKind::StringArray),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ),
    ToolPermutation::new(
        "upgrade",
        "run full pacman -Syu upgrade lane",
        &[ToolArg::optional("timeout_secs", ToolArgKind::Integer)],
    ),
    ToolPermutation::new(
        "keyring-repair",
        "repair Arch pacman keyring with pacman-key init/populate/refresh/updatedb and archlinux-keyring install",
        &[
            ToolArg::optional("package", ToolArgKind::String),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ),
];
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION, PERMUTATIONS);

const HARMONIA_PACMAN_PATH_ENV: &str = "HARMONIA_PACMAN_PATH";
const HARMONIA_PACMAN_KEY_PATH_ENV: &str = "HARMONIA_PACMAN_KEY_PATH";
const DEFAULT_PACKAGE_TIMEOUT_SECS: u64 = 1800;

#[cfg(test)]
thread_local! {
    static TEST_PACMAN_PATH: RefCell<Option<String>> = const { RefCell::new(None) };
}

#[allow(dead_code)]
pub(crate) fn set_test_pacman_path(path: Option<String>) {
    #[cfg(test)]
    TEST_PACMAN_PATH.with(|slot| {
        *slot.borrow_mut() = path;
    });
    #[cfg(not(test))]
    let _ = path;
}

pub(crate) fn pacman_program() -> String {
    #[cfg(test)]
    if let Some(path) = TEST_PACMAN_PATH.with(|slot| slot.borrow().clone()) {
        return path;
    }
    env::var(HARMONIA_PACMAN_PATH_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "/usr/bin/pacman".to_string())
}

pub(crate) fn pacman_key_program() -> String {
    env::var(HARMONIA_PACMAN_KEY_PATH_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
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

#[allow(dead_code)]
pub(crate) fn pacman_mutate_packages(sync: bool, packages: &[String]) -> CmdResult {
    pacman_mutate_packages_with_options(sync, packages, None, &[], DEFAULT_PACKAGE_TIMEOUT_SECS)
}

#[allow(dead_code)]
pub(crate) fn pacman_mutate_packages_with_conflict_policy(
    sync: bool,
    packages: &[String],
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
) -> CmdResult {
    pacman_mutate_packages_with_options(
        sync,
        packages,
        conflict_policy,
        conflict_paths,
        DEFAULT_PACKAGE_TIMEOUT_SECS,
    )
}

pub(crate) fn pacman_mutate_packages_with_options(
    sync: bool,
    packages: &[String],
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
    timeout_secs: u64,
) -> CmdResult {
    let program = pacman_program();
    let mut args = pacman_base_args(sync);
    args.extend(packages.iter().map(String::as_str));
    let result = command::capture_with_timeout(&program, &args, timeout_secs);
    if result.ok || !pacman_needs_overwrite_retry(&result) {
        return result;
    }
    let Some(policy) = conflict_policy else {
        return result;
    };
    if policy != "overwrite-declared-paths" {
        return CmdResult {
            ok: false,
            code: result.code,
            stdout: result.stdout,
            stderr: format!(
                "{}\npacman-package-file-conflict-policy-unsupported:{policy}",
                result.stderr
            )
            .trim()
            .to_string(),
        };
    }
    let Some(mut overwrite_args) = overwrite_allowed_args(&pacman_base_args(sync), conflict_paths)
    else {
        return CmdResult {
            ok: false,
            code: result.code,
            stdout: result.stdout,
            stderr: format!(
                "{}\npacman-package-file-conflict-overwrite-paths-missing-or-wildcard",
                result.stderr
            )
            .trim()
            .to_string(),
        };
    };
    overwrite_args.extend(packages.iter().map(String::as_str));
    let second = command::capture_with_timeout(&program, &overwrite_args, timeout_secs);
    CmdResult {
        ok: second.ok,
        code: second.code,
        stdout: format!(
            "first_command={} {}\nfirst_ok={}\nsecond_command={} {}\n{}",
            program,
            args.join(" "),
            result.ok,
            program,
            overwrite_args.join(" "),
            second.stdout
        )
        .trim()
        .to_string(),
        stderr: format!(
            "first_stderr={}\nsecond_stderr={}",
            result.stderr, second.stderr
        )
        .trim()
        .to_string(),
    }
}

pub(crate) fn pacman_stdout_indicates_change(stdout: &str) -> bool {
    let lower = stdout.to_ascii_lowercase();
    lower.contains("upgrading")
        || lower.contains("installing")
        || lower.contains("reinstalling")
        || lower.contains("removing")
}

pub(crate) fn package_tool_for_backend(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    packages: &[String],
    apply: bool,
    backend: PackageBackend,
) -> Result<OperationOutcome, String> {
    package_tool_with_policy_for_backend(
        receipt_dir,
        name,
        action,
        packages,
        apply,
        None,
        &[],
        DEFAULT_PACKAGE_TIMEOUT_SECS,
        backend,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn package_tool_with_policy_for_backend(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    packages: &[String],
    apply: bool,
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
    timeout_secs: u64,
    backend: PackageBackend,
) -> Result<OperationOutcome, String> {
    match backend {
        PackageBackend::Pacman => package_tool_with_policy(
            receipt_dir,
            name,
            action,
            packages,
            apply,
            conflict_policy,
            conflict_paths,
            timeout_secs,
        ),
        PackageBackend::Apt => apt_package_tool(receipt_dir, name, action, packages, apply, timeout_secs),
    }
}

fn apt_program() -> String {
    env::var("HARMONIA_APT_GET_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "/usr/bin/apt-get".to_string())
}

fn apt_package_tool(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    packages: &[String],
    apply: bool,
    timeout_secs: u64,
) -> Result<OperationOutcome, String> {
    let program = apt_program();
    let args: Vec<&str> = match (action, apply) {
        ("check", _) => vec!["-s", "upgrade"],
        ("install", true) => {
            let mut args = vec!["install", "--yes"];
            args.extend(packages.iter().map(String::as_str));
            args
        }
        ("install", false) => {
            let mut args = vec!["-s", "install"];
            args.extend(packages.iter().map(String::as_str));
            args
        }
        ("upgrade" | "update", true) => vec!["full-upgrade", "--yes"],
        ("upgrade" | "update", false) => vec!["-s", "full-upgrade"],
        (other, _) => return Err(format!("apt-package-action-unsupported-{other}")),
    };
    let result = command::capture_with_timeout(&program, &args, timeout_secs);
    let ok = result.ok;
    let changed = apply && ok && apt_stdout_indicates_change(&result.stdout);
    let outcome = OperationOutcome {
        ok,
        changed,
        skipped: false,
        message: format!("apt package {action}"),
        command: Some(result),
    };
    write_package_receipt_with_backend(receipt_dir, name, action, &outcome, PackageBackend::Apt)?;
    Ok(outcome)
}

fn apt_stdout_indicates_change(stdout: &str) -> bool {
    let lower = stdout.to_ascii_lowercase();
    lower.contains("the following packages will be") || lower.contains("setting up ")
}

pub(crate) fn package_tool(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    packages: &[String],
    apply: bool,
) -> Result<OperationOutcome, String> {
    package_tool_with_policy(
        receipt_dir,
        name,
        action,
        packages,
        apply,
        None,
        &[],
        DEFAULT_PACKAGE_TIMEOUT_SECS,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn package_tool_with_policy(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    packages: &[String],
    apply: bool,
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
    timeout_secs: u64,
) -> Result<OperationOutcome, String> {
    let pacman = pacman_program();
    if !pacman_available(&pacman) {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "non-Arch bootstrap not applicable".to_string(),
            command: None,
        };
        write_package_receipt(receipt_dir, name, action, &outcome)?;
        return Ok(outcome);
    }
    let result = match action {
        "upgrade" | "update" if apply => {
            command::capture_with_timeout(&pacman, &["-Syu", "--noconfirm"], timeout_secs)
        }
        "upgrade" | "update" | "check" => command::capture(&pacman, &["-Qu"]),
        "install" if apply => pacman_mutate_packages_with_options(
            false,
            packages,
            conflict_policy,
            conflict_paths,
            timeout_secs,
        ),
        "install" => command::capture(&pacman, &["-Q"]),
        other => {
            let outcome = OperationOutcome {
                ok: false,
                changed: false,
                skipped: false,
                message: format!("unsupported package action {other}"),
                command: None,
            };
            write_package_receipt(receipt_dir, name, action, &outcome)?;
            return Ok(outcome);
        }
    };
    let changed = matches!(action, "upgrade" | "update" | "install")
        && apply
        && result.ok
        && pacman_stdout_indicates_change(&result.stdout);
    let ok = match action {
        "check" | "upgrade" | "update" if !apply => result.ok || result.code == 1,
        _ => result.ok,
    };
    let outcome = OperationOutcome {
        ok,
        changed,
        skipped: false,
        message: format!("package {action}"),
        command: Some(result),
    };
    write_package_receipt(receipt_dir, name, action, &outcome)?;
    Ok(outcome)
}

pub(crate) fn keyring_repair_tool(
    receipt_dir: &Path,
    name: &str,
    package_name: &str,
    apply: bool,
    timeout_secs: u64,
) -> Result<OperationOutcome, String> {
    let pacman = pacman_program();
    let pacman_key = pacman_key_program();
    let pacman_present = pacman_available(&pacman);
    let pacman_key_present = pacman_available(&pacman_key);
    if !pacman_present || !pacman_key_present {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "non-Arch bootstrap not applicable".to_string(),
            command: None,
        };
        write_keyring_receipt(
            receipt_dir,
            name,
            package_name,
            apply,
            pacman_present,
            pacman_key_present,
            0,
            &outcome,
        )?;
        return Ok(outcome);
    }
    let mut commands = Vec::new();
    commands.push((
        "pacman-key-version",
        command::capture(&pacman_key, &["--version"]),
    ));
    commands.push((
        "archlinux-keyring-query",
        command::capture(&pacman, &["-Q", package_name]),
    ));
    if apply {
        commands.push((
            "pacman-key-init",
            command::capture_with_timeout(&pacman_key, &["--init"], timeout_secs),
        ));
        commands.push((
            "pacman-key-populate",
            command::capture_with_timeout(&pacman_key, &["--populate", "archlinux"], timeout_secs),
        ));
        commands.push((
            "archlinux-keyring-refresh",
            pacman_mutate_packages_with_options(
                false,
                &[package_name.to_string()],
                None,
                &[],
                timeout_secs,
            ),
        ));
        commands.push((
            "pacman-key-updatedb",
            command::capture_with_timeout(&pacman_key, &["--updatedb"], timeout_secs),
        ));
    }
    for (command_name, result) in &commands {
        crate::write_command_receipt(receipt_dir, command_name, result)?;
    }
    let ok = commands.iter().all(|(command_name, result)| {
        result.ok || (!apply && *command_name == "archlinux-keyring-query")
    });
    let changed = apply && ok;
    let first_failure = commands.iter().position(|(_, result)| !result.ok);
    let command = first_failure
        .map(|index| commands[index].1.clone())
        .or_else(|| commands.last().map(|(_, result)| result.clone()));
    let outcome = OperationOutcome {
        ok,
        changed,
        skipped: false,
        message: "package keyring-repair".to_string(),
        command,
    };
    write_keyring_receipt(
        receipt_dir,
        name,
        package_name,
        apply,
        pacman_present,
        pacman_key_present,
        commands.len(),
        &outcome,
    )?;
    Ok(outcome)
}

pub(crate) fn write_package_receipt(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    outcome: &OperationOutcome,
) -> Result<(), String> {
    write_package_receipt_with_backend(receipt_dir, name, action, outcome, PackageBackend::Pacman)
}

fn write_package_receipt_with_backend(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    outcome: &OperationOutcome,
    backend: PackageBackend,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{}.json", name)),
        &serde_json::json!({
            "schema": "harmonia.package_tool.v1",
            "name": name,
            "tool": NAME,
            "permutation": action,
            "declared_package_backend": backend.name(),
            "ok": outcome.ok,
            "changed": outcome.changed,
            "skipped": outcome.skipped,
            "message": outcome.message,
            "command": outcome.command,
        }),
    )
}

fn write_keyring_receipt(
    receipt_dir: &Path,
    name: &str,
    package_name: &str,
    apply: bool,
    pacman_present: bool,
    pacman_key_present: bool,
    operation_count: usize,
    outcome: &OperationOutcome,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{}.json", name)),
        &serde_json::json!({
            "schema": "harmonia.package_keyring_repair.v1",
            "name": name,
            "tool": NAME,
            "permutation": "keyring-repair",
            "ok": outcome.ok,
            "changed": outcome.changed,
            "skipped": outcome.skipped,
            "apply": apply,
            "package": package_name,
            "pacman_present": pacman_present,
            "pacman_key_present": pacman_key_present,
            "operation_count": operation_count,
            "first_missing_signal": if outcome.ok || outcome.skipped { "none" } else if !pacman_present || !pacman_key_present { "arch-keyring-tools-missing" } else { "package-keyring-repair-failed" },
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn receipt_dir(test_name: &str) -> std::path::PathBuf {
        let path = env::temp_dir().join(format!(
            "harmonia-package-{test_name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn sync_package_mutation_uses_full_upgrade_semantics() {
        let args = pacman_base_args(true);
        assert_eq!(args, vec!["-Syu", "--noconfirm"]);
    }

    #[test]
    fn install_package_mutation_uses_needed_semantics() {
        let args = pacman_base_args(false);
        assert_eq!(args, vec!["-S", "--noconfirm", "--needed"]);
    }

    #[test]
    fn overwrite_policy_rejects_wildcard_paths() {
        assert!(overwrite_allowed_args(&pacman_base_args(false), &["*".to_string()]).is_none());
    }

    #[test]
    fn keyring_repair_skips_non_arch_host_when_applying() {
        let receipt_dir = receipt_dir("keyring-skip");
        set_test_pacman_path(Some("/nonexistent/harmonia-pacman".to_string()));
        let outcome = keyring_repair_tool(
            &receipt_dir,
            "keyring",
            "archlinux-keyring",
            true,
            DEFAULT_PACKAGE_TIMEOUT_SECS,
        )
        .unwrap();
        set_test_pacman_path(None);

        assert!(outcome.ok);
        assert!(outcome.skipped);
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(receipt_dir.join("keyring.json")).unwrap()).unwrap();
        assert_eq!(receipt["first_missing_signal"], "none");
        fs::remove_dir_all(receipt_dir).unwrap();
    }

    #[test]
    fn package_install_skips_non_arch_host_when_applying() {
        let receipt_dir = receipt_dir("package-skip");
        set_test_pacman_path(Some("/nonexistent/harmonia-pacman".to_string()));
        let outcome = package_tool(
            &receipt_dir,
            "package",
            "install",
            &["git".to_string()],
            true,
        )
        .unwrap();
        set_test_pacman_path(None);

        assert!(outcome.ok);
        assert!(outcome.skipped);
        fs::remove_dir_all(receipt_dir).unwrap();
    }
}
