use super::comparison::{self, DiffDecision};
use super::{command, ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::{write_json, CmdResult, OperationOutcome, PackageBackend};
use serde::Serialize;
#[cfg(test)]
use std::cell::RefCell;
use std::env;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

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
const PACMAN_DATABASE_LOCK_RELATIVE_PATH: &str = "var/lib/pacman/db.lck";

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PackageObservation {
    pub(crate) observed_state: String,
    pub(crate) desired_state: String,
    pub(crate) current: Option<CmdResult>,
}

pub(crate) fn package_receipt_fields(
    observation: &PackageObservation,
    decision: DiffDecision,
    movement: Option<&OperationOutcome>,
    changed: bool,
) -> serde_json::Value {
    serde_json::json!({
        "observed_state": observation.observed_state,
        "desired_state": observation.desired_state,
        "diff_decision": match decision { DiffDecision::Empty => "empty", DiffDecision::Different => "different" },
        "movement": movement.map(|movement| serde_json::json!({
            "ok": movement.ok,
            "changed": movement.changed,
            "skipped": movement.skipped,
            "message": movement.message,
            "command": movement.command,
        })),
        "changed": changed,
    })
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PacmanLockDecision {
    lock_present: bool,
    live_holder_found: bool,
    reclaim: bool,
}

fn pacman_lock_decision(lock_present: bool, live_holder_found: bool) -> PacmanLockDecision {
    PacmanLockDecision {
        lock_present,
        live_holder_found,
        reclaim: lock_present && !live_holder_found,
    }
}

fn resolved_pacman_program(program: &str) -> PathBuf {
    fs::canonicalize(program).unwrap_or_else(|_| PathBuf::from(program))
}

fn pacman_database_lock_path(program: &str) -> PathBuf {
    let resolved = resolved_pacman_program(program);
    let root = resolved
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("/"));
    root.join(PACMAN_DATABASE_LOCK_RELATIVE_PATH)
}

fn live_pacman_process_exists(program: &Path) -> bool {
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .chars()
                .all(|character| character.is_ascii_digit())
        })
        .any(|entry| {
            let process = entry.path();
            let executable = fs::read_link(process.join("exe"))
                .ok()
                .and_then(|path| fs::canonicalize(&path).ok().or(Some(path)));
            if executable.as_deref() == Some(program) {
                return true;
            }
            fs::read(process.join("cmdline"))
                .ok()
                .and_then(|cmdline| {
                    cmdline.split(|byte| *byte == 0).next().map(|argument| {
                        PathBuf::from(std::ffi::OsString::from_vec(argument.to_vec()))
                    })
                })
                .and_then(|path| fs::canonicalize(&path).ok().or(Some(path)))
                .as_deref()
                == Some(program)
        })
}

pub(crate) fn reclaim_pacman_database_lock(
    receipt_dir: &Path,
    program: &str,
    apply: bool,
) -> Result<(), String> {
    let resolved_program = resolved_pacman_program(program);
    let lock_path = pacman_database_lock_path(program);
    let lock_present = lock_path.exists();
    let live_holder_found = lock_present && live_pacman_process_exists(&resolved_program);
    let decision = pacman_lock_decision(lock_present, live_holder_found);
    let removal_error = if decision.reclaim && apply {
        fs::remove_file(&lock_path).err()
    } else {
        None
    };
    let reclaimed = decision.reclaim && apply && removal_error.is_none();
    write_json(
        &receipt_dir.join("pacman-database-lock-reclaim.json"),
        &serde_json::json!({
            "schema": "harmonia.pacman_lock_reclaim.v1",
            "name": "pacman-database-lock-reclaim",
            "tool": NAME,
            "pacman_program": resolved_program,
            "lock_path": lock_path,
            "lock_present": decision.lock_present,
            "live_holder_found": decision.live_holder_found,
            "reclaimed": reclaimed,
            "planned_reclamation": decision.reclaim && !apply,
            "apply": apply,
            "first_missing_signal": removal_error.as_ref().map_or("none", |_| "pacman-lock-reclaim-failed"),
        }),
    )?;
    if let Some(error) = removal_error {
        return Err(format!("pacman-lock-reclaim-failed:{error}"));
    }
    Ok(())
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
pub(crate) fn pacman_mutate_packages(
    receipt_dir: &Path,
    sync: bool,
    packages: &[String],
) -> Result<CmdResult, String> {
    pacman_mutate_packages_with_options(
        receipt_dir,
        sync,
        packages,
        None,
        &[],
        DEFAULT_PACKAGE_TIMEOUT_SECS,
    )
}

#[allow(dead_code)]
pub(crate) fn pacman_mutate_packages_with_conflict_policy(
    receipt_dir: &Path,
    sync: bool,
    packages: &[String],
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
) -> Result<CmdResult, String> {
    pacman_mutate_packages_with_options(
        receipt_dir,
        sync,
        packages,
        conflict_policy,
        conflict_paths,
        DEFAULT_PACKAGE_TIMEOUT_SECS,
    )
}

pub(crate) fn pacman_mutate_packages_with_options(
    receipt_dir: &Path,
    sync: bool,
    packages: &[String],
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
    timeout_secs: u64,
) -> Result<CmdResult, String> {
    let program = pacman_program();
    reclaim_pacman_database_lock(receipt_dir, &program, true)?;
    Ok(pacman_mutate_packages_without_lock_reclaim(
        sync,
        packages,
        conflict_policy,
        conflict_paths,
        timeout_secs,
    ))
}

fn pacman_mutate_packages_without_lock_reclaim(
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
    invocation: Option<crate::atoms::r#do::InvocationKey>) -> Result<OperationOutcome, String> {
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
        invocation,
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
    invocation: Option<crate::atoms::r#do::InvocationKey>) -> Result<OperationOutcome, String> {
    match backend {
        PackageBackend::Pacman if action == "install" => crate::install_package::run(
            receipt_dir,
            name,
            packages,
            apply,
            conflict_policy,
            conflict_paths,
            timeout_secs,
            &pacman_program(),
            invocation,
        ),
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
        PackageBackend::Apt => {
            apt_package_tool(receipt_dir, name, action, packages, apply, timeout_secs)
        }
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
    let mut observe_args = match action {
        "check" => vec!["-s".to_string(), "upgrade".to_string()],
        "install" => vec!["-s".to_string(), "install".to_string()],
        "upgrade" | "update" => vec!["-s".to_string(), "full-upgrade".to_string()],
        other => return Err(format!("apt-package-action-unsupported-{other}")),
    };
    if action == "install" {
        observe_args.extend(packages.iter().cloned());
    }
    let observe_refs: Vec<&str> = observe_args.iter().map(String::as_str).collect();
    let observation = PackageObservation {
        observed_state: "apt-current-state-observed".to_string(),
        desired_state: format!("apt-{action}-declared"),
        current: Some(command::capture_with_timeout(
            &program,
            &observe_refs,
            timeout_secs,
        )),
    };
    let desired_differs = observation
        .current
        .as_ref()
        .is_some_and(|result| !result.ok || apt_stdout_indicates_change(&result.stdout));
    let run = comparison::execute(
        || Ok::<_, String>(observation.clone()),
        |_| {
            if desired_differs {
                DiffDecision::Different
            } else {
                DiffDecision::Empty
            }
        },
        |_authorization, _| {
            let mut args: Vec<String> = match (action, apply) {
                ("check", _) => vec!["-s".into(), "upgrade".into()],
                ("install", true) => vec!["install".into(), "--yes".into()],
                ("install", false) => vec!["-s".into(), "install".into()],
                ("upgrade" | "update", true) => vec!["full-upgrade".into(), "--yes".into()],
                ("upgrade" | "update", false) => vec!["-s".into(), "full-upgrade".into()],
                (other, _) => return Err(format!("apt-package-action-unsupported-{other}")),
            };
            args.extend(packages.iter().cloned());
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let result = command::capture_with_timeout(&program, &refs, timeout_secs);
            Ok(OperationOutcome {
                ok: result.ok,
                changed: apply && result.ok && apt_stdout_indicates_change(&result.stdout),
                skipped: false,
                message: format!("apt package {action}"),
                command: Some(result),
            })
        },
    )?;
    let (decision, movement) = match run {
        comparison::ComparisonRun::Current { decision, .. } => (decision, None),
        comparison::ComparisonRun::Moved {
            decision, movement, ..
        } => (decision, Some(movement)),
    };
    let outcome = movement.clone().unwrap_or(OperationOutcome {
        ok: true,
        changed: false,
        skipped: true,
        message: format!("apt package {action} already current"),
        command: observation.current.clone(),
    });
    write_json(
        &receipt_dir.join(format!("{name}.comparison.json")),
        &package_receipt_fields(&observation, decision, movement.as_ref(), outcome.changed),
    )?;
    write_package_receipt_with_backend(receipt_dir, name, action, &outcome, PackageBackend::Apt)?;
    Ok(outcome)
}

fn apt_stdout_indicates_change(stdout: &str) -> bool {
    let lower = stdout.to_ascii_lowercase();
    lower.contains("the following packages will be") || lower.contains("setting up ")
}

pub(crate) fn non_arch_install(
    receipt_dir: &Path,
    name: &str,
    packages: &[String],
) -> Result<OperationOutcome, String> {
    let outcome = OperationOutcome {
        ok: true,
        changed: false,
        skipped: true,
        message: "non-Arch bootstrap not applicable".into(),
        command: None,
    };
    let observation = PackageObservation {
        observed_state: "package-manager-unavailable".into(),
        desired_state: format!("install-declared:{}", packages.join(",")),
        current: None,
    };
    write_json(
        &receipt_dir.join(format!("{name}.comparison.json")),
        &package_receipt_fields(&observation, DiffDecision::Empty, None, false),
    )?;
    write_package_receipt(receipt_dir, name, "install", &outcome)?;
    Ok(outcome)
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
        let observation = PackageObservation {
            observed_state: "package-manager-unavailable".into(),
            desired_state: format!("{action}-declared"),
            current: None,
        };
        write_json(
            &receipt_dir.join(format!("{name}.comparison.json")),
            &package_receipt_fields(&observation, DiffDecision::Empty, None, false),
        )?;
        write_package_receipt(receipt_dir, name, action, &outcome)?;
        return Ok(outcome);
    }
    let observe_result = match action {
        "install" => command::capture(&pacman, &["-Q"]),
        _ => command::capture(&pacman, &["-Qu"]),
    };
    let observed_state = if observe_result.ok {
        observe_result.stdout.clone()
    } else {
        format!("probe-failed:{}", observe_result.code)
    };
    let desired_state = match action {
        "install" => format!("packages-present:{}", packages.join(",")),
        "check" | "upgrade" | "update" => "no-pending-updates".into(),
        other => format!("{other}-declared"),
    };
    let differs = match action {
        "install" => packages.iter().any(|package| {
            !observe_result
                .stdout
                .lines()
                .any(|line| line.split_whitespace().next() == Some(package))
        }),
        "check" | "upgrade" | "update" => {
            !observe_result.stdout.trim().is_empty() || !observe_result.ok
        }
        _ => true,
    };
    let observation = PackageObservation {
        observed_state,
        desired_state,
        current: Some(observe_result),
    };
    let run = comparison::execute(
        || Ok::<_, String>(observation.clone()),
        |_| {
            if differs {
                DiffDecision::Different
            } else {
                DiffDecision::Empty
            }
        },
        |_authorization, _| {
            let result = match action {
                "upgrade" | "update" if apply => {
                    reclaim_pacman_database_lock(receipt_dir, &pacman, true)?;
                    command::capture_with_timeout(&pacman, &["-Syu", "--noconfirm"], timeout_secs)
                }
                "upgrade" | "update" | "check" => {
                    reclaim_pacman_database_lock(receipt_dir, &pacman, false)?;
                    command::capture(&pacman, &["-Qu"])
                }
                "install" if apply => pacman_mutate_packages_with_options(
                    receipt_dir,
                    false,
                    packages,
                    conflict_policy,
                    conflict_paths,
                    timeout_secs,
                )?,
                "install" => {
                    reclaim_pacman_database_lock(receipt_dir, &pacman, false)?;
                    command::capture(&pacman, &["-Q"])
                }
                other => return Err(format!("unsupported package action {other}")),
            };
            let ok = match action {
                "check" | "upgrade" | "update" if !apply => result.ok || result.code == 1,
                _ => result.ok,
            };
            Ok(OperationOutcome {
                ok,
                changed: matches!(action, "upgrade" | "update" | "install")
                    && apply
                    && result.ok
                    && pacman_stdout_indicates_change(&result.stdout),
                skipped: false,
                message: format!("package {action}"),
                command: Some(result),
            })
        },
    )?;
    let (decision, movement) = match run {
        comparison::ComparisonRun::Current { decision, .. } => (decision, None),
        comparison::ComparisonRun::Moved {
            decision, movement, ..
        } => (decision, Some(movement)),
    };
    let outcome = movement.clone().unwrap_or(OperationOutcome {
        ok: true,
        changed: false,
        skipped: true,
        message: format!("package {action} already current"),
        command: observation.current.clone(),
    });
    write_json(
        &receipt_dir.join(format!("{name}.comparison.json")),
        &package_receipt_fields(&observation, decision, movement.as_ref(), outcome.changed),
    )?;
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
    let current = if pacman_present && pacman_key_present {
        Some(command::capture(&pacman, &["-Q", package_name]))
    } else {
        None
    };
    let observation = PackageObservation {
        observed_state: if pacman_present && pacman_key_present {
            "keyring-tools-and-package-observed".into()
        } else {
            "keyring-tools-unavailable".into()
        },
        desired_state: format!("keyring-repaired:{package_name}"),
        current,
    };
    let differs = !pacman_present
        || !pacman_key_present
        || observation
            .current
            .as_ref()
            .is_some_and(|result| !result.ok);
    let run = comparison::execute(
        || Ok::<_, String>(observation.clone()),
        |_| {
            if differs {
                DiffDecision::Different
            } else {
                DiffDecision::Empty
            }
        },
        |_authorization, _| {
            keyring_repair_action(receipt_dir, name, package_name, apply, timeout_secs)
        },
    )?;
    let (decision, movement) = match run {
        comparison::ComparisonRun::Current { decision, .. } => (decision, None),
        comparison::ComparisonRun::Moved {
            decision, movement, ..
        } => (decision, Some(movement)),
    };
    let outcome = movement.clone().unwrap_or(OperationOutcome {
        ok: true,
        changed: false,
        skipped: true,
        message: "package keyring-repair already current".into(),
        command: observation.current.clone(),
    });
    write_json(
        &receipt_dir.join(format!("{name}.comparison.json")),
        &package_receipt_fields(&observation, decision, movement.as_ref(), outcome.changed),
    )?;
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
    Ok(outcome)
}

fn keyring_repair_action(
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
    if !apply {
        reclaim_pacman_database_lock(receipt_dir, &pacman, false)?;
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
                receipt_dir,
                false,
                &[package_name.to_string()],
                None,
                &[],
                timeout_secs,
            )?,
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
    let comparison = fs::read(receipt_dir.join(format!("{name}.comparison.json")))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    let mut receipt = serde_json::json!({
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
    });
    if let Some(comparison) = comparison {
        for field in [
            "observed_state",
            "desired_state",
            "diff_decision",
            "movement",
        ] {
            if let Some(value) = comparison.get(field) {
                receipt[field] = value.clone();
            }
        }
    }
    write_json(&receipt_dir.join(format!("{}.json", name)), &receipt)
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
    let comparison = fs::read(receipt_dir.join(format!("{name}.comparison.json")))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    let mut receipt = serde_json::json!({
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
    });
    if let Some(comparison) = comparison {
        for field in [
            "observed_state",
            "desired_state",
            "diff_decision",
            "movement",
        ] {
            if let Some(value) = comparison.get(field) {
                receipt[field] = value.clone();
            }
        }
    }
    write_json(&receipt_dir.join(format!("{}.json", name)), &receipt)
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
    fn pacman_lock_decision_distinguishes_absent_live_and_orphaned_locks() {
        assert_eq!(
            pacman_lock_decision(false, false),
            PacmanLockDecision {
                lock_present: false,
                live_holder_found: false,
                reclaim: false,
            }
        );
        assert_eq!(
            pacman_lock_decision(true, true),
            PacmanLockDecision {
                lock_present: true,
                live_holder_found: true,
                reclaim: false,
            }
        );
        assert_eq!(
            pacman_lock_decision(true, false),
            PacmanLockDecision {
                lock_present: true,
                live_holder_found: false,
                reclaim: true,
            }
        );
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
