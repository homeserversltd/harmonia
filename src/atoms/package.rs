use super::command;
use super::comparison::{self, DiffDecision};
use crate::{write_json, CmdResult, OperationOutcome, PackageBackend};
use serde::Serialize;
use std::env;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

const NAME: &str = "package";

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

pub(crate) fn pacman_program() -> String {
    env::var(HARMONIA_PACMAN_PATH_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "/usr/bin/pacman".to_string())
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

pub(crate) fn capture_overwrite_preimage(
    receipt_dir: &Path,
    paths: &[String],
) -> Result<(), String> {
    let entries = paths.iter().map(|path| {
        let target = Path::new(path);
        let metadata = fs::symlink_metadata(target).ok();
        let (kind, bytes) = match metadata.as_ref() {
            Some(m) if m.is_file() => ("file", fs::read(target).ok()),
            Some(m) if m.is_dir() => ("directory", None),
            Some(_) => ("other", None),
            None => ("missing", None),
        };
        serde_json::json!({"path": path, "exists": metadata.is_some(), "type": kind, "bytes_hex": bytes.as_ref().map(|b| b.iter().map(|v| format!("{:02x}", v)).collect::<String>())})
    }).collect::<Vec<_>>();
    crate::write_json(
        &receipt_dir.join("pacman-overwrite-preimage.json"),
        &serde_json::json!({"schema":"harmonia.pacman_overwrite_preimage.v1", "paths": entries}),
    )
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

pub(crate) fn package_tool_for_backend(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    packages: &[String],
    apply: bool,
    backend: PackageBackend,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
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
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
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
    let run = comparison::execute_with_failure_receipt(
        "package",
        || {
            let current = command::capture_with_timeout(&program, &observe_refs, timeout_secs);
            Ok(PackageObservation {
                observed_state: "apt-current-state-observed".to_string(),
                desired_state: format!("apt-{action}-declared"),
                current: Some(current),
            })
        },
        |current| {
            if current
                .current
                .as_ref()
                .is_some_and(|result| !result.ok || apt_stdout_indicates_change(&result.stdout))
            {
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
        |before, movement, after| {
            let mut _receipt = package_receipt_fields(
                before,
                DiffDecision::Different,
                Some(movement),
                movement.changed,
            );
            if let Some(fields) = _receipt.as_object_mut() {
                fields.insert(
                    "observed_before".into(),
                    serde_json::to_value(before).map_err(|e| e.to_string())?,
                );
                fields.insert(
                    "act".into(),
                    serde_json::json!({"ok": movement.ok, "changed": movement.changed, "skipped": movement.skipped, "message": movement.message, "command": movement.command}),
                );
                fields.insert(
                    "observed_after".into(),
                    serde_json::to_value(after).map_err(|e| e.to_string())?,
                );
            }
            write_guard_receipts(receipt_dir, name, before, movement, after)
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

fn package_differs(action: &str, packages: &[String], observation: &PackageObservation) -> bool {
    let Some(result) = observation.current.as_ref() else {
        return true;
    };
    match action {
        "install" => packages.iter().any(|package| {
            !result
                .stdout
                .lines()
                .any(|line| line.split_whitespace().next() == Some(package))
        }),
        "check" | "upgrade" | "update" => !pacman_update_query_is_empty(result),
        _ => true,
    }
}

fn pacman_update_query_is_empty(result: &crate::CmdResult) -> bool {
    result.stdout.trim().is_empty()
        && (result.code == 0 || (result.code == 1 && result.stderr.trim().is_empty()))
}

pub(crate) fn write_install_package_guard_receipt(
    receipt_dir: &Path,
    name: &str,
    before: &PackageObservation,
    movement: &OperationOutcome,
    after: &PackageObservation,
) -> Result<(), String> {
    write_guard_receipts(receipt_dir, name, before, movement, after)
}

fn write_guard_receipts(
    receipt_dir: &Path,
    name: &str,
    before: &PackageObservation,
    movement: &OperationOutcome,
    after: &PackageObservation,
) -> Result<(), String> {
    let mut comparison = package_receipt_fields(
        before,
        DiffDecision::Different,
        Some(movement),
        movement.changed,
    );
    let fields = comparison
        .as_object_mut()
        .ok_or_else(|| "package-receipt-not-object".to_string())?;
    fields.insert(
        "observed_before".into(),
        serde_json::to_value(before).map_err(|e| e.to_string())?,
    );
    fields.insert("act".into(), serde_json::json!({"ok": movement.ok, "changed": movement.changed, "skipped": movement.skipped, "message": movement.message, "command": movement.command}));
    fields.insert(
        "observed_after".into(),
        serde_json::to_value(after).map_err(|e| e.to_string())?,
    );
    fields.insert("converged".into(), serde_json::json!(false));
    write_json(
        &receipt_dir.join(format!("{name}.comparison.json")),
        &comparison,
    )?;
    let mut standard = serde_json::json!({"schema":"harmonia.package_tool.v1","name":name,"tool":NAME,"ok":false,"changed":movement.changed,"skipped":movement.skipped,"message":movement.message,"command":movement.command});
    if let Some(obj) = standard.as_object_mut() {
        for key in ["observed_before", "act", "observed_after", "converged"] {
            obj.insert(key.into(), comparison[key].clone());
        }
    }
    write_json(&receipt_dir.join(format!("{name}.json")), &standard)
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
    let observed_state = if matches!(action, "check" | "upgrade" | "update")
        && pacman_update_query_is_empty(&observe_result)
    {
        String::new()
    } else if observe_result.ok {
        observe_result.stdout.clone()
    } else {
        format!("probe-failed:{}", observe_result.code)
    };
    let desired_state = match action {
        "install" => format!("packages-present:{}", packages.join(",")),
        "check" | "upgrade" | "update" => "no-pending-updates".into(),
        other => format!("{other}-declared"),
    };
    let observation = PackageObservation {
        observed_state,
        desired_state: desired_state.clone(),
        current: Some(observe_result),
    };
    let run = comparison::execute_with_failure_receipt(
        if action == "install" {
            "install-package"
        } else {
            "package"
        },
        || {
            let result = match action {
                "install" => command::capture(&pacman, &["-Q"]),
                _ => command::capture(&pacman, &["-Qu"]),
            };
            let observed_state = if matches!(action, "check" | "upgrade" | "update")
                && pacman_update_query_is_empty(&result)
            {
                String::new()
            } else if result.ok {
                result.stdout.clone()
            } else {
                format!("probe-failed:{}", result.code)
            };
            Ok(PackageObservation {
                observed_state,
                desired_state: desired_state.clone(),
                current: Some(result),
            })
        },
        |current| {
            if package_differs(action, packages, current) {
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
                "install" if apply => {
                    crate::atoms::r#do::install_package::pacman_mutate_packages_with_options(
                        receipt_dir,
                        false,
                        packages,
                        conflict_policy,
                        conflict_paths,
                        timeout_secs,
                    )?
                }
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
        |before, movement, after| {
            let mut _receipt = package_receipt_fields(
                before,
                DiffDecision::Different,
                Some(movement),
                movement.changed,
            );
            if let Some(fields) = _receipt.as_object_mut() {
                fields.insert(
                    "observed_before".into(),
                    serde_json::to_value(before).map_err(|e| e.to_string())?,
                );
                fields.insert(
                    "act".into(),
                    serde_json::json!({"ok": movement.ok, "changed": movement.changed, "skipped": movement.skipped, "message": movement.message, "command": movement.command}),
                );
                fields.insert(
                    "observed_after".into(),
                    serde_json::to_value(after).map_err(|e| e.to_string())?,
                );
            }
            write_guard_receipts(receipt_dir, name, before, movement, after)
        },
    )?;
    let final_observation = run.observation().clone();
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
    let mut comparison = package_receipt_fields(
        &final_observation,
        decision,
        movement.as_ref(),
        outcome.changed,
    );
    if let Some(fields) = comparison.as_object_mut() {
        fields.insert(
            "observed_before".into(),
            serde_json::to_value(&observation).map_err(|e| e.to_string())?,
        );
        fields.insert("act".into(), serde_json::json!({"ok": outcome.ok, "changed": outcome.changed, "skipped": outcome.skipped, "message": outcome.message, "command": outcome.command}));
        fields.insert(
            "observed_after".into(),
            serde_json::to_value(&final_observation).map_err(|e| e.to_string())?,
        );
        fields.insert("converged".into(), serde_json::json!(true));
    }
    write_json(
        &receipt_dir.join(format!("{name}.comparison.json")),
        &comparison,
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
    let run = comparison::execute_with_failure_receipt(
        "package",
        || {
            let current = if pacman_present && pacman_key_present {
                Some(command::capture(&pacman, &["-Q", package_name]))
            } else {
                None
            };
            Ok(PackageObservation {
                observed_state: observation.observed_state.clone(),
                desired_state: observation.desired_state.clone(),
                current,
            })
        },
        |current| {
            if !pacman_present
                || !pacman_key_present
                || current.current.as_ref().is_some_and(|result| !result.ok)
            {
                DiffDecision::Different
            } else {
                DiffDecision::Empty
            }
        },
        |_authorization, _| {
            keyring_repair_action(receipt_dir, name, package_name, apply, timeout_secs)
        },
        |before, movement, after| {
            let mut _receipt = package_receipt_fields(
                before,
                DiffDecision::Different,
                Some(movement),
                movement.changed,
            );
            if let Some(fields) = _receipt.as_object_mut() {
                fields.insert(
                    "observed_before".into(),
                    serde_json::to_value(before).map_err(|e| e.to_string())?,
                );
                fields.insert("act".into(), serde_json::json!({"ok": movement.ok, "changed": movement.changed, "skipped": movement.skipped, "message": movement.message, "command": movement.command}));
                fields.insert(
                    "observed_after".into(),
                    serde_json::to_value(after).map_err(|e| e.to_string())?,
                );
            }
            write_guard_receipts(receipt_dir, name, before, movement, after)
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
            crate::atoms::r#do::install_package::pacman_mutate_packages_with_options(
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
            "observed_before",
            "act",
            "observed_after",
            "converged",
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
            "observed_before",
            "act",
            "observed_after",
            "converged",
        ] {
            if let Some(value) = comparison.get(field) {
                receipt[field] = value.clone();
            }
        }
    }
    write_json(&receipt_dir.join(format!("{}.json", name)), &receipt)
}

pub(crate) fn slice4_bench(
    root: &Path,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<serde_json::Value, String> {
    let fake = root.join("fake-pacman");
    let log = root.join("pacman.log");
    let receipts = root.join("receipts");
    std::fs::create_dir_all(&receipts).map_err(|e| e.to_string())?;
    std::fs::write(&fake, format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$1\" in -Q) exit 0;; -Qu) test -f {}.state || echo pending-update; exit 0;; -Syu) echo Upgrading slice4; touch {}.state; exit 0;; esac\nexit 0\n", log.display(), log.display(), log.display())).map_err(|e| e.to_string())?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    let old = std::env::var_os("HARMONIA_PACMAN_PATH");
    std::env::set_var("HARMONIA_PACMAN_PATH", &fake);
    let result = package_tool_with_policy_for_backend(
        &receipts,
        "bench",
        "upgrade",
        &[],
        true,
        None,
        &[],
        2,
        crate::PackageBackend::Pacman,
        invocation,
    );
    match old {
        Some(v) => std::env::set_var("HARMONIA_PACMAN_PATH", v),
        None => std::env::remove_var("HARMONIA_PACMAN_PATH"),
    };
    let out = result?;
    let text = std::fs::read_to_string(&log).map_err(|e| e.to_string())?;
    let argv = text.lines().map(str::to_string).collect::<Vec<_>>();
    let exact = argv.iter().any(|line| line == "-Syu --noconfirm");
    let typed_receipt = receipts.join("bench.json").is_file();
    Ok(serde_json::json!({
        "production_ok": out.ok,
        "typed_receipt": typed_receipt,
        "upgrade_argv_exact": exact,
        "fake_log_only": !text.is_empty(),
        "pacman_argv": argv,
        "skipped": out.skipped,
        "skip_refusal_truthful": out.ok && !out.skipped,
        "ok": out.ok && exact && !out.skipped && typed_receipt,
    }))

}
