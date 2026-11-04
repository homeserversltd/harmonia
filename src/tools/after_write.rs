use crate::atoms::comparison::{ComparisonRun, DiffDecision};
use crate::atoms::r#do::InvocationKey;
use crate::{OperationOutcome, ValidatedStep};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::path::Path;
use std::time::{Duration, Instant};

const ACTION_TIMEOUT_SECS: u64 = 30;

#[derive(Debug)]
pub(crate) struct StepExecution {
    pub outcome: OperationOutcome,
    pub after_write: Vec<Value>,
}

#[derive(Debug, Default)]
pub(crate) struct AfterWriteRun {
    pub entries: Vec<Value>,
    pub failure: Option<String>,
}

#[derive(Debug)]
struct ActionResult {
    exit_code: Value,
    readback: Value,
    failure: Option<String>,
}

impl ActionResult {
    fn success(exit_code: Value, readback: Value) -> Self {
        Self {
            exit_code,
            readback,
            failure: None,
        }
    }

    fn failed(signal: impl Into<String>, exit_code: Value, readback: Value) -> Self {
        Self {
            exit_code,
            readback,
            failure: Some(signal.into()),
        }
    }
}

/// Tool permutations whose operation may write the live filesystem. Keep the
/// proposal-only cases here so an undeclared real writer can still be recorded;
/// package-manager upgrades remain outside this action path.
pub(crate) fn is_supported_writer(tool: &str, permutation: &str) -> bool {
    matches!(
        (tool, permutation),
        ("pull-repo", "acquire")
            | ("build-crate", "build")
            | ("place-file", "place" | "binary-promotion" | "source-sha-record")
            | ("backfill-file", "backfill")
            | (
                "files",
                "json-key-proposal"
                    | "managed-files"
                    | "metadata"
                    | "converge"
                    | "compile-fragments"
                    | "hotfix-file-backfill"
                    | "remove"
                    | "directory-sync"
                    | "validated-sudoers-converge"
                    | "source-shelf-sweep"
                    | "symlink-converge"
                    | "validated-symlink"
                    | "validated-file-symlink"
            )
            | ("git-artifact", "sync")
            | ("grub", "apply-theme")
            | ("household-time", "set-timezone" | "watch-and-set")
            | ("systemd", "model-slots")
            | ("venv", "converge")
            | ("fetch-artifact", "fetch")
            | ("release-binary", "install")
            | ("hermes-maintenance", "converge")
            | ("service-runtime", "converge")
            // Synthetic child emitted by managed-files lowering.
            | ("remove-file", "remove-file")
    )
}

pub(crate) fn validate_step_args(
    step_id: &str,
    tool: &str,
    permutation: &str,
    args: &BTreeMap<String, Value>,
) -> Result<(), String> {
    let has_after_write = args.contains_key("after_write");
    let has_no_reader = args.contains_key("no_running_reader");
    if !has_after_write && !has_no_reader {
        return Ok(());
    }
    if !is_supported_writer(tool, permutation) {
        return Err(format!("after-write-declaration-on-non-writer {step_id}"));
    }
    if has_after_write && has_no_reader {
        return Err(format!("after-write-declarations-conflict {step_id}"));
    }
    if let Some(reason) = args.get("no_running_reader") {
        let reason = reason.as_str().ok_or_else(|| {
            format!("no-running-reader-reason-invalid {step_id}")
        })?;
        if reason.trim().is_empty() {
            return Err(format!("no-running-reader-reason-empty {step_id}"));
        }
        return Ok(());
    }
    let entries = args
        .get("after_write")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("after-write-entries-invalid {step_id}"))?;
    for (index, entry) in entries.iter().enumerate() {
        let object = entry
            .as_object()
            .ok_or_else(|| format!("after-write-entry-not-object {step_id} {index}"))?;
        validate_entry(step_id, index, object)?;
    }
    Ok(())
}

fn validate_entry(step_id: &str, index: usize, object: &Map<String, Value>) -> Result<(), String> {
    const ACTION_KEYS: [&str; 4] = ["daemon_reload", "reload", "restart", "program"];
    for key in object.keys() {
        if key != "user" && !ACTION_KEYS.contains(&key.as_str()) && key != "args" {
            return Err(format!("after-write-entry-unknown-key {step_id} {index} {key}"));
        }
    }
    let actions: Vec<_> = ACTION_KEYS
        .iter()
        .filter(|key| object.contains_key(**key))
        .copied()
        .collect();
    if actions.len() != 1 {
        return Err(format!("after-write-entry-action-count-invalid {step_id} {index}"));
    }
    if let Some(user) = object.get("user") {
        let user = user
            .as_str()
            .filter(|user| valid_account_name(user))
            .ok_or_else(|| format!("after-write-entry-user-invalid {step_id} {index}"))?;
        if user.contains('\0') {
            return Err(format!("after-write-entry-user-invalid {step_id} {index}"));
        }
    }
    match actions[0] {
        "daemon_reload" => {
            if object.get("daemon_reload").and_then(Value::as_bool) != Some(true)
                || object.contains_key("args")
            {
                return Err(format!("after-write-daemon-reload-shape-invalid {step_id} {index}"));
            }
        }
        "reload" | "restart" => {
            let unit = object[actions[0]]
                .as_str()
                .filter(|unit| !unit.trim().is_empty() && !unit.starts_with('-'))
                .ok_or_else(|| format!("after-write-unit-invalid {step_id} {index}"))?;
            if unit.chars().any(char::is_control) || object.contains_key("args") {
                return Err(format!("after-write-unit-invalid {step_id} {index}"));
            }
        }
        "program" => {
            let program = object["program"]
                .as_str()
                .ok_or_else(|| format!("after-write-program-invalid {step_id} {index}"))?;
            if !Path::new(program).is_absolute() || program.contains('\0') {
                return Err(format!("after-write-program-must-be-absolute {step_id} {index}"));
            }
            let arguments = object
                .get("args")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("after-write-program-args-invalid {step_id} {index}"))?;
            if arguments.iter().any(|argument| {
                argument.as_str().is_none_or(|argument| argument.contains('\0'))
            }) {
                return Err(format!("after-write-program-args-invalid {step_id} {index}"));
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn valid_account_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

pub(crate) fn run_for_write(
    step_id: &str,
    tool: &str,
    permutation: &str,
    args: &BTreeMap<String, Value>,
    changed: bool,
    apply: bool,
    owner_acceptance: bool,
    invocation: Option<&InvocationKey>,
) -> AfterWriteRun {
    if !changed || !apply || !is_supported_writer(tool, permutation) {
        return AfterWriteRun::default();
    }
    if !owner_acceptance && is_proposal_only_write(tool, permutation, args) {
        return AfterWriteRun::default();
    }
    let mut run = AfterWriteRun::default();
    let entries = args.get("after_write").and_then(Value::as_array);
    if let Some(entries) = entries.filter(|entries| !entries.is_empty()) {
        for (index, entry) in entries.iter().enumerate() {
            let started = Instant::now();
            let (receipt, failure) = run_entry(step_id, index, entry, invocation);
            let action = receipt.get("action").and_then(Value::as_str).unwrap_or("invalid");
            let signal: String = failure.as_deref().unwrap_or("none").chars().take(256).collect();
            let target: String = step_id.chars().take(128).collect();
            eprintln!(
                "actor=harmonia verb=after-write target={:?} outcome={} duration_ms={} entry={} action={} signal={:?}",
                target,
                if failure.is_some() { "failed" } else { "ok" },
                started.elapsed().as_millis(),
                index,
                action,
                signal,
            );
            run.entries.push(receipt);
            if let Some(failure) = failure {
                run.failure = Some(failure);
                break;
            }
        }
    } else if let Some(reason) = args.get("no_running_reader").and_then(Value::as_str) {
        run.entries.push(json!({
            "step_id": step_id,
            "ok": true,
            "no_running_reader": reason,
        }));
    } else {
        let signal = format!("after-write-undeclared {step_id}");
        run.entries.push(json!({
            "step_id": step_id,
            "ok": true,
            "signal": signal,
        }));
    }
    run
}

fn is_proposal_only_write(tool: &str, permutation: &str, args: &BTreeMap<String, Value>) -> bool {
    if tool == "files" && permutation == "json-key-proposal" {
        return true;
    }
    if tool == "files" && permutation == "compile-fragments" {
        let target = args
            .get("target_path")
            .or_else(|| args.get("output_path"))
            .and_then(Value::as_str)
            .map(Path::new);
        return target.is_some_and(|target| {
            matches!(
                crate::atoms::files::classify_target(target),
                crate::atoms::files::TargetClass::Config
            )
        });
    }
    false
}

fn run_entry(
    step_id: &str,
    index: usize,
    entry: &Value,
    invocation: Option<&InvocationKey>,
) -> (Value, Option<String>) {
    let Some(object) = entry.as_object() else {
        let signal = format!("after-write-entry-not-object {step_id} {index}");
        return (
            json!({
                "step_id": step_id,
                "entry": index,
                "action": "invalid",
                "unit": Value::Null,
                "ok": false,
                "exit_code": Value::Null,
                "readback": Value::Null,
                "signal": signal,
            }),
            Some(signal),
        );
    };
    let action = ["daemon_reload", "reload", "restart", "program"]
        .into_iter()
        .find(|key| object.contains_key(*key))
        .unwrap_or("invalid");
    let user = object.get("user").and_then(Value::as_str);
    let unit = object
        .get("reload")
        .or_else(|| object.get("restart"))
        .and_then(Value::as_str);
    let mut receipt = json!({
        "step_id": step_id,
        "entry": index,
        "action": action,
        "unit": unit,
        "user": user,
        "ok": false,
        "exit_code": Value::Null,
        "readback": Value::Null,
    });
    let result = if let Some(invocation) = invocation {
        match action {
            "daemon_reload" => run_daemon_reload(invocation, user),
            "reload" => object["reload"]
                .as_str()
                .map(|unit| run_unit_action(invocation, unit, user, false))
                .unwrap_or_else(|| {
                    ActionResult::failed(
                        format!("after-write-unit-invalid {step_id} {index}"),
                        Value::Null,
                        Value::Null,
                    )
                }),
            "restart" => object["restart"]
                .as_str()
                .map(|unit| run_unit_action(invocation, unit, user, true))
                .unwrap_or_else(|| {
                    ActionResult::failed(
                        format!("after-write-unit-invalid {step_id} {index}"),
                        Value::Null,
                        Value::Null,
                    )
                }),
            "program" => run_program(invocation, object, user),
            _ => ActionResult::failed(
                format!("after-write-entry-action-invalid {step_id} {index}"),
                Value::Null,
                Value::Null,
            ),
        }
    } else {
        ActionResult::failed(
            format!("after-write-owner-invocation-required {step_id} {index}"),
            Value::Null,
            Value::Null,
        )
    };
    receipt["exit_code"] = result.exit_code;
    receipt["readback"] = result.readback;
    if let Some(signal) = result.failure {
        receipt["signal"] = Value::String(signal.clone());
        (receipt, Some(signal))
    } else {
        receipt["ok"] = Value::Bool(true);
        (receipt, None)
    }
}

fn run_daemon_reload(
    invocation: &InvocationKey,
    user: Option<&str>,
) -> ActionResult {
    let observation = match run_systemd_change(
        invocation,
        "",
        crate::atoms::r#do::change_unit::UnitVerb::DaemonReload,
        user,
    ) {
        Ok(observation) => observation,
        Err(signal) => return ActionResult::failed(signal, Value::Null, Value::Null),
    };
    let exit_code = json!(observation.code);
    let readback = json!({"daemon_reloaded": observation.ok});
    if !observation.ok {
        ActionResult::failed("after-write-daemon-reload-failed", exit_code, readback)
    } else {
        ActionResult::success(exit_code, readback)
    }
}

fn run_unit_action(
    invocation: &InvocationKey,
    unit: &str,
    user: Option<&str>,
    restart: bool,
) -> ActionResult {
    let before_active = match active_state(unit, user) {
        Ok(state) => state,
        Err(signal) => return ActionResult::failed(signal, Value::Null, Value::Null),
    };
    let before_identity = if restart && before_active == "active" {
        match process_identity(unit, user) {
            Ok(identity) => Some(identity),
            Err(signal) => {
                return ActionResult::failed(
                    signal,
                    Value::Null,
                    json!({"active_state_before": before_active}),
                )
            }
        }
    } else {
        None
    };
    let verb = if restart {
        crate::atoms::r#do::change_unit::UnitVerb::TryRestart
    } else {
        crate::atoms::r#do::change_unit::UnitVerb::TryReloadOrRestart
    };
    let observation = match run_systemd_change(invocation, unit, verb, user) {
        Ok(observation) => observation,
        Err(signal) => {
            return ActionResult::failed(
                signal,
                Value::Null,
                json!({"active_state_before": before_active}),
            )
        }
    };
    let exit_code = json!(observation.code);
    let after_active = match active_state(unit, user) {
        Ok(state) => state,
        Err(signal) => {
            return ActionResult::failed(
                signal.clone(),
                exit_code,
                json!({
                    "active_state_before": before_active,
                    "active_state_after": Value::Null,
                    "readback_signal": signal,
                }),
            )
        }
    };
    let mut readback = json!({
        "active_state_before": before_active,
        "active_state_after": after_active,
        "exit_code": observation.code,
    });
    let after_identity = if restart && before_active == "active" && after_active == "active" {
        match process_identity(unit, user) {
            Ok(identity) => Some(identity),
            Err(signal) => {
                readback["readback_signal"] = Value::String(signal.clone());
                return ActionResult::failed(signal, exit_code, readback);
            }
        }
    } else {
        None
    };
    if let Some(before_identity) = before_identity.as_ref() {
        readback["main_pid_before"] = Value::String(before_identity.0.clone());
        readback["exec_main_start_timestamp_before"] =
            Value::String(before_identity.1.clone());
    }
    if let Some(after_identity) = after_identity.as_ref() {
        readback["main_pid_after"] = Value::String(after_identity.0.clone());
        readback["exec_main_start_timestamp_after"] =
            Value::String(after_identity.1.clone());
    }
    if !observation.ok {
        return ActionResult::failed(
            format!(
                "after-write-systemd-action-failed action={} unit={unit}",
                if restart { "restart" } else { "reload" }
            ),
            exit_code,
            readback,
        );
    }
    if !restart && after_active != "active" {
        return ActionResult::failed(
            format!("after-write-reload-not-observed unit={unit}"),
            exit_code,
            readback,
        );
    }
    if restart && before_active == "active" {
        if after_active != "active" || before_identity.as_ref() == after_identity.as_ref() {
            return ActionResult::failed(
                format!("after-write-restart-not-observed unit={unit}"),
                exit_code,
                readback,
            );
        }
    } else {
        readback["skipped_inactive"] = Value::Bool(before_active != "active");
    }
    ActionResult::success(exit_code, readback)
}

fn run_systemd_change(
    invocation: &InvocationKey,
    unit: &str,
    verb: crate::atoms::r#do::change_unit::UnitVerb,
    user: Option<&str>,
) -> Result<crate::atoms::CommandObservation, String> {
    let result = crate::atoms::comparison::execute_once(
        "harmonia-after-write-systemd",
        || Ok::<(), String>(()),
        |_| DiffDecision::Different,
        |authorization, _| {
            crate::atoms::r#do::change_unit::unit_change_scoped(
                &authorization,
                invocation,
                unit,
                verb,
                user.is_some(),
                user,
                ACTION_TIMEOUT_SECS,
            )
        },
    )?;
    match result {
        ComparisonRun::Moved { movement, .. } => Ok(movement),
        ComparisonRun::Current { .. } => Err("after-write-systemd-action-not-executed".into()),
    }
}

fn active_state(unit: &str, user: Option<&str>) -> Result<String, String> {
    let observation = crate::atoms::ask::systemd_state_query(
        "active-state",
        unit,
        user.is_some(),
        user,
        ACTION_TIMEOUT_SECS,
    );
    if !observation.ok {
        return Err(format!("after-write-active-state-readback-failed unit={unit}"));
    }
    let state = observation.stdout.trim();
    if state.is_empty() || state.chars().any(char::is_control) {
        return Err(format!("after-write-active-state-readback-invalid unit={unit}"));
    }
    Ok(state.to_owned())
}

fn process_identity(unit: &str, user: Option<&str>) -> Result<(String, String), String> {
    let main_pid = systemd_property("main-pid", unit, user)?;
    let start_timestamp = systemd_property("exec-main-start-timestamp", unit, user)?;
    Ok((main_pid, start_timestamp))
}

fn systemd_property(kind: &str, unit: &str, user: Option<&str>) -> Result<String, String> {
    let observation = crate::atoms::ask::systemd_state_query(
        kind,
        unit,
        user.is_some(),
        user,
        ACTION_TIMEOUT_SECS,
    );
    if !observation.ok {
        return Err(format!("after-write-process-identity-readback-failed unit={unit}"));
    }
    let value = observation.stdout.trim();
    if value.chars().any(char::is_control) {
        return Err(format!("after-write-process-identity-readback-invalid unit={unit}"));
    }
    Ok(value.to_owned())
}

fn run_program(
    invocation: &InvocationKey,
    entry: &Map<String, Value>,
    user: Option<&str>,
) -> ActionResult {
    match run_program_inner(invocation, entry, user) {
        Ok(result) => result,
        Err(signal) => ActionResult::failed(signal, Value::Null, Value::Null),
    }
}

fn run_program_inner(
    invocation: &InvocationKey,
    entry: &Map<String, Value>,
    user: Option<&str>,
) -> Result<ActionResult, String> {
    let program = entry
        .get("program")
        .and_then(Value::as_str)
        .ok_or_else(|| "after-write-program-invalid".to_string())?;
    let args: Vec<String> = entry
        .get("args")
        .and_then(Value::as_array)
        .ok_or_else(|| "after-write-program-args-invalid".to_string())?
        .iter()
        .map(|argument| {
            argument
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "after-write-program-args-invalid".to_string())
        })
        .collect::<Result<_, _>>()?;
    let (command, command_args, bearer) = if let Some(user) = user {
        let uid = account_uid(user)?;
        let current_uid = unsafe { libc::geteuid() };
        let bearer = if uid == current_uid {
            None
        } else if current_uid == 0 {
            Some(crate::atoms::command::resolve_command_bearer(Some(user)))
        } else {
            return Err("after-write-program-user-privilege-refused".into());
        };
        let mut command_args = vec![format!("XDG_RUNTIME_DIR=/run/user/{uid}"), program.to_owned()];
        command_args.extend(args);
        ("/usr/bin/env", command_args, bearer)
    } else {
        (program, args, None)
    };
    let result = crate::atoms::comparison::execute_once(
        "harmonia-after-write-program",
        || Ok::<(), String>(()),
        |_| DiffDecision::Different,
        |authorization, _| {
            crate::atoms::command::authorized_capture(
                &authorization,
                invocation,
                command,
                &command_args,
                None,
                Duration::from_secs(ACTION_TIMEOUT_SECS),
                None,
                bearer.as_ref(),
            )
        },
    )?;
    let observation = match result {
        ComparisonRun::Moved { movement, .. } => movement,
        ComparisonRun::Current { .. } => {
            return Err("after-write-program-not-executed".into())
        }
    };
    let exit_code = json!(observation.code);
    let readback = json!({"program": program, "completed": observation.ok});
    if !observation.ok {
        Ok(ActionResult::failed(
            "after-write-program-failed",
            exit_code,
            readback,
        ))
    } else {
        Ok(ActionResult::success(exit_code, readback))
    }
}

fn account_uid(user: &str) -> Result<u32, String> {
    let name = CString::new(user).map_err(|_| "after-write-program-user-invalid")?;
    let mut passwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut entry = std::ptr::null_mut();
    let mut buffer = vec![0u8; 64 * 1024];
    let status = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            passwd.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut entry,
        )
    };
    if status != 0 || entry.is_null() {
        return Err("after-write-program-user-not-found".into());
    }
    Ok(unsafe { (*entry).pw_uid })
}

pub(crate) fn covers_systemd_step(
    after_write_entries: &[Value],
    step: &ValidatedStep,
) -> bool {
    if step.tool != "systemd" {
        return false;
    }
    let (wanted_action, wanted_unit, wanted_user) = match step.permutation.as_str() {
        "daemon-reload" => ("daemon_reload", None, systemd_step_user(&step.args, false)),
        "user-daemon-reload" => ("daemon_reload", None, systemd_step_user(&step.args, true)),
        "restart" => (
            "restart",
            step.args.get("service").and_then(Value::as_str),
            systemd_step_user(&step.args, false),
        ),
        "user-restart" => (
            "restart",
            step.args.get("service").and_then(Value::as_str),
            systemd_step_user(&step.args, true),
        ),
        _ => return false,
    };
    after_write_entries.iter().any(|entry| {
        let Some(object) = entry.as_object() else { return false; };
        let (action, unit) = if object.contains_key("daemon_reload") {
            ("daemon_reload", None)
        } else if let Some(unit) = object.get("restart").and_then(Value::as_str) {
            ("restart", Some(unit))
        } else if let Some(unit) = object.get("reload").and_then(Value::as_str) {
            ("restart", Some(unit))
        } else {
            return false;
        };
        action == wanted_action
            && unit == wanted_unit
            && object.get("user").and_then(Value::as_str) == wanted_user
    })
}

pub(crate) fn receipt_covers_systemd_step(
    after_write_receipts: &[Value],
    tool: &str,
    permutation: &str,
    args: &BTreeMap<String, Value>,
) -> bool {
    receipt_covers_systemd_step_with_reload(after_write_receipts, tool, permutation, args, true)
}

pub(crate) fn receipt_covers_systemd_restart_step(
    after_write_receipts: &[Value],
    tool: &str,
    permutation: &str,
    args: &BTreeMap<String, Value>,
) -> bool {
    receipt_covers_systemd_step_with_reload(after_write_receipts, tool, permutation, args, false)
}

fn receipt_covers_systemd_step_with_reload(
    after_write_receipts: &[Value],
    tool: &str,
    permutation: &str,
    args: &BTreeMap<String, Value>,
    allow_reload: bool,
) -> bool {
    if tool != "systemd" {
        return false;
    }
    let (wanted_action, wanted_unit, wanted_user) = match permutation {
        "daemon-reload" => ("daemon_reload", None, systemd_step_user(args, false)),
        "user-daemon-reload" => ("daemon_reload", None, systemd_step_user(args, true)),
        "restart" => ("restart", args.get("service").and_then(Value::as_str), systemd_step_user(args, false)),
        "user-restart" => ("restart", args.get("service").and_then(Value::as_str), systemd_step_user(args, true)),
        _ => return false,
    };
    after_write_receipts.iter().any(|receipt| {
        if receipt.get("ok").and_then(Value::as_bool) != Some(true) {
            return false;
        }
        let action = receipt.get("action").and_then(Value::as_str);
        let unit = receipt.get("unit").and_then(Value::as_str);
        let covers_action = match (wanted_action, action) {
            ("restart", Some("restart")) => true,
            ("restart", Some("reload")) => allow_reload,
            ("daemon_reload", Some("daemon_reload")) => true,
            _ => false,
        };
        covers_action
            && unit == wanted_unit
            && receipt.get("user").and_then(Value::as_str) == wanted_user
    })
}

fn systemd_step_user(args: &BTreeMap<String, Value>, explicit_user: bool) -> Option<&str> {
    if explicit_user {
        args.get("user").and_then(Value::as_str)
    } else if args.get("user").and_then(Value::as_bool) == Some(true) {
        args.get("target_user").and_then(Value::as_str)
    } else {
        None
    }
}

pub(crate) fn run_on_outcome(
    step: &ValidatedStep,
    outcome: OperationOutcome,
    apply: bool,
    owner_acceptance: bool,
    invocation: Option<&InvocationKey>,
) -> StepExecution {
    let mut run = run_for_write(
        &step.step_id,
        &step.tool,
        &step.permutation,
        &step.args,
        outcome.changed,
        apply,
        owner_acceptance,
        invocation,
    );
    let mut outcome = outcome;
    if let Some(failure) = run.failure.as_ref() {
        outcome.ok = false;
        outcome.message = failure.clone();
    }
    if run.entries.is_empty() {
        // Do not synthesize an empty field on a read, plan, or unchanged step.
        run.entries.shrink_to_fit();
    }
    StepExecution {
        outcome,
        after_write: run.entries,
    }
}
