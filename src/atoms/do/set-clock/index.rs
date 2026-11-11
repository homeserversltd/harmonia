//! Authorized household clock convergence atom.
use crate::atoms;
use crate::tools::comparison::DiffDecision;
use crate::CmdResult;
use std::path::Path;

pub(crate) struct Request<'a> {
    pub backend: &'a str,
    pub operation: &'a str,
    pub timezone: Option<&'a str>,
    pub state_url: Option<&'a str>,
    pub state_path: Option<&'a str>,
    pub timeout_secs: u64,
}

pub(crate) fn run(
    request: &Request<'_>,
    apply: bool,
    invocation: Option<&atoms::r#do::InvocationKey>,
) -> Result<CmdResult, String> {
    if !apply {
        return Ok(crate::tools::household_time::planned(request.operation));
    }
    if request.operation == "watch-and-set" {
        if let Err(reason) = crate::interactables::household_zone::require_follow_mode() {
            return Ok(crate::tools::household_time::preserved(&reason, CmdResult {
                ok: false, code: -1, stdout: String::new(), stderr: String::new(),
            }));
        }
    }
    let observation = crate::atoms::ask::set_clock::clock(request);
    let desired_timezone = request.timezone.map(str::to_owned).or_else(|| {
        observation
            .remote_state
            .as_ref()
            .and_then(|result| crate::tools::household_time::fresh_timezone(&result.stdout))
    });
    if request.operation == "watch-and-set" {
        let remote = observation.remote_state.as_ref().expect("watch state");
        if !remote.ok {
            return Ok(crate::tools::household_time::preserved(
                "household-time-peer-state-unreachable",
                remote.clone(),
            ));
        }
        if desired_timezone.is_none() {
            return Ok(crate::tools::household_time::preserved(
                "household-time-peer-state-unavailable-or-stale",
                remote.clone(),
            ));
        }
    }
    let observe = || Ok::<_, String>(crate::atoms::ask::set_clock::clock(request));
    let compare = |current: &crate::atoms::ask::set_clock::ClockObservation| {
                let desired = request.timezone.map(str::to_owned).or_else(|| {
                    current.remote_state.as_ref().and_then(|result| {
                        crate::tools::household_time::fresh_timezone(&result.stdout)
                    })
                });
                match request.operation {
                    "resolve" => DiffDecision::Different,
                    "set-timezone" | "watch-and-set" => {
                        if (request.operation == "watch-and-set" && (desired.is_none()
                            || current.remote_state.as_ref().is_none_or(|remote| !remote.ok)))
                            || desired
                            .as_deref()
                            .is_some_and(|zone| current.timezone.as_deref() != Some(zone))
                            || !current.timesync
                        {
                            DiffDecision::Different
                        } else {
                            DiffDecision::Empty
                        }
                    }
                    _ => DiffDecision::Different,
                }
            };
    let act = |authorization: crate::atoms::comparison::ActionAuthorization, current: &crate::atoms::ask::set_clock::ClockObservation| {
                let authorization = &authorization;
                if request.operation == "watch-and-set" {
                    if let Err(reason) = crate::interactables::household_zone::require_follow_mode() {
                        return Ok(crate::tools::household_time::preserved(&reason, CmdResult {
                            ok: false, code: -1, stdout: String::new(), stderr: String::new(),
                        }));
                    }
                    let remote = current.remote_state.as_ref().expect("watch state");
                    if !remote.ok || crate::tools::household_time::fresh_timezone(&remote.stdout).is_none() {
                        return Ok(crate::tools::household_time::preserved("household-time-peer-state-unavailable", remote.clone()));
                    }
                }
                let invocation =
                    invocation.ok_or_else(|| "set-clock-invocation-key-missing".to_string())?;
                let desired = request.timezone.map(str::to_owned).or_else(|| {
                    current.remote_state.as_ref().and_then(|result| {
                        crate::tools::household_time::fresh_timezone(&result.stdout)
                    })
                });
                crate::atoms::r#do::set_clock::apply(
                    authorization,
                    invocation,
                    request,
                    desired.as_deref(),
                )
            };
    let run = if matches!(request.operation, "resolve" | "watch-and-set") {
        crate::tools::declaration::execute_once("set-clock", "set-clock", observe, compare, act)
    } else {
        crate::tools::declaration::execute("set-clock", "set-clock", observe, compare, act)
    }?;
    let result = match run {
        crate::tools::comparison::ComparisonRun::Current { observation, .. } => observation
            .remote_state
            .clone()
            .unwrap_or_else(|| crate::atoms::ask::set_clock::current_receipt(&observation)),
        crate::tools::comparison::ComparisonRun::Moved { movement, .. } => movement,
    };
    if request.operation == "resolve" && (!result.ok || serde_json::from_str::<serde_json::Value>(&result.stdout)
        .ok().and_then(|value| value.get("ok").and_then(serde_json::Value::as_bool)) == Some(false)) {
        return Ok(crate::tools::household_time::preserved("household-time-resolve-failed", result));
    }
    if request.operation == "watch-and-set" && (!result.ok || serde_json::from_str::<serde_json::Value>(&result.stdout)
        .ok().and_then(|value| value.get("ok").and_then(serde_json::Value::as_bool)) == Some(false)) {
        let after = crate::atoms::ask::set_clock::clock(request);
        let changed = if observation.local_state.ok && after.local_state.ok {
            Some(observation.timezone != after.timezone || observation.timesync != after.timesync)
        } else { None };
        return Ok(CmdResult { ok: true, code: 0,
            stdout: serde_json::json!({"schema":"harmonia.household-time.receipt.v1", "ok":true,
                "changed":changed, "preserved":changed.map(|value| !value), "converged":false,
                "first_missing_signal":"household-time-watch-and-set-failed"}).to_string(),
            stderr: result.stderr });
    }
    Ok(result)
}

pub(crate) fn execute(
    receipt_dir: &Path,
    step_id: &str,
    permutation: &str,
    args: &std::collections::BTreeMap<String, serde_json::Value>,
    apply: bool,
    invocation: Option<&atoms::r#do::InvocationKey>,
) -> Result<crate::OperationOutcome, String> {
    let timeout = args
        .get("timeout_secs")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(15);
    let request = Request {
        backend: args
            .get("backend")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
        operation: permutation,
        timezone: (permutation == "set-timezone").then(|| {
            args.get("timezone")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
        }),
        state_url: (permutation == "watch-and-set").then(|| {
            args.get("state_url")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
        }),
        state_path: args.get("state_path").and_then(serde_json::Value::as_str),
        timeout_secs: timeout,
    };
    let result = run(&request, apply, invocation)?;
    let changed = serde_json::from_str::<serde_json::Value>(&result.stdout)
        .ok()
        .and_then(|v| v.get("changed").and_then(serde_json::Value::as_bool))
        .unwrap_or(false);
    let outcome = crate::OperationOutcome {
        ok: result.ok,
        changed,
        skipped: !apply,
        message: format!("set-clock {permutation}"),
        command: Some(result),
    };
    crate::atoms::attest::set_clock::write_tool_receipt(
        receipt_dir,
        step_id,
        permutation,
        &outcome,
    )?;
    crate::atoms::attest::set_clock::attest(
        &receipt_dir.join(format!("{step_id}")),
        permutation,
        outcome.command.as_ref().expect("set-clock command result"),
        changed,
    )?;
    Ok(outcome)
}

pub(crate) fn execute_validated_step(
    step: &crate::tools::ladder::ValidatedStep,
    module_dir: &Path,
    apply: bool,
    invocation: Option<&atoms::r#do::InvocationKey>,
) -> Result<crate::OperationOutcome, String> {
    crate::tools::household_time::validate_ladder_args(&step.permutation, &step.args)?;
    execute(
        module_dir,
        &step.step_id,
        &step.permutation,
        &step.args,
        apply,
        invocation,
    )
}

use crate::atoms::comparison::ActionAuthorization;
use std::time::Duration;

pub(crate) fn apply(
    authorization: &ActionAuthorization,
    invocation: &atoms::r#do::InvocationKey,
    request: &Request<'_>,
    timezone: Option<&str>,
) -> Result<CmdResult, String> {
    if request.operation == "resolve" {
        return command(authorization, invocation, request, "resolve", None);
    }
    let timezone = timezone.ok_or_else(|| "set-clock-timezone-missing".to_string())?;
    let set = command(
        authorization,
        invocation,
        request,
        "set-timezone",
        Some(timezone),
    )?;
    if !set.ok {
        return Ok(set);
    }
    let sync = command(authorization, invocation, request, "ensure-ntp", None)?;
    if sync.ok {
        Ok(set)
    } else {
        Ok(sync)
    }
}

pub(crate) fn command(
    authorization: &ActionAuthorization,
    invocation: &atoms::r#do::InvocationKey,
    request: &Request<'_>,
    operation: &str,
    timezone: Option<&str>,
) -> Result<CmdResult, String> {
    let (program, args) = match request.backend {
        "caduceus" => {
            let mut args = vec!["time".into(), operation.into()];
            if let Some(zone) = timezone {
                args.push(zone.into());
            }
            (
                std::env::var("HARMONIA_CLOCK_CADUCEUS")
                    .unwrap_or_else(|_| "/usr/local/bin/caduceus".into()),
                args,
            )
        }
        "staff" => {
            let mut args =
                vec!["PYTHONPATH=/usr/local/sbin".into()];
            if let Some(path) = request.state_path {
                args.push(format!("CADUCEUS_HOUSEHOLD_TIME_STATE_PATH={path}"));
            }
            args.extend([
                "/usr/bin/python3".into(),
                "-m".into(),
                "agathodaimon.household_time".into(),
                operation.into(),
            ]);
            if let Some(zone) = timezone {
                args.push(zone.into());
            }
            ("/usr/bin/env".into(), args)
        }
        _ => {
            return Ok(CmdResult {
                ok: false,
                code: -1,
                stdout: String::new(),
                stderr: "household-time-backend-invalid".into(),
            });
        }
    };
    let result = atoms::r#do::run_command::command_with_timeout(
        authorization,
        invocation,
        &program,
        &args,
        Duration::from_secs(request.timeout_secs),
    )?;
    Ok(CmdResult {
        ok: result.ok,
        code: result.code.unwrap_or(-1),
        stdout: result.stdout,
        stderr: result.stderr,
    })
}
