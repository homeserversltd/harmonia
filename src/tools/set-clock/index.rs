//! Household clock convergence through comparison and ownership lanes.
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
    invocation: Option<atoms::r#do::InvocationKey>,
) -> Result<CmdResult, String> {
    if !apply {
        return Ok(crate::tools::household_time::planned(request.operation));
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
    let run =
        crate::tools::declaration::execute(
            "set-clock",
            "set-clock",
            || Ok::<_, String>(crate::atoms::ask::set_clock::clock(request)),
            |current| {
                let desired = request.timezone.map(str::to_owned).or_else(|| {
                    current.remote_state.as_ref().and_then(|result| {
                        crate::tools::household_time::fresh_timezone(&result.stdout)
                    })
                });
                match request.operation {
                    "resolve" => {
                        if current
                            .remote_state
                            .as_ref()
                            .and_then(|value| {
                                crate::tools::household_time::fresh_timezone(&value.stdout)
                            })
                            .is_none()
                        {
                            DiffDecision::Different
                        } else {
                            DiffDecision::Empty
                        }
                    }
                    "set-timezone" | "watch-and-set" => {
                        if desired
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
            },
            |authorization, current| {
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
            },
        )?;
    let result = match run {
        crate::tools::comparison::ComparisonRun::Current { observation, .. } => observation
            .remote_state
            .clone()
            .unwrap_or_else(|| crate::atoms::ask::set_clock::current_receipt(&observation)),
        crate::tools::comparison::ComparisonRun::Moved { movement, .. } => movement,
    };
    Ok(result)
}

pub(crate) fn execute(
    receipt_dir: &Path,
    step_id: &str,
    permutation: &str,
    args: &std::collections::BTreeMap<String, serde_json::Value>,
    apply: bool,
    invocation: Option<atoms::r#do::InvocationKey>,
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
        &receipt_dir.join(format!("{step_id}.attest.jsonl")),
        permutation,
        outcome.command.as_ref().expect("set-clock command result"),
    )?;
    Ok(outcome)
}

pub(crate) fn execute_validated_step(
    step: &crate::tools::ladder::ValidatedStep,
    module_dir: &Path,
    apply: bool,
    invocation: Option<atoms::r#do::InvocationKey>,
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

pub fn declaration() -> Result<Option<&'static crate::tools::declaration::Declaration>, String> {
    crate::tools::declaration::get("set-clock")
}
