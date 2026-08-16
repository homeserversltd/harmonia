//! Household clock convergence behind observe/compare/act/report-home.
use crate::atoms;
use crate::tools::comparison::{self, DiffDecision};
use crate::CmdResult;
use std::path::Path;

#[path = "act/index.rs"]
mod act;
#[path = "observe/index.rs"]
mod observe;
#[path = "report-home/index.rs"]
mod report_home;

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
    let observation = observe::clock(request);
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
    let differs = match request.operation {
        "resolve" => observation
            .remote_state
            .as_ref()
            .and_then(|value| crate::tools::household_time::fresh_timezone(&value.stdout))
            .is_none(),
        "set-timezone" | "watch-and-set" => {
            desired_timezone
                .as_deref()
                .is_some_and(|zone| observation.timezone.as_deref() != Some(zone))
                || !observation.timesync
        }
        _ => true,
    };
    let run = crate::tools::declaration::execute(
        "set-clock",
        "set-clock",
        || Ok::<_, String>(observation.clone()),
        |_| {
            if differs {
                DiffDecision::Different
            } else {
                DiffDecision::Empty
            }
        },
        |authorization, _| {
            let invocation =
                invocation.ok_or_else(|| "set-clock-invocation-key-missing".to_string())?;
            act::apply(
                authorization,
                invocation,
                request,
                desired_timezone.as_deref(),
            )
        },
    )?;
    let result = match run {
        comparison::ComparisonRun::Current { observation, .. } => observation
            .remote_state
            .clone()
            .unwrap_or_else(|| observe::current_receipt(&observation)),
        comparison::ComparisonRun::Moved { movement, .. } => movement,
    };
    Ok(result)
}

pub(crate) fn report_home(log: &Path, operation: &str, result: &CmdResult) -> Result<(), String> {
    report_home::attest(log, operation, result)
}

pub fn declaration() -> Result<Option<&'static crate::tools::declaration::Declaration>, String> {
    crate::tools::declaration::get("set-clock")
}
