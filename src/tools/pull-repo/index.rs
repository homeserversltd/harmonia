use crate::tools::git_artifact::{self, Outcome, Request, SourceOutcome, SourcePlan};
use crate::{
    tools::comparison::{self, DiffDecision},
    CmdResult,
};

#[path = "act/index.rs"]
mod act;
#[path = "observe/index.rs"]
mod observe;
#[path = "report-home/index.rs"]
mod report_home;

pub(crate) fn plan(request: &Request) -> Outcome {
    report_home::outcome(observe::plan(request))
}
pub(crate) fn apply(request: &Request, invocation: crate::atoms::r#do::InvocationKey) -> Outcome {
    let run = comparison::execute(
        "pull-repo",
        || Ok::<_, String>(observe::request(request)),
        |current| {
            if current.is_some() {
                DiffDecision::Empty
            } else {
                DiffDecision::Different
            }
        },
        |authorization, _| Ok(act::git_pull(authorization, request, invocation)),
    );
    let outcome = match run {
        Ok(comparison::ComparisonRun::Current {
            observation: Some(outcome),
            ..
        }) => outcome,
        Ok(comparison::ComparisonRun::Moved { movement, .. }) => movement,
        Ok(_) => Outcome {
            ok: false,
            changed: false,
            message: "git-artifact sync failed".into(),
            command: CmdResult {
                ok: false,
                code: -1,
                stdout: String::new(),
                stderr: "git-pull-unavailable".into(),
            },
        },
        Err(error) => Outcome {
            ok: false,
            changed: false,
            message: error,
            command: CmdResult {
                ok: false,
                code: -1,
                stdout: String::new(),
                stderr: String::new(),
            },
        },
    };
    report_home::outcome(outcome)
}
pub(crate) fn acquire_source(plan: &SourcePlan, invocation: Option<crate::atoms::r#do::InvocationKey>) -> SourceOutcome {
    let Some(invocation) = invocation else { return SourceOutcome { ok:false, changed:false, receipt: git_artifact::SourceReceipt { attempts:Vec::new(), served_index:None, resolved_commit:None, promotion:"invocation-key-missing".into() } }; };
    let run = comparison::execute(
        "pull-repo",
        || Ok::<_, String>(observe::source(plan)),
        |current| {
            if current.is_some() {
                DiffDecision::Empty
            } else {
                DiffDecision::Different
            }
        },
        |authorization, _| Ok(act::git_acquire(authorization, plan, invocation)),
    );
    let outcome = match run {
        Ok(comparison::ComparisonRun::Current {
            observation: Some(outcome),
            ..
        }) => outcome,
        Ok(comparison::ComparisonRun::Moved { movement, .. }) => movement,
        Ok(_) => git_artifact::legacy_acquire_source(plan),
        Err(_) => git_artifact::legacy_acquire_source(plan),
    };
    report_home::source(outcome)
}


pub(crate) fn attest_source(log: &std::path::Path, value: &SourceOutcome) -> Result<(), String> {
    report_home::attest_source(log, value)
}
