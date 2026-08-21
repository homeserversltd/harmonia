use crate::tools::git_artifact::{self, Outcome, Request, SourceOutcome, SourcePlan};
use crate::{
    tools::comparison::{self, DiffDecision},
    CmdResult,
};

pub(crate) fn plan(request: &Request) -> Outcome {
    crate::atoms::ask::plan(request)
}
pub(crate) fn apply(request: &Request, invocation: crate::atoms::r#do::InvocationKey) -> Outcome {
    let run = crate::tools::declaration::execute(
        "pull-repo",
        "pull-repo",
        || Ok::<_, String>(crate::atoms::ask::observe_request_current(request)),
        |current| {
            if current.is_some() {
                DiffDecision::Empty
            } else {
                DiffDecision::Different
            }
        },
        |authorization, _| {
            Ok(crate::atoms::r#do::pull_repo::git_pull(
                authorization,
                invocation,
                request,
                || crate::atoms::r#do::pull_repo::apply(request),
            ))
        },
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
    outcome
}
pub(crate) fn acquire_source(
    plan: &SourcePlan,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> SourceOutcome {
    let Some(invocation) = invocation else {
        return SourceOutcome {
            ok: false,
            changed: false,
            receipt: git_artifact::SourceReceipt {
                attempts: Vec::new(),
                served_index: None,
                resolved_commit: None,
                promotion: "invocation-key-missing".into(),
            },
        };
    };
    // The git-artifact owner supplies the fresh post-act identity observation.
    // Preserve its movement so acquisition diagnostics survive a guard error.
    let mut acted = None;
    let run = crate::tools::declaration::execute(
        "pull-repo",
        "pull-repo",
        || Ok::<_, String>(crate::atoms::ask::observe_source_current(plan)),
        |current| {
            if current.is_some() {
                DiffDecision::Empty
            } else {
                DiffDecision::Different
            }
        },
        |authorization, _| {
            let outcome =
                crate::atoms::r#do::pull_repo::git_acquire(authorization, invocation, plan, || {
                    crate::atoms::r#do::pull_repo::acquire_source(plan)
                });
            acted = Some(outcome.clone());
            Ok(outcome)
        },
    );
    let outcome = match run {
        Ok(comparison::ComparisonRun::Current {
            observation: Some(outcome),
            ..
        }) => outcome,
        Ok(comparison::ComparisonRun::Moved { movement, .. }) => movement,
        Ok(_) | Err(_) => acted.unwrap_or(SourceOutcome {
            ok: false,
            changed: false,
            receipt: git_artifact::SourceReceipt {
                attempts: Vec::new(),
                served_index: None,
                resolved_commit: None,
                promotion: "declaration-or-comparison-failed".into(),
            },
        }),
    };
    outcome
}

pub(crate) fn observe_source(plan: &SourcePlan) -> Option<SourceOutcome> {
    crate::atoms::ask::observe_source_current(plan)
}

pub(crate) fn attest_source(log: &std::path::Path, value: &SourceOutcome) -> Result<(), String> {
    crate::atoms::attest::attest(
        log,
        &crate::atoms::Receipt {
            atom: "pull-repo".into(),
            ok: value.ok,
            drift: crate::atoms::Drift::Current,
            message: "authoritative receipt=pull-repo.json".into(),
        },
        &[],
    )
}

pub fn declaration() -> Result<Option<&'static crate::tools::declaration::Declaration>, String> {
    crate::tools::declaration::get("pull-repo")
}
