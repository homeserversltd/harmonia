use crate::tools::git_artifact::{
    self, source_attempt, Outcome, Request, SourceCandidate, SourceCandidateKind, SourceOutcome,
    SourcePlan, SourceReceipt,
};
use std::cell::RefCell;
use std::path::PathBuf;
use crate::{
    tools::comparison::{self},
    CmdResult,
};

pub(crate) fn plan(request: &Request) -> Outcome {
    crate::atoms::ask::pull_repo::plan(request)
}
pub(crate) fn apply(
    request: &Request,
    invocation: &crate::atoms::r#do::InvocationKey,
) -> Outcome {
    let run = crate::atoms::comparison::execute_mode(
        "pull-repo",
        || Ok::<_, String>(crate::atoms::ask::pull_repo::observe_request(request)),
        crate::atoms::ask::pull_repo::compare_pull_repo,
        |authorization, observation| Ok(crate::atoms::r#do::pull_repo::git_pull(
            &authorization, invocation,
            |authorization, invocation| crate::atoms::r#do::pull_repo::apply(authorization, invocation, request, observation),
        )),
        true,
    );
    match run {
        Ok(crate::atoms::comparison::ComparisonRun::Current { .. }) => Outcome {
            ok: true, changed: false, message: format!("git-artifact sync {} already current", request.path.display()),
            command: CmdResult { ok: true, code: 0, stdout: "already-current".into(), stderr: String::new() },
        },
        Ok(crate::atoms::comparison::ComparisonRun::Moved { movement, .. }) => movement,
        Err(error) => Outcome { ok: false, changed: false, message: error, command: CmdResult { ok: false, code: -1, stdout: String::new(), stderr: String::new() } },
    }
}
pub(crate) fn acquire_xenia_clone(
    entry: &serde_json::Value,
    destination: PathBuf,
    apply: bool,
) -> SourceOutcome {
    let repo = entry
        .pointer("/source/repo")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let reference = entry
        .pointer("/source/ref")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let owner = entry
        .pointer("/install/owner")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let locator = repo
        .split_once('/')
        .filter(|(owner, name)| {
            !owner.is_empty()
                && !name.is_empty()
                && !name.contains('/')
                && !repo.contains("://")
        })
        .map(|_| format!("https://git.home.arpa/{repo}.git"));
    let candidate = SourceCandidate {
        kind: SourceCandidateKind::Git,
        locator: locator.clone().unwrap_or_else(|| repo.to_owned()),
        credential_selector: None,
    };
    let failure = |detail: String| SourceOutcome {
        ok: false,
        changed: false,
        receipt: SourceReceipt {
            attempts: vec![source_attempt(1, &candidate, "failed", None, false, detail.clone())],
            served_index: None,
            resolved_commit: None,
            promotion: detail,
        },
    };
    if repo.is_empty() || reference.is_empty() || owner.is_empty() || locator.is_none() {
        return failure("xenia-clone-source-incomplete".into());
    }
    if !apply {
        let resolved = crate::atoms::ask::pull_repo::source_head(&destination, owner);
        let resolved = resolved
            .ok
            .then(|| resolved.stdout.trim().to_owned())
            .filter(|value| crate::atoms::git_artifact::is_lower_hex_sha(value));
        return SourceOutcome {
            ok: true,
            changed: false,
            receipt: SourceReceipt {
                attempts: vec![source_attempt(1, &candidate, "planned", resolved.clone(), false, "in-place clone planned".into())],
                served_index: None,
                resolved_commit: resolved,
                promotion: "xenia clone planned".into(),
            },
        };
    }
    let request = crate::atoms::git_artifact::Request::new(
        locator,
        destination,
        reference.to_owned(),
        "origin".into(),
    )
    .with_bearer(owner.to_owned());
    match crate::atoms::ask::pull_repo::clone_in_place(&request, reference, owner) {
        Ok((changed, resolved, detail)) => SourceOutcome {
            ok: true,
            changed,
            receipt: SourceReceipt {
                attempts: vec![source_attempt(1, &candidate, "served-in-place", Some(resolved.clone()), false, detail)],
                served_index: Some(1),
                resolved_commit: Some(resolved),
                promotion: "xenia clone fetched and checked out in place; untracked target preserved".into(),
            },
        },
        Err(error) => failure(error),
    }
}

pub(crate) fn acquire_source(
    plan: &SourcePlan,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> SourceOutcome {
    let Some(invocation) = invocation else {
        return SourceOutcome {
            ok: false,
            changed: false,
            receipt: git_artifact::SourceReceipt {
                attempts: Vec::new(), served_index: None, resolved_commit: None,
                promotion: "invocation-key-missing".into(),
            },
        };
    };
    let staged = RefCell::new(None::<(usize, PathBuf)>);
    let before = RefCell::new(None::<Vec<crate::atoms::ask::pull_repo::SourceObservation>>);
    let run = crate::atoms::comparison::execute_mode(
        "pull-repo",
        || {
            if let Some((index, stage)) = staged.borrow().as_ref() {
                let mut observations = before.borrow().clone().unwrap_or_default();
                if let Some(observation) = crate::atoms::ask::pull_repo::observe_staged_candidate(plan, *index, stage) {
                    if observations.len() < *index { observations.resize(*index, Default::default()); }
                    observations[*index - 1] = observation;
                }
                Ok(observations)
            } else {
                let observations = crate::atoms::ask::pull_repo::observe_source_candidates(plan);
                *before.borrow_mut() = Some(observations.clone());
                Ok(observations)
            }
        },
        |observations: &Vec<_>| {
            if let Some((index, _)) = staged.borrow().as_ref() {
                compare_staged_candidate(plan, observations, *index)
            } else {
                crate::atoms::ask::pull_repo::compare_source_candidates(plan, observations)
            }
        },
        |authorization, observations| {
            let outcome = crate::atoms::r#do::pull_repo::git_acquire(
                &authorization, invocation,
                |authorization, invocation| crate::atoms::r#do::pull_repo::acquire_source(authorization, invocation, plan, observations),
            );
            if let Some((index, path)) = parse_staged_marker(&outcome.receipt.promotion) {
                *staged.borrow_mut() = Some((index, path));
            }
            Ok(outcome)
        },
        true,
    );
    match run {
        Ok(comparison::ComparisonRun::Current { observation, .. }) => {
            let candidate = &plan.candidates[0];
            let commit = observation[0].remote_head.clone().expect("empty comparison has remote identity");
            SourceOutcome {
                ok: true,
                changed: false,
                receipt: git_artifact::SourceReceipt {
                    attempts: vec![git_artifact::SourceAttemptReceipt {
                        index: 1,
                        kind: candidate.kind,
                        locator: candidate.locator.clone(),
                        credential_selector: candidate.credential_selector.clone(),
                        disposition: "already-current".into(),
                        resolved_commit: Some(commit.clone()),
                        external_freshness: false,
                        detail: "destination-already-projects-observed-head".into(),
                    }],
                    served_index: Some(1),
                    resolved_commit: Some(commit),
                    promotion: "already-current; destination projects observed remote head; no clone, stage, or promotion".into(),
                },
            }
        }
        Ok(comparison::ComparisonRun::Moved { observation, mut movement, .. }) => {
            let Some((index, stage)) = staged.into_inner() else { return movement; };
            let Some(post) = observation.get(index - 1) else {
                crate::atoms::r#do::pull_repo::discard_staged_source(&stage);
                return movement;
            };
            let Some(commit) = post.local_head.clone() else {
                crate::atoms::r#do::pull_repo::discard_staged_source(&stage);
                return movement;
            };
            if let Err(error) = crate::atoms::r#do::pull_repo::promote_staged_source(&stage, &plan.destination) {
                crate::atoms::r#do::pull_repo::discard_staged_source(&stage);
                movement.ok = false;
                movement.changed = false;
                movement.receipt.served_index = None;
                movement.receipt.resolved_commit = None;
                movement.receipt.promotion = error;
                return movement;
            }
            if let Some(attempt) = movement.receipt.attempts.iter_mut().find(|a| a.index == index) {
                attempt.disposition = if plan.candidates[index - 1].kind == SourceCandidateKind::LocalCheckout { "served-external-projected".into() } else { "served".into() };
                attempt.resolved_commit = Some(commit.clone());
                attempt.detail = "verified and promoted".into();
                attempt.external_freshness = plan.candidates[index - 1].kind == SourceCandidateKind::LocalCheckout;
            }
            movement.receipt.resolved_commit = Some(commit);
            movement.receipt.promotion = if plan.candidates[index - 1].kind == SourceCandidateKind::LocalCheckout { "local-checkout-observed; external freshness authority; destination-projected".into() } else { "same-filesystem rename; no blended tree; power-loss may require selecting sibling backup".into() };
            movement
        }
        Err(error) => {
            if let Some((_, stage)) = staged.into_inner() { crate::atoms::r#do::pull_repo::discard_staged_source(&stage); }
            SourceOutcome { ok: false, changed: false, receipt: git_artifact::SourceReceipt { attempts: Vec::new(), served_index: None, resolved_commit: None, promotion: error } }
        }
    }
}

fn compare_staged_candidate(
    plan: &SourcePlan,
    observations: &[crate::atoms::ask::pull_repo::SourceObservation],
    index: usize,
) -> crate::atoms::comparison::DiffDecision {
    let Some(candidate) = plan.candidates.get(index - 1) else {
        return crate::atoms::comparison::DiffDecision::Different;
    };
    let Some(observation) = observations.get(index - 1) else {
        return crate::atoms::comparison::DiffDecision::Different;
    };
    if observation.dirty
        || !observation.destination_is_git_checkout
        || observation.local_head.is_none()
        || observation.local_head != observation.remote_head
        || !observation.expected_matches
    {
        crate::atoms::comparison::DiffDecision::Different
    } else {
        let _ = candidate;
        crate::atoms::comparison::DiffDecision::Empty
    }
}

fn parse_staged_marker(promotion: &str) -> Option<(usize, PathBuf)> {
    let index = promotion.lines().find_map(|line| line.strip_prefix("staged-source-index=")?.parse().ok())?;
    let path = promotion.lines().find_map(|line| line.strip_prefix("staged-source-path=").map(PathBuf::from))?;
    Some((index, path))
}

pub(crate) fn observe_source(plan: &SourcePlan) -> Option<SourceOutcome> {
    crate::atoms::ask::pull_repo::observe_source_current(plan)
}

pub(crate) fn attest_source(log: &std::path::Path, value: &SourceOutcome) -> Result<(), String> {
    crate::atoms::attest::pull_repo::write_source_receipt(
        &log.with_extension("source.json"),
        &value.receipt,
    )?;
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
