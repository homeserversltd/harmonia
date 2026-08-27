//! Typed Git pull-repo observations. This module owns every read of Git state.
use super::super::git_artifact::{
    self, scoped_request, source_attempt, CommandReceipt, RemoteHeadProbe, SourceCandidateKind,
    SourceOutcome, SourcePlan, SourceReceipt,
};
use crate::atoms::comparison::DiffDecision;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PullRepoObservation {
    pub destination_exists: bool,
    pub destination_kind: &'static str,
    pub dirty: bool,
    pub local_head: Option<String>,
    pub remote_head: Option<String>,
    pub remote_url_matches: bool,
    pub destination_status: CommandReceipt,
    pub dirty_paths: Vec<String>,
    pub prior_branch: Option<String>,
    pub remote_configured: bool,
    pub local_credential_helpers_present: bool,
    pub credential_helpers_status_ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceObservation {
    pub dirty: bool,
    pub local_head: Option<String>,
    pub remote_head: Option<String>,
    pub remote_url_matches: bool,
    pub destination_status: CommandReceipt,
    pub destination_is_git_checkout: bool,
    pub dirty_paths: Vec<String>,
    pub expected_matches: bool,
    pub destination_is_ancestor: bool,
}

impl Default for SourceObservation {
    fn default() -> Self {
        Self {
            dirty: false, local_head: None, remote_head: None, remote_url_matches: false,
            destination_status: CommandReceipt { ok: false, code: -1, stdout: String::new(), stderr: String::new() },
            destination_is_git_checkout: false, dirty_paths: Vec::new(), expected_matches: false, destination_is_ancestor: false,
        }
    }
}

fn dirty_paths(status: &str) -> Vec<String> {
    status.lines().filter_map(|line| {
        let start = if line.as_bytes().get(2) == Some(&b' ') { 3 } else if line.as_bytes().get(1) == Some(&b' ') { 2 } else { return None };
        let path = line.get(start..)?.trim();
        if path.is_empty() { return None }
        Some(path.replace(" -> ", "; "))
    }).collect()
}

fn observe_head(request: &git_artifact::Request, cwd: Option<&str>) -> Option<String> {
    let result = git_observe(request, &["rev-parse", "HEAD^{commit}"], cwd);
    result.ok.then(|| result.stdout.trim().to_string()).filter(|v| git_artifact::is_lower_hex_sha(v))
}

pub(crate) fn compare_pull_repo(observation: &PullRepoObservation) -> DiffDecision {
    if observation.destination_exists
        && !observation.dirty
        && observation.local_head.is_some()
        && observation.local_head == observation.remote_head
        && observation.remote_url_matches
        && !observation.local_credential_helpers_present
        && observation.credential_helpers_status_ok
    { DiffDecision::Empty } else { DiffDecision::Different }
}

pub(crate) fn observe_request(request: &git_artifact::Request) -> PullRepoObservation {
    let destination_exists = request.path.join(".git").exists();
    let destination_kind = if request.path.join(".git").is_dir() { "git-checkout" } else if request.path.exists() { "other" } else { "absent" };
    let cwd = request.path.to_str();
    let local_head = destination_exists.then(|| observe_head(request, cwd)).flatten();
    let destination_status = if destination_exists {
        git_observe(request, &["status", "--porcelain", "--untracked-files=all", "--", ".", ":(exclude).worktrees"], cwd)
    } else { CommandReceipt { ok: true, code: 0, stdout: String::new(), stderr: String::new() } };
    let dirty_paths = dirty_paths(&destination_status.stdout);
    let dirty = !destination_status.ok || !dirty_paths.is_empty();
    let prior_branch = destination_exists.then(|| git_observe(request, &["symbolic-ref", "--short", "HEAD"], cwd))
        .and_then(|r| r.ok.then(|| r.stdout.trim().to_string()));
    let configured = git_observe(request, &["remote", "get-url", &request.remote], cwd);
    let remote_configured = configured.ok;
    let configured_url = configured.stdout.trim().to_string();
    let remote_url_matches = request.repo.as_deref().map_or(remote_configured, |repo| {
        remote_configured && configured_url == repo
    });
    let remote_url = request.repo.as_deref().unwrap_or(&configured_url);
    let reference = format!("refs/heads/{}", request.branch);
    let remote = if remote_configured && !remote_url.is_empty() {
        git_observe(request, &["ls-remote", "--refs", remote_url, &reference], None)
    } else {
        configured
    };
    let remote_head = remote.ok
        .then(|| git_artifact::parse_declared_remote_head(&remote.stdout, &reference))
        .flatten();
    let helpers = if destination_exists { git_observe(request, &["config", "--local", "--get-all", "credential.helper"], cwd) } else { CommandReceipt { ok: false, code: 1, stdout: String::new(), stderr: String::new() } };
    PullRepoObservation { destination_exists, destination_kind, dirty, local_head, remote_head, remote_url_matches, destination_status, dirty_paths, prior_branch, remote_configured, local_credential_helpers_present: helpers.ok && !helpers.stdout.trim().is_empty(), credential_helpers_status_ok: helpers.ok || helpers.code == 1 }
}

pub(crate) fn observe_source_candidate(plan: &SourcePlan, candidate: &git_artifact::SourceCandidate) -> SourceObservation {
    let request = scoped_request(plan, candidate, plan.destination.clone());
    let destination_is_git_checkout = plan.destination.join(".git").exists();
    let cwd = plan.destination.to_str();
    let (local_head, remote_head, remote_url_matches) = if candidate.kind == SourceCandidateKind::LocalCheckout {
        let source_request = scoped_request(plan, candidate, PathBuf::from(&candidate.locator));
        let head = observe_head(&source_request, Some(&candidate.locator));
        (head.clone(), head, true)
    } else {
        let local = observe_head(&request, cwd);
        let reference = format!("refs/heads/{}", plan.reference);
        let remote = git_observe(&request, &["ls-remote", "--refs", &candidate.locator, &reference], None);
        let remote_head = remote.ok.then(|| git_artifact::parse_declared_remote_head(&remote.stdout, &reference)).flatten();
        (local, remote_head, remote.ok)
    };
    let destination_status = git_observe(&request, &["status", "--porcelain", "--untracked-files=all", "--", ".", ":(exclude).worktrees"], cwd);
    let dirty_paths = if destination_status.ok { dirty_paths(&destination_status.stdout) } else { Vec::new() };
    let dirty = destination_is_git_checkout && !dirty_paths.is_empty();
    let expected_matches = plan.expected_commit.as_deref().is_none_or(|expected| remote_head.as_deref() == Some(expected));
    let destination_is_ancestor = match (local_head.as_deref(), remote_head.as_deref()) {
        (Some(local), Some(remote)) if local != remote => git_observe(&request, &["merge-base", "--is-ancestor", local, remote], cwd).ok,
        (Some(_), Some(_)) => true,
        _ => false,
    };
    SourceObservation { dirty, local_head, remote_head, remote_url_matches, destination_status, destination_is_git_checkout, dirty_paths, expected_matches, destination_is_ancestor }
}

pub(crate) fn observe_request_current(
    request: &crate::atoms::git_artifact::Request,
) -> Option<crate::atoms::git_artifact::Outcome> {
    if !request.path.join(".git").exists() {
        return None;
    }
    let cwd = request.path.to_str()?;
    let before = git_observe(request, &["rev-parse", "HEAD"], Some(cwd));
    if !before.ok {
        return None;
    }
    let dirty = git_observe(
        request,
        &["status", "--porcelain", "--", ".", ":(exclude).worktrees"],
        Some(cwd),
    );
    if !dirty.ok || !dirty.stdout.trim().is_empty() {
        return None;
    }
    let configured = git_observe(request, &["remote", "get-url", &request.remote], Some(cwd));
    if !configured.ok
        || request
            .repo
            .as_deref()
            .is_some_and(|repo| configured.stdout.trim() != repo)
    {
        return None;
    }
    let remote_url = configured.stdout.trim().to_string();
    let helpers = git_observe(
        request,
        &["config", "--local", "--get-all", "credential.helper"],
        Some(cwd),
    );
    if helpers.ok && !helpers.stdout.trim().is_empty() {
        return None;
    }
    if !helpers.ok && helpers.code != 1 {
        return None;
    }
    let reference = format!("refs/heads/{}", request.branch);
    let remote = git_observe(
        request,
        &["ls-remote", "--refs", &remote_url, &reference],
        None,
    );
    let remote_sha = remote
        .ok
        .then(|| crate::atoms::git_artifact::parse_declared_remote_head(&remote.stdout, &reference))
        .flatten()?;
    if remote_sha != before.stdout.trim() {
        return None;
    }
    Some(crate::atoms::git_artifact::Outcome {
        ok: true,
        changed: false,
        message: format!("git-artifact sync {}", request.path.display()),
        command: crate::atoms::git_artifact::CommandReceipt {
            ok: true,
            code: 0,
            stdout: format!(
                "before={}\\nafter={}\\nls-remote --refs {} {}\\nno fetch; already current",
                before.stdout.trim(),
                before.stdout.trim(),
                remote_url,
                reference
            ),
            stderr: String::new(),
        },
    })
}

pub(crate) fn plan(
    request: &crate::atoms::git_artifact::Request,
) -> crate::atoms::git_artifact::Outcome {
    let command = if request.path.join(".git").exists() {
        git_observe(request, &["status", "--short"], request.path.to_str())
    } else {
        crate::atoms::git_artifact::CommandReceipt {
            ok: true,
            code: 0,
            stdout: format!("planned clone/update path={}", request.path.display()),
            stderr: String::new(),
        }
    };
    crate::atoms::git_artifact::Outcome {
        ok: command.ok,
        changed: false,
        message: format!("git-artifact planned {}", request.path.display()),
        command,
    }
}

// Git observation lives in Ask.  The pull-repo deed may consume these
// observations, but it owns all clone/fetch/checkout/promotion actuation.
pub(crate) fn git_observe(
    request: &crate::atoms::git_artifact::Request,
    args: &[&str],
    cwd: Option<&str>,
) -> crate::atoms::git_artifact::CommandReceipt {
    let context = match crate::atoms::git_artifact::git_command_context(request) {
        Ok(context) => context,
        Err(stderr) => {
            return crate::atoms::git_artifact::CommandReceipt {
                ok: false,
                code: -1,
                stdout: String::new(),
                stderr,
            };
        }
    };
    let mut owned_args = context.config_args;
    owned_args.extend(args.iter().map(|arg| (*arg).to_string()));
    let refs = owned_args.iter().map(String::as_str).collect::<Vec<_>>();
    crate::atoms::command::capture_with_cwd_as_bearer_and_env(
        "/usr/bin/git",
        &refs,
        cwd,
        &request.bearer,
        context.env,
    )
}

pub(crate) fn source_head(path: &Path, bearer: &str) -> crate::atoms::git_artifact::CommandReceipt {
    let request = crate::atoms::git_artifact::Request::new(
        None,
        path.to_path_buf(),
        String::new(),
        String::new(),
    )
    .with_bearer(bearer)
    .with_safe_directory(path);
    git_observe(&request, &["rev-parse", "HEAD"], path.to_str())
}

pub(crate) fn probe_declared_remote_head(plan: &SourcePlan) -> RemoteHeadProbe {
    if plan.candidates.is_empty() {
        return RemoteHeadProbe {
            state: "not-applicable".into(),
            candidate_index: None,
            candidate_kind: None,
            locator: None,
            credential_selector: None,
            reference: plan.reference.clone(),
            remote_sha: None,
            command: CommandReceipt {
                ok: true,
                code: 0,
                stdout: "source candidates absent; remote probe not applicable".into(),
                stderr: String::new(),
            },
            failed_attempts: Vec::new(),
        };
    }

    let reference = format!("refs/heads/{}", plan.reference);
    let mut failed_attempts = Vec::new();
    let mut last_command = CommandReceipt {
        ok: true,
        code: 0,
        stdout: "source candidates absent; remote probe not applicable".into(),
        stderr: String::new(),
    };
    for (offset, candidate) in plan.candidates.iter().enumerate() {
        let index = offset + 1;
        if candidate.kind == SourceCandidateKind::LocalCheckout {
            let command = source_head(Path::new(&candidate.locator), &plan.bearer);
            let remote_sha = command
                .ok
                .then(|| command.stdout.trim().to_string())
                .filter(|sha| crate::atoms::git_artifact::is_lower_hex_sha(sha));
            return RemoteHeadProbe {
                state: if remote_sha.is_some() {
                    "local-checkout-observed".into()
                } else {
                    "probe-unavailable".into()
                },
                candidate_index: Some(index),
                candidate_kind: Some(candidate.kind),
                locator: Some(candidate.locator.clone()),
                credential_selector: candidate.credential_selector.clone(),
                reference: plan.reference.clone(),
                remote_sha,
                command,
                failed_attempts,
            };
        }
        if let Some(selector) = candidate.credential_selector.as_deref() {
            if !plan.credentials.contains_key(selector) {
                let command = CommandReceipt {
                    ok: false,
                    code: -1,
                    stdout: String::new(),
                    stderr: "credential-selector-unresolved".into(),
                };
                failed_attempts.push(source_attempt(
                    index,
                    candidate,
                    "hard-red-credential",
                    None,
                    false,
                    command.stderr.clone(),
                ));
                return RemoteHeadProbe {
                    state: "probe-unavailable".into(),
                    candidate_index: None,
                    candidate_kind: None,
                    locator: None,
                    credential_selector: None,
                    reference: plan.reference.clone(),
                    remote_sha: None,
                    command,
                    failed_attempts,
                };
            }
        }
        let request = scoped_request(plan, candidate, plan.destination.clone());
        let command = git_observe(
            &request,
            &["ls-remote", "--refs", &candidate.locator, &reference],
            None,
        );
        let remote_sha = command
            .ok
            .then(|| {
                crate::atoms::git_artifact::parse_declared_remote_head(&command.stdout, &reference)
            })
            .flatten();
        if let Some(remote_sha) = remote_sha {
            return RemoteHeadProbe {
                state: "remote-head-observed".into(),
                candidate_index: Some(index),
                candidate_kind: Some(candidate.kind),
                locator: Some(candidate.locator.clone()),
                credential_selector: candidate.credential_selector.clone(),
                reference: plan.reference.clone(),
                remote_sha: Some(remote_sha),
                command,
                failed_attempts,
            };
        }
        let detail = if command.ok {
            "ls-remote-output-invalid".into()
        } else if command.stderr.trim().is_empty() {
            "ls-remote-failed".into()
        } else {
            command.stderr.clone()
        };
        failed_attempts.push(source_attempt(
            index,
            candidate,
            "probe-unavailable",
            None,
            false,
            detail,
        ));
        last_command = command;
    }
    RemoteHeadProbe {
        state: "probe-unavailable".into(),
        candidate_index: None,
        candidate_kind: None,
        locator: None,
        credential_selector: None,
        reference: plan.reference.clone(),
        remote_sha: None,
        command: last_command,
        failed_attempts,
    }
}

/// Acquire one candidate into a fresh sibling staging tree, verify it, then
/// promote it.  No existing checkout remote participates in this operation.
///
/// Promotion uses same-filesystem renames.  It prevents blends, but Unix does
/// not offer an atomic replacement of a non-empty directory: a power loss
/// between moving the old tree aside and installing the new tree can leave the
/// old tree at the named backup path.  The receipt states that limit plainly.
pub(crate) fn observe_source_candidates(plan: &SourcePlan) -> Vec<SourceObservation> {
    plan.candidates.iter().map(|candidate| observe_source_candidate(plan, candidate)).collect()
}

/// Re-observe the freshly acted staging tree and the declared source authority.
pub(crate) fn observe_staged_candidate(
    plan: &SourcePlan,
    candidate_index: usize,
    stage: &Path,
) -> Option<SourceObservation> {
    let candidate = plan.candidates.get(candidate_index.checked_sub(1)?)?;
    let request = scoped_request(plan, candidate, stage.to_path_buf());
    let local_head = observe_head(&request, stage.to_str());
    let reference = format!("refs/heads/{}", plan.reference);
    let remote = if candidate.kind == SourceCandidateKind::LocalCheckout {
        let source_request = scoped_request(plan, candidate, PathBuf::from(&candidate.locator));
        git_observe(&source_request, &["rev-parse", "HEAD^{commit}"], Some(&candidate.locator))
    } else {
        git_observe(&request, &["ls-remote", "--refs", &candidate.locator, &reference], None)
    };
    let remote_head = if candidate.kind == SourceCandidateKind::LocalCheckout {
        remote.ok.then(|| remote.stdout.trim().to_string())
            .filter(|v| git_artifact::is_lower_hex_sha(v))
    } else {
        remote.ok.then(|| git_artifact::parse_declared_remote_head(&remote.stdout, &reference)).flatten()
    };
    let destination_status = git_observe(
        &request,
        &["status", "--porcelain", "--untracked-files=all", "--", ".", ":(exclude).worktrees"],
        stage.to_str(),
    );
    let paths = if destination_status.ok { dirty_paths(&destination_status.stdout) } else { Vec::new() };
    Some(SourceObservation {
        dirty: !destination_status.ok || !paths.is_empty(),
        local_head,
        remote_head: remote_head.clone(),
        remote_url_matches: remote.ok,
        destination_status,
        destination_is_git_checkout: stage.join(".git").exists(),
        dirty_paths: paths,
        expected_matches: plan.expected_commit.as_deref().is_none_or(|expected| remote_head.as_deref() == Some(expected)),
        destination_is_ancestor: true,
    })
}

pub(crate) fn compare_source_candidates(
    plan: &SourcePlan,
    observations: &[SourceObservation],
) -> DiffDecision {
    let Some(candidate) = plan.candidates.first() else {
        return DiffDecision::Different;
    };
    if candidate.kind != SourceCandidateKind::Git {
        return DiffDecision::Different;
    }
    let Some(observation) = observations.first() else {
        return DiffDecision::Different;
    };
    if candidate.credential_selector.as_deref().is_some_and(|selector| {
        !plan.credentials.contains_key(selector)
    }) {
        return DiffDecision::Different;
    }
    if !observation.destination_is_git_checkout
        || observation.dirty
        || observation.local_head.is_none()
        || observation.remote_head.is_none()
        || !observation.expected_matches
        || observation.local_head != observation.remote_head
    {
        DiffDecision::Different
    } else {
        DiffDecision::Empty
    }
}

pub(crate) fn observe_source_current(plan: &SourcePlan) -> Option<SourceOutcome> {
    let candidate = plan.candidates.first()?;
    if candidate.kind != SourceCandidateKind::Git {
        return None;
    }
    if candidate.credential_selector.as_deref().is_some_and(|selector| {
        !plan.credentials.contains_key(selector)
    }) {
        return None;
    }
    let destination = source_head(&plan.destination, &plan.bearer);
    let destination_commit = destination
        .ok
        .then(|| destination.stdout.trim().to_string())
        .filter(|v| crate::atoms::git_artifact::is_lower_hex_sha(v))?;
    let request = scoped_request(plan, candidate, plan.destination.clone());
    let destination_status = git_observe(
        &request,
        &["status", "--porcelain", "--", ".", ":(exclude).worktrees"],
        plan.destination.to_str(),
    );
    if !destination_status.ok || !destination_status.stdout.trim().is_empty() {
        return None;
    }
    let reference = format!("refs/heads/{}", plan.reference);
    let remote = git_observe(
        &request,
        &["ls-remote", "--refs", &candidate.locator, &reference],
        None,
    );
    let remote_commit = remote
        .ok
        .then(|| crate::atoms::git_artifact::parse_declared_remote_head(&remote.stdout, &reference))
        .flatten()?;
    if plan.expected_commit.as_deref().is_some_and(|expected| remote_commit != expected)
        || destination_commit != remote_commit
    {
        return None;
    }
    let commit = remote_commit.clone();
    Some(SourceOutcome {
        ok: true,
        changed: false,
        receipt: SourceReceipt {
            attempts: vec![source_attempt(
                1,
                candidate,
                "already-current",
                Some(commit.clone()),
                false,
                "destination-already-projects-observed-head".into(),
            )],
            served_index: Some(1),
            resolved_commit: Some(commit),
            promotion: "already-current; destination projects observed remote head; no clone, stage, or promotion".into(),
        },
    })
}
