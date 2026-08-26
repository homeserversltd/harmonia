//! Git repository pull-source actuator.
//!
//! This deed owns clone/fetch/checkout/fast-forward and staged promotion;
//! observation remains in `atoms::ask`, while plan/credential types stay in
//! `tools::git_artifact` for compatibility.

use crate::atoms::git_artifact::{
    self, scoped_request, source_attempt, CommandReceipt, Outcome, Request, SourceAttemptReceipt,
    SourceCandidate, SourceCandidateKind, SourceOutcome, SourcePlan, SourceReceipt,
};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::atoms::git_artifact::{
    credential_scope, git_command_context, is_lower_hex_sha, parse_declared_remote_head,
};

fn capture_git(request: &Request, args: &[&str], cwd: Option<&str>) -> CommandReceipt {
    let context = match git_command_context(request) {
        Ok(context) => context,
        Err(stderr) => return CommandReceipt {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr,
        },
    };
    let mut owned_args = context.config_args;
    owned_args.extend(args.iter().map(|arg| (*arg).to_string()));
    let refs = owned_args.iter().map(String::as_str).collect::<Vec<_>>();
    crate::atoms::command::capture_with_cwd_as_bearer_and_env(
        "/usr/bin/git", &refs, cwd, &request.bearer, context.env,
    )
}

fn destination_type(path: &Path) -> &'static str {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return "absent",
        Err(_) => return "other",
    };
    if metadata.file_type().is_symlink() {
        return "symlink";
    }
    if metadata.file_type().is_file() {
        return "regular-file";
    }
    if metadata.is_dir() {
        return if path.join(".git").exists() {
            "git-checkout"
        } else {
            "non-git-directory"
        };
    }
    "other"
}

pub(crate) fn preserved_non_git_path(path: &Path) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("source");
    path.with_file_name(format!("{name}.non-git-preserved-{stamp}"))
}

pub(crate) fn apply(
    _authorization: &crate::atoms::comparison::ActionAuthorization,
    _invocation: &crate::atoms::r#do::InvocationKey,
    request: &Request,
) -> Outcome {
    let sync = sync_repo(request);
    Outcome {
        ok: sync.command.ok,
        changed: sync.changed,
        message: format!("git-artifact sync {}", request.path.display()),
        command: sync.command,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SyncResult {
    command: CommandReceipt,
    changed: bool,
}

#[derive(Debug, Default)]
struct BearerPathPreparation {
    changed: bool,
    transcript: Vec<String>,
}

fn ownership_prepared_result(
    mut command: CommandReceipt,
    changed: bool,
    transcript: &[String],
) -> SyncResult {
    if !transcript.is_empty() {
        let preparation = transcript.join("\n");
        command.stdout = if command.stdout.is_empty() {
            preparation
        } else {
            format!("{preparation}\n{}", command.stdout)
        };
    }
    SyncResult { command, changed }
}

fn dirty_paths(status: &str) -> Vec<String> {
    status
        .lines()
        .filter_map(|line| {
            let start = if line.as_bytes().get(2) == Some(&b' ') {
                3
            } else if line.as_bytes().get(1) == Some(&b' ') {
                2
            } else {
                return None;
            };
            let path = line.get(start..)?.trim();
            if path.is_empty() {
                return None;
            }
            if let Some((old, new)) = path.split_once(" -> ") {
                Some(format!("{old}; {new}"))
            } else {
                Some(path.to_string())
            }
        })
        .collect()
}

fn clobber_dirty_destination(
    request: &Request,
    destination: &Path,
    commit: &str,
    paths: &[String],
) -> Result<String, String> {
    let cwd = destination
        .to_str()
        .ok_or_else(|| "destination-path-not-utf8".to_string())?;
    let reset = capture_git(request, &["reset", "--hard", commit], Some(cwd));
    if !reset.ok {
        return Err(format!("dirty-destination-reset-failed: {}", reset.stderr));
    }
    let clean = capture_git(request, &["clean", "-fd"], Some(cwd));
    if !clean.ok {
        return Err(format!("dirty-destination-clean-failed: {}", clean.stderr));
    }
    Ok(format!(
        "clobbered-dirty-destination; discarded_paths={}",
        paths.join(", ")
    ))
}

fn sync_repo(request: &Request) -> SyncResult {
    let mut initial_transcript = vec![
        format!("destination_type={}", destination_type(&request.path)),
        format!("requested_ref={}", request.branch),
        format!("credential_scope={}", credential_scope(request)),
    ];
    let preparation = match prepare_bearer_writable_path(request) {
        Ok(preparation) => preparation,
        Err(stderr) => {
            return SyncResult {
                command: CommandReceipt {
                    ok: false,
                    code: -1,
                    stdout: initial_transcript.join("\n"),
                    stderr,
                },
                changed: false,
            };
        }
    };
    let ownership_changed = preparation.changed;
    let mut repository_config_changed = false;
    initial_transcript.extend(preparation.transcript);
    let mut transcript = initial_transcript;
    if !request.path.join(".git").exists() {
        let Some(repo) = request.repo.as_deref() else {
            return ownership_prepared_result(
                CommandReceipt {
                    ok: false,
                    code: 2,
                    stdout: String::new(),
                    stderr: format!(
                        "repo missing and no clone URL supplied for {}",
                        request.path.display()
                    ),
                },
                ownership_changed,
                &transcript,
            );
        };
        if let Some(parent) = request.path.parent() {
            if let Err(err) = fs::create_dir_all(parent) {
                return ownership_prepared_result(
                    CommandReceipt {
                        ok: false,
                        code: 2,
                        stdout: String::new(),
                        stderr: format!("create parent failed {}: {err}", parent.display()),
                    },
                    ownership_changed,
                    &transcript,
                );
            }
        }
        if request.path.exists() {
            let preserved = preserved_non_git_path(&request.path);
            match fs::rename(&request.path, &preserved) {
                Ok(()) => transcript.push(format!(
                    "non_git_existing_path_preserved={}",
                    preserved.display()
                )),
                Err(err) => {
                    return SyncResult {
                        command: CommandReceipt {
                            ok: false,
                            code: 2,
                            stdout: transcript.join("\n"),
                            stderr: format!(
                                "existing non-git path could not be preserved {}: {err}",
                                request.path.display()
                            ),
                        },
                        changed: ownership_changed,
                    };
                }
            }
        }
        let preparation = match prepare_bearer_writable_path(request) {
            Ok(preparation) => preparation,
            Err(stderr) => {
                return SyncResult {
                    command: CommandReceipt {
                        ok: false,
                        code: -1,
                        stdout: transcript.join("\n"),
                        stderr,
                    },
                    changed: ownership_changed,
                };
            }
        };
        transcript.extend(preparation.transcript);
        let clone = capture_git(
            request,
            &[
                "clone",
                "--branch",
                &request.branch,
                repo,
                request.path.to_string_lossy().as_ref(),
            ],
            None,
        );
        transcript.push(format!("clone exit={} ok={}", clone.code, clone.ok));
        if !clone.stdout.is_empty() {
            transcript.push(clone.stdout.clone());
        }
        if !clone.stderr.is_empty() {
            transcript.push(clone.stderr.clone());
        }
        if !clone.ok {
            return SyncResult {
                command: CommandReceipt {
                    ok: false,
                    code: clone.code,
                    stdout: transcript.join("\n"),
                    stderr: clone.stderr,
                },
                changed: ownership_changed,
            };
        }
        let resulting_head = capture_git(
            request,
            &["rev-parse", "HEAD^{commit}"],
            request.path.to_str(),
        );
        if resulting_head.ok {
            transcript.push(format!("resulting_head={}", resulting_head.stdout.trim()));
        }
        return SyncResult {
            command: CommandReceipt {
                ok: true,
                code: 0,
                stdout: transcript.join("\n"),
                stderr: String::new(),
            },
            changed: true,
        };
    }

    let cwd = request.path.to_str();
    let before = crate::atoms::ask::git_observe(request, &["rev-parse", "HEAD"], cwd);
    if !before.ok {
        return ownership_prepared_result(before, ownership_changed, &transcript);
    }
    let dirty = crate::atoms::ask::git_observe(
        request,
        &["status", "--porcelain", "--untracked-files=all", "--", ".", ":(exclude).worktrees"],
        cwd,
    );
    if !dirty.ok {
        return ownership_prepared_result(dirty, ownership_changed, &transcript);
    }
    let prior_branch =
        crate::atoms::ask::git_observe(request, &["symbolic-ref", "--short", "HEAD"], cwd);
    transcript.push(format!("prior_head={}", before.stdout.trim()));
    transcript.push(format!(
        "prior_branch={}",
        if prior_branch.ok {
            prior_branch.stdout.trim()
        } else {
            "detached-or-unavailable"
        }
    ));
    transcript.push(format!(
        "dirty_state={}",
        if dirty.stdout.trim().is_empty() { "clean" } else { "dirty" }
    ));
    let dirty_paths = dirty_paths(&dirty.stdout);
    let destination_was_dirty = !dirty_paths.is_empty();
    let configured = request.repo.as_deref().map(|repo| {
        let probe = crate::atoms::ask::git_observe(
            request,
            &["remote", "get-url", &request.remote],
            cwd,
        );
        transcript.push(format!("prior_remote_configured={}", probe.ok));
        transcript.push(format!(
            "prior_remote_matches_declared={}",
            probe.ok && probe.stdout.trim() == repo
        ));
        probe
    });
    let local_helpers_probe = crate::atoms::ask::git_observe(
        request,
        &["config", "--local", "--get-all", "credential.helper"],
        cwd,
    );
    let local_credential_helpers_present =
        local_helpers_probe.ok && !local_helpers_probe.stdout.trim().is_empty();
    transcript.push(format!(
        "local_credential_helpers_present={local_credential_helpers_present}"
    ));

    if let Some(repo) = request.repo.as_deref() {
        let configured = configured.expect("remote probe exists when repo is declared");
        if !configured.ok {
            return ownership_prepared_result(configured, ownership_changed, &transcript);
        }
        if configured.stdout.trim() != repo {
            let reconcile =
                capture_git(request, &["remote", "set-url", &request.remote, repo], cwd);
            transcript.push(format!(
                "remote_url_reconcile remote={} exit={} ok={}",
                request.remote, reconcile.code, reconcile.ok
            ));
            if !reconcile.ok {
                return SyncResult {
                    command: CommandReceipt {
                        ok: false,
                        code: reconcile.code,
                        stdout: transcript.join("\n"),
                        stderr: reconcile.stderr,
                    },
                    changed: ownership_changed,
                };
            }
        }
    }

    if local_credential_helpers_present {
        let clear = capture_git(
            request,
            &["config", "--local", "--unset-all", "credential.helper"],
            cwd,
        );
        transcript.push(format!(
            "local_credential_helpers_retired exit={} ok={}",
            clear.code, clear.ok
        ));
        if !clear.ok {
            return ownership_prepared_result(clear, ownership_changed, &transcript);
        }
        repository_config_changed = true;
    } else if !local_helpers_probe.ok && local_helpers_probe.code != 1 {
        return ownership_prepared_result(local_helpers_probe, ownership_changed, &transcript);
    }

    let remote_tracking_refspec = format!(
        "+refs/heads/{}:refs/remotes/{}/{}",
        request.branch, request.remote, request.branch
    );
    let fetch = capture_git(
        request,
        &["fetch", &request.remote, &remote_tracking_refspec],
        cwd,
    );
    transcript.push(format!("fetch exit={} ok={}", fetch.code, fetch.ok));
    if !fetch.ok {
        return SyncResult {
            command: CommandReceipt {
                ok: false,
                code: fetch.code,
                stdout: transcript.join("\n"),
                stderr: fetch.stderr,
            },
            changed: ownership_changed,
        };
    }
    let intended = crate::atoms::ask::git_observe(
        request,
        &["rev-parse", &format!("{}/{}", request.remote, request.branch)],
        cwd,
    );
    if intended.ok {
        transcript.push(format!("intended_resulting_head={}", intended.stdout.trim()));
    }
    if destination_was_dirty && !intended.ok {
        return ownership_prepared_result(
            intended,
            ownership_changed || destination_was_dirty,
            &transcript,
        );
    }
    if destination_was_dirty {
        let intended_commit = intended.stdout.trim();
        match clobber_dirty_destination(request, &request.path, intended_commit, &dirty_paths) {
            Ok(detail) => transcript.push(detail),
            Err(stderr) => {
                return SyncResult {
                    command: CommandReceipt {
                        ok: false,
                        code: 3,
                        stdout: transcript.join("\n"),
                        stderr,
                    },
                    changed: ownership_changed,
                };
            }
        }
    }
    let checkout = capture_git(request, &["checkout", &request.branch], cwd);
    transcript.push(format!(
        "checkout exit={} ok={}",
        checkout.code, checkout.ok
    ));
    if !checkout.ok {
        return SyncResult {
            command: CommandReceipt {
                ok: false,
                code: checkout.code,
                stdout: transcript.join("\n"),
                stderr: checkout.stderr,
            },
            changed: ownership_changed,
        };
    }
    let pull_ref = format!("{}/{}", request.remote, request.branch);
    let merge = capture_git(request, &["merge", "--ff-only", &pull_ref], cwd);
    transcript.push(format!("merge_ff exit={} ok={}", merge.code, merge.ok));
    if !merge.stdout.is_empty() {
        transcript.push(merge.stdout.clone());
    }
    if !merge.ok {
        return SyncResult {
            command: CommandReceipt {
                ok: false,
                code: merge.code,
                stdout: transcript.join("\n"),
                stderr: merge.stderr,
            },
            changed: ownership_changed,
        };
    }
    let after = crate::atoms::ask::git_observe(request, &["rev-parse", "HEAD"], cwd);
    if !after.ok {
        return ownership_prepared_result(after, ownership_changed, &transcript);
    }
    let changed = ownership_changed
        || destination_was_dirty
        || repository_config_changed
        || before.stdout.trim() != after.stdout.trim();
    transcript.push(format!("before={}", before.stdout.trim()));
    transcript.push(format!("after={}", after.stdout.trim()));
    transcript.push(format!("resulting_head={}", after.stdout.trim()));
    SyncResult {
        command: CommandReceipt {
            ok: true,
            code: 0,
            stdout: transcript.join("\n"),
            stderr: String::new(),
        },
        changed,
    }
}

fn prepare_bearer_writable_path(request: &Request) -> Result<BearerPathPreparation, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(BearerPathPreparation::default());
    }
    let (uid, gid) = bearer_ids(&request.bearer)?;
    if request.path.exists() {
        return repair_tree_owned_by_bearer(&request.path, uid, gid);
    }
    fs::create_dir_all(&request.path).map_err(|err| {
        format!(
            "git-owner-source-path-create-failed {}: {err}",
            request.path.display()
        )
    })?;
    let mut preparation = BearerPathPreparation::default();
    if let Some(transcript) = chown_new_bearer_path(&request.path, uid, gid)? {
        preparation.changed = true;
        preparation.transcript.push(transcript);
    }
    Ok(preparation)
}

fn bearer_ids(bearer: &str) -> Result<(u32, u32), String> {
    let name = std::ffi::CString::new(bearer).map_err(|_| "git-bearer-invalid-name".to_string())?;
    let passwd = unsafe { libc::getpwnam(name.as_ptr()) };
    if passwd.is_null() {
        return Err(format!("git-bearer-unknown {bearer}"));
    }
    let passwd = unsafe { &*passwd };
    if passwd.pw_uid == 0 || passwd.pw_gid == 0 {
        return Err(format!("git-bearer-root-refused {bearer}"));
    }
    Ok((passwd.pw_uid, passwd.pw_gid))
}

fn repair_tree_owned_by_bearer(
    path: &Path,
    uid: u32,
    gid: u32,
) -> Result<BearerPathPreparation, String> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        format!(
            "git-owner-source-path-stat-failed {}: {err}",
            path.display()
        )
    })?;
    let mut preparation = BearerPathPreparation::default();
    if let Some(transcript) = chown_new_bearer_path(path, uid, gid)? {
        preparation.changed = true;
        preparation.transcript.push(transcript);
    }
    if metadata.file_type().is_dir() {
        for entry in fs::read_dir(path).map_err(|err| {
            format!(
                "git-owner-source-path-read-failed {}: {err}",
                path.display()
            )
        })? {
            let entry = entry.map_err(|err| {
                format!(
                    "git-owner-source-path-entry-failed {}: {err}",
                    path.display()
                )
            })?;
            let child = repair_tree_owned_by_bearer(&entry.path(), uid, gid)?;
            preparation.changed |= child.changed;
            preparation.transcript.extend(child.transcript);
        }
    }
    Ok(preparation)
}

fn chown_new_bearer_path(path: &Path, uid: u32, gid: u32) -> Result<Option<String>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        format!(
            "git-owner-source-path-stat-failed {}: {err}",
            path.display()
        )
    })?;
    let previous_uid = metadata.uid();
    let previous_gid = metadata.gid();
    if previous_uid == uid && previous_gid == gid {
        return Ok(None);
    }
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("git-owner-source-path-non-utf8 {}", path.display()))?;
    if unsafe { libc::lchown(path_c.as_ptr(), uid, gid) } != 0 {
        return Err(format!(
            "git-owner-source-path-chown-failed {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(Some(format!(
        "git-owner-source-path-ownership-repaired path={} before={previous_uid}:{previous_gid} after={uid}:{gid}",
        path.display()
    )))
}

pub(crate) fn acquire_source(
    _authorization: &crate::atoms::comparison::ActionAuthorization,
    _invocation: &crate::atoms::r#do::InvocationKey,
    plan: &SourcePlan,
) -> SourceOutcome {
    let mut attempts = Vec::new();
    let mut precondition = Vec::new();
    let mut precondition_changed = false;
    let mut candidate_parent_prepared = false;
    let parent = match plan.destination.parent() {
        Some(parent) => parent,
        None => return source_failure(attempts, "destination-has-no-parent", false),
    };
    let stem = plan
        .destination
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("source");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_nanos())
        .unwrap_or(0);

    for (offset, candidate) in plan.candidates.iter().enumerate() {
        let index = offset + 1;
        if candidate.kind == SourceCandidateKind::Git {
            if let Some(selector) = candidate.credential_selector.as_deref() {
                if !plan.credentials.contains_key(selector) {
                    attempts.push(source_attempt(
                        index,
                        candidate,
                        "hard-red-credential",
                        None,
                        false,
                        "credential-selector-unresolved".into(),
                    ));
                    return source_hard_red(attempts, precondition_changed);
                }
            }
        }
        let candidate_was_dirty;
        match candidate.kind {
            SourceCandidateKind::LocalCheckout => {
                let source = PathBuf::from(&candidate.locator);
                if let Err(detail) = local_checkout_source_preflight(&source) {
                    attempts.push(source_attempt(
                        index,
                        candidate,
                        "unavailable",
                        None,
                        true,
                        detail,
                    ));
                    continue;
                }
                let request = scoped_request(plan, candidate, source.clone());
                let head = crate::atoms::ask::git_observe(
                    &request,
                    &["rev-parse", "HEAD^{commit}"],
                    Some(&candidate.locator),
                );
                if !head.ok {
                    attempts.push(source_attempt(
                        index,
                        candidate,
                        "unavailable",
                        None,
                        true,
                        head.stderr,
                    ));
                    continue;
                }
                let commit = head.stdout.trim().to_string();
                if let Some(expected) = plan.expected_commit.as_deref() {
                    if commit != expected {
                        attempts.push(source_attempt(
                            index,
                            candidate,
                            "hard-red-identity",
                            Some(commit),
                            true,
                            "expected-commit-mismatch".into(),
                        ));
                        return source_hard_red(attempts, precondition_changed);
                    }
                }
                if !candidate_parent_prepared {
                    let preparation = match prepare_source_acquisition_parent(plan) {
                        Ok(preparation) => preparation,
                        Err(detail) => {
                            attempts.push(source_attempt(
                                index,
                                candidate,
                                "hard-red-precondition",
                                Some(commit),
                                true,
                                detail,
                            ));
                            return source_hard_red(attempts, precondition_changed);
                        }
                    };
                    precondition_changed |= preparation.changed;
                    precondition.extend(preparation.transcript);
                }
                match project_local_checkout(&request, &source, &plan.destination, &commit) {
                    Ok((changed, clobber_detail)) => {
                        attempts.push(source_attempt(
                            index,
                            candidate,
                            if clobber_detail.is_some() {
                                "clobbered-dirty-destination"
                            } else {
                                "served-external-projected"
                            },
                            Some(commit.clone()),
                            true,
                            match (changed, clobber_detail.as_deref()) {
                                (_, Some(detail)) => detail.to_string(),
                                (true, None) => source_acquisition_detail(&precondition, "head-observed; freshness-is-external; destination-projected"),
                                (false, None) => source_acquisition_detail(&precondition, "head-observed; freshness-is-external; destination-already-projects-observed-head"),
                            },
                        ));
                        return SourceOutcome {
                            ok: true,
                            changed: precondition_changed || changed,
                            receipt: SourceReceipt {
                                attempts,
                                served_index: Some(index),
                                resolved_commit: Some(commit),
                                promotion: if changed {
                                    clobber_detail.clone().unwrap_or_else(|| "local-checkout-observed; external freshness authority; destination-projected".into())
                                } else {
                                    clobber_detail.clone().unwrap_or_else(|| "local-checkout-observed; external freshness authority; destination-already-projects-observed-head".into())
                                },
                            },
                        };
                    }
                    Err(detail) => {
                        attempts.push(source_attempt(
                            index,
                            candidate,
                            "hard-red-projection",
                            Some(commit),
                            true,
                            source_acquisition_detail(&precondition, &detail),
                        ));
                        return source_hard_red(attempts, precondition_changed);
                    }
                }
            }
            SourceCandidateKind::Git => {
                // Observe both authoritative identities before creating a parent,
                // staging tree, or Git checkout. A failed/ambiguous observation is
                // deliberately a nonempty comparison so the established acquisition
                // path retains its identity and transport checks.
                let destination_head =
                    crate::atoms::ask::source_head(&plan.destination, &plan.bearer);
                let destination_commit = destination_head
                    .ok
                    .then(|| destination_head.stdout.trim().to_string())
                    .filter(|sha| is_lower_hex_sha(sha));
                let probe_request = scoped_request(plan, candidate, plan.destination.clone());
                let reference = format!("refs/heads/{}", plan.reference);
                let remote_probe = crate::atoms::ask::git_observe(
                    &probe_request,
                    &["ls-remote", "--refs", &candidate.locator, &reference],
                    None,
                );
                let remote_commit = remote_probe
                    .ok
                    .then(|| parse_declared_remote_head(&remote_probe.stdout, &reference))
                    .flatten();
                let expected_matches = plan
                    .expected_commit
                    .as_deref()
                    .map_or(true, |expected| remote_commit.as_deref() == Some(expected));
                let destination_status = crate::atoms::ask::git_observe(
                    &probe_request,
                    &["status", "--porcelain", "--untracked-files=all", "--", ".", ":(exclude).worktrees"],
                    plan.destination.to_str(),
                );
                let destination_is_git_checkout = plan.destination.join(".git").exists();
                if destination_is_git_checkout && !destination_status.ok {
                    attempts.push(source_attempt(
                        index,
                        candidate,
                        "hard-red-status",
                        remote_commit.clone(),
                        false,
                        format!("destination-status-failed: {}", destination_status.stderr),
                    ));
                    return source_hard_red(attempts, precondition_changed);
                }
                let dirty_paths = if destination_status.ok {
                    dirty_paths(&destination_status.stdout)
                } else {
                    Vec::new()
                };
                candidate_was_dirty = destination_is_git_checkout && !dirty_paths.is_empty();
                if candidate_was_dirty && !expected_matches {
                    attempts.push(source_attempt(
                        index,
                        candidate,
                        "hard-red-identity",
                        remote_commit.clone(),
                        false,
                        "expected-commit-mismatch".into(),
                    ));
                    return source_hard_red(attempts, precondition_changed);
                }
                let already_current = !candidate_was_dirty
                    && destination_commit.is_some()
                    && destination_commit == remote_commit
                    && expected_matches;
                if candidate_was_dirty {
                    let Some(commit) = remote_commit.as_deref() else {
                        // Do not destroy a dirty destination until the candidate
                        // identity has been resolved authoritatively.
                        continue;
                    };
                    let fetch = capture_git(
                        &probe_request,
                        &["fetch", "--no-tags", &candidate.locator, &reference],
                        plan.destination.to_str(),
                    );
                    if !fetch.ok {
                        attempts.push(source_attempt(
                            index,
                            candidate,
                            "unavailable",
                            Some(commit.to_string()),
                            false,
                            format!("destination-fetch-before-clobber-failed: {}", fetch.stderr),
                        ));
                        continue;
                    }
                    match clobber_dirty_destination(
                        &probe_request,
                        &plan.destination,
                        commit,
                        &dirty_paths,
                    ) {
                        Ok(detail) => precondition.push(detail),
                        Err(detail) => {
                            attempts.push(source_attempt(
                                index,
                                candidate,
                                "hard-red-precondition",
                                Some(commit.to_string()),
                                false,
                                detail,
                            ));
                            return source_hard_red(attempts, precondition_changed);
                        }
                    }
                }
                if already_current {
                    let commit = remote_commit.expect("empty comparison requires remote commit");
                    attempts.push(source_attempt(
                        index,
                        candidate,
                        "already-current",
                        Some(commit.clone()),
                        false,
                        "destination-already-projects-observed-head".into(),
                    ));
                    return SourceOutcome {
                        ok: true,
                        changed: false,
                        receipt: SourceReceipt {
                            attempts,
                            served_index: Some(index),
                            resolved_commit: Some(commit),
                            promotion: "already-current; destination projects observed remote head; no clone, stage, or promotion".into(),
                        },
                    };
                }
            }
        }
        if !candidate_parent_prepared {
            let preparation = match prepare_source_acquisition_parent(plan) {
                Ok(preparation) => preparation,
                Err(detail) => {
                    attempts.push(source_attempt(
                        index,
                        candidate,
                        "hard-red-precondition",
                        None,
                        false,
                        detail,
                    ));
                    return source_hard_red(attempts, precondition_changed);
                }
            };
            precondition_changed |= preparation.changed;
            precondition.extend(preparation.transcript);
            candidate_parent_prepared = true;
        }
        let stage = parent.join(format!(
            ".{stem}.source-acquire-{}-{nonce}-candidate-{index}",
            std::process::id()
        ));
        let _guard = SourceStagingGuard(stage.clone());
        let request = scoped_request(plan, candidate, stage.clone());
        let clone = capture_git(
            &request,
            &[
                "clone",
                "--no-checkout",
                &candidate.locator,
                stage.to_string_lossy().as_ref(),
            ],
            None,
        );
        if !clone.ok {
            let _ = fs::remove_dir_all(&stage);
            attempts.push(source_attempt(
                index,
                candidate,
                "unavailable",
                None,
                false,
                source_acquisition_detail(&precondition, &clone.stderr),
            ));
            continue;
        }
        let fetch = capture_git(
            &request,
            &["fetch", "--no-tags", "origin", &plan.reference],
            stage.to_str(),
        );
        if !fetch.ok {
            let _ = fs::remove_dir_all(&stage);
            attempts.push(source_attempt(
                index,
                candidate,
                "unavailable",
                None,
                false,
                source_acquisition_detail(&precondition, &fetch.stderr),
            ));
            continue;
        }
        let checkout = capture_git(
            &request,
            &["checkout", "-B", &plan.reference, "FETCH_HEAD"],
            stage.to_str(),
        );
        let head = if checkout.ok {
            crate::atoms::ask::git_observe(
                &request,
                &["rev-parse", "HEAD^{commit}"],
                stage.to_str(),
            )
        } else {
            checkout
        };
        if !head.ok {
            attempts.push(source_attempt(
                index,
                candidate,
                "hard-red-identity",
                None,
                false,
                source_acquisition_detail(&precondition, &head.stderr),
            ));
            return source_hard_red(attempts, precondition_changed);
        }
        let commit = head.stdout.trim().to_string();
        if let Some(expected) = plan.expected_commit.as_deref() {
            if commit != expected {
                attempts.push(source_attempt(
                    index,
                    candidate,
                    "hard-red-identity",
                    Some(commit),
                    false,
                    source_acquisition_detail(&precondition, "expected-commit-mismatch"),
                ));
                return source_hard_red(attempts, precondition_changed);
            }
        }
        match promote_staged_source(&stage, &plan.destination) {
            Ok(()) => {
                attempts.push(source_attempt(
                    index,
                    candidate,
                    if candidate_was_dirty {
                        "clobbered-dirty-destination"
                    } else {
                        "served"
                    },
                    Some(commit.clone()),
                    false,
                    source_acquisition_detail(&precondition, "verified and promoted"),
                ));
                return SourceOutcome { ok: true, changed: true, receipt: SourceReceipt { attempts, served_index: Some(index), resolved_commit: Some(commit), promotion: "same-filesystem rename; no blended tree; power-loss may require selecting sibling backup".into() } };
            }
            Err(detail) => {
                attempts.push(source_attempt(
                    index,
                    candidate,
                    "hard-red-promotion",
                    Some(commit),
                    false,
                    source_acquisition_detail(&precondition, &detail),
                ));
                return source_hard_red(attempts, precondition_changed);
            }
        }
    }
    // Every failed candidate is staged under a guarded sibling and removed before
    // reaching this terminal outcome. The source destination is therefore
    // preserved, so the module receipt must not claim a source change.
    source_failure(attempts, "all-candidates-unavailable", false)
}

fn local_checkout_source_preflight(source: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source).map_err(|err| {
        format!(
            "local-checkout-source-stat-failed {}: {err}",
            source.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "local-checkout-source-symlink-refused {}",
            source.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!(
            "local-checkout-source-not-directory {}",
            source.display()
        ));
    }
    Ok(())
}

/// Clone a local source into a same-parent staging directory, attest that its
/// immutable commit equals the observed external head, then atomically install
/// it at the declared destination. The source is never used as a destination,
/// never fetched, and never checked out.
fn project_local_checkout(
    request: &Request,
    source: &Path,
    destination: &Path,
    observed_commit: &str,
) -> Result<(bool, Option<String>), String> {
    let mut clobber_detail: Option<String> = None;
    let destination_state = match fs::symlink_metadata(destination) {
        Ok(metadata) => Some(metadata),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(format!(
                "local-checkout-destination-stat-failed {}: {err}",
                destination.display()
            ));
        }
    };
    if let Some(metadata) = destination_state {
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "local-checkout-destination-symlink-refused {}",
                destination.display()
            ));
        }
        if !metadata.is_dir() {
            return Err(format!(
                "local-checkout-destination-not-directory-refused {}",
                destination.display()
            ));
        }
        let destination_head = crate::atoms::ask::git_observe(
            request,
            &["rev-parse", "HEAD^{commit}"],
            destination.to_str(),
        );
        if !destination_head.ok {
            return Err(format!(
                "local-checkout-destination-not-git-refused {}: {}",
                destination.display(),
                destination_head.stderr
            ));
        }
        let dirty = crate::atoms::ask::git_observe(
            request,
            &["status", "--porcelain", "--untracked-files=all", "--", ".", ":(exclude).worktrees"],
            destination.to_str(),
        );
        if !dirty.ok {
            return Err(format!(
                "local-checkout-destination-status-failed {}: {}",
                destination.display(),
                dirty.stderr
            ));
        }
        let dirty_paths = dirty_paths(&dirty.stdout);
        if dirty_paths.is_empty() {
            let destination_commit = destination_head.stdout.trim();
            if destination_commit == observed_commit {
                return Ok((false, None));
            }
            let destination_is_ancestor = crate::atoms::ask::git_observe(
                request,
                &[
                    "merge-base",
                    "--is-ancestor",
                    destination_commit,
                    observed_commit,
                ],
                source.to_str(),
            );
            if !destination_is_ancestor.ok {
                return Err(format!(
                    "local-checkout-destination-divergent-refused {}",
                    destination.display()
                ));
            }
        } else {
            let fetch = capture_git(
                request,
                &["fetch", "--no-tags", source.to_string_lossy().as_ref(), "HEAD"],
                destination.to_str(),
            );
            if !fetch.ok {
                return Err(format!(
                    "local-checkout-destination-fetch-before-clobber-failed: {}",
                    fetch.stderr
                ));
            }
            clobber_detail = Some(clobber_dirty_destination(
                request,
                destination,
                observed_commit,
                &dirty_paths,
            )?);
        }
    }

    let parent = destination
        .parent()
        .ok_or_else(|| "destination-has-no-parent".to_string())?;
    let stem = destination
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("source");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    let stage = parent.join(format!(
        ".{stem}.local-checkout-projection-{}-{nonce}",
        std::process::id()
    ));
    let _guard = SourceStagingGuard(stage.clone());
    let clone = capture_git(
        request,
        &[
            "clone",
            "--no-local",
            "--no-hardlinks",
            source.to_string_lossy().as_ref(),
            stage.to_string_lossy().as_ref(),
        ],
        None,
    );
    if !clone.ok {
        return Err(format!(
            "local-checkout-projection-clone-failed: {}",
            clone.stderr
        ));
    }
    let projected_head =
        crate::atoms::ask::git_observe(request, &["rev-parse", "HEAD^{commit}"], stage.to_str());
    if !projected_head.ok {
        return Err(format!(
            "local-checkout-projection-head-failed: {}",
            projected_head.stderr
        ));
    }
    if projected_head.stdout.trim() != observed_commit {
        return Err("local-checkout-projection-identity-mismatch".into());
    }
    promote_staged_source(&stage, destination)
        .map_err(|detail| format!("local-checkout-projection-promote-failed: {detail}"))?;
    Ok((true, clobber_detail))
}

fn prepare_source_acquisition_parent(plan: &SourcePlan) -> Result<BearerPathPreparation, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(BearerPathPreparation::default());
    }
    let parent = plan
        .destination
        .parent()
        .ok_or_else(|| "destination-has-no-parent".to_string())?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "source-acquire-candidate-parent-create-failed {}: {err}",
            parent.display()
        )
    })?;
    let (uid, gid) = bearer_ids(&plan.bearer)?;
    let mut preparation = BearerPathPreparation::default();
    match chown_new_bearer_path(parent, uid, gid)? {
        Some(change) => {
            preparation.changed = true;
            preparation.transcript.push(format!(
                "source-acquire-precondition role=candidate-parent bearer={} {}",
                plan.bearer, change
            ));
        }
        None => preparation.transcript.push(format!(
            "source-acquire-precondition role=candidate-parent bearer={} path={} owner={uid}:{gid} state=satisfied",
            plan.bearer,
            parent.display()
        )),
    }
    Ok(preparation)
}

fn source_acquisition_detail(precondition: &[String], detail: &str) -> String {
    if precondition.is_empty() {
        detail.to_string()
    } else {
        format!("{}; {detail}", precondition.join("; "))
    }
}

struct SourceStagingGuard(PathBuf);
impl Drop for SourceStagingGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn promote_staged_source(stage: &Path, destination: &Path) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or_else(|| "destination-has-no-parent".to_string())?;
    if stage.parent() != Some(parent) {
        return Err("unsafe-cross-filesystem-promotion-refused".into());
    }
    if !destination.exists() {
        return fs::rename(stage, destination)
            .map_err(|err| format!("promotion-install-failed: {err}"));
    }
    let backup = destination.with_file_name(format!(
        "{}.source-backup-{}",
        destination
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("source"),
        std::process::id()
    ));
    fs::rename(destination, &backup).map_err(|err| format!("promotion-backup-failed: {err}"))?;
    match fs::rename(stage, destination) {
        Ok(()) => {
            let _ = fs::remove_dir_all(backup);
            Ok(())
        }
        Err(err) => {
            let restore = fs::rename(&backup, destination);
            Err(format!(
                "promotion-install-failed: {err}; restore={restore:?}"
            ))
        }
    }
}

fn source_failure(
    attempts: Vec<SourceAttemptReceipt>,
    detail: &str,
    changed: bool,
) -> SourceOutcome {
    SourceOutcome {
        ok: false,
        changed,
        receipt: SourceReceipt {
            attempts,
            served_index: None,
            resolved_commit: None,
            promotion: detail.into(),
        },
    }
}
fn source_hard_red(attempts: Vec<SourceAttemptReceipt>, changed: bool) -> SourceOutcome {
    SourceOutcome {
        ok: false,
        changed,
        receipt: SourceReceipt {
            attempts,
            served_index: None,
            resolved_commit: None,
            promotion: "hard-red; no-next-candidate".into(),
        },
    }
}

pub(crate) fn git_pull(
    authorization: &crate::atoms::comparison::ActionAuthorization,
    invocation: &crate::atoms::r#do::InvocationKey,
    callback: impl FnOnce(
        &crate::atoms::comparison::ActionAuthorization,
        &crate::atoms::r#do::InvocationKey,
    ) -> Outcome,
) -> Outcome {
    callback(authorization, invocation)
}

pub(crate) fn git_acquire(
    authorization: &crate::atoms::comparison::ActionAuthorization,
    invocation: &crate::atoms::r#do::InvocationKey,
    callback: impl FnOnce(
        &crate::atoms::comparison::ActionAuthorization,
        &crate::atoms::r#do::InvocationKey,
    ) -> SourceOutcome,
) -> SourceOutcome {
    callback(authorization, invocation)
}

pub(crate) fn demo(
    root: &Path,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<serde_json::Value, String> {
    let source = root.join("source");
    let destination = root.join("destination");
    fs::create_dir_all(&source).map_err(|e| e.to_string())?;
    for args in [
        &["init", "-b", "main"][..],
        &["config", "user.email", "demo@example.invalid"],
        &["config", "user.name", "Harmonia Demo"],
    ] {
        if !crate::atoms::command::capture_with_cwd("/usr/bin/git", args, source.to_str())
            .ok
        {
            return Err("git-demo-init-failed".into());
        }
    }
    fs::write(source.join("payload"), b"source-bytes\n").map_err(|e| e.to_string())?;
    for args in [&["add", "payload"][..], &["commit", "-m", "seed"]] {
        if !crate::atoms::command::capture_with_cwd("/usr/bin/git", args, source.to_str())
            .ok
        {
            return Err("git-demo-commit-failed".into());
        }
    }
    let head_before = crate::atoms::command::capture_with_cwd(
        "/usr/bin/git",
        &["rev-parse", "HEAD"],
        source.to_str(),
    );
    let plan = SourcePlan {
        candidates: vec![SourceCandidate {
            kind: SourceCandidateKind::LocalCheckout,
            locator: source.display().to_string(),
            credential_selector: None,
        }],
        reference: "main".into(),
        destination: destination.clone(),
        expected_commit: None,
        bearer: "owner".into(),
        credentials: std::collections::BTreeMap::new(),
    };
    let first = crate::pull_repo::acquire_source(&plan, invocation);
    let first_changed = first.ok && first.changed;
    let destination_payload = destination.join("payload");
    let exact = destination_payload.is_file()
        && fs::read(&destination_payload)
            .map(|bytes| bytes == b"source-bytes\n")
            .unwrap_or(false);
    let second = crate::pull_repo::acquire_source(&plan, invocation);
    let quiet = second.ok && !second.changed;
    let head_after = crate::atoms::command::capture_with_cwd(
        "/usr/bin/git",
        &["rev-parse", "HEAD"],
        source.to_str(),
    );
    let source_unchanged =
        head_before.ok && head_after.ok && head_before.stdout == head_after.stdout;
    Ok(serde_json::json!({
        "source_head_unchanged": source_unchanged, "destination_exact": exact, "first_movement": first_changed, "second_quiet": quiet, "production_ok": first.ok && second.ok,
        "first_ok": first.ok, "first_changed": first.changed, "first_message": format!("{:?}", first.receipt), "first_attempts": format!("{:?}", first.receipt.attempts),
        "second_ok": second.ok, "second_changed": second.changed, "second_message": format!("{:?}", second.receipt), "second_attempts": format!("{:?}", second.receipt.attempts),
        "source_head_before": head_before.stdout, "source_head_after": head_after.stdout, "ok": first_changed && exact && quiet && source_unchanged,
    }))
}
