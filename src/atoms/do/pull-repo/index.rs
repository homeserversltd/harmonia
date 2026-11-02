//! Git repository pull-source actuator.
//!
//! This deed owns clone/fetch/checkout/fast-forward and staged promotion;
//! typed Ask owns observations; this atom owns orchestration and mutation;
//! declarations and compatibility types are exposed through the tool facade.

use crate::atoms::git_artifact::{
    self, scoped_request, source_attempt, CommandReceipt, Outcome, Request, SourceAttemptReceipt,
    SourceCandidate, SourceCandidateKind, SourceOutcome, SourcePlan, SourceReceipt,
};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::atoms::git_artifact::{
    credential_scope, git_command_context,
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
    observation: &crate::atoms::ask::pull_repo::PullRepoObservation,
) -> Outcome {
    let sync = sync_repo(request, observation);
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

fn sync_repo(request: &Request, observation: &crate::atoms::ask::pull_repo::PullRepoObservation) -> SyncResult {
    let mut initial_transcript = vec![
        format!("destination_type={}", observation.destination_kind),
        format!("requested_ref={}", request.branch),
        format!("credential_scope={}", credential_scope(request)),
    ];
    if observation.destination_kind == "absent" || !request.path.exists() {
        return SyncResult {
            command: CommandReceipt {
                ok: false,
                code: 2,
                stdout: initial_transcript.join("\n"),
                stderr: format!("pull-repo-destination-absent {}; birth places the destination", request.path.display()),
            },
            changed: false,
        };
    }
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
    initial_transcript.extend(preparation.transcript);
    let mut transcript = initial_transcript;
    if !observation.destination_exists {
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
        transcript.push("resulting_head=post-act-ask-attested".into());
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
    let before = observation.local_head.as_deref().map(|head| CommandReceipt { ok: true, code: 0, stdout: head.into(), stderr: String::new() }).unwrap_or_else(|| observation.destination_status.clone());
    if !before.ok { return ownership_prepared_result(before, ownership_changed, &transcript); }
    let destination_was_dirty = observation.dirty;
    let dirty_paths = observation.dirty_paths.clone();
    transcript.push(format!("prior_head={}", before.stdout.trim()));
    transcript.push(format!("prior_branch={}", observation.prior_branch.as_deref().unwrap_or("detached-or-unavailable")));
    transcript.push(format!("dirty_state={}", if destination_was_dirty { "dirty" } else { "clean" }));
    transcript.push(format!("prior_remote_configured={}", observation.remote_configured));
    transcript.push(format!("prior_remote_matches_declared={}", observation.remote_url_matches));
    transcript.push(format!("local_credential_helpers_present={}", observation.local_credential_helpers_present));

    if let Some(repo) = request.repo.as_deref() {
        if !observation.remote_configured {
            return ownership_prepared_result(observation.destination_status.clone(), ownership_changed, &transcript);
        }
        if !observation.remote_url_matches {
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

    if observation.local_credential_helpers_present {
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
    } else if !observation.credential_helpers_status_ok {
        return ownership_prepared_result(observation.destination_status.clone(), ownership_changed, &transcript);
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
    let intended_commit = observation.remote_head.as_deref().unwrap_or("");
    transcript.push(format!("intended_resulting_head={intended_commit}"));
    if destination_was_dirty && intended_commit.is_empty() {
        return ownership_prepared_result(observation.destination_status.clone(), ownership_changed, &transcript);
    }
    if destination_was_dirty {
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
    transcript.push(format!("before={}", before.stdout.trim()));
    transcript.push("resulting_head=post-act-ask-attested".into());
    SyncResult {
        command: CommandReceipt {
            ok: true,
            code: 0,
            stdout: transcript.join("\n"),
            stderr: String::new(),
        },
        changed: true,
    }
}

fn prepare_bearer_writable_path(request: &Request) -> Result<BearerPathPreparation, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(BearerPathPreparation::default());
    }
    let (uid, gid) = bearer_ids(&request.bearer)?;
    repair_tree_owned_by_bearer(&request.path, uid, gid)
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
    observations: &[crate::atoms::ask::pull_repo::SourceObservation],
) -> SourceOutcome {
    let mut attempts = Vec::new();
    let mut precondition = Vec::new();
    let mut precondition_changed = false;
    let mut candidate_parent_prepared = false;
    let parent = match plan.destination.parent() {
        Some(parent) => parent,
        None => return source_failure(attempts, "destination-has-no-parent", false),
    };
    if !parent.exists() {
        return source_failure(attempts, &format!("source-acquire-destination-parent-absent {}; birth places the parent", parent.display()), false);
    }
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
        let candidate_was_dirty = candidate.kind == SourceCandidateKind::Git
            && observations.get(index - 1).is_some_and(|observation| observation.dirty);
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
                let observation = observations.get(index - 1).cloned().unwrap_or_default();
                let head = observation.local_head.clone().map(|stdout| CommandReceipt { ok: true, code: 0, stdout, stderr: String::new() }).unwrap_or_else(|| CommandReceipt { ok: false, code: -1, stdout: String::new(), stderr: "local-checkout-head-unavailable".into() });
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
                if plan.source_policy == "developer"
                    && observation.remote_head.as_deref() != Some(commit.as_str())
                {
                    attempts.push(source_attempt(
                        index,
                        candidate,
                        "hard-red-identity",
                        Some(commit),
                        true,
                        "developer-local-checkout-not-main-head".into(),
                    ));
                    return source_hard_red(attempts, precondition_changed);
                }
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
                match project_local_checkout(&request, &source, &plan.destination, &commit, &observation) {
                    Ok((changed, clobber_detail, stage)) => {
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
                            {
                                let detail = match (changed, clobber_detail.as_deref()) {
                                    (_, Some(detail)) => detail.to_string(),
                                    (true, None) => "head-observed; freshness-is-external; destination-projected".into(),
                                    (false, None) => "head-observed; freshness-is-external; destination-already-projects-observed-head".into(),
                                };
                                format!("{}\nstaged-source-index={index}\nstaged-source-path={}", source_acquisition_detail(&precondition, &detail), stage.display())
                            },
                        ));
                        return SourceOutcome {
                            ok: true,
                            changed: precondition_changed || changed,
                            receipt: SourceReceipt {
                                attempts,
                                served_index: Some(index),
                                resolved_commit: Some(commit),
                                promotion: {
                                    let detail = if changed {
                                        clobber_detail.clone().unwrap_or_else(|| "local-checkout-observed; external freshness authority; destination-projected".into())
                                    } else {
                                        clobber_detail.clone().unwrap_or_else(|| "local-checkout-observed; external freshness authority; destination-already-projects-observed-head".into())
                                    };
                                    format!("{detail}\nstaged-source-index={index}\nstaged-source-path={}", stage.display())
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
                // All Git-state reads are supplied by the typed Ask observation.
                let observation = observations.get(index - 1).cloned().unwrap_or_default();
                if candidate_was_dirty && !observation.expected_matches {
                    attempts.push(source_attempt(index, candidate, "hard-red-identity", observation.remote_head.clone(), false, "expected-commit-mismatch".into()));
                    return source_hard_red(attempts, precondition_changed);
                }
                if candidate_was_dirty {
                    let Some(commit) = observation.remote_head.as_deref() else { continue };
                    let request = scoped_request(plan, candidate, plan.destination.clone());
                    let commit_expression = format!("{commit}^{{commit}}");
                    let destination_commit = crate::atoms::ask::pull_repo::git_observe(
                        &request,
                        &["cat-file", "-e", &commit_expression],
                        plan.destination.to_str(),
                    );
                    if destination_commit.ok {
                        precondition.push(
                            "destination-holds-resolved-commit; destination-fetch-before-clobber skipped"
                                .into(),
                        );
                    } else {
                        let fetch_command = format!(
                            "/usr/bin/git fetch --no-tags {:?} {:?}",
                            candidate.locator, plan.reference
                        );
                        let fetch = capture_git(
                            &request,
                            &["fetch", "--no-tags", &candidate.locator, &plan.reference],
                            plan.destination.to_str(),
                        );
                        if !fetch.ok {
                            attempts.push(source_attempt(
                                index,
                                candidate,
                                "unavailable",
                                Some(commit.to_string()),
                                false,
                                format!(
                                    "destination-fetch-before-clobber-failed command={fetch_command}; exit={} stderr={}",
                                    fetch.code, fetch.stderr
                                ),
                            ));
                            continue;
                        }
                        precondition.push(format!(
                            "destination-fetch-before-clobber command={fetch_command}; exit={} ok=true",
                            fetch.code
                        ));
                    }
                    match clobber_dirty_destination(&request, &plan.destination, commit, &observation.dirty_paths) {
                        Ok(detail) => precondition.push(detail),
                        Err(detail) => {
                            attempts.push(source_attempt(
                                index,
                                candidate,
                                "hard-red-precondition",
                                Some(commit.to_string()),
                                false,
                                source_acquisition_detail(&precondition, &detail),
                            ));
                            return source_hard_red(attempts, precondition_changed);
                        }
                    }
                }
                if observation.remote_head.is_none() {
                    continue;
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
        let clone_command = format!(
            "/usr/bin/git clone --no-checkout {:?} {:?}",
            candidate.locator,
            stage.to_string_lossy()
        );
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
                source_acquisition_detail(
                    &precondition,
                    &format!("command={clone_command}; stderr={}", clone.stderr),
                ),
            ));
            continue;
        }
        let fetch_command = format!("/usr/bin/git fetch --no-tags origin {:?}", plan.reference);
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
                source_acquisition_detail(
                    &precondition,
                    &format!("command={fetch_command}; stderr={}", fetch.stderr),
                ),
            ));
            continue;
        }
        let (head, checkout_command) = if git_artifact::is_lower_hex_sha(&plan.reference) {
            (
                capture_git(&request, &["checkout", "--detach", "FETCH_HEAD"], stage.to_str()),
                "/usr/bin/git checkout --detach FETCH_HEAD".to_string(),
            )
        } else {
            (
                capture_git(
                    &request,
                    &["checkout", "-B", &plan.reference, "FETCH_HEAD"],
                    stage.to_str(),
                ),
                format!("/usr/bin/git checkout -B {:?} FETCH_HEAD", plan.reference),
            )
        };
        if !head.ok {
            attempts.push(source_attempt(
                index,
                candidate,
                "hard-red-identity",
                None,
                false,
                source_acquisition_detail(
                    &precondition,
                    &format!("command={checkout_command}; stderr={}", head.stderr),
                ),
            ));
            return source_hard_red(attempts, precondition_changed);
        }
        attempts.push(source_attempt(
            index,
            candidate,
            "staged",
            None,
            false,
            source_acquisition_detail(&precondition, format!("staged-source-index={index}; staged-source-path={}", stage.display()).as_str()),
        ));
        std::mem::forget(_guard);
        return SourceOutcome { ok: true, changed: true, receipt: SourceReceipt { attempts, served_index: Some(index), resolved_commit: None, promotion: format!("staged-source-index={index}\nstaged-source-path={}", stage.display()) } };
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
    observation: &crate::atoms::ask::pull_repo::SourceObservation,
) -> Result<(bool, Option<String>, PathBuf), String> {
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
        if !observation.destination_is_git_checkout {
            return Err(format!("local-checkout-destination-not-git-refused {}", destination.display()));
        }
        let dirty_paths = observation.dirty_paths.clone();
        if dirty_paths.is_empty() {
            if observation.local_head.as_deref() == Some(observed_commit) { /* still project through a fresh stage */ }
            if !observation.destination_is_ancestor {
                return Err(format!("local-checkout-destination-divergent-refused {}", destination.display()));
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
    std::mem::forget(_guard);
    Ok((true, clobber_detail, stage))
}

fn prepare_source_acquisition_parent(plan: &SourcePlan) -> Result<BearerPathPreparation, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(BearerPathPreparation::default());
    }
    let parent = plan
        .destination
        .parent()
        .ok_or_else(|| "destination-has-no-parent".to_string())?;
    if !parent.exists() {
        return Err(format!("source-acquire-destination-parent-absent {}; birth places the parent", parent.display()));
    }
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

pub(crate) fn promote_staged_source(stage: &Path, destination: &Path) -> Result<(), String> {
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

pub(crate) fn discard_staged_source(stage: &Path) {
    let _ = fs::remove_dir_all(stage);
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


pub(crate) fn xenia_owner_ids(owner: &str) -> Result<(u32, u32), String> {
    #[cfg(test)]
    if owner == "xenia" {
        return Ok((unsafe { libc::geteuid() }, unsafe { libc::getegid() }));
    }
    let name = std::ffi::CString::new(owner).map_err(|_| "xenia-owner-invalid".to_string())?;
    let passwd = unsafe { libc::getpwnam(name.as_ptr()) };
    if passwd.is_null() {
        return Err(format!("xenia-owner-absent {owner}"));
    }
    let passwd = unsafe { &*passwd };
    let group = std::ffi::CString::new("xenia").map_err(|_| "xenia-group-invalid".to_string())?;
    let shared = unsafe { libc::getgrnam(group.as_ptr()) };
    if shared.is_null() {
        return Err("xenia-group-absent".into());
    }
    Ok((passwd.pw_uid, unsafe { (*shared).gr_gid }))
}

/// Source orchestration is owned by the pull-repo Do atom.
pub(crate) mod source_orchestration {
    use crate::atoms::git_artifact::{self, Outcome, Request, SourceOutcome, SourcePlan, SourceCandidate, SourceCandidateKind, SourceReceipt, source_attempt};
    use std::cell::RefCell;
    use std::path::PathBuf;
    use crate::{tools::comparison::{self}, CmdResult};
pub(crate) fn plan(request: &Request) -> Outcome {
    crate::atoms::ask::pull_repo::plan(request)
}
pub(crate) fn apply(
    request: &Request,
    invocation: &crate::atoms::r#do::InvocationKey,
) -> Outcome {
    if !request.path.exists() {
        let signal = format!("pull-repo-destination-absent {}; birth places the destination", request.path.display());
        return Outcome { ok: false, changed: false, message: signal.clone(), command: CmdResult { ok: false, code: 2, stdout: String::new(), stderr: signal } };
    }
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
    if let Some(parent) = plan.destination.parent() {
        if !parent.exists() {
            return super::source_failure(Vec::new(), &format!("source-acquire-destination-parent-absent {}; birth places the parent", parent.display()), false);
        }
    }
    let staged = RefCell::new(None::<(usize, PathBuf)>);
    let before = RefCell::new(None::<Vec<crate::atoms::ask::pull_repo::SourceObservation>>);
    let preserved_attempts = RefCell::new(Vec::<git_artifact::SourceAttemptReceipt>::new());
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
            preserved_attempts
                .borrow_mut()
                .extend(outcome.receipt.attempts.iter().cloned());
            if let Some((index, path)) = parse_staged_marker(&outcome.receipt.promotion) {
                *staged.borrow_mut() = Some((index, path));
            }
            Ok(outcome)
        },
        true,
    );
    match run {
        Ok(comparison::ComparisonRun::Current { observation, .. }) => {
            let (index, candidate, current) =
                crate::atoms::ask::pull_repo::first_answering_source_candidate(plan, &observation)
                    .expect("Current comparison has an answering Git candidate");
            let commit = current
                .remote_head
                .clone()
                .expect("Current comparison has remote identity");
            SourceOutcome {
                ok: true,
                changed: false,
                receipt: git_artifact::SourceReceipt {
                    attempts: vec![source_attempt(
                        index,
                        candidate,
                        "already-current",
                        Some(commit.clone()),
                        false,
                        "destination-already-projects-observed-head".into(),
                    )],
                    served_index: Some(index),
                    resolved_commit: Some(commit),
                    promotion: "already-current; destination projects observed remote head; no clone, stage, or promotion".into(),
                },
            }
        }
        Ok(comparison::ComparisonRun::Moved { observation, mut movement, .. }) => {
            let Some((index, stage)) = staged.into_inner() else {
                movement.ok = false;
                movement.changed = false;
                movement.receipt.served_index = None;
                movement.receipt.resolved_commit = None;
                movement.receipt.promotion =
                    "staged acquisition outcome missing stage identity; destination unchanged".into();
                return movement;
            };
            let Some(post) = observation.get(index - 1) else {
                crate::atoms::r#do::pull_repo::discard_staged_source(&stage);
                movement.ok = false;
                movement.changed = false;
                movement.receipt.served_index = None;
                movement.receipt.resolved_commit = None;
                movement.receipt.promotion =
                    "staged source post-observation missing; stage discarded; destination unchanged".into();
                return movement;
            };
            let Some(commit) = post.local_head.clone() else {
                crate::atoms::r#do::pull_repo::discard_staged_source(&stage);
                movement.ok = false;
                movement.changed = false;
                movement.receipt.served_index = None;
                movement.receipt.resolved_commit = None;
                movement.receipt.promotion =
                    "staged source post-observation has no local commit; stage discarded; destination unchanged".into();
                return movement;
            };
            if post.dirty
                || !post.destination_is_git_checkout
                || post.remote_head.as_deref() != Some(commit.as_str())
                || !post.expected_matches
            {
                crate::atoms::r#do::pull_repo::discard_staged_source(&stage);
                movement.ok = false;
                movement.changed = false;
                movement.receipt.served_index = None;
                movement.receipt.resolved_commit = Some(commit);
                movement.receipt.promotion =
                    "staged source post-state did not converge; stage discarded; destination unchanged".into();
                return movement;
            }
            if let Err(error) = crate::atoms::r#do::pull_repo::promote_staged_source(&stage, &plan.destination) {
                crate::atoms::r#do::pull_repo::discard_staged_source(&stage);
                movement.ok = false;
                movement.changed = false;
                movement.receipt.served_index = None;
                movement.receipt.resolved_commit = None;
                movement.receipt.promotion = error;
                return movement;
            }
            let promoted = crate::atoms::ask::pull_repo::observe_source_candidate(
                plan, &plan.candidates[index - 1],
            );
            if promoted.dirty
                || !promoted.destination_is_git_checkout
                || promoted.local_head.as_deref() != Some(commit.as_str())
                || promoted.remote_head.as_deref() != Some(commit.as_str())
                || !promoted.expected_matches
            {
                movement.ok = false;
                movement.changed = true;
                movement.receipt.promotion = format!(
                    "promoted but destination post-state unproved: expected={commit}; local={:?}; remote={:?}; dirty={}",
                    promoted.local_head, promoted.remote_head, promoted.dirty
                );
                movement.receipt.resolved_commit = Some(commit);
                return movement;
            }
            if let Some(attempt) = movement.receipt.attempts.iter_mut().find(|a| a.index == index) {
                attempt.disposition = if plan.candidates[index - 1].kind == SourceCandidateKind::LocalCheckout { "served-external-projected".into() } else { "served".into() };
                attempt.resolved_commit = Some(commit.clone());
                if attempt.detail.contains("destination-fetch-before-clobber")
                    || attempt.detail.contains("destination-holds-resolved-commit")
                {
                    attempt.detail = format!("{}; verified and promoted", attempt.detail);
                } else {
                    attempt.detail = "verified and promoted".into();
                }
                attempt.external_freshness = plan.candidates[index - 1].kind == SourceCandidateKind::LocalCheckout;
            }
            movement.receipt.resolved_commit = Some(commit);
            movement.receipt.promotion = if plan.candidates[index - 1].kind == SourceCandidateKind::LocalCheckout { "local-checkout-observed; external freshness authority; destination-projected".into() } else { "same-filesystem rename; no blended tree; power-loss may require selecting sibling backup".into() };
            movement
        }
        Err(error) => {
            if let Some((_, stage)) = staged.into_inner() { crate::atoms::r#do::pull_repo::discard_staged_source(&stage); }
            SourceOutcome { ok: false, changed: false, receipt: git_artifact::SourceReceipt { attempts: preserved_attempts.into_inner(), served_index: None, resolved_commit: None, promotion: error } }
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
            drift: if value.ok {
                crate::atoms::Drift::Current
            } else {
                crate::atoms::Drift::File { expected_sha256: "successful-acquisition".into(), actual_sha256: None }
            },
            message: format!("authoritative receipt=pull-repo.json; changed={}", value.changed),
        },
        &[], value.changed)
}

}
