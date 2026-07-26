use super::{command, ToolArg, ToolArgKind, ToolContract, ToolPermutation};

pub const NAME: &str = "git-artifact";
pub const DESCRIPTION: &str = "Bottled repository primitive for clone, fetch, clean-tree guard, checkout, and fast-forward update through profile modules.";
pub const PERMUTATIONS: &[ToolPermutation] = &[ToolPermutation::new(
    "sync",
    "clone or fast-forward a repository artifact",
    &[
        ToolArg::required("component", ToolArgKind::String),
        ToolArg::required("path", ToolArgKind::String),
        // Source Git runs as the declared non-root bearer.
        ToolArg::optional("bearer", ToolArgKind::String),
    ],
)];
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION, PERMUTATIONS);

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub type CommandReceipt = crate::CmdResult;

const DEFAULT_BEARER: &str = "owner";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub ok: bool,
    pub changed: bool,
    pub message: String,
    pub command: CommandReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub repo: Option<String>,
    pub path: PathBuf,
    pub branch: String,
    pub remote: String,
    pub bearer: String,
    pub ssh_key_path: Option<PathBuf>,
    pub git_https_credential_host: Option<String>,
    pub git_https_credential_token_path: Option<PathBuf>,
}

impl Request {
    pub fn new(repo: Option<String>, path: PathBuf, branch: String, remote: String) -> Self {
        Self {
            repo,
            path,
            branch,
            remote,
            bearer: DEFAULT_BEARER.to_string(),
            ssh_key_path: None,
            git_https_credential_host: None,
            git_https_credential_token_path: None,
        }
    }

    pub fn with_bearer(mut self, bearer: impl Into<String>) -> Self {
        self.bearer = bearer.into();
        self
    }

    pub fn with_ssh_key_path(mut self, path: Option<PathBuf>) -> Self {
        self.ssh_key_path = path;
        self
    }

    pub fn with_https_credentials(
        mut self,
        host: Option<String>,
        token_path: Option<PathBuf>,
    ) -> Self {
        self.git_https_credential_host = host;
        self.git_https_credential_token_path = token_path;
        self
    }
}

fn capture_git(request: &Request, args: &[&str], cwd: Option<&str>) -> CommandReceipt {
    let env = match git_ssh_env(request.ssh_key_path.as_deref()) {
        Ok(env) => env,
        Err(stderr) => {
            return CommandReceipt {
                ok: false,
                code: -1,
                stdout: String::new(),
                stderr,
            };
        }
    };
    let credential_helper = owner_https_credential_helper(request);
    let mut git_args =
        Vec::with_capacity(args.len() + usize::from(credential_helper.is_some()) * 2);
    if let Some(helper) = credential_helper.as_deref() {
        git_args.extend(["-c", helper]);
    }
    git_args.extend_from_slice(args);
    command::capture_with_cwd_as_bearer_and_env(
        "/usr/bin/git",
        &git_args,
        cwd,
        &request.bearer,
        env,
    )
}

fn owner_https_credential_helper(request: &Request) -> Option<String> {
    let host = request.git_https_credential_host.as_deref()?;
    let token_path = request.git_https_credential_token_path.as_deref()?;
    let repo = request.repo.as_deref()?;
    if !repo.starts_with(&format!("https://{host}/")) {
        return None;
    }
    let token_path = token_path.to_str()?;
    Some(format!(
        "credential.helper=!f() {{ protocol= host= username= token=; while IFS= read -r line && [ -n \"$line\" ]; do case \"$line\" in protocol=*) protocol=${{line#protocol=}} ;; host=*) host=${{line#host=}} ;; esac; done; if [ \"$protocol\" = https ] && [ \"$host\" = {} ]; then while IFS= read -r line; do case \"$line\" in FORGEJO_USERNAME=*) username=${{line#FORGEJO_USERNAME=}} ;; FORGEJO_TOKEN=*) token=${{line#FORGEJO_TOKEN=}} ;; esac; done < {}; if [ -n \"$username\" ] && [ -n \"$token\" ]; then printf \"username=%s\\npassword=%s\\n\" \"$username\" \"$token\"; fi; fi; }}; f",
        shell_quote(host),
        shell_quote(token_path),
    ))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Validate only path identity and stage the SSH selector for the Git child.
/// This deliberately never opens the key: `ssh` reads it only in the exec'd
/// Git transport process, after a privileged parent has dropped to its bearer.
fn git_ssh_env(path: Option<&Path>) -> Result<BTreeMap<String, String>, String> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    if !path.is_absolute() {
        return Err(format!("git-ssh-key-path-not-absolute {}", path.display()));
    }
    let metadata = fs::metadata(path)
        .map_err(|err| format!("git-ssh-key-unavailable {}: {err}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("git-ssh-key-not-regular-file {}", path.display()));
    }
    let path = path
        .to_str()
        .ok_or_else(|| format!("git-ssh-key-path-non-utf8 {}", path.display()))?;
    let quoted = format!("'{}'", path.replace('\'', "'\\''"));
    Ok(BTreeMap::from([(
        "GIT_SSH_COMMAND".to_string(),
        format!("ssh -i {quoted} -o IdentitiesOnly=yes"),
    )]))
}

pub fn plan(request: &Request) -> Outcome {
    let command = if request.path.join(".git").exists() {
        capture_git(request, &["status", "--short"], request.path.to_str())
    } else {
        CommandReceipt {
            ok: true,
            code: 0,
            stdout: format!("planned clone/update path={}", request.path.display()),
            stderr: String::new(),
        }
    };
    Outcome {
        ok: command.ok,
        changed: false,
        message: format!("git-artifact planned {}", request.path.display()),
        command,
    }
}

pub fn apply(request: &Request) -> Outcome {
    let sync = sync_repo(request);
    Outcome {
        ok: sync.command.ok,
        changed: sync.command.ok && sync.changed,
        message: format!("git-artifact sync {}", request.path.display()),
        command: sync.command,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SyncResult {
    command: CommandReceipt,
    changed: bool,
}

fn sync_repo(request: &Request) -> SyncResult {
    if let Err(stderr) = prepare_bearer_writable_path(request) {
        return SyncResult {
            command: CommandReceipt {
                ok: false,
                code: -1,
                stdout: String::new(),
                stderr,
            },
            changed: false,
        };
    }
    let mut transcript = Vec::new();
    if !request.path.join(".git").exists() {
        let Some(repo) = request.repo.as_deref() else {
            return SyncResult {
                command: CommandReceipt {
                    ok: false,
                    code: 2,
                    stdout: String::new(),
                    stderr: format!(
                        "repo missing and no clone URL supplied for {}",
                        request.path.display()
                    ),
                },
                changed: false,
            };
        };
        if let Some(parent) = request.path.parent() {
            if let Err(err) = fs::create_dir_all(parent) {
                return SyncResult {
                    command: CommandReceipt {
                        ok: false,
                        code: 2,
                        stdout: String::new(),
                        stderr: format!("create parent failed {}: {err}", parent.display()),
                    },
                    changed: false,
                };
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
                        changed: false,
                    };
                }
            }
        }
        if let Err(stderr) = prepare_bearer_writable_path(request) {
            return SyncResult {
                command: CommandReceipt {
                    ok: false,
                    code: -1,
                    stdout: transcript.join("\n"),
                    stderr,
                },
                changed: false,
            };
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
                changed: false,
            };
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
    let before = capture_git(request, &["rev-parse", "HEAD"], cwd);
    if !before.ok {
        return SyncResult {
            command: before,
            changed: false,
        };
    }
    let dirty = capture_git(
        request,
        &["status", "--porcelain", "--", ".", ":(exclude).worktrees"],
        cwd,
    );
    if !dirty.ok {
        return SyncResult {
            command: dirty,
            changed: false,
        };
    }
    if !dirty.stdout.trim().is_empty() {
        return SyncResult {
            command: CommandReceipt {
                ok: false,
                code: 3,
                stdout: dirty.stdout,
                stderr: "working tree has local modifications; refusing repo sync".to_string(),
            },
            changed: false,
        };
    }

    if let Some(repo) = request.repo.as_deref() {
        let configured = capture_git(request, &["remote", "get-url", &request.remote], cwd);
        if !configured.ok {
            return SyncResult {
                command: configured,
                changed: false,
            };
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
                    changed: false,
                };
            }
        }
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
            changed: false,
        };
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
            changed: false,
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
            changed: false,
        };
    }
    let after = capture_git(request, &["rev-parse", "HEAD"], cwd);
    if !after.ok {
        return SyncResult {
            command: after,
            changed: false,
        };
    }
    let changed = before.stdout.trim() != after.stdout.trim();
    transcript.push(format!("before={}", before.stdout.trim()));
    transcript.push(format!("after={}", after.stdout.trim()));
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

fn prepare_bearer_writable_path(request: &Request) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let (uid, gid) = bearer_ids(&request.bearer)?;
    if request.path.exists() {
        return verify_tree_owned_by_bearer(&request.path, uid, gid);
    }
    fs::create_dir_all(&request.path).map_err(|err| {
        format!(
            "git-owner-source-path-create-failed {}: {err}",
            request.path.display()
        )
    })?;
    chown_new_bearer_path(&request.path, uid, gid)
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

fn verify_tree_owned_by_bearer(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        format!(
            "git-owner-source-path-stat-failed {}: {err}",
            path.display()
        )
    })?;
    if metadata.uid() != uid || metadata.gid() != gid {
        return Err(format!(
            "git-owner-source-path-bearer-mismatch {} expected_uid={uid} expected_gid={gid} actual_uid={} actual_gid={}",
            path.display(),
            metadata.uid(),
            metadata.gid(),
        ));
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
            verify_tree_owned_by_bearer(&entry.path(), uid, gid)?;
        }
    }
    Ok(())
}

fn chown_new_bearer_path(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("git-owner-source-path-non-utf8 {}", path.display()))?;
    if unsafe { libc::lchown(path_c.as_ptr(), uid, gid) } != 0 {
        return Err(format!(
            "git-owner-source-path-chown-failed {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

pub fn stdout_changed(stdout: &str) -> bool {
    stdout.lines().any(|line| line.trim() == "changed=true")
}

fn preserved_non_git_path(path: &Path) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("source");
    path.with_file_name(format!("{name}.non-git-preserved-{stamp}"))
}

/// A resolved source plan.  This intentionally contains candidates, not policy
/// certificates or component names: policy selection belongs to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePlan {
    pub candidates: Vec<SourceCandidate>,
    pub reference: String,
    pub destination: PathBuf,
    pub expected_commit: Option<String>,
    pub bearer: String,
    pub credentials: BTreeMap<String, CredentialScope>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCandidate {
    pub kind: SourceCandidateKind,
    pub locator: String,
    /// Opaque plan-local key.  A missing selector is deliberately anonymous.
    pub credential_selector: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceCandidateKind {
    Git,
    LocalCheckout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialScope {
    pub ssh_key_path: Option<PathBuf>,
    pub https_host: Option<String>,
    pub https_token_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceAttemptReceipt {
    pub index: usize,
    pub kind: SourceCandidateKind,
    pub locator: String,
    pub credential_selector: Option<String>,
    pub disposition: String,
    pub resolved_commit: Option<String>,
    pub external_freshness: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceReceipt {
    pub attempts: Vec<SourceAttemptReceipt>,
    pub served_index: Option<usize>,
    pub resolved_commit: Option<String>,
    pub promotion: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceOutcome {
    pub ok: bool,
    pub changed: bool,
    pub receipt: SourceReceipt,
}

/// Acquire one candidate into a fresh sibling staging tree, verify it, then
/// promote it.  No existing checkout remote participates in this operation.
///
/// Promotion uses same-filesystem renames.  It prevents blends, but Unix does
/// not offer an atomic replacement of a non-empty directory: a power loss
/// between moving the old tree aside and installing the new tree can leave the
/// old tree at the named backup path.  The receipt states that limit plainly.
pub fn acquire_source(plan: &SourcePlan) -> SourceOutcome {
    let mut attempts = Vec::new();
    let parent = match plan.destination.parent() {
        Some(parent) => parent,
        None => return source_failure(attempts, "destination-has-no-parent"),
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
                return source_hard_red(attempts);
            }
        }
        match candidate.kind {
            SourceCandidateKind::LocalCheckout => {
                let request = scoped_request(plan, candidate, PathBuf::from(&candidate.locator));
                let head = capture_git(
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
                        return source_hard_red(attempts);
                    }
                }
                attempts.push(source_attempt(
                    index,
                    candidate,
                    "served-external",
                    Some(commit.clone()),
                    true,
                    "head-observed; freshness-is-external".into(),
                ));
                return SourceOutcome {
                    ok: true,
                    changed: false,
                    receipt: SourceReceipt {
                        attempts,
                        served_index: Some(index),
                        resolved_commit: Some(commit),
                        promotion: "local-checkout-observed; external freshness authority".into(),
                    },
                };
            }
            SourceCandidateKind::Git => {}
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
                clone.stderr,
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
                fetch.stderr,
            ));
            continue;
        }
        let checkout = capture_git(
            &request,
            &["checkout", "--detach", "FETCH_HEAD"],
            stage.to_str(),
        );
        let head = if checkout.ok {
            capture_git(&request, &["rev-parse", "HEAD^{commit}"], stage.to_str())
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
                head.stderr,
            ));
            return source_hard_red(attempts);
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
                    "expected-commit-mismatch".into(),
                ));
                return source_hard_red(attempts);
            }
        }
        match promote_staged_source(&stage, &plan.destination) {
            Ok(()) => {
                attempts.push(source_attempt(
                    index,
                    candidate,
                    "served",
                    Some(commit.clone()),
                    false,
                    "verified and promoted".into(),
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
                    detail,
                ));
                return source_hard_red(attempts);
            }
        }
    }
    source_failure(attempts, "all-candidates-unavailable")
}

struct SourceStagingGuard(PathBuf);
impl Drop for SourceStagingGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scoped_request(plan: &SourcePlan, candidate: &SourceCandidate, path: PathBuf) -> Request {
    let mut request = Request::new(
        Some(candidate.locator.clone()),
        path,
        plan.reference.clone(),
        "origin".into(),
    )
    .with_bearer(plan.bearer.clone());
    // No selector means no SSH key and no HTTPS helper, even after a private attempt.
    if let Some(selector) = candidate.credential_selector.as_deref() {
        if let Some(scope) = plan.credentials.get(selector) {
            request = request
                .with_ssh_key_path(scope.ssh_key_path.clone())
                .with_https_credentials(scope.https_host.clone(), scope.https_token_path.clone());
        }
    }
    request
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

fn source_attempt(
    index: usize,
    candidate: &SourceCandidate,
    disposition: &str,
    resolved_commit: Option<String>,
    external_freshness: bool,
    detail: String,
) -> SourceAttemptReceipt {
    SourceAttemptReceipt {
        index,
        kind: candidate.kind,
        locator: candidate.locator.clone(),
        credential_selector: candidate.credential_selector.clone(),
        disposition: disposition.into(),
        resolved_commit,
        external_freshness,
        detail,
    }
}
fn source_failure(attempts: Vec<SourceAttemptReceipt>, detail: &str) -> SourceOutcome {
    SourceOutcome {
        ok: false,
        changed: false,
        receipt: SourceReceipt {
            attempts,
            served_index: None,
            resolved_commit: None,
            promotion: detail.into(),
        },
    }
}
fn source_hard_red(attempts: Vec<SourceAttemptReceipt>) -> SourceOutcome {
    SourceOutcome {
        ok: false,
        changed: false,
        receipt: SourceReceipt {
            attempts,
            served_index: None,
            resolved_commit: None,
            promotion: "hard-red; destination-preserved; no-next-candidate".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_accepts_missing_repo_as_future_clone() {
        let request = Request::new(
            Some("https://github.com/homeserversltd/keyman.git".into()),
            PathBuf::from("/opt/keyman/source"),
            "main".into(),
            "origin".into(),
        );
        let outcome = plan(&request);
        assert!(outcome.ok);
        assert!(!outcome.changed);
        assert!(outcome.command.stdout.contains("planned clone/update"));
    }

    #[test]
    fn declared_ssh_key_path_is_absolute_regular_file_and_shell_quoted() {
        let root = std::env::temp_dir().join(format!(
            "harmonia-git-artifact-ssh-key-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let key = root.join("forgejo owner's key");
        fs::write(&key, "not-a-private-key\n").unwrap();
        let env = git_ssh_env(Some(&key)).unwrap();
        let expected = format!(
            "ssh -i '{}' -o IdentitiesOnly=yes",
            key.display().to_string().replace('\'', "'\\''")
        );
        assert_eq!(
            env.get("GIT_SSH_COMMAND").map(String::as_str),
            Some(expected.as_str())
        );
        assert!(git_ssh_env(Some(Path::new("relative-key")))
            .unwrap_err()
            .contains("git-ssh-key-path-not-absolute"));
        assert!(git_ssh_env(Some(&root.join("absent-key")))
            .unwrap_err()
            .contains("git-ssh-key-unavailable"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sync_preserves_existing_non_git_path_before_clone() {
        let root = std::env::temp_dir().join(format!(
            "harmonia-git-artifact-non-git-{}",
            std::process::id()
        ));
        let repo = root.join("repo");
        let target = root.join("source");
        fs::create_dir_all(&repo).unwrap();
        command::capture_with_cwd("/usr/bin/git", &["init", "-b", "main"], repo.to_str());
        command::capture_with_cwd(
            "/usr/bin/git",
            &["config", "user.email", "harmonia@example.invalid"],
            repo.to_str(),
        );
        command::capture_with_cwd(
            "/usr/bin/git",
            &["config", "user.name", "Harmonia Test"],
            repo.to_str(),
        );
        fs::write(repo.join("README.md"), "repo source\n").unwrap();
        command::capture_with_cwd("/usr/bin/git", &["add", "README.md"], repo.to_str());
        command::capture_with_cwd("/usr/bin/git", &["commit", "-m", "seed"], repo.to_str());
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("old-payload"), "preserve me\n").unwrap();

        let request = Request::new(
            Some(repo.display().to_string()),
            target.clone(),
            "main".into(),
            "origin".into(),
        );
        let sync = sync_repo(&request);
        let receipt = sync.command;
        assert!(receipt.ok, "{}", receipt.stderr);
        assert!(sync.changed);
        assert!(target.join(".git").exists());
        assert!(receipt.stdout.contains("non_git_existing_path_preserved="));
        let preserved_exists = fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("non-git-preserved")
            });
        assert!(preserved_exists);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sync_fetches_configured_branch_into_remote_tracking_ref_before_fast_forward() {
        let root = std::env::temp_dir().join(format!(
            "harmonia-git-artifact-remote-main-{}",
            std::process::id()
        ));
        let seed = root.join("seed");
        let remote = root.join("remote.git");
        let target = root.join("target");
        fs::create_dir_all(&seed).unwrap();
        command::capture_with_cwd("/usr/bin/git", &["init", "-b", "main"], seed.to_str());
        for (key, value) in [
            ("user.email", "harmonia@example.invalid"),
            ("user.name", "Harmonia Test"),
        ] {
            command::capture_with_cwd("/usr/bin/git", &["config", key, value], seed.to_str());
        }
        fs::write(seed.join("payload"), "first\n").unwrap();
        command::capture_with_cwd("/usr/bin/git", &["add", "payload"], seed.to_str());
        command::capture_with_cwd("/usr/bin/git", &["commit", "-m", "first"], seed.to_str());
        command::capture(
            "/usr/bin/git",
            &[
                "clone",
                "--bare",
                seed.to_str().unwrap(),
                remote.to_str().unwrap(),
            ],
        );
        command::capture(
            "/usr/bin/git",
            &["clone", remote.to_str().unwrap(), target.to_str().unwrap()],
        );

        fs::write(seed.join("payload"), "second\n").unwrap();
        command::capture_with_cwd("/usr/bin/git", &["commit", "-am", "second"], seed.to_str());
        command::capture_with_cwd(
            "/usr/bin/git",
            &["push", remote.to_str().unwrap(), "main"],
            seed.to_str(),
        );

        let request = Request::new(
            Some(remote.display().to_string()),
            target.clone(),
            "main".into(),
            "origin".into(),
        );
        let sync = sync_repo(&request);
        assert!(sync.command.ok, "{}", sync.command.stderr);
        assert!(sync.changed);
        assert_eq!(
            fs::read_to_string(target.join("payload")).unwrap(),
            "second\n"
        );
        let local_head =
            command::capture_with_cwd("/usr/bin/git", &["rev-parse", "HEAD"], target.to_str());
        let tracking_head = command::capture_with_cwd(
            "/usr/bin/git",
            &["rev-parse", "refs/remotes/origin/main"],
            target.to_str(),
        );
        assert_eq!(local_head.stdout.trim(), tracking_head.stdout.trim());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sync_ignores_cibation_worktrees_but_refuses_other_untracked_paths() {
        let root = std::env::temp_dir().join(format!(
            "harmonia-git-artifact-worktree-guard-{}",
            std::process::id()
        ));
        let seed = root.join("seed");
        let remote = root.join("remote.git");
        let target = root.join("target");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&seed).unwrap();
        command::capture_with_cwd("/usr/bin/git", &["init", "-b", "main"], seed.to_str());
        for (key, value) in [
            ("user.email", "harmonia@example.invalid"),
            ("user.name", "Harmonia Test"),
        ] {
            command::capture_with_cwd("/usr/bin/git", &["config", key, value], seed.to_str());
        }
        fs::write(seed.join("payload"), "first\n").unwrap();
        command::capture_with_cwd("/usr/bin/git", &["add", "payload"], seed.to_str());
        command::capture_with_cwd("/usr/bin/git", &["commit", "-m", "first"], seed.to_str());
        command::capture(
            "/usr/bin/git",
            &[
                "clone",
                "--bare",
                seed.to_str().unwrap(),
                remote.to_str().unwrap(),
            ],
        );
        command::capture(
            "/usr/bin/git",
            &["clone", remote.to_str().unwrap(), target.to_str().unwrap()],
        );

        let request = Request::new(
            Some(remote.display().to_string()),
            target.clone(),
            "main".into(),
            "origin".into(),
        );
        fs::create_dir_all(target.join(".worktrees/live-cibation-worktree")).unwrap();
        fs::write(
            target.join(".worktrees/live-cibation-worktree/marker"),
            "preserve me\n",
        )
        .unwrap();
        let allowed = sync_repo(&request);
        assert!(allowed.command.ok, "{}", allowed.command.stderr);
        assert!(target
            .join(".worktrees/live-cibation-worktree/marker")
            .exists());

        fs::write(target.join("ordinary-untracked"), "must block sync\n").unwrap();
        let refused = sync_repo(&request);
        assert!(!refused.command.ok);
        assert_eq!(refused.command.code, 3);
        assert!(refused.command.stdout.contains("ordinary-untracked"));
        assert!(!refused.command.stdout.contains(".worktrees"));
        assert!(refused
            .command
            .stderr
            .contains("working tree has local modifications"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn command_timeout_kills_sleeping_child() {
        let result =
            command::capture_with_cwd_and_timeout("/usr/bin/sh", &["-c", "sleep 2"], None, 1);
        assert!(!result.ok);
        assert!(result.stderr.contains("command-timeout-after-1s"));
        assert!(result.stderr.contains("/usr/bin/sh -c sleep 2"));
    }
}
