use super::command;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub type CommandReceipt = crate::CmdResult;

const DEFAULT_BEARER: &str = "owner";
const ESTATE_FORGEJO_PREFIX: &str = "https://git.home.arpa/";
const ESTATE_FORGEJO_TOKEN_PATH: &str = "/home/owner/.ssh/forgejo-token";

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
    /// Exact declared checkout paths trusted only for this Git child.
    pub safe_directories: Vec<PathBuf>,
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
            safe_directories: Vec::new(),
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

    pub fn with_safe_directory(mut self, path: impl Into<PathBuf>) -> Self {
        self.safe_directories.push(path.into());
        self
    }
}

pub(crate) fn capture_git(request: &Request, args: &[&str], cwd: Option<&str>) -> CommandReceipt {
    let mut env = match git_ssh_env(request.ssh_key_path.as_deref()) {
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
    // Read-only Git probes must not refresh the index or create lock files.
    env.insert("GIT_OPTIONAL_LOCKS".into(), "0".into());
    let estate_single_source = request
        .repo
        .as_deref()
        .is_some_and(|repo| repo.starts_with(ESTATE_FORGEJO_PREFIX));
    let credential_helper = if estate_single_source {
        match estate_forgejo_credential_helper() {
            Ok(helper) => Some(helper),
            Err(stderr) => {
                return CommandReceipt {
                    ok: false,
                    code: -1,
                    stdout: String::new(),
                    stderr,
                };
            }
        }
    } else {
        owner_https_credential_helper(request)
    };
    let mut safe_configs = Vec::with_capacity(request.safe_directories.len());
    for path in &request.safe_directories {
        let path = match path.to_str() {
            Some(path) => path,
            None => {
                return CommandReceipt {
                    ok: false,
                    code: -1,
                    stdout: String::new(),
                    stderr: format!("git-safe-directory-non-utf8 {}", path.display()),
                };
            }
        };
        safe_configs.push(format!("safe.directory={path}"));
    }
    let mut git_args = Vec::with_capacity(args.len() + 4 + safe_configs.len() * 2);
    for config in &safe_configs {
        git_args.extend(["-c", config.as_str()]);
    }
    if let Some(helper) = credential_helper.as_deref() {
        git_args.extend(["-c", "credential.helper="]);
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

pub(crate) fn ls_remote(repo: &str, refspec: &str, insecure_tls: bool) -> CommandReceipt {
    let mut cmd = Command::new("/usr/bin/git");
    if insecure_tls {
        cmd.arg("-c").arg("http.sslVerify=false");
    }
    cmd.arg("ls-remote").arg(repo).arg(refspec);
    match cmd.output() {
        Ok(output) => CommandReceipt {
            ok: output.status.success(),
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        },
        Err(err) => CommandReceipt {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: err.to_string(),
        },
    }
}

fn estate_forgejo_credential_helper() -> Result<String, String> {
    // Validate in the engine so absent/empty owner material enters the existing
    // Git unavailable receipt path before a child is started. The inline helper
    // re-reads the same file at Git's credential query boundary, so the token
    // never enters Git argv, the repository config, or a filesystem helper.
    read_forgejo_token(Path::new(ESTATE_FORGEJO_TOKEN_PATH))?;
    Ok(format!(
        "credential.helper=!f() {{ protocol= host=; while IFS= read -r line && [ -n \"$line\" ]; do case \"$line\" in protocol=*) protocol=${{line#protocol=}} ;; host=*) host=${{line#host=}} ;; esac; done; if [ \"$protocol\" = https ] && [ \"$host\" = git.home.arpa ]; then token=; while IFS= read -r line || [ -n \"$line\" ]; do value=$(printf '%s' \"$line\" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'); case \"$value\" in FORGEJO_TOKEN=*) token=${{value#FORGEJO_TOKEN=}} ;; *=*) ;; *) token=$value ;; esac; [ -n \"$token\" ] && break; done < {}; if [ -n \"$token\" ]; then printf \"username=owner\\npassword=%s\\n\" \"$token\"; fi; fi; }}; f",
        shell_quote(ESTATE_FORGEJO_TOKEN_PATH),
    ))
}

fn read_forgejo_token(path: &Path) -> Result<(), String> {
    let contents = fs::read_to_string(path)
        .map_err(|err| format!("forgejo-token-unavailable {}: {err}", path.display()))?;
    let token = contents.lines().find_map(|line| {
        let value = line.trim();
        if value.is_empty() {
            return None;
        }
        value
            .strip_prefix("FORGEJO_TOKEN=")
            .map(str::trim)
            .or((!value.contains('=')).then_some(value))
            .filter(|token| !token.is_empty())
    });
    token
        .map(|_| ())
        .ok_or_else(|| format!("forgejo-token-empty {}", path.display()))
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

pub(crate) fn is_lower_hex_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) fn parse_declared_remote_head(output: &str, reference: &str) -> Option<String> {
    let mut rows = output.lines().filter_map(|line| {
        let mut fields = line.split_whitespace();
        let sha = fields.next()?;
        let observed_ref = fields.next()?;
        (fields.next().is_none() && observed_ref == reference && is_lower_hex_sha(sha))
            .then(|| sha.to_string())
    });
    let first = rows.next()?;
    rows.next().is_none().then_some(first)
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
    crate::pull_repo::plan(request)
}

pub fn apply(request: &Request, invocation: crate::atoms::r#do::InvocationKey) -> Outcome {
    crate::pull_repo::apply(request, invocation)
}

pub(crate) fn observe_request_current(request: &Request) -> Option<Outcome> {
    crate::atoms::ask::observe_request_current(request)
}

pub(crate) fn legacy_plan(request: &Request) -> Outcome {
    crate::atoms::ask::legacy_plan(request)
}


pub fn stdout_changed(stdout: &str) -> bool {
    stdout.lines().any(|line| line.trim() == "changed=true")
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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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

/// Read-only authority observed before a runtime decides whether a fresh source
/// candidate is needed. This probe never changes the destination or a Git
/// checkout; acquisition remains the sole promotion path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteHeadProbe {
    pub state: String,
    pub candidate_index: Option<usize>,
    pub candidate_kind: Option<SourceCandidateKind>,
    pub locator: Option<String>,
    pub credential_selector: Option<String>,
    pub reference: String,
    pub remote_sha: Option<String>,
    pub command: CommandReceipt,
    /// Failed ordered Git candidates observed before the serving candidate.
    /// The successful candidate remains represented by the primary fields so
    /// callers can distinguish authority from fallthrough evidence.
    pub failed_attempts: Vec<SourceAttemptReceipt>,
}

/// Read the declared source head through ordered candidates exactly as
/// acquisition does. A local checkout observes its immutable commit directly;
/// its credential selector is a declaration for later Git candidates and is not
/// required to read the local checkout. Failed Git transports fall through to
/// the next declared Git candidate.
pub(crate) fn scoped_request(
    plan: &SourcePlan,
    candidate: &SourceCandidate,
    path: PathBuf,
) -> Request {
    let mut request = Request::new(
        Some(candidate.locator.clone()),
        path.clone(),
        plan.reference.clone(),
        "origin".into(),
    )
    .with_bearer(plan.bearer.clone());
    if candidate.kind == SourceCandidateKind::LocalCheckout {
        request = request.with_safe_directory(path);
    }
    if let Some(selector) = candidate.credential_selector.as_deref() {
        if let Some(scope) = plan.credentials.get(selector) {
            request = request
                .with_ssh_key_path(scope.ssh_key_path.clone())
                .with_https_credentials(scope.https_host.clone(), scope.https_token_path.clone());
        }
    }
    request
}

pub(crate) fn source_attempt(
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

pub fn source_head(path: &Path, bearer: &str) -> CommandReceipt {
    crate::atoms::ask::source_head(path, bearer)
}

pub fn probe_declared_remote_head(plan: &SourcePlan) -> RemoteHeadProbe {
    crate::atoms::ask::probe_declared_remote_head(plan)
}

pub(crate) fn observe_source_current(plan: &SourcePlan) -> Option<SourceOutcome> {
    crate::atoms::ask::observe_source_current(plan)
}

pub fn acquire_source(
    plan: &SourcePlan,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> SourceOutcome {
    crate::pull_repo::acquire_source(plan, invocation)
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
        let sync = legacy_apply(&request);
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
        let sync = legacy_apply(&request);
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
        let allowed = legacy_apply(&request);
        assert!(allowed.command.ok, "{}", allowed.command.stderr);
        assert!(target
            .join(".worktrees/live-cibation-worktree/marker")
            .exists());

        fs::write(target.join("ordinary-untracked"), "must block sync\n").unwrap();
        let refused = legacy_apply(&request);
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
    fn local_checkout_projects_external_checkout_into_absent_destination_without_mutating_source() {
        let root = std::env::temp_dir().join(format!(
            "harmonia-git-artifact-local-projection-{}",
            std::process::id()
        ));
        let source = root.join("external-owner-checkout");
        let destination = root.join("declared-destination");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&source).unwrap();
        for args in [
            &["init", "-b", "main"][..],
            &["config", "user.email", "harmonia@example.invalid"],
            &["config", "user.name", "Harmonia Test"],
        ] {
            let receipt = command::capture_with_cwd("/usr/bin/git", args, source.to_str());
            assert!(receipt.ok, "{}", receipt.stderr);
        }
        fs::write(source.join("payload"), "external owner bytes\n").unwrap();
        for args in [&["add", "payload"][..], &["commit", "-m", "seed"]] {
            let receipt = command::capture_with_cwd("/usr/bin/git", args, source.to_str());
            assert!(receipt.ok, "{}", receipt.stderr);
        }
        let source_head = command::capture_with_cwd(
            "/usr/bin/git",
            &["rev-parse", "HEAD^{commit}"],
            source.to_str(),
        );
        let source_status =
            command::capture_with_cwd("/usr/bin/git", &["status", "--porcelain"], source.to_str());
        let plan = SourcePlan {
            candidates: vec![SourceCandidate {
                kind: SourceCandidateKind::LocalCheckout,
                locator: source.display().to_string(),
                credential_selector: None,
            }],
            reference: "main".into(),
            destination: destination.clone(),
            expected_commit: None,
            bearer: DEFAULT_BEARER.into(),
            credentials: BTreeMap::new(),
        };

        let outcome = legacy_acquire_source(&plan);

        assert!(outcome.ok, "{:?}", outcome.receipt);
        assert!(destination.join(".git").exists());
        let destination_head = command::capture_with_cwd(
            "/usr/bin/git",
            &["rev-parse", "HEAD^{commit}"],
            destination.to_str(),
        );
        assert!(destination_head.ok, "{}", destination_head.stderr);
        assert_eq!(destination_head.stdout.trim(), source_head.stdout.trim());
        assert!(outcome
            .receipt
            .promotion
            .contains("external freshness authority"));
        assert_eq!(
            outcome.receipt.attempts[0].disposition,
            "served-external-projected"
        );
        assert!(outcome.receipt.attempts[0].external_freshness);
        let second = legacy_acquire_source(&plan);
        assert!(second.ok, "{:?}", second.receipt);
        assert!(!second.changed);
        assert!(second
            .receipt
            .promotion
            .contains("destination-already-projects-observed-head"));
        fs::write(destination.join("local-change"), "must be preserved\n").unwrap();
        let refused = legacy_acquire_source(&plan);
        assert!(!refused.ok);
        assert!(refused
            .receipt
            .promotion
            .contains("hard-red; destination-preserved"));
        assert!(destination.join("local-change").exists());
        let source_head_final = command::capture_with_cwd(
            "/usr/bin/git",
            &["rev-parse", "HEAD^{commit}"],
            source.to_str(),
        );
        let source_status_final =
            command::capture_with_cwd("/usr/bin/git", &["status", "--porcelain"], source.to_str());
        assert_eq!(source_head_final.stdout, source_head.stdout);
        assert_eq!(source_status_final.stdout, source_status.stdout);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn owner_borne_existing_checkout_source_acquisition_is_command_local_and_quiet() {
        let root = std::env::temp_dir().join(format!(
            "harmonia-git-artifact-owner-borne-source-{}",
            std::process::id()
        ));
        let source = root.join("source");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&source).unwrap();
        for args in [
            &["init", "-b", "main"][..],
            &["config", "user.email", "harmonia@example.invalid"],
            &["config", "user.name", "Harmonia Test"],
        ] {
            let receipt = command::capture_with_cwd("/usr/bin/git", args, source.to_str());
            assert!(receipt.ok, "{}", receipt.stderr);
        }
        fs::write(source.join("payload"), "owner-borne bytes\n").unwrap();
        for args in [&["add", "payload"][..], &["commit", "-m", "seed"]] {
            let receipt = command::capture_with_cwd("/usr/bin/git", args, source.to_str());
            assert!(receipt.ok, "{}", receipt.stderr);
        }
        let plan = SourcePlan {
            candidates: vec![SourceCandidate {
                kind: SourceCandidateKind::LocalCheckout,
                locator: source.display().to_string(),
                credential_selector: None,
            }],
            reference: "main".into(),
            destination: source.clone(),
            expected_commit: None,
            bearer: DEFAULT_BEARER.into(),
            credentials: BTreeMap::new(),
        };

        let outcome = legacy_acquire_source(&plan);

        assert!(outcome.ok, "{:?}", outcome.receipt);
        assert!(!outcome.changed);
        assert_eq!(outcome.receipt.served_index, Some(1));
        assert_eq!(
            outcome.receipt.attempts[0].disposition,
            "served-external-projected"
        );
        let head = source_head(&source, DEFAULT_BEARER);
        assert!(head.ok, "{}", head.stderr);
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
