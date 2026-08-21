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

pub(crate) fn demo(
    root: &Path,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<serde_json::Value, String> {
    let source = root.join("source");
    let destination = root.join("destination");
    std::fs::create_dir_all(&source).map_err(|e| e.to_string())?;
    for args in [
        &["init", "-b", "main"][..],
        &["config", "user.email", "demo@example.invalid"],
        &["config", "user.name", "Harmonia Demo"],
    ] {
        if !command::capture_with_cwd("/usr/bin/git", args, source.to_str()).ok {
            return Err("git-demo-init-failed".into());
        }
    }
    std::fs::write(source.join("payload"), b"source-bytes\n").map_err(|e| e.to_string())?;
    for args in [&["add", "payload"][..], &["commit", "-m", "seed"]] {
        if !command::capture_with_cwd("/usr/bin/git", args, source.to_str()).ok {
            return Err("git-demo-commit-failed".into());
        }
    }
    let head_before =
        command::capture_with_cwd("/usr/bin/git", &["rev-parse", "HEAD"], source.to_str());
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
    let first = crate::atoms::r#do::pull_repo::acquire_source(&plan);
    let first_changed = first.ok && first.changed;
    let destination_payload = destination.join("payload");
    let exact = destination_payload.is_file()
        && std::fs::read(&destination_payload)
            .map(|bytes| bytes == b"source-bytes\n")
            .unwrap_or(false);
    let second = crate::atoms::r#do::pull_repo::acquire_source(&plan);
    let quiet = second.ok && !second.changed;
    let head_after =
        command::capture_with_cwd("/usr/bin/git", &["rev-parse", "HEAD"], source.to_str());
    let source_unchanged =
        head_before.ok && head_after.ok && head_before.stdout == head_after.stdout;
    Ok(serde_json::json!({
        "source_head_unchanged": source_unchanged,
        "destination_exact": exact,
        "first_movement": first_changed,
        "second_quiet": quiet,
        "production_ok": first.ok && second.ok,
        "first_ok": first.ok,
        "first_changed": first.changed,
        "first_message": format!("{:?}", first.receipt),
        "first_attempts": format!("{:?}", first.receipt.attempts),
        "second_ok": second.ok,
        "second_changed": second.changed,
        "second_message": format!("{:?}", second.receipt),
        "second_attempts": format!("{:?}", second.receipt.attempts),
        "source_head_before": head_before.stdout,
        "source_head_after": head_after.stdout,
        "ok": first_changed && exact && quiet && source_unchanged,
    }))
}
