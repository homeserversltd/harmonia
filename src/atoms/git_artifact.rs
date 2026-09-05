use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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

    pub fn with_safe_directory(mut self, path: impl Into<PathBuf>) -> Self {
        self.safe_directories.push(path.into());
        self
    }
}

pub(crate) struct GitCommandContext {
    pub(crate) env: BTreeMap<String, String>,
    pub(crate) config_args: Vec<String>,
}

pub(crate) fn git_command_context(request: &Request) -> Result<GitCommandContext, String> {
    git_command_context_for_credential_source(
        request,
        Path::new(crate::atoms::forge_credential::ROOT_PLANE_FORGEJO_CREDENTIAL),
        crate::atoms::forge_credential::ESTATE_FORGEJO_HOST,
    )
}

fn git_command_context_for_credential_source(
    request: &Request,
    credential_path: &Path,
    estate_host: &str,
) -> Result<GitCommandContext, String> {
    let mut env = git_ssh_env(request.ssh_key_path.as_deref())?;
    env.insert("GIT_OPTIONAL_LOCKS".into(), "0".into());
    let credential_helper = match request.repo.as_deref() {
        Some(repo) => match crate::atoms::forge_credential::resolve_for_url_at(
            repo,
            credential_path,
            estate_host,
        ) {
            crate::atoms::forge_credential::Outcome::Present { username, token } => {
                env.insert("HARMONIA_FORGEJO_USERNAME".into(), username);
                env.insert("HARMONIA_FORGEJO_TOKEN".into(), token);
                Some(owner_https_credential_helper())
            }
            crate::atoms::forge_credential::Outcome::Absent => None,
            crate::atoms::forge_credential::Outcome::Err(reason) => return Err(reason),
        },
        None => None,
    };
    let mut safe_configs = Vec::with_capacity(request.safe_directories.len());
    for path in &request.safe_directories {
        let path = path
            .to_str()
            .ok_or_else(|| format!("git-safe-directory-non-utf8 {}", path.display()))?;
        safe_configs.push(format!("safe.directory={path}"));
    }
    let mut config_args = Vec::with_capacity(4 + safe_configs.len() * 2);
    for config in &safe_configs {
        config_args.extend(["-c".to_string(), config.clone()]);
    }
    if let Some(helper) = credential_helper.as_deref() {
        config_args.extend(["-c".to_string(), "credential.helper=".to_string()]);
        config_args.extend(["-c".to_string(), helper.to_string()]);
    }
    Ok(GitCommandContext { env, config_args })
}

pub(crate) fn credential_scope(request: &Request) -> String {
    let credential = request
        .repo
        .as_deref()
        .map(crate::atoms::forge_credential::resolve_for_url);
    let credential = match credential {
        Some(crate::atoms::forge_credential::Outcome::Present { .. }) => "present",
        _ => "absent",
    };
    format!("ssh_key_configured={};credential={credential}", request.ssh_key_path.is_some())
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

fn owner_https_credential_helper() -> String {
    let host = crate::atoms::forge_credential::ESTATE_FORGEJO_HOST;
    format!(
        "credential.helper=!f() {{ protocol= host=; while IFS= read -r line && [ -n \"$line\" ]; do case \"$line\" in protocol=*) protocol=${{line#protocol=}} ;; host=*) host=${{line#host=}} ;; esac; done; if [ \"$protocol\" = https ] && [ \"$host\" = {} ]; then printf \"username=%s\\npassword=%s\\n\" \"$HARMONIA_FORGEJO_USERNAME\" \"$HARMONIA_FORGEJO_TOKEN\"; fi; }}; f",
        shell_quote(host),
    )
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

pub fn stdout_changed(stdout: &str) -> bool {
    stdout.lines().any(|line| line.trim() == "changed=true")
}

/// A resolved source plan.  This intentionally contains candidates, not policy
/// certificates or component names: policy selection belongs to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePlan {
    pub candidates: Vec<SourceCandidate>,
    pub reference: String,
    pub source_policy: String,
    pub destination: PathBuf,
    pub expected_commit: Option<String>,
    pub bearer: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCandidate {
    pub kind: SourceCandidateKind,
    pub locator: String,
    /// Opaque plan-local key.  A missing selector is deliberately anonymous.
    pub credential_selector: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceCandidateKind {
    Git,
    LocalCheckout,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    crate::atoms::ask::pull_repo::source_head(path, bearer)
}


#[cfg(test)]
mod forgejo_credential_contract_tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Stdio;

    fn has_credential_helper(context: &GitCommandContext) -> bool {
        context
            .config_args
            .iter()
            .any(|argument| argument.starts_with("credential.helper=!f()"))
    }

    fn run_credential_helper(helper: &str, host: &str) -> String {
        let script = helper
            .strip_prefix("credential.helper=!")
            .expect("generated helper must be a git credential helper config");
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .env("HARMONIA_FORGEJO_USERNAME", "owner")
            .env("HARMONIA_FORGEJO_TOKEN", "test-token")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(child.stdin.as_mut().unwrap(), "protocol=https").unwrap();
        writeln!(child.stdin.as_mut().unwrap(), "host={host}").unwrap();
        writeln!(child.stdin.as_mut().unwrap()).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    }

    #[test]
    fn forgejo_credential_contract_git_context_helper_scope() {
        let credential = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            credential.path(),
            "FORGEJO_TOKEN=test-token\nFORGEJO_USERNAME=owner\n",
        )
        .unwrap();
        let mut permissions = std::fs::metadata(credential.path()).unwrap().permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(credential.path(), permissions).unwrap();

        let present = Request::new(
            Some("https://git.home.arpa/HOMESERVERSLTD/harmonia.git".into()),
            ".".into(),
            "main".into(),
            "origin".into(),
        );
        let context = git_command_context_for_credential_source(
            &present,
            credential.path(),
            "git.home.arpa",
        )
        .unwrap();
        let helper = context
            .config_args
            .iter()
            .find(|argument| argument.starts_with("credential.helper=!f()"))
            .expect("present Forgejo repository must receive generated helper");
        assert!(helper.contains("git.home.arpa"));
        assert!(helper.contains("HARMONIA_FORGEJO_TOKEN"));
        assert!(!helper.contains('/'));
        assert!(!helper.contains("test-token"));
        assert_eq!(
            context.env.get("HARMONIA_FORGEJO_USERNAME"),
            Some(&"owner".to_string())
        );
        assert_eq!(
            context.env.get("HARMONIA_FORGEJO_TOKEN"),
            Some(&"test-token".to_string())
        );
        assert_eq!(
            run_credential_helper(helper, "git.home.arpa"),
            "username=owner\npassword=test-token\n"
        );
        assert_eq!(run_credential_helper(helper, "foreign.example"), "");
        assert!(has_credential_helper(&context));
        println!("trace git credential=present generated_helper=true token=redacted");

        let missing = credential.path().with_extension("missing");
        let missing_request = Request::new(
            Some("https://git.home.arpa/HOMESERVERSLTD/harmonia.git".into()),
            ".".into(),
            "main".into(),
            "origin".into(),
        );
        let missing_context = git_command_context_for_credential_source(
            &missing_request,
            &missing,
            "git.home.arpa",
        )
        .unwrap();
        assert!(!has_credential_helper(&missing_context));
        assert!(!missing_context.env.contains_key("HARMONIA_FORGEJO_USERNAME"));
        assert!(!missing_context.env.contains_key("HARMONIA_FORGEJO_TOKEN"));
        println!("trace git credential=missing generated_helper=false");

        let foreign_request = Request::new(
            Some("https://foreign.example/HOMESERVERSLTD/harmonia.git".into()),
            ".".into(),
            "main".into(),
            "origin".into(),
        );
        let foreign_context = git_command_context_for_credential_source(
            &foreign_request,
            credential.path(),
            "git.home.arpa",
        )
        .unwrap();
        assert!(!has_credential_helper(&foreign_context));
        assert!(!foreign_context.env.contains_key("HARMONIA_FORGEJO_USERNAME"));
        assert!(!foreign_context.env.contains_key("HARMONIA_FORGEJO_TOKEN"));
        println!("trace git credential=foreign generated_helper=false");
    }
}
