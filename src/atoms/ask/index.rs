//! Typed, bounded, non-blocking observation atoms.
#![allow(dead_code)]
#[path = "change_unit.rs"]
pub(crate) mod change_unit;
#[path = "backfill_file.rs"]
pub(crate) mod backfill_file;
#[path = "build_crate.rs"]
pub(crate) mod build_crate;
#[path = "build_venv.rs"]
pub(crate) mod build_venv;
#[path = "check_health.rs"]
pub(crate) mod check_health;
#[path = "install_package.rs"]
pub(crate) mod install_package;
#[path = "build_aur_pinned.rs"]
pub(crate) mod build_aur_pinned;
#[path = "install_aur.rs"]
pub(crate) mod install_aur;
#[path = "install_aur_pinned.rs"]
pub(crate) mod install_aur_pinned;
#[path = "run_command.rs"]
pub(crate) mod run_command;
#[path = "replace_process.rs"]
pub(crate) mod replace_process;
#[path = "set_clock.rs"]
pub(crate) mod set_clock;
use super::{ask_file, CommandObservation, FileObservation, HttpObservation, UnitObservation};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::atoms::git_artifact::{scoped_request, source_attempt};
use crate::atoms::git_artifact::{
    CommandReceipt, RemoteHeadProbe, SourceCandidateKind, SourceOutcome, SourcePlan, SourceReceipt,
};
const OUTPUT_LIMIT: usize = 16 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(12);

pub(crate) fn file(path: &Path) -> Result<FileObservation, String> {
    ask_file(path)
}

pub(crate) fn line_count(path: &Path) -> Result<u64, String> {
    let file = File::open(path).map_err(|error| error.to_string())?;
    Ok(BufReader::new(file).lines().count() as u64)
}

pub(crate) fn text(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|error| format!("ask-text-read {}: {error}", path.display()))
}

pub(crate) fn optional_text(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("ask-text-read {}: {error}", path.display())),
    }
}

pub(crate) fn exists(path: &Path) -> bool {
    std::fs::metadata(path).is_ok()
}

pub(crate) fn directory_entries(path: &Path) -> Result<Vec<std::path::PathBuf>, String> {
    let mut entries = std::fs::read_dir(path)
        .map_err(|e| format!("ask-directory-open: {e}"))?
        .map(|entry| {
            entry
                .map(|e| e.path())
                .map_err(|e| format!("ask-directory-entry: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    Ok(entries)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PathKind {
    RegularFile,
    Symlink,
    Other,
}

pub(crate) fn path_kind(path: &Path) -> Result<Option<PathKind>, String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(Some(PathKind::RegularFile)),
        Ok(metadata) if metadata.file_type().is_symlink() => Ok(Some(PathKind::Symlink)),
        Ok(_) => Ok(Some(PathKind::Other)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

pub(crate) fn link_target(path: &Path) -> Result<std::path::PathBuf, String> {
    std::fs::read_link(path).map_err(|error| error.to_string())
}

#[cfg(unix)]
pub(crate) fn file_mode(path: &Path) -> Result<u32, String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o777)
        .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
pub(crate) fn file_mode(_path: &Path) -> Result<u32, String> {
    Ok(0)
}

pub(crate) fn file_if_present(path: &Path) -> Result<Option<FileObservation>, String> {
    match File::open(path) {
        Ok(_) => ask_file(path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("ask-file-open: {error}")),
    }
}

pub(crate) fn read_only_command(program: &str, args: &[String]) -> CommandObservation {
    read_only_command_with_timeout(program, args, COMMAND_TIMEOUT)
}

pub(crate) fn read_only_command_with_timeout(
    program: &str,
    args: &[String],
    timeout: Duration,
) -> CommandObservation {
    let mut child = match Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return CommandObservation {
                program: program.into(),
                args: args.to_vec(),
                ok: false,
                code: None,
                stdout: String::new(),
                stderr: error.to_string(),
            }
        }
    };
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let out = thread::spawn(move || bounded_read(stdout));
    let err = thread::spawn(move || bounded_read(stderr));
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => {
                timed_out = true;
                let _ = child.kill();
                break child.wait().ok();
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(_) => break None,
        }
    };
    let stdout = out.join().unwrap_or_default();
    let mut stderr = err.join().unwrap_or_default();
    if timed_out {
        stderr = format!("command timed out after {}s; {stderr}", timeout.as_secs());
    }
    CommandObservation {
        program: program.into(),
        args: args.to_vec(),
        ok: status
            .as_ref()
            .is_some_and(std::process::ExitStatus::success),
        code: status.and_then(|s| s.code()),
        stdout,
        stderr,
    }
}

fn bounded_read<R: Read>(mut reader: R) -> String {
    let mut bytes = Vec::with_capacity(OUTPUT_LIMIT.min(4096));
    let mut chunk = [0u8; 4096];
    while bytes.len() < OUTPUT_LIMIT {
        let take = (OUTPUT_LIMIT - bytes.len()).min(chunk.len());
        match reader.read(&mut chunk[..take]) {
            Ok(0) | Err(_) => break,
            Ok(n) => bytes.extend_from_slice(&chunk[..n]),
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

pub(crate) fn unit_state(unit: &str) -> UnitObservation {
    let active = read_only_command("/usr/bin/systemctl", &["is-active".into(), unit.into()]);
    let enabled = read_only_command("/usr/bin/systemctl", &["is-enabled".into(), unit.into()]);
    let show = read_only_command(
        "/usr/bin/systemctl",
        &["show".into(), unit.into(), "-p".into(), "SubState".into()],
    );
    let state = format!(
        "active={:?}; enabled={:?}; show={:?}",
        active.stdout.trim(),
        enabled.stdout.trim(),
        show.stdout.trim()
    );
    UnitObservation {
        unit: unit.into(),
        active: active.ok && active.stdout.trim() == "active",
        enabled: enabled.ok && enabled.stdout.trim() == "enabled",
        state,
        active_query: active,
        enabled_query: enabled,
        show_query: show,
    }
}

pub(crate) fn http_probe(url: &str) -> HttpObservation {
    let result = read_only_command(
        "/usr/bin/curl",
        &[
            "-sS".into(),
            "-o".into(),
            "/dev/null".into(),
            "-w".into(),
            "%{http_code}".into(),
            "--max-time".into(),
            "10".into(),
            url.into(),
        ],
    );
    let status = result.stdout.trim().parse::<u16>().ok().filter(|s| *s != 0);
    HttpObservation {
        url: url.into(),
        reachable: result.ok && status.is_some(),
        status,
    }
}

pub(crate) fn systemd_state_query(
    kind: &str,
    unit: &str,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
) -> CommandObservation {
    let mut args = Vec::new();
    if user {
        args.push("--user".into());
        if let Some(target) = target_user.filter(|v| !v.trim().is_empty()) {
            args.push(format!("--machine={target}@.host"));
        }
    }
    match kind {
        "is-enabled" | "is-active" => args.extend([kind.into(), unit.into()]),
        "load-state" | "unit-file-state" | "needs-reload" => {
            let property = match kind {
                "load-state" => "LoadState",
                "unit-file-state" => "UnitFileState",
                _ => "NeedDaemonReload",
            };
            args.extend([
                "show".into(),
                format!("--property={property}"),
                "--value".into(),
                unit.into(),
            ]);
        }
        _ => {
            return CommandObservation {
                program: "/usr/bin/systemctl".into(),
                args,
                ok: false,
                code: None,
                stdout: String::new(),
                stderr: format!("unsupported systemd state kind {kind}"),
            }
        }
    }
    let result = read_only_command_with_timeout(
        "/usr/bin/systemctl",
        &args,
        Duration::from_secs(timeout_secs),
    );
    result
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

pub(crate) fn observe_source_current(plan: &SourcePlan) -> Option<SourceOutcome> {
    for (offset, candidate) in plan.candidates.iter().enumerate() {
        if candidate.kind != SourceCandidateKind::Git {
            return None;
        }
        if let Some(selector) = candidate.credential_selector.as_deref() {
            if !plan.credentials.contains_key(selector) {
                return None;
            }
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
            .then(|| {
                crate::atoms::git_artifact::parse_declared_remote_head(&remote.stdout, &reference)
            })
            .flatten()?;
        if plan
            .expected_commit
            .as_deref()
            .is_some_and(|expected| remote_commit != expected)
            || destination_commit != remote_commit
        {
            return None;
        }
        let index = offset + 1;
        let commit = remote_commit.clone();
        return Some(SourceOutcome { ok:true, changed:false, receipt: SourceReceipt { attempts: vec![source_attempt(index,candidate,"already-current",Some(commit.clone()),false,"destination-already-projects-observed-head".into())], served_index:Some(index), resolved_commit:Some(commit), promotion:"already-current; destination projects observed remote head; no clone, stage, or promotion".into() } });
    }
    None
}
