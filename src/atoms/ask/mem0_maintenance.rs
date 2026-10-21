//! Read-only Git, app identity, systemd, process, and bounded health observations.
use crate::tools::mem0_maintenance::{Output, Request};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const HEALTH_LIMIT: usize = 64 * 1024;
const STDERR_LIMIT: usize = 4096;

#[derive(Debug, Clone)]
pub(crate) struct Observation {
    pub(crate) source_head: String,
    pub(crate) source_tree: String,
    pub(crate) recorded_head: Option<String>,
    pub(crate) recorded_tree: Option<String>,
    pub(crate) changed: bool,
    pub(crate) first_missing_signal: Option<String>,
    pub(crate) target_device: Option<u64>,
    pub(crate) target_inode: Option<u64>,
    pub(crate) app_root_device: Option<u64>,
    pub(crate) app_root_inode: Option<u64>,
}

#[derive(Debug, Clone)]
pub(crate) struct PromotionBoundary {
    pub(crate) boot_id: String,
    pub(crate) monotonic_usec: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeWitness {
    pub(crate) ok: bool,
    pub(crate) health: String,
    pub(crate) restart: String,
    pub(crate) runtime_identity: Option<String>,
    pub(crate) identity_evidence: Option<String>,
    pub(crate) main_pid: Option<u32>,
    pub(crate) start_monotonic_usec: Option<String>,
    pub(crate) boot_id: Option<String>,
    pub(crate) cwd_binding: Option<bool>,
    pub(crate) cmdline_binding: Option<bool>,
    pub(crate) first_missing_signal: Option<String>,
}

pub(crate) fn read_request(path: &Path, max_bytes: u64) -> Result<Request, String> {
    let meta = fs::symlink_metadata(path).map_err(|error| format!("mem0-maintenance-request-read-failed: {error}"))?;
    if !meta.file_type().is_file() || meta.file_type().is_symlink() || meta.len() > max_bytes {
        return Err("mem0-maintenance-request-file-not-regular-or-over-limit".into());
    }
    let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)
        .map_err(|error| format!("mem0-maintenance-request-open-failed: {error}"))?;
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(max_bytes + 1).read_to_end(&mut bytes).map_err(|error| format!("mem0-maintenance-request-read-failed: {error}"))?;
    if bytes.len() as u64 > max_bytes { return Err("mem0-maintenance-request-file-over-limit".into()); }
    serde_json::from_slice(&bytes).map_err(|error| format!("mem0-maintenance-request-json-invalid: {error}"))
}

pub(crate) fn observe(request: &Request) -> Result<Observation, String> {
    let lock = lock_app_root(request, false)?;
    let result = observe_unlocked(request);
    drop(lock);
    result
}

pub(crate) fn observe_unlocked(request: &Request) -> Result<Observation, String> {
    let source_root = canonical_directory(&request.source_root, "source-root")?;
    let app_root = canonical_directory(&request.app_root, "app-root")?;
    if source_root.starts_with(&app_root) || app_root.starts_with(&source_root) {
        return Err("mem0-maintenance-source-and-app-roots-must-be-disjoint".into());
    }
    validate_owner(request)?;
    let app_root_metadata = fs::symlink_metadata(&app_root)
        .map_err(|error| format!("mem0-maintenance-app-root-observe-failed: {error}"))?;
    let subtree = request.subtree.to_str().ok_or("mem0-maintenance-subtree-not-utf8")?;
    let source_head = git_text(&source_root, &["rev-parse", "--verify", "HEAD"])?;
    validate_oid(&source_head, "source-head")?;
    let source_tree = resolve_tree(&source_root, &source_head, subtree)?;
    let (recorded_head, recorded_tree) = read_recorded_identity(request, &source_root, subtree)?;
    let target = app_root.join(&request.subtree);
    let target_metadata = match fs::symlink_metadata(&target) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err("mem0-maintenance-target-not-plain-directory".into());
            }
            Some(metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("mem0-maintenance-target-observe-failed: {error}")),
    };
    let changed = target_metadata.is_none() || recorded_tree.as_deref() != Some(source_tree.as_str());
    let first_missing_signal = if target_metadata.is_none() {
        Some("managed-subtree-absent".into())
    } else if recorded_tree.is_none() {
        Some("recorded-source-tree-identity-absent".into())
    } else {
        None
    };
    Ok(Observation {
        source_head,
        source_tree,
        recorded_head,
        recorded_tree,
        changed,
        first_missing_signal,
        target_device: target_metadata.as_ref().map(|metadata| metadata.dev()),
        target_inode: target_metadata.as_ref().map(|metadata| metadata.ino()),
        app_root_device: Some(app_root_metadata.dev()),
        app_root_inode: Some(app_root_metadata.ino()),
    })
}

pub(crate) fn lock_app_root(request: &Request, exclusive: bool) -> Result<File, String> {
    let root = canonical_directory(&request.app_root, "app-root")?;
    let before = fs::symlink_metadata(&root)
        .map_err(|error| format!("mem0-maintenance-app-root-observe-failed: {error}"))?;
    let parent = root.parent().ok_or("mem0-maintenance-app-root-parent-missing")?;
    let parent = canonical_directory(parent, "app-root-parent")?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .map_err(|error| format!("mem0-maintenance-app-root-parent-open-failed: {error}"))?;
    let operation = if exclusive { libc::LOCK_EX } else { libc::LOCK_SH };
    if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
        return Err(format!("mem0-maintenance-app-root-parent-lock-failed: {}", std::io::Error::last_os_error()));
    }
    let after = fs::symlink_metadata(&root)
        .map_err(|error| format!("mem0-maintenance-app-root-after-lock-unavailable: {error}"))?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err("mem0-maintenance-app-root-changed-before-parent-lock".into());
    }
    Ok(file)
}

pub(crate) fn report_home(request: &Request) -> Result<Output, String> {
    let _lock = lock_app_root(request, false)?;
    let observed = observe_unlocked(request)?;
    let expected_head = match (&observed.recorded_head, &observed.recorded_tree) {
        (Some(head), Some(tree)) if tree == &observed.source_tree => {
            match resolve_tree(&canonical_directory(&request.source_root, "source-root")?, head, request.subtree.to_str().ok_or("mem0-maintenance-subtree-not-utf8")?) {
                Ok(recorded_source_tree) if recorded_source_tree == observed.source_tree => head.clone(),
                _ => observed.source_head.clone(),
            }
        }
        _ => observed.source_head.clone(),
    };
    let boundary = match (&request.promotion_boot_id, request.promotion_monotonic_usec) {
        (Some(boot_id), Some(monotonic_usec)) if !boot_id.trim().is_empty() => Some(PromotionBoundary { boot_id: boot_id.clone(), monotonic_usec }),
        _ => None,
    };
    let witness = match boundary.as_ref() {
        Some(boundary) => runtime_witness(request, &expected_head, &observed.source_tree, Some(boundary))?,
        None => RuntimeWitness::missing("promotion-boundary-unavailable", "not-proven"),
    };
    let identity_matches = observed.recorded_tree.as_deref() == Some(observed.source_tree.as_str());
    let missing = if observed.first_missing_signal.as_deref() == Some("managed-subtree-absent") {
        Some("managed-subtree-absent".into())
    } else if boundary.is_none() {
        Some("promotion-boundary-unavailable".into())
    } else {
        observed.first_missing_signal.clone()
            .or_else(|| witness.first_missing_signal.clone())
            .or_else(|| if identity_matches { None } else { Some("installed-source-identity-does-not-match-current-source-tree".into()) })
    };
    let proven = witness.ok && identity_matches && missing.is_none();
    let mut output = Output {
        action: "report-home".into(),
        ok: proven,
        changed: false,
        status: if proven { "proven".into() } else { "unproven".into() },
        owner: request.owner.clone(),
        source_root: request.source_root.display().to_string(),
        subtree: request.subtree.display().to_string(),
        app_root: request.app_root.display().to_string(),
        source_head: Some(observed.source_head),
        source_tree: Some(observed.source_tree),
        recorded_head: observed.recorded_head,
        recorded_tree: observed.recorded_tree,
        diff: if observed.changed { "different".into() } else { "empty".into() },
        predecessor: crate::atoms::r#do::mem0_maintenance::predecessor_path(request).display().to_string(),
        restart: Some(witness.restart),
        health: Some(witness.health),
        runtime_identity: witness.runtime_identity,
        identity_evidence: witness.identity_evidence,
        process_main_pid: witness.main_pid,
        process_start_monotonic_usec: witness.start_monotonic_usec,
        process_boot_id: witness.boot_id,
        process_cwd_binding: witness.cwd_binding,
        process_cmdline_binding: witness.cmdline_binding,
        promotion_boot_id: request.promotion_boot_id.clone(),
        promotion_monotonic_usec: request.promotion_monotonic_usec,
        first_missing_signal: missing,
    };
    if observed.first_missing_signal.as_deref() == Some("managed-subtree-absent") {
        output.ok = false;
        output.status = "unproven".into();
        output.first_missing_signal = Some("managed-subtree-absent".into());
    }
    Ok(output)
}

pub(crate) fn runtime_witness(
    request: &Request,
    expected_head: &str,
    expected_tree: &str,
    boundary: Option<&PromotionBoundary>,
) -> Result<RuntimeWitness, String> {
    let unit = request.unit.as_deref().ok_or("mem0-maintenance-unit-required-for-runtime-readback")?;
    let health_url = request.health_url.as_deref().ok_or("mem0-maintenance-health-url-required-for-runtime-readback")?;
    let pointer = request.identity_json_pointer.as_deref().ok_or("process-source-identity-pointer-not-configured")?;
    let expected = BTreeMap::from([
        ("LoadState".to_owned(), Value::Null),
        ("ActiveState".to_owned(), Value::Null),
        ("MainPID".to_owned(), Value::Null),
        ("ExecMainStartTimestampMonotonic".to_owned(), Value::Null),
    ]);
    let (command, properties) = crate::atoms::ask::change_unit::show_properties(unit, &expected);
    if !command.ok { return Ok(RuntimeWitness::missing("systemd-runtime-properties-unavailable", "unavailable")); }
    if properties.get("LoadState").map(String::as_str) != Some("loaded") {
        return Ok(RuntimeWitness::missing("systemd-unit-not-loaded", "inactive"));
    }
    if properties.get("ActiveState").map(String::as_str) != Some("active") {
        return Ok(RuntimeWitness::missing("systemd-unit-not-active", "inactive"));
    }
    let pid = properties.get("MainPID").and_then(|value| value.parse::<u32>().ok()).filter(|pid| *pid > 0);
    let start = properties.get("ExecMainStartTimestampMonotonic")
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()) && *value != "0").cloned();
    let Some(pid) = pid else { return Ok(RuntimeWitness::missing("systemd-main-pid-missing", "active-without-main-pid")); };
    let Some(start) = start else { return Ok(RuntimeWitness::missing("systemd-process-start-monotonic-missing", "active-without-start-time")); };
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()
        .map(|value| value.trim().to_owned()).filter(|value| !value.is_empty());
    let Some(boot_id) = boot_id else { return Ok(RuntimeWitness::missing("process-boot-identity-unavailable", "active")); };
    let health_deadline = Instant::now() + Duration::from_secs(request.timeout_secs);
    let health = loop {
        let remaining = health_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(RuntimeWitness::missing("health-request-failed-timeout", "health-unavailable"));
        }
        match read_health(health_url, remaining, pointer) {
            Ok(health) => break health,
            Err(signal) if retryable_health_read_error(&signal) => {
                let remaining = health_deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Ok(RuntimeWitness::missing(&signal, "health-unavailable"));
                }
                thread::sleep(Duration::from_millis(200).min(remaining));
                if Instant::now() >= health_deadline {
                    return Ok(RuntimeWitness::missing(&signal, "health-unavailable"));
                }
            }
            Err(signal) => return Ok(RuntimeWitness::missing(&signal, "health-unavailable")),
        }
    };
    let (confirm_command, confirm_properties) = crate::atoms::ask::change_unit::show_properties(unit, &expected);
    let process_stable = confirm_command.ok
        && confirm_properties.get("LoadState").map(String::as_str) == Some("loaded")
        && confirm_properties.get("ActiveState").map(String::as_str) == Some("active")
        && confirm_properties.get("MainPID").and_then(|value| value.parse::<u32>().ok()) == Some(pid)
        && confirm_properties.get("ExecMainStartTimestampMonotonic").map(String::as_str) == Some(start.as_str());
    let cwd = fs::read_link(format!("/proc/{pid}/cwd")).ok();
    let app_root = canonical_directory(&request.app_root, "app-root")?;
    let cwd_binding = cwd.as_ref().is_some_and(|path| path.starts_with(&app_root));
    let root_bytes = app_root.as_os_str().as_bytes();
    let cmdline_binding = read_proc_cmdline(pid).ok()
        .is_some_and(|bytes| cmdline_contains_app_root(&bytes, root_bytes));
    let expected_identity = if health.identity == expected_head {
        Some("process-reported-source-head".to_owned())
    } else if health.identity == expected_tree {
        Some("process-reported-source-tree".to_owned())
    } else { None };
    let mut first_missing_signal = None;
    if !process_stable { first_missing_signal.get_or_insert_with(|| "systemd-process-changed-during-health-read".into()); }
    if !(200..300).contains(&health.status) { first_missing_signal.get_or_insert_with(|| "health-http-status-not-success".into()); }
    if expected_identity.is_none() { first_missing_signal.get_or_insert_with(|| "process-source-identity-does-not-match-promoted-tree".into()); }
    if !cwd_binding && !cmdline_binding { first_missing_signal.get_or_insert_with(|| "process-not-bound-to-declared-app-root".into()); }
    if let Some(boundary) = boundary {
        if boundary.boot_id != boot_id {
            first_missing_signal.get_or_insert_with(|| "process-boot-id-differs-from-promotion-boundary".into());
        } else {
            let start_usec = start.parse::<u64>().ok();
            if !matches!(start_usec, Some(value) if value > boundary.monotonic_usec) {
                first_missing_signal.get_or_insert_with(|| "process-start-not-after-promotion-boundary".into());
            }
        }
    }
    Ok(RuntimeWitness {
        ok: first_missing_signal.is_none(),
        health: format!("http_status={}; semantic_ok=true; active=true", health.status),
        restart: if boundary.is_some() { "post-promotion-systemd-process-readback".into() } else { "systemd-active-process-readback".into() },
        runtime_identity: Some(health.identity),
        identity_evidence: expected_identity,
        main_pid: Some(pid),
        start_monotonic_usec: Some(start),
        boot_id: Some(boot_id),
        cwd_binding: Some(cwd_binding),
        cmdline_binding: Some(cmdline_binding),
        first_missing_signal,
    })
}

impl RuntimeWitness {
    pub(crate) fn missing(signal: &str, health: &str) -> Self {
        Self { ok: false, health: health.into(), restart: "not-proven".into(), runtime_identity: None, identity_evidence: None, main_pid: None, start_monotonic_usec: None, boot_id: None, cwd_binding: None, cmdline_binding: None, first_missing_signal: Some(signal.into()) }
    }
}

struct HealthResult { status: u16, identity: String }
fn retryable_health_read_error(signal: &str) -> bool {
    signal == "health-request-failed" || signal.starts_with("health-request-failed-")
}
fn read_health(url: &str, timeout: Duration, pointer: &str) -> Result<HealthResult, String> {
    let args = vec![
        "--disable".to_owned(), "--silent".to_owned(), "--show-error".to_owned(), "--max-redirs".to_owned(), "0".to_owned(),
        "--noproxy".to_owned(), "*".to_owned(), "--proto".to_owned(), "=http,https".to_owned(), "--max-time".to_owned(), timeout.as_secs_f64().to_string(),
        "--max-filesize".to_owned(), HEALTH_LIMIT.to_string(), "--write-out".to_owned(), "\\n%{http_code}".to_owned(),
        "--".to_owned(), url.to_owned(),
    ];
    let (status, stdout, _) = bounded_command("/usr/bin/curl", &args, timeout, HEALTH_LIMIT + 8, STDERR_LIMIT)
        .map_err(|error| format!("health-request-failed-{error}"))?;
    if !status { return Err("health-request-failed".into()); }
    let marker = stdout.iter().rposition(|byte| *byte == b'\n').ok_or("health-http-status-missing")?;
    let code = std::str::from_utf8(&stdout[marker + 1..]).map_err(|_| "health-http-status-invalid")?.trim().parse::<u16>().map_err(|_| "health-http-status-invalid")?;
    let body = &stdout[..marker];
    if body.len() > HEALTH_LIMIT { return Err("health-response-exceeds-bound".into()); }
    let value: Value = serde_json::from_slice(body).map_err(|_| "health-response-not-json")?;
    if value.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err("health-semantic-ok-not-true".into());
    }
    let identity = value.pointer(pointer).and_then(Value::as_str).filter(|value| !value.is_empty()).ok_or("process-source-identity-unreported")?;
    Ok(HealthResult { status: code, identity: identity.to_owned() })
}

fn bounded_command(program: &str, args: &[String], timeout: Duration, stdout_limit: usize, stderr_limit: usize) -> Result<(bool, Vec<u8>, Vec<u8>), String> {
    let mut child = Command::new(program).args(args).env_clear().env("PATH", "/usr/bin:/bin").stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|error| error.to_string())?;
    let stdout = child.stdout.take().ok_or("child-stdout-unavailable")?;
    let stderr = child.stderr.take().ok_or("child-stderr-unavailable")?;
    let overflow = Arc::new(AtomicBool::new(false));
    let out_overflow = Arc::clone(&overflow);
    let out = thread::spawn(move || bounded_child_read(stdout, stdout_limit, out_overflow));
    let err_overflow = Arc::clone(&overflow);
    let err = thread::spawn(move || bounded_child_read(stderr, stderr_limit, err_overflow));
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        if overflow.load(Ordering::Relaxed) { let _ = child.kill(); break child.wait().ok(); }
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => { timed_out = true; let _ = child.kill(); break child.wait().ok(); }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(_) => break None,
        }
    };
    let stdout = out.join().map_err(|_| "child-stdout-reader-failed")?;
    let stderr = err.join().map_err(|_| "child-stderr-reader-failed")?;
    if timed_out { return Err("timeout".into()); }
    if overflow.load(Ordering::Relaxed) { return Err("output-over-limit".into()); }
    Ok((status.as_ref().is_some_and(std::process::ExitStatus::success), stdout, stderr))
}
fn bounded_child_read<R: Read>(mut reader: R, limit: usize, overflow: Arc<AtomicBool>) -> Vec<u8> {
    let mut output = Vec::with_capacity(limit.min(8192));
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                if output.len().saturating_add(count) > limit { overflow.store(true, Ordering::Relaxed); break; }
                output.extend_from_slice(&chunk[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    output
}

pub(crate) fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    if !path.is_absolute() { return Err(format!("mem0-maintenance-{label}-not-absolute")); }
    let canonical = fs::canonicalize(path).map_err(|error| format!("mem0-maintenance-{label}-unavailable: {error}"))?;
    if canonical != path { return Err(format!("mem0-maintenance-{label}-contains-symlink-or-noncanonical-component")); }
    let metadata = fs::symlink_metadata(&canonical).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() { return Err(format!("mem0-maintenance-{label}-not-plain-directory")); }
    Ok(canonical)
}

pub(crate) fn validate_owner(request: &Request) -> Result<(u32, u32), String> {
    let name = std::ffi::CString::new(request.owner.as_str()).map_err(|_| "mem0-maintenance-owner-invalid")?;
    let (uid, gid) = unsafe {
        let entry = libc::getpwnam(name.as_ptr());
        if entry.is_null() { return Err("mem0-maintenance-owner-unknown".into()); }
        ((*entry).pw_uid, (*entry).pw_gid)
    };
    let effective_uid = unsafe { libc::geteuid() };
    if effective_uid != 0 && effective_uid != uid { return Err("mem0-maintenance-caller-owner-mismatch".into()); }
    Ok((uid, gid))
}

fn read_recorded_identity(request: &Request, source_root: &Path, subtree: &str) -> Result<(Option<String>, Option<String>), String> {
    let head_path = request.app_root.join("SOURCE_HEAD");
    let tree_path = request.app_root.join("SOURCE_TREE");
    let recorded_head = read_optional_identity(&head_path, "source-head")?;
    let explicit_tree = read_optional_identity(&tree_path, "source-tree")?;
    if recorded_head.is_none() && explicit_tree.is_some() { return Err("mem0-maintenance-source-tree-without-source-head".into()); }
    let recorded_tree = match (&recorded_head, &explicit_tree) {
        (_, Some(tree)) => { validate_oid(tree, "recorded-tree")?; Some(tree.clone()) }
        (Some(head), None) => Some(resolve_tree(source_root, head, subtree)?),
        (None, None) => None,
    };
    Ok((recorded_head, recorded_tree))
}

fn read_optional_identity(path: &Path, name: &str) -> Result<Option<String>, String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("mem0-maintenance-{name}-observe-failed: {error}")),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 128 => return Err(format!("mem0-maintenance-{name}-not-small-regular-file")),
        Ok(_) => (),
    }
    let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)
        .map_err(|error| format!("mem0-maintenance-{name}-open-failed: {error}"))?;
    let mut bytes = Vec::new();
    file.take(129).read_to_end(&mut bytes).map_err(|error| error.to_string())?;
    let value = std::str::from_utf8(&bytes).map_err(|_| format!("mem0-maintenance-{name}-not-utf8"))?.trim().to_owned();
    if !valid_oid(&value) { return Err(format!("mem0-maintenance-{name}-invalid")); }
    Ok(Some(value))
}

pub(crate) fn git_text(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = git_output(root, args, 4096)?;
    if !output.0 { return Err(format!("mem0-maintenance-git-command-failed-{}", args.first().copied().unwrap_or("unknown"))); }
    String::from_utf8(output.1).map(|value| value.trim().to_owned()).map_err(|_| "mem0-maintenance-git-output-not-utf8".into())
}
fn git_output(root: &Path, args: &[&str], limit: usize) -> Result<(bool, Vec<u8>), String> {
    let mut command = Command::new("/usr/bin/git");
    command.arg("-C").arg(root).args(args).env_clear().env("PATH", "/usr/bin:/bin")
        .env("GIT_NO_LAZY_FETCH", "1").env("GIT_OPTIONAL_LOCKS", "0").env("GIT_TERMINAL_PROMPT", "0")
        .stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = command.spawn().map_err(|error| format!("mem0-maintenance-git-spawn-failed: {error}"))?;
    let stdout = child.stdout.take().ok_or("git-stdout-unavailable")?;
    let mut reader = BufReader::new(stdout);
    let mut bytes = Vec::with_capacity(limit.min(256));
    reader.take((limit + 1) as u64).read_to_end(&mut bytes).map_err(|error| error.to_string())?;
    if bytes.len() > limit { let _ = child.kill(); let _ = child.wait(); return Err("mem0-maintenance-git-output-over-limit".into()); }
    let status = child.wait().map_err(|error| error.to_string())?;
    Ok((status.success(), bytes))
}
fn resolve_tree(root: &Path, commit: &str, subtree: &str) -> Result<String, String> {
    validate_oid(commit, "recorded-head")?;
    let expression = format!("{commit}:{subtree}");
    let tree = git_text(root, &["rev-parse", "--verify", &expression])?;
    validate_oid(&tree, "tree")?;
    if git_text(root, &["cat-file", "-t", &tree])? != "tree" { return Err("mem0-maintenance-subtree-object-not-tree".into()); }
    Ok(tree)
}
fn validate_oid(value: &str, label: &str) -> Result<(), String> {
    if valid_oid(value) { Ok(()) } else { Err(format!("mem0-maintenance-{label}-invalid-object-id")) }
}
fn valid_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn cmdline_contains_app_root(cmdline: &[u8], root: &[u8]) -> bool {
    if root.is_empty() { return false; }
    cmdline.windows(root.len()).enumerate().any(|(start, window)| {
        if window != root { return false; }
        let end = start + root.len();
        let left = start == 0 || matches!(cmdline[start - 1], 0 | b'=' | b' ');
        let right = end == cmdline.len() || matches!(cmdline[end], 0 | b'/' | b' ');
        left && right
    })
}

fn read_proc_cmdline(pid: u32) -> Result<Vec<u8>, String> {
    let file = File::open(format!("/proc/{pid}/cmdline")).map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    file.take(16 * 1024).read_to_end(&mut bytes).map_err(|error| error.to_string())?;
    Ok(bytes)
}
