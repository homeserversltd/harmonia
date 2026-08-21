use super::command;
use super::comparison::{self, DiffDecision};
use crate::{write_json, CmdResult, OperationOutcome, PackageBackend};
use serde::Serialize;
use std::env;
use std::ffi::CString;
use std::fs;
use std::io::{self, Read, Seek};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const NAME: &str = "package";

pub(crate) const PACKAGE_PIN_SCOPE_LIMITATION: &str =
    "Harmonia's pin excludes names only from Harmonia-owned package transactions; it cannot stop the operator's own hand or a bare pacman/apt command run outside Harmonia (for example, `pacman -Syu`).";

const HARMONIA_PACMAN_PATH_ENV: &str = "HARMONIA_PACMAN_PATH";
const HARMONIA_PACMAN_KEY_PATH_ENV: &str = "HARMONIA_PACMAN_KEY_PATH";
const DEFAULT_PACKAGE_TIMEOUT_SECS: u64 = 1800;
const PACMAN_DATABASE_LOCK_RELATIVE_PATH: &str = "var/lib/pacman/db.lck";

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PackageObservation {
    pub(crate) observed_state: String,
    pub(crate) desired_state: String,
    pub(crate) current: Option<CmdResult>,
}

pub(crate) fn package_receipt_fields(
    observation: &PackageObservation,
    decision: DiffDecision,
    movement: Option<&OperationOutcome>,
    changed: bool,
) -> serde_json::Value {
    serde_json::json!({
        "observed_state": observation.observed_state,
        "desired_state": observation.desired_state,
        "diff_decision": match decision { DiffDecision::Empty => "empty", DiffDecision::Different => "different" },
        "movement": movement.map(|movement| serde_json::json!({
            "ok": movement.ok,
            "changed": movement.changed,
            "skipped": movement.skipped,
            "message": movement.message,
            "command": movement.command,
        })),
        "observed_before": serde_json::Value::Null,
        "act": serde_json::Value::Null,
        "observed_after": serde_json::Value::Null,
        "converged": false,
        "changed": changed,
    })
}

pub(crate) fn pacman_program() -> String {
    env::var(HARMONIA_PACMAN_PATH_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "/usr/bin/pacman".to_string())
}

pub(crate) fn pacman_key_program() -> String {
    env::var(HARMONIA_PACMAN_KEY_PATH_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "/usr/bin/pacman-key".to_string())
}

pub(crate) fn pacman_available(program: &str) -> bool {
    Path::new(program).exists()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PacmanLockDecision {
    lock_present: bool,
    live_holder_found: bool,
    reclaim: bool,
}

fn pacman_lock_decision(lock_present: bool, live_holder_found: bool) -> PacmanLockDecision {
    PacmanLockDecision {
        lock_present,
        live_holder_found,
        reclaim: lock_present && !live_holder_found,
    }
}

fn resolved_pacman_program(program: &str) -> PathBuf {
    fs::canonicalize(program).unwrap_or_else(|_| PathBuf::from(program))
}

fn pacman_database_lock_path(program: &str) -> PathBuf {
    let resolved = resolved_pacman_program(program);
    let root = resolved
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("/"));
    root.join(PACMAN_DATABASE_LOCK_RELATIVE_PATH)
}

fn live_pacman_process_exists(program: &Path) -> bool {
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .chars()
                .all(|character| character.is_ascii_digit())
        })
        .any(|entry| {
            let process = entry.path();
            let executable = fs::read_link(process.join("exe"))
                .ok()
                .and_then(|path| fs::canonicalize(&path).ok().or(Some(path)));
            if executable.as_deref() == Some(program) {
                return true;
            }
            fs::read(process.join("cmdline"))
                .ok()
                .and_then(|cmdline| {
                    cmdline.split(|byte| *byte == 0).next().map(|argument| {
                        PathBuf::from(std::ffi::OsString::from_vec(argument.to_vec()))
                    })
                })
                .and_then(|path| fs::canonicalize(&path).ok().or(Some(path)))
                .as_deref()
                == Some(program)
        })
}

pub(crate) fn reclaim_pacman_database_lock(
    receipt_dir: &Path,
    program: &str,
    apply: bool,
) -> Result<(), String> {
    let resolved_program = resolved_pacman_program(program);
    let lock_path = pacman_database_lock_path(program);
    let lock_present = lock_path.exists();
    let live_holder_found = lock_present && live_pacman_process_exists(&resolved_program);
    let decision = pacman_lock_decision(lock_present, live_holder_found);
    let removal_error = if decision.reclaim && apply {
        fs::remove_file(&lock_path).err()
    } else {
        None
    };
    let reclaimed = decision.reclaim && apply && removal_error.is_none();
    write_json(
        &receipt_dir.join("pacman-database-lock-reclaim.json"),
        &serde_json::json!({
            "schema": "harmonia.pacman_lock_reclaim.v1",
            "name": "pacman-database-lock-reclaim",
            "tool": NAME,
            "pacman_program": resolved_program,
            "lock_path": lock_path,
            "lock_present": decision.lock_present,
            "live_holder_found": decision.live_holder_found,
            "reclaimed": reclaimed,
            "planned_reclamation": decision.reclaim && !apply,
            "apply": apply,
            "first_missing_signal": removal_error.as_ref().map_or("none", |_| "pacman-lock-reclaim-failed"),
        }),
    )?;
    if let Some(error) = removal_error {
        return Err(format!("pacman-lock-reclaim-failed:{error}"));
    }
    Ok(())
}

pub(crate) fn pacman_conflict_signal(result: &CmdResult) -> Option<String> {
    if result.ok {
        return None;
    }
    let combined = format!("{}\n{}", result.stdout, result.stderr);
    if combined.contains("conflicting files") || combined.contains("exists in filesystem") {
        Some("pacman-package-file-conflict".to_string())
    } else {
        None
    }
}

pub(crate) fn pacman_needs_overwrite_retry(result: &CmdResult) -> bool {
    pacman_conflict_signal(result).is_some()
}

pub(crate) fn pacman_base_args(sync: bool) -> Vec<&'static str> {
    if sync {
        vec!["-Syu", "--noconfirm"]
    } else {
        vec!["-S", "--noconfirm", "--needed"]
    }
}

pub(crate) fn capture_overwrite_preimage(
    receipt_dir: &Path,
    paths: &[String],
) -> Result<(), String> {
    let entries = paths.iter().map(|path| {
        let target = Path::new(path);
        let metadata = fs::symlink_metadata(target).ok();
        let (kind, bytes) = match metadata.as_ref() {
            Some(m) if m.is_file() => ("file", fs::read(target).ok()),
            Some(m) if m.is_dir() => ("directory", None),
            Some(_) => ("other", None),
            None => ("missing", None),
        };
        serde_json::json!({"path": path, "exists": metadata.is_some(), "type": kind, "bytes_hex": bytes.as_ref().map(|b| b.iter().map(|v| format!("{:02x}", v)).collect::<String>())})
    }).collect::<Vec<_>>();
    crate::write_json(
        &receipt_dir.join("pacman-overwrite-preimage.json"),
        &serde_json::json!({"schema":"harmonia.pacman_overwrite_preimage.v1", "paths": entries}),
    )
}

pub(crate) fn overwrite_allowed_args<'a>(
    base: &[&'a str],
    paths: &'a [String],
) -> Option<Vec<&'a str>> {
    if paths.is_empty() || paths.iter().any(|path| path == "*") {
        return None;
    }
    let mut args = base.to_vec();
    for path in paths {
        args.push("--overwrite");
        args.push(path.as_str());
    }
    Some(args)
}

pub(crate) fn pacman_stdout_indicates_change(stdout: &str) -> bool {
    let lower = stdout.to_ascii_lowercase();
    lower.contains("upgrading")
        || lower.contains("installing")
        || lower.contains("reinstalling")
        || lower.contains("removing")
}

pub(crate) fn package_tool_for_backend(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    packages: &[String],
    apply: bool,
    backend: PackageBackend,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    package_tool_with_policy_for_backend(
        receipt_dir,
        name,
        action,
        packages,
        apply,
        None,
        &[],
        DEFAULT_PACKAGE_TIMEOUT_SECS,
        backend,
        invocation,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn package_tool_with_policy_for_backend(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    packages: &[String],
    apply: bool,
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
    timeout_secs: u64,
    backend: PackageBackend,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    package_tool_with_policy_for_backend_and_pins(
        receipt_dir,
        name,
        action,
        packages,
        apply,
        conflict_policy,
        conflict_paths,
        timeout_secs,
        backend,
        invocation,
        &std::collections::BTreeMap::new(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn package_tool_with_policy_for_backend_and_pins(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    packages: &[String],
    apply: bool,
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
    timeout_secs: u64,
    backend: PackageBackend,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
    pins: &std::collections::BTreeMap<String, String>,
) -> Result<OperationOutcome, String> {
    if !pins.is_empty() {
        write_pin_witness(receipt_dir, name, pins, backend)?;
        let witness_path = receipt_dir.join(format!("{name}.pin-witness.json"));
        let _witness: serde_json::Value =
            serde_json::from_slice(&fs::read(&witness_path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
    }
    match backend {
        PackageBackend::Pacman if action == "install" => crate::install_package::run_with_ignores(
            receipt_dir,
            name,
            &packages
                .iter()
                .filter(|package| !pins.contains_key(*package))
                .cloned()
                .collect::<Vec<_>>(),
            apply,
            conflict_policy,
            conflict_paths,
            timeout_secs,
            &pacman_program(),
            invocation,
            &pins.keys().cloned().collect::<Vec<_>>(),
        ),
        PackageBackend::Pacman if matches!(action, "check" | "upgrade" | "update") => {
            package_update_tool(
                receipt_dir,
                name,
                action,
                packages,
                apply,
                timeout_secs,
                PackageBackend::Pacman,
                pins,
            )
        }
        PackageBackend::Pacman => package_tool_with_policy(
            receipt_dir,
            name,
            action,
            packages,
            apply,
            conflict_policy,
            conflict_paths,
            timeout_secs,
        ),
        PackageBackend::Apt if matches!(action, "check" | "upgrade" | "update") => {
            package_update_tool(
                receipt_dir,
                name,
                action,
                packages,
                apply,
                timeout_secs,
                PackageBackend::Apt,
                pins,
            )
        }
        PackageBackend::Apt => apt_package_tool(
            receipt_dir,
            name,
            action,
            packages,
            apply,
            timeout_secs,
            pins,
        ),
    }
}

fn apt_program() -> String {
    env::var("HARMONIA_APT_GET_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "/usr/bin/apt-get".to_string())
}

fn apt_package_tool(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    packages: &[String],
    apply: bool,
    timeout_secs: u64,
    pins: &std::collections::BTreeMap<String, String>,
) -> Result<OperationOutcome, String> {
    let program = apt_program();
    let mut observe_args = match action {
        "check" => vec!["-s".to_string(), "upgrade".to_string()],
        "install" => vec!["-s".to_string(), "install".to_string()],
        "upgrade" | "update" => vec!["-s".to_string(), "full-upgrade".to_string()],
        other => return Err(format!("apt-package-action-unsupported-{other}")),
    };
    if action == "install" {
        observe_args.extend(packages.iter().cloned());
    }
    let observation = PackageObservation {
        observed_state: "apt-current-state-observed".to_string(),
        desired_state: format!("apt-{action}-declared"),
        current: Some(run_apt_command(
            receipt_dir,
            name,
            &program,
            observe_args.clone(),
            timeout_secs,
            pins,
        )),
    };
    let run = comparison::execute_with_failure_receipt(
        "package",
        || {
            let current = run_apt_command(
                receipt_dir,
                name,
                &program,
                observe_args.clone(),
                timeout_secs,
                pins,
            );
            Ok(PackageObservation {
                observed_state: "apt-current-state-observed".to_string(),
                desired_state: format!("apt-{action}-declared"),
                current: Some(current),
            })
        },
        |current| {
            if current
                .current
                .as_ref()
                .is_some_and(|result| !result.ok || apt_stdout_indicates_change(&result.stdout))
            {
                DiffDecision::Different
            } else {
                DiffDecision::Empty
            }
        },
        |_authorization, _| {
            let mut args: Vec<String> = match (action, apply) {
                ("check", _) => vec!["-s".into(), "upgrade".into()],
                ("install", true) => vec!["install".into(), "--yes".into(), "--no-remove".into()],
                ("install", false) => vec!["-s".into(), "install".into()],
                ("upgrade" | "update", true) => {
                    vec!["full-upgrade".into(), "--yes".into(), "--no-remove".into()]
                }
                ("upgrade" | "update", false) => vec!["-s".into(), "full-upgrade".into()],
                (other, _) => return Err(format!("apt-package-action-unsupported-{other}")),
            };
            args.extend(packages.iter().cloned());
            let result = run_apt_command(receipt_dir, name, &program, args, timeout_secs, pins);
            Ok(OperationOutcome {
                ok: result.ok,
                changed: apply && result.ok && apt_stdout_indicates_change(&result.stdout),
                skipped: false,
                message: format!("apt package {action}"),
                command: Some(result),
            })
        },
        |before, movement, after| {
            let mut _receipt = package_receipt_fields(
                before,
                DiffDecision::Different,
                Some(movement),
                movement.changed,
            );
            if let Some(fields) = _receipt.as_object_mut() {
                fields.insert(
                    "observed_before".into(),
                    serde_json::to_value(before).map_err(|e| e.to_string())?,
                );
                fields.insert(
                    "act".into(),
                    serde_json::json!({"ok": movement.ok, "changed": movement.changed, "skipped": movement.skipped, "message": movement.message, "command": movement.command}),
                );
                fields.insert(
                    "observed_after".into(),
                    serde_json::to_value(after).map_err(|e| e.to_string())?,
                );
            }
            write_guard_receipts(receipt_dir, name, before, movement, after)
        },
    )?;
    let (decision, movement) = match run {
        comparison::ComparisonRun::Current { decision, .. } => (decision, None),
        comparison::ComparisonRun::Moved {
            decision, movement, ..
        } => (decision, Some(movement)),
    };
    let outcome = movement.clone().unwrap_or(OperationOutcome {
        ok: true,
        changed: false,
        skipped: true,
        message: format!("apt package {action} already current"),
        command: observation.current.clone(),
    });
    let mut comparison =
        package_receipt_fields(&observation, decision, movement.as_ref(), outcome.changed);
    if let Ok(bytes) = fs::read(receipt_dir.join(format!("{name}.pin-witness.json"))) {
        if let Ok(witness) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if let Some(fields) = comparison.as_object_mut() {
                fields.insert("exclusion_set".into(), witness["exclusion_set"].clone());
                fields.insert("pin_witness".into(), witness);
            }
        }
    }
    write_json(
        &receipt_dir.join(format!("{name}.comparison.json")),
        &comparison,
    )?;
    write_package_receipt_with_backend(receipt_dir, name, action, &outcome, PackageBackend::Apt)?;
    Ok(outcome)
}

#[derive(Debug, Clone, Serialize)]
struct PendingPackage {
    name: String,
    current: Option<String>,
    candidate: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
struct UpdateObservation {
    backend: String,
    observed_state: String,
    desired_state: String,
    current: CmdResult,
    probe_ok: bool,
    pending_count: usize,
    pending: Vec<PendingPackage>,
    db_synced_at: Option<String>,
    refresh_command: CmdResult,
    query: CmdResult,
    cleanup_failure: Option<String>,
}
static UPDATE_SANDBOX_COUNTER: AtomicU64 = AtomicU64::new(0);
fn now_rfc3339() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let timestamp = seconds.min(i64::MAX as u64) as libc::time_t;
    let mut utc: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::gmtime_r(&timestamp, &mut utc) }.is_null() {
        return "1970-01-01T00:00:00Z".into();
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        utc.tm_year + 1900,
        utc.tm_mon + 1,
        utc.tm_mday,
        utc.tm_hour,
        utc.tm_min,
        utc.tm_sec
    )
}
fn update_sandbox(r: &Path) -> PathBuf {
    let n = UPDATE_SANDBOX_COUNTER.fetch_add(1, Ordering::Relaxed);
    r.join(format!("package-update-sandbox-{}-{n}", std::process::id()))
}
fn parse_pacman_pending(s: &str) -> Vec<PendingPackage> {
    s.lines()
        .filter_map(|l| {
            let (n, r) = l.split_once(' ')?;
            let (c, v) = r.split_once(" -> ")?;
            Some(PendingPackage {
                name: n.into(),
                current: Some(c.trim().into()),
                candidate: Some(v.trim().into()),
            })
        })
        .collect()
}
fn parse_apt_pending(s: &str) -> Vec<PendingPackage> {
    s.lines()
        .filter_map(|l| {
            let l = l.trim().strip_prefix("Inst ")?;
            let n = l.split_whitespace().next()?.into();
            let c = l
                .split_once('[')
                .and_then(|(_, x)| x.split_once(']').map(|(v, _)| v.trim().into()));
            let v = l
                .split_once('(')
                .and_then(|(_, x)| x.split_whitespace().next().map(Into::into));
            Some(PendingPackage {
                name: n,
                current: c,
                candidate: v,
            })
        })
        .collect()
}
#[derive(Debug, Clone)]
struct LogMark {
    path: PathBuf,
    offset: u64,
}
#[derive(Debug, Clone, Serialize)]
struct UpgradedPackage {
    name: String,
    old: String,
    new: String,
}
fn log_mark(path: impl Into<PathBuf>) -> LogMark {
    let path = path.into();
    let offset = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    LogMark { path, offset }
}
fn read_appended(m: &LogMark) -> Result<String, String> {
    let mut f = match fs::File::open(&m.path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(e) => return Err(e.to_string()),
    };
    f.seek(std::io::SeekFrom::Start(m.offset))
        .map_err(|e| e.to_string())?;
    let mut b = Vec::new();
    f.read_to_end(&mut b).map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&b).into_owned())
}
fn log_tail(xs: &[String]) -> String {
    let mut v = xs.iter().flat_map(|x| x.lines()).collect::<Vec<_>>();
    if v.len() > 20 {
        v.drain(..v.len() - 20);
    }
    v.join(
        "
",
    )
}
fn parse_upgraded(b: PackageBackend, xs: &[String]) -> Vec<UpgradedPackage> {
    let mut o = Vec::new();
    for x in xs {
        for l in x.lines() {
            match b {
                PackageBackend::Pacman => {
                    if let Some(r) = l.split_once("[ALPM] upgraded ").map(|(_, x)| x) {
                        if let Some((n, v)) = r.split_once(" (") {
                            if let Some((old, new)) = v.trim_end_matches(')').split_once(" -> ") {
                                o.push(UpgradedPackage {
                                    name: n.trim().into(),
                                    old: old.trim().into(),
                                    new: new.trim().into(),
                                });
                            }
                        }
                    }
                }
                PackageBackend::Apt => {
                    if let Some(r) = l.trim().strip_prefix("Upgrade: ") {
                        for i in r.split(", ") {
                            if let Some((n, v)) = i.rsplit_once(" (") {
                                if let Some((old, new)) = v.trim_end_matches(')').split_once(", ") {
                                    o.push(UpgradedPackage {
                                        name: n.trim().into(),
                                        old: old.trim().into(),
                                        new: new.trim().into(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    o
}
fn synthetic(s: &str) -> CmdResult {
    CmdResult {
        ok: false,
        code: -1,
        stdout: String::new(),
        stderr: s.into(),
    }
}
fn fallback_upgraded(b: PackageBackend, p: &[PendingPackage], t: u64) -> Vec<UpgradedPackage> {
    if p.is_empty() {
        return Vec::new();
    }
    let names = p.iter().map(|x| x.name.clone()).collect::<Vec<_>>();
    let (prog, args) = match b {
        PackageBackend::Pacman => (
            pacman_program(),
            std::iter::once("-Q".to_string())
                .chain(names.clone())
                .collect::<Vec<_>>(),
        ),
        PackageBackend::Apt => (
            "/usr/bin/dpkg-query".to_string(),
            vec![
                "-W".into(),
                r"-f=${Package}	${Version}
"
                .into(),
            ]
            .into_iter()
            .chain(names.clone())
            .collect(),
        ),
    };
    let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    let r = command::capture_with_timeout(&prog, &refs, t);
    if !r.ok {
        return Vec::new();
    }
    let mut have = std::collections::HashMap::new();
    for l in r.stdout.lines() {
        let mut q = l.split_whitespace();
        if let (Some(n), Some(v)) = (q.next(), q.next()) {
            have.insert(n.to_string(), v.to_string());
        }
    }
    p.iter()
        .filter_map(|x| {
            let old = x.current.as_ref()?;
            let new = have.get(&x.name)?;
            (old != new).then(|| UpgradedPackage {
                name: x.name.clone(),
                old: old.clone(),
                new: new.clone(),
            })
        })
        .collect()
}
fn observe_update(
    r: &Path,
    a: &str,
    t: u64,
    b: PackageBackend,
    pins: &std::collections::BTreeMap<String, String>,
) -> UpdateObservation {
    let bn = b.name().into();
    match b {
        PackageBackend::Pacman => {
            let d = update_sandbox(r);
            let setup = fs::create_dir_all(&d).and_then(|_| {
                if unsafe { libc::geteuid() } == 0 {
                    fs::set_permissions(&d, fs::Permissions::from_mode(0o755))?;
                    let name = CString::new("alpm").map_err(io::Error::other)?;
                    let passwd = unsafe { libc::getpwnam(name.as_ptr()) };
                    if passwd.is_null() {
                        return Err(io::Error::other("pacman sandbox alpm user lookup failed"));
                    }
                    std::os::unix::fs::chown(
                        &d,
                        Some(unsafe { (*passwd).pw_uid } as u32),
                        Some(unsafe { (*passwd).pw_gid } as u32),
                    )?;
                }
                std::os::unix::fs::symlink("/var/lib/pacman/local", d.join("local"))
            });
            let (refresh, q, mut p, ok) = if let Err(e) = setup {
                (
                    synthetic(&format!("pacman sandbox setup failed: {e}")),
                    synthetic("pacman query skipped after sandbox setup failure"),
                    Vec::new(),
                    false,
                )
            } else {
                let db = d.to_string_lossy().into_owned();
                let x = pacman_program();
                let refresh = command::capture_with_timeout(
                    &x,
                    &["-Sy", "--dbpath", &db, "--logfile", "/dev/null"],
                    t,
                );
                if !refresh.ok {
                    (
                        refresh,
                        synthetic("pacman query skipped after refresh failure"),
                        Vec::new(),
                        false,
                    )
                } else {
                    let q = command::capture_with_timeout(&x, &["-Qu", "--dbpath", &db], t);
                    let ok = q.ok || (q.code == 1 && q.stdout.is_empty() && q.stderr.is_empty());
                    let p = if ok {
                        parse_pacman_pending(&q.stdout)
                    } else {
                        Vec::new()
                    };
                    (refresh, q, p, ok)
                }
            };
            let cleanup = fs::remove_dir_all(&d).err().map(|e| e.to_string());
            let probe_ok = ok && cleanup.is_none();
            p.retain(|item| !pins.contains_key(&item.name));
            UpdateObservation {
                backend: bn,
                observed_state: if !probe_ok {
                    "probe-failed".into()
                } else if p.is_empty() {
                    "empty".into()
                } else {
                    "pending".into()
                },
                desired_state: "no-pending-updates".into(),
                current: q.clone(),
                probe_ok,
                pending_count: p.len(),
                pending: p,
                db_synced_at: probe_ok.then(|| now_rfc3339()),
                refresh_command: refresh,
                query: q,
                cleanup_failure: cleanup,
            }
        }
        PackageBackend::Apt => {
            let x = apt_program();
            let refresh =
                command::capture_with_timeout(&x, &["update", "--allow-releaseinfo-change"], t);
            let sim = if a == "check" {
                "upgrade"
            } else {
                "full-upgrade"
            };
            let q = if refresh.ok {
                run_apt_command(r, a, &x, vec!["-s".into(), sim.into()], t, pins)
            } else {
                synthetic("apt query skipped after refresh failure")
            };
            let ok = refresh.ok && q.ok;
            let mut p = if ok {
                parse_apt_pending(&q.stdout)
            } else {
                Vec::new()
            };
            p.retain(|item| !pins.contains_key(&item.name));
            UpdateObservation {
                backend: bn,
                observed_state: if !ok {
                    "probe-failed".into()
                } else if p.is_empty() {
                    "empty".into()
                } else {
                    "pending".into()
                },
                desired_state: "no-pending-updates".into(),
                current: q.clone(),
                probe_ok: ok,
                pending_count: p.len(),
                pending: p,
                db_synced_at: ok.then(|| now_rfc3339()),
                refresh_command: refresh,
                query: q,
                cleanup_failure: None,
            }
        }
    }
}
fn capture_owned_with_timeout(program: &str, args: Vec<String>, timeout: u64) -> CmdResult {
    let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    command::capture_with_timeout(program, &refs, timeout)
}

fn pin_args(
    base: &[&str],
    pins: &std::collections::BTreeMap<String, String>,
    pacman: bool,
) -> Vec<String> {
    let mut args = base.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
    if pacman {
        for name in pins.keys() {
            args.extend(["--ignore".into(), name.clone()]);
        }
    }
    args
}

pub(crate) fn write_pin_witness(
    receipt_dir: &Path,
    name: &str,
    pins: &std::collections::BTreeMap<String, String>,
    backend: PackageBackend,
) -> Result<(), String> {
    let mut witness = Vec::new();
    for (package, expected) in pins {
        let result = match backend {
            PackageBackend::Pacman => command::capture(&pacman_program(), &["-Q", package]),
            PackageBackend::Apt => {
                command::capture("/usr/bin/dpkg-query", &["-W", "-f=${Version}", package])
            }
        };
        let installed = result
            .stdout
            .split_whitespace()
            .nth(if backend == PackageBackend::Pacman {
                1
            } else {
                0
            })
            .map(str::to_string);
        let state = match installed.as_deref() {
            Some(v) if v == expected => "held/green",
            Some(_) => "divergent",
            None => "absent",
        };
        witness.push(serde_json::json!({"name":package,"expected_version":expected,"installed_version":installed,"state":state,"report_home_divergence":state != "held/green"}));
    }
    write_json(
        &receipt_dir.join(format!("{name}.pin-witness.json")),
        &serde_json::json!({"schema":"harmonia.package_pin_witness.v1","exclusion_set":pins.keys().collect::<Vec<_>>(),"witness":witness,"pin_scope_limitation":PACKAGE_PIN_SCOPE_LIMITATION}),
    )
}

fn run_apt_command(
    receipt_dir: &Path,
    name: &str,
    program: &str,
    mut args: Vec<String>,
    timeout_secs: u64,
    pins: &std::collections::BTreeMap<String, String>,
) -> CmdResult {
    let pref = receipt_dir.join(format!(
        ".harmonia-apt-preferences-{name}-{}",
        UPDATE_SANDBOX_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut created = false;
    if !pins.is_empty() {
        let bytes = match apt_preferences_bytes(pins) {
            Ok(bytes) => bytes,
            Err(error) => return synthetic(&format!("apt preferences generation failed: {error}")),
        };
        if let Err(error) = fs::write(&pref, bytes) {
            return synthetic(&format!("apt preferences write failed: {error}"));
        }
        created = true;
        args.splice(
            0..0,
            [
                "-o".into(),
                format!("Dir::Etc::preferences={}", pref.display()),
                "-o".into(),
                "Dir::Etc::preferencesparts=-".into(),
            ],
        );
    }
    let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    let result = command::capture_with_timeout(program, &refs, timeout_secs);
    if created {
        if let Err(error) = fs::remove_file(&pref) {
            return synthetic(&format!(
                "apt preferences cleanup failed: {error}; apt result: ok={} code={}",
                result.ok, result.code
            ));
        }
    }
    result
}

fn apt_preferences_bytes(
    pins: &std::collections::BTreeMap<String, String>,
) -> Result<Vec<u8>, String> {
    let mut out = String::new();
    for (package, _expected) in pins {
        if package.trim().is_empty() {
            return Err("empty package name".to_string());
        }
        let result = command::capture("/usr/bin/dpkg-query", &["-W", "-f=${Version}", package]);
        if result.ok && !result.stdout.trim().is_empty() {
            out.push_str(&format!(
                "Package: {package}\nPin: version {}\nPin-Priority: 1001\n\n",
                result.stdout.trim()
            ));
        }
        out.push_str(&format!("Package: {package}\nPin: *\nPin-Priority: -1\n\n"));
    }
    Ok(out.into_bytes())
}

fn package_update_tool(
    r: &Path,
    n: &str,
    a: &str,
    _pkgs: &[String],
    apply: bool,
    t: u64,
    b: PackageBackend,
    pins: &std::collections::BTreeMap<String, String>,
) -> Result<OperationOutcome, String> {
    let pre = observe_update(r, a, t, b, pins);
    write_pin_witness(r, n, pins, b)?;
    let different = !pre.probe_ok || pre.pending_count > 0;
    let release_info_change_accepted = match b {
        PackageBackend::Apt => apt_release_info_change_accepted(&pre.refresh_command),
        PackageBackend::Pacman => false,
    };
    let mut out = serde_json::json!({"schema":"harmonia.package_tool.v1","name":n,"tool":NAME,"permutation":a,"declared_package_backend":b.name(),"backend":b.name(),"observed_state":if !pre.probe_ok {"probe-failed"} else if pre.pending_count==0 {"empty"} else {"pending"},"desired_state":"no-pending-updates","diff_decision":if different {"different"} else {"empty"},"probe_ok":pre.probe_ok,"pending_count":pre.pending_count,"pending":pre.pending,"db_synced_at":pre.db_synced_at,"refresh_command":pre.refresh_command,"command":pre.query,"upgraded_count":0,"upgraded":[],"backend_log_tail":serde_json::Value::Null,"movement":serde_json::Value::Null,"observed_before":pre,"observed_after":serde_json::Value::Null,"act":serde_json::Value::Null,"converged":false,"changed":false,"skipped":false,"exclusion_set":pins.keys().collect::<Vec<_>>()});
    if let PackageBackend::Apt = b {
        out["release_info_change_accepted"] = serde_json::json!(release_info_change_accepted);
    }
    let (outcome, msg, should_err) = if !pre.probe_ok {
        let m = "package update probe failed".to_string();
        (
            OperationOutcome {
                ok: false,
                changed: false,
                skipped: false,
                message: m.clone(),
                command: Some(pre.query.clone()),
            },
            m,
            false,
        )
    } else if pre.pending_count == 0 || !apply {
        let m = if pre.pending_count == 0 {
            format!(
                "package {a} already current; pending_count=0 db_synced_at={}",
                pre.db_synced_at.as_deref().unwrap_or("unknown")
            )
        } else {
            format!(
                "package {a}: pending updates observed; pending_count={} db_synced_at={}",
                pre.pending_count,
                pre.db_synced_at.as_deref().unwrap_or("unknown")
            )
        };
        (
            OperationOutcome {
                ok: true,
                changed: false,
                skipped: true,
                message: m.clone(),
                command: Some(pre.query.clone()),
            },
            m,
            false,
        )
    } else {
        let pm = log_mark("/var/log/pacman.log");
        let am = [
            log_mark("/var/log/apt/history.log"),
            log_mark("/var/log/apt/term.log"),
        ];
        let (refresh, act) = match b {
            PackageBackend::Pacman => (
                None,
                capture_owned_with_timeout(
                    &pacman_program(),
                    pin_args(["-Syu", "--noconfirm"].as_slice(), pins, true),
                    t,
                ),
            ),
            PackageBackend::Apt => {
                let u = run_apt_command(
                    r,
                    n,
                    &apt_program(),
                    vec!["update".into(), "--allow-releaseinfo-change".into()],
                    t,
                    pins,
                );
                if u.ok {
                    (
                        Some(u),
                        run_apt_command(
                            r,
                            n,
                            &apt_program(),
                            vec!["full-upgrade".into(), "--yes".into(), "--no-remove".into()],
                            t,
                            pins,
                        ),
                    )
                } else {
                    (Some(u.clone()), u)
                }
            }
        };
        let texts = match b {
            PackageBackend::Pacman => vec![read_appended(&pm).unwrap_or_default()],
            PackageBackend::Apt => am
                .iter()
                .map(|m| read_appended(m).unwrap_or_default())
                .collect::<Vec<_>>(),
        };
        let mut upgraded = parse_upgraded(b, &texts);
        if upgraded.is_empty() && act.ok {
            upgraded = fallback_upgraded(b, &pre.pending, t);
        }
        let post = observe_update(r, a, t, b, pins);
        let changed = act.ok && !upgraded.is_empty();
        let converged = act.ok && post.probe_ok && post.pending_count == 0;
        let m = if converged {
            format!("package {a}")
        } else if !act.ok {
            format!("package {a} failed")
        } else {
            "package-act-did-not-converge".to_string()
        };
        out["act_refresh_command"] = serde_json::to_value(&refresh).map_err(|e| e.to_string())?;
        if let PackageBackend::Apt = b {
            out["act_release_info_change_accepted"] = serde_json::json!(refresh
                .as_ref()
                .is_some_and(apt_release_info_change_accepted));
        }
        out["act"] = serde_json::json!({"ok":act.ok,"changed":changed,"skipped":false,"message":format!("package {a}"),"command":act,"act_refresh_command":refresh});
        out["movement"] = out["act"].clone();
        out["observed_after"] = serde_json::to_value(&post).map_err(|e| e.to_string())?;
        out["upgraded_count"] = upgraded.len().into();
        out["upgraded"] = serde_json::to_value(upgraded).map_err(|e| e.to_string())?;
        out["backend_log_tail"] = log_tail(&texts).into();
        out["converged"] = converged.into();
        out["changed"] = changed.into();
        out["skipped"] = false.into();
        (
            OperationOutcome {
                ok: converged,
                changed,
                skipped: false,
                message: m.clone(),
                command: Some(act.clone()),
            },
            m,
            act.ok && !converged,
        )
    };
    out["ok"] = outcome.ok.into();
    out["changed"] = outcome.changed.into();
    out["skipped"] = outcome.skipped.into();
    out["message"] = msg.clone().into();
    out["command"] = serde_json::to_value(outcome.command.clone()).map_err(|e| e.to_string())?;
    write_json(&r.join(format!("{n}.comparison.json")), &out)?;
    write_json(&r.join(format!("{n}.json")), &out)?;
    if should_err {
        return Err("package-act-did-not-converge".into());
    }
    Ok(outcome)
}

fn apt_release_info_change_accepted(result: &CmdResult) -> bool {
    if !result.ok {
        return false;
    }
    let combined = format!("{}\n{}", result.stdout, result.stderr);
    combined.contains(" changed its '") && combined.contains("' value from ")
}

fn apt_stdout_indicates_change(stdout: &str) -> bool {
    let lower = stdout.to_ascii_lowercase();
    lower.contains("the following packages will be") || lower.contains("setting up ")
}

pub(crate) fn non_arch_install(
    receipt_dir: &Path,
    name: &str,
    packages: &[String],
) -> Result<OperationOutcome, String> {
    let outcome = OperationOutcome {
        ok: true,
        changed: false,
        skipped: true,
        message: "non-Arch bootstrap not applicable".into(),
        command: None,
    };
    let observation = PackageObservation {
        observed_state: "package-manager-unavailable".into(),
        desired_state: format!("install-declared:{}", packages.join(",")),
        current: None,
    };
    write_json(
        &receipt_dir.join(format!("{name}.comparison.json")),
        &package_receipt_fields(&observation, DiffDecision::Empty, None, false),
    )?;
    write_package_receipt(receipt_dir, name, "install", &outcome)?;
    Ok(outcome)
}

fn package_differs(action: &str, packages: &[String], observation: &PackageObservation) -> bool {
    let Some(result) = observation.current.as_ref() else {
        return true;
    };
    match action {
        "install" => packages.iter().any(|package| {
            !result
                .stdout
                .lines()
                .any(|line| line.split_whitespace().next() == Some(package))
        }),
        "check" | "upgrade" | "update" => !pacman_update_query_is_empty(result),
        _ => true,
    }
}

fn pacman_update_query_is_empty(result: &crate::CmdResult) -> bool {
    result.stdout.trim().is_empty()
        && (result.code == 0 || (result.code == 1 && result.stderr.trim().is_empty()))
}

pub(crate) fn write_install_package_guard_receipt(
    receipt_dir: &Path,
    name: &str,
    before: &PackageObservation,
    movement: &OperationOutcome,
    after: &PackageObservation,
) -> Result<(), String> {
    write_guard_receipts(receipt_dir, name, before, movement, after)
}

fn write_guard_receipts(
    receipt_dir: &Path,
    name: &str,
    before: &PackageObservation,
    movement: &OperationOutcome,
    after: &PackageObservation,
) -> Result<(), String> {
    let mut comparison = package_receipt_fields(
        before,
        DiffDecision::Different,
        Some(movement),
        movement.changed,
    );
    let fields = comparison
        .as_object_mut()
        .ok_or_else(|| "package-receipt-not-object".to_string())?;
    fields.insert(
        "observed_before".into(),
        serde_json::to_value(before).map_err(|e| e.to_string())?,
    );
    fields.insert("act".into(), serde_json::json!({"ok": movement.ok, "changed": movement.changed, "skipped": movement.skipped, "message": movement.message, "command": movement.command}));
    fields.insert(
        "observed_after".into(),
        serde_json::to_value(after).map_err(|e| e.to_string())?,
    );
    fields.insert("converged".into(), serde_json::json!(false));
    write_json(
        &receipt_dir.join(format!("{name}.comparison.json")),
        &comparison,
    )?;
    let mut standard = serde_json::json!({"schema":"harmonia.package_tool.v1","name":name,"tool":NAME,"ok":false,"changed":movement.changed,"skipped":movement.skipped,"message":movement.message,"command":movement.command});
    if let Some(obj) = standard.as_object_mut() {
        for key in ["observed_before", "act", "observed_after", "converged"] {
            obj.insert(key.into(), comparison[key].clone());
        }
    }
    write_json(&receipt_dir.join(format!("{name}.json")), &standard)
}

pub(crate) fn package_tool(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    packages: &[String],
    apply: bool,
) -> Result<OperationOutcome, String> {
    package_tool_with_policy(
        receipt_dir,
        name,
        action,
        packages,
        apply,
        None,
        &[],
        DEFAULT_PACKAGE_TIMEOUT_SECS,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn package_tool_with_policy(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    packages: &[String],
    apply: bool,
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
    timeout_secs: u64,
) -> Result<OperationOutcome, String> {
    let pacman = pacman_program();
    if !pacman_available(&pacman) {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "non-Arch bootstrap not applicable".to_string(),
            command: None,
        };
        let observation = PackageObservation {
            observed_state: "package-manager-unavailable".into(),
            desired_state: format!("{action}-declared"),
            current: None,
        };
        write_json(
            &receipt_dir.join(format!("{name}.comparison.json")),
            &package_receipt_fields(&observation, DiffDecision::Empty, None, false),
        )?;
        write_package_receipt(receipt_dir, name, action, &outcome)?;
        return Ok(outcome);
    }
    let observe_result = match action {
        "install" => command::capture(&pacman, &["-Q"]),
        _ => command::capture(&pacman, &["-Qu"]),
    };
    let observed_state = if matches!(action, "check" | "upgrade" | "update")
        && pacman_update_query_is_empty(&observe_result)
    {
        String::new()
    } else if observe_result.ok {
        observe_result.stdout.clone()
    } else {
        format!("probe-failed:{}", observe_result.code)
    };
    let desired_state = match action {
        "install" => format!("packages-present:{}", packages.join(",")),
        "check" | "upgrade" | "update" => "no-pending-updates".into(),
        other => format!("{other}-declared"),
    };
    let observation = PackageObservation {
        observed_state,
        desired_state: desired_state.clone(),
        current: Some(observe_result),
    };
    let run = comparison::execute_with_failure_receipt(
        if action == "install" {
            "install-package"
        } else {
            "package"
        },
        || {
            let result = match action {
                "install" => command::capture(&pacman, &["-Q"]),
                _ => command::capture(&pacman, &["-Qu"]),
            };
            let observed_state = if matches!(action, "check" | "upgrade" | "update")
                && pacman_update_query_is_empty(&result)
            {
                String::new()
            } else if result.ok {
                result.stdout.clone()
            } else {
                format!("probe-failed:{}", result.code)
            };
            Ok(PackageObservation {
                observed_state,
                desired_state: desired_state.clone(),
                current: Some(result),
            })
        },
        |current| {
            if package_differs(action, packages, current) {
                DiffDecision::Different
            } else {
                DiffDecision::Empty
            }
        },
        |_authorization, _| {
            let result = match action {
                "upgrade" | "update" if apply => {
                    reclaim_pacman_database_lock(receipt_dir, &pacman, true)?;
                    command::capture_with_timeout(&pacman, &["-Syu", "--noconfirm"], timeout_secs)
                }
                "upgrade" | "update" | "check" => {
                    reclaim_pacman_database_lock(receipt_dir, &pacman, false)?;
                    command::capture(&pacman, &["-Qu"])
                }
                "install" if apply => {
                    crate::atoms::r#do::install_package::pacman_mutate_packages_with_options(
                        receipt_dir,
                        false,
                        packages,
                        conflict_policy,
                        conflict_paths,
                        timeout_secs,
                    )?
                }
                "install" => {
                    reclaim_pacman_database_lock(receipt_dir, &pacman, false)?;
                    command::capture(&pacman, &["-Q"])
                }
                other => return Err(format!("unsupported package action {other}")),
            };
            let ok = match action {
                "check" | "upgrade" | "update" if !apply => result.ok || result.code == 1,
                _ => result.ok,
            };
            Ok(OperationOutcome {
                ok,
                changed: matches!(action, "upgrade" | "update" | "install")
                    && apply
                    && result.ok
                    && pacman_stdout_indicates_change(&result.stdout),
                skipped: false,
                message: format!("package {action}"),
                command: Some(result),
            })
        },
        |before, movement, after| {
            let mut _receipt = package_receipt_fields(
                before,
                DiffDecision::Different,
                Some(movement),
                movement.changed,
            );
            if let Some(fields) = _receipt.as_object_mut() {
                fields.insert(
                    "observed_before".into(),
                    serde_json::to_value(before).map_err(|e| e.to_string())?,
                );
                fields.insert(
                    "act".into(),
                    serde_json::json!({"ok": movement.ok, "changed": movement.changed, "skipped": movement.skipped, "message": movement.message, "command": movement.command}),
                );
                fields.insert(
                    "observed_after".into(),
                    serde_json::to_value(after).map_err(|e| e.to_string())?,
                );
            }
            write_guard_receipts(receipt_dir, name, before, movement, after)
        },
    )?;
    let final_observation = run.observation().clone();
    let (decision, movement) = match run {
        comparison::ComparisonRun::Current { decision, .. } => (decision, None),
        comparison::ComparisonRun::Moved {
            decision, movement, ..
        } => (decision, Some(movement)),
    };
    let outcome = movement.clone().unwrap_or(OperationOutcome {
        ok: true,
        changed: false,
        skipped: true,
        message: format!("package {action} already current"),
        command: observation.current.clone(),
    });
    let mut comparison = package_receipt_fields(
        &final_observation,
        decision,
        movement.as_ref(),
        outcome.changed,
    );
    if let Some(fields) = comparison.as_object_mut() {
        fields.insert(
            "observed_before".into(),
            serde_json::to_value(&observation).map_err(|e| e.to_string())?,
        );
        fields.insert("act".into(), serde_json::json!({"ok": outcome.ok, "changed": outcome.changed, "skipped": outcome.skipped, "message": outcome.message, "command": outcome.command}));
        fields.insert(
            "observed_after".into(),
            serde_json::to_value(&final_observation).map_err(|e| e.to_string())?,
        );
        fields.insert("converged".into(), serde_json::json!(true));
        let witness_path = receipt_dir.join(format!("{name}.pin-witness.json"));
        if let Ok(bytes) = fs::read(witness_path) {
            if let Ok(witness) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                fields.insert("exclusion_set".into(), witness["exclusion_set"].clone());
                fields.insert("pin_witness".into(), witness);
            }
        }
    }
    write_json(
        &receipt_dir.join(format!("{name}.comparison.json")),
        &comparison,
    )?;
    write_package_receipt(receipt_dir, name, action, &outcome)?;
    Ok(outcome)
}

pub(crate) fn keyring_repair_tool(
    receipt_dir: &Path,
    name: &str,
    package_name: &str,
    apply: bool,
    timeout_secs: u64,
    pins: &std::collections::BTreeMap<String, String>,
) -> Result<OperationOutcome, String> {
    let pacman = pacman_program();
    let pacman_key = pacman_key_program();
    let pacman_present = pacman_available(&pacman);
    let pacman_key_present = pacman_available(&pacman_key);
    let current = if pacman_present && pacman_key_present {
        Some(command::capture(&pacman, &["-Q", package_name]))
    } else {
        None
    };
    let observation = PackageObservation {
        observed_state: if pacman_present && pacman_key_present {
            "keyring-tools-and-package-observed".into()
        } else {
            "keyring-tools-unavailable".into()
        },
        desired_state: format!("keyring-repaired:{package_name}"),
        current,
    };
    let run = comparison::execute_with_failure_receipt(
        "package",
        || {
            let current = if pacman_present && pacman_key_present {
                Some(command::capture(&pacman, &["-Q", package_name]))
            } else {
                None
            };
            Ok(PackageObservation {
                observed_state: observation.observed_state.clone(),
                desired_state: observation.desired_state.clone(),
                current,
            })
        },
        |current| {
            if !pacman_present
                || !pacman_key_present
                || current.current.as_ref().is_some_and(|result| !result.ok)
            {
                DiffDecision::Different
            } else {
                DiffDecision::Empty
            }
        },
        |_authorization, _| {
            keyring_repair_action(receipt_dir, name, package_name, apply, timeout_secs, pins)
        },
        |before, movement, after| {
            let mut _receipt = package_receipt_fields(
                before,
                DiffDecision::Different,
                Some(movement),
                movement.changed,
            );
            if let Some(fields) = _receipt.as_object_mut() {
                fields.insert(
                    "observed_before".into(),
                    serde_json::to_value(before).map_err(|e| e.to_string())?,
                );
                fields.insert("act".into(), serde_json::json!({"ok": movement.ok, "changed": movement.changed, "skipped": movement.skipped, "message": movement.message, "command": movement.command}));
                fields.insert(
                    "observed_after".into(),
                    serde_json::to_value(after).map_err(|e| e.to_string())?,
                );
            }
            write_guard_receipts(receipt_dir, name, before, movement, after)
        },
    )?;
    let (decision, movement) = match run {
        comparison::ComparisonRun::Current { decision, .. } => (decision, None),
        comparison::ComparisonRun::Moved {
            decision, movement, ..
        } => (decision, Some(movement)),
    };
    let outcome = movement.clone().unwrap_or(OperationOutcome {
        ok: true,
        changed: false,
        skipped: true,
        message: "package keyring-repair already current".into(),
        command: observation.current.clone(),
    });
    write_json(
        &receipt_dir.join(format!("{name}.comparison.json")),
        &package_receipt_fields(&observation, decision, movement.as_ref(), outcome.changed),
    )?;
    write_keyring_receipt(
        receipt_dir,
        name,
        package_name,
        apply,
        pacman_present,
        pacman_key_present,
        0,
        &outcome,
    )?;
    Ok(outcome)
}

fn keyring_repair_action(
    receipt_dir: &Path,
    name: &str,
    package_name: &str,
    apply: bool,
    timeout_secs: u64,
    pins: &std::collections::BTreeMap<String, String>,
) -> Result<OperationOutcome, String> {
    let pacman = pacman_program();
    let pacman_key = pacman_key_program();
    let pacman_present = pacman_available(&pacman);
    let pacman_key_present = pacman_available(&pacman_key);
    if !pacman_present || !pacman_key_present {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "non-Arch bootstrap not applicable".to_string(),
            command: None,
        };
        write_keyring_receipt(
            receipt_dir,
            name,
            package_name,
            apply,
            pacman_present,
            pacman_key_present,
            0,
            &outcome,
        )?;
        return Ok(outcome);
    }
    if !apply {
        reclaim_pacman_database_lock(receipt_dir, &pacman, false)?;
    }
    let mut commands = Vec::new();
    commands.push((
        "pacman-key-version",
        command::capture(&pacman_key, &["--version"]),
    ));
    commands.push((
        "archlinux-keyring-query",
        command::capture(&pacman, &["-Q", package_name]),
    ));
    if apply {
        commands.push((
            "pacman-key-init",
            command::capture_with_timeout(&pacman_key, &["--init"], timeout_secs),
        ));
        commands.push((
            "pacman-key-populate",
            command::capture_with_timeout(&pacman_key, &["--populate", "archlinux"], timeout_secs),
        ));
        commands.push((
            "archlinux-keyring-refresh",
            crate::atoms::r#do::install_package::pacman_mutate_packages_with_ignores(
                receipt_dir,
                false,
                &[package_name.to_string()],
                &pins.keys().cloned().collect::<Vec<_>>(),
                None,
                &[],
                timeout_secs,
            )?,
        ));
        commands.push((
            "pacman-key-updatedb",
            command::capture_with_timeout(&pacman_key, &["--updatedb"], timeout_secs),
        ));
    }
    for (command_name, result) in &commands {
        crate::write_command_receipt(receipt_dir, command_name, result)?;
    }
    let ok = commands.iter().all(|(command_name, result)| {
        result.ok || (!apply && *command_name == "archlinux-keyring-query")
    });
    let changed = apply && ok;
    let first_failure = commands.iter().position(|(_, result)| !result.ok);
    let command = first_failure
        .map(|index| commands[index].1.clone())
        .or_else(|| commands.last().map(|(_, result)| result.clone()));
    let outcome = OperationOutcome {
        ok,
        changed,
        skipped: false,
        message: "package keyring-repair".to_string(),
        command,
    };
    write_keyring_receipt(
        receipt_dir,
        name,
        package_name,
        apply,
        pacman_present,
        pacman_key_present,
        commands.len(),
        &outcome,
    )?;
    Ok(outcome)
}

pub(crate) fn write_package_receipt(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    outcome: &OperationOutcome,
) -> Result<(), String> {
    write_package_receipt_with_backend(receipt_dir, name, action, outcome, PackageBackend::Pacman)
}

fn write_package_receipt_with_backend(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    outcome: &OperationOutcome,
    backend: PackageBackend,
) -> Result<(), String> {
    let comparison = fs::read(receipt_dir.join(format!("{name}.comparison.json")))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    let mut receipt = serde_json::json!({
        "schema": "harmonia.package_tool.v1",
        "name": name,
        "tool": NAME,
        "permutation": action,
        "declared_package_backend": backend.name(),
        "ok": outcome.ok,
        "changed": outcome.changed,
        "skipped": outcome.skipped,
        "message": outcome.message,
        "command": outcome.command,
    });
    if let Some(comparison) = comparison {
        for field in [
            "observed_state",
            "desired_state",
            "diff_decision",
            "movement",
            "observed_before",
            "act",
            "observed_after",
            "converged",
            "backend",
            "probe_ok",
            "pending_count",
            "pending",
            "db_synced_at",
            "refresh_command",
            "upgraded_count",
            "upgraded",
            "backend_log_tail",
            "act_refresh_command",
            "release_info_change_accepted",
            "act_release_info_change_accepted",
            "exclusion_set",
            "pin_witness",
        ] {
            if let Some(value) = comparison.get(field) {
                receipt[field] = value.clone();
            }
        }
    }
    write_json(&receipt_dir.join(format!("{}.json", name)), &receipt)
}

fn write_keyring_receipt(
    receipt_dir: &Path,
    name: &str,
    package_name: &str,
    apply: bool,
    pacman_present: bool,
    pacman_key_present: bool,
    operation_count: usize,
    outcome: &OperationOutcome,
) -> Result<(), String> {
    let comparison = fs::read(receipt_dir.join(format!("{name}.comparison.json")))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    let mut receipt = serde_json::json!({
        "schema": "harmonia.package_keyring_repair.v1",
        "name": name,
        "tool": NAME,
        "permutation": "keyring-repair",
        "ok": outcome.ok,
        "changed": outcome.changed,
        "skipped": outcome.skipped,
        "apply": apply,
        "package": package_name,
        "pacman_present": pacman_present,
        "pacman_key_present": pacman_key_present,
        "operation_count": operation_count,
        "first_missing_signal": if outcome.ok || outcome.skipped { "none" } else if !pacman_present || !pacman_key_present { "arch-keyring-tools-missing" } else { "package-keyring-repair-failed" },
    });
    if let Some(comparison) = comparison {
        for field in [
            "observed_state",
            "desired_state",
            "diff_decision",
            "movement",
            "observed_before",
            "act",
            "observed_after",
            "converged",
        ] {
            if let Some(value) = comparison.get(field) {
                receipt[field] = value.clone();
            }
        }
    }
    write_json(&receipt_dir.join(format!("{}.json", name)), &receipt)
}

pub(crate) fn slice4_bench(
    root: &Path,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<serde_json::Value, String> {
    let fake = root.join("fake-pacman");
    let log = root.join("pacman.log");
    let receipts = root.join("receipts");
    std::fs::create_dir_all(&receipts).map_err(|e| e.to_string())?;
    std::fs::write(&fake, format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$1\" in -Q) printf 'heldpkg 1.2.3\n'; exit 0;; -Qu) test -f {}.state || echo 'pendingpkg 1 -> 2'; exit 0;; -Syu) echo Upgrading slice4; touch {}.state; exit 0;; esac\nexit 0\n", log.display(), log.display(), log.display())).map_err(|e| e.to_string())?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    let old = std::env::var_os("HARMONIA_PACMAN_PATH");
    std::env::set_var("HARMONIA_PACMAN_PATH", &fake);
    let result = package_tool_with_policy_for_backend(
        &receipts,
        "bench",
        "upgrade",
        &[],
        true,
        None,
        &[],
        2,
        crate::PackageBackend::Pacman,
        invocation,
    );
    match old {
        Some(ref v) => std::env::set_var("HARMONIA_PACMAN_PATH", v),
        None => std::env::remove_var("HARMONIA_PACMAN_PATH"),
    };
    let out = result?;
    let mut validation_cases = Vec::new();
    for (label, name, version, expected_ok) in [
        ("empty-name", "", "1", false),
        ("unsafe-name", "bad name", "1", false),
        ("empty-version", "safe-name", "", false),
        ("shell-metachar-version", "safe-name", "1; rm", false),
        ("valid-pin", "safe-name", "1.2.3-1", true),
    ] {
        let mut pins = std::collections::BTreeMap::new();
        pins.insert(name.into(), version.into());
        let actual_ok = crate::ladder::validate_package_pins(&pins).is_ok();
        validation_cases
            .push(serde_json::json!({"case": label, "ok": actual_ok, "expected_ok": expected_ok}));
    }
    let fixture_root = root.join("pin-profile");
    let pins_dir = fixture_root.join("modules/pins");
    let other_dir = fixture_root.join("modules/other");
    let refusal_dir = fixture_root.join("modules/refusal");
    std::fs::create_dir_all(&pins_dir).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&other_dir).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&refusal_dir).map_err(|e| e.to_string())?;
    let pin_manifest = serde_json::json!({"schema": crate::ladder::SCHEMA, "id": "pins", "version": "1", "constants": {}, "package_pins": {"heldpkg": "1.2.3"}, "ladder": []});
    let other_manifest = serde_json::json!({"schema": crate::ladder::SCHEMA, "id": "other", "version": "1", "constants": {}, "ladder": []});
    let refusal_manifest = serde_json::json!({"schema": crate::ladder::SCHEMA, "id": "refusal", "version": "1", "constants": {}, "package_pins": {"heldpkg": "1.2.3"}, "ladder": []});
    for (dir, manifest) in [
        (pins_dir, pin_manifest),
        (other_dir, other_manifest),
        (refusal_dir, refusal_manifest),
    ] {
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec(&manifest).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    }
    let profile = crate::Profile {
        id: "pin-fixture".into(),
        identity: "pin-fixture".into(),
        package_authority: Some(crate::PackageAuthority {
            os_family: "arch".into(),
            package_manager: "pacman".into(),
        }),
        modules: vec!["pins".into(), "other".into()],
        hotfixes: Vec::new(),
        syzygy_declaration: None,
    };
    let projection = crate::bands::stage_profile::projection::load_profile_projection(
        &profile,
        &fixture_root.join("modules"),
        &std::collections::BTreeSet::new(),
    )?;
    let expected_pins =
        std::collections::BTreeMap::from([("heldpkg".to_string(), "1.2.3".to_string())]);
    let projected_pins = match projection.modules.get("pins").map(|module| &module.loaded) {
        Some(crate::LoadedModule::Ladder(manifest)) => manifest.package_pins.clone(),
        _ => return Err("pins-fixture-not-projected-ladder".into()),
    };
    let ordinary_projected_pins = match projection.modules.get("other").map(|module| &module.loaded)
    {
        Some(crate::LoadedModule::Ladder(manifest)) => manifest.package_pins.clone(),
        _ => return Err("ordinary-fixture-not-projected-ladder".into()),
    };
    let projection_propagation =
        projected_pins == expected_pins && ordinary_projected_pins == expected_pins;
    let refusal_result = crate::bands::stage_profile::groups::load_profile_module(
        &fixture_root.join("modules"),
        "refusal",
    );
    let non_pins_refusal = match refusal_result {
        Err(error) => error == "pin-declared-outside-pins-module",
        Ok(_) => false,
    };
    std::env::set_var("HARMONIA_PACMAN_PATH", &fake);
    let fixture_result = package_tool_with_policy_for_backend_and_pins(
        &receipts,
        "fixture",
        "upgrade",
        &[],
        true,
        None,
        &[],
        2,
        PackageBackend::Pacman,
        invocation,
        &ordinary_projected_pins,
    );
    match old {
        Some(ref v) => std::env::set_var("HARMONIA_PACMAN_PATH", v),
        None => std::env::remove_var("HARMONIA_PACMAN_PATH"),
    };
    let fixture_out = fixture_result?;
    let fixture_receipt: serde_json::Value = serde_json::from_slice(
        &std::fs::read(receipts.join("fixture.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let fixture_witness: serde_json::Value = serde_json::from_slice(
        &std::fs::read(receipts.join("fixture.pin-witness.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let transaction_exclusion = fixture_out.ok
        && fixture_receipt["exclusion_set"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "heldpkg"));
    let witness = fixture_witness["witness"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item["name"] == "heldpkg" && item["state"] == "held/green")
    });
    let text = std::fs::read_to_string(&log).map_err(|e| e.to_string())?;
    let argv = text.lines().map(str::to_string).collect::<Vec<_>>();
    let exact = argv.iter().any(|line| line == "-Syu --noconfirm");
    let typed_receipt = receipts.join("bench.json").is_file();
    let mut proof_pins = std::collections::BTreeMap::new();
    proof_pins.insert("heldpkg".to_string(), "1.2.3".to_string());
    let exact_root = root.join("exact-pin-proof");
    std::fs::create_dir_all(&exact_root).map_err(|e| e.to_string())?;
    let exact_action = exact_root.join("actions");
    let exact_fake = exact_root.join("pacman");
    std::fs::write(
        &exact_fake,
        format!(
            "#!/bin/sh\ncase \"$1\" in -Q) printf 'heldpkg 1.2.3\\n';; -Qu) exit 0;; -Syu) touch '{}';; esac\n",
            exact_action.display()
        ),
    )
    .map_err(|e| e.to_string())?;
    std::fs::set_permissions(
        &exact_fake,
        std::fs::Permissions::from_mode(0o755),
    )
    .map_err(|e| e.to_string())?;
    std::env::set_var("HARMONIA_PACMAN_PATH", &exact_fake);
    let exact_result = package_tool_with_policy_for_backend_and_pins(
        &exact_root,
        "exact",
        "upgrade",
        &[],
        false,
        None,
        &[],
        2,
        PackageBackend::Pacman,
        invocation,
        &proof_pins,
    )?;
    let exact_witness: serde_json::Value = serde_json::from_slice(
        &std::fs::read(exact_root.join("exact.pin-witness.json"))
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let exact_pin_no_actuation = exact_result.ok
        && exact_witness["witness"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item["name"] == "heldpkg" && item["state"] == "held/green"
            })
        })
        && exact_witness["exclusion_set"] == serde_json::json!(["heldpkg"])
        && !exact_action.exists();
    match old {
        Some(ref v) => std::env::set_var("HARMONIA_PACMAN_PATH", v),
        None => std::env::remove_var("HARMONIA_PACMAN_PATH"),
    };
    let apt_root = root.join("apt-proof");
    std::fs::create_dir_all(&apt_root).map_err(|e| e.to_string())?;
    let apt_log = apt_root.join("argv");
    let apt_fake = apt_root.join("apt-get");
    std::fs::write(
        &apt_fake,
        format!(
            "#!/bin/sh\nprintf '%s\n' \"$*\" >> '{}'\nexit 0\n",
            apt_log.display()
        ),
    )
    .map_err(|e| e.to_string())?;
    std::fs::set_permissions(&apt_fake, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    let apt_result = run_apt_command(
        &apt_root,
        "apt",
        &apt_fake.to_string_lossy(),
        vec!["full-upgrade".into(), "--yes".into(), "--no-remove".into()],
        2,
        &proof_pins,
    );
    let apt_argv = std::fs::read_to_string(&apt_log).unwrap_or_default();
    let apt_preferences_argv = apt_argv.contains("Dir::Etc::preferences=")
        && apt_argv.contains("Dir::Etc::preferencesparts=-");
    let apt_no_remove = apt_argv.contains("--no-remove");
    let apt_guard_removed = !std::fs::read_dir(&apt_root)
        .map(|entries| {
            entries.flatten().any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains(".harmonia-apt-preferences")
            })
        })
        .unwrap_or(false);
    let apt_success_proof =
        apt_result.ok && apt_preferences_argv && apt_no_remove && apt_guard_removed;

    let write_root = root.join("apt-write-failure");
    std::fs::write(&write_root, b"file").map_err(|e| e.to_string())?;
    let invoked = root.join("apt-invoked");
    let write_fake = root.join("apt-write-failure-bin");
    std::fs::write(
        &write_fake,
        format!("#!/bin/sh\ntouch '{}'\n", invoked.display()),
    )
    .map_err(|e| e.to_string())?;
    std::fs::set_permissions(&write_fake, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    let write_result = run_apt_command(
        &write_root,
        "apt",
        &write_fake.to_string_lossy(),
        vec!["full-upgrade".into()],
        2,
        &proof_pins,
    );
    let apt_guard_write_failure_fail_closed = !write_result.ok
        && write_result.stderr.contains("apt preferences write failed")
        && !invoked.exists();

    let exec_root = root.join("apt-exec-failure");
    std::fs::create_dir_all(&exec_root).map_err(|e| e.to_string())?;
    let exec_fake = exec_root.join("apt-get");
    std::fs::write(&exec_fake, "#!/bin/sh\nexit 17\n").map_err(|e| e.to_string())?;
    std::fs::set_permissions(&exec_fake, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    let exec_result = run_apt_command(
        &exec_root,
        "apt",
        &exec_fake.to_string_lossy(),
        vec!["full-upgrade".into()],
        2,
        &proof_pins,
    );
    let apt_failed_execution_cleans_guard = !exec_result.ok
        && !std::fs::read_dir(&exec_root)
            .map(|entries| {
                entries.flatten().any(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .contains(".harmonia-apt-preferences")
                })
            })
            .unwrap_or(false);

    let cleanup_root = root.join("apt-cleanup-failure");
    std::fs::create_dir_all(&cleanup_root).map_err(|e| e.to_string())?;
    let cleanup_fake = cleanup_root.join("apt-get");
    std::fs::write(
        &cleanup_fake,
        "#!/bin/sh\nfor arg in \"$@\"; do case \"$arg\" in Dir::Etc::preferences=*) rm -f \"${arg#*=}\";; esac; done\nexit 0\n",
    )
    .map_err(|e| e.to_string())?;
    std::fs::set_permissions(&cleanup_fake, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    let cleanup_result = run_apt_command(
        &cleanup_root,
        "apt",
        &cleanup_fake.to_string_lossy(),
        vec!["full-upgrade".into()],
        2,
        &proof_pins,
    );
    let apt_cleanup_failure_non_green =
        !cleanup_result.ok && cleanup_result.stderr.contains("apt preferences cleanup failed");

    let divergent_root = root.join("divergent-proof");
    std::fs::create_dir_all(&divergent_root).map_err(|e| e.to_string())?;
    let divergent_fake = divergent_root.join("pacman");
    let acted = divergent_root.join("acted");
    std::fs::write(
        &divergent_fake,
        format!(
            "#!/bin/sh\ncase \"$1\" in -Q) printf 'heldpkg 9.9.9\n';; -Syu) touch '{}';; esac\n",
            acted.display()
        ),
    )
    .map_err(|e| e.to_string())?;
    std::fs::set_permissions(&divergent_fake, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    std::env::set_var("HARMONIA_PACMAN_PATH", &divergent_fake);
    let divergent = package_tool_with_policy_for_backend_and_pins(
        &divergent_root,
        "divergent",
        "upgrade",
        &[],
        true,
        None,
        &[],
        2,
        PackageBackend::Pacman,
        invocation,
        &proof_pins,
    )?;
    let divergent_witness: serde_json::Value = serde_json::from_slice(
        &std::fs::read(divergent_root.join("divergent.pin-witness.json"))
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let divergent_pin_no_remediation = divergent.ok
        && divergent_witness["witness"].as_array().is_some_and(|items| {
            items.iter().any(|item| item["state"] == "divergent")
        })
        && !acted.exists();
    match old {
        Some(ref v) => std::env::set_var("HARMONIA_PACMAN_PATH", v),
        None => std::env::remove_var("HARMONIA_PACMAN_PATH"),
    };
    Ok(serde_json::json!({
        "production_ok": out.ok,
        "typed_receipt": typed_receipt,
        "upgrade_argv_exact": exact,
        "fake_log_only": !text.is_empty(),
        "pacman_argv": argv,
        "skipped": out.skipped,
        "skip_refusal_truthful": out.ok && !out.skipped,
        "pin_validation_cases": validation_cases,
        "pin_validation_all_cases": validation_cases.iter().all(|case| case["ok"] == case["expected_ok"]),
        "projection_propagation": projection_propagation,
        "transaction_exclusion": transaction_exclusion,
        "witness": witness,
        "non_pins_refusal": non_pins_refusal,
        "exact_pin_no_actuation": exact_pin_no_actuation,
        "apt_preferences_argv": apt_preferences_argv,
        "apt_no_remove": apt_no_remove,
        "apt_guard_removed_after_success": apt_guard_removed,
        "apt_guard_write_failure_fail_closed": apt_guard_write_failure_fail_closed,
        "apt_failed_execution_cleans_guard": apt_failed_execution_cleans_guard,
        "apt_cleanup_failure_non_green": apt_cleanup_failure_non_green,
        "divergent_pin_no_remediation": divergent_pin_no_remediation,
        "ok": out.ok && exact && !out.skipped && typed_receipt
            && validation_cases.iter().all(|case| case["ok"] == case["expected_ok"])
            && projection_propagation
            && transaction_exclusion
            && witness
            && non_pins_refusal
            && exact_pin_no_actuation
            && apt_success_proof
        && apt_guard_write_failure_fail_closed
        && apt_failed_execution_cleans_guard
        && apt_cleanup_failure_non_green
        && divergent_pin_no_remediation,
    }))
}
