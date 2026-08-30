use crate::atoms::command;
use crate::atoms::r#do::InvocationKey;
use crate::atoms::CommandObservation;
use crate::atoms::package::{pacman_available, pacman_key_program, pacman_program, pacman_stdout_indicates_change, CeilingCommandEvidence, CeilingEntry, CurrentnessWitness, DeclaredCeiling, IdentityChange, PACKAGE_PIN_SCOPE_LIMITATION};
use crate::atoms::ask::install_package::{package_differs, pacman_observed_state, pacman_update_query_is_empty, PackageObservation};
use crate::atoms::attest::install_package::{package_receipt_fields, write_install_package_guard_receipt, write_keyring_receipt, write_package_receipt, write_package_receipt_with_backend};
use crate::write_json;
use crate::CmdResult;

const NAME: &str = "package";
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

const PACMAN_DATABASE_LOCK_RELATIVE_PATH: &str = "var/lib/pacman/db.lck";

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
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .chars()
                .all(|c| c.is_ascii_digit())
        })
        .any(|e| {
            let p = e.path();
            let exe = fs::read_link(p.join("exe"))
                .ok()
                .and_then(|x| fs::canonicalize(&x).ok().or(Some(x)));
            if exe.as_deref() == Some(program) {
                return true;
            }
            fs::read(p.join("cmdline"))
                .ok()
                .and_then(|b| {
                    b.split(|x| *x == 0)
                        .next()
                        .map(|a| PathBuf::from(std::ffi::OsString::from_vec(a.to_vec())))
                })
                .and_then(|x| fs::canonicalize(&x).ok().or(Some(x)))
                .as_deref()
                == Some(program)
        })
}

pub(crate) fn reclaim_pacman_database_lock(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    receipt_dir: &Path,
    program: &str,
    apply: bool,
) -> Result<(), String> {
    let _capability = (authorization, invocation);
    let resolved_program = resolved_pacman_program(program);
    let lock_path = pacman_database_lock_path(program);
    let lock_present = lock_path.exists();
    let live_holder_found = lock_present && live_pacman_process_exists(&resolved_program);
    let decision = pacman_lock_decision(lock_present, live_holder_found);
    let mut state_changed_before_action = false;
    let mut holder_before_action = false;
    let removal_error = if decision.reclaim && apply {
        let second_present = lock_path.exists();
        let second_holder = second_present && live_pacman_process_exists(&resolved_program);
        state_changed_before_action = second_present != lock_present;
        holder_before_action = second_holder;
        if state_changed_before_action || second_holder {
            None
        } else {
            fs::remove_file(&lock_path).err()
        }
    } else {
        None
    };
    let reclaimed = decision.reclaim && apply && !state_changed_before_action
        && !holder_before_action && removal_error.is_none();
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
            "first_missing_signal": if state_changed_before_action { "pacman-lock-state-changed-before-action" } else if holder_before_action { "pacman-live-holder-appeared" } else { removal_error.as_ref().map_or("none", |_| "pacman-lock-reclaim-failed") },
            "state_changed_before_action": state_changed_before_action,
        }),
    )?;
    if state_changed_before_action {
        return Err("pacman-lock-state-changed-before-action".into());
    }
    if holder_before_action {
        return Err("pacman-live-holder-appeared".into());
    }
    if let Some(error) = removal_error {
        return Err(format!("pacman-lock-reclaim-failed:{error}"));
    }
    Ok(())
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn pacman_mutate_packages_with_options(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    receipt_dir: &Path,
    sync: bool,
    packages: &[String],
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
    timeout_secs: u64,
) -> Result<CmdResult, String> {
    pacman_mutate_packages_with_ignores(
        authorization,
        invocation,
        receipt_dir,
        sync,
        packages,
        &[],
        conflict_policy,
        conflict_paths,
        timeout_secs,
    )
}

pub(crate) fn pacman_mutate_packages_with_ignores(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    receipt_dir: &Path,
    sync: bool,
    packages: &[String],
    ignored: &[String],
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
    timeout_secs: u64,
) -> Result<CmdResult, String> {
    let program = crate::atoms::package::pacman_program();
    reclaim_pacman_database_lock(authorization, invocation, receipt_dir, &program, true)?;
    let mut args = crate::atoms::package::pacman_base_args(sync);
    for package in ignored {
        args.extend(["--ignore", package.as_str()]);
    }
    args.extend(packages.iter().map(String::as_str));
    capture_overwrite_preimage(receipt_dir, conflict_paths)?;
    let result = command::capture_with_timeout(&program, &args, timeout_secs);
    if result.ok || !crate::atoms::package::pacman_needs_overwrite_retry(&result) {
        return Ok(result);
    }
    let Some(policy) = conflict_policy else {
        return Ok(result);
    };
    if policy != "overwrite-declared-paths" {
        return Ok(CmdResult {
            ok: false,
            code: result.code,
            stdout: result.stdout,
            stderr: format!(
                "{}\npacman-package-file-conflict-policy-unsupported:{policy}",
                result.stderr
            )
            .trim()
            .to_string(),
        });
    }
    let mut overwrite_base = crate::atoms::package::pacman_base_args(sync);
    for package in ignored {
        overwrite_base.extend(["--ignore", package.as_str()]);
    }
    let Some(mut overwrite_args) =
        crate::atoms::package::overwrite_allowed_args(&overwrite_base, conflict_paths)
    else {
        return Ok(CmdResult {
            ok: false,
            code: result.code,
            stdout: result.stdout,
            stderr: format!(
                "{}\npacman-package-file-conflict-overwrite-paths-missing-or-wildcard",
                result.stderr
            )
            .trim()
            .to_string(),
        });
    };
    overwrite_args.extend(packages.iter().map(String::as_str));
    let second = command::capture_with_timeout(&program, &overwrite_args, timeout_secs);
    crate::write_json(
        &receipt_dir.join("pacman-package-transaction.json"),
        &serde_json::json!({"schema":"harmonia.pacman_package_transaction.v1", "first_ok": result.ok, "second_ok": second.ok, "overwrite_paths": conflict_paths}),
    )?;
    Ok(CmdResult {
        ok: second.ok,
        code: second.code,
        stdout: format!(
            "first_command={} {}\nfirst_ok={}\nsecond_command={} {}\n{}",
            program,
            args.join(" "),
            result.ok,
            program,
            overwrite_args.join(" "),
            second.stdout
        )
        .trim()
        .to_string(),
        stderr: format!(
            "first_stderr={}\nsecond_stderr={}",
            result.stderr, second.stderr
        )
        .trim()
        .to_string(),
    })
}
use crate::atoms::comparison::ActionAuthorization;

pub(crate) fn package_install(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    receipt_dir: &Path,
    packages: &[String],
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
    timeout_secs: u64,
) -> Result<CommandObservation, String> {
    package_install_with_ignores(
        authorization,
        invocation,
        receipt_dir,
        packages,
        &[],
        conflict_policy,
        conflict_paths,
        timeout_secs,
    )
}

pub(crate) fn package_install_with_ignores(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    receipt_dir: &Path,
    packages: &[String],
    ignored: &[String],
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
    timeout_secs: u64,
) -> Result<CommandObservation, String> {
    let result = pacman_mutate_packages_with_ignores(
        authorization,
        invocation,
        receipt_dir,
        false,
        packages,
        ignored,
        conflict_policy,
        conflict_paths,
        timeout_secs,
    )?;
    Ok(CommandObservation {
        program: crate::atoms::package::pacman_program(),
        args: {
            let mut a = vec!["-S".into(), "--noconfirm".into(), "--needed".into()];
            for p in ignored {
                a.extend(["--ignore".into(), p.clone()]);
            }
            a
        },
        ok: result.ok,
        code: Some(result.code),
        stdout: result.stdout,
        stderr: result.stderr,
    })
}

use crate::atoms::comparison::{self, CeilingAuthorization, DiffDecision};
use crate::{OperationOutcome, PackageBackend};
use serde::Serialize;
use std::env;
use std::ffi::CString;
use std::io::{self, Read, Seek};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_PACKAGE_TIMEOUT_SECS: u64 = 1800;

pub(crate) fn package_tool_for_backend(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    packages: &[String],
    apply: bool,
    backend: PackageBackend,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
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
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
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
pub(crate) fn package_tool_with_policy_for_backend_and_ceilings(
    receipt_dir: &Path, name: &str, action: &str, packages: &[String], apply: bool,
    conflict_policy: Option<&str>, conflict_paths: &[String], timeout_secs: u64,
    backend: PackageBackend, invocation: Option<&InvocationKey>,
    pins: &std::collections::BTreeMap<String, String>,
    ceilings: &std::collections::BTreeMap<String, String>,
) -> Result<OperationOutcome, String> {
    if ceilings.is_empty() {
        return package_tool_with_policy_for_backend_and_pins(receipt_dir, name, action, packages, apply, conflict_policy, conflict_paths, timeout_secs, backend, invocation, pins);
    }
    let timeout = std::time::Duration::from_secs(timeout_secs.min(12));
    let relevant: Vec<String> = if action == "install" {
        packages.iter().filter_map(|spec| spec.split_once('=').map(|(p, _)| p.to_string()).or_else(|| ceilings.contains_key(spec).then(|| spec.clone()))).filter(|p| ceilings.contains_key(p)).collect()
    } else {
        ceilings.keys().cloned().collect()
    };
    if relevant.is_empty() {
        return package_tool_with_policy_for_backend_and_pins(receipt_dir, name, action, packages, apply, conflict_policy, conflict_paths, timeout_secs, backend, invocation, pins);
    }
    if backend != PackageBackend::Apt {
        let receipt = serde_json::json!({"schema":"harmonia.package_ceiling.v1","module_seat":"pins/pins","entries":[],"first_blocker":"ceiling-backend-unsupported","posture":"preserved"});
        write_json(&receipt_dir.join(format!("{name}.ceiling.json")), &receipt)?;
        return Err("package-ceiling-backend-unsupported".into());
    }
    if !matches!(action, "install" | "upgrade" | "update") {
        let receipt = serde_json::json!({"schema":"harmonia.package_ceiling.v1","module_seat":"pins/pins","entries":[],"first_blocker":"ceiling-action-unsupported","posture":"preserved"});
        write_json(&receipt_dir.join(format!("{name}.ceiling.json")), &receipt)?;
        return Err("package-ceiling-action-unsupported".into());
    }
    let mut runner = |program: &str, args: &[String], duration: std::time::Duration| -> Result<CommandObservation, String> {
        Ok(crate::atoms::ask::read_only_command_with_timeout(program, args, duration))
    };
    let (entries, first_blocker) = evaluate_package_ceiling(action, packages, ceilings, timeout, &mut runner);
    if entries.is_empty() {
        return package_tool_with_policy_for_backend_and_pins(receipt_dir, name, action, packages, apply, conflict_policy, conflict_paths, timeout_secs, backend, invocation, pins);
    }
    let comparison = aggregate_ceiling_comparison(&entries);
    let posture = if first_blocker.is_some() { "preserved" } else { "authorized" };
    let receipt = serde_json::json!({"schema":"harmonia.package_ceiling.v1","module_seat":"pins/pins","entries":entries,"first_blocker":first_blocker,"posture":posture});
    write_json(&receipt_dir.join(format!("{name}.ceiling.json")), &receipt)?;
    let run = crate::atoms::comparison::execute_with_ceiling(
        "package",
        || Ok::<_, String>(()),
        |_| comparison,
        |_action_authorization, ceiling_authorization, _| {
            if matches!(action, "upgrade" | "update") {
                package_update_tool(receipt_dir, name, action, packages, apply, timeout_secs, PackageBackend::Apt, pins, invocation, Some(&ceiling_authorization))
            } else {
                apt_package_tool(receipt_dir, name, action, packages, apply, timeout_secs, pins, invocation, Some(&ceiling_authorization))
            }
        },
    )?;
    match run {
        crate::atoms::comparison::CeilingComparisonRun::Moved { movement, .. } => Ok(movement),
        crate::atoms::comparison::CeilingComparisonRun::Current { comparison, .. } => match comparison {
            crate::atoms::comparison::CeilingComparison::Empty => Ok(OperationOutcome {
                ok: true,
                changed: false,
                skipped: true,
                message: format!("apt package {action} already current within declared ceiling"),
                command: None,
            }),
            crate::atoms::comparison::CeilingComparison::CeilingExceeded => Err(format!(
                "package-ceiling-{}",
                first_blocker.as_deref().unwrap_or("ceiling-exceeded")
            )),
            crate::atoms::comparison::CeilingComparison::Incomparable => Err(format!(
                "package-ceiling-{}",
                first_blocker.as_deref().unwrap_or("version-incomparable")
            )),
            crate::atoms::comparison::CeilingComparison::DifferentAndWithinCeiling => {
                Err("package-ceiling-internal-current-within-ceiling".into())
            }
        },
    }
}

fn aggregate_ceiling_comparison(entries: &[CeilingEntry]) -> crate::atoms::comparison::CeilingComparison {
    if entries.iter().any(|entry| entry.comparison == "incomparable") {
        crate::atoms::comparison::CeilingComparison::Incomparable
    } else if entries.iter().any(|entry| entry.comparison == "exceeded") {
        crate::atoms::comparison::CeilingComparison::CeilingExceeded
    } else if entries.iter().all(|entry| entry.comparison == "empty") {
        crate::atoms::comparison::CeilingComparison::Empty
    } else {
        crate::atoms::comparison::CeilingComparison::DifferentAndWithinCeiling
    }
}

fn command_evidence(o: &CommandObservation, timeout: std::time::Duration) -> CeilingCommandEvidence {
    let timed_out = o.stderr.to_ascii_lowercase().contains("timed out");
    CeilingCommandEvidence { program: o.program.clone(), args: o.args.clone(), ok: o.ok, code: o.code, stdout: o.stdout.clone(), stderr: o.stderr.clone(), timeout_secs: timeout.as_secs(), timeout: timed_out, timeout_effect: if timed_out { "incomparable".into() } else { "none".into() } }
}

fn evaluate_package_ceiling<F>(action: &str, packages: &[String], ceilings: &std::collections::BTreeMap<String, String>, timeout: std::time::Duration, runner: &mut F) -> (Vec<CeilingEntry>, Option<String>)
where F: FnMut(&str, &[String], std::time::Duration) -> Result<CommandObservation, String> {
    let mut entries = Vec::new();
    for package in if action == "install" { packages.iter().filter_map(|spec| spec.split_once('=').map(|(p, _)| p.to_string()).or_else(|| ceilings.contains_key(spec).then(|| spec.clone()))).filter(|p| ceilings.contains_key(p)).collect::<Vec<_>>() } else { ceilings.keys().cloned().collect() } {
        let mut declared = DeclaredCeiling { package: package.clone(), desired: String::new(), ceiling: ceilings[&package].clone() };
        let ceiling = declared.ceiling.clone();
        let spec = packages.iter().find(|s| s.split_once('=').map(|(p, _)| p == package).unwrap_or(s.as_str() == package)).cloned();
        let mut evidence = Vec::new();
        let desired = if let Some(spec) = spec.and_then(|s| s.split_once('=').map(|(_, v)| v.to_string())) { spec } else {
            let args = vec!["policy".into(), package.clone()];
            match runner("/usr/bin/apt-cache", &args, timeout) {
                Ok(obs) => { evidence.push(command_evidence(&obs, timeout)); let candidates: Vec<_> = obs.stdout.lines().filter_map(|l| l.trim().strip_prefix("Candidate:").map(str::trim)).filter(|v| !v.is_empty() && *v != "(none)").collect(); if !obs.ok || candidates.len() != 1 { entries.push(CeilingEntry { package, desired_version: "".into(), ceiling, live_version: None, comparison: "incomparable".into(), witness_state: "incomparable".into(), identity_change: IdentityChange::Incomparable { before: "".into(), after: "".into(), first_blocker: "candidate-incomparable".into() }, currentness_witness: CurrentnessWitness { before: None, after: None, state: "incomparable".into() }, posture: "preserved".into(), command_evidence: evidence, first_blocker: Some("candidate-incomparable".into()) }); continue; } candidates[0].to_string() }
                Err(error) => { entries.push(CeilingEntry { package, desired_version: "".into(), ceiling, live_version: None, comparison: "incomparable".into(), witness_state: "incomparable".into(), identity_change: IdentityChange::Incomparable { before: "".into(), after: "".into(), first_blocker: error.clone() }, currentness_witness: CurrentnessWitness { before: None, after: None, state: "incomparable".into() }, posture: "preserved".into(), command_evidence: evidence, first_blocker: Some(error) }); continue; }
            }
        };
        declared.desired = desired.clone();
        let live_args = vec!["-W".into(), "-f=${Version}".into(), package.clone()];
        let live = match runner("/usr/bin/dpkg-query", &live_args, timeout) { Ok(o) => { evidence.push(command_evidence(&o, timeout)); o }, Err(e) => { entries.push(CeilingEntry { package, desired_version: desired.clone(), ceiling, live_version: None, comparison: "incomparable".into(), witness_state: "incomparable".into(), identity_change: IdentityChange::Incomparable { before: "".into(), after: desired, first_blocker: e.clone() }, currentness_witness: CurrentnessWitness { before: None, after: None, state: "incomparable".into() }, posture: "preserved".into(), command_evidence: evidence, first_blocker: Some(e) }); continue; } };
        let live_version = live.ok.then(|| live.stdout.trim().to_string()).filter(|v| !v.is_empty());
        let mut compare_runner = |p: &str, a: &[String], t: std::time::Duration| runner(p, a, t);
        let live_version_for_change = live_version.clone().unwrap_or_default();
        let (comparison, blocker, identity, state) = if live_version.is_none() { ("incomparable", Some("live-version-missing"), IdentityChange::Incomparable { before: "".into(), after: desired.clone(), first_blocker: "live-version-missing".into() }, "incomparable") } else {
            let live_v = live_version.as_ref().unwrap();
            let same = crate::atoms::ask::package_ceiling::compare_debian_versions_with_runner(&desired, live_v, timeout, &mut compare_runner);
            for item in match &same { Ok(comparison) => &comparison.evidence, Err(failure) => &failure.evidence } { evidence.push(CeilingCommandEvidence { program: item.program.clone(), args: item.args.clone(), ok: item.exit_code == Some(0), code: item.exit_code, stdout: item.stdout.clone(), stderr: item.stderr.clone(), timeout_secs: item.timeout_secs, timeout: item.refused.as_deref() == Some("timeout"), timeout_effect: item.refused.clone().unwrap_or_else(|| "none".into()) }); }
            let within = crate::atoms::ask::package_ceiling::compare_debian_versions_with_runner(&desired, &ceiling, timeout, &mut compare_runner);
            for item in match &within { Ok(comparison) => &comparison.evidence, Err(failure) => &failure.evidence } { evidence.push(CeilingCommandEvidence { program: item.program.clone(), args: item.args.clone(), ok: item.exit_code == Some(0), code: item.exit_code, stdout: item.stdout.clone(), stderr: item.stderr.clone(), timeout_secs: item.timeout_secs, timeout: item.refused.as_deref() == Some("timeout"), timeout_effect: item.refused.clone().unwrap_or_else(|| "none".into()) }); }
            let identity = match &same { Ok(c) if matches!(c.order, crate::atoms::ask::package_ceiling::DebianVersionOrder::Equal) => IdentityChange::Unchanged, Ok(_) => IdentityChange::Ordered { before: live_v.clone(), after: desired.clone() }, _ => IdentityChange::Incomparable { before: live_v.clone(), after: desired.clone(), first_blocker: "identity-version-order-unavailable".into() } };
            let result = match (same, within) { (Ok(s), Ok(_w)) if matches!(s.order, crate::atoms::ask::package_ceiling::DebianVersionOrder::Equal) => ("empty", None, identity, "current"), (Ok(_), Ok(w)) if !matches!(w.order, crate::atoms::ask::package_ceiling::DebianVersionOrder::Greater) => ("different-and-within-ceiling", None, identity, "different"), (Ok(_), Ok(_)) => ("exceeded", Some("ceiling-exceeded"), identity, "exceeded"), _ => ("incomparable", Some("version-incomparable"), identity, "incomparable") }; result
        };
        entries.push(CeilingEntry { package, desired_version: declared.desired.clone(), ceiling, live_version, comparison: comparison.into(), witness_state: state.into(), identity_change: identity, currentness_witness: CurrentnessWitness { before: Some(live_version_for_change), after: Some(desired.clone()), state: state.into() }, posture: if blocker.is_none() { "authorized".into() } else { "preserved".into() }, command_evidence: evidence, first_blocker: blocker.map(str::to_string) });
    }
    let blocker = entries.iter().find_map(|e| e.first_blocker.clone());
    (entries, blocker)
}

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
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
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
                invocation,
                None,
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
            invocation,
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
                invocation,
                None,
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
            invocation,
            None,
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
    invocation: Option<&InvocationKey>,
    ceiling_authorization: Option<&CeilingAuthorization>,
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
        |authorization, _| {
            let authorization = &authorization;
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
            let result = if apply {
                let invocation = invocation
                    .ok_or_else(|| "package-mutation-invocation-missing".to_string())?;
                if let Some(ceiling) = ceiling_authorization {
                    run_apt_command_authorized_with_ceiling(
                        authorization, ceiling, invocation, receipt_dir, name, &program, args, timeout_secs, pins,
                    )
                } else {
                    run_apt_command_authorized(
                        authorization, invocation, receipt_dir, name, &program, args, timeout_secs, pins,
                    )
                }
            } else {
                run_apt_command(receipt_dir, name, &program, args, timeout_secs, pins)
            };
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
            crate::atoms::attest::install_package::write_guard_receipts(receipt_dir, name, before, movement, after)
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

fn run_apt_command_authorized_with_ceiling(
    action: &ActionAuthorization,
    ceiling: &CeilingAuthorization,
    invocation: &InvocationKey,
    receipt_dir: &Path,
    name: &str,
    program: &str,
    args: Vec<String>,
    timeout_secs: u64,
    pins: &std::collections::BTreeMap<String, String>,
) -> CmdResult {
    let _both_capabilities = (action, ceiling);
    run_apt_command_authorized(action, invocation, receipt_dir, name, program, args, timeout_secs, pins)
}

fn run_apt_command_authorized(
    _authorization: &ActionAuthorization,
    _invocation: &InvocationKey,
    receipt_dir: &Path,
    name: &str,
    program: &str,
    args: Vec<String>,
    timeout_secs: u64,
    pins: &std::collections::BTreeMap<String, String>,
) -> CmdResult {
    run_apt_command(receipt_dir, name, program, args, timeout_secs, pins)
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
    ignored_upgrades: Vec<PendingPackage>,
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
const PACMAN_CONF_TIMEOUT_SECS: u64 = 30;

fn pacman_configured_ignored(db: &str, t: u64) -> std::collections::BTreeSet<String> {
    let program = crate::atoms::package::pacman_conf_program();
    let packages = command::capture_with_timeout(&program, &["IgnorePkg"], PACMAN_CONF_TIMEOUT_SECS);
    let groups = command::capture_with_timeout(&program, &["IgnoreGroup"], PACMAN_CONF_TIMEOUT_SECS);
    let mut names = std::collections::BTreeSet::new();
    if packages.ok {
        names.extend(
            packages
                .stdout
                .lines()
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string),
        );
    }
    let groups = if groups.ok {
        groups
            .stdout
            .lines()
            .map(str::trim)
            .filter(|group| !group.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    for group in groups {
        let result = command::capture_with_timeout(
            &pacman_program(),
            &["-Sgq", "--dbpath", db, &group],
            t,
        );
        if result.ok {
            names.extend(result.stdout.lines().map(str::trim).filter(|name| !name.is_empty()).map(str::to_string));
        }
    }
    names
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
            let (refresh, q, mut p, ok, ignored_upgrades) = if let Err(e) = setup {
                (
                    synthetic(&format!("pacman sandbox setup failed: {e}")),
                    synthetic("pacman query skipped after sandbox setup failure"),
                    Vec::new(),
                    false,
                    Vec::new(),
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
                        Vec::new(),
                    )
                } else {
                    let q = command::capture_with_timeout(&x, &["-Qu", "--dbpath", &db], t);
                    let ok = q.ok || (q.code == 1 && q.stdout.is_empty() && q.stderr.is_empty());
                    let mut p = if ok {
                        parse_pacman_pending(&q.stdout)
                    } else {
                        Vec::new()
                    };
                    let ignored_upgrades = pacman_configured_ignored(&db, t);
                    let ignored = p.iter().filter(|item| ignored_upgrades.contains(&item.name)).cloned().collect::<Vec<_>>();
                    p.retain(|item| !ignored_upgrades.contains(&item.name));
                    (refresh, q, p, ok, ignored)
                }
            };
            let cleanup = fs::remove_dir_all(&d).err().map(|e| e.to_string());
            let probe_ok = ok && cleanup.is_none();
            p.retain(|item| !pins.contains_key(&item.name));
            UpdateObservation {
                backend: bn,
                observed_state: if !probe_ok {
                    "probe-failed".into()
                } else if p.is_empty() && q.code == 1 && q.stdout.is_empty() && q.stderr.is_empty()
                {
                    "pacman-query-no-pending-exit-1-empty".into()
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
                ignored_upgrades,
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
                ignored_upgrades: Vec::new(),
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

fn capture_owned_authorized(
    _authorization: &ActionAuthorization,
    _invocation: &InvocationKey,
    program: &str,
    args: Vec<String>,
    timeout: u64,
) -> CmdResult {
    capture_owned_with_timeout(program, args, timeout)
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

pub(crate) fn run_apt_command(
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
    invocation: Option<&InvocationKey>,
    ceiling_authorization: Option<&CeilingAuthorization>,
) -> Result<OperationOutcome, String> {
    let pre = observe_update(r, a, t, b, pins);
    write_pin_witness(r, n, pins, b)?;
    let different = !pre.probe_ok || pre.pending_count > 0;
    let release_info_change_accepted = match b {
        PackageBackend::Apt => apt_release_info_change_accepted(&pre.refresh_command),
        PackageBackend::Pacman => false,
    };
    let mut out = serde_json::json!({"schema":"harmonia.package_tool.v1","name":n,"tool":NAME,"permutation":a,"declared_package_backend":b.name(),"backend":b.name(),"observed_state":pre.observed_state.clone(),"desired_state":"no-pending-updates","diff_decision":if different {"different"} else {"empty"},"probe_ok":pre.probe_ok,"pending_count":pre.pending_count,"pending":pre.pending,"ignored_upgrades":pre.ignored_upgrades,"db_synced_at":pre.db_synced_at,"refresh_command":pre.refresh_command,"command":pre.query,"upgraded_count":0,"upgraded":[],"backend_log_tail":serde_json::Value::Null,"movement":serde_json::Value::Null,"observed_before":pre,"observed_after":serde_json::Value::Null,"act":serde_json::Value::Null,"converged":pre.probe_ok && pre.pending_count == 0,"changed":false,"skipped":false,"exclusion_set":pins.keys().collect::<Vec<_>>()});
    out["first_missing_signal"] = serde_json::json!(if !pre.probe_ok {
        "package-probe-unavailable"
    } else if pre.pending_count > 0 {
        "pending-package-updates-report-only"
    } else {
        "none"
    });
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
                ok: pre.pending_count == 0,
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
        let authorized = comparison::execute_once(
            "package-update",
            || Ok::<_, String>(pre.clone()),
            |_| DiffDecision::Different,
            |authorization, _| {
                let authorization = &authorization;
                let invocation = invocation
                    .ok_or_else(|| "package-mutation-invocation-missing".to_string())?;
                let pair = match b {
                    PackageBackend::Pacman => (
                        None,
                        capture_owned_authorized(
                            authorization,
                            invocation,
                            &pacman_program(),
                            pin_args(["-Syu", "--noconfirm"].as_slice(), pins, true),
                            t,
                        ),
                    ),
                    PackageBackend::Apt => {
                        let u = if let Some(ceiling) = ceiling_authorization { run_apt_command_authorized_with_ceiling(authorization, ceiling, invocation, r, n, &apt_program(), vec!["update".into(), "--allow-releaseinfo-change".into()], t, pins) } else { run_apt_command_authorized(
                            authorization,
                            invocation,
                            r,
                            n,
                            &apt_program(),
                            vec!["update".into(), "--allow-releaseinfo-change".into()],
                            t,
                            pins,
                        ) };
                        if u.ok {
                            (
                                Some(u),
                                if let Some(ceiling) = ceiling_authorization { run_apt_command_authorized_with_ceiling(authorization, ceiling, invocation, r, n, &apt_program(), vec!["full-upgrade".into(), "--yes".into(), "--no-remove".into()], t, pins) } else { run_apt_command_authorized(authorization, invocation, r, n, &apt_program(), vec!["full-upgrade".into(), "--yes".into(), "--no-remove".into()], t, pins) },
                            )
                        } else {
                            (Some(u.clone()), u)
                        }
                    }
                };
                Ok(pair)
            },
        )?;
        let (refresh, act) = match authorized {
            comparison::ComparisonRun::Moved { movement, .. } => movement,
            comparison::ComparisonRun::Current { .. } => unreachable!("different update must act"),
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
        out["act"] = serde_json::json!({"ok":act.ok,"changed":changed,"skipped":false,"message":format!("package {a}"),"command":act,"act_refresh_command":refresh,"ignored_upgrades":post.ignored_upgrades.clone()});
        out["movement"] = out["act"].clone();
        out["observed_after"] = serde_json::to_value(&post).map_err(|e| e.to_string())?;
        out["ignored_upgrades"] = serde_json::to_value(&post.ignored_upgrades).map_err(|e| e.to_string())?;
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
        None,
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
    invocation: Option<&InvocationKey>,
) -> Result<OperationOutcome, String> {
    let pacman = pacman_program();
    if !pacman_available(&pacman) {
        let outcome = OperationOutcome {
            ok: false,
            changed: false,
            skipped: true,
            message: "package-manager-unavailable".to_string(),
            command: None,
        };
        let observation = PackageObservation {
            observed_state: "package-manager-unavailable".into(),
            desired_state: format!("{action}-declared"),
            current: None,
        };
        let mut comparison = package_receipt_fields(&observation, DiffDecision::Empty, None, false);
        if let Some(fields) = comparison.as_object_mut() {
            fields.insert("converged".into(), serde_json::Value::Bool(false));
            fields.insert(
                "first_missing_signal".into(),
                serde_json::Value::String("package-manager-unavailable".into()),
            );
        }
        write_json(
            &receipt_dir.join(format!("{name}.comparison.json")),
            &comparison,
        )?;
        write_package_receipt(receipt_dir, name, action, &outcome)?;
        return Ok(outcome);
    }
    let observe_result = match action {
        "install" => command::capture(&pacman, &["-Q"]),
        _ => command::capture(&pacman, &["-Qu"]),
    };
    let observed_state = if matches!(action, "check" | "upgrade" | "update") {
        pacman_observed_state(&observe_result)
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
            let observed_state = if matches!(action, "check" | "upgrade" | "update") {
                pacman_observed_state(&result)
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
        |authorization, _| {
            let authorization = &authorization;
            let result = match action {
                "upgrade" | "update" if apply => {
                    let invocation = invocation.ok_or_else(|| "package-mutation-invocation-missing".to_string())?;
                    reclaim_pacman_database_lock(authorization, invocation, receipt_dir, &pacman, true)?;
                    command::capture_with_timeout(&pacman, &["-Syu", "--noconfirm"], timeout_secs)
                }
                "upgrade" | "update" | "check" => {
                    command::capture(&pacman, &["-Qu"])
                }
                "install" if apply => {
                    let invocation = invocation.ok_or_else(|| "package-mutation-invocation-missing".to_string())?;
                    pacman_mutate_packages_with_options(
                        authorization,
                        invocation,
                        receipt_dir,
                        false,
                        packages,
                        conflict_policy,
                        conflict_paths,
                        timeout_secs,
                    )?
                }
                "install" => {
                    command::capture(&pacman, &["-Q"])
                }
                other => return Err(format!("unsupported package action {other}")),
            };
            let ok = match action {
                "check" | "upgrade" | "update" if !apply => {
                    result.ok || (result.code == 1 && pacman_update_query_is_empty(&result))
                }
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
            crate::atoms::attest::install_package::write_guard_receipts(receipt_dir, name, before, movement, after)
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
    invocation: Option<&InvocationKey>,
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
        |authorization, _| {
            let authorization = &authorization;
            let invocation = invocation.ok_or_else(|| "keyring-repair-invocation-missing".to_string())?;
            keyring_repair_action(authorization, invocation, receipt_dir, name, package_name, apply, timeout_secs, pins)
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
            crate::atoms::attest::install_package::write_guard_receipts(receipt_dir, name, before, movement, after)
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
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
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
            pacman_mutate_packages_with_ignores(
                authorization,
                invocation,
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


#[cfg(test)]
mod package_ceiling_production_tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::Duration;

    fn obs(program: &str, args: &[String], code: i32, stdout: &str) -> CommandObservation {
        CommandObservation { program: program.into(), args: args.to_vec(), ok: code == 0, code: Some(code), stdout: stdout.into(), stderr: String::new() }
    }
    fn map(items: &[(&str, &str)]) -> BTreeMap<String, String> { items.iter().map(|(p, v)| ((*p).into(), (*v).into())).collect() }
    fn ceiling_entry(comparison: &str) -> CeilingEntry {
        CeilingEntry {
            package: "pkg".into(),
            desired_version: "2.0".into(),
            ceiling: "3.0".into(),
            live_version: Some("1.0".into()),
            comparison: comparison.into(),
            witness_state: comparison.into(),
            identity_change: IdentityChange::Unchanged,
            currentness_witness: CurrentnessWitness { before: Some("1.0".into()), after: Some("2.0".into()), state: comparison.into() },
            posture: "preserved".into(),
            command_evidence: Vec::new(),
            first_blocker: None,
        }
    }
    fn fake<'a>(mode: &'static str, seen: &'a mut Vec<(String, Vec<String>, Duration)>) -> impl FnMut(&str, &[String], Duration) -> Result<CommandObservation, String> + 'a {
        move |program, args, timeout| {
            seen.push((program.into(), args.to_vec(), timeout));
            if program == "/usr/bin/apt-cache" {
                return Ok(obs(program, args, 0, "Candidate: 2.0\n"));
            }
            if program == "/usr/bin/dpkg-query" {
                return Ok(obs(program, args, 0, "1.0\n"));
            }
            let code = if mode == "equal" { 0 } else {
                let left: f64 = args.get(1).and_then(|v| v.parse().ok()).unwrap_or(0.0);
                let right: f64 = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(0.0);
                if left <= right { 0 } else { 1 }
            };
            Ok(obs(program, args, code, ""))
        }
    }

    #[test]
    fn package_ceiling_aggregate_empty_is_no_action() {
        assert_eq!(aggregate_ceiling_comparison(&[ceiling_entry("empty")]), crate::atoms::comparison::CeilingComparison::Empty);
        assert_eq!(aggregate_ceiling_comparison(&[ceiling_entry("different-and-within-ceiling")]), crate::atoms::comparison::CeilingComparison::DifferentAndWithinCeiling);
    }

    #[test]
    fn package_ceiling_aggregate_exceeded_and_incomparable_block() {
        assert_eq!(aggregate_ceiling_comparison(&[ceiling_entry("exceeded")]), crate::atoms::comparison::CeilingComparison::CeilingExceeded);
        assert_eq!(aggregate_ceiling_comparison(&[ceiling_entry("exceeded"), ceiling_entry("incomparable")]), crate::atoms::comparison::CeilingComparison::Incomparable);
    }

    #[test]
    fn package_ceiling_relevant_target_filtering_excludes_unlisted_install_targets() {
        let mut seen = Vec::new(); let mut runner = fake("equal", &mut seen);
        let (entries, blocker) = evaluate_package_ceiling("install", &["other=2.0".into(), "kept=2.0".into()], &map(&[("kept", "3.0")]), Duration::from_secs(7), &mut runner);
        assert_eq!(blocker, None); assert_eq!(entries.len(), 1); assert_eq!(entries[0].package, "kept");
    }
    #[test]
    fn package_ceiling_explicit_install_equal_is_empty() {
        let mut seen = Vec::new(); let mut runner = fake("equal", &mut seen);
        let (entries, _) = evaluate_package_ceiling("install", &["pkg=1.0".into()], &map(&[("pkg", "2.0")]), Duration::from_secs(7), &mut runner);
        assert_eq!(entries[0].comparison, "empty"); assert_eq!(entries[0].witness_state, "current");
    }
    #[test]
    fn package_ceiling_below_is_within_ceiling() {
        let mut seen = Vec::new(); let mut runner = fake("ordered", &mut seen);
        let (entries, _) = evaluate_package_ceiling("install", &["pkg=2.0".into()], &map(&[("pkg", "3.0")]), Duration::from_secs(7), &mut runner);
        assert_eq!(entries[0].comparison, "different-and-within-ceiling");
    }
    #[test]
    fn package_ceiling_above_is_exceeded() {
        let mut seen = Vec::new(); let mut runner = fake("above", &mut seen);
        let (entries, blocker) = evaluate_package_ceiling("install", &["pkg=3.0".into()], &map(&[("pkg", "2.0")]), Duration::from_secs(7), &mut runner);
        assert_eq!(entries[0].comparison, "exceeded"); assert_eq!(blocker, Some("ceiling-exceeded".into()));
    }
    #[test]
    fn package_ceiling_upgrade_selects_candidates_for_all_ceiling_keys() {
        let mut seen = Vec::new(); let mut runner = fake("equal", &mut seen);
        let (entries, _) = evaluate_package_ceiling("upgrade", &[], &map(&[("pkg", "3.0")]), Duration::from_secs(7), &mut runner);
        drop(runner);
        assert_eq!(entries.len(), 1); assert_eq!(entries[0].desired_version, "2.0"); assert_eq!(seen[0].0, "/usr/bin/apt-cache");
    }
    #[test]
    fn package_ceiling_multiple_entries_retained_and_first_blocker_is_first_entry() {
        let mut seen = Vec::new();
        let mut runner = |program: &str, args: &[String], timeout: Duration| { seen.push((program.to_string(), args.to_vec(), timeout)); if program == "/usr/bin/apt-cache" { Ok(obs(program,args,0,if args[1]=="a" { "Candidate: (none)\n" } else { "Candidate: 1.0\n" })) } else { Ok(obs(program,args,0,"1.0\n")) } };
        let (entries, blocker) = evaluate_package_ceiling("upgrade", &[], &map(&[("a", "2.0"), ("b", "2.0")]), Duration::from_secs(7), &mut runner);
        assert_eq!(entries.len(), 2); assert_eq!(entries[0].first_blocker, Some("candidate-incomparable".into())); assert_eq!(blocker, Some("candidate-incomparable".into()));
    }
    #[test]
    fn package_ceiling_receipt_evidence_has_exact_commands_and_timeout() {
        let mut seen = Vec::new(); let mut runner = fake("equal", &mut seen);
        let (entries, _) = evaluate_package_ceiling("install", &["pkg=1.0".into()], &map(&[("pkg", "2.0")]), Duration::from_secs(7), &mut runner);
        drop(runner);
        assert_eq!(seen[0].0, "/usr/bin/dpkg-query"); assert_eq!(seen[0].1, vec!["-W", "-f=${Version}", "pkg"]); assert_eq!(seen[0].2, Duration::from_secs(7));
        assert!(entries[0].command_evidence.iter().any(|e| e.program == "/usr/bin/dpkg")); assert!(entries[0].command_evidence.iter().all(|e| !e.timeout));
    }
    #[test]
    fn package_ceiling_malformed_candidate_is_incomparable() {
        let mut runner = |program: &str, args: &[String], _timeout: Duration| {
            if program == "/usr/bin/apt-cache" { Ok(obs(program, args, 0, "Candidate: (none)\n")) } else { Ok(obs(program, args, 0, "1.0\n")) }
        };
        let (entries, blocker) = evaluate_package_ceiling("upgrade", &[], &map(&[("pkg", "2.0")]), Duration::from_secs(7), &mut runner);
        assert_eq!(entries[0].comparison, "incomparable"); assert_eq!(blocker, Some("candidate-incomparable".into()));
    }
    #[test]
    fn package_ceiling_failed_dpkg_probe_receipt_retains_command_evidence() {
        let mut dpkg_calls = 0;
        let mut runner = |program: &str, args: &[String], _timeout: Duration| {
            if program == "/usr/bin/dpkg-query" { return Ok(obs(program, args, 0, "1.0\n")); }
            if program == "/usr/bin/dpkg" {
                dpkg_calls += 1;
                return Ok(CommandObservation { program: program.into(), args: args.to_vec(), ok: false, code: Some(if dpkg_calls == 1 { 2 } else { 0 }), stdout: String::new(), stderr: if dpkg_calls == 1 { "dpkg probe failed".into() } else { String::new() } });
            }
            Ok(obs(program, args, 0, ""))
        };
        let (entries, blocker) = evaluate_package_ceiling("install", &["pkg=2.0".into()], &map(&[("pkg", "3.0")]), Duration::from_secs(7), &mut runner);
        assert_eq!(entries[0].comparison, "incomparable");
        assert_eq!(entries[0].posture, "preserved");
        assert_eq!(blocker, Some("version-incomparable".into()));
        let evidence = entries[0].command_evidence.iter().find(|item| item.program == "/usr/bin/dpkg" && item.code == Some(2)).unwrap();
        assert_eq!(evidence.args.first().map(String::as_str), Some("--compare-versions"));
        assert_eq!(evidence.stderr, "dpkg probe failed");
        assert_eq!(evidence.timeout_secs, 7);
        assert_eq!(evidence.timeout_effect, "nonempty-stderr");
    }

    #[test]
    fn package_ceiling_live_missing_is_incomparable() {
        let mut runner = |program: &str, args: &[String], _timeout: Duration| { Ok(obs(program,args,1,"")) };
        let (entries, blocker) = evaluate_package_ceiling("install", &["pkg=1.0".into()], &map(&[("pkg", "2.0")]), Duration::from_secs(7), &mut runner);
        assert_eq!(entries[0].comparison, "incomparable"); assert_eq!(blocker, Some("live-version-missing".into()));
    }
}
