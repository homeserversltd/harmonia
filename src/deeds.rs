//! One appliance deed stream. Callers supply outcome fields, never a body.
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, MetadataExt};
use std::path::Path;
use std::cell::{Cell, RefCell};
use std::time::Instant;

const LOG: &str = "/var/log/appliance/appliance.log";

thread_local! {
    static OBSERVATION_ONLY: Cell<bool> = const { Cell::new(false) };
    static ACTIVE_CONTEXT: RefCell<Option<Context>> = const { RefCell::new(None) };
    // One coded signal per surface in this CLI invocation, never a body/history.
    static DEED_FAILURE: RefCell<Option<String>> = const { RefCell::new(None) };
    static LEDGER_FAILURE: RefCell<Option<String>> = const { RefCell::new(None) };
    static SWEEP_FAILURE: RefCell<Option<String>> = const { RefCell::new(None) };
}

struct Context {
    run_id: Option<String>,
    module_id: Option<String>,
    started: Instant,
    duration_scope: &'static str,
}

/// Invocation-local identities and elapsed time, released on every return.
/// A step may nest under its run; no receipt body or history is retained.
pub(crate) struct ContextGuard(Option<Context>);

impl ContextGuard {
    pub(crate) fn enter(run_id: Option<&str>, module_id: Option<&str>, duration_scope: &'static str) -> Self {
        ACTIVE_CONTEXT.with(|active| {
            let mut active = active.borrow_mut();
            let context = Context {
                run_id: run_id.map(str::to_owned).or_else(|| active.as_ref().and_then(|value| value.run_id.clone())),
                module_id: module_id.map(str::to_owned).or_else(|| active.as_ref().and_then(|value| value.module_id.clone())),
                started: Instant::now(),
                duration_scope,
            };
            Self(active.replace(context))
        })
    }
}

impl Drop for ContextGuard {
    fn drop(&mut self) { ACTIVE_CONTEXT.with(|active| { active.replace(self.0.take()); }); }
}

/// Report-only failures are failed observations, not failed mutation attempts.
/// The native receipts still carry them; no deed or forwarding is manufactured.
pub(crate) struct ObservationGuard(bool);

impl ObservationGuard {
    pub(crate) fn enter(observation_only: bool) -> Self {
        Self(OBSERVATION_ONLY.with(|active| active.replace(observation_only)))
    }
}

impl Drop for ObservationGuard {
    fn drop(&mut self) { OBSERVATION_ONLY.with(|active| active.set(self.0)); }
}

pub(crate) fn should_record(ok: bool, changed: bool) -> bool {
    // Failures in a run are deeds of the serialized per-module material outcome,
    // not of every atom/press. Standalone atoms still report directly.
    if !ok && ACTIVE_CONTEXT.with(|active| active.borrow().as_ref()
        .is_some_and(|value| value.run_id.is_some() && value.module_id.is_some())) {
        return false;
    }
    changed || (!ok && !OBSERVATION_ONLY.with(Cell::get))
}

fn token(value: &str, limit: usize) -> String {
    value.chars().take(limit).map(|character| {
        if character.is_ascii_alphanumeric() || matches!(character, '-'|'_'|'.'|'/'|':') {
            character
        } else { '_' }
    }).collect()
}

pub(crate) fn coded_signal(error: &str) -> String {
    token(error.split_whitespace().next().unwrap_or("reporting-unavailable").trim_end_matches(':'), 96)
}

pub(crate) fn reporting_failure(surface: &str, error: &str) {
    let signal = coded_signal(error);
    let save = |slot: &RefCell<Option<String>>| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() { *slot = Some(signal.clone()); }
    };
    match surface {
        "profile_ledger" => LEDGER_FAILURE.with(save),
        "receipt_sweep" => SWEEP_FAILURE.with(save),
        _ => {}
    }
}

pub(crate) fn annotate_reporting(receipt: &mut serde_json::Value) {
    for (field, signal) in [
        ("deed_log", DEED_FAILURE.with(|value| value.borrow().clone())),
        ("profile_ledger", LEDGER_FAILURE.with(|value| value.borrow().clone())),
        ("receipt_sweep", SWEEP_FAILURE.with(|value| value.borrow().clone())),
    ] {
        if let Some(signal) = signal {
            if !receipt.get(field).is_some_and(serde_json::Value::is_object) {
                receipt[field] = serde_json::json!({});
            }
            receipt[field]["ok"] = serde_json::json!(false);
            receipt[field]["signal"] = serde_json::json!(signal);
        }
    }
}

fn append(line: &str) -> Result<(), String> {
    fs::create_dir_all(Path::new(LOG).parent().unwrap())
        .map_err(|_| "appliance-log-parent-failed")?;
    let mut log = OpenOptions::new().create(true).append(true).mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(LOG)
        .map_err(|_| "appliance-log-open-failed")?;
    let metadata = log.metadata().map_err(|_| "appliance-log-stat-failed")?;
    if !metadata.is_file() || metadata.nlink()!=1 {
        return Err("appliance-log-not-regular".into());
    }
    log.write_all(line.as_bytes()).map_err(|_| "appliance-log-write-failed".into())
}

/// Only a pending handoff needs acknowledgement. Failure is not an action error.
pub(crate) fn record_delivery(
    verb: &str, target: &str, ok: bool, changed: bool, duration_ms: Option<u128>,
    run_id: Option<&str>, module_id: Option<&str>, signal: Option<&str>, count: Option<u64>,
) -> bool {
    let reporting_attempt = matches!(verb, "profile-ledger" | "proposal-rows" | "sweep-retired-receipts");
    if !reporting_attempt && !should_record(ok, changed) { return true; }
    let context = ACTIVE_CONTEXT.with(|active| active.borrow().as_ref().map(|value| (
        value.started.elapsed().as_millis(), value.duration_scope, value.run_id.clone(), value.module_id.clone(),
    )));
    let (duration, scope) = match (duration_ms, context.as_ref()) {
        (Some(value), _) => (Some(value), "operation"),
        (None, Some(context)) => (Some(context.0), context.1),
        (None, None) => (None, "unmeasured"),
    };
    let run_id = run_id.or_else(|| context.as_ref().and_then(|value| value.2.as_deref()));
    let module_id = module_id.or_else(|| context.as_ref().and_then(|value| value.3.as_deref()));
    let line = format!(
        "who=harmonia verb={} target={} outcome={} duration_ms={} duration_scope={} run_id={} module_id={} signal={} count={}\n",
        token(verb,64), token(target,192), if ok {"changed"} else {"failed"},
        duration.map(|value| value.to_string()).unwrap_or_else(|| "none".into()), scope,
        token(run_id.unwrap_or("none"),80), token(module_id.unwrap_or("none"),96),
        token(signal.unwrap_or(if ok {"none"} else {"operation-failed"}),96),
        count.map(|value|value.to_string()).unwrap_or_else(||"none".into()),
    );
    debug_assert!(line.len()<850);
    match append(&line) {
        Ok(()) => true,
        Err(signal) => {
            DEED_FAILURE.with(|failure| {
                let mut failure = failure.borrow_mut();
                if failure.is_none() {
                    *failure = Some(signal.clone());
                    eprintln!("{} deed_recorded=false recording_signal={signal}", line.trim_end());
                }
            });
            false
        }
    }
}

/// Existing callers keep their Result interface, but a deed never fails them.
pub(crate) fn record(
    verb: &str, target: &str, ok: bool, changed: bool, duration_ms: Option<u128>,
    run_id: Option<&str>, module_id: Option<&str>, signal: Option<&str>, count: Option<u64>,
) -> Result<(), String> {
    record_delivery(verb, target, ok, changed, duration_ms, run_id, module_id, signal, count);
    Ok(())
}
