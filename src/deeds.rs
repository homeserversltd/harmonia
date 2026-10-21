//! One appliance deed stream. Callers supply outcome fields, never a body.
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, MetadataExt};
use std::path::Path;
use std::cell::Cell;

const LOG: &str = "/var/log/appliance/appliance.log";

thread_local! {
    static OBSERVATION_ONLY: Cell<bool> = const { Cell::new(false) };
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
    changed || (!ok && !OBSERVATION_ONLY.with(Cell::get))
}

fn token(value: &str, limit: usize) -> String {
    value.chars().take(limit).map(|character| {
        if character.is_ascii_alphanumeric() || matches!(character, '-'|'_'|'.'|'/'|':') {
            character
        } else { '_' }
    }).collect()
}

pub(crate) fn record(
    verb: &str, target: &str, ok: bool, changed: bool, duration_ms: u128,
    run_id: Option<&str>, module_id: Option<&str>, signal: Option<&str>, count: Option<u64>,
) -> Result<(), String> {
    if !should_record(ok, changed) { return Ok(()); }
    let line = format!(
        "who=harmonia verb={} target={} outcome={} duration_ms={} run_id={} module_id={} signal={} count={}\n",
        token(verb,64), token(target,192), if ok {"changed"} else {"failed"}, duration_ms,
        token(run_id.unwrap_or("none"),80), token(module_id.unwrap_or("none"),96),
        token(signal.unwrap_or(if ok {"none"} else {"operation-failed"}),96),
        count.map(|value|value.to_string()).unwrap_or_else(||"none".into()),
    );
    debug_assert!(line.len()<1024);
    fs::create_dir_all(Path::new(LOG).parent().unwrap())
        .map_err(|error|format!("appliance-log-parent-failed: {error}"))?;
    let mut log = OpenOptions::new().create(true).append(true).mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(LOG)
        .map_err(|error|format!("appliance-log-open-failed: {error}"))?;
    let metadata = log.metadata().map_err(|error|error.to_string())?;
    if !metadata.is_file() || metadata.nlink()!=1 {
        return Err("appliance-log-not-regular".into());
    }
    log.write_all(line.as_bytes()).map_err(|error|format!("appliance-log-write-failed: {error}"))
}
