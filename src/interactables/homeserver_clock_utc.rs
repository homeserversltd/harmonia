use super::{DriftSummary, Interactable};
use crate::Profile;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

pub(crate) const INTERACTABLE_ID: &str = "homeserver-clock-utc";
const MARKER_FIELD: &str = "homeserver_clock_utc";
const MODULE_ID: &str = "household-time";
const DESIRED_TIMEZONE: &str = "UTC";
const TIMEDATECTL_DEFAULT: &str = "/usr/bin/timedatectl";
const OBSERVATION_LIMIT: usize = 512;
const COMMAND_TIMEOUT_SECS: u64 = 15;

/// Keep clock-specific evidence in this additive marker. The generic `evidence`
/// slot stays null because its canonical receipt one-of does not admit a clock variant.
/// Unknown marker fields survive a read/refresh cycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct HomeserverClockUtcMarker {
    pub(crate) profile: String,
    pub(crate) observed_timezone: String,
    pub(crate) desired_timezone: String,
    #[serde(default, flatten)]
    extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Serialize)]
struct ReconcileSummary {
    ok: bool,
    profile: String,
    observed_timezone: String,
    desired_timezone: String,
    proposal_id: Option<String>,
    proposal_state: &'static str,
    changed: bool,
}

#[derive(Debug)]
struct ClockReadFailure {
    phase: &'static str,
    reason: String,
    command: Option<crate::atoms::CommandObservation>,
}

impl ClockReadFailure {
    fn signal(&self) -> String {
        match self.command.as_ref() {
            Some(command) if !command.ok && command.code.is_none() => {
                format!("timedatectl-{}-exit-status-unavailable", self.phase)
            }
            _ => format!("timedatectl-{}-failed", self.phase),
        }
    }

    fn detail(&self) -> String {
        let command = self
            .command
            .as_ref()
            .map(command_value)
            .unwrap_or(Value::Null);
        format!("{} command={command}", self.reason)
    }
}

fn require_homeserver_authority(profile: &Profile) -> Result<String, String> {
    let certificate_profile = crate::device_profile::certificate_profile()?;
    if certificate_profile != "homeserver" {
        return Err(format!(
            "homeserver-clock-utc-certificate-profile-required actual={certificate_profile}"
        ));
    }
    if !profile.modules.iter().any(|module| module == MODULE_ID) {
        return Err("homeserver-clock-utc-module-authority-absent household-time".to_string());
    }
    Ok(certificate_profile)
}

fn timedatectl_program() -> Result<String, String> {
    match std::env::var("HARMONIA_CLOCK_TIMEDATECTL") {
        Ok(program) if !program.trim().is_empty() => Ok(program),
        Ok(_) => Err("homeserver-clock-utc-timedatectl-override-empty".to_string()),
        Err(std::env::VarError::NotPresent) => Ok(TIMEDATECTL_DEFAULT.to_string()),
        Err(error) => Err(format!(
            "homeserver-clock-utc-timedatectl-override-invalid: {error}"
        )),
    }
}

fn command_value(command: &crate::atoms::CommandObservation) -> Value {
    json!({
        "program": command.program,
        "argv": command.args,
        "exit_code": command.code,
        "signal": Value::Null,
        "signal_observation": if command.code.is_none() && !command.ok {
            json!("not-reported-by-command-helper")
        } else {
            Value::Null
        },
        "ok": command.ok,
        "stdout": command.stdout,
        "stderr": command.stderr,
    })
}

fn command_failure_value(
    phase: &'static str,
    program: &str,
    args: &[String],
    error: &str,
) -> Value {
    json!({
        "phase": phase,
        "program": program,
        "argv": args,
        "exit_code": Value::Null,
        "signal": Value::Null,
        "signal_observation": "not-reported-by-command-helper",
        "error": error,
    })
}

fn observe_timezone_with_program(
    program: &str,
    phase: &'static str,
) -> Result<String, ClockReadFailure> {
    let args = vec![
        "show".to_string(),
        "--property=Timezone".to_string(),
        "--value".to_string(),
    ];
    let command = crate::atoms::ask::read_only_command_with_timeout_and_limit(
        program,
        &args,
        Duration::from_secs(COMMAND_TIMEOUT_SECS),
        OBSERVATION_LIMIT,
    );
    if !command.ok || command.code != Some(0) {
        return Err(ClockReadFailure {
            phase,
            reason: format!(
                "timedatectl-{phase}-failed exit_code={:?} stderr={:?}",
                command.code, command.stderr
            ),
            command: Some(command),
        });
    }
    if command.stdout.len() >= OBSERVATION_LIMIT {
        return Err(ClockReadFailure {
            phase,
            reason: format!("timedatectl-{phase}-output-limit-reached"),
            command: Some(command),
        });
    }
    let timezone = command.stdout.trim();
    if timezone.is_empty() || timezone.chars().any(char::is_control) {
        return Err(ClockReadFailure {
            phase,
            reason: format!("timedatectl-{phase}-timezone-empty-or-malformed"),
            command: Some(command),
        });
    }
    Ok(timezone.to_string())
}

fn marker_from_item(item: &Interactable) -> Option<HomeserverClockUtcMarker> {
    serde_json::from_value(item.extra.get(MARKER_FIELD)?.clone()).ok()
}

pub(crate) fn is_generated_proposal(item: &Interactable) -> bool {
    if item.id != INTERACTABLE_ID || item.module_id != MODULE_ID || item.kind != "hard-stamp" {
        return false;
    }
    marker_from_item(item).is_some_and(|marker| {
        marker.profile == "homeserver"
            && marker.desired_timezone == DESIRED_TIMEZONE
            && !marker.observed_timezone.trim().is_empty()
            && !is_utc_timezone(&marker.observed_timezone)
    })
}

fn is_utc_timezone(timezone: &str) -> bool {
    matches!(timezone, "UTC" | "Etc/UTC")
}

fn validate_marker(item: &Interactable) -> Result<HomeserverClockUtcMarker, String> {
    if item.id != INTERACTABLE_ID || item.kind != "hard-stamp" || item.module_id != MODULE_ID {
        return Err("homeserver-clock-utc-interactable-binding-invalid".to_string());
    }
    let marker =
        marker_from_item(item).ok_or_else(|| "homeserver-clock-utc-marker-invalid".to_string())?;
    if marker.profile != "homeserver"
        || marker.desired_timezone != DESIRED_TIMEZONE
        || marker.observed_timezone.trim().is_empty()
        || is_utc_timezone(&marker.observed_timezone)
    {
        return Err("homeserver-clock-utc-marker-binding-invalid".to_string());
    }
    Ok(marker)
}

pub(crate) fn reconcile_for_update(profile: &Profile) {
    let started = Instant::now();
    let result = (|| {
        if crate::device_profile::certificate_profile()? != "homeserver" {
            return Ok(());
        }
        reconcile_profile(profile).map(|_| ())
    })();
    if let Err(reason) = result {
        let signal = reconcile_failure_signal(&reason);
        let duration_ms = started.elapsed().as_millis();
        let _ = writeln!(
            std::io::stderr().lock(),
            "actor=harmonia verb=reconcile target={INTERACTABLE_ID} outcome=failed duration_ms={duration_ms} id={INTERACTABLE_ID} signal={signal}"
        );
    }
}

pub(crate) fn reconcile_from_certificate(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        let reason = "interactable reconcile accepts no profile or other arguments".to_string();
        return emit_reconcile_refusal(&reason);
    }
    let (profile, _) = match crate::device_profile::resolve_certificate_profile() {
        Ok(resolved) => resolved,
        Err(reason) => return emit_reconcile_refusal(&reason),
    };
    if let Err(reason) = require_homeserver_authority(&profile) {
        return emit_reconcile_refusal(&reason);
    }
    match reconcile_profile(&profile) {
        Ok(summary) => {
            println!(
                "{}",
                serde_json::to_string(&reconcile_receipt(&summary))
                    .map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Err(reason) => emit_reconcile_refusal(&reason),
    }
}

fn reconcile_receipt(summary: &ReconcileSummary) -> Value {
    json!({
        "schema": "harmonia.config_state.receipt.v1",
        "config_state": "interactable",
        "id": INTERACTABLE_ID,
        "target": Value::Null,
        "reference_id": Value::Null,
        "score": Value::Null,
        "kind": "hard-stamp",
        "before": summary.observed_timezone,
        "after": summary.observed_timezone,
        "actuator": {
            "has_run": false,
            "changed": summary.changed,
            "kind": "hard-stamp",
            "observed": {
                "profile": summary.profile,
                "timezone": summary.observed_timezone,
            },
            "could-change": "offer or remove the HomeServer UTC timezone interactable",
            "attempt": [],
            "final-state": {
                "timezone": summary.observed_timezone,
                "proposal_id": summary.proposal_id,
                "proposal_state": summary.proposal_state,
            },
        },
        "ok": summary.ok,
        "first_missing_signal": "none",
    })
}

fn emit_reconcile_refusal(reason: &str) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "harmonia.config_state.receipt.v1",
            "config_state": "interactable",
            "id": INTERACTABLE_ID,
            "target": Value::Null,
            "reference_id": Value::Null,
            "score": Value::Null,
            "kind": "hard-stamp",
            "ok": false,
            "first_missing_signal": reason,
        }))
        .map_err(|error| error.to_string())?
    );
    Err(reason.to_string())
}

fn reconcile_failure_signal(reason: &str) -> String {
    if reason.starts_with("homeserver-clock-utc-proposal-persistence-failed") {
        "homeserver-clock-utc-proposal-persistence-failed".to_string()
    } else if reason.contains("proposal-id-collision") {
        "homeserver-clock-utc-proposal-id-collision".to_string()
    } else if reason.starts_with("interactables-feed-") {
        "homeserver-clock-utc-feed-observation-failed".to_string()
    } else if reason.starts_with("timedatectl-read-") {
        "homeserver-clock-utc-timedatectl-read-failed".to_string()
    } else if reason.starts_with("homeserver-clock-utc-timedatectl-override-") {
        "homeserver-clock-utc-timedatectl-override-failed".to_string()
    } else if reason.starts_with("device-profile-certificate-")
        || reason.starts_with("device-profile-profile-")
        || reason.starts_with("homeserver-clock-utc-certificate-profile-")
    {
        "homeserver-clock-utc-certificate-failed".to_string()
    } else if reason.starts_with("homeserver-clock-utc-module-authority-") {
        "homeserver-clock-utc-module-authority-failed".to_string()
    } else {
        "homeserver-clock-utc-reconcile-failed".to_string()
    }
}

fn reconcile_profile(profile: &Profile) -> Result<ReconcileSummary, String> {
    require_homeserver_authority(profile)?;
    let program = timedatectl_program()?;
    let timezone = observe_timezone_with_program(&program, "read")
        .map_err(|failure| format!("{}: {}", failure.signal(), failure.detail()))?;
    reconcile_observation(profile, &timezone)
}

fn reconcile_observation(
    profile: &Profile,
    observed_timezone: &str,
) -> Result<ReconcileSummary, String> {
    require_homeserver_authority(profile)?;
    if observed_timezone.trim().is_empty() {
        return Err("homeserver-clock-utc-observed-timezone-empty".to_string());
    }
    let path = crate::interactables::feed_path_for_command();
    let feed = crate::interactables::load_feed_raw(&path)?;
    let matching = feed
        .interactables
        .iter()
        .filter(|item| item.id == INTERACTABLE_ID)
        .collect::<Vec<_>>();
    if matching.iter().any(|item| !is_generated_proposal(item)) {
        return Err("homeserver-clock-utc-proposal-id-collision".to_string());
    }
    let matching_ids = matching
        .iter()
        .map(|item| item.id.clone())
        .collect::<BTreeSet<_>>();

    if is_utc_timezone(observed_timezone) {
        let changed = !matching.is_empty();
        if changed {
            crate::bands::propose_edits::persist_feed_with_intent(
                &path,
                crate::bands::propose_edits::FeedPersistenceIntent::Remove {
                    ids: matching_ids,
                    receipts: Vec::new(),
                },
            )
            .map_err(|error| {
                format!("homeserver-clock-utc-proposal-persistence-failed: {error}")
            })?;
        }
        return Ok(ReconcileSummary {
            ok: true,
            profile: profile.id.clone(),
            observed_timezone: observed_timezone.to_string(),
            desired_timezone: DESIRED_TIMEZONE.to_string(),
            proposal_id: None,
            proposal_state: if changed { "removed" } else { "absent" },
            changed,
        });
    }

    let mut prior = matching.first().map(|item| (*item).clone());
    let name = format!("Set this HomeServer timezone from {observed_timezone} to UTC");
    let description = format!(
        "This HomeServer reports timezone {observed_timezone}. Press to set this body to UTC."
    );
    let mut marker = prior
        .as_ref()
        .and_then(marker_from_item)
        .unwrap_or_else(|| HomeserverClockUtcMarker {
            profile: "homeserver".to_string(),
            observed_timezone: String::new(),
            desired_timezone: DESIRED_TIMEZONE.to_string(),
            extra: serde_json::Map::new(),
        });
    marker.profile = "homeserver".to_string();
    marker.observed_timezone = observed_timezone.to_string();
    marker.desired_timezone = DESIRED_TIMEZONE.to_string();
    let marker_value = serde_json::to_value(&marker).map_err(|error| error.to_string())?;
    let now = crate::bands::propose_edits::iso8601_now();
    let mut item = match prior.take() {
        Some(item) => item,
        None => Interactable {
            id: INTERACTABLE_ID.to_string(),
            module_id: MODULE_ID.to_string(),
            name: name.clone(),
            description: description.clone(),
            kind: "hard-stamp".to_string(),
            target_path: None,
            reference_source_path: None,
            drift: DriftSummary {
                content: true,
                mode: false,
                ownership: false,
            },
            created_at: now.clone(),
            refreshed_at: now.clone(),
            available_at: Some(now.clone()),
            silenced: false,
            silenced_at: None,
            has_run: false,
            mode: None,
            owner: None,
            group: None,
            source_sha: None,
            target_sha: None,
            commits_behind: None,
            live_sha: None,
            reference_sha: None,
            recognition_score: None,
            diff: None,
            script: String::new(),
            show_only_if: String::new(),
            completion_check: String::new(),
            evidence: Value::Null,
            extra: serde_json::Map::new(),
        },
    };
    for duplicate in matching.iter().skip(1) {
        for (key, value) in &duplicate.extra {
            item.extra
                .entry(key.clone())
                .or_insert_with(|| value.clone());
        }
    }
    item.id = INTERACTABLE_ID.to_string();
    item.module_id = MODULE_ID.to_string();
    item.name = name;
    item.description = description;
    item.kind = "hard-stamp".to_string();
    item.target_path = None;
    item.reference_source_path = None;
    item.drift = DriftSummary {
        content: true,
        mode: false,
        ownership: false,
    };
    item.diff = Some(format!(
        "observed timezone={observed_timezone}; desired timezone={DESIRED_TIMEZONE}"
    ));
    item.script = format!("harmonia interactable run {INTERACTABLE_ID}");
    item.show_only_if = "profile=homeserver;timezone!=UTC;timezone!=Etc/UTC".to_string();
    item.completion_check = "timezone=UTC-or-Etc/UTC".to_string();
    item.extra.insert(MARKER_FIELD.to_string(), marker_value);

    let previous = matching.first().map(|item| serde_json::to_value(item));
    let current = serde_json::to_value(&item).map_err(|error| error.to_string())?;
    let unchanged = previous
        .transpose()
        .map_err(|error| error.to_string())?
        .is_some_and(|previous| previous == current)
        && matching.len() == 1;
    if unchanged {
        return Ok(ReconcileSummary {
            ok: true,
            profile: profile.id.clone(),
            observed_timezone: observed_timezone.to_string(),
            desired_timezone: DESIRED_TIMEZONE.to_string(),
            proposal_id: Some(INTERACTABLE_ID.to_string()),
            proposal_state: "current",
            changed: false,
        });
    }
    if !matching.is_empty() {
        item.refreshed_at = crate::bands::propose_edits::iso8601_now();
    }
    let mut remove_ids = BTreeSet::new();
    if !matching.is_empty() {
        remove_ids.insert(INTERACTABLE_ID.to_string());
    }
    crate::bands::propose_edits::persist_feed_with_intent(
        &path,
        crate::bands::propose_edits::FeedPersistenceIntent::Upsert {
            entries: vec![item],
            remove_ids,
            sort_by_id: true,
        },
    )
    .map_err(|error| format!("homeserver-clock-utc-proposal-persistence-failed: {error}"))?;
    Ok(ReconcileSummary {
        ok: true,
        profile: profile.id.clone(),
        observed_timezone: observed_timezone.to_string(),
        desired_timezone: DESIRED_TIMEZONE.to_string(),
        proposal_id: Some(INTERACTABLE_ID.to_string()),
        proposal_state: if matching.is_empty() {
            "offered"
        } else {
            "refreshed"
        },
        changed: true,
    })
}

fn run_receipt(
    before: Option<&str>,
    after: Option<&str>,
    observed: Value,
    attempt: Vec<Value>,
    changed: bool,
    ok: bool,
    first_missing_signal: Option<String>,
    proposal_removed: bool,
    proposal_retained: bool,
) -> Value {
    json!({
        "schema": "harmonia.config_state.receipt.v1",
        "config_state": "interactable",
        "id": INTERACTABLE_ID,
        "target": Value::Null,
        "reference_id": Value::Null,
        "score": Value::Null,
        "kind": "hard-stamp",
        "before": before,
        "after": after,
        "actuator": {
            "has_run": true,
            "changed": changed,
            "kind": "hard-stamp",
            "observed": observed,
            "could-change": "set this body's timezone to UTC using timedatectl",
            "attempt": attempt,
            "final-state": {
                "timezone": after,
                "converged": after.is_some_and(is_utc_timezone),
                "proposal_removed": proposal_removed,
                "proposal_retained": proposal_retained,
            },
        },
        "ok": ok,
        "first_missing_signal": first_missing_signal.unwrap_or_else(|| "none".to_string()),
    })
}

fn emit_run_receipt(receipt: &Value) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(receipt).map_err(|error| error.to_string())?
    );
    if receipt.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(receipt
            .get("first_missing_signal")
            .and_then(Value::as_str)
            .unwrap_or("homeserver-clock-utc-refused")
            .to_string())
    }
}

fn read_failure_receipt(
    phase: &'static str,
    failure: &ClockReadFailure,
    before: Option<&str>,
    attempt: Vec<Value>,
    after: Option<&str>,
    changed: bool,
    proposal_retained: bool,
) -> Value {
    run_receipt(
        before,
        after,
        json!({
            "phase": phase,
            "error": failure.reason,
            "command": failure.command.as_ref().map(command_value),
        }),
        attempt,
        changed,
        false,
        Some(failure.signal()),
        false,
        proposal_retained,
    )
}

fn run_refusal_receipt(reason: &str) -> Value {
    run_receipt(
        None,
        None,
        json!({"phase":"preflight","error":reason}),
        Vec::new(),
        false,
        false,
        Some(reason.to_string()),
        false,
        true,
    )
}

pub(crate) fn run(
    _path: &Path,
    item: &Interactable,
    invocation: Option<&crate::Invocation>,
) -> Result<(), String> {
    if item.id != INTERACTABLE_ID || !item.extra.contains_key(MARKER_FIELD) {
        return emit_run_receipt(&run_refusal_receipt(
            "homeserver-clock-utc-dispatch-binding-invalid",
        ));
    }
    let marker = match validate_marker(item) {
        Ok(marker) => marker,
        Err(reason) => return emit_run_receipt(&run_refusal_receipt(&reason)),
    };
    let invocation_key = match invocation.and_then(crate::Invocation::key) {
        Some(key) => key,
        None => {
            return emit_run_receipt(&run_refusal_receipt(
                "homeserver-clock-utc-operator-invocation-required",
            ));
        }
    };
    let (profile, _) = match crate::device_profile::resolve_certificate_profile() {
        Ok(resolved) => resolved,
        Err(reason) => return emit_run_receipt(&run_refusal_receipt(&reason)),
    };
    let certificate_profile = match require_homeserver_authority(&profile) {
        Ok(certificate_profile) => certificate_profile,
        Err(reason) => return emit_run_receipt(&run_refusal_receipt(&reason)),
    };
    if marker.profile != certificate_profile {
        let reason = format!(
            "homeserver-clock-utc-profile-stale expected={} actual={}",
            certificate_profile, marker.profile
        );
        return emit_run_receipt(&run_refusal_receipt(&reason));
    }
    let program = match timedatectl_program() {
        Ok(program) => program,
        Err(reason) => return emit_run_receipt(&run_refusal_receipt(&reason)),
    };
    let before = match observe_timezone_with_program(&program, "read") {
        Ok(timezone) => timezone,
        Err(failure) => {
            let receipt =
                read_failure_receipt("before", &failure, None, Vec::new(), None, false, true);
            return emit_run_receipt(&receipt);
        }
    };
    if let Err(reason) = reconcile_observation(&profile, &before) {
        let receipt = run_receipt(
            Some(&before),
            None,
            json!({"phase":"proposal-reconcile","timezone":before,"error":reason}),
            Vec::new(),
            false,
            false,
            Some(reconcile_failure_signal(&reason)),
            false,
            true,
        );
        return emit_run_receipt(&receipt);
    }
    if is_utc_timezone(&before) {
        let receipt = run_receipt(
            Some(&before),
            Some(&before),
            json!({"timezone":before,"setter_skipped":"already-utc"}),
            Vec::new(),
            false,
            true,
            None,
            true,
            false,
        );
        return emit_run_receipt(&receipt);
    }

    // The press observes again immediately before comparing and authorizing the
    // one bounded setter. This read is independent of Ruyi and source acquisition.
    let current = match observe_timezone_with_program(&program, "read") {
        Ok(timezone) => timezone,
        Err(failure) => {
            let receipt = read_failure_receipt(
                "before-set",
                &failure,
                Some(&before),
                Vec::new(),
                None,
                false,
                true,
            );
            return emit_run_receipt(&receipt);
        }
    };
    if let Err(reason) = reconcile_observation(&profile, &current) {
        let receipt = run_receipt(
            Some(&current),
            None,
            json!({"phase":"proposal-reconcile-before-set","timezone":current,"error":reason}),
            Vec::new(),
            false,
            false,
            Some(reconcile_failure_signal(&reason)),
            false,
            true,
        );
        return emit_run_receipt(&receipt);
    }
    if is_utc_timezone(&current) {
        let receipt = run_receipt(
            Some(&before),
            Some(&current),
            json!({"timezone_before":before,"timezone_before_set":current,"setter_skipped":"already-utc"}),
            Vec::new(),
            before != current,
            true,
            None,
            true,
            false,
        );
        return emit_run_receipt(&receipt);
    }

    let args = vec!["set-timezone".to_string(), DESIRED_TIMEZONE.to_string()];
    let comparison = crate::atoms::comparison::execute_once(
        "homeserver-clock-utc",
        || Ok::<_, String>(current.clone()),
        |timezone| {
            if is_utc_timezone(timezone) {
                crate::atoms::comparison::DiffDecision::Empty
            } else {
                crate::atoms::comparison::DiffDecision::Different
            }
        },
        |authorization, _| {
            Ok(crate::atoms::command::authorized_capture(
                &authorization,
                invocation_key,
                &program,
                &args,
                None,
                Duration::from_secs(COMMAND_TIMEOUT_SECS),
                None,
                None,
            ))
        },
    )
    .map_err(|error| format!("homeserver-clock-utc-comparison-failed: {error}"))?;
    let attempted = match comparison {
        crate::atoms::comparison::ComparisonRun::Current { observation, .. } => {
            // This branch is defensive; current was freshly observed non-UTC.
            if let Err(reason) = reconcile_observation(&profile, &observation) {
                let receipt = run_receipt(
                    Some(&observation),
                    Some(&observation),
                    json!({"timezone":observation,"setter_skipped":"already-utc"}),
                    Vec::new(),
                    false,
                    false,
                    Some(reconcile_failure_signal(&reason)),
                    false,
                    true,
                );
                return emit_run_receipt(&receipt);
            }
            let receipt = run_receipt(
                Some(&observation),
                Some(&observation),
                json!({"timezone":observation,"setter_skipped":"already-utc"}),
                Vec::new(),
                false,
                true,
                None,
                true,
                false,
            );
            return emit_run_receipt(&receipt);
        }
        crate::atoms::comparison::ComparisonRun::Moved { movement, .. } => movement,
    };
    let attempt = match &attempted {
        Ok(command) => vec![command_value(command)],
        Err(error) => vec![command_failure_value("set", &program, &args, error)],
    };
    let set_ok = attempted
        .as_ref()
        .is_ok_and(|command| command.ok && command.code == Some(0));
    let after = match observe_timezone_with_program(&program, "readback") {
        Ok(timezone) => Some(timezone),
        Err(failure) => {
            let receipt = read_failure_receipt(
                "readback",
                &failure,
                Some(&current),
                attempt,
                None,
                false,
                true,
            );
            return emit_run_receipt(&receipt);
        }
    };
    let after = after.expect("successful readback is present");
    let changed = after != current;
    let mut proposal_removed = false;
    let mut proposal_retained = true;
    let mut proposal_failure = None;
    if set_ok && is_utc_timezone(&after) {
        match reconcile_observation(&profile, &after) {
            Ok(_) => {
                proposal_removed = true;
                proposal_retained = false;
            }
            Err(reason) => {
                proposal_failure = Some(format!("{}: {reason}", reconcile_failure_signal(&reason)));
            }
        }
    } else if set_ok {
        if let Err(reason) = reconcile_observation(&profile, &after) {
            proposal_failure = Some(format!("{}: {reason}", reconcile_failure_signal(&reason)));
        }
    }
    let set_failure = match attempted.as_ref() {
        Ok(command) if !set_ok => Some(format!(
            "timedatectl-set-failed exit_code={:?} stderr={:?}",
            command.code, command.stderr
        )),
        Err(error) => Some(format!("timedatectl-set-command-failed: {error}")),
        _ => None,
    };
    let readback_failure =
        (!is_utc_timezone(&after) && set_ok).then(|| "timedatectl-readback-not-utc".to_string());
    let first_missing_signal = set_failure
        .or(readback_failure)
        .or(proposal_failure.clone());
    let ok = set_ok && is_utc_timezone(&after) && proposal_failure.is_none() && proposal_removed;
    let receipt = run_receipt(
        Some(&current),
        Some(&after),
        json!({
            "timezone_before_set": current,
            "timezone_after_set": after,
            "set_ok": set_ok,
            "set_command": attempted.as_ref().map(command_value).unwrap_or_else(|error| json!({"error":error})),
            "proposal_reconciliation_failure": proposal_failure,
        }),
        attempt,
        changed,
        ok,
        first_missing_signal,
        proposal_removed,
        proposal_retained,
    );
    emit_run_receipt(&receipt)
}
