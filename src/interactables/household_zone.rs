use super::{DriftSummary, Interactable};
use crate::Profile;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

pub(crate) const INTERACTABLE_ID: &str = "household-zone-resolve";
pub(crate) const SET_INTERACTABLE_ID: &str = "household-zone-set";
const MODULE_ID: &str = "household-time";
const MARKER: &str = "household_zone_role";

#[derive(Clone)]
enum Fact {
    Fresh,
    Stale { zone: Value, observed_at: Value, valid_until: Value },
}

fn authority(profile: &Profile) -> Result<(), String> {
    if crate::device_profile::certificate_product()? != "homeserver"
        || !profile.modules.iter().any(|module| module == MODULE_ID)
    {
        return Err("household-zone-homeserver-authority-required".into());
    }
    Ok(())
}

fn valid_utc(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() != 20 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T'
        || bytes[13] != b':' || bytes[16] != b':' || bytes[19] != b'Z'
        || bytes.iter().enumerate().any(|(i, b)| ![4, 7, 10, 13, 16, 19].contains(&i) && !b.is_ascii_digit())
    {
        return None;
    }
    let year: u32 = value[0..4].parse().ok()?;
    let month: u32 = value[5..7].parse().ok()?;
    let day: u32 = value[8..10].parse().ok()?;
    let hour: u32 = value[11..13].parse().ok()?;
    let minute: u32 = value[14..16].parse().ok()?;
    let second: u32 = value[17..19].parse().ok()?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month { 1 | 3 | 5 | 7 | 8 | 10 | 12 => 31, 4 | 6 | 9 | 11 => 30, 2 if leap => 29, 2 => 28, _ => return None };
    if year == 0 || day == 0 || day > days || hour > 23 || minute > 59 || second > 59 { return None; }
    crate::tools::household_time::parse_utc(value)
}

fn observe() -> Result<Fact, String> {
    let program = std::env::var("HARMONIA_CLOCK_CADUCEUS")
        .unwrap_or_else(|_| "/usr/local/bin/caduceus".into());
    let result = crate::atoms::ask::read_only_command_with_timeout_and_limit(
        &program, &["time".into(), "state".into()], Duration::from_secs(15), 65536,
    );
    if !result.ok || result.code != Some(0) || result.stdout.len() >= 65536 {
        return Err("household-zone-state-command-failed".into());
    }
    let value: Value = serde_json::from_str(&result.stdout)
        .map_err(|_| "household-zone-state-json-invalid".to_string())?;
    if value.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err("household-zone-state-refused".into());
    }
    let state = value.get("state").unwrap_or(&value);
    if state.is_null() {
        return Ok(Fact::Stale { zone: Value::Null, observed_at: Value::Null, valid_until: Value::Null });
    }
    let object = state.as_object().ok_or("household-zone-state-invalid")?;
    let zone = object.get("timezone").filter(|v| !v.is_null());

    if zone.is_none() {
        return Ok(Fact::Stale { zone: Value::Null, observed_at: Value::Null, valid_until: Value::Null });
    }
    let zone = zone.and_then(Value::as_str).ok_or("household-zone-timezone-invalid")?;
    crate::tools::household_time::validate_timezone(zone)?;
    Ok(Fact::Fresh)
}

pub(crate) fn is_generated_proposal(item: &Interactable) -> bool {
    item.id == INTERACTABLE_ID && item.module_id == MODULE_ID && item.kind == "household-zone"
        && item.target_path.is_none() && item.extra.get(MARKER).and_then(Value::as_str) == Some("resolve")
}

fn reconcile(fact: Option<&Fact>) -> Result<(), String> {
    let path = crate::ledger::database_path();
    let feed = super::load_feed_raw(&path)?;
    let matching: Vec<_> = feed.interactables.iter().filter(|item| item.id == INTERACTABLE_ID).collect();
    if matching.iter().any(|item| !is_generated_proposal(item)) {
        return Err("household-zone-proposal-id-collision".into());
    }
    let ids = matching.iter().map(|item| item.id.clone()).collect::<BTreeSet<_>>();
    let Some(Fact::Stale { zone, observed_at, valid_until }) = fact else {
        if !ids.is_empty() {
            crate::bands::propose_edits::persist_feed_with_intent(&path,
                crate::bands::propose_edits::FeedPersistenceIntent::Remove { ids, receipts: Vec::new() })?;
        }
        return Ok(());
    };
    let now = crate::bands::propose_edits::iso8601_now();
    let mut item = matching.first().map(|item| (*item).clone()).unwrap_or_else(|| Interactable {
        id: INTERACTABLE_ID.into(), module_id: MODULE_ID.into(),
        name: "Refresh the household timezone".into(),
        description: "The household timezone observation is absent or stale. Press to refresh it.".into(),
        kind: "household-zone".into(), target_path: None, reference_source_path: None,
        drift: DriftSummary { content: true, mode: false, ownership: false },
        created_at: now.clone(), refreshed_at: now.clone(), available_at: Some(now.clone()),
        silenced: false, silenced_at: None, has_run: false, mode: None, owner: None, group: None,
        source_sha: None, target_sha: None, commits_behind: None, live_sha: None, reference_sha: None,
        recognition_score: None, diff: Some("household timezone fact: stale -> refreshed".into()),
        script: format!("harmonia interactable run {INTERACTABLE_ID}"),
        show_only_if: "profile=homeserver;household-zone=stale".into(),
        completion_check: "household-zone=fresh".into(), evidence: Value::Null,
        extra: serde_json::Map::new(),
    });
    let staged_at = item.evidence.get("staged_at").cloned().unwrap_or_else(|| json!(now));
    item.evidence = json!({"household_zone":zone,"observed_at":observed_at,"valid_until":valid_until,"staged_at":staged_at});
    item.extra.insert(MARKER.into(), json!("resolve"));
    if matching.len() == 1 && serde_json::to_value(matching[0]).ok() == serde_json::to_value(&item).ok() {
        return Ok(());
    }
    if !matching.is_empty() { item.refreshed_at = now; }
    crate::bands::propose_edits::persist_feed_with_intent(&path,
        crate::bands::propose_edits::FeedPersistenceIntent::Upsert {
            entries: vec![item], remove_ids: ids, sort_by_id: true,
        })?;
    Ok(())
}

pub(crate) fn reconcile_for_update(profile: &Profile) {
    if face_authority(profile).is_ok() {
        let observed = observe_face();
        if let Err(reason) = &observed {
            let signal: String = reason.chars().flat_map(char::escape_default).take(700).collect();
            eprintln!("actor=harmonia verb=observe target={SET_INTERACTABLE_ID} outcome=refused signal={signal}");
        }
        if let Err(reason) = reconcile_set(observed.as_ref().ok()) {
            eprintln!("actor=harmonia verb=reconcile target={SET_INTERACTABLE_ID} outcome=failed signal={reason}");
        }
        return;
    }
    if let Err(reason) = reconcile_set(None) {
        eprintln!("actor=harmonia verb=reconcile target={SET_INTERACTABLE_ID} outcome=failed signal={reason}");
    }
    if authority(profile).is_err() { return; }
    let fact = observe();
    let result = reconcile(fact.as_ref().ok());
    if let Err(reason) = fact.map(|_| ()).and(result) {
        eprintln!("actor=harmonia verb=reconcile target={INTERACTABLE_ID} outcome=failed signal={reason}");
    }
}

fn face_authority(profile: &Profile) -> Result<(), String> {
    if !matches!(crate::device_profile::certificate_product()?.as_str(), "hometv" | "homesi" | "homeconsole")
        || !profile.modules.iter().any(|module| module == MODULE_ID)
    {
        return Err("household-zone-face-authority-required".into());
    }
    Ok(())
}

#[derive(Clone)]
struct FaceFact {
    zone: String,
    observed_at: Value,
    valid_until: Value,
    face_zone: String,
}

pub(crate) fn require_follow_mode() -> Result<(), String> {
    let config: Value = serde_json::from_slice(&std::fs::read("/etc/appliance/config.json")
        .map_err(|_| "household-zone-mode-unreadable")?)
        .map_err(|_| "household-zone-mode-invalid")?;
    let root = config.as_object().ok_or("household-zone-mode-invalid")?;
    let mode = match root.get("time") {
        None => "follow",
        Some(value) => match value.as_object().ok_or("household-zone-mode-invalid")?.get("zone_mode") {
            None => "follow",
            Some(value) => value.as_str().ok_or("household-zone-mode-invalid")?,
        },
    };
    if mode != "follow" { return Err("household-zone-not-following".into()); }
    Ok(())
}

// Unresolved authority never permits a retained face proposal or an action.
pub(crate) fn reconcile_unavailable_profile() {
    if let Err(reason) = reconcile_set(None) {
        eprintln!("actor=harmonia verb=reconcile target={SET_INTERACTABLE_ID} outcome=failed signal={reason}");
    }
}

fn observe_face() -> Result<FaceFact, String> {
    require_follow_mode()?;
    let (profile, profile_path) = crate::device_profile::resolve_certificate_profile()?;
    face_authority(&profile)?;
    let path = crate::default_module_root(&profile_path).join(MODULE_ID).join("manifest.json");
    let manifest: Value = serde_json::from_slice(&std::fs::read(path)
        .map_err(|_| "household-zone-manifest-unreadable")?)
        .map_err(|_| "household-zone-manifest-invalid")?;
    let step = manifest.get("ladder").and_then(Value::as_array)
        .and_then(|steps| steps.iter().find(|step| step.get("tool").and_then(Value::as_str) == Some("household-time")
            && step.get("permutation").and_then(Value::as_str) == Some("watch-and-set")))
        .ok_or("household-zone-manifest-step-absent")?;
    let raw_url = step.pointer("/args/state_url").and_then(Value::as_str).ok_or("household-zone-url-absent")?;
    let url = if let Some(name) = raw_url.strip_prefix("$constants.") {
        manifest.get("constants").and_then(|value| value.get(name)).and_then(Value::as_str)
            .ok_or("household-zone-url-absent")?
    } else { raw_url };
    if !(url.starts_with("http://") || url.starts_with("https://")) || url.contains(char::is_whitespace)
        || url.contains('?') || url.contains('#') {
        return Err("household-zone-url-invalid".into());
    }
    let timeout = step.pointer("/args/timeout_secs").and_then(Value::as_u64).unwrap_or(10);
    if timeout == 0 || timeout > 60 { return Err("household-zone-timeout-invalid".into()); }
    let request = crate::atoms::r#do::set_clock::Request {
        backend: "caduceus", operation: "watch-and-set", timezone: None,
        state_url: Some(url), state_path: None, timeout_secs: timeout,
    };
    let observation = crate::atoms::ask::set_clock::clock(&request);
    let remote = observation.remote_state.ok_or("household-zone-peer-unreadable")?;
    if !remote.ok || remote.code != 0 { return Err("household-zone-peer-unreadable".into()); }
    let zone = crate::tools::household_time::fresh_timezone(&remote.stdout).ok_or("household-zone-peer-stale")?;
    if zone.split('/').any(|part| part == "." || part == "..") {
        return Err("household-zone-peer-invalid".into());
    }
    let value: Value = serde_json::from_str(&remote.stdout).map_err(|_| "household-zone-peer-invalid")?;
    let state = value.get("state").unwrap_or(&value);
    let until = state.get("valid_until").cloned().unwrap_or(Value::Null);
    if !observation.local_state.ok || observation.local_state.code != Some(0) {
        return Err("household-zone-face-clock-unreadable".into());
    }
    let face_zone = observation.timezone.filter(|zone| !zone.is_empty() && zone.split('/').all(|part|
        !part.is_empty() && part != "." && part != ".." && part.chars().all(|c|
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))))
        .ok_or("household-zone-face-clock-invalid")?;
    Ok(FaceFact { zone, observed_at: state.get("observed_at").cloned().unwrap_or(Value::Null),
        valid_until: until, face_zone })
}

pub(crate) fn is_generated_set_proposal(item: &Interactable) -> bool {
    item.id == SET_INTERACTABLE_ID && item.module_id == MODULE_ID && item.kind == "household-zone"
        && item.target_path.as_deref() == Some(Path::new("/etc/localtime"))
        && item.extra.get(MARKER).and_then(Value::as_str) == Some("set")
}

fn reconcile_set(fact: Option<&FaceFact>) -> Result<(), String> {
    let path = crate::ledger::database_path();
    let feed = super::load_feed_raw(&path)?;
    let matching: Vec<_> = feed.interactables.iter().filter(|item| item.id == SET_INTERACTABLE_ID).collect();
    if matching.iter().any(|item| !is_generated_set_proposal(item)) {
        return Err("household-zone-set-proposal-id-collision".into());
    }
    let ids = matching.iter().map(|item| item.id.clone()).collect::<BTreeSet<_>>();
    let Some(fact) = fact.filter(|fact| fact.zone != fact.face_zone) else {
        if !ids.is_empty() {
            crate::bands::propose_edits::persist_feed_with_intent(&path,
                crate::bands::propose_edits::FeedPersistenceIntent::Remove { ids, receipts: Vec::new() })?;
        }
        return Ok(());
    };
    let now = crate::bands::propose_edits::iso8601_now();
    let mut item = matching.first().map(|item| (*item).clone()).unwrap_or_else(|| Interactable {
        id: SET_INTERACTABLE_ID.into(), module_id: MODULE_ID.into(), name: "Use the household timezone".into(),
        description: "Set this device's timezone from the HomeServer.".into(), kind: "household-zone".into(),
        target_path: Some("/etc/localtime".into()), reference_source_path: None,
        drift: DriftSummary { content: true, mode: false, ownership: false },
        created_at: now.clone(), refreshed_at: now.clone(), available_at: Some(now.clone()),
        silenced: false, silenced_at: None, has_run: false, mode: None, owner: None, group: None,
        source_sha: None, target_sha: None, commits_behind: None, live_sha: None, reference_sha: None,
        recognition_score: None, diff: None, script: format!("harmonia interactable run {SET_INTERACTABLE_ID}"),
        show_only_if: "household-zone=follow-and-different".into(), completion_check: "household-zone=equal".into(),
        evidence: Value::Null, extra: serde_json::Map::new(),
    });
    let staged_at = item.evidence.get("staged_at").cloned().unwrap_or_else(|| json!(now));
    item.evidence = json!({"household_zone":fact.zone,"fact_observed_at":fact.observed_at,
        "fact_valid_until":fact.valid_until,"face_zone":fact.face_zone,"face_mode":"follow","staged_at":staged_at});
    item.diff = Some(format!("/etc/localtime -> /usr/share/zoneinfo/{}  =>  /usr/share/zoneinfo/{}", fact.face_zone, fact.zone));
    item.extra.insert(MARKER.into(), json!("set"));
    if matching.len() == 1 && serde_json::to_value(matching[0]).ok() == serde_json::to_value(&item).ok() { return Ok(()); }
    if !matching.is_empty() { item.refreshed_at = now; }
    crate::bands::propose_edits::persist_feed_with_intent(&path,
        crate::bands::propose_edits::FeedPersistenceIntent::Upsert { entries: vec![item], remove_ids: ids, sort_by_id: true })?;
    Ok(())
}

pub(crate) fn run_set(_path: &Path, item: &Interactable, invocation: Option<&crate::Invocation>) -> Result<(), String> {
    if !is_generated_set_proposal(item) { return Err("household-zone-set-binding-invalid".into()); }
    let key = invocation.and_then(crate::Invocation::key).ok_or("household-zone-owner-invocation-required")?;
    let (profile, _) = match crate::device_profile::resolve_certificate_profile() {
        Ok(profile) => profile,
        Err(reason) => { reconcile_unavailable_profile(); return Err(reason); }
    };
    face_authority(&profile)?;
    let before = match observe_face() { Ok(fact) => fact, Err(reason) => { reconcile_set(None)?; return Err(reason); } };
    if before.zone == before.face_zone {
        reconcile_set(Some(&before))?;
        println!("{}", json!({"id":SET_INTERACTABLE_ID,"ok":true,"changed":false,"converged":true}));
        return Ok(());
    }
    if let Err(reason) = require_follow_mode() {
        reconcile_set(None)?;
        return Err(reason);
    }

    let request = crate::atoms::r#do::set_clock::Request {
        backend: "caduceus", operation: "set-timezone", timezone: Some(&before.zone), state_url: None,
        state_path: None, timeout_secs: 15,
    };
    let comparison = crate::atoms::comparison::execute_once(
        "household-zone-set", || Ok::<_, String>(before.clone()),
        |fact| if fact.zone == fact.face_zone { crate::atoms::comparison::DiffDecision::Empty } else { crate::atoms::comparison::DiffDecision::Different },
        |authorization, fact| crate::atoms::r#do::set_clock::command(&authorization, key, &request, "set-timezone", Some(&fact.zone)),
    )?;
    let result = match comparison {
        crate::atoms::comparison::ComparisonRun::Moved { movement, .. } => movement,
        crate::atoms::comparison::ComparisonRun::Current { .. } => return Err("household-zone-observation-changed".into()),
    };
    let receipt = serde_json::from_str::<Value>(&result.stdout).ok();
    let changed = receipt.as_ref().and_then(|v| v.get("changed")).and_then(Value::as_bool);
    let success = result.ok && result.code == 0 && receipt.as_ref().and_then(|v| v.get("ok")).and_then(Value::as_bool) == Some(true) && changed.is_some();
    let after = match observe_face() {
        Ok(fact) => fact,
        Err(reason) => {
            reconcile_set(None)?;
            println!("{}", json!({"id":SET_INTERACTABLE_ID,"ok":false,"changed":changed,
                "converged":false,"first_missing_signal":reason}));
            return Err(reason);
        }
    };
    reconcile_set(Some(&after))?;
    let converged = after.face_zone == after.zone && after.zone == before.zone;
    println!("{}", json!({"id":SET_INTERACTABLE_ID,"ok":success && converged,"changed":changed,"converged":converged,"proposal_removed":after.face_zone == after.zone}));
    if !success { return Err("household-zone-set-failed".into()); }
    if !converged { return Err("household-zone-set-readback-mismatch".into()); }
    Ok(())
}

pub(crate) fn run(_path: &Path, item: &Interactable, invocation: Option<&crate::Invocation>) -> Result<(), String> {
    if !is_generated_proposal(item) { return Err("household-zone-binding-invalid".into()); }
    let key = invocation.and_then(crate::Invocation::key).ok_or("household-zone-owner-invocation-required")?;
    let (profile, _) = crate::device_profile::resolve_certificate_profile()?;
    authority(&profile)?;
    let before = match observe() {
        Ok(fact) => fact,
        Err(reason) => { reconcile(None)?; return Err(reason); }
    };
    if matches!(before, Fact::Fresh) {
        reconcile(Some(&before))?;
        println!("{}", json!({"id":INTERACTABLE_ID,"ok":true,"changed":false,"converged":true,"resolve":"skipped-already-fresh"}));
        return Ok(());
    }
    let request = crate::atoms::r#do::set_clock::Request {
        backend: "caduceus", operation: "resolve", timezone: None, state_url: None,
        state_path: None, timeout_secs: 15,
    };
    let comparison = crate::atoms::comparison::execute_once(
        "household-zone-resolve", || Ok::<_, String>(before.clone()),
        |fact| if matches!(fact, Fact::Fresh) { crate::atoms::comparison::DiffDecision::Empty } else { crate::atoms::comparison::DiffDecision::Different },
        |authorization, _| crate::atoms::r#do::set_clock::command(&authorization, key, &request, "resolve", None),
    );
    let after = match observe() {
        Ok(fact) => fact,
        Err(reason) => { reconcile(None)?; return Err(reason); }
    };
    reconcile(Some(&after))?;
    let result = match comparison? {
        crate::atoms::comparison::ComparisonRun::Moved { movement, .. } => movement,
        crate::atoms::comparison::ComparisonRun::Current { .. } => return Err("household-zone-observation-changed".into()),
    };
    let resolve_receipt = serde_json::from_str::<Value>(&result.stdout).ok();
    let changed = resolve_receipt.as_ref().and_then(|value| value.get("changed")).and_then(Value::as_bool);
    let resolve_ok = result.ok && result.code == 0 && changed.is_some()
        && resolve_receipt.as_ref().and_then(|value| value.get("ok")).and_then(Value::as_bool) == Some(true);
    let fresh = matches!(after, Fact::Fresh);
    println!("{}", json!({"id":INTERACTABLE_ID,"ok":resolve_ok && fresh,"changed":changed,"converged":fresh,"proposal_removed":fresh,"first_missing_signal":if !resolve_ok {"household-zone-resolve-failed"} else if !fresh {"household-zone-readback-stale"} else {"none"}}));
    if !resolve_ok { return Err("household-zone-resolve-failed".into()); }
    if !fresh { return Err("household-zone-readback-stale".into()); }
    Ok(())
}
