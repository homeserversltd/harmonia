use super::{DriftSummary, Interactable};
use crate::Profile;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

pub(crate) const INTERACTABLE_ID: &str = "household-zone-resolve";
const MODULE_ID: &str = "household-time";
const MARKER: &str = "household_zone_role";

#[derive(Clone)]
enum Fact {
    Fresh,
    Stale { zone: Value, observed_at: Value, valid_until: Value },
}

fn authority(profile: &Profile) -> Result<(), String> {
    if crate::device_profile::certificate_profile()? != "homeserver"
        || profile.id != "homeserver" || profile.identity != "homeserver"
        || !profile.modules.iter().any(|module| module == MODULE_ID)
    {
        return Err("household-zone-homeserver-authority-required".into());
    }
    Ok(())
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
    let valid = object.get("valid_until").filter(|v| !v.is_null());
    if zone.is_none() && valid.is_none() {
        return Ok(Fact::Stale { zone: Value::Null, observed_at: Value::Null, valid_until: Value::Null });
    }
    let zone = zone.and_then(Value::as_str).ok_or("household-zone-timezone-invalid")?;
    crate::tools::household_time::validate_timezone(zone)?;
    let valid = valid.and_then(Value::as_str).ok_or("household-zone-valid-until-invalid")?;
    let until = crate::tools::household_time::parse_utc(valid).ok_or("household-zone-valid-until-invalid")?;
    if until > crate::tools::household_time::unix_now() {
        return Ok(Fact::Fresh);
    }
    Ok(Fact::Stale {
        zone: json!(zone), observed_at: object.get("observed_at").cloned().unwrap_or(Value::Null), valid_until: json!(valid),
    })
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
    if authority(profile).is_err() { return; }
    let fact = observe();
    let result = reconcile(fact.as_ref().ok());
    if let Err(reason) = fact.map(|_| ()).and(result) {
        eprintln!("actor=harmonia verb=reconcile target={INTERACTABLE_ID} outcome=failed signal={reason}");
    }
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
    )?;
    let result = match comparison {
        crate::atoms::comparison::ComparisonRun::Moved { movement, .. } => movement,
        crate::atoms::comparison::ComparisonRun::Current { .. } => return Err("household-zone-observation-changed".into()),
    };
    let resolve_receipt = serde_json::from_str::<Value>(&result.stdout).ok();
    let resolve_ok = result.ok && result.code == 0
        && resolve_receipt.as_ref().and_then(|value| value.get("ok")).and_then(Value::as_bool) == Some(true);
    let changed = resolve_receipt.as_ref().and_then(|value| value.get("changed")).and_then(Value::as_bool).unwrap_or(false);
    let after = match observe() {
        Ok(fact) => fact,
        Err(reason) => { reconcile(None)?; return Err(reason); }
    };
    reconcile(Some(&after))?;
    let fresh = matches!(after, Fact::Fresh);
    println!("{}", json!({"id":INTERACTABLE_ID,"ok":resolve_ok && fresh,"changed":changed,"converged":fresh,"proposal_removed":fresh,"first_missing_signal":if !resolve_ok {"household-zone-resolve-failed"} else if !fresh {"household-zone-readback-stale"} else {"none"}}));
    if !resolve_ok { return Err("household-zone-resolve-failed".into()); }
    if !fresh { return Err("household-zone-readback-stale".into()); }
    Ok(())
}
