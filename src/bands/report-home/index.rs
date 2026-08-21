use super::Band;
use crate::bands::stage_profile::ProfileProjection;
use crate::module_dispatch::ModuleExecution;
use crate::receipts::{
    append_profile_ledger_entry, write_engine_run_receipt_with_duration, write_json,
    ProfileLedgerEntry,
};
use crate::Profile;
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Instant;

pub(crate) fn enter(enter: &mut impl FnMut(Band) -> Result<(), String>) -> Result<(), String> {
    enter(Band::ReportHome)
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct TransactionReportingSnapshot {
    pub transaction_census: Option<crate::atoms::r#do::transaction::TransactionCensusSnapshot>,
    pub has_projection: bool,
    pub has_update_plan: bool,
    pub has_refreshed_profile: bool,
    pub has_module_root_consistency: bool,
    pub has_refreshed_profile_value: bool,
    pub has_sealed_snapshot: bool,
    pub sealed_services_count: Option<usize>,
}

pub(crate) fn serialize_transaction_state(
    carrier: Option<&crate::atoms::r#do::transaction::RunCarrierRef>,
) -> Result<serde_json::Value, String> {
    let value = carrier.map(|carrier| carrier.borrow());
    serde_json::to_value(TransactionReportingSnapshot {
        transaction_census: value
            .as_ref()
            .and_then(|v| v.transaction_census.as_ref().map(Into::into)),
        has_projection: value.as_ref().is_some_and(|v| v.projection.is_some()),
        has_update_plan: value.as_ref().is_some_and(|v| v.update_plan.is_some()),
        has_refreshed_profile: value
            .as_ref()
            .is_some_and(|v| v.refreshed_profile.is_some()),
        has_module_root_consistency: value
            .as_ref()
            .is_some_and(|v| v.module_root_consistency.is_some()),
        has_refreshed_profile_value: value
            .as_ref()
            .is_some_and(|v| v.refreshed_profile_value.is_some()),
        has_sealed_snapshot: value.as_ref().is_some_and(|v| v.sealed_snapshot.is_some()),
        sealed_services_count: value
            .as_ref()
            .and_then(|v| v.sealed_services.as_ref().map(Vec::len)),
    })
    .map_err(|e| format!("report-transaction-state-serialize-failed: {e}"))
}

#[derive(Clone, Debug)]
pub(crate) enum SettlementOutcome {
    Success,
    ReportOnlyFailure,
    ApplyFailure(String),
}

#[derive(Clone, Debug)]
pub(crate) struct DeferredRunSummary {
    pub profile_id: String,
    pub apply: bool,
    pub ok: bool,
    pub suite_ok: bool,
    pub changed: bool,
    pub first_missing_signal: String,
    pub module_count: usize,
    pub operation_count: usize,
    pub duration_ms: u128,
}

pub(crate) struct RunState {
    pub run_id: String,
    pub apply: bool,
    pub ok: bool,
    pub suite_ok: bool,
    pub changed: bool,
    pub first_missing_signal: String,
    pub module_count: usize,
    pub operation_count: usize,
    pub module_states: BTreeMap<String, ModuleExecution>,
    pub visited_bands: Vec<String>,
    pub run_started: Instant,
    pub transaction_state: serde_json::Value,
    pub settlement: Option<SettlementOutcome>,
    pub defer_terminal: bool,
}

pub(crate) fn collect_package_pin_witnesses(receipt_dir: &Path) -> (Vec<serde_json::Value>, BTreeSet<String>) {
    let mut paths = Vec::new();
    let mut pending = vec![receipt_dir.join("modules")];
    while let Some(path) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|v| v.ends_with(".pin-witness.json"))
            {
                paths.push(path);
            }
        }
    }
    paths.sort();
    let mut witnesses = Vec::new();
    let mut exclusions = BTreeSet::new();
    for path in paths {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        if let Some(items) = value.get("exclusion_set").and_then(|v| v.as_array()) {
            for item in items {
                if let Some(name) = item.as_str() {
                    exclusions.insert(name.to_string());
                }
            }
        }
        witnesses.push(value);
    }
    (witnesses, exclusions)
}

pub(crate) fn settle(
    state: RunState,
    profile: &Profile,
    projection: &ProfileProjection,
    module_root: &Path,
    receipt_dir: &Path,
    carrier: Option<&crate::atoms::r#do::transaction::RunCarrierRef>,
) -> Result<(), String> {
    let _serialized_transaction_state = state
        .transaction_state
        .as_object()
        .ok_or_else(|| "report-transaction-state-missing".to_string())?;
    for module_id in &profile.modules {
        if let Some(s) = state.module_states.get(module_id) {
            let loaded = projection.modules.get(module_id).map(|p| &p.loaded);
            append_profile_ledger_entry(
                receipt_dir,
                profile,
                ProfileLedgerEntry {
                    run_id: &state.run_id,
                    module_id,
                    ok: s.ok,
                    changed: s.changed,
                    operation_count: s.operation_count,
                    first_missing_signal: s.first_missing_signal.as_deref().unwrap_or("none"),
                    receipt_dir,
                    module_version: loaded.as_ref().and_then(|v| v.version()),
                },
            )?;
        }
    }
    let (package_pin_witnesses, package_pin_exclusion_set) =
        collect_package_pin_witnesses(receipt_dir);
    write_json(
        &receipt_dir.join("band-walk.receipt.json"),
        &json!({"schema":"harmonia.band-walk.receipt.v1","bands":state.visited_bands,"module_steps":state.module_states.iter().map(|(id,s)| json!({"module_id":id,"operation_count":s.operation_count,"ok":s.ok,"changed":s.changed,"first_missing_signal":s.first_missing_signal,"steps":s.placements})).collect::<Vec<_>>(),"package_pin_exclusion_set":package_pin_exclusion_set,"package_pin_witnesses":package_pin_witnesses,"pin_scope_limitation":crate::atoms::package::PACKAGE_PIN_SCOPE_LIMITATION}),
    )?;
    let settlement = state
        .settlement
        .clone()
        .expect("settlement must be computed before report-home");
    if state.defer_terminal {
        let Some(carrier) = carrier else {
            return Err("report-transaction-carrier-missing".to_string());
        };
        carrier.borrow_mut().deferred_terminal_summary = Some(DeferredRunSummary {
            profile_id: profile.id.clone(),
            apply: state.apply,
            ok: state.ok,
            suite_ok: state.suite_ok,
            changed: state.changed,
            first_missing_signal: state.first_missing_signal.clone(),
            module_count: state.module_count,
            operation_count: state.operation_count,
            duration_ms: state.run_started.elapsed().as_millis(),
        });
        return match settlement {
            SettlementOutcome::Success | SettlementOutcome::ReportOnlyFailure => Ok(()),
            SettlementOutcome::ApplyFailure(signal) => Err(signal),
        };
    }
    write_engine_run_receipt_with_duration(
        receipt_dir,
        profile,
        state.apply,
        state.ok,
        state.changed,
        state.module_count,
        state.operation_count,
        &state.first_missing_signal,
        module_root,
        state.suite_ok,
        state.run_started.elapsed().as_millis(),
    )?;
    println!("schema=harmonia.run_profile.v1");
    crate::hyalos::forward_receipt(
        "schema=harmonia.run_profile.v1",
        &format!("schema=harmonia.run_profile.v1 ok={}", state.ok),
        Some(json!({"schema":"harmonia.run_profile.v1","ok":state.ok})),
        Some(state.ok),
    );
    println!("ok={}", state.ok);
    println!("changed={}", state.changed);
    println!("profile_id={}", profile.id);
    println!("module_count={}", state.module_count);
    println!("operation_count={}", state.operation_count);
    println!("first_missing_signal={}", state.first_missing_signal);
    println!("receipt_dir={}", receipt_dir.display());
    match settlement {
        SettlementOutcome::Success | SettlementOutcome::ReportOnlyFailure => Ok(()),
        SettlementOutcome::ApplyFailure(signal) => Err(signal),
    }
}

pub(crate) fn finalize_deferred_terminal(
    summary: DeferredRunSummary,
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
) -> Result<(), String> {
    write_engine_run_receipt_with_duration(
        receipt_dir,
        profile,
        summary.apply,
        summary.ok,
        summary.changed,
        summary.module_count,
        summary.operation_count,
        &summary.first_missing_signal,
        module_root,
        summary.suite_ok,
        summary.duration_ms,
    )?;
    println!("schema=harmonia.run_profile.v1");
    crate::hyalos::forward_receipt(
        "schema=harmonia.run_profile.v1",
        &format!("schema=harmonia.run_profile.v1 ok={}", summary.ok),
        Some(json!({"schema":"harmonia.run_profile.v1","ok":summary.ok})),
        Some(summary.ok),
    );
    println!("ok={}", summary.ok);
    println!("changed={}", summary.changed);
    println!("profile_id={}", summary.profile_id);
    println!("module_count={}", summary.module_count);
    println!("operation_count={}", summary.operation_count);
    println!("first_missing_signal={}", summary.first_missing_signal);
    println!("receipt_dir={}", receipt_dir.display());
    Ok(())
}
