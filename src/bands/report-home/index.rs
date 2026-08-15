use super::Band;
use crate::module_dispatch::ModuleExecution;
use crate::profile_engine::ProfileProjection;
use crate::receipts::{
    append_profile_ledger_entry, write_engine_run_receipt_with_duration, write_json,
    ProfileLedgerEntry,
};
use crate::Profile;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;
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
}

pub(crate) fn settle(
    state: RunState,
    profile: &Profile,
    projection: &ProfileProjection,
    module_root: &Path,
    receipt_dir: &Path,
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
    write_json(
        &receipt_dir.join("band-walk.receipt.json"),
        &json!({"schema":"harmonia.band-walk.receipt.v1","bands":state.visited_bands,"module_steps":state.module_states.iter().map(|(id,s)| json!({"module_id":id,"operation_count":s.operation_count,"ok":s.ok,"changed":s.changed,"first_missing_signal":s.first_missing_signal,"steps":s.placements})).collect::<Vec<_>>() }),
    )?;
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
    match state
        .settlement
        .expect("settlement must be computed before report-home")
    {
        SettlementOutcome::Success | SettlementOutcome::ReportOnlyFailure => Ok(()),
        SettlementOutcome::ApplyFailure(signal) => Err(signal),
    }
}
