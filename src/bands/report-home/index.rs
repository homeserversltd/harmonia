use super::Band;
use crate::bands::stage_profile::ProfileProjection;
use crate::module_dispatch::ModuleExecution;
use crate::receipts::{
    append_profile_ledger_entry, write_engine_run_receipt_with_duration_and_steps_and_debt,
    write_json, ProfileLedgerEntry,
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

#[derive(Clone, Debug, Serialize)]
pub(crate) struct EngineArtifactExhaustionDebt {
    pub ok: bool,
    pub first_missing_signal: String,
    pub candidate_count: usize,
    pub candidates: Vec<serde_json::Value>,
    pub preflight_receipt: String,
}

#[derive(Clone, Debug)]
pub(crate) struct DeferredRunSummary {
    pub profile_id: String,
    pub apply: bool,
    pub ok: bool,
    pub suite_ok: bool,
    pub changed: bool,
    pub first_missing_signal: String,
    pub engine_debt: Option<EngineArtifactExhaustionDebt>,
    pub module_artifact_debt: Vec<serde_json::Value>,
    pub module_count: usize,
    pub operation_count: usize,
    pub duration_ms: u128,
    pub module_steps: Vec<serde_json::Value>,
}

pub(crate) struct RunState {
    pub run_id: String,
    pub apply: bool,
    pub ok: bool,
    pub suite_ok: bool,
    pub changed: bool,
    pub first_missing_signal: String,
    pub engine_debt: Option<EngineArtifactExhaustionDebt>,
    pub module_count: usize,
    pub operation_count: usize,
    pub module_states: BTreeMap<String, ModuleExecution>,
    pub visited_bands: Vec<String>,
    pub band_failures: Vec<serde_json::Value>,
    pub run_started: Instant,
    pub transaction_state: serde_json::Value,
    pub settlement: Option<SettlementOutcome>,
    pub defer_terminal: bool,
}

pub(crate) fn collect_package_pin_witnesses(
    receipt_dir: &Path,
) -> (Vec<serde_json::Value>, BTreeSet<String>) {
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

fn closing_module_steps(state: &RunState, receipt_dir: &Path) -> Vec<serde_json::Value> {
    state
        .module_states
        .iter()
        .map(|(module_id, step)| {
            let attempt = step
                .placements
                .iter()
                .map(|placement| {
                    let mut value = placement.clone();
                    if let Some(object) = value.as_object_mut() {
                        let step_id = object
                            .get("step_id")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_string);
                        let result = step_id.as_deref().and_then(|id| {
                            let path = receipt_dir.join("modules").join(module_id).join(format!("{id}.json"));
                            std::fs::read(path)
                                .ok()
                                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                        });
                        if let Some(result) = result {
                            if let Some(result_object) = result.as_object() {
                                for field in ["ok", "changed", "status", "first_missing_signal"] {
                                    if !object.contains_key(field) {
                                        if let Some(value) = result_object.get(field) {
                                            object.insert(field.to_string(), value.clone());
                                        }
                                    }
                                }
                            }
                            object.insert("result".into(), result);
                        }
                        let ok = object.get("ok").and_then(serde_json::Value::as_bool).unwrap_or(step.ok);
                        let changed = object.get("changed").and_then(serde_json::Value::as_bool).unwrap_or(step.changed);
                        let status = object.get("status").cloned().unwrap_or_else(|| json!("unknown"));
                        object.entry("outcome").or_insert_with(|| json!({"ok": ok, "changed": changed, "status": status}));
                        let outcome_fields = object
                            .get("outcome")
                            .and_then(serde_json::Value::as_object)
                            .map(|outcome| {
                                ["ok", "changed", "status", "first_missing_signal"]
                                    .into_iter()
                                    .filter_map(|field| outcome.get(field).map(|value| (field, value.clone())))
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default();
                        for (field, value) in outcome_fields {
                            if !object.contains_key(field) {
                                object.insert(field.to_string(), value);
                            }
                        }
                    }
                    value
                })
                .collect::<Vec<_>>();
            json!({
                "module": module_id,
                "observed": {"ok": step.ok, "changed": step.changed, "first_missing_signal": step.first_missing_signal},
                "could_change_to": serde_json::Value::Null,
                "attempt": attempt,
                "outcome": {"ok": step.ok, "changed": step.changed, "first_missing_signal": step.first_missing_signal},
            })
        })
        .collect()
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
    let module_artifact_debt =
        crate::bands::module_artifact_debt::collect_exhaustion_receipts(receipt_dir)?;
    let first_missing_signal = if state.first_missing_signal == "none" {
        module_artifact_debt
            .first()
            .and_then(|debt| debt.get("first_missing_signal"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| state.first_missing_signal.clone())
    } else {
        state.first_missing_signal.clone()
    };
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
        &json!({"schema":"harmonia.band-walk.receipt.v1","bands":state.visited_bands,"band_failures":state.band_failures,"module_steps":state.module_states.iter().map(|(id,s)| json!({"module_id":id,"operation_count":s.operation_count,"ok":s.ok,"changed":s.changed,"first_missing_signal":s.first_missing_signal,"steps":s.placements})).collect::<Vec<_>>(),"package_pin_exclusion_set":package_pin_exclusion_set,"package_pin_witnesses":package_pin_witnesses,"pin_scope_limitation":crate::atoms::package::PACKAGE_PIN_SCOPE_LIMITATION}),
    )?;
    let settlement = state
        .settlement
        .clone()
        .expect("settlement must be computed before report-home");
    let engine_debt = state
        .engine_debt
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| format!("report-engine-debt-serialize-failed: {error}"))?;
    if state.defer_terminal {
        let Some(carrier) = carrier else {
            return Err("report-transaction-carrier-missing".to_string());
        };
        let module_steps = closing_module_steps(&state, receipt_dir);
        carrier.borrow_mut().deferred_terminal_summary = Some(DeferredRunSummary {
            profile_id: profile.id.clone(),
            apply: state.apply,
            ok: state.ok && state.module_states.values().all(|step| step.ok),
            suite_ok: state.suite_ok,
            changed: state.changed,
            first_missing_signal: first_missing_signal.clone(),
            engine_debt: state.engine_debt.clone(),
            module_artifact_debt: module_artifact_debt.clone(),
            module_count: state.module_count,
            operation_count: state.operation_count,
            duration_ms: state.run_started.elapsed().as_millis(),
            module_steps,
        });
        return match settlement {
            SettlementOutcome::Success | SettlementOutcome::ReportOnlyFailure => Ok(()),
            SettlementOutcome::ApplyFailure(signal) => Err(signal),
        };
    }
    let module_steps = closing_module_steps(&state, receipt_dir);
    write_engine_run_receipt_with_duration_and_steps_and_debt(
        receipt_dir,
        profile,
        state.apply,
        state.ok && state.module_states.values().all(|step| step.ok),
        state.changed,
        state.module_count,
        state.operation_count,
        &first_missing_signal,
        module_root,
        state.suite_ok,
        state.run_started.elapsed().as_millis(),
        Some(&module_steps),
        engine_debt.as_ref(),
        Some(&module_artifact_debt),
    )?;
    println!("schema=harmonia.run_profile.v1");
    let run_ok = state.ok && state.module_states.values().all(|step| step.ok);
    let degraded = engine_debt.is_some() || !module_artifact_debt.is_empty();
    let overall_ok = run_ok && !degraded;
    let mut forwarded = json!({
        "schema":"harmonia.run_profile.v1",
        "ok":run_ok,
        "module_artifact_debt":module_artifact_debt.clone(),
    });
    if let Some(debt) = engine_debt.as_ref() {
        forwarded["engine_debt"] = debt.clone();
    }
    if degraded {
        forwarded["degraded"] = json!(true);
        forwarded["overall_ok"] = json!(false);
    } else {
        forwarded["overall_ok"] = json!(overall_ok);
    }
    crate::hyalos::forward_receipt(
        "schema=harmonia.run_profile.v1",
        &if degraded {
            format!("schema=harmonia.run_profile.v1 ok={run_ok} degraded=true overall_ok=false")
        } else {
            format!("schema=harmonia.run_profile.v1 ok={run_ok}")
        },
        Some(forwarded),
        Some(overall_ok),
        None,
    );
    println!("ok={}", state.ok);
    if degraded {
        println!("degraded=true");
        println!("overall_ok={overall_ok}");
    }
    if let Some(debt) = state.engine_debt.as_ref() {
        println!(
            "engine_debt_first_missing_signal={}",
            debt.first_missing_signal
        );
    }
    if let Some(debt) = module_artifact_debt.first() {
        if let Some(signal) = debt
            .get("first_missing_signal")
            .and_then(serde_json::Value::as_str)
        {
            println!("module_artifact_debt_first_missing_signal={signal}");
        }
    }
    println!("changed={}", state.changed);
    println!("profile_id={}", profile.id);
    println!("module_count={}", state.module_count);
    println!("operation_count={}", state.operation_count);
    println!("first_missing_signal={first_missing_signal}");
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
    let engine_debt = summary
        .engine_debt
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| format!("report-engine-debt-serialize-failed: {error}"))?;
    write_engine_run_receipt_with_duration_and_steps_and_debt(
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
        Some(&summary.module_steps),
        engine_debt.as_ref(),
        Some(&summary.module_artifact_debt),
    )?;
    println!("schema=harmonia.run_profile.v1");
    let degraded = engine_debt.is_some() || !summary.module_artifact_debt.is_empty();
    let overall_ok = summary.ok && !degraded;
    let mut forwarded = json!({
        "schema":"harmonia.run_profile.v1",
        "ok":summary.ok,
        "module_artifact_debt":summary.module_artifact_debt.clone(),
    });
    if let Some(debt) = engine_debt.as_ref() {
        forwarded["engine_debt"] = debt.clone();
    }
    if degraded {
        forwarded["degraded"] = json!(true);
        forwarded["overall_ok"] = json!(false);
    } else {
        forwarded["overall_ok"] = json!(overall_ok);
    }
    crate::hyalos::forward_receipt(
        "schema=harmonia.run_profile.v1",
        &if degraded {
            format!(
                "schema=harmonia.run_profile.v1 ok={} degraded=true overall_ok=false",
                summary.ok
            )
        } else {
            format!("schema=harmonia.run_profile.v1 ok={}", summary.ok)
        },
        Some(forwarded),
        Some(overall_ok),
        None,
    );
    println!("ok={}", summary.ok);
    if degraded {
        println!("degraded=true");
        println!("overall_ok={overall_ok}");
    }
    if let Some(debt) = summary.engine_debt.as_ref() {
        println!(
            "engine_debt_first_missing_signal={}",
            debt.first_missing_signal
        );
    }
    if let Some(debt) = summary.module_artifact_debt.first() {
        if let Some(signal) = debt
            .get("first_missing_signal")
            .and_then(serde_json::Value::as_str)
        {
            println!("module_artifact_debt_first_missing_signal={signal}");
        }
    }
    println!("changed={}", summary.changed);
    println!("profile_id={}", summary.profile_id);
    println!("module_count={}", summary.module_count);
    println!("operation_count={}", summary.operation_count);
    println!("first_missing_signal={}", summary.first_missing_signal);
    println!("receipt_dir={}", receipt_dir.display());
    Ok(())
}
