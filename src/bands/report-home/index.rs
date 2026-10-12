use super::Band;
use crate::bands::stage_profile::ProfileProjection;
use crate::module_dispatch::ModuleExecution;
use crate::receipts::{
    write_engine_run_receipt_with_duration_and_steps_and_debt, write_json,
    write_profile_ledger_run, ProfileLedgerEntry,
};
use crate::Profile;
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
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
    pub run_id: String,
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
    pub receipt_retention: usize,
    pub ledger_unparsable_lines: usize,
    pub ledger_read_warnings: Vec<String>,
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
    pub receipt_retention: usize,
    pub requested_latest_alias: Option<PathBuf>,
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

fn forward_module_outcome(
    profile_id: &str,
    module_id: &str,
    ok: Option<bool>,
    changed: bool,
    operation_count: Option<usize>,
    first_missing_signal: Option<&str>,
    run_id: Option<&str>,
) {
    let profile_id = crate::hyalos::bounded_json_string(profile_id, 96);
    let module_id = crate::hyalos::bounded_json_string(module_id, 96);
    let outcome = match ok {
        Some(false) => "failed",
        Some(true) if changed => "changed",
        Some(true) => "unchanged",
        None => "not-run",
    };
    let mut metadata = json!({
        "profile_id": profile_id,
        "module": module_id,
        "state": outcome,
        "changed": changed,
    });
    if let Some(ok) = ok {
        metadata["ok"] = json!(ok);
    }
    if let Some(operation_count) = operation_count {
        metadata["operation_count"] = json!(operation_count);
    }
    if ok == Some(false) {
        let signal = first_missing_signal
            .filter(|signal| *signal != "none")
            .unwrap_or("module-failed");
        metadata["first_missing_signal"] =
            json!(crate::hyalos::bounded_json_string(signal, 320));
    }
    let message = format!(
        "profile={profile_id} module={module_id} outcome={outcome}"
    );
    let correlation_id = run_id.map(|id| crate::hyalos::bounded_json_string(id, 96));
    crate::hyalos::forward_bounded_receipt(
        "harmonia.module.outcome",
        &message,
        Some(metadata),
        ok,
        correlation_id.as_deref(),
    );
}

fn forward_module_outcomes_from_states(
    profile: &Profile,
    module_states: &BTreeMap<String, ModuleExecution>,
    run_id: Option<&str>,
) {
    for module_id in &profile.modules {
        let state = module_states.get(module_id);
        forward_module_outcome(
            &profile.id,
            module_id,
            state.map(|state| state.ok),
            state.is_some_and(|state| state.changed),
            state.map(|state| state.operation_count),
            state.and_then(|state| state.first_missing_signal.as_deref()),
            run_id,
        );
    }
}

fn forward_module_outcomes_from_steps(
    profile: &Profile,
    module_steps: &[serde_json::Value],
    run_id: Option<&str>,
) {
    for module_id in &profile.modules {
        let step = module_steps.iter().find(|step| {
            step.get("module").and_then(serde_json::Value::as_str)
                == Some(module_id.as_str())
        });
        let observed = step.and_then(|step| step.get("observed"));
        forward_module_outcome(
            &profile.id,
            module_id,
            observed.and_then(|value| value.get("ok")).and_then(serde_json::Value::as_bool),
            observed
                .and_then(|value| value.get("changed"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            None,
            observed
                .and_then(|value| value.get("first_missing_signal"))
                .and_then(serde_json::Value::as_str),
            run_id,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn forward_run_outcome(
    profile_id: &str,
    run_id: Option<&str>,
    ok: bool,
    changed: bool,
    overall_ok: bool,
    degraded: bool,
    module_count: usize,
    operation_count: usize,
    duration_ms: u128,
    first_missing_signal: &str,
    engine_debt_signal: Option<&str>,
    module_debt_signal: Option<&str>,
) {
    let profile_id = crate::hyalos::bounded_json_string(profile_id, 96);
    let mut metadata = json!({
        "schema": "harmonia.run_profile.v1",
        "ok": ok,
        "changed": changed,
        "profile_id": profile_id,
        "module_count": module_count,
        "operation_count": operation_count,
        "duration_ms": duration_ms,
        "degraded": degraded,
        "overall_ok": overall_ok,
    });
    if first_missing_signal != "none" {
        metadata["first_missing_signal"] =
            json!(crate::hyalos::bounded_json_string(first_missing_signal, 320));
    }
    if let Some(signal) = engine_debt_signal {
        metadata["engine_debt_first_missing_signal"] =
            json!(crate::hyalos::bounded_json_string(signal, 320));
    }
    if let Some(signal) = module_debt_signal {
        metadata["module_artifact_debt_first_missing_signal"] =
            json!(crate::hyalos::bounded_json_string(signal, 320));
    }
    let message = if degraded {
        format!("schema=harmonia.run_profile.v1 ok={ok} degraded=true overall_ok=false")
    } else {
        format!("schema=harmonia.run_profile.v1 ok={ok}")
    };
    let correlation_id = run_id.map(|id| crate::hyalos::bounded_json_string(id, 96));
    crate::hyalos::forward_bounded_receipt(
        "schema=harmonia.run_profile.v1",
        &message,
        Some(metadata),
        Some(overall_ok),
        correlation_id.as_deref(),
    );
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
    let mut ledger_entries = Vec::new();
    for module_id in &profile.modules {
        if let Some(step) = state.module_states.get(module_id) {
            let loaded = projection.modules.get(module_id).map(|module| &module.loaded);
            ledger_entries.push(ProfileLedgerEntry {
                module_id,
                ok: step.ok,
                changed: step.changed,
                operation_count: step.operation_count,
                first_missing_signal: step.first_missing_signal.as_deref().unwrap_or("none"),
                receipt_dir,
                module_version: loaded.and_then(|module| module.version()),
            });
        }
    }
    let ledger_report = write_profile_ledger_run(
        receipt_dir,
        state.requested_latest_alias.as_deref(),
        profile,
        &state.run_id,
        &ledger_entries,
        state.receipt_retention,
    )?;
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
            run_id: state.run_id.clone(),
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
            receipt_retention: state.receipt_retention,
            ledger_unparsable_lines: ledger_report.unparsable_lines,
            ledger_read_warnings: ledger_report.read_warnings,
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
    if let Err(error) = crate::receipts::record_profile_ledger_projection(
        receipt_dir,
        state.receipt_retention,
        &ledger_report,
    ) {
        eprintln!("profile-ledger-projection-warning: {error}");
    }
    println!("schema=harmonia.run_profile.v1");
    let run_ok = state.ok && state.module_states.values().all(|step| step.ok);
    let degraded = engine_debt.is_some() || !module_artifact_debt.is_empty();
    let overall_ok = run_ok && !degraded;
    forward_module_outcomes_from_states(profile, &state.module_states, Some(&state.run_id));
    if state.changed || !overall_ok {
        forward_run_outcome(
            &profile.id,
            Some(&state.run_id),
            run_ok,
            state.changed,
            overall_ok,
            degraded,
            state.module_count,
            state.operation_count,
            state.run_started.elapsed().as_millis(),
            &first_missing_signal,
            state
                .engine_debt
                .as_ref()
                .map(|debt| debt.first_missing_signal.as_str()),
            module_artifact_debt
                .first()
                .and_then(|debt| debt.get("first_missing_signal"))
                .and_then(serde_json::Value::as_str),
        );
    }
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
    if let Err(error) = crate::receipts::record_profile_ledger_projection(
        receipt_dir,
        summary.receipt_retention,
        &crate::receipts::ProfileLedgerWriteReport {
            unparsable_lines: summary.ledger_unparsable_lines,
            read_warnings: summary.ledger_read_warnings,
        },
    ) {
        eprintln!("profile-ledger-projection-warning: {error}");
    }
    println!("schema=harmonia.run_profile.v1");
    let degraded = engine_debt.is_some() || !summary.module_artifact_debt.is_empty();
    let overall_ok = summary.ok && !degraded;
    forward_module_outcomes_from_steps(profile, &summary.module_steps, Some(&summary.run_id));
    if summary.changed || !overall_ok {
        forward_run_outcome(
            &summary.profile_id,
            Some(&summary.run_id),
            summary.ok,
            summary.changed,
            overall_ok,
            degraded,
            summary.module_count,
            summary.operation_count,
            summary.duration_ms,
            &summary.first_missing_signal,
            summary
                .engine_debt
                .as_ref()
                .map(|debt| debt.first_missing_signal.as_str()),
            summary
                .module_artifact_debt
                .first()
                .and_then(|debt| debt.get("first_missing_signal"))
                .and_then(serde_json::Value::as_str),
        );
    }
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
