#[path = "backfill-files/index.rs"]
pub(crate) mod backfill_files;
#[path = "compare/index.rs"]
pub(crate) mod compare;
#[path = "install-packages/index.rs"]
pub(crate) mod install_packages;
#[path = "propose-edits/index.rs"]
pub(crate) mod propose_edits;
#[path = "pull-source/index.rs"]
pub(crate) mod pull_source;
#[path = "ratchet-binaries/index.rs"]
pub(crate) mod ratchet_binaries;
#[path = "renew-self/index.rs"]
pub(crate) mod renew_self;
#[path = "migrations/index.rs"]
pub(crate) mod migrations;
#[path = "report-home/index.rs"]
pub(crate) mod report_home;
#[path = "restart-services/index.rs"]
pub(crate) mod restart_services;
#[path = "stage-profile/index.rs"]
pub(crate) mod stage_profile;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Band {
    RenewSelf,
    Migrations,
    PullSource,
    StageProfile,
    Compare,
    InstallPackages,
    RatchetBinaries,
    RestartServices,
    BackfillFiles,
    ProposeEdits,
    ReportHome,
}

pub(crate) fn walk(mut enter: impl FnMut(Band) -> Result<(), String>) -> Result<(), String> {
    let mut first_error = None;
    macro_rules! invoke {
        ($module:ident, $band:expr) => {
            if let Err(error) = $module::enter(&mut enter) {
                first_error.get_or_insert_with(|| format!("band={:?} failure={error}", $band));
            }
        };
    }
    invoke!(renew_self, Band::RenewSelf);
    invoke!(migrations, Band::Migrations);
    invoke!(pull_source, Band::PullSource);
    invoke!(stage_profile, Band::StageProfile);
    invoke!(compare, Band::Compare);
    invoke!(install_packages, Band::InstallPackages);
    invoke!(ratchet_binaries, Band::RatchetBinaries);
    invoke!(restart_services, Band::RestartServices);
    invoke!(backfill_files, Band::BackfillFiles);
    invoke!(propose_edits, Band::ProposeEdits);
    invoke!(report_home, Band::ReportHome);
    first_error.map_or(Ok(()), Err)
}

fn record_downstream_blocked(
    state: &mut crate::bands::report_home::RunState,
    halted_modules: &BTreeSet<String>,
    halt_origins: &BTreeMap<String, String>,
    band: Band,
) {
    for module_id in halted_modules {
        let Some(blocked_by) = halt_origins.get(module_id) else {
            continue;
        };
        state
            .module_states
            .entry(module_id.clone())
            .or_insert_with(|| crate::module_dispatch::ModuleExecution {
                ok: false,
                changed: false,
                operation_count: 0,
                first_missing_signal: Some(blocked_by.clone()),
                placements: Vec::new(),
            })
            .placements
            .push(serde_json::json!({
                "module": module_id,
                "band": format!("{band:?}"),
                "status": "blocked",
                "ok": false,
                "changed": false,
                "blocked_by": blocked_by,
            }));
    }
}

fn remember_halt_origins(
    halted_modules: &BTreeSet<String>,
    halt_origins: &mut BTreeMap<String, String>,
    band: Band,
) {
    let origin = format!("{band:?}");
    for module_id in halted_modules {
        halt_origins.entry(module_id.clone()).or_insert_with(|| origin.clone());
    }
}

use crate::bands::stage_profile::groups::{
    group_loser_winners, read_device_module_policy, resolve_group_selections,
};
use crate::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Instant;

pub(crate) fn run_profile_engine(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
) -> Result<(), String> {
    run_profile_engine_with_preflight(profile, module_root, receipt_dir, mode, false, None, None)
}

pub(crate) fn run_profile_engine_with_preflight(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode<'_>,
    skip_preflight: bool,
    completed_preflight: Option<ModuleExecution>,
    suite_debt: Option<&str>,
) -> Result<(), String> {
    let policy = read_device_module_policy()?;
    let projection = load_profile_projection(profile, module_root, &policy.disabled_modules)?;
    run_profile_engine_with_projection(
        profile,
        module_root,
        receipt_dir,
        &mode,
        skip_preflight,
        completed_preflight,
        suite_debt,
        &projection,
        None,
        None,
        false,
    )
}

pub(crate) fn run_profile_engine_with_projection(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: &UpdateMode<'_>,
    skip_preflight: bool,
    mut completed_preflight: Option<ModuleExecution>,
    suite_debt: Option<&str>,
    projection: &ProfileProjection,
    context: Option<&crate::RunContext>,
    carrier: Option<&crate::atoms::r#do::transaction::RunCarrierRef>,
    materialize_on_stage: bool,
) -> Result<(), String> {
    let mut active_profile = profile.clone();
    let mut active_projection = projection.clone();
    let mut rerun_preflight_after_stage = false;
    let apply = mode.is_software_apply();
    let invocation = mode.invocation();
    let run_started = Instant::now();
    let mut events = crate::atoms::attest::create_receipt_file(&receipt_dir.join("events.jsonl"))?;
    event(
        &mut events,
        "engine-start",
        true,
        &format!("profile {}", active_profile.id),
    )?;
    let run_id = run_id_from_stamp();
    let mut state = crate::bands::report_home::RunState {
        run_id: run_id.clone(),
        apply,
        ok: true,
        suite_ok: true,
        changed: false,
        first_missing_signal: "none".to_string(),
        module_count: active_profile.modules.len(),
        operation_count: 0,
        module_states: BTreeMap::new(),
        visited_bands: Vec::new(),
        band_failures: Vec::new(),
        run_started,
        transaction_state: serde_json::Value::Null,
        settlement: None,
        defer_terminal: materialize_on_stage,
    };
    let mut halted_modules: BTreeSet<String> = BTreeSet::new();
    let mut halt_origins: BTreeMap<String, String> = BTreeMap::new();
    let mut routine_states: BTreeMap<String, BTreeMap<String, crate::ModuleWalkState>> =
        BTreeMap::new();
    let mut group_losers: BTreeMap<String, String> = BTreeMap::new();
    let mut final_result: Option<Result<(), String>> = None;
    let device_module_policy = read_device_module_policy()?;
    let _walk_result = crate::bands::walk(|band| {
        state.visited_bands.push(format!("{:?}", band));
        let band_result = (|| -> Result<(), String> {
            match band {
            crate::bands::Band::RenewSelf => {
                if let Some(suite_debt) = suite_debt {
                    state.ok = false;
                    state.suite_ok = false;
                    state.first_missing_signal = suite_debt.to_string();
                    event(&mut events, "profile-suite-spine-debt", false, suite_debt)?;
                }

                if skip_preflight {
                    event(
                        &mut events,
                        "engine-preflight-skipped",
                        true,
                        "already completed by update suite",
                    )?;
                    if let Some(preflight) = completed_preflight.take() {
                        state.operation_count += preflight.operation_count;
                        if preflight.changed {
                            state.changed = true;
                        }
                        if !preflight.ok {
                            let preflight_signal = preflight
                                .first_missing_signal
                                .clone()
                                .unwrap_or_else(|| "harmonia-engine-preflight-failed".to_string());
                            if apply
                                && materialize_on_stage
                                && crate::bands::renew_self::is_stale_staged_validation_failure(
                                    &preflight,
                                )
                            {
                                rerun_preflight_after_stage = true;
                                event(
                                    &mut events,
                                    "engine-preflight-deferred-stale-validation",
                                    false,
                                    &preflight_signal,
                                )?;
                            } else {
                                event(
                                    &mut events,
                                    "engine-preflight-honest-staleness",
                                    false,
                                    &preflight_signal,
                                )?;
                                state.ok = false;
                                if state.first_missing_signal == "none" {
                                    state.first_missing_signal = preflight_signal;
                                }
                            }
                        }
                    }
                } else {
                    // Engine-plane self-update is automatic in every profile run. It has its
                    // own receipt and never derives from, nor widens, module hard consent.
                    let preflight =
                        crate::bands::renew_self::run(module_root, receipt_dir, apply, invocation)?;
                    state.operation_count += preflight.operation_count;
                    if preflight.changed {
                        state.changed = true;
                    }
                    if !preflight.ok {
                        let preflight_signal = preflight
                            .first_missing_signal
                            .unwrap_or_else(|| "harmonia-engine-preflight-failed".to_string());
                        event(
                            &mut events,
                            "engine-preflight-honest-staleness",
                            false,
                            &preflight_signal,
                        )?;
                        // An observation failure is a named blocker in both
                        // report-only and apply modes; never report convergence
                        // from an unavailable probe.
                        state.ok = false;
                        state.first_missing_signal = preflight_signal;
                    }
                }

                if active_profile.modules.is_empty() {
                    state.ok = false;
                    state.first_missing_signal = "profile-modules-empty".to_string();
                    event(
                        &mut events,
                        "profile-modules",
                        false,
                        "profile module spine is empty",
                    )?;
                }
            }
            crate::bands::Band::Migrations => {
                crate::bands::migrations::run_profile_hotfixes(profile, receipt_dir, invocation);
            }
            crate::bands::Band::PullSource => {
                // Primitive rolling-update acquisition already ran; routine children still visit this band.
                crate::bands::pull_source::execute_manifest_modules(
                    &active_profile,
                    receipt_dir,
                    mode,
                    apply,
                    &device_module_policy.disabled_modules,
                    &active_projection,
                    &mut state.module_states,
                    &mut routine_states,
                    &mut halted_modules,
                    &mut state.module_count,
                    &mut state.operation_count,
                    &mut state.changed,
                    &mut state.ok,
                    &mut state.first_missing_signal,
                    &mut events,
                )?;
            }
            crate::bands::Band::StageProfile => {
                if apply && materialize_on_stage {
                    let engine = crate::bands::renew_self::load_engine_plane_config(
                        &crate::bands::renew_self::engine_config_path(),
                    )?
                    .ok_or_else(|| "engine-self-possession-unconfigured".to_string())?;
                    let refreshed = crate::bands::stage_profile::materialize(
                        &engine.source_dir,
                        &active_profile.id,
                        module_root,
                        receipt_dir,
                        "owner",
                        invocation.ok_or_else(|| "stage-profile-invocation-key-missing".to_string())?,
                        context,
                        carrier,
                        active_profile.syzygy_declaration.clone(),
                    )?;
                    active_profile = refreshed;
                    let target_carrier = carrier.or_else(|| context.map(|value| &value.carrier));
                    let Some(target_carrier) = target_carrier else {
                        return Err("stage-profile-transaction-carrier-missing".to_string());
                    };
                    let value = target_carrier.borrow();
                    active_profile = value
                        .refreshed_profile_value
                        .clone()
                        .unwrap_or(active_profile.clone());
                    active_projection = value
                        .projection
                        .clone()
                        .ok_or_else(|| "stage-profile-projection-not-sealed".to_string())?;
                    // The initial preflight may have observed the old installed module
                    // root. Once molt has installed the fresh profile, proof that same
                    // fresh root before any later band can consume the deferred result.
                    if rerun_preflight_after_stage {
                        rerun_preflight_after_stage = false;
                        let fresh = crate::bands::renew_self::run(
                            module_root,
                            receipt_dir,
                            apply,
                            invocation,
                        )?;
                        state.operation_count += fresh.operation_count;
                        state.changed |= fresh.changed;
                        if !fresh.ok {
                            let signal = fresh
                                .first_missing_signal
                                .unwrap_or_else(|| "harmonia-engine-preflight-failed".into());
                            state.ok = false;
                            if state.first_missing_signal == "none" {
                                state.first_missing_signal = signal.clone();
                            }
                            event(
                                &mut events,
                                "engine-preflight-fresh-root-failed",
                                false,
                                &signal,
                            )?;
                        } else {
                            event(
                                &mut events,
                                "engine-preflight-stale-validation-cleared",
                                true,
                                "fresh installed module root proved",
                            )?;
                        }
                    }
                }
            }
            crate::bands::Band::Compare => {
                record_downstream_blocked(&mut state, &halted_modules, &halt_origins, band);
                if let Some(target_carrier) =
                    carrier.or_else(|| context.map(|value| &value.carrier))
                {
                    let value = target_carrier.borrow();
                    if let Some(refreshed) = value.refreshed_profile_value.as_ref() {
                        active_profile = refreshed.clone();
                    }
                    if let Some(refreshed) = value.projection.as_ref() {
                        active_projection = refreshed.clone();
                    }
                }
                let group_selections = resolve_group_selections(
                    &active_profile,
                    module_root,
                    receipt_dir,
                    &active_projection,
                )?;
                group_losers = group_loser_winners(&group_selections);
                crate::bands::compare::execute_manifest_modules(
                    &active_profile,
                    receipt_dir,
                    mode,
                    apply,
                    &device_module_policy.disabled_modules,
                    &active_projection,
                    &mut state.module_states,
                    &mut routine_states,
                    &mut halted_modules,
                    &mut state.module_count,
                    &mut state.operation_count,
                    &mut state.changed,
                    &mut state.ok,
                    &mut state.first_missing_signal,
                    &mut events,
                )?;
            }
            crate::bands::Band::InstallPackages => {
                record_downstream_blocked(&mut state, &halted_modules, &halt_origins, band);
                crate::bands::install_packages::execute_manifest_modules(
                    &active_profile,
                    receipt_dir,
                    mode,
                    apply,
                    &device_module_policy.disabled_modules,
                    &active_projection,
                    &mut state.module_states,
                    &mut routine_states,
                    &mut halted_modules,
                    &mut state.module_count,
                    &mut state.operation_count,
                    &mut state.changed,
                    &mut state.ok,
                    &mut state.first_missing_signal,
                    &mut events,
                )?;
            }
            crate::bands::Band::RestartServices => {
                record_downstream_blocked(&mut state, &halted_modules, &halt_origins, band);
                crate::bands::restart_services::execute_manifest_modules(
                    &active_profile,
                    receipt_dir,
                    mode,
                    apply,
                    &device_module_policy.disabled_modules,
                    &active_projection,
                    &mut state.module_states,
                    &mut routine_states,
                    &mut halted_modules,
                    &mut state.module_count,
                    &mut state.operation_count,
                    &mut state.changed,
                    &mut state.ok,
                    &mut state.first_missing_signal,
                    &mut events,
                )?;
            }
            crate::bands::Band::RatchetBinaries => {
                record_downstream_blocked(&mut state, &halted_modules, &halt_origins, band);
                crate::bands::ratchet_binaries::execute_manifest_modules(
                    &active_profile,
                    receipt_dir,
                    mode,
                    apply,
                    &device_module_policy.disabled_modules,
                    &active_projection,
                    &mut state.module_states,
                    &mut routine_states,
                    &mut halted_modules,
                    &mut state.module_count,
                    &mut state.operation_count,
                    &mut state.changed,
                    &mut state.ok,
                    &mut state.first_missing_signal,
                    &mut events,
                )?;
            }
            crate::bands::Band::BackfillFiles => {
                record_downstream_blocked(&mut state, &halted_modules, &halt_origins, band);
                crate::bands::backfill_files::execute_manifest_modules(
                    &active_profile,
                    receipt_dir,
                    mode,
                    apply,
                    &device_module_policy.disabled_modules,
                    &active_projection,
                    &mut state.module_states,
                    &mut routine_states,
                    &mut halted_modules,
                    &mut state.module_count,
                    &mut state.operation_count,
                    &mut state.changed,
                    &mut state.ok,
                    &mut state.first_missing_signal,
                    &mut events,
                )?;
            }
            crate::bands::Band::ProposeEdits => {
                record_downstream_blocked(&mut state, &halted_modules, &halt_origins, band);
                crate::bands::propose_edits::execute_manifest_modules(
                    &active_profile,
                    receipt_dir,
                    mode,
                    apply,
                    &device_module_policy.disabled_modules,
                    &active_projection,
                    &mut state.module_states,
                    &mut routine_states,
                    &mut halted_modules,
                    &mut state.module_count,
                    &mut state.operation_count,
                    &mut state.changed,
                    &mut state.ok,
                    &mut state.first_missing_signal,
                    &mut events,
                    context.map(|value| value.face.as_str()),
                )?;
            }
            crate::bands::Band::ReportHome => {
                let target_carrier = carrier.or_else(|| context.map(|value| &value.carrier));
                state.transaction_state =
                    crate::bands::report_home::serialize_transaction_state(target_carrier)?;
                state.settlement = Some(if state.ok {
                    crate::bands::report_home::SettlementOutcome::Success
                } else if !state.apply {
                    crate::bands::report_home::SettlementOutcome::ReportOnlyFailure
                } else {
                    crate::bands::report_home::SettlementOutcome::ApplyFailure(
                        state.first_missing_signal.clone(),
                    )
                });
                let report_state = std::mem::replace(
                    &mut state,
                    crate::bands::report_home::RunState {
                        run_id: String::new(),
                        apply: false,
                        ok: false,
                        suite_ok: false,
                        changed: false,
                        first_missing_signal: String::new(),
                        module_count: 0,
                        operation_count: 0,
                        module_states: BTreeMap::new(),
                        visited_bands: Vec::new(),
                        band_failures: Vec::new(),
                        run_started: Instant::now(),
                        transaction_state: serde_json::Value::Null,
                        settlement: None,
                        defer_terminal: false,
                    },
                );
                final_result = Some(crate::bands::report_home::settle(
                    report_state,
                    &active_profile,
                    &active_projection,
                    module_root,
                    receipt_dir,
                    target_carrier,
                ));
            }
            }
            Ok(())
        })();
        if matches!(
            band,
            crate::bands::Band::PullSource
                | crate::bands::Band::Compare
                | crate::bands::Band::InstallPackages
                | crate::bands::Band::RestartServices
                | crate::bands::Band::RatchetBinaries
                | crate::bands::Band::BackfillFiles
                | crate::bands::Band::ProposeEdits
        ) {
            remember_halt_origins(&halted_modules, &mut halt_origins, band);
        }
        if let Err(error) = band_result {
            let named = format!("band={band:?} failure={error}");
            state.ok = false;
            if state.first_missing_signal == "none" {
                state.first_missing_signal = named.clone();
            }
            state.band_failures.push(serde_json::json!({
                "band": format!("{band:?}"),
                "status": "failed",
                "failure": error,
            }));
            event(&mut events, "band-failed", false, &named)?;
        }
        Ok(())
    });
    match final_result {
        Some(result) => result,
        None => Err("band-walk-report-home-missing".to_string()),
    }
}
