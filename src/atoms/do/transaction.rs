//! Profile/update adapters for the durable ritual owner in ritual.rs.
use crate::atoms::r#do::InvocationKey;
use crate::Profile;
use crate::*;
use std::{
    cell::RefCell,
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    rc::Rc,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct RefreshedProfileIdentity {
    pub profile_id: String,
    pub identity: String,
    pub source_head: String,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ModuleRootConsistency {
    pub source_root: String,
    pub installed_root: String,
    pub source_tree_sha256: String,
    pub installed_tree_sha256: String,
    pub matches: bool,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct TransactionCensus {
    pub profile_id: String,
    pub profile_identity: String,
    pub source_head: String,
    pub target_count: usize,
    pub service_count: usize,
    pub caduceus_count: usize,
    pub gui_face: String,
    pub gui_member: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct TransactionCensusSnapshot {
    pub profile_id: String,
    pub profile_identity: String,
    pub source_head: String,
    pub target_count: usize,
    pub service_count: usize,
    pub caduceus_count: usize,
    pub gui_face: String,
    pub gui_member: String,
}

impl From<&TransactionCensus> for TransactionCensusSnapshot {
    fn from(value: &TransactionCensus) -> Self {
        Self {
            profile_id: value.profile_id.clone(),
            profile_identity: value.profile_identity.clone(),
            source_head: value.source_head.clone(),
            target_count: value.target_count,
            service_count: value.service_count,
            caduceus_count: value.caduceus_count,
            gui_face: value.gui_face.clone(),
            gui_member: value.gui_member.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Target {
    pub path: PathBuf,
    pub member: String,
}
#[derive(Clone, Debug)]
pub(crate) struct ServiceBinding {
    pub name: String,
    pub user: bool,
    pub target_user: Option<String>,
}
#[derive(Clone, Debug)]
pub(crate) struct UpdatePlan {
    pub targets: Vec<Target>,
    pub services: Vec<ServiceBinding>,
    pub gui_face: Option<String>,
    pub gui_member: Option<String>,
    pub caduceus_count: usize,
    pub pinned_members: Option<Vec<String>>,
}
pub(crate) fn derive_plan(
    profile: &Profile,
    module_root: &Path,
    projection_root: Option<&Path>,
) -> Result<UpdatePlan, String> {
    let projection = crate::bands::stage_profile::projection::load_profile_projection(
        profile,
        module_root,
        &BTreeSet::new(),
    )?;
    let mut plan = projection.derive_update_plan(profile, module_root)?;
    if let Some(scratch) = projection_root {
        for target in &mut plan.targets {
            let rel = target
                .path
                .strip_prefix("/")
                .map_err(|_| "projection-target-not-absolute")?;
            target.path = scratch.join(rel);
        }
        plan.services.clear();
    }
    Ok(plan)
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RunCarrier {
    pub projection: Option<crate::bands::stage_profile::ProfileProjection>,
    pub update_plan: Option<UpdatePlan>,
    pub refreshed_profile: Option<RefreshedProfileIdentity>,
    pub module_root_consistency: Option<ModuleRootConsistency>,
    pub transaction_census: Option<TransactionCensus>,
    pub refreshed_profile_value: Option<crate::Profile>,
    pub sealed_snapshot: Option<Snapshot>,
    pub sealed_services: Option<Vec<crate::atoms::systemd::ServiceStateSnapshot>>,
    pub sealed_projection: Option<ProjectionTransaction>,
    pub deferred_terminal_summary: Option<crate::bands::report_home::DeferredRunSummary>,
}

pub(crate) type RunCarrierRef = Rc<RefCell<RunCarrier>>;

#[derive(Clone, Debug)]
pub(crate) struct RunContext {
    pub run_id: String,
    pub profile: String,
    pub face: String,
    pub(crate) key: InvocationKey,
    pub(crate) carrier: RunCarrierRef,
}
// Compatibility/profile entrypoints remain here; the durable transaction owner lives in ritual.rs.
pub(crate) use super::ritual::{
    apply_projection, bench, commit_projection, project_update_set_v1, rollback_projection,
    seal_projection, snapshot, snapshot_services, strict_rejects_forward_only, strict_rejects_weak,
    update_set_bench, validate_exact_root, validate_member_scoped_target, Atom, AtomKind,
    ProjectionChild, ProjectionTransaction, RestorationImage, Reversibility, SealedProjection,
    ServiceImage, ServiceState, Snapshot, TransactionReceipt, TransactionState,
};

pub(crate) fn rolling_update_run(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
    context: Option<&crate::RunContext>,
    suite_debt: Option<String>,
    lock_path: PathBuf,
    materialize_receipt: fn(&Path, &str) -> Result<PathBuf, String>,
    try_acquire_lock: fn(&Path) -> Result<ConvergenceLockGuard, ConvergenceLockBusy>,
) -> Result<(), String> {
    let apply = mode.is_software_apply();
    let run_id = run_id_from_stamp();
    let effective_receipt_dir = materialize_receipt(receipt_dir, &run_id)?;
    fs::create_dir_all(&effective_receipt_dir).map_err(|e| e.to_string())?;
    let run = || {
        let carrier = context
            .map(|value| value.carrier.clone())
            .unwrap_or_else(|| {
                std::rc::Rc::new(std::cell::RefCell::new(
                    crate::atoms::r#do::transaction::RunCarrier::default(),
                ))
            });
        let projection = load_profile_projection(profile, module_root, &BTreeSet::new())?;
        let execution_projection = projection.clone();
        let preflight = crate::bands::renew_self::run(
            module_root,
            &effective_receipt_dir,
            apply,
            mode.invocation(),
        )?;
        if !apply {
            return run_profile_engine_with_projection(
                profile,
                module_root,
                &effective_receipt_dir,
                mode,
                true,
                Some(preflight),
                suite_debt.as_deref(),
                &execution_projection,
                context,
                Some(&carrier),
                false,
            );
        }
        let transaction = run_profile_engine_with_projection(
            profile,
            module_root,
            &effective_receipt_dir,
            mode,
            true,
            Some(preflight),
            suite_debt.as_deref(),
            &execution_projection,
            context,
            Some(&carrier),
            true,
        );
        let transaction_guard = carrier.borrow_mut().sealed_projection.take();
        if let Err(error) = transaction {
            let Some(mut txn) = transaction_guard else {
                write_transaction_failure_run_receipt(
                    &effective_receipt_dir,
                    profile,
                    module_root,
                    "transaction-engine-failed",
                    Some(&error),
                )?;
                return Err(error);
            };
            let failure_receipt = write_transaction_failure_run_receipt(
                &effective_receipt_dir,
                profile,
                module_root,
                "transaction-engine-failed",
                Some(&error),
            );
            if let Some(key) = mode.invocation() {
                if let Ok(receipt) =
                    crate::atoms::r#do::transaction::rollback_projection(&mut txn, key)
                {
                    let _ = crate::atoms::attest::write_transaction_receipt(
                        &effective_receipt_dir,
                        &receipt,
                        Some(&error),
                    );
                }
            }
            failure_receipt?;
            return Err(error);
        }
        let Some(mut txn) = transaction_guard else {
            write_transaction_failure_run_receipt(
                &effective_receipt_dir,
                profile,
                module_root,
                "transaction-missing",
                None,
            )?;
            return Err("stage-profile-transaction-missing".to_string());
        };
        if let Some(key) = mode.invocation() {
            for child in 0..txn.sealed.children.len() {
                if let Err(error) =
                    crate::atoms::r#do::transaction::apply_projection(&mut txn, child, key)
                {
                    let failure_receipt = write_transaction_failure_run_receipt(
                        &effective_receipt_dir,
                        profile,
                        module_root,
                        "transaction-apply-failed",
                        Some(&error),
                    );
                    if let Ok(receipt) =
                        crate::atoms::r#do::transaction::rollback_projection(&mut txn, key)
                    {
                        let _ = crate::atoms::attest::write_transaction_receipt(
                            &effective_receipt_dir,
                            &receipt,
                            Some(&error),
                        );
                    }
                    failure_receipt?;
                    return Err(error);
                }
            }
        } else {
            write_transaction_failure_run_receipt(
                &effective_receipt_dir,
                profile,
                module_root,
                "transaction-invocation-missing",
                None,
            )?;
            return Err("stage-profile-invocation-missing".to_string());
        }
        let receipt = match crate::atoms::r#do::transaction::commit_projection(&mut txn) {
            Ok(receipt) => receipt,
            Err(error) => {
                write_transaction_failure_run_receipt(
                    &effective_receipt_dir,
                    profile,
                    module_root,
                    "transaction-commit-failed",
                    Some(&error),
                )?;
                return Err(error);
            }
        };
        if let Err(error) =
            crate::atoms::attest::write_transaction_receipt(&effective_receipt_dir, &receipt, None)
        {
            write_transaction_failure_run_receipt(
                &effective_receipt_dir,
                profile,
                module_root,
                "transaction-receipt-failed",
                Some(&error),
            )?;
            return Err(error);
        }
        let Some(summary) = carrier.borrow_mut().deferred_terminal_summary.take() else {
            write_transaction_failure_run_receipt(
                &effective_receipt_dir,
                profile,
                module_root,
                "transaction-terminal-summary-missing",
                None,
            )?;
            return Err("stage-profile-terminal-summary-missing".to_string());
        };
        if let Err(error) = crate::bands::report_home::finalize_deferred_terminal(
            summary,
            profile,
            module_root,
            &effective_receipt_dir,
        ) {
            write_transaction_failure_run_receipt(
                &effective_receipt_dir,
                profile,
                module_root,
                "transaction-terminal-receipt-failed",
                Some(&error),
            )?;
            return Err(error);
        }
        Ok(())
    };
    if apply {
        match try_acquire_lock(&lock_path) {
            Ok(_guard) => run(),
            Err(ConvergenceLockBusy) => {
                write_convergence_skipped_receipt(
                    &effective_receipt_dir,
                    profile,
                    apply,
                    "lock-held",
                    &lock_path,
                    receipt_dir,
                )?;
                emit_convergence_skipped_stdout(&effective_receipt_dir, "lock-held", &profile.id);
                Ok(())
            }
        }
    } else {
        run()
    }
}

fn write_transaction_failure_run_receipt(
    receipt_dir: &Path,
    profile: &Profile,
    module_root: &Path,
    fallback_signal: &str,
    error: Option<&str>,
) -> Result<(), String> {
    let signal = transaction_failure_signal(error, fallback_signal);
    write_engine_run_receipt_with_duration(
        receipt_dir,
        profile,
        true,
        false,
        false,
        profile.modules.len(),
        0,
        &signal,
        module_root,
        false,
        0,
    )?;
    let mut run = serde_json::from_reader::<_, serde_json::Value>(
        fs::File::open(receipt_dir.join("run.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if let Some(error_text) = error {
        run["error"] = serde_json::Value::String(error_text.to_string());
        write_json(&receipt_dir.join("run.json"), &run)?;
    }
    crate::atoms::attest::append_jsonl(
        &receipt_dir.join("events.jsonl"),
        &serde_json::json!({
            "event": "transaction-failed",
            "ok": false,
            "first_missing_signal": signal,
            "message": error.unwrap_or(fallback_signal),
            "error": error.unwrap_or(fallback_signal),
        }),
    )?;
    println!("schema=harmonia.run_profile.v1");
    crate::hyalos::forward_receipt(
        "schema=harmonia.run_profile.v1",
        "schema=harmonia.run_profile.v1 ok=false",
        Some(serde_json::json!({"schema":"harmonia.run_profile.v1","ok":false})),
        Some(false),
    );
    println!("ok=false");
    println!("changed=false");
    println!("profile_id={}", profile.id);
    println!("module_count={}", profile.modules.len());
    println!("operation_count=0");
    println!("first_missing_signal={}", signal);
    println!("receipt_dir={}", receipt_dir.display());
    Ok(())
}

fn transaction_failure_signal(error: Option<&str>, fallback: &str) -> String {
    let Some(error) = error else {
        return fallback.to_string();
    };
    if let Some(signal) = error
        .split_whitespace()
        .find_map(|part| part.strip_prefix("harmonia_error="))
    {
        if stable_transaction_signal(signal) {
            return signal.to_string();
        }
    }
    if let Some(signal) = error.split_whitespace().next() {
        let signal = signal.strip_suffix(':').unwrap_or(signal);
        if stable_transaction_signal(signal) {
            return signal.to_string();
        }
    }
    fallback.to_string()
}

fn stable_transaction_signal(value: &str) -> bool {
    !value.is_empty()
        && value.contains('-')
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
}

pub(crate) fn rolling_update_from_certificate_with_context(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
    context: Option<crate::RunContext>,
) -> Result<(), String> {
    rolling_update_run(
        profile,
        module_root,
        receipt_dir,
        mode,
        context.as_ref(),
        enforce_update_suite(profile, module_root)?,
        engine_run_lock_path(),
        materialize_tv_receipt_dir,
        try_acquire_homeconsole_update_lock,
    )
}
