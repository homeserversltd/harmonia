//! Profile/update adapters for the durable ritual owner in ritual.rs.
use crate::Profile;
use crate::*;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
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
    pub member_modules: BTreeMap<String, Vec<String>>,
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
    let mut plan = projection.derive_standing_update_plan(profile, module_root)?;
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
    /// This run only: populated by actual pointer movement, never quiet success.
    pub rung_promoted: Vec<String>,
    /// Per-surface pointer preimages and the last rung moved to by this run.
    pub known_good_pointer_moves:
        BTreeMap<String, crate::known_good_ledger::KnownGoodPointerMovement>,
    pub projection: Option<crate::bands::stage_profile::ProfileProjection>,
    pub update_plan: Option<UpdatePlan>,
    pub refreshed_profile: Option<RefreshedProfileIdentity>,
    pub module_root_consistency: Option<ModuleRootConsistency>,
    pub transaction_census: Option<TransactionCensus>,
    pub refreshed_profile_value: Option<crate::Profile>,
    pub sealed_snapshot: Option<Snapshot>,
    pub sealed_services: Option<Vec<crate::atoms::ask::change_unit::ServiceStateSnapshot>>,
    pub sealed_projection: Option<ProjectionTransaction>,
    pub deferred_terminal_summary: Option<crate::bands::report_home::DeferredRunSummary>,
}

pub(crate) type RunCarrierRef = Rc<RefCell<RunCarrier>>;

#[derive(Debug)]
pub(crate) struct RunContext {
    pub run_id: String,
    pub profile: String,
    pub face: String,
    pub(crate) carrier: RunCarrierRef,
}

fn restore_known_good_pointer_movements(
    carrier: &RunCarrierRef,
    receipt_dir: &Path,
) -> Vec<crate::known_good_ledger::KnownGoodPointerRestore> {
    let movements = carrier
        .borrow()
        .known_good_pointer_moves
        .iter()
        .map(|(surface, movement)| (surface.clone(), movement.clone()))
        .collect::<Vec<_>>();
    let root = crate::known_good_ledger::integration_root(receipt_dir);
    let restores = movements
        .iter()
        .map(|(surface, movement)| {
            crate::known_good_ledger::restore_run_pointer(
                &root,
                surface,
                &movement.to,
                movement.from.as_deref(),
            )
        })
        .collect();
    carrier.borrow_mut().known_good_pointer_moves.clear();
    restores
}

fn pointer_restore_errors(
    restores: &[crate::known_good_ledger::KnownGoodPointerRestore],
) -> Vec<String> {
    restores
        .iter()
        .filter_map(|restore| {
            restore.blocker.as_ref().map(|blocker| {
                format!(
                    "known-good-pointer-restore-failed surface={} from={} to={}: {blocker}",
                    restore.surface,
                    restore.from.as_deref().unwrap_or("absent-or-unreadable"),
                    restore.to.as_deref().unwrap_or("absent")
                )
            })
        })
        .collect()
}

fn attach_pointer_rollback_to_run_receipt(
    receipt_dir: &Path,
    transaction_error: &str,
    restores: &[crate::known_good_ledger::KnownGoodPointerRestore],
    rollback_errors: &[String],
) -> Result<(), String> {
    if restores.is_empty() {
        return Ok(());
    }
    let run_path = receipt_dir.join("run.json");
    let mut run = serde_json::from_reader::<_, serde_json::Value>(
        fs::File::open(&run_path)
            .map_err(|error| format!("known-good-pointer-run-receipt-read-failed: {error}"))?,
    )
    .map_err(|error| format!("known-good-pointer-run-receipt-invalid: {error}"))?;
    if run.get("schema").and_then(serde_json::Value::as_str) != Some("harmonia.run_profile.v1") {
        return Err("known-good-pointer-run-receipt-schema-mismatch".into());
    }
    run["error"] = serde_json::json!(transaction_error);
    run["known_good_pointer_restores"] = serde_json::json!(restores);
    run["rollback_errors"] = serde_json::json!(rollback_errors);
    crate::atoms::attest::write_json_atomic(&run_path, &run)
}

fn write_transaction_rollback_receipt(
    receipt_dir: &Path,
    txn: &ProjectionTransaction,
    mut receipt: TransactionReceipt,
    failed_step: &str,
    pointer_restores: &[crate::known_good_ledger::KnownGoodPointerRestore],
) -> Result<(), String> {
    let pointer_errors = pointer_restore_errors(pointer_restores);
    let mut rollback_errors = txn.rollback_errors.clone();
    rollback_errors.extend(pointer_errors.iter().cloned());
    if !pointer_errors.is_empty() {
        receipt.state = TransactionState::RollbackIncomplete;
    }
    let mint = crate::atoms::attest::committed_syzygy_mint_with_sudoers(
        receipt_dir,
        &receipt,
        &txn.sealed.sudoers_fragments,
        &txn.sealed.snapshot.roots,
    );
    #[cfg(feature = "test-facade")]
    prepare_rollback_receipt_failure(receipt_dir)?;
    crate::atoms::attest::write_transaction_rollback_receipt(
        receipt_dir,
        &receipt,
        &mint,
        Some(failed_step),
        &txn.restored_paths,
        pointer_restores,
        &rollback_errors,
    )
}

fn append_errors(target: &mut String, errors: &[String]) {
    for error in errors {
        target.push_str("; ");
        target.push_str(error);
    }
}

// Compatibility/profile entrypoints remain here; the durable transaction owner lives in ritual.rs.
pub(crate) use super::ritual::{
    apply_projection, commit_projection, compute_syzygy_sha, project_update_set_v1,
    rollback_projection, seal_projection, snapshot, snapshot_services, transaction_receipt,
    validate_exact_root, validate_exact_root_at, validate_member_scoped_target, ProjectionChild,
    ProjectionTransaction, SealedProjection, Snapshot, TransactionReceipt, TransactionState,
};

fn content_seat_apply_failure(preflight: &ModuleExecution, apply: bool) -> Option<&str> {
    (apply)
        .then(|| preflight.first_missing_signal.as_deref())
        .flatten()
        .filter(|signal| crate::bands::renew_self::is_content_seat_failure(signal))
}

fn write_run_refusal_receipt(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
    reason: &str,
) -> Result<(), String> {
    let receipt = serde_json::json!({
        "schema": "harmonia.run_profile.v1",
        "ok": false,
        "changed": false,
        "mutation": apply,
        "mode": "refused",
        "profile_id": profile.id,
        "identity": profile.identity,
        "identity_source": crate::device_profile::run_identity_source(),
        "first_missing_signal": reason,
    });
    let fallback_stem = format!("{}-update", profile.id);
    crate::atoms::attest::convergence_receipts::write_fixed_refusal_receipt(
        receipt_dir,
        &fallback_stem,
        &receipt,
    )
    .map_err(|error| format!("{reason}; update-refusal-receipt-failed: {error}"))
}

#[cfg(feature = "test-facade")]
fn prepare_rollback_receipt_failure(receipt_dir: &Path) -> Result<(), String> {
    if std::env::var_os("HARMONIA_TEST_ROLLBACK_RECEIPT_UNWRITABLE").as_deref()
        != Some(std::ffi::OsStr::new("1"))
    {
        return Ok(());
    }
    let path = receipt_dir.join("update-set.json");
    match fs::symlink_metadata(&path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => match fs::create_dir(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(format!(
                "rollback-test-receipt-collision-create-failed {}: {error}",
                path.display()
            )),
        },
        Err(error) => Err(format!(
            "rollback-test-receipt-collision-observe-failed {}: {error}",
            path.display()
        )),
    }
}

fn valid_run_receipt(receipt_dir: &Path) -> Option<serde_json::Value> {
    let path = receipt_dir.join("run.json");
    if !fs::symlink_metadata(&path).ok()?.file_type().is_file() {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let receipt = serde_json::from_slice::<serde_json::Value>(&bytes).ok()?;
    if receipt.get("schema").and_then(serde_json::Value::as_str)
        != Some("harmonia.run_profile.v1")
        || receipt.get("ok").and_then(serde_json::Value::as_bool).is_none()
    {
        return None;
    }
    let mutation = receipt.get("mutation").and_then(serde_json::Value::as_bool)?;
    let mode = receipt.get("mode").and_then(serde_json::Value::as_str)?;
    let expected_mode = if mutation { "apply" } else { "report-only" };
    if mode != expected_mode {
        return None;
    }
    Some(receipt)
}

fn run_receipt_matches_invocation(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
) -> bool {
    let Some(receipt) = valid_run_receipt(receipt_dir) else {
        return false;
    };
    receipt.get("profile_id").and_then(serde_json::Value::as_str)
        == Some(profile.id.as_str())
        && receipt.get("identity").and_then(serde_json::Value::as_str)
            == Some(profile.identity.as_str())
        && receipt.get("mutation").and_then(serde_json::Value::as_bool) == Some(apply)
        && receipt.get("mode").and_then(serde_json::Value::as_str)
            == Some(if apply { "apply" } else { "report-only" })
}

fn write_early_failed_run_receipt(
    receipt_dir: &Path,
    profile: &Profile,
    module_root: &Path,
    apply: bool,
    error: &str,
) -> Result<(), String> {
    let signal = transaction_failure_signal(Some(error), "rolling-run-failed-before-receipt");
    crate::receipts::write_engine_run_receipt_with_duration_and_steps_and_debt(
        receipt_dir,
        profile,
        apply,
        false,
        false,
        profile.modules.len(),
        0,
        &signal,
        module_root,
        false,
        0,
        None,
        None,
        None,
    )
}

pub(crate) fn rolling_update_run(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode<'_>,
    context: Option<&crate::RunContext>,
    suite_debt: Option<String>,
    receipt_retention: usize,
    lock_path: PathBuf,
    materialize_receipt: fn(&Path, &str) -> Result<PathBuf, String>,
    try_acquire_lock: fn(&Path) -> Result<ConvergenceLockGuard, ConvergenceLockBusy>,
) -> Result<(), String> {
    let _mint_seats = crate::atoms::ask::mint_seats::at_start();
    let apply = mode.is_software_apply();
    let _convergence_lock = if apply {
        match try_acquire_lock(&lock_path) {
            Ok(guard) => Some(guard),
            Err(ConvergenceLockBusy) => {
                crate::atoms::attest::convergence_receipts::emit_convergence_skipped_stdout(
                    receipt_dir,
                    "lock-held",
                    &profile.id,
                );
                return Ok(());
            }
        }
    } else {
        None
    };
    let requested_run_id = context
        .map(|context| context.run_id.clone())
        .unwrap_or_else(run_id_from_stamp);
    let _run_id_guard = crate::receipts::RunIdGuard::enter(&requested_run_id);
    let policy = match crate::bands::stage_profile::groups::read_device_module_policy() {
        Ok(policy) => policy,
        Err(reason) => {
            write_run_refusal_receipt(receipt_dir, profile, apply, &reason)?;
            return Err(reason);
        }
    };
    let mut effective_profile = profile.clone();
    if let Some(declaration) = policy.syzygy_declaration {
        effective_profile.syzygy_declaration = Some(declaration);
    }
    let profile = &effective_profile;
    let fallback_stem = format!("{}-update", profile.id);
    let receipt_parent = receipt_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| "receipt-dir-parentless-path".to_string())?;
    crate::atoms::attest::prepare_receipt_parent(receipt_parent)?;
    let family_stem = crate::atoms::attest::convergence_receipts::latest_receipt_stem(
        receipt_dir,
        &fallback_stem,
    );
    let effective_receipt_dir = match materialize_receipt(receipt_dir, &requested_run_id) {
        Ok(path) => path,
        Err(reason) => {
            write_run_refusal_receipt(receipt_dir, profile, apply, &reason)?;
            return Err(reason);
        }
    };
    let run_id = crate::receipts::run_id_from_effective_receipt_directory(
        &effective_receipt_dir,
        Some(receipt_dir),
        &fallback_stem,
        &requested_run_id,
    );
    let _run_id_guard = crate::receipts::RunIdGuard::enter(&run_id);
    fs::create_dir_all(&effective_receipt_dir).map_err(|e| e.to_string())?;
    crate::atoms::attest::write_json_atomic(
        &effective_receipt_dir.join("ruyi.json"),
        &serde_json::json!({
            "run_id": run_id,
            "profile": profile.id,
            "in_flight": true,
        }),
    )?;
    let run = || {
        let carrier = context
            .map(|value| value.carrier.clone())
            .unwrap_or_else(|| {
                std::rc::Rc::new(std::cell::RefCell::new(
                    crate::atoms::r#do::transaction::RunCarrier::default(),
                ))
            });
        carrier.borrow_mut().rung_promoted.clear();
        carrier.borrow_mut().known_good_pointer_moves.clear();
        let preflight = crate::bands::renew_self::run(
            module_root,
            &effective_receipt_dir,
            apply,
            mode.invocation(),
        )?;
        if !apply {
            crate::bands::stage_profile::reconcile_legacy_module_seats(
                profile,
                module_root,
                &effective_receipt_dir,
                &mode,
            )?;
            let projection = load_profile_projection(profile, module_root, &BTreeSet::new())?;
            let execution_projection = projection.clone();
            return run_profile_engine_with_projection(
                profile,
                module_root,
                &effective_receipt_dir,
                &mode,
                true,
                Some(preflight),
                suite_debt.as_deref(),
                &execution_projection,
                context,
                Some(&carrier),
                receipt_retention,
                Some(receipt_dir),
                false,
            );
        }
        if let Some(signal) = content_seat_apply_failure(&preflight, apply) {
            write_transaction_failure_run_receipt(
                &effective_receipt_dir,
                profile,
                module_root,
                signal,
                None,
                preflight.changed,
                preflight.operation_count,
            )?;
            return Err(signal.to_string());
        }
        crate::bands::stage_profile::reconcile_legacy_module_seats(
            profile,
            module_root,
            &effective_receipt_dir,
            &mode,
        )?;
        let projection = load_profile_projection(profile, module_root, &BTreeSet::new())?;
        let execution_projection = projection.clone();
        let transaction = run_profile_engine_with_projection(
            profile,
            module_root,
            &effective_receipt_dir,
            &mode,
            true,
            Some(preflight),
            suite_debt.as_deref(),
            &execution_projection,
            context,
            Some(&carrier),
            receipt_retention,
            Some(receipt_dir),
            true,
        );
        let (changed, operation_count) = carrier
            .borrow()
            .deferred_terminal_summary
            .as_ref()
            .map(|summary| (summary.changed, summary.operation_count))
            .unwrap_or((false, 0));
        let transaction_guard = carrier.borrow_mut().sealed_projection.take();
        if let Err(error) = transaction {
            let Some(mut txn) = transaction_guard else {
                let failure_receipt = write_transaction_failure_run_receipt(
                    &effective_receipt_dir,
                    profile,
                    module_root,
                    "transaction-engine-failed",
                    Some(&error),
                    changed,
                    operation_count,
                );
                let restores = restore_known_good_pointer_movements(&carrier, &effective_receipt_dir);
                let restore_errors = pointer_restore_errors(&restores);
                let mut return_error = error.clone();
                append_errors(&mut return_error, &restore_errors);
                if let Err(write_error) = attach_pointer_rollback_to_run_receipt(
                    &effective_receipt_dir,
                    &error,
                    &restores,
                    &restore_errors,
                ) {
                    return_error.push_str(&format!("; rollback-incomplete: rollback-receipt-write-failed: {write_error}"));
                }
                if let Err(write_error) = failure_receipt {
                    return_error.push_str(&format!("; transaction-failure-receipt-write-failed: {write_error}"));
                }
                return Err(return_error);
            };
            let failure_receipt = write_transaction_failure_run_receipt(
                &effective_receipt_dir,
                profile,
                module_root,
                "transaction-engine-failed",
                Some(&error),
                changed,
                operation_count,
            );
            let mut return_error = error.clone();
            let (receipt, rollback_error) = if let Some(key) = mode.invocation() {
                let rollback = crate::atoms::r#do::transaction::rollback_projection(&mut txn, key);
                match rollback {
                    Ok(receipt) => (receipt, None),
                    Err(rollback_error) => (
                        crate::atoms::r#do::transaction::transaction_receipt(&txn),
                        Some(rollback_error),
                    ),
                }
            } else {
                (
                    crate::atoms::r#do::transaction::transaction_receipt(&txn),
                    Some("rollback-invocation-missing".to_owned()),
                )
            };
            let restores = restore_known_good_pointer_movements(&carrier, &effective_receipt_dir);
            if let Some(rollback_error) = rollback_error.as_ref() {
                return_error.push_str(&format!("; {rollback_error}"));
            }
            let pointer_errors = pointer_restore_errors(&restores);
            append_errors(&mut return_error, &pointer_errors);
            let failed_step = std::iter::once(error.as_str())
                .chain(rollback_error.as_deref())
                .chain(pointer_errors.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join("; ");
            if let Err(write_error) = write_transaction_rollback_receipt(
                &effective_receipt_dir,
                &txn,
                receipt,
                &failed_step,
                &restores,
            ) {
                return_error.push_str(&format!("; rollback-incomplete: rollback-receipt-write-failed: {write_error}"));
            }
            if let Err(write_error) = failure_receipt {
                return_error = format!(
                    "{return_error}; transaction-failure-receipt-write-failed: {write_error}"
                );
            }
            return Err(return_error);
        }
        let Some(mut txn) = transaction_guard else {
            let failure_receipt = write_transaction_failure_run_receipt(
                &effective_receipt_dir,
                profile,
                module_root,
                "transaction-missing",
                None,
                changed,
                operation_count,
            );
            let restores = restore_known_good_pointer_movements(&carrier, &effective_receipt_dir);
            let restore_errors = pointer_restore_errors(&restores);
            let mut return_error = "stage-profile-transaction-missing".to_string();
            append_errors(&mut return_error, &restore_errors);
            if let Err(write_error) = attach_pointer_rollback_to_run_receipt(
                &effective_receipt_dir,
                &return_error,
                &restores,
                &restore_errors,
            ) {
                return_error.push_str(&format!("; rollback-incomplete: rollback-receipt-write-failed: {write_error}"));
            }
            if let Err(write_error) = failure_receipt {
                return_error.push_str(&format!("; transaction-failure-receipt-write-failed: {write_error}"));
            }
            return Err(return_error);
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
                        changed,
                        operation_count,
                    );
                    let rollback =
                        crate::atoms::r#do::transaction::rollback_projection(&mut txn, key);
                    let (receipt, rollback_error) = match rollback {
                        Ok(receipt) => (receipt, None),
                        Err(rollback_error) => (
                            crate::atoms::r#do::transaction::transaction_receipt(&txn),
                            Some(rollback_error),
                        ),
                    };
                    let restores =
                        restore_known_good_pointer_movements(&carrier, &effective_receipt_dir);
                    let mut return_error = error.clone();
                    if let Some(rollback_error) = rollback_error.as_ref() {
                        return_error.push_str(&format!("; {rollback_error}"));
                    }
                    let pointer_errors = pointer_restore_errors(&restores);
                    append_errors(&mut return_error, &pointer_errors);
                    let failed_step = std::iter::once(error.as_str())
                        .chain(rollback_error.as_deref())
                        .chain(pointer_errors.iter().map(String::as_str))
                        .collect::<Vec<_>>()
                        .join("; ");
                    if let Err(write_error) = write_transaction_rollback_receipt(
                        &effective_receipt_dir,
                        &txn,
                        receipt,
                        &failed_step,
                        &restores,
                    ) {
                        return_error.push_str(&format!("; rollback-incomplete: rollback-receipt-write-failed: {write_error}"));
                    }
                    if let Err(write_error) = failure_receipt {
                        return_error = format!(
                            "{return_error}; transaction-failure-receipt-write-failed: {write_error}"
                        );
                    }
                    return Err(return_error);
                }
            }
        } else {
            let failure_receipt = write_transaction_failure_run_receipt(
                &effective_receipt_dir,
                profile,
                module_root,
                "transaction-invocation-missing",
                None,
                changed,
                operation_count,
            );
            let restores = restore_known_good_pointer_movements(&carrier, &effective_receipt_dir);
            let restore_errors = pointer_restore_errors(&restores);
            let mut return_error = "stage-profile-invocation-missing".to_string();
            append_errors(&mut return_error, &restore_errors);
            let transaction_receipt =
                crate::atoms::r#do::transaction::transaction_receipt(&txn);
            if let Err(write_error) = write_transaction_rollback_receipt(
                &effective_receipt_dir,
                &txn,
                transaction_receipt,
                &return_error,
                &restores,
            ) {
                return_error.push_str(&format!("; rollback-incomplete: rollback-receipt-write-failed: {write_error}"));
            }
            if let Err(write_error) = failure_receipt {
                return_error.push_str(&format!("; transaction-failure-receipt-write-failed: {write_error}"));
            }
            return Err(return_error);
        }
        let receipt = match crate::atoms::r#do::transaction::commit_projection(&mut txn) {
            Ok(receipt) => receipt,
            Err(error) => {
                let failure_receipt = write_transaction_failure_run_receipt(
                    &effective_receipt_dir,
                    profile,
                    module_root,
                    "transaction-commit-failed",
                    Some(&error),
                    changed,
                    operation_count,
                );
                let (receipt, rollback_error) = if let Some(key) = mode.invocation() {
                    match crate::atoms::r#do::transaction::rollback_projection(&mut txn, key) {
                        Ok(receipt) => (receipt, None),
                        Err(rollback_error) => (
                            crate::atoms::r#do::transaction::transaction_receipt(&txn),
                            Some(rollback_error),
                        ),
                    }
                } else {
                    (
                        crate::atoms::r#do::transaction::transaction_receipt(&txn),
                        Some("rollback-invocation-missing".to_owned()),
                    )
                };
                let restores = restore_known_good_pointer_movements(&carrier, &effective_receipt_dir);
                let pointer_errors = pointer_restore_errors(&restores);
                let mut return_error = error.clone();
                if let Some(rollback_error) = rollback_error.as_ref() {
                    return_error.push_str(&format!("; {rollback_error}"));
                }
                append_errors(&mut return_error, &pointer_errors);
                let failed_step = std::iter::once(error.as_str())
                    .chain(rollback_error.as_deref())
                    .chain(pointer_errors.iter().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join("; ");
                if let Err(write_error) = write_transaction_rollback_receipt(
                    &effective_receipt_dir,
                    &txn,
                    receipt,
                    &failed_step,
                    &restores,
                ) {
                    return_error.push_str(&format!("; rollback-incomplete: rollback-receipt-write-failed: {write_error}"));
                }
                if let Err(write_error) = failure_receipt {
                    return_error.push_str(&format!("; transaction-failure-receipt-write-failed: {write_error}"));
                }
                return Err(return_error);
            }
        };
        let mint = crate::atoms::attest::committed_syzygy_mint_with_sudoers(
            &effective_receipt_dir,
            &receipt,
            &txn.sealed.sudoers_fragments,
            &txn.sealed.snapshot.roots,
        );
        if let Err(error) = crate::atoms::attest::write_transaction_receipt(
            &effective_receipt_dir,
            &receipt,
            &mint,
            None,
        ) {
            write_transaction_failure_run_receipt(
                &effective_receipt_dir,
                profile,
                module_root,
                "transaction-receipt-failed",
                Some(&error),
                changed,
                operation_count,
            )?;
            return Err(error);
        }
        // The marker belongs to this carrier/run, not an older ledger pointer.
        // Commit and its durable transaction receipt must precede any exchange.
        if !carrier.borrow().rung_promoted.is_empty() {
            match crate::atoms::ask::ruyi::local_identity() {
                Ok(identity) => {
                    if let Err(error) = crate::atoms::ask::ruyi::register_promoted(
                        profile, &run_id, &receipt, &mint, &identity, &effective_receipt_dir,
                    ) {
                        crate::atoms::ask::ruyi::registrant::save_registration_failure(
                            &effective_receipt_dir,
                            &error,
                        )?;
                    }
                }
                Err(error) => {
                    crate::atoms::ask::ruyi::registrant::save_identity_absent(
                        &effective_receipt_dir,
                        "new-artifact",
                        &error,
                    )?;
                }
            }
        }
        let Some(summary) = carrier.borrow_mut().deferred_terminal_summary.take() else {
            write_transaction_failure_run_receipt(
                &effective_receipt_dir,
                profile,
                module_root,
                "transaction-terminal-summary-missing",
                None,
                changed,
                operation_count,
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
                changed,
                operation_count,
            )?;
            return Err(error);
        }
        if let Err(error) =
            crate::atoms::attest::augment_run_json_with_stamp(&effective_receipt_dir, &mint)
        {
            if let Err(write_error) = write_transaction_failure_run_receipt(
                &effective_receipt_dir,
                profile,
                module_root,
                "transaction-stamp-run-receipt-failed",
                Some(&error),
                changed,
                operation_count,
            ) {
                return Err(format!(
                    "{error}; transaction-stamp-run-failure-receipt-failed: {write_error}"
                ));
            }
            return Err(error);
        }
        Ok(())
    };
    let mut run_result = run();
    let mut lifecycle_receipt_ready =
        run_receipt_matches_invocation(&effective_receipt_dir, profile, apply);
    if let Some(run_error) = run_result.as_ref().err().cloned() {
        let existing_valid_receipt = valid_run_receipt(&effective_receipt_dir).is_some();
        let failure_receipt_result = if existing_valid_receipt {
            Ok(())
        } else {
            write_early_failed_run_receipt(
                &effective_receipt_dir,
                profile,
                module_root,
                apply,
                &run_error,
            )
        };
        let empty_ledger_result = if !existing_valid_receipt
            || run_receipt_matches_invocation(&effective_receipt_dir, profile, apply)
        {
            crate::receipts::write_profile_ledger_run(
                &effective_receipt_dir,
                Some(receipt_dir),
                profile,
                &run_id,
                &[],
                receipt_retention,
            )
            .map(|ledger_report| {
                if let Err(error) = crate::receipts::record_profile_ledger_projection(
                    &effective_receipt_dir,
                    receipt_retention,
                    &ledger_report,
                ) {
                    eprintln!("profile-ledger-projection-warning: {error}");
                }
            })
        } else {
            Ok(())
        };
        let mut receipt_errors = Vec::new();
        if let Err(error) = failure_receipt_result {
            receipt_errors.push(format!("failed-run-receipt-write-failed: {error}"));
        }
        if let Err(error) = empty_ledger_result {
            receipt_errors.push(format!("failed-run-ledger-write-failed: {error}"));
        }
        lifecycle_receipt_ready = receipt_errors.is_empty()
            && run_receipt_matches_invocation(&effective_receipt_dir, profile, apply);
        if !receipt_errors.is_empty() {
            run_result = Err(format!("{run_error}; {}", receipt_errors.join("; ")));
        }
    }
    let mut report = crate::atoms::attest::convergence_receipts::ReceiptPruneReport::default();
    let mut promoted = false;
    let mut promotion_attempted = false;
    let mut prune_attempted = false;
    let mut promotion_status = "skipped";
    let mut promotion_error = None;
    if !lifecycle_receipt_ready {
        let reason = format!(
            "receipt-lifecycle-run-receipt-missing {}",
            effective_receipt_dir.display()
        );
        report.warnings.push(reason.clone());
        promotion_error = Some(reason);
    } else if let Some(stem) = family_stem.as_deref() {
        match crate::atoms::attest::convergence_receipts::lock_receipt_parent(
            receipt_dir,
            "receipt-lifecycle",
        ) {
            Ok(_parent_lock) => {
                promotion_attempted = true;
                match crate::atoms::attest::convergence_receipts::promote_receipt_latest_locked(
                    receipt_dir,
                    &effective_receipt_dir,
                    &run_id,
                    "receipt-lifecycle",
                ) {
                    Ok(()) => {
                        promoted = true;
                        promotion_status = "promoted";
                    }
                    Err(error) => {
                        promotion_status = "failed";
                        promotion_error = Some(error);
                    }
                }
                prune_attempted = true;
                report = crate::atoms::attest::convergence_receipts::prune_receipt_family_locked_for_current(
                    receipt_dir,
                    stem,
                    receipt_retention,
                    &effective_receipt_dir,
                );
                if report.pruning_confined {
                    match crate::receipts::reconcile_profile_ledger_family(
                        &effective_receipt_dir,
                        receipt_dir,
                        profile,
                        receipt_retention,
                        stem,
                    ) {
                        Ok(warnings) => report.warnings.extend(warnings),
                        Err(error) => report.warnings.push(format!(
                            "profile-ledger-retention-reconcile-failed: {error}"
                        )),
                    }
                }
                if let Err(error) = crate::atoms::attest::convergence_receipts::clear_fixed_refusal_after_green(
                    receipt_dir,
                    &effective_receipt_dir,
                    stem,
                ) {
                    report.warnings.push(format!("receipt-refusal-clear-warning: {error}"));
                }
            }
            Err(reason) if reason.contains("receipt-lifecycle-parent-busy") => {
                let reason = reason.replacen(
                    "receipt-lifecycle-parent-busy",
                    "receipt-parent-busy",
                    1,
                );
                report.warnings.push(reason.clone());
                promotion_error = Some(reason);
            }
            Err(reason) => {
                promotion_status = "failed";
                report.warnings.push(format!("receipt-promotion-lock-failed: {reason}"));
                promotion_error = Some(reason);
            }
        }
    } else {
        report
            .warnings
            .push("receipt-promotion-skipped: receipt-family-stem-unavailable".to_string());
    }
    report.summarize_warnings();
    if let Err(error) = crate::receipts::record_receipt_cleanup(
        &effective_receipt_dir,
        &mut report,
    ) {
        report.warnings.push(format!(
            "receipt-cleanup-projection-write-failed: {error}"
        ));
        report.summarize_warnings();
    }
    let lifecycle_projection = serde_json::json!({
        "promotion_status": promotion_status,
        "promotion_attempted": promotion_attempted,
        "promoted": promoted,
        "promotion_error": promotion_error.clone(),
        "prune_attempted": prune_attempted,
        "pruning_confined": if prune_attempted { Some(report.pruning_confined) } else { None },
        "warnings": report.warnings.clone(),
    });
    if lifecycle_receipt_ready {
        let run_path = effective_receipt_dir.join("run.json");
        let lifecycle_projection_result = (|| -> Result<(), String> {
            let mut receipt = valid_run_receipt(&effective_receipt_dir)
                .ok_or_else(|| format!("receipt-lifecycle-run-receipt-unavailable {}", run_path.display()))?;
            let object = receipt
                .as_object_mut()
                .ok_or_else(|| format!("receipt-lifecycle-run-receipt-not-object {}", run_path.display()))?;
            object.insert("receipt_lifecycle".to_string(), lifecycle_projection);
            write_json(&run_path, &receipt)
        })();
        if let Err(error) = lifecycle_projection_result {
            report.warnings.push(format!(
                "receipt-lifecycle-projection-write-failed: {error}"
            ));
            report.summarize_warnings();
        }
    }
    if promotion_status == "failed" {
        let error = promotion_error
            .clone()
            .unwrap_or_else(|| "receipt-lifecycle-promotion-failed".to_string());
        println!("receipt_lifecycle.promotion_status=failed");
        println!("receipt_lifecycle.promotion_error={error}");
        println!("receipt_lifecycle.first_missing_signal=receipt-promotion-failed");
    }
    if !report.warnings.is_empty() {
        eprintln!("receipt-cleanup-warning: {}", report.warnings.join("; "));
    }
    run_result
}

fn write_transaction_failure_run_receipt(
    receipt_dir: &Path,
    profile: &Profile,
    module_root: &Path,
    fallback_signal: &str,
    error: Option<&str>,
    changed: bool,
    operation_count: usize,
) -> Result<(), String> {
    let signal = transaction_failure_signal(error, fallback_signal);
    let engine_debt = crate::bands::engine_artifact_exhaustion_debt(receipt_dir, true, None)
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| format!("transaction-engine-debt-serialize-failed: {error}"))?;
    let module_artifact_debt =
        crate::bands::module_artifact_debt::collect_exhaustion_receipts(receipt_dir)?;
    crate::receipts::write_engine_run_receipt_with_duration_and_steps_and_debt(
        receipt_dir,
        profile,
        true,
        false,
        changed,
        profile.modules.len(),
        operation_count,
        &signal,
        module_root,
        false,
        0,
        None,
        engine_debt.as_ref(),
        Some(&module_artifact_debt),
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
            "changed": changed,
            "operation_count": operation_count,
            "message": error.unwrap_or(fallback_signal),
            "error": error.unwrap_or(fallback_signal),
        }),
    )?;
    println!("schema=harmonia.run_profile.v1");
    let mut forwarded = serde_json::json!({
        "schema":"harmonia.run_profile.v1",
        "ok":false,
        "module_artifact_debt":module_artifact_debt.clone(),
        "overall_ok":false,
    });
    if let Some(debt) = engine_debt.as_ref() {
        forwarded["engine_debt"] = debt.clone();
    }
    let degraded = engine_debt.is_some() || !module_artifact_debt.is_empty();
    if degraded {
        forwarded["degraded"] = serde_json::json!(true);
        forwarded["overall_ok"] = serde_json::json!(false);
    }
    crate::hyalos::forward_receipt(
        "schema=harmonia.run_profile.v1",
        &if degraded {
            "schema=harmonia.run_profile.v1 ok=false degraded=true overall_ok=false"
        } else {
            "schema=harmonia.run_profile.v1 ok=false"
        },
        Some(forwarded),
        Some(false),
        None,
    );
    println!("ok=false");
    if degraded {
        println!("degraded=true");
        println!("overall_ok=false");
    }
    if let Some(debt) = engine_debt.as_ref() {
        println!(
            "engine_debt_first_missing_signal={}",
            debt["first_missing_signal"].as_str().unwrap_or("unknown")
        );
    }
    if let Some(debt) = module_artifact_debt.first() {
        if let Some(signal) = debt.get("first_missing_signal").and_then(serde_json::Value::as_str) {
            println!("module_artifact_debt_first_missing_signal={signal}");
        }
    }
    println!("changed={}", changed);
    println!("profile_id={}", profile.id);
    println!("module_count={}", profile.modules.len());
    println!("operation_count={}", operation_count);
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
    if let Some(signal) = error
        .split_whitespace()
        .find_map(|part| part.strip_prefix("defect="))
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
    mode: UpdateMode<'_>,
    context: Option<&crate::RunContext>,
    receipt_retention: usize,
) -> Result<(), String> {
    let materialize = match profile.id.as_str() {
        "homeserver" => materialize_homeserver_receipt_dir,
        "homeconsole" => materialize_homeconsole_receipt_dir,
        _ => materialize_tv_receipt_dir,
    };
    rolling_update_run(
        profile,
        module_root,
        receipt_dir,
        mode,
        context,
        enforce_update_suite(profile, module_root)?,
        receipt_retention,
        engine_run_lock_path(),
        materialize,
        try_acquire_homeconsole_update_lock,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    #[test]
    fn content_seat_failure_stops_only_apply_before_profile_molt() {
        let failed = ModuleExecution {
            ok: false,
            changed: false,
            operation_count: 1,
            first_missing_signal: Some("engine-content-seat-move-failed".into()),
            placements: Vec::new(),
        };
        assert_eq!(content_seat_apply_failure(&failed, true), Some("engine-content-seat-move-failed"));
        assert_eq!(content_seat_apply_failure(&failed, false), None);

        let unrelated = ModuleExecution {
            first_missing_signal: Some("engine-proof-validate-ladder-failed".into()),
            ..failed
        };
        assert_eq!(content_seat_apply_failure(&unrelated, true), None);
    }

    static ENGINE_TRANSACTION_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EngineTransactionEnvGuard(Vec<(&'static str, Option<std::ffi::OsString>)>);

    impl EngineTransactionEnvGuard {
        fn set(values: &[(&'static str, std::ffi::OsString)]) -> Self {
            let previous = values.iter().map(|(key, value)| {
                let old = std::env::var_os(key);
                std::env::set_var(key, value);
                (*key, old)
            }).collect();
            Self(previous)
        }

        fn clear(keys: &[&'static str]) -> Self {
            let previous = keys.iter().map(|key| {
                let old = std::env::var_os(key);
                std::env::remove_var(key);
                (*key, old)
            }).collect();
            Self(previous)
        }
    }

    impl Drop for EngineTransactionEnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.0.drain(..) {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    fn fixture_git(root: &Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .expect("run fixture git");
        assert!(output.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&output.stderr));
    }

    fn fixture_tree_bytes(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(root: &Path, path: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(path).expect("read fixture tree") {
                let entry = entry.expect("fixture entry");
                let path = entry.path();
                if entry.file_type().expect("fixture type").is_dir() {
                    visit(root, &path, files);
                } else {
                    files.insert(path.strip_prefix(root).unwrap().to_path_buf(), fs::read(path).expect("fixture bytes"));
                }
            }
        }
        let mut files = BTreeMap::new();
        if root.exists() {
            visit(root, root, &mut files);
        }
        files
    }

    fn fixture_materialize_receipt_dir(path: &Path, _run_id: &str) -> Result<PathBuf, String> {
        Ok(path.to_path_buf())
    }

    fn fixture_profile_source(source: &Path, module_id: &str, module_bytes: &[u8]) {
        let module = source.join("profiles/demo/modules").join(module_id);
        fs::create_dir_all(&module).expect("module fixture directory");
        fs::write(source.join("profiles/demo/index.json"), serde_json::json!({
            "id": "demo", "identity": "fixture", "modules": [module_id]
        }).to_string()).expect("profile index");
        fs::write(module.join("manifest.json"), serde_json::json!({
            "schema": "harmonia.module.ladder.v1", "id": module_id,
            "version": "1", "ladder": []
        }).to_string()).expect("module manifest");
        fs::write(module.join("payload.bin"), module_bytes).expect("module payload");
    }

    #[test]
    fn transaction_apply_acquires_artifact_pair_then_molts_new_profile_tree() {
        transaction_apply_acquires_artifact_pair_fixture(true);
    }

    #[test]
    fn transaction_apply_uses_real_layout_staging_then_molts_new_profile_tree() {
        transaction_apply_acquires_artifact_pair_fixture(false);
    }

    fn transaction_apply_acquires_artifact_pair_fixture(use_staged_override: bool) {
        use std::os::unix::fs::PermissionsExt;
        let _env_lock = ENGINE_TRANSACTION_ENV_LOCK.lock().unwrap();
        let root = tempfile::tempdir().expect("transaction fixture");
        let source = root.path().join("source-repository");
        fs::create_dir_all(&source).unwrap();
        fixture_git(&source, &["init", "-q"]);
        fixture_git(&source, &["config", "user.name", "Harmonia Fixture"]);
        fixture_git(&source, &["config", "user.email", "fixture@example.invalid"]);
        fs::write(source.join("Cargo.toml"), "[package]\nname = \"harmonia-fixture\"\nversion = \"0.1.0\"\n").unwrap();
        fs::create_dir_all(source.join("src/tools")).unwrap();
        fs::write(source.join("src/tools/.keep"), b"fixture tool directory\n").unwrap();
        fixture_profile_source(&source, "old-module", b"old profile module\n");
        fixture_git(&source, &["add", "."]);
        fixture_git(&source, &["commit", "-qm", "old profile"]);
        let old_head = crate::atoms::ask::pull_repo::source_head(&source, "owner").stdout.trim().to_string();
        let engine_source = root.path().join("engine-source");
        fixture_git(root.path(), &["clone", "--shared", source.to_str().unwrap(), engine_source.to_str().unwrap()]);
        fixture_git(&engine_source, &["checkout", "-q", &old_head]);
        assert_eq!(crate::atoms::ask::pull_repo::source_head(&engine_source, "owner").stdout.trim(), old_head);
        fs::remove_dir_all(source.join("profiles/demo/modules/old-module")).unwrap();
        fixture_profile_source(&source, "new-module", b"new-only profile module bytes\n");
        fs::write(source.join("profiles/demo/index.json"), serde_json::json!({
            "id": "demo", "identity": "fixture", "modules": ["new-module"]
        }).to_string()).unwrap();
        fixture_git(&source, &["add", "."]);
        fixture_git(&source, &["commit", "-qm", "new profile"]);
        let new_head = crate::atoms::ask::pull_repo::source_head(&source, "owner").stdout.trim().to_string();

        let installed_profile = root.path().join("installed/profiles/demo");
        let module_root = installed_profile.join("modules");
        fixture_profile_source(&root.path().join("installed"), "old-module", b"old profile module\n");
        fs::create_dir_all(&module_root).unwrap();
        let installed_binary = root.path().join("installed-engine");
        let staged_override = root.path().join("staged-engine");
        let artifact_bytes = b"#!/bin/sh\n# validated fixture release artifact\nexit 0\n";
        fs::write(&installed_binary, artifact_bytes).unwrap();
        if use_staged_override {
            fs::write(&staged_override, artifact_bytes).unwrap();
            fs::set_permissions(&staged_override, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::set_permissions(&installed_binary, fs::Permissions::from_mode(0o755)).unwrap();
        let running_sha = crate::bands::renew_self::install_bin_fingerprint(&installed_binary).unwrap();
        let appliance_config = root.path().join("appliance-config.json");
        let certificate = root.path().join("device-profile.json");
        fs::write(&appliance_config, serde_json::json!({
            "schema": "appliance.config.v1", "source_policy": "developer",
            "sources": {"harmonia": {"ref": "main", "candidates": [{"kind": "local-checkout", "path": source}]}}
        }).to_string()).unwrap();
        fs::write(&certificate, serde_json::json!({
            "schema": "homeserver.device-profile.v1", "kernel": {"profile": "demo"},
            "source_policy": "developer", "sources": {}
        }).to_string()).unwrap();
        let subscription = root.path().join("subscription.json");
        let interactables = root.path().join("interactables.json");
        let _clear_staged_override = EngineTransactionEnvGuard::clear(&["HARMONIA_TEST_ENGINE_STAGED_BIN"]);
        let mut test_env = vec![
            ("HARMONIA_TEST_APPLIANCE_CONFIG_PATH", appliance_config.as_os_str().to_owned()),
            ("HARMONIA_INTERACTABLES_PATH", interactables.as_os_str().to_owned()),
            ("HARMONIA_DEVICE_PROFILE_PATH", certificate.as_os_str().to_owned()),
            ("HARMONIA_SUBSCRIPTION_PATH", subscription.as_os_str().to_owned()),
            ("HARMONIA_TEST_ENGINE_INSTALL_BIN", installed_binary.as_os_str().to_owned()),
            ("HARMONIA_TEST_ENGINE_RUNNING_SHA", running_sha.into()),
        ];
        if use_staged_override {
            test_env.push(("HARMONIA_TEST_ENGINE_STAGED_BIN", staged_override.as_os_str().to_owned()));
        }
        let _test_env = EngineTransactionEnvGuard::set(&test_env);
        let artifact = crate::atoms::ask::fetch_artifact::Download {
            manifest: crate::atoms::ask::fetch_artifact::Manifest {
                schema: "harmonia.engine_artifact.v1".into(), component: "harmonia".into(),
                source_sha: new_head.clone(), target: "x86_64-unknown-linux-gnu".into(),
                sha256: String::new(), built_at: "fixture".into(), pipeline_url: "fixture".into(), env_sha: None,
            }, bytes: artifact_bytes.to_vec(), identity: "fixture".into(),
        };
        let _seam = crate::bands::renew_self::install_engine_test_seam(engine_source.clone(), Some(artifact));
        let profile = Profile { id: "demo".into(), identity: "fixture".into(), package_authority: None,
            modules: vec!["old-module".into()], hotfixes: Vec::new(), syzygy_declaration: None };
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let mode = UpdateMode::from_apply_flag_with_invocation(true, Some(&invocation));
        let receipt = root.path().join("receipt");
        let result = rolling_update_run(&profile, &module_root, &receipt, mode, None, None,
            root.path().join("lock"), fixture_materialize_receipt_dir,
            crate::atoms::r#do::convergence_lock::try_acquire_homeconsole_update_lock);
        assert!(result.is_ok(), "transaction apply failed: {result:?}");
        let acquired = root.path().join("engine-source");
        assert_eq!(crate::atoms::ask::pull_repo::source_head(&acquired, "owner").stdout.trim(), new_head);
        assert!(installed_profile.join("index.json").is_file());
        assert_eq!(fixture_tree_bytes(&module_root).get(Path::new("new-module/payload.bin")).unwrap(), b"new-only profile module bytes\n");
        assert!(!module_root.join("old-module").exists());
        let run: serde_json::Value = serde_json::from_slice(&fs::read(receipt.join("run.json")).unwrap()).unwrap();
        assert_eq!(run["ok"].as_bool(), Some(true));
        let preflight: serde_json::Value = serde_json::from_slice(&fs::read(receipt.join("engine-preflight/run.json")).unwrap()).unwrap();
        assert_eq!(preflight["engine_lane"], "artifact");
        assert_eq!(preflight["source_head"], new_head);
        assert_eq!(preflight["content_head_observed"], new_head);
        assert_eq!(preflight["content_head_matches"], true);
        let staged = if use_staged_override {
            staged_override
        } else {
            engine_source.join("target/release/harmonia")
        };
        if !use_staged_override {
            assert!(std::env::var_os("HARMONIA_TEST_ENGINE_STAGED_BIN").is_none());
        }
        assert_eq!(fs::read(&staged).unwrap(), artifact_bytes);
        assert_eq!(
            preflight["staged_sha256"],
            format!("{:x}", sha2::Sha256::digest(artifact_bytes))
        );
        assert_eq!(fs::read(installed_binary).unwrap(), artifact_bytes);
        let seat: serde_json::Value = serde_json::from_slice(
            &fs::read(receipt.join("engine-preflight/content-seat.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(seat["attempt"], "acquire-exact-source-head");
        assert_eq!(seat["matches"], true);
        let preflight_dir = receipt.join("engine-preflight");
        let proof_receipts = fs::read_dir(&preflight_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("proof-"))
            .count();
        assert_eq!(proof_receipts, 3, "one proof battery should emit its three receipts");
        assert!(preflight_dir.join("staged-build.json").is_file());
    }

    #[test]
    fn content_seat_move_failure_preserves_engine_and_prior_profile_tree() {
        use std::os::unix::fs::PermissionsExt;
        let _env_lock = ENGINE_TRANSACTION_ENV_LOCK.lock().unwrap();
        let root = tempfile::tempdir().expect("transaction fixture");
        let source = root.path().join("source-repository");
        fs::create_dir_all(&source).unwrap();
        fixture_git(&source, &["init", "-q"]);
        fixture_git(&source, &["config", "user.name", "Harmonia Fixture"]);
        fixture_git(&source, &["config", "user.email", "fixture@example.invalid"]);
        fixture_profile_source(&source, "new-module", b"new profile bytes\n");
        fixture_git(&source, &["add", "."]);
        fixture_git(&source, &["commit", "-qm", "new profile"]);
        let new_head = crate::atoms::ask::pull_repo::source_head(&source, "owner").stdout.trim().to_string();
        let installed_profile = root.path().join("installed/profiles/demo");
        let module_root = installed_profile.join("modules");
        fixture_profile_source(&root.path().join("installed"), "old-module", b"previous bytes\n");
        let previous_tree = fixture_tree_bytes(&installed_profile);
        let installed_binary = root.path().join("installed-engine");
        let staged_binary = root.path().join("staged-engine");
        let script = b"#!/bin/sh\nexit 0\n";
        fs::write(&installed_binary, script).unwrap();
        fs::write(&staged_binary, script).unwrap();
        fs::set_permissions(&installed_binary, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&staged_binary, fs::Permissions::from_mode(0o755)).unwrap();
        let binary_before = fs::read(&installed_binary).unwrap();
        let running_sha = crate::bands::renew_self::install_bin_fingerprint(&installed_binary).unwrap();
        let appliance_config = root.path().join("appliance-config.json");
        let certificate = root.path().join("device-profile.json");
        fs::write(&appliance_config, serde_json::json!({
            "schema": "appliance.config.v1", "source_policy": "developer",
            "sources": {"harmonia": {"ref": "main", "candidates": [{"kind": "local-checkout", "path": source}]}}
        }).to_string()).unwrap();
        fs::write(&certificate, serde_json::json!({
            "schema": "homeserver.device-profile.v1", "kernel": {"profile": "demo"},
            "source_policy": "developer", "sources": {}
        }).to_string()).unwrap();
        let subscription = root.path().join("subscription.json");
        let interactables = root.path().join("interactables.json");
        let _test_env = EngineTransactionEnvGuard::set(&[
            ("HARMONIA_TEST_APPLIANCE_CONFIG_PATH", appliance_config.as_os_str().to_owned()),
            ("HARMONIA_INTERACTABLES_PATH", interactables.as_os_str().to_owned()),
            ("HARMONIA_DEVICE_PROFILE_PATH", certificate.as_os_str().to_owned()),
            ("HARMONIA_SUBSCRIPTION_PATH", subscription.as_os_str().to_owned()),
            ("HARMONIA_TEST_ENGINE_INSTALL_BIN", installed_binary.as_os_str().to_owned()),
            ("HARMONIA_TEST_ENGINE_STAGED_BIN", staged_binary.as_os_str().to_owned()),
            ("HARMONIA_TEST_ENGINE_RUNNING_SHA", running_sha.into()),
        ]);
        let artifact = crate::atoms::ask::fetch_artifact::Download {
            manifest: crate::atoms::ask::fetch_artifact::Manifest {
                schema: "harmonia.engine_artifact.v1".into(), component: "harmonia".into(),
                source_sha: new_head, target: "x86_64-unknown-linux-gnu".into(),
                sha256: String::new(), built_at: "fixture".into(), pipeline_url: "fixture".into(), env_sha: None,
            }, bytes: script.to_vec(), identity: "fixture".into(),
        };
        let blocked_destination = root.path().join("engine-source-blocked");
        fs::write(&blocked_destination, b"not a directory").unwrap();
        let _seam = crate::bands::renew_self::install_engine_test_seam(blocked_destination, Some(artifact));
        let profile = Profile { id: "demo".into(), identity: "fixture".into(), package_authority: None,
            modules: vec!["old-module".into()], hotfixes: Vec::new(), syzygy_declaration: None };
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let mode = UpdateMode::from_apply_flag_with_invocation(true, Some(&invocation));
        let receipt = root.path().join("receipt");
        let result = rolling_update_run(&profile, &module_root, &receipt, mode, None, None,
            root.path().join("lock"), fixture_materialize_receipt_dir,
            crate::atoms::r#do::convergence_lock::try_acquire_homeconsole_update_lock);
        assert_eq!(result.as_ref().map_err(String::as_str), Err("engine-content-seat-move-failed"));
        assert_eq!(fs::read(&installed_binary).unwrap(), binary_before);
        assert_eq!(fixture_tree_bytes(&installed_profile), previous_tree);
        let run: serde_json::Value = serde_json::from_slice(&fs::read(receipt.join("run.json")).unwrap()).unwrap();
        assert_eq!(run["first_missing_signal"], "engine-content-seat-move-failed");
        let preflight: serde_json::Value = serde_json::from_slice(&fs::read(receipt.join("engine-preflight/run.json")).unwrap()).unwrap();
        assert_eq!(preflight["first_missing_signal"], "engine-content-seat-move-failed");
        assert_eq!(preflight["engine_lane"], "artifact");
    }


}
