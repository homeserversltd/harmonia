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
// Compatibility/profile entrypoints remain here; the durable transaction owner lives in ritual.rs.
pub(crate) use super::ritual::{
    apply_projection, commit_projection, compute_syzygy_sha, project_update_set_v1,
    rollback_projection, seal_projection, snapshot, snapshot_services, validate_exact_root,
    validate_exact_root_at, validate_member_scoped_target, ProjectionChild, ProjectionTransaction,
    SealedProjection, Snapshot, TransactionReceipt, TransactionState,
};

fn content_seat_apply_failure(preflight: &ModuleExecution, apply: bool) -> Option<&str> {
    (apply)
        .then(|| preflight.first_missing_signal.as_deref())
        .flatten()
        .filter(|signal| crate::bands::renew_self::is_content_seat_failure(signal))
}

pub(crate) fn rolling_update_run(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode<'_>,
    context: Option<&crate::RunContext>,
    suite_debt: Option<String>,
    lock_path: PathBuf,
    materialize_receipt: fn(&Path, &str) -> Result<PathBuf, String>,
    try_acquire_lock: fn(&Path) -> Result<ConvergenceLockGuard, ConvergenceLockBusy>,
) -> Result<(), String> {
    let _mint_seats = crate::atoms::ask::mint_seats::at_start();
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
        carrier.borrow_mut().rung_promoted.clear();
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
                write_transaction_failure_run_receipt(
                    &effective_receipt_dir,
                    profile,
                    module_root,
                    "transaction-engine-failed",
                    Some(&error),
                    changed,
                    operation_count,
                )?;
                return Err(error);
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
            if let Some(key) = mode.invocation() {
                if let Ok(receipt) =
                    crate::atoms::r#do::transaction::rollback_projection(&mut txn, key)
                {
                    let mint =
                        crate::atoms::attest::committed_syzygy_mint(&effective_receipt_dir, &receipt);
                    let _ = crate::atoms::attest::write_transaction_receipt(
                        &effective_receipt_dir,
                        &receipt,
                        &mint,
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
                changed,
                operation_count,
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
                        changed,
                        operation_count,
                    );
                    if let Ok(receipt) =
                        crate::atoms::r#do::transaction::rollback_projection(&mut txn, key)
                    {
                        let mint = crate::atoms::attest::committed_syzygy_mint(
                            &effective_receipt_dir,
                            &receipt,
                        );
                        let _ = crate::atoms::attest::write_transaction_receipt(
                            &effective_receipt_dir,
                            &receipt,
                            &mint,
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
                changed,
                operation_count,
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
                    changed,
                    operation_count,
                )?;
                return Err(error);
            }
        };
        let mint = crate::atoms::attest::committed_syzygy_mint(&effective_receipt_dir, &receipt);
        if let Err(error) =
            crate::atoms::attest::write_transaction_receipt(
                &effective_receipt_dir,
                &receipt,
                &mint,
                None,
            )
        {
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
            let identity = crate::atoms::ask::ruyi::local_identity()?;
            crate::atoms::ask::ruyi::register_promoted(
                profile, &run_id, &receipt, &mint, &identity, &effective_receipt_dir,
            )?;
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
    changed: bool,
    operation_count: usize,
) -> Result<(), String> {
    let signal = transaction_failure_signal(error, fallback_signal);
    write_engine_run_receipt_with_duration(
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
    crate::hyalos::forward_receipt(
        "schema=harmonia.run_profile.v1",
        "schema=harmonia.run_profile.v1 ok=false",
        Some(serde_json::json!({"schema":"harmonia.run_profile.v1","ok":false})),
        Some(false),
            None,
);
    println!("ok=false");
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
) -> Result<(), String> {
    rolling_update_run(
        profile,
        module_root,
        receipt_dir,
        mode,
        context,
        enforce_update_suite(profile, module_root)?,
        engine_run_lock_path(),
        materialize_tv_receipt_dir,
        try_acquire_homeconsole_update_lock,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let staged_binary = root.path().join("staged-engine");
        let script = b"#!/bin/sh\nexit 0\n";
        fs::write(&installed_binary, script).unwrap();
        fs::write(&staged_binary, script).unwrap();
        fs::set_permissions(&installed_binary, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&staged_binary, fs::Permissions::from_mode(0o755)).unwrap();
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
                source_sha: new_head.clone(), target: "x86_64-unknown-linux-gnu".into(),
                sha256: String::new(), built_at: "fixture".into(), pipeline_url: "fixture".into(), env_sha: None,
            }, bytes: script.to_vec(), identity: "fixture".into(),
        };
        let _seam = crate::bands::renew_self::install_engine_test_seam(engine_source, Some(artifact));
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

    #[test]
    fn band_walk_preserves_failed_module_a_aggregate_after_module_b_changes() {
        let tree = tempfile::tempdir().expect("module tree");
        let receipt_dir = tempfile::tempdir().expect("receipt directory");
        let target = tree.path().join("created-by-module-b");
        fs::create_dir_all(tree.path().join("module-b")).expect("module-b directory");
        fs::write(
            tree.path().join("module-b/manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema": "harmonia.module.ladder.v1",
                "id": "module-b",
                "version": "1",
                "ladder": [{
                    "step_id": "module-b-directories",
                    "tool": "files",
                    "permutation": "managed-directories",
                    "args": {"directories": [{
                        "path": target,
                        "mode": 493,
                        "owner": "1000",
                        "group": "1000"
                    }]},
                    "on_failure": "stop"
                }]
            }))
            .expect("module-b manifest"),
        )
        .expect("write module-b manifest");
        assert!(!target.exists());

        let profile = Profile {
            id: "demo".into(),
            identity: "test".into(),
            package_authority: None,
            modules: vec!["module-a".into(), "module-b".into()],
            hotfixes: Vec::new(),
            syzygy_declaration: None,
        };
        let projection = crate::bands::stage_profile::projection::load_profile_projection(
            &profile,
            tree.path(),
            &BTreeSet::new(),
        )
        .expect("profile projection");
        assert!(projection.errors.contains_key("module-a"));
        assert!(projection.modules.contains_key("module-b"));

        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let mode = UpdateMode::from_apply_flag_with_invocation(true, Some(&invocation));
        let preflight = ModuleExecution {
            ok: true,
            changed: false,
            operation_count: 0,
            first_missing_signal: None,
            placements: Vec::new(),
        };
        let carrier = Rc::new(RefCell::new(RunCarrier::default()));
        let engine_error = crate::bands::run_profile_engine_with_projection(
            &profile,
            tree.path(),
            receipt_dir.path(),
            &mode,
            true,
            Some(preflight),
            None,
            &projection,
            None,
            Some(&carrier),
            false,
        )
        .expect_err("missing module-a must fail the apply run");
        assert!(
            target.is_dir(),
            "module-b must still execute after module-a"
        );

        let run_path = receipt_dir.path().join("run.json");
        let first_run: serde_json::Value =
            serde_json::from_reader(fs::File::open(&run_path).expect("band-walk run receipt"))
                .expect("valid band-walk run receipt");
        let observed_changed = first_run["changed"].as_bool().expect("changed bool");
        let observed_operation_count = first_run["operation_count"]
            .as_u64()
            .expect("operation count") as usize;
        let observed_signal = first_run["first_missing_signal"]
            .as_str()
            .expect("first missing signal")
            .to_string();
        assert!(!first_run["ok"].as_bool().expect("ok bool"));
        assert!(observed_changed);
        assert!(observed_operation_count > 0);
        assert!(observed_signal.contains("module-a"));

        write_transaction_failure_run_receipt(
            receipt_dir.path(),
            &profile,
            tree.path(),
            &observed_signal,
            None,
            observed_changed,
            observed_operation_count,
        )
        .expect("transaction failure receipt");
        let rewritten: serde_json::Value =
            serde_json::from_reader(fs::File::open(&run_path).expect("rewritten run receipt"))
                .expect("valid rewritten run receipt");
        assert_eq!(rewritten["ok"], false);
        assert_eq!(rewritten["changed"].as_bool(), Some(observed_changed));
        assert_eq!(
            rewritten["operation_count"].as_u64(),
            Some(observed_operation_count as u64)
        );
        assert_eq!(rewritten["first_missing_signal"], observed_signal);

        let event = fs::read_to_string(receipt_dir.path().join("events.jsonl"))
            .expect("event receipt")
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|event| event["event"] == "transaction-failed")
            .expect("transaction-failed event");
        assert_eq!(event["ok"], false);
        assert_eq!(event["changed"].as_bool(), Some(observed_changed));
        assert_eq!(
            event["operation_count"].as_u64(),
            Some(observed_operation_count as u64)
        );
        assert_eq!(event["first_missing_signal"], observed_signal);
        assert!(engine_error.contains("module-a"));
    }
}
