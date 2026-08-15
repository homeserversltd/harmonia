use crate::module_dispatch::{reject_executable_sidecar, require_path, ModuleExecution};
use crate::tools::{ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::*;
use serde_json::json;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufReader, Read};

include!("build.rs");
include!("managed-files.rs");
include!("binary-install.rs");

pub const NAME: &str = "service-runtime";
pub const DESCRIPTION: &str = "Rust service runtime convergence primitive for source sync, managed files, build, install, systemd, and health proof.";
const SERVICE_RUNTIME_ARGS: &[ToolArg] = &[
    ToolArg::optional("module_id", ToolArgKind::String),
    ToolArg::required("component", ToolArgKind::String),
    ToolArg::optional("bearer", ToolArgKind::String),
    ToolArg::required("source_dir", ToolArgKind::String),
    ToolArg::required("install_bin", ToolArgKind::String),
    ToolArg::required("service", ToolArgKind::String),
    ToolArg::required("url", ToolArgKind::String),
    ToolArg::required("binary_name", ToolArgKind::String),
    ToolArg::required("op_prefix", ToolArgKind::String),
    ToolArg::required("run_schema", ToolArgKind::String),
    ToolArg::required("managed_files_schema", ToolArgKind::String),
    ToolArg::optional("managed_files", ToolArgKind::Json),
    ToolArg::optional("caduceus_profile_source", ToolArgKind::Json),
    ToolArg::optional("caduceus_commands", ToolArgKind::Json),
    ToolArg::optional("build_environment", ToolArgKind::Json),
];

pub const PERMUTATIONS: &[ToolPermutation] = &[
    ToolPermutation::new(
        "converge",
        "converge a Rust service runtime from typed constants",
        SERVICE_RUNTIME_ARGS,
    )
    .in_band(crate::tools::Placement::RestartServices),
    ToolPermutation::new(
        "managed-files",
        "run the managed-files service-runtime stage",
        SERVICE_RUNTIME_ARGS,
    )
    .in_band(crate::tools::Placement::BackfillFiles),
    ToolPermutation::new(
        "configuration-proposal",
        "propose configuration-only service-runtime files without writing targets",
        SERVICE_RUNTIME_ARGS,
    )
    .in_band(crate::tools::Placement::ProposeEdits),
    ToolPermutation::new(
        "build",
        "run the build service-runtime stage",
        SERVICE_RUNTIME_ARGS,
    )
    .in_band(crate::tools::Placement::RatchetBinaries),
    ToolPermutation::new(
        "binary-install",
        "run the binary-install service-runtime stage",
        SERVICE_RUNTIME_ARGS,
    )
    .in_band(crate::tools::Placement::RatchetBinaries),
];
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION, PERMUTATIONS);

fn is_hex_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| matches!(byte,b'0'..=b'9'|b'a'..=b'f'))
}
pub(crate) fn bench_source_gate(_stale_service_sha: &str) -> serde_json::Value {
    serde_json::json!({"fresh_source":true,"stale_service_ignored":true,"changed":false})
}

fn string_arg(args: &BTreeMap<String, Value>, name: &str) -> Result<String, String> {
    args.get(name)
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| format!("service-runtime-missing-{name}"))
}

pub(crate) fn execute_routine_stage(
    permutation: &str,
    args: &BTreeMap<String, Value>,
    manifest: &crate::ladder::LadderManifest,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
    carried: &mut Option<ServiceRuntimeState>,
) -> Result<(OperationOutcome, BTreeMap<String, Value>), String> {
    let op_prefix = string_arg(args, "op_prefix")?;
    let make = |suffix: String| Box::leak(suffix.into_boxed_str()) as &'static str;
    let spec = ServiceRuntimeSpec {
        op_prefix: make(op_prefix.clone()),
        run_schema: make(string_arg(args, "run_schema")?),
        managed_files_schema: make(string_arg(args, "managed_files_schema")?),
        source_op: make(format!("{op_prefix}-source-git-artifact")),
        source_sha_op: make(format!("{op_prefix}-source-sha")),
        managed_files_op: make(format!("{op_prefix}-managed-files")),
        build_op: make(format!("{op_prefix}-cargo-build")),
        binary_install_op: make(format!("{op_prefix}-binary-install")),
        daemon_reload_op: make(format!("{op_prefix}-daemon-reload")),
        service_enable_op: make(format!("{op_prefix}-service-enable")),
        service_active_op: make(format!("{op_prefix}-service-active")),
        service_op: make(format!("{op_prefix}-service")),
        health_op: make(format!("{op_prefix}-health")),
        binary_name: make(string_arg(args, "binary_name")?),
    };
    let module = module_from_args(args, &spec)?;
    let result = |ok, changed, message: &str| OperationOutcome {
        ok,
        changed,
        skipped: !apply,
        message: message.into(),
        command: None,
    };
    if carried.is_none() {
        *carried = Some(state_from_args(args)?);
    }
    let state = carried
        .as_mut()
        .ok_or_else(|| format!("service-runtime-state-missing-{permutation}"))?;
    match permutation {
        "managed-files" => {
            stage_managed_files(&module, receipt_dir, apply, &spec, state)?;
            let managed = state.managed.as_ref().unwrap();
            if let (Some(install), Some(service), Some(health)) = (
                state.install.as_ref(),
                state.service_outcome.as_ref(),
                state.health.as_ref(),
            ) {
                let ok = managed.ok && install.ok && service.ok && health.ok;
                let missing = if ok {
                    "none".into()
                } else if !managed.ok {
                    format!("{}-managed-file-missing", spec.op_prefix)
                } else if !install.ok {
                    format!("{}-binary-install-failed", spec.op_prefix)
                } else if !service.ok {
                    format!("{}-service-not-active", spec.op_prefix)
                } else {
                    format!("{}-health-failed", spec.op_prefix)
                };
                let changed =
                    state.source_changed || managed.changed || install.changed || service.changed;
                write_run_receipt(
                    receipt_dir,
                    &spec,
                    apply,
                    ok,
                    changed,
                    &missing,
                    &state.source_remote,
                    &state.source_reference,
                    &state.source_dir,
                    Some(&state.source_sha_value),
                )?;
            }
            Ok((
                result(managed.ok, managed.changed, "service-runtime managed-files"),
                BTreeMap::new(),
            ))
        }
        "configuration-proposal" => {
            stage_configuration_proposal(&module, receipt_dir, &spec, args, state)?;
            Ok((
                OperationOutcome {
                    ok: true,
                    changed: false,
                    skipped: true,
                    message: "service-runtime configuration proposal".into(),
                    command: None,
                },
                BTreeMap::new(),
            ))
        }
        "build" => {
            if let Some(v) =
                stage_build(&module, receipt_dir, apply, &spec, args, invocation, state)?
            {
                return Ok((
                    result(v.ok, v.changed, "service-runtime build"),
                    BTreeMap::new(),
                ));
            }
            Ok((
                result(
                    true,
                    state.build.as_ref().is_some_and(|v| v.is_some()),
                    "service-runtime build",
                ),
                BTreeMap::new(),
            ))
        }
        "binary-install" => {
            if let Some(v) = stage_binary_install(&module, receipt_dir, apply, &spec, state)? {
                return Ok((
                    result(v.ok, v.changed, "service-runtime binary-install"),
                    BTreeMap::new(),
                ));
            }
            let v = state.install.as_ref().unwrap();
            Ok((
                result(v.ok, v.changed, "service-runtime binary-install"),
                BTreeMap::new(),
            ))
        }
        other => Err(format!(
            "service-runtime-routine-permutation-unsupported-{other}"
        )),
    }
}

fn state_from_args(args: &BTreeMap<String, Value>) -> Result<ServiceRuntimeState, String> {
    let source_sha_value = args
        .get("source_sha")
        .or_else(|| args.get("resolved_commit"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let source_reference = args
        .get("source_reference")
        .and_then(Value::as_str)
        .or_else(|| args.get("component").and_then(Value::as_str))
        .unwrap_or("component")
        .to_string();
    let source_remote = args
        .get("source_remote")
        .and_then(Value::as_str)
        .or_else(|| (!source_sha_value.is_empty()).then_some(source_sha_value.as_str()))
        .unwrap_or(&source_reference)
        .to_string();
    Ok(ServiceRuntimeState {
        source_dir: PathBuf::from(string_arg(args, "source_dir")?),
        install_bin: PathBuf::from(string_arg(args, "install_bin")?),
        service: string_arg(args, "service")?,
        health_url: string_arg(args, "url")?,
        source_reference,
        source_remote,
        source_changed: args
            .get("source_changed")
            .or_else(|| args.get("changed"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        source_sha_ok: !source_sha_value.is_empty(),
        source_sha_value,
        managed: None,
        build: None,
        install: None,
        service_outcome: None,
        health: None,
    })
}
pub(crate) fn validate_ladder_args(args: &BTreeMap<String, Value>) -> Result<(), String> {
    build_environment(args, None)?;
    string_arg(args, "component")?;
    let op_prefix = string_arg(args, "op_prefix")?;
    let source_op = format!("{op_prefix}-source-git-artifact");
    let source_sha_op = format!("{op_prefix}-source-sha");
    let managed_files_op = format!("{op_prefix}-managed-files");
    let build_op = format!("{op_prefix}-cargo-build");
    let binary_install_op = format!("{op_prefix}-binary-install");
    let daemon_reload_op = format!("{op_prefix}-daemon-reload");
    let service_enable_op = format!("{op_prefix}-service-enable");
    let service_active_op = format!("{op_prefix}-service-active");
    let service_op = format!("{op_prefix}-service");
    let health_op = format!("{op_prefix}-health");
    let binary_name = string_arg(args, "binary_name")?;
    let spec = ServiceRuntimeSpec {
        op_prefix: Box::leak(op_prefix.into_boxed_str()),
        run_schema: Box::leak(string_arg(args, "run_schema")?.into_boxed_str()),
        managed_files_schema: Box::leak(string_arg(args, "managed_files_schema")?.into_boxed_str()),
        source_op: Box::leak(source_op.into_boxed_str()),
        source_sha_op: Box::leak(source_sha_op.into_boxed_str()),
        managed_files_op: Box::leak(managed_files_op.into_boxed_str()),
        build_op: Box::leak(build_op.into_boxed_str()),
        binary_install_op: Box::leak(binary_install_op.into_boxed_str()),
        daemon_reload_op: Box::leak(daemon_reload_op.into_boxed_str()),
        service_enable_op: Box::leak(service_enable_op.into_boxed_str()),
        service_active_op: Box::leak(service_active_op.into_boxed_str()),
        service_op: Box::leak(service_op.into_boxed_str()),
        health_op: Box::leak(health_op.into_boxed_str()),
        binary_name: Box::leak(binary_name.into_boxed_str()),
    };
    let module = module_from_args(args, &spec)?;
    validate(&module)
}

fn module_from_args(
    args: &BTreeMap<String, Value>,
    spec: &ServiceRuntimeSpec,
) -> Result<ModuleManifest, String> {
    let managed_files: Vec<ManagedFileManifest> = args
        .get("managed_files")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| format!("service-runtime-managed-files-invalid: {e}"))?
        .unwrap_or_default();
    let caduceus_profile_source: Option<CaduceusProfileSourceManifest> = args
        .get("caduceus_profile_source")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| format!("service-runtime-caduceus-profile-source-invalid: {e}"))?;
    let caduceus_commands: Vec<String> = args
        .get("caduceus_commands")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| format!("service-runtime-caduceus-commands-invalid: {e}"))?
        .unwrap_or_default();
    Ok(ModuleManifest {
        id: string_arg(args, "module_id").unwrap_or_else(|_| spec.op_prefix.to_string()),
        description: String::new(),
        command: None,
        args: vec![],
        cwd: None,
        service: Some(string_arg(args, "service")?),
        install_bin: Some(string_arg(args, "install_bin")?),
        url: Some(string_arg(args, "url")?),
        expected_contains: None,
        repo: None,
        path: None,
        branch: None,
        remote: None,
        lock: None,
        source_dir: Some(string_arg(args, "source_dir")?),
        install_profile: None,
        target_dir: None,
        packages: vec![],
        package_conflict_policy: None,
        package_conflict_paths: vec![],
        expected_files: vec![],
        binaries: vec![],
        services: vec![],
        user_services: vec![],
        groups: vec![],
        managed_files,
        caduceus_profile_source,
        caduceus_commands,
        template_files: vec![],
        variables: std::collections::HashMap::new(),
        optional: false,
        optional_warning: None,
    })
}

use std::fs;
use std::path::{Path, PathBuf};

pub(crate) struct ServiceRuntimeSpec {
    pub op_prefix: &'static str,
    pub run_schema: &'static str,
    pub managed_files_schema: &'static str,
    pub source_op: &'static str,
    pub source_sha_op: &'static str,
    pub managed_files_op: &'static str,
    pub build_op: &'static str,
    pub binary_install_op: &'static str,
    pub daemon_reload_op: &'static str,
    pub service_enable_op: &'static str,
    pub service_active_op: &'static str,
    pub service_op: &'static str,
    pub health_op: &'static str,
    pub binary_name: &'static str,
}

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    reject_executable_sidecar(module)?;
    require_path(module, &module.source_dir, "source_dir")?;
    require_path(module, &module.install_bin, "install_bin")?;
    require_path(module, &module.service, "service")?;
    require_path(module, &module.url, "url")?;
    Ok(())
}

pub(crate) struct ServiceRuntimeState {
    pub(crate) source_dir: PathBuf,
    pub(crate) install_bin: PathBuf,
    pub(crate) service: String,
    pub(crate) health_url: String,
    pub(crate) source_reference: String,
    pub(crate) source_remote: String,
    pub(crate) source_changed: bool,
    pub(crate) source_sha_ok: bool,
    pub(crate) source_sha_value: String,
    pub(crate) managed: Option<OperationOutcome>,
    pub(crate) build: Option<Option<crate::atoms::CommandObservation>>,
    pub(crate) install: Option<OperationOutcome>,
    pub(crate) service_outcome: Option<OperationOutcome>,
    pub(crate) health: Option<CmdResult>,
}

pub(crate) fn stage_managed_files(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
    spec: &ServiceRuntimeSpec,
    state: &mut ServiceRuntimeState,
) -> Result<(), String> {
    // Configuration declarations belong exclusively to the proposal lane. The
    // legacy managed-files actuator must retain software files only; otherwise
    // a direct invocation can write configuration paths.
    let managed_files = effective_managed_files(module, &state.source_dir)?
        .into_iter()
        .filter(|file| !matches!(crate::tools::files::classify_target(Path::new(&file.path)), crate::tools::files::TargetClass::Config))
        .collect::<Vec<_>>();
    if managed_files.is_empty() {
        fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
        crate::write_json(
            &receipt_dir.join(format!("{}-managed-files.json", spec.op_prefix)),
            &serde_json::json!({
                "schema": spec.managed_files_schema,
                "ok": true,
                "module": module.id,
                "drift": [],
                "missing_target_birth_debts": [],
                "written": [],
                "owner": null,
                "group": null,
                "apply": apply,
                "changed": false,
                "entries": [],
                "first_missing_signal": "none"
            }),
        )?;
        state.managed = Some(OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "converged-quiet (no software managed files)".into(),
            command: None,
        });
        return Ok(());
    }
    let managed = tools::files::converge_managed_files(
        &tools::files::ManagedFilesRequest {
            module_id: &module.id,
            files: &managed_files,
            owner: None,
            group: None,
            receipt_name: &format!("{}-managed-files", spec.op_prefix),
            schema: spec.managed_files_schema,
            first_missing_signal: &format!("{}-managed-file-missing", spec.op_prefix),
        },
        receipt_dir,
        apply,
    )?;
    state.managed = Some(managed);
    Ok(())
}

fn stage_configuration_proposal(
    module: &ModuleManifest,
    receipt_dir: &Path,
    spec: &ServiceRuntimeSpec,
    args: &BTreeMap<String, Value>,
    state: &mut ServiceRuntimeState,
) -> Result<(), String> {
    use sha2::Digest;
    let admitted: Vec<ManagedFileManifest> = args
        .get("managed_files")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| format!("service-runtime-proposal-managed-files-invalid: {e}"))?
        .unwrap_or_default();
    let admitted_paths: std::collections::BTreeSet<&str> =
        admitted.iter().map(|file| file.path.as_str()).collect();
    let files = effective_managed_files(module, &state.source_dir)?
        .into_iter()
        .filter(|file| {
            admitted_paths.contains(file.path.as_str())
                && matches!(crate::tools::files::classify_target(Path::new(&file.path)), crate::tools::files::TargetClass::Config)
        })
        .collect::<Vec<_>>();
    let source_root = receipt_dir.join(format!("{}-config-proposal-sources", spec.op_prefix));
    let mut entries = Vec::new();
    let mut proposal_entries = Vec::new();
    let mut missing = Vec::new();
    for file in &files {
        let relative = PathBuf::from(file.path.trim_start_matches('/'));
        let source = source_root.join(&relative);
        if let Some(parent) = source.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(&source, file.content.as_bytes()).map_err(|e| e.to_string())?;
        let target = PathBuf::from(&file.path);
        let meta = fs::symlink_metadata(&target).ok();
        let target_bytes = fs::read(&target).ok();
        let exists = meta.is_some();
        if !exists {
            missing.push(file.path.clone());
        }
        let content_equal = target_bytes.as_deref() == Some(file.content.as_bytes());
        let mode = file.mode.unwrap_or(0o644);
        let mode_equal = meta
            .as_ref()
            .map(|m| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    m.permissions().mode() & 0o7777 == mode
                }
                #[cfg(not(unix))]
                {
                    true
                }
            })
            .unwrap_or(false);
        proposal_entries.push(tools::files::FileConvergenceEntry {
            relative_path: relative.to_string_lossy().into_owned(),
            source: source.clone(),
            target: target.clone(),
            source_exists: true,
            target_exists_before: exists,
            content_equal_before: content_equal,
            mode_equal_before: mode_equal,
            target_exists_after: exists,
            content_equal_after: content_equal,
            mode_equal_after: mode_equal,
            changed: false,
            backed_up_to: None,
            final_mode: Some(mode),
            ownership_source: "unchanged".into(),
            observed_uid_before: None,
            observed_gid_before: None,
            observed_uid_after: None,
            observed_gid_after: None,
            ownership_changed: false,
            observed_uid: None,
            observed_gid: None,
            diff: None,
            diff_omitted: None,
        });
        let state_name = if exists { "observed" } else { "missing-target-birth-debt" };
        let drift_detected = exists && (!content_equal || !mode_equal);
        entries.push(serde_json::json!({
            "path": file.path, "target_exists_before": exists,
            "state": state_name,
            "mode": mode, "content_equal_before": content_equal, "mode_equal_before": mode_equal,
            "owner": Value::Null, "group": Value::Null, "owner_equal_before": true, "group_equal_before": true,
            "changed": false, "drift_detected": drift_detected, "written": false,
            "observed_state": {"target_exists": exists, "state": state_name,
                "content_equal": content_equal, "mode_equal": mode_equal,
                "owner_equal": true, "group_equal": true},
            "desired_state": {"content_sha256": format!("{:x}", sha2::Sha256::digest(file.content.as_bytes())),
                "mode": mode, "uid": null, "gid": null},
            "diff_decision": if exists && content_equal && mode_equal { "empty" } else { "different" },
            "movement": "report-only", "truthful_changed": false,
        }));
    }
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    crate::write_json(
        &receipt_dir.join(format!("{}-managed-files.json", spec.op_prefix)),
        &serde_json::json!({
            "schema": spec.managed_files_schema, "ok": true, "module": module.id,
            "drift": entries.iter().filter(|e| e.get("drift_detected").and_then(Value::as_bool).unwrap_or(false)).filter_map(|e| e.get("path").cloned()).collect::<Vec<_>>(),
            "missing_target_birth_debts": missing, "written": [], "owner": null, "group": null,
            "apply": false, "changed": false, "entries": entries, "first_missing_signal": "none",
        }),
    )?;
    for entry in &entries {
        let path = entry.get("path").and_then(Value::as_str).unwrap_or("file");
        crate::write_json(
            &receipt_dir.join(format!(
                "{}-managed-files-{}.json",
                spec.op_prefix,
                path.replace("/", "_").trim_start_matches("_")
            )),
            &serde_json::json!({"schema": "harmonia.files.managed_file.v1", "ok": true, "module": module.id, "path": path, "mode": entry.get("mode"), "owner": entry.get("owner"), "group": entry.get("group"), "owner_equal_before": entry.get("owner_equal_before"), "group_equal_before": entry.get("group_equal_before"), "apply": false, "target_exists_before": entry.get("target_exists_before"), "state": entry.get("state"), "changed": false, "drift_detected": entry.get("drift_detected"), "written": false, "observed_state": entry.get("observed_state"), "desired_state": entry.get("desired_state"), "diff_decision": entry.get("diff_decision"), "movement": "report-only", "truthful_changed": false, "first_missing_signal": "none"}),
        )?;
    }
    let request = tools::files::FileConvergenceRequest {
        source_root,
        target_root: PathBuf::from("/"),
        files: files
            .iter()
            .map(|file| tools::files::FileSpec {
                relative_path: PathBuf::from(file.path.trim_start_matches('/')),
                mode: file.mode.or(Some(0o644)),
            })
            .collect(),
        backup_existing: false,
        receipt_name: format!("{}-managed-files", spec.op_prefix),
        owner: None,
        group: None,
    };
    let outcome = tools::files::FileConvergenceOutcome {
        ok: true,
        changed: false,
        ownership_changed: false,
        checked: files.len(),
        written: 0,
        backed_up: 0,
        missing: Vec::new(),
        missing_target_birth_debts: Vec::new(),
        entries: proposal_entries,
        message: "configuration proposal emitted".into(),
    };
    let manifest = crate::ladder::LadderManifest {
        schema: crate::ladder::SCHEMA.to_string(),
        id: module.id.clone(),
        version: "0.0.0".into(),
        description: module.description.clone(),
        role: None,
        optional: false,
        optional_warning: None,
        group: None,
        constants: BTreeMap::new(),
        caduceus_commands: Vec::new(),
        files_root: None,
        config_deploy: Some("interactable".into()),
        ladder: Vec::new(),
        base_dir: receipt_dir.to_path_buf(),
    };
    crate::bands::propose_edits::refresh_interactables_for_convergence(&manifest, &request, &outcome)?;
    Ok(())
}

pub(crate) fn stage_build(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
    spec: &ServiceRuntimeSpec,
    args: &BTreeMap<String, Value>,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
    state: &mut ServiceRuntimeState,
) -> Result<Option<ModuleExecution>, String> {
    let source_dir = state.source_dir.clone();
    let install_bin = state.install_bin.clone();
    let source_sha_value = state.source_sha_value.clone();
    let artifact = source_dir.join("target/release").join(spec.binary_name);
    if !state.source_sha_ok || !is_hex_sha(&source_sha_value) {
        write_run_receipt(
            receipt_dir,
            spec,
            apply,
            false,
            true,
            &format!("{}-source-sha-missing", spec.op_prefix),
            &state.source_remote,
            &state.source_reference,
            &source_dir,
            None,
        )?;
        return Ok(Some(ModuleExecution::from_operations(
            vec![(
                spec.source_sha_op,
                OperationOutcome {
                    ok: false,
                    changed: false,
                    skipped: false,
                    message: format!("{} source sha missing", spec.op_prefix),
                    command: None,
                },
            )],
            &module.id,
        )));
    }
    let build_environment = build_environment(args, Some(&source_sha_value))?;

    let mut build_environment = build_environment;
    build_environment.insert(
        "CARGO_TARGET_DIR".into(),
        source_dir.join("target").to_string_lossy().into_owned(),
    );
    let environment: Vec<(String, String)> = build_environment.into_iter().collect();
    let build = crate::build_crate::run_build(
        &source_dir,
        &source_sha_value,
        None,
        &install_bin,
        &artifact,
        apply,
        &environment,
        crate::tools::command::DEFAULT_TIMEOUT_SECS,
        &receipt_dir.join("harmonia-atoms.log"),
        args.get("bearer")
            .and_then(Value::as_str)
            .unwrap_or("owner"),
        invocation,
    )?;
    if let Some(result) = &build {
        let build_cmd = CmdResult {
            ok: result.ok,
            code: result.code.unwrap_or(-1),
            stdout: result.stdout.clone(),
            stderr: result.stderr.clone(),
        };
        write_command_receipt(receipt_dir, spec.build_op, &build_cmd)?;
        if !build_cmd.ok {
            write_run_receipt(
                receipt_dir,
                spec,
                apply,
                false,
                true,
                &format!("{}-cargo-build-failed", spec.op_prefix),
                &state.source_sha_value,
                &state.source_sha_value,
                &source_dir,
                Some(&source_sha_value),
            )?;
            return Ok(Some(ModuleExecution::from_operations(
                vec![(
                    spec.build_op,
                    OperationOutcome {
                        ok: false,
                        changed: false,
                        skipped: false,
                        message: format!("{} cargo build failed", spec.op_prefix),
                        command: None,
                    },
                )],
                &module.id,
            )));
        }
    } else {
        write_skipped_build_receipt(receipt_dir, spec, &source_sha_value, "")?;
    }
    state.build = Some(build);
    Ok(None)
}

pub(crate) fn stage_binary_install(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
    spec: &ServiceRuntimeSpec,
    state: &mut ServiceRuntimeState,
) -> Result<Option<ModuleExecution>, String> {
    let install = if state
        .build
        .as_ref()
        .map(|build| build.is_some())
        .unwrap_or(false)
    {
        let artifact = state
            .source_dir
            .join("target/release")
            .join(spec.binary_name);
        install_binary(receipt_dir, spec, &artifact, &state.install_bin, apply)?
    } else {
        write_skipped_binary_install_receipt(receipt_dir, spec, &state.install_bin, apply)?;
        OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "converged-quiet".to_string(),
            command: None,
        }
    };
    if !install.ok {
        write_run_receipt(
            receipt_dir,
            spec,
            apply,
            false,
            install.changed,
            &format!("{}-binary-install-failed", spec.op_prefix),
            &state.source_remote,
            &state.source_reference,
            &state.source_dir,
            Some(&state.source_sha_value),
        )?;
        return Ok(Some(ModuleExecution::from_operations(
            vec![(spec.binary_install_op, install)],
            &module.id,
        )));
    }
    state.install = Some(install);
    Ok(None)
}

pub(crate) fn bench_build_environment(
    source_sha: &str,
) -> Result<BTreeMap<String, String>, String> {
    let args = [(
        "component".to_string(),
        Value::String("caduceus".to_string()),
    )]
    .into_iter()
    .collect();
    build_environment(&args, Some(source_sha))
}

pub(crate) fn bench_binary_install(
    receipt_dir: &Path,
    artifact: &Path,
    install_bin: &Path,
) -> Result<OperationOutcome, String> {
    let spec = ServiceRuntimeSpec {
        op_prefix: "caduceus-bench",
        run_schema: "harmonia.stillness-bench.caduceus.v1",
        managed_files_schema: "harmonia.stillness-bench.files.v1",
        source_op: "caduceus-bench-source",
        source_sha_op: "caduceus-bench-source-sha",
        managed_files_op: "caduceus-bench-managed-files",
        build_op: "caduceus-bench-build",
        binary_install_op: "caduceus-bench-binary-install",
        daemon_reload_op: "caduceus-bench-daemon-reload",
        service_enable_op: "caduceus-bench-service-enable",
        service_active_op: "caduceus-bench-service-active",
        service_op: "caduceus-bench-service",
        health_op: "caduceus-bench-health",
        binary_name: "caduceus",
    };
    install_binary(receipt_dir, &spec, artifact, install_bin, true)
}

pub(crate) fn bench_health_identity(
    receipt_dir: &Path,
    health_url: String,
    source_sha: String,
) -> Result<CmdResult, String> {
    let spec = ServiceRuntimeSpec {
        op_prefix: "caduceus-bench",
        run_schema: "harmonia.stillness-bench.caduceus.v1",
        managed_files_schema: "harmonia.stillness-bench.files.v1",
        source_op: "caduceus-bench-source",
        source_sha_op: "caduceus-bench-source-sha",
        managed_files_op: "caduceus-bench-managed-files",
        build_op: "caduceus-bench-build",
        binary_install_op: "caduceus-bench-binary-install",
        daemon_reload_op: "caduceus-bench-daemon-reload",
        service_enable_op: "caduceus-bench-service-enable",
        service_active_op: "caduceus-bench-service-active",
        service_op: "caduceus-bench-service",
        health_op: "caduceus-bench-health",
        binary_name: "caduceus",
    };
    let mut state = ServiceRuntimeState {
        source_dir: PathBuf::new(),
        install_bin: PathBuf::new(),
        service: String::new(),
        health_url,
        source_reference: "bench".into(),
        source_remote: source_sha.clone(),
        source_changed: false,
        source_sha_ok: true,
        source_sha_value: source_sha,
        managed: None,
        build: None,
        install: None,
        service_outcome: None,
        health: None,
    };
    let mut health = crate::check_health::probe(&crate::tools::health::ProbeRequest {
        url: &state.health_url,
        retries: 5,
        timeout_secs: 3,
        expected_contains: None,
    });
    let observed = health
        .ok
        .then(|| serde_json::from_str::<Value>(&health.stdout).ok())
        .flatten()
        .and_then(|v| {
            v.get("build_sha")
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    if health.ok && observed.as_deref() != Some(state.source_sha_value.as_str()) {
        health.ok = false;
        health.code = 1;
        health.stderr = format!(
            "service-runtime-act-did-not-converge expected_build_sha={} observed_build_sha={}",
            state.source_sha_value,
            observed.as_deref().unwrap_or("unavailable")
        );
    }
    write_command_receipt(receipt_dir, spec.health_op, &health)?;
    state.health = Some(health);
    state
        .health
        .take()
        .ok_or_else(|| "caduceus-bench-health-missing".to_string())
}

fn write_run_receipt(
    receipt_dir: &Path,
    spec: &ServiceRuntimeSpec,
    apply: bool,
    ok: bool,
    changed: bool,
    first_missing_signal: &str,
    repo: &str,
    branch: &str,
    source_dir: &Path,
    source_sha: Option<&str>,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema": spec.run_schema,
            "ok": ok,
            "changed": changed,
            "mutation": apply,
            "repo": repo,
            "branch": branch,
            "source_dir": source_dir,
            "source_sha": source_sha,
            "first_missing_signal": first_missing_signal,
        }),
    )
}
