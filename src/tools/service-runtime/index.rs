use crate::tools::{ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::module_dispatch::{reject_executable_sidecar, require_path, ModuleExecution};
use crate::*;
use serde_json::json;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufReader, Read};

include!("build.rs");
include!("source-gate.rs");
include!("managed-files.rs");
include!("binary-install.rs");
include!("service-epilogue.rs");
include!("health-proof.rs");

pub const NAME: &str = "service-runtime";
pub const DESCRIPTION: &str = "Rust service runtime convergence primitive for source sync, managed files, build, install, systemd, and health proof.";
pub const PERMUTATIONS: &[ToolPermutation] = &[ToolPermutation::new(
    "converge",
    "converge a Rust service runtime from typed constants",
    &[
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
    ],
)];
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION, PERMUTATIONS);

fn string_arg(args: &BTreeMap<String, Value>, name: &str) -> Result<String, String> {
    args.get(name)
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| format!("service-runtime-missing-{name}"))
}


pub(crate) fn execute_ladder_step(
    args: &BTreeMap<String, Value>,
    receipt_dir: &Path,
    apply: bool,
    source_plan: &tools::git_artifact::SourcePlan,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<ModuleExecution, String> {
    build_environment(args, None)?;
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
    execute(
        &module,
        receipt_dir,
        apply,
        &spec,
        args.get("bearer").and_then(Value::as_str),
        args,
        source_plan,
        invocation,
    )
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

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
    spec: &ServiceRuntimeSpec,
    bearer: Option<&str>,
    args: &BTreeMap<String, Value>,
    source_plan: &tools::git_artifact::SourcePlan,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<ModuleExecution, String> {
    validate(module)?;
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;

    let source_dir = PathBuf::from(require_path(module, &module.source_dir, "source_dir")?);
    let install_bin = PathBuf::from(require_path(module, &module.install_bin, "install_bin")?);
    let service = require_path(module, &module.service, "service")?;
    let health_url = require_path(module, &module.url, "url")?;

    let mut source_plan = source_plan.clone();
    if let Some(bearer) = bearer {
        source_plan.bearer = bearer.to_string();
    }
    let source_bearer = source_plan.bearer.clone();
    let source_gate = tools::comparison::execute(
        || {
            let remote_probe =
                apply.then(|| tools::git_artifact::probe_declared_remote_head(&source_plan));
            let promoted_source_head = remote_probe
                .as_ref()
                .and_then(|probe| probe.remote_sha.as_ref())
                .map(|_| tools::git_artifact::source_head(&source_dir, &source_bearer));
            let installed_binary_present = fs::symlink_metadata(&install_bin)
                .map(|metadata| metadata.file_type().is_file())
                .unwrap_or(false);
            let installed_build_sha = installed_binary_present
                .then(|| read_installed_build_sha(health_url))
                .flatten();
            Ok::<_, String>(SourceGateObservation {
                remote_probe,
                promoted_source_head,
                installed_binary_present,
                installed_build_sha,
            })
        },
        |observation| {
            if observation.decision() == SourceGateDecision::ConfirmedMatch {
                tools::comparison::DiffDecision::Empty
            } else {
                tools::comparison::DiffDecision::Different
            }
        },
        |_, _| {
            if apply {
                Ok(tools::git_artifact::acquire_source(&source_plan, invocation))
            } else {
                Ok(tools::git_artifact::SourceOutcome {
                    ok: true,
                    changed: false,
                    receipt: tools::git_artifact::SourceReceipt {
                        attempts: Vec::new(),
                        served_index: None,
                        resolved_commit: None,
                        promotion: "planned source acquisition".to_string(),
                    },
                })
            }
        },
    )?;
    let source_gate_matched = source_gate.decision() == tools::comparison::DiffDecision::Empty;
    let remote_probe = source_gate.observation().remote_probe.clone();
    let promoted_source_head = source_gate.observation().promoted_source_head.clone();
    let installed_binary_present = source_gate.observation().installed_binary_present;
    let installed_build_sha = source_gate.observation().installed_build_sha.clone();
    let source_gate_decision = source_gate.observation().decision();
    let git_outcome = match source_gate {
        tools::comparison::ComparisonRun::Current { .. } => {
            let source_sha = promoted_source_head
                .as_ref()
                .map(|result| result.stdout.trim())
                .unwrap_or_default();
            tools::git_artifact::SourceOutcome {
                ok: true,
                changed: false,
                receipt: tools::git_artifact::SourceReceipt {
                    attempts: Vec::new(),
                    served_index: remote_probe.as_ref().and_then(|probe| probe.candidate_index),
                    resolved_commit: Some(source_sha.to_string()),
                    promotion: format!(
                        "state=converged-quiet; acquire_skipped=true; remote_sha={source_sha}; promoted_source_sha={source_sha}; installed_binary_present={installed_binary_present}; installed_build_sha={}",
                        installed_build_sha.as_deref().unwrap_or_default(),
                    ),
                },
            }
        }
        tools::comparison::ComparisonRun::Moved { movement, .. } => movement,
    };
    write_source_gate_receipt(
        receipt_dir,
        spec,
        remote_probe.as_ref(),
        promoted_source_head.as_ref(),
        installed_binary_present,
        installed_build_sha.as_deref(),
        source_gate_decision,
        &git_outcome,
    )?;
    let source_command = source_outcome_cmd(&git_outcome);
    write_command_receipt(receipt_dir, spec.source_op, &source_command)?;
    if !git_outcome.ok {
        write_run_receipt(
            receipt_dir,
            spec,
            apply,
            false,
            git_outcome.changed,
            &format!("{}-source-git-artifact-failed", spec.op_prefix),
            &source_plan.reference,
            &source_plan.reference,
            &source_dir,
            None,
        )?;
        return Ok(ModuleExecution::from_operations(
            vec![(
                spec.source_op,
                OperationOutcome {
                    ok: false,
                    changed: git_outcome.changed,
                    skipped: false,
                    message: format!("{} source sync failed", spec.op_prefix),
                    command: None,
                },
            )],
            &module.id,
        ));
    }

    let source_sha = promoted_source_head
        .filter(|_| source_gate_matched)
        .unwrap_or_else(|| tools::git_artifact::source_head(&source_dir, &source_bearer));
    write_source_sha_receipt(receipt_dir, spec.source_sha_op, &source_sha, &source_bearer)?;
    let source_sha_value = source_sha.stdout.trim().to_string();

    let managed_files = effective_managed_files(module, &source_dir)?;
    // pali:harmonia-apply-ladder-law: SoftwareApplyAuthorization is structurally
    // bounded to SoftwarePlane; configuration paths can only be observed here.
    let config_write = managed_files.iter().any(|file| crate::ladder::is_configuration_path(Path::new(&file.path)));
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
        apply && !config_write,
    )?;
    if config_write {
        let source_root = receipt_dir.join(format!("{}-config-proposal-sources", spec.op_prefix));
        let mut files = Vec::new();
        let mut entries = Vec::new();
        for file in managed_files.iter().filter(|file| crate::ladder::is_configuration_path(Path::new(&file.path))) {
            let relative = PathBuf::from(file.path.trim_start_matches('/'));
            let source = source_root.join(&relative);
            if let Some(parent) = source.parent() { fs::create_dir_all(parent).map_err(|error| error.to_string())?; }
            fs::write(&source, file.content.as_bytes()).map_err(|error| error.to_string())?;
            let target = PathBuf::from(&file.path);
            let target_bytes = fs::read(&target).ok();
            let target_exists = target_bytes.is_some();
            let content_equal = target_bytes.as_deref() == Some(file.content.as_bytes());
            let final_mode = file.mode.or(Some(0o644));
            let mode_equal = target.metadata().ok().map(|metadata| {
                #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; metadata.permissions().mode() & 0o7777 == final_mode.unwrap_or(0o644) }
                #[cfg(not(unix))] { true }
            }).unwrap_or(false);
            files.push(tools::files::FileSpec { relative_path: relative.clone(), mode: final_mode });
            entries.push(tools::files::FileConvergenceEntry {
                relative_path: relative.to_string_lossy().into_owned(), source, target, source_exists: true,
                target_exists_before: target_exists, content_equal_before: content_equal, mode_equal_before: mode_equal,
                target_exists_after: target_exists, content_equal_after: content_equal, mode_equal_after: mode_equal,
                changed: false, backed_up_to: None, final_mode, ownership_source: "unchanged".to_string(),
                observed_uid_before: None, observed_gid_before: None, observed_uid_after: None, observed_gid_after: None,
                ownership_changed: false, observed_uid: None, observed_gid: None, diff: None, diff_omitted: None,
            });
        }
        let request = tools::files::FileConvergenceRequest { source_root, target_root: PathBuf::from("/"), files,
            backup_existing: false, receipt_name: format!("{}-managed-files", spec.op_prefix), owner: None, group: None };
        let outcome = tools::files::FileConvergenceOutcome { ok: managed.ok, changed: false, ownership_changed: false,
            checked: entries.len(), written: 0, backed_up: 0, missing: Vec::new(), missing_target_birth_debts: Vec::new(),
            entries, message: managed.message.clone() };
        let manifest = crate::ladder::LadderManifest { schema: crate::ladder::SCHEMA.to_string(), id: module.id.clone(),
            version: "0.0.0".to_string(), description: module.description.clone(), role: None, optional: false,
            optional_warning: None, group: None, constants: BTreeMap::new(), caduceus_commands: Vec::new(), files_root: None,
            config_deploy: Some("interactable".to_string()), ladder: Vec::new(), base_dir: receipt_dir.to_path_buf() };
        crate::refresh_interactables_for_convergence(&manifest, &request, &outcome)?;
    }

    if !apply {
        let managed_missing_signal = format!("{}-managed-file-missing", spec.op_prefix);
        let first_missing = if managed.ok {
            "none"
        } else {
            managed_missing_signal.as_str()
        };
        write_run_receipt(
            receipt_dir,
            spec,
            apply,
            managed.ok,
            git_outcome.changed || managed.changed,
            first_missing,
            &source_plan.reference,
            &source_plan.reference,
            &source_dir,
            if is_hex_sha(&source_sha_value) {
                Some(source_sha_value.as_str())
            } else {
                None
            },
        )?;
        return Ok(ModuleExecution::from_operations(
            vec![
                (
                    spec.source_op,
                    OperationOutcome {
                        ok: true,
                        changed: git_outcome.changed,
                        skipped: false,
                        message: format!("{} source planned", spec.op_prefix),
                        command: None,
                    },
                ),
                (spec.managed_files_op, managed),
            ],
            &module.id,
        ));
    }

    if !source_sha.ok || !is_hex_sha(&source_sha_value) {
        write_run_receipt(
            receipt_dir,
            spec,
            apply,
            false,
            true,
            &format!("{}-source-sha-missing", spec.op_prefix),
            &source_plan.reference,
            &source_plan.reference,
            &source_dir,
            None,
        )?;
        return Ok(ModuleExecution::from_operations(
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
        ));
    }

    let build_environment = build_environment(args, Some(&source_sha_value))?;

    let environment: Vec<(String, String)> = build_environment.into_iter().collect();
    let build = crate::build_crate::run_build(
        &source_dir, &source_sha_value, installed_build_sha.as_deref(), &install_bin, apply,
        &environment, crate::tools::command::DEFAULT_TIMEOUT_SECS,
        &receipt_dir.join("harmonia-atoms.log"), &source_bearer,
        invocation,
    )?;
    let install = if let Some(result) = build {
        let build = CmdResult { ok: result.ok, code: result.code.unwrap_or(-1), stdout: result.stdout, stderr: result.stderr };
        write_command_receipt(receipt_dir, spec.build_op, &build)?;
        if !build.ok {
            write_run_receipt(
                receipt_dir,
                spec,
                apply,
                false,
                true,
                &format!("{}-cargo-build-failed", spec.op_prefix),
                &source_plan.reference,
                &source_plan.reference,
                &source_dir,
                Some(&source_sha_value),
            )?;
            return Ok(ModuleExecution::from_operations(
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
            ));
        }

        let artifact = source_dir.join("target/release").join(spec.binary_name);
        install_binary(receipt_dir, spec, &artifact, &install_bin, apply)?
    } else {
        write_skipped_build_receipt(
            receipt_dir,
            spec,
            &source_sha_value,
            remote_probe
                .as_ref()
                .and_then(|probe| probe.remote_sha.as_deref())
                .unwrap_or_default(),
        )?;
        write_skipped_binary_install_receipt(receipt_dir, spec, &install_bin, apply)?;
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
            &source_plan.reference,
            &source_plan.reference,
            &source_dir,
            Some(&source_sha_value),
        )?;
        return Ok(ModuleExecution::from_operations(
            vec![(spec.binary_install_op, install)],
            &module.id,
        ));
    }

    let service_outcome = ensure_service_active(
        receipt_dir,
        spec,
        service,
        apply,
        managed.changed,
        install.changed,
        invocation,
    )?;
    let health = health_probe(health_url, 5, 3);
    write_command_receipt(receipt_dir, spec.health_op, &health)?;

    let ok = managed.ok && install.ok && service_outcome.ok && health.ok;
    let first_missing_signal = if ok {
        "none".to_string()
    } else if !managed.ok {
        format!("{}-managed-file-missing", spec.op_prefix)
    } else if !install.ok {
        format!("{}-binary-install-failed", spec.op_prefix)
    } else if !service_outcome.ok {
        format!("{}-service-not-active", spec.op_prefix)
    } else {
        format!("{}-health-failed", spec.op_prefix)
    };
    let changed =
        git_outcome.changed || managed.changed || install.changed || service_outcome.changed;
    write_run_receipt(
        receipt_dir,
        spec,
        apply,
        ok,
        changed,
        &first_missing_signal,
        &source_plan.reference,
        &source_plan.reference,
        &source_dir,
        Some(&source_sha_value),
    )?;

    println!("schema={}", spec.run_schema);
    println!("ok={ok}");
    println!("changed={changed}");
    println!("first_missing_signal={first_missing_signal}");
    println!("source_sha={source_sha_value}");
    println!("health_url={health_url}");
    println!("receipt_dir={}", receipt_dir.display());

    Ok(ModuleExecution::from_operations(
        vec![
            (
                spec.source_op,
                OperationOutcome {
                    ok: true,
                    changed: git_outcome.changed,
                    skipped: false,
                    message: format!("{} source synced", spec.op_prefix),
                    command: None,
                },
            ),
            (spec.managed_files_op, managed),
            (spec.binary_install_op, install),
            (spec.service_op, service_outcome),
            (
                spec.health_op,
                OperationOutcome {
                    ok: health.ok,
                    changed: false,
                    skipped: false,
                    message: if health.ok {
                        format!("{} HTTP health proved", spec.op_prefix)
                    } else {
                        format!("{} HTTP health failed", spec.op_prefix)
                    },
                    command: None,
                },
            ),
        ],
        &module.id,
    ))
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

