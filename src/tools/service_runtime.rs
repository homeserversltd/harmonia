use super::{ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::module_dispatch::{reject_executable_sidecar, require_path, ModuleExecution};
use crate::*;
use serde_json::json;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufReader, Read};

pub const NAME: &str = "service-runtime";
pub const DESCRIPTION: &str = "Rust service runtime convergence primitive for source sync, managed files, build, install, systemd, and health proof.";
const BUILD_ENV_ALLOWLIST: &[&str] = &["RUSTUP_HOME", "CARGO_HOME"];
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
        ToolArg::required("source_sha_file", ToolArgKind::String),
        ToolArg::required("binary_name", ToolArgKind::String),
        ToolArg::required("op_prefix", ToolArgKind::String),
        ToolArg::required("run_schema", ToolArgKind::String),
        ToolArg::required("managed_files_schema", ToolArgKind::String),
        ToolArg::optional("managed_files", ToolArgKind::Json),
        ToolArg::optional("caduceus_profile_source", ToolArgKind::Json),
        ToolArg::optional("caduceus_commands", ToolArgKind::Json),
        ToolArg::optional("build_environment", ToolArgKind::Json),
        ToolArg::optional("identity_environment", ToolArgKind::Json),
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

fn identity_environment(args: &BTreeMap<String, Value>) -> Result<Vec<String>, String> {
    let Some(value) = args.get("identity_environment") else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| "service-runtime-identity-environment-invalid".to_string())?;
    let mut declared = Vec::with_capacity(values.len());
    for value in values {
        let name = value
            .as_str()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| "service-runtime-identity-environment-invalid".to_string())?;
        let safe_identity_name = name
            .strip_suffix("_SOURCE_SHA")
            .or_else(|| name.strip_suffix("_BUILD_SHA"))
            .is_some_and(|prefix| {
                !prefix.is_empty()
                    && prefix
                        .chars()
                        .all(|character| character.is_ascii_uppercase() || character == '_')
            });
        if !safe_identity_name {
            return Err(format!(
                "service-runtime-identity-environment-refused-{name}"
            ));
        }
        if declared.iter().any(|declared_name| declared_name == name) {
            return Err(format!(
                "service-runtime-identity-environment-duplicate-{name}"
            ));
        }
        declared.push(name.to_string());
    }
    Ok(declared)
}

fn build_environment(
    args: &BTreeMap<String, Value>,
    acquired_source_sha: Option<&str>,
) -> Result<BTreeMap<String, String>, String> {
    let mut environment = match args.get("build_environment") {
        None => BTreeMap::new(),
        Some(Value::Object(values)) => values
            .iter()
            .map(|(key, value)| {
                if !BUILD_ENV_ALLOWLIST.contains(&key.as_str()) {
                    return Err(format!("service-runtime-build-environment-refused-{key}"));
                }
                let value = value
                    .as_str()
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| format!("service-runtime-build-environment-invalid-{key}"))?;
                Ok((key.clone(), value.to_string()))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?,
        Some(_) => return Err("service-runtime-build-environment-invalid".to_string()),
    };
    for name in identity_environment(args)? {
        if let Some(source_sha) = acquired_source_sha {
            if !is_hex_sha(source_sha) {
                return Err("service-runtime-identity-source-sha-invalid".to_string());
            }
            environment.insert(name, source_sha.to_string());
        }
    }
    Ok(environment)
}

pub(crate) fn execute_ladder_step(
    args: &BTreeMap<String, Value>,
    receipt_dir: &Path,
    apply: bool,
    source_plan: &tools::git_artifact::SourcePlan,
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
        source_sha_file: Some(string_arg(args, "source_sha_file")?),
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
    require_path(module, &module.source_sha_file, "source_sha_file")?;
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
) -> Result<ModuleExecution, String> {
    validate(module)?;
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;

    let source_dir = PathBuf::from(require_path(module, &module.source_dir, "source_dir")?);
    let install_bin = PathBuf::from(require_path(module, &module.install_bin, "install_bin")?);
    let service = require_path(module, &module.service, "service")?;
    let health_url = require_path(module, &module.url, "url")?;
    let source_sha_file = PathBuf::from(require_path(
        module,
        &module.source_sha_file,
        "source_sha_file",
    )?);

    let mut source_plan = source_plan.clone();
    if let Some(bearer) = bearer {
        source_plan.bearer = bearer.to_string();
    }
    let source_bearer = source_plan.bearer.clone();
    let git_outcome = if apply {
        tools::git_artifact::acquire_source(&source_plan)
    } else {
        tools::git_artifact::SourceOutcome {
            ok: true,
            changed: false,
            receipt: tools::git_artifact::SourceReceipt {
                attempts: Vec::new(),
                served_index: None,
                resolved_commit: None,
                promotion: "planned source acquisition".to_string(),
            },
        }
    };
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

    let source_sha = tools::command::capture_with_cwd_as_bearer(
        "/usr/bin/git",
        &["rev-parse", "HEAD"],
        source_dir.to_str(),
        &source_bearer,
    );
    write_source_sha_receipt(receipt_dir, spec.source_sha_op, &source_sha, &source_bearer)?;
    let source_sha_value = source_sha.stdout.trim().to_string();

    let managed_files = effective_managed_files(module, &source_dir)?;
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

    let build = tools::command::capture_with_cwd_as_bearer_and_env(
        "cargo",
        &["build", "--release"],
        source_dir.to_str(),
        &source_bearer,
        build_environment,
    );
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
    let install = install_binary(receipt_dir, spec, &artifact, &install_bin, apply)?;
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

    if apply {
        write_text_if_changed(
            &source_sha_file,
            &format!("{source_sha_value}\n"),
            &format!("{}-source-sha", spec.op_prefix),
        )?;
    }

    let service_outcome = ensure_service_active(
        receipt_dir,
        spec,
        service,
        apply,
        managed.changed,
        install.changed,
    )?;
    let health = tools::health::curl_probe(&tools::health::ProbeRequest::new(health_url));
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

fn effective_managed_files(
    module: &ModuleManifest,
    source_dir: &Path,
) -> Result<Vec<ManagedFileManifest>, String> {
    let mut files = module.managed_files.clone();
    if let Some(profile_source) = &module.caduceus_profile_source {
        files.push(render_caduceus_profile_source(profile_source, source_dir)?);
    }
    if !module.caduceus_commands.is_empty() {
        for file in &mut files {
            if file.path.ends_with("/profile.json") {
                let mut value: Value = serde_json::from_str(&file.content).map_err(|e| {
                    format!(
                        "service-runtime-caduceus-profile-json-invalid {}: {e}",
                        file.path
                    )
                })?;
                let commands = value
                    .get_mut("commands")
                    .and_then(Value::as_array_mut)
                    .ok_or_else(|| {
                        format!(
                            "service-runtime-caduceus-profile-json-commands-missing {}",
                            file.path
                        )
                    })?;
                for command in &module.caduceus_commands {
                    let value = Value::String(command.clone());
                    if !commands.contains(&value) {
                        commands.push(value);
                    }
                }
                file.content = serde_json::to_string_pretty(&value).map_err(|e| {
                    format!("service-runtime-caduceus-profile-json-render-failed: {e}")
                })? + "\n";
            } else if file.path.ends_with("/profile.yaml") {
                file.content =
                    append_caduceus_yaml_commands(&file.content, &module.caduceus_commands)?;
            }
        }
    }
    Ok(files)
}

fn append_caduceus_yaml_commands(content: &str, additions: &[String]) -> Result<String, String> {
    let mut lines: Vec<String> = content.lines().map(ToString::to_string).collect();
    let services = lines
        .iter()
        .position(|line| line == "services:")
        .ok_or_else(|| "service-runtime-caduceus-profile-yaml-services-missing".to_string())?;
    let existing: std::collections::BTreeSet<String> = lines
        .iter()
        .filter_map(|line| line.strip_prefix("- "))
        .map(ToString::to_string)
        .collect();
    let mut insert_at = services;
    for command in additions {
        if !existing.contains(command) {
            lines.insert(insert_at, format!("- {command}"));
            insert_at += 1;
        }
    }
    Ok(lines.join("\n") + "\n")
}

fn render_caduceus_profile_source(
    profile_source: &CaduceusProfileSourceManifest,
    source_dir: &Path,
) -> Result<ManagedFileManifest, String> {
    let source_path = source_dir.join(&profile_source.source);
    let source = fs::read_to_string(&source_path).map_err(|e| {
        format!(
            "service-runtime-caduceus-profile-source-read-failed {}: {e}",
            source_path.display()
        )
    })?;
    let mut rendered = String::new();
    let mut inserted_profile = profile_source.insert_after_profile.trim().is_empty();
    let mut inserted_mode = profile_source.insert_after_mode.trim().is_empty();
    for line in source.lines() {
        rendered.push_str(line);
        rendered.push('\n');
        if !inserted_profile && line.starts_with("profile:") {
            rendered.push_str(profile_source.insert_after_profile.trim_end());
            rendered.push('\n');
            inserted_profile = true;
        }
        if !inserted_mode && line.starts_with("mode:") {
            rendered.push_str(profile_source.insert_after_mode.trim_end());
            rendered.push('\n');
            inserted_mode = true;
        }
    }
    if !inserted_profile {
        return Err("service-runtime-caduceus-profile-source-missing-profile".to_string());
    }
    if !inserted_mode {
        return Err("service-runtime-caduceus-profile-source-missing-mode".to_string());
    }
    if !profile_source.append.trim().is_empty() {
        rendered.push_str(profile_source.append.trim_start());
        if !rendered.ends_with('\n') {
            rendered.push('\n');
        }
    }
    Ok(ManagedFileManifest {
        path: profile_source.path.clone(),
        content: rendered,
        mode: profile_source.mode,
    })
}

fn source_outcome_cmd(outcome: &tools::git_artifact::SourceOutcome) -> CmdResult {
    let detail = outcome
        .receipt
        .attempts
        .iter()
        .map(|attempt| {
            format!(
                "candidate={} disposition={} detail={}",
                attempt.index, attempt.disposition, attempt.detail
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    CmdResult {
        ok: outcome.ok,
        code: if outcome.ok { 0 } else { 1 },
        stdout: format!("promotion={}\n{}", outcome.receipt.promotion, detail),
        stderr: if outcome.ok {
            String::new()
        } else {
            outcome.receipt.promotion.clone()
        },
    }
}

fn write_source_sha_receipt(
    receipt_dir: &Path,
    name: &str,
    result: &CmdResult,
    bearer: &str,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{name}.json")),
        &json!({
            "schema": "harmonia.command_receipt.v1",
            "name": name,
            "ok": result.ok,
            "exit_code": result.code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "first_missing_signal": if result.ok { "none" } else { "command-failed" },
            "bearer": bearer,
        }),
    )
}

fn is_hex_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
fn install_binary(
    receipt_dir: &Path,
    spec: &ServiceRuntimeSpec,
    artifact: &Path,
    install_bin: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    if !artifact.is_file() {
        return Ok(OperationOutcome {
            ok: false,
            changed: false,
            skipped: false,
            message: format!("{} build artifact missing", spec.op_prefix),
            command: None,
        });
    }
    if files_equal(artifact, install_bin)? {
        write_binary_install_receipt(receipt_dir, spec, artifact, install_bin, apply, false)?;
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "converged-quiet".to_string(),
            command: None,
        });
    }
    if !apply {
        write_binary_install_receipt(receipt_dir, spec, artifact, install_bin, apply, false)?;
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: format!("{} binary install planned", spec.op_prefix),
            command: None,
        });
    }
    if let Some(parent) = install_bin.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp_install = install_bin.with_extension("harmonia-new");
    fs::copy(artifact, &tmp_install)
        .map_err(|e| format!("{}-artifact-copy-failed: {e}", spec.op_prefix))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&tmp_install)
            .map_err(|e| e.to_string())?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&tmp_install, perms).map_err(|e| e.to_string())?;
    }
    fs::rename(&tmp_install, install_bin)
        .map_err(|e| format!("{}-artifact-promote-failed: {e}", spec.op_prefix))?;
    write_binary_install_receipt(receipt_dir, spec, artifact, install_bin, apply, true)?;
    Ok(OperationOutcome {
        ok: true,
        changed: true,
        skipped: false,
        message: format!("{} binary installed", spec.op_prefix),
        command: None,
    })
}

fn ensure_service_active(
    receipt_dir: &Path,
    spec: &ServiceRuntimeSpec,
    service: &str,
    apply: bool,
    managed_files_changed: bool,
    binary_changed: bool,
) -> Result<OperationOutcome, String> {
    if !apply {
        let active = tools::command::capture("/usr/bin/systemctl", &["is-active", service]);
        return Ok(OperationOutcome {
            ok: active.ok,
            changed: false,
            skipped: true,
            message: format!("{} service activation planned", spec.op_prefix),
            command: None,
        });
    }
    let service_material_changed = managed_files_changed || binary_changed;
    let active_before = tools::command::capture("/usr/bin/systemctl", &["is-active", service]);
    if !service_material_changed {
        let active = tools::systemd::run_action(
            receipt_dir,
            spec.service_active_op,
            "is-active-probe",
            Some(service),
            false,
            None,
            30,
            apply,
            false,
        )?;
        return Ok(OperationOutcome {
            ok: active.ok,
            changed: false,
            skipped: true,
            message: "converged-quiet".to_string(),
            command: None,
        });
    }
    if managed_files_changed {
        let daemon_reload = tools::systemd::run_action(
            receipt_dir,
            spec.daemon_reload_op,
            "daemon-reload",
            Some(service),
            false,
            None,
            30,
            apply,
            true,
        )?;
        if !daemon_reload.ok {
            return Ok(OperationOutcome {
                ok: false,
                changed: false,
                skipped: false,
                message: format!("{} systemd daemon-reload failed", spec.op_prefix),
                command: None,
            });
        }
    }
    let enable = tools::systemd::run_action(
        receipt_dir,
        spec.service_enable_op,
        "enable-now",
        Some(service),
        false,
        None,
        30,
        apply,
        service_material_changed,
    )?;
    let restart = if active_before.ok {
        Some(tools::systemd::run_permutation(
            receipt_dir,
            spec.service_op,
            "restart",
            Some(service),
            &[],
            None,
            30,
            apply,
            service_material_changed,
        )?)
    } else {
        None
    };
    let active = tools::systemd::run_action(
        receipt_dir,
        spec.service_active_op,
        "is-active-probe",
        Some(service),
        false,
        None,
        30,
        apply,
        service_material_changed,
    )?;
    Ok(OperationOutcome {
        ok: enable.ok && restart.as_ref().is_none_or(|outcome| outcome.ok) && active.ok,
        changed: enable.changed || restart.as_ref().is_some_and(|outcome| outcome.changed),
        skipped: false,
        message: format!("{} service material reconciled", spec.op_prefix),
        command: None,
    })
}

fn files_equal(left: &Path, right: &Path) -> Result<bool, String> {
    let Ok(left_meta) = fs::metadata(left) else {
        return Ok(false);
    };
    let Ok(right_meta) = fs::metadata(right) else {
        return Ok(false);
    };
    if left_meta.len() != right_meta.len() {
        return Ok(false);
    }
    let mut left = BufReader::new(fs::File::open(left).map_err(|e| e.to_string())?);
    let mut right = BufReader::new(fs::File::open(right).map_err(|e| e.to_string())?);
    let mut left_buf = [0_u8; 64 * 1024];
    let mut right_buf = [0_u8; 64 * 1024];
    loop {
        let left_read = left.read(&mut left_buf).map_err(|e| e.to_string())?;
        let right_read = right.read(&mut right_buf).map_err(|e| e.to_string())?;
        if left_read != right_read || left_buf[..left_read] != right_buf[..right_read] {
            return Ok(false);
        }
        if left_read == 0 {
            return Ok(true);
        }
    }
}

fn write_text_if_changed(path: &Path, desired: &str, label: &str) -> Result<bool, String> {
    if fs::read_to_string(path).ok().as_deref() == Some(desired) {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(path, desired).map_err(|e| format!("{label}-write-failed: {e}"))?;
    Ok(true)
}

fn write_binary_install_receipt(
    receipt_dir: &Path,
    spec: &ServiceRuntimeSpec,
    artifact: &Path,
    install_bin: &Path,
    apply: bool,
    changed: bool,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{}.json", spec.binary_install_op)),
        &json!({
            "schema": "harmonia.service-runtime.binary-install.v1",
            "artifact": artifact,
            "install_bin": install_bin,
            "apply": apply,
            "ok": true,
            "changed": changed,
            "state": if changed { "binary-swapped" } else { "converged-quiet" },
        }),
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time moves forward")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "harmonia-service-runtime-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn base_args(root: &Path) -> BTreeMap<String, Value> {
        let source_dir = root.join("source");
        let install_bin = root.join("bin/service");
        let source_sha_file = root.join("state/service.sha");
        BTreeMap::from([
            (
                "module_id".to_string(),
                json!("empty-managed-files-runtime"),
            ),
            ("component".to_string(), json!("test-service")),
            ("repo".to_string(), json!(source_dir.display().to_string())),
            ("branch".to_string(), json!("main")),
            ("remote".to_string(), json!("origin")),
            (
                "source_dir".to_string(),
                json!(source_dir.display().to_string()),
            ),
            (
                "install_bin".to_string(),
                json!(install_bin.display().to_string()),
            ),
            ("service".to_string(), json!("empty-managed-files.service")),
            ("url".to_string(), json!("http://127.0.0.1:1/health")),
            (
                "source_sha_file".to_string(),
                json!(source_sha_file.display().to_string()),
            ),
            ("binary_name".to_string(), json!("service")),
            ("op_prefix".to_string(), json!("empty-managed-files")),
            (
                "run_schema".to_string(),
                json!("harmonia.test.service_runtime.v1"),
            ),
            (
                "managed_files_schema".to_string(),
                json!("harmonia.test.service_runtime.managed_files.v1"),
            ),
            ("managed_files".to_string(), json!([])),
        ])
    }

    fn init_git_repo(path: &Path) {
        fs::create_dir_all(path).unwrap();
        for args in [
            vec!["init", "-b", "main"],
            vec!["config", "user.email", "harmonia-test@example.invalid"],
            vec!["config", "user.name", "Harmonia Test"],
        ] {
            assert!(Command::new("/usr/bin/git")
                .args(args)
                .current_dir(path)
                .status()
                .unwrap()
                .success());
        }
        fs::write(path.join("README.md"), "test repo\n").unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["add", "README.md"])
            .current_dir(path)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .args(["commit", "-m", "seed"])
            .current_dir(path)
            .status()
            .unwrap()
            .success());
    }

    #[test]
    fn validate_allows_declared_empty_managed_files_but_keeps_required_args() {
        let root = scratch("validate");
        let mut args = base_args(&root);
        validate_ladder_args(&args).unwrap();
        args.remove("component");
        assert_eq!(
            validate_ladder_args(&args).unwrap_err(),
            "service-runtime-missing-component"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn declared_identity_environment_supplies_exact_acquired_sha_to_cargo_build() {
        let root = scratch("identity-environment");
        let mut args = base_args(&root);
        args.insert(
            "build_environment".to_string(),
            json!({
                "RUSTUP_HOME": "/opt/rustup",
                "CARGO_HOME": "/opt/cargo"
            }),
        );
        args.insert(
            "identity_environment".to_string(),
            json!(["CORONATIO_SOURCE_SHA", "CORONATIO_BUILD_SHA"]),
        );
        let acquired_sha = "a5c8cd44e139db3d949b3c601fff9337cc6f3c80";

        let environment = build_environment(&args, Some(acquired_sha)).unwrap();

        assert_eq!(
            environment.get("CORONATIO_SOURCE_SHA").map(String::as_str),
            Some(acquired_sha),
            "cargo build lacks the exact acquired source identity environment"
        );
        assert_eq!(
            environment.get("CORONATIO_BUILD_SHA").map(String::as_str),
            Some(acquired_sha),
            "cargo build lacks the exact acquired build identity environment"
        );
        assert_eq!(
            environment.get("RUSTUP_HOME").map(String::as_str),
            Some("/opt/rustup")
        );
        assert_eq!(
            environment.get("CARGO_HOME").map(String::as_str),
            Some("/opt/cargo")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn malformed_identity_environment_is_refused_by_ladder_validation() {
        let root = scratch("identity-environment-invalid");
        let mut args = base_args(&root);
        args.insert("identity_environment".to_string(), json!(["RUSTFLAGS"]));

        assert_eq!(
            validate_ladder_args(&args).unwrap_err(),
            "service-runtime-identity-environment-refused-RUSTFLAGS"
        );
        args.insert(
            "identity_environment".to_string(),
            json!(["CORONATIO_SOURCE_SHA"]),
        );
        assert_eq!(
            build_environment(&args, Some("g5c8cd44e139db3d949b3c601fff9337cc6f3c80")).unwrap_err(),
            "service-runtime-identity-source-sha-invalid"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn empty_managed_files_idle_plan_writes_truthful_noop_receipt() {
        let root = scratch("noop");
        let source_dir = root.join("source");
        init_git_repo(&source_dir);
        let receipt_dir = root.join("receipts");
        let args = base_args(&root);

        let source_plan = tools::git_artifact::SourcePlan {
            candidates: Vec::new(),
            reference: "main".into(),
            destination: source_dir,
            expected_commit: None,
            bearer: "owner".into(),
            credentials: std::collections::BTreeMap::new(),
        };
        let execution = execute_ladder_step(&args, &receipt_dir, false, &source_plan).unwrap();
        assert!(execution.ok);
        assert!(!execution.changed);

        let receipt: Value = serde_json::from_str(
            &fs::read_to_string(receipt_dir.join("empty-managed-files-managed-files.json"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            receipt.get("schema").and_then(Value::as_str),
            Some("harmonia.test.service_runtime.managed_files.v1")
        );
        assert_eq!(receipt.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(receipt.get("changed").and_then(Value::as_bool), Some(false));
        assert_eq!(
            receipt
                .get("entries")
                .and_then(Value::as_array)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            receipt.get("first_missing_signal").and_then(Value::as_str),
            Some("none")
        );
        let _ = fs::remove_dir_all(root);
    }
}
