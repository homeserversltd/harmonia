use super::{ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::module_dispatch::{reject_executable_sidecar, require_path, ModuleExecution};
use crate::*;
use serde_json::json;
use serde_json::Value;
use std::collections::BTreeMap;

pub const NAME: &str = "service-runtime";
pub const DESCRIPTION: &str = "Rust service runtime convergence primitive for source sync, managed files, build, install, systemd, and health proof.";
pub const PERMUTATIONS: &[ToolPermutation] = &[ToolPermutation::new(
    "converge",
    "converge a Rust service runtime from typed constants",
    &[
        ToolArg::optional("module_id", ToolArgKind::String),
        ToolArg::required("repo", ToolArgKind::String),
        ToolArg::optional("branch", ToolArgKind::String),
        ToolArg::optional("remote", ToolArgKind::String),
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
) -> Result<ModuleExecution, String> {
    let op_prefix = string_arg(args, "op_prefix")?;
    let source_op = format!("{op_prefix}-source-git-artifact");
    let source_sha_op = format!("{op_prefix}-source-sha");
    let managed_files_op = format!("{op_prefix}-managed-files");
    let build_op = format!("{op_prefix}-cargo-build");
    let binary_install_op = format!("{op_prefix}-binary-install");
    let service_stop_op = format!("{op_prefix}-service-stop");
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
        service_stop_op: Box::leak(service_stop_op.into_boxed_str()),
        daemon_reload_op: Box::leak(daemon_reload_op.into_boxed_str()),
        service_enable_op: Box::leak(service_enable_op.into_boxed_str()),
        service_active_op: Box::leak(service_active_op.into_boxed_str()),
        service_op: Box::leak(service_op.into_boxed_str()),
        health_op: Box::leak(health_op.into_boxed_str()),
        binary_name: Box::leak(binary_name.into_boxed_str()),
    };
    let module = module_from_args(args, &spec)?;
    execute(&module, receipt_dir, apply, &spec)
}

pub(crate) fn validate_ladder_args(args: &BTreeMap<String, Value>) -> Result<(), String> {
    let op_prefix = string_arg(args, "op_prefix")?;
    let source_op = format!("{op_prefix}-source-git-artifact");
    let source_sha_op = format!("{op_prefix}-source-sha");
    let managed_files_op = format!("{op_prefix}-managed-files");
    let build_op = format!("{op_prefix}-cargo-build");
    let binary_install_op = format!("{op_prefix}-binary-install");
    let service_stop_op = format!("{op_prefix}-service-stop");
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
        service_stop_op: Box::leak(service_stop_op.into_boxed_str()),
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
        repo: Some(string_arg(args, "repo")?),
        path: None,
        branch: args
            .get("branch")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        remote: args
            .get("remote")
            .and_then(Value::as_str)
            .map(ToString::to_string),
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
    pub service_stop_op: &'static str,
    pub daemon_reload_op: &'static str,
    pub service_enable_op: &'static str,
    pub service_active_op: &'static str,
    pub service_op: &'static str,
    pub health_op: &'static str,
    pub binary_name: &'static str,
}

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    reject_executable_sidecar(module)?;
    require_path(module, &module.repo, "repo")?;
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
) -> Result<ModuleExecution, String> {
    validate(module)?;
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;

    let repo = require_path(module, &module.repo, "repo")?;
    let branch = module.branch.as_deref().unwrap_or("main");
    let source_dir = PathBuf::from(require_path(module, &module.source_dir, "source_dir")?);
    let install_bin = PathBuf::from(require_path(module, &module.install_bin, "install_bin")?);
    let service = require_path(module, &module.service, "service")?;
    let health_url = require_path(module, &module.url, "url")?;
    let source_sha_file = PathBuf::from(require_path(
        module,
        &module.source_sha_file,
        "source_sha_file",
    )?);

    let git_request = tools::git_artifact::Request::new(
        Some(repo.to_string()),
        source_dir.clone(),
        branch.to_string(),
        module
            .remote
            .clone()
            .unwrap_or_else(|| "origin".to_string()),
    );
    let git_outcome = if apply {
        tools::git_artifact::apply(&git_request)
    } else {
        tools::git_artifact::plan(&git_request)
    };
    write_command_receipt(
        receipt_dir,
        spec.source_op,
        &git_artifact_cmd(&git_outcome.command),
    )?;
    if !git_outcome.ok {
        write_run_receipt(
            receipt_dir,
            spec,
            apply,
            false,
            git_outcome.changed,
            &format!("{}-source-git-artifact-failed", spec.op_prefix),
            repo,
            branch,
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

    let source_sha = tools::command::capture_with_cwd(
        "/usr/bin/git",
        &["rev-parse", "HEAD"],
        source_dir.to_str(),
    );
    write_command_receipt(receipt_dir, spec.source_sha_op, &source_sha)?;
    let source_sha_value = source_sha.stdout.trim().to_string();

    let managed_files = effective_managed_files(module, &source_dir)?;
    let managed = tools::files::converge_managed_files(
        &tools::files::ManagedFilesRequest {
            module_id: &module.id,
            files: &managed_files,
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
            repo,
            branch,
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
            repo,
            branch,
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

    let build =
        tools::command::capture_with_cwd(cargo_bin(), &["build", "--release"], source_dir.to_str());
    write_command_receipt(receipt_dir, spec.build_op, &build)?;
    if !build.ok {
        write_run_receipt(
            receipt_dir,
            spec,
            apply,
            false,
            true,
            &format!("{}-cargo-build-failed", spec.op_prefix),
            repo,
            branch,
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
    let install = install_binary(receipt_dir, spec, &artifact, &install_bin, service, apply)?;
    if !install.ok {
        write_run_receipt(
            receipt_dir,
            spec,
            apply,
            false,
            install.changed,
            &format!("{}-binary-install-failed", spec.op_prefix),
            repo,
            branch,
            &source_dir,
            Some(&source_sha_value),
        )?;
        return Ok(ModuleExecution::from_operations(
            vec![(spec.binary_install_op, install)],
            &module.id,
        ));
    }

    if let Some(parent) = source_sha_file.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(&source_sha_file, format!("{source_sha_value}\n"))
        .map_err(|e| format!("{}-source-sha-write-failed: {e}", spec.op_prefix))?;

    let service_outcome = ensure_service_active(receipt_dir, spec, service, apply)?;
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
        repo,
        branch,
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
    Ok(files)
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

fn git_artifact_cmd(result: &tools::git_artifact::CommandReceipt) -> CmdResult {
    CmdResult {
        ok: result.ok,
        code: result.code,
        stdout: result.stdout.clone(),
        stderr: result.stderr.clone(),
    }
}

fn is_hex_sha(value: &str) -> bool {
    value.len() == 40 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}
fn cargo_bin() -> &'static str {
    if Path::new("/opt/cargo/bin/cargo").exists() {
        "/opt/cargo/bin/cargo"
    } else {
        "/usr/bin/cargo"
    }
}

fn install_binary(
    receipt_dir: &Path,
    spec: &ServiceRuntimeSpec,
    artifact: &Path,
    install_bin: &Path,
    service: &str,
    apply: bool,
) -> Result<OperationOutcome, String> {
    if !apply {
        let exists = fs::metadata(install_bin).is_ok() && fs::metadata(artifact).is_ok();
        return Ok(OperationOutcome {
            ok: exists,
            changed: false,
            skipped: true,
            message: format!("{} binary install planned", spec.op_prefix),
            command: None,
        });
    }
    if let Some(parent) = install_bin.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let before_len = fs::metadata(install_bin).map(|m| m.len()).ok();
    let _stop = tools::systemd::run_action(
        receipt_dir,
        spec.service_stop_op,
        "stop",
        Some(service),
        false,
        None,
        30,
        apply,
    )?;
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
    let artifact_len = fs::metadata(artifact).map_err(|e| e.to_string())?.len();
    Ok(OperationOutcome {
        ok: true,
        changed: before_len != Some(artifact_len),
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
    let daemon_reload = tools::systemd::run_action(
        receipt_dir,
        spec.daemon_reload_op,
        "daemon-reload",
        Some(service),
        false,
        None,
        30,
        apply,
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
    let enable = tools::systemd::run_action(
        receipt_dir,
        spec.service_enable_op,
        "enable-now",
        Some(service),
        false,
        None,
        30,
        apply,
    )?;
    let active = tools::systemd::run_action(
        receipt_dir,
        spec.service_active_op,
        "is-active-probe",
        Some(service),
        false,
        None,
        30,
        apply,
    )?;
    Ok(OperationOutcome {
        ok: enable.ok && active.ok,
        changed: enable.ok,
        skipped: false,
        message: format!("{} service enabled", spec.op_prefix),
        command: None,
    })
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
        args.remove("repo");
        assert_eq!(
            validate_ladder_args(&args).unwrap_err(),
            "service-runtime-missing-repo"
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

        let execution = execute_ladder_step(&args, &receipt_dir, false).unwrap();
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
