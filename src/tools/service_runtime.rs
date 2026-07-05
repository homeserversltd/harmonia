use crate::module_dispatch::{reject_executable_sidecar, require_path, ModuleExecution};
use crate::*;
use serde_json::json;
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
    if module.managed_files.is_empty() {
        return Err(format!(
            "module-sidecar-missing-{}-managed_files",
            module.id
        ));
    }
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

    let managed = tools::files::converge_managed_files(
        &tools::files::ManagedFilesRequest {
            module_id: &module.id,
            files: &module.managed_files,
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
    let stop = tools::command::capture("/usr/bin/systemctl", &["stop", service]);
    write_command_receipt(receipt_dir, spec.service_stop_op, &stop)?;
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
    let daemon_reload = tools::command::capture("/usr/bin/systemctl", &["daemon-reload"]);
    write_command_receipt(receipt_dir, spec.daemon_reload_op, &daemon_reload)?;
    if !daemon_reload.ok {
        return Ok(OperationOutcome {
            ok: false,
            changed: false,
            skipped: false,
            message: format!("{} systemd daemon-reload failed", spec.op_prefix),
            command: None,
        });
    }
    let enable = tools::command::capture("/usr/bin/systemctl", &["enable", "--now", service]);
    write_command_receipt(receipt_dir, spec.service_enable_op, &enable)?;
    let active = tools::command::capture("/usr/bin/systemctl", &["is-active", service]);
    write_command_receipt(receipt_dir, spec.service_active_op, &active)?;
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
