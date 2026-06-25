use crate::module_dispatch::{reject_executable_sidecar, require_path, ModuleExecution};
use crate::*;
use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

pub(crate) const ID: &str = "coronatio";

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

fn coronatio_health_with_retry(url: &str) -> CmdResult {
    let mut last = command_capture("/usr/bin/curl", &["-fsS", "--max-time", "3", url]);
    for _ in 0..5 {
        if last.ok {
            return last;
        }
        thread::sleep(Duration::from_secs(1));
        last = command_capture("/usr/bin/curl", &["-fsS", "--max-time", "3", url]);
    }
    last
}

fn managed_files(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let mut missing = Vec::new();
    let mut written = Vec::new();
    let mut changed = false;
    for file in &module.managed_files {
        let path = PathBuf::from(&file.path);
        let existing = fs::read_to_string(&path).ok();
        let content_equal = existing.as_deref() == Some(file.content.as_str());
        if !content_equal {
            if apply {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("coronatio-managed-file-parent-failed: {e}"))?;
                }
                fs::write(&path, file.content.as_bytes())
                    .map_err(|e| format!("coronatio-managed-file-write-failed: {e}"))?;
                fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(file.mode.unwrap_or(0o644)),
                )
                .map_err(|e| format!("coronatio-managed-file-mode-failed: {e}"))?;
                written.push(file.path.clone());
                changed = true;
            } else {
                missing.push(file.path.clone());
            }
        }
    }
    let ok = missing.is_empty() || !apply;
    let outcome = OperationOutcome {
        ok,
        changed,
        skipped: !apply && !missing.is_empty(),
        message: format!("{} managed files checked", module.managed_files.len()),
        command: None,
    };
    write_json(
        &receipt_dir.join("coronatio-managed-files.json"),
        &json!({
            "schema": "harmonia.homeserver.coronatio_managed_files.v1",
            "ok": ok,
            "module": module.id,
            "missing": missing,
            "written": written,
            "apply": apply,
            "changed": changed,
            "first_missing_signal": if ok { "none" } else { "coronatio-managed-file-missing" }
        }),
    )?;
    Ok(outcome)
}

fn install_binary(
    receipt_dir: &Path,
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
            message: "coronatio binary install planned".to_string(),
            command: None,
        });
    }
    if let Some(parent) = install_bin.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let before_len = fs::metadata(install_bin).map(|m| m.len()).ok();
    let stop = command_capture("/usr/bin/systemctl", &["stop", service]);
    write_command_receipt(receipt_dir, "coronatio-service-stop", &stop)?;
    let tmp_install = install_bin.with_extension("harmonia-new");
    fs::copy(artifact, &tmp_install).map_err(|e| format!("coronatio-artifact-copy-failed: {e}"))?;
    let mut perms = fs::metadata(&tmp_install)
        .map_err(|e| e.to_string())?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&tmp_install, perms).map_err(|e| e.to_string())?;
    fs::rename(&tmp_install, install_bin)
        .map_err(|e| format!("coronatio-artifact-promote-failed: {e}"))?;
    let artifact_len = fs::metadata(artifact).map_err(|e| e.to_string())?.len();
    Ok(OperationOutcome {
        ok: true,
        changed: before_len != Some(artifact_len),
        skipped: false,
        message: "coronatio binary installed".to_string(),
        command: None,
    })
}

fn ensure_service_active(
    receipt_dir: &Path,
    service: &str,
    apply: bool,
) -> Result<OperationOutcome, String> {
    if !apply {
        let active = command_capture("/usr/bin/systemctl", &["is-active", service]);
        return Ok(OperationOutcome {
            ok: active.ok,
            changed: false,
            skipped: true,
            message: "coronatio service activation planned".to_string(),
            command: None,
        });
    }
    let daemon_reload = command_capture("/usr/bin/systemctl", &["daemon-reload"]);
    write_command_receipt(receipt_dir, "coronatio-daemon-reload", &daemon_reload)?;
    if !daemon_reload.ok {
        return Ok(OperationOutcome {
            ok: false,
            changed: false,
            skipped: false,
            message: "coronatio systemd daemon-reload failed".to_string(),
            command: None,
        });
    }
    let enable = command_capture("/usr/bin/systemctl", &["enable", "--now", service]);
    write_command_receipt(receipt_dir, "coronatio-service-enable", &enable)?;
    let active = command_capture("/usr/bin/systemctl", &["is-active", service]);
    write_command_receipt(receipt_dir, "coronatio-service-active", &active)?;
    Ok(OperationOutcome {
        ok: enable.ok && active.ok,
        changed: enable.ok,
        skipped: false,
        message: "coronatio service enabled".to_string(),
        command: None,
    })
}

fn write_run_receipt(
    receipt_dir: &Path,
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
            "schema": "harmonia.homeserver.coronatio_runtime.v1",
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

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
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
        "coronatio-source-git-artifact",
        &git_artifact_cmd(&git_outcome.command),
    )?;
    if !git_outcome.ok {
        write_run_receipt(
            receipt_dir,
            apply,
            false,
            git_outcome.changed,
            "coronatio-source-git-artifact-failed",
            repo,
            branch,
            &source_dir,
            None,
        )?;
        return Ok(ModuleExecution::from_operations(
            vec![(
                "coronatio-source-git-artifact",
                OperationOutcome {
                    ok: false,
                    changed: git_outcome.changed,
                    skipped: false,
                    message: "coronatio source sync failed".to_string(),
                    command: None,
                },
            )],
            &module.id,
        ));
    }

    let source_sha =
        command_capture_with_cwd("/usr/bin/git", &["rev-parse", "HEAD"], source_dir.to_str());
    write_command_receipt(receipt_dir, "coronatio-source-sha", &source_sha)?;
    let source_sha_value = source_sha.stdout.trim().to_string();

    let managed = managed_files(module, receipt_dir, apply)?;

    if !apply {
        write_run_receipt(
            receipt_dir,
            apply,
            managed.ok,
            git_outcome.changed || managed.changed,
            if managed.ok {
                "none"
            } else {
                "coronatio-managed-file-missing"
            },
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
                    "coronatio-source-git-artifact",
                    OperationOutcome {
                        ok: true,
                        changed: git_outcome.changed,
                        skipped: false,
                        message: "coronatio source planned".to_string(),
                        command: None,
                    },
                ),
                ("coronatio-managed-files", managed),
            ],
            &module.id,
        ));
    }

    if !source_sha.ok || !is_hex_sha(&source_sha_value) {
        write_run_receipt(
            receipt_dir,
            apply,
            false,
            true,
            "coronatio-source-sha-missing",
            repo,
            branch,
            &source_dir,
            None,
        )?;
        return Ok(ModuleExecution::from_operations(
            vec![(
                "coronatio-source-sha",
                OperationOutcome {
                    ok: false,
                    changed: false,
                    skipped: false,
                    message: "coronatio source sha missing".to_string(),
                    command: None,
                },
            )],
            &module.id,
        ));
    }

    let build = command_capture_with_cwd(
        if Path::new("/opt/cargo/bin/cargo").exists() {
            "/opt/cargo/bin/cargo"
        } else {
            "/usr/bin/cargo"
        },
        &["build", "--release"],
        source_dir.to_str(),
    );
    write_command_receipt(receipt_dir, "coronatio-cargo-build", &build)?;
    if !build.ok {
        write_run_receipt(
            receipt_dir,
            apply,
            false,
            true,
            "coronatio-cargo-build-failed",
            repo,
            branch,
            &source_dir,
            Some(&source_sha_value),
        )?;
        return Ok(ModuleExecution::from_operations(
            vec![(
                "coronatio-cargo-build",
                OperationOutcome {
                    ok: false,
                    changed: false,
                    skipped: false,
                    message: "coronatio cargo build failed".to_string(),
                    command: None,
                },
            )],
            &module.id,
        ));
    }

    let artifact = source_dir.join("target/release/coronatio");
    let install = install_binary(receipt_dir, &artifact, &install_bin, service, apply)?;
    if !install.ok {
        write_run_receipt(
            receipt_dir,
            apply,
            false,
            install.changed,
            "coronatio-binary-install-failed",
            repo,
            branch,
            &source_dir,
            Some(&source_sha_value),
        )?;
        return Ok(ModuleExecution::from_operations(
            vec![("coronatio-binary-install", install)],
            &module.id,
        ));
    }

    if let Some(parent) = source_sha_file.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(&source_sha_file, format!("{source_sha_value}\n"))
        .map_err(|e| format!("coronatio-source-sha-write-failed: {e}"))?;

    let service_outcome = ensure_service_active(receipt_dir, service, apply)?;
    let health = coronatio_health_with_retry(health_url);
    write_command_receipt(receipt_dir, "coronatio-health", &health)?;

    let ok = managed.ok && install.ok && service_outcome.ok && health.ok;
    let first_missing_signal = if ok {
        "none"
    } else if !managed.ok {
        "coronatio-managed-file-missing"
    } else if !install.ok {
        "coronatio-binary-install-failed"
    } else if !service_outcome.ok {
        "coronatio-service-not-active"
    } else {
        "coronatio-health-failed"
    };
    let changed =
        git_outcome.changed || managed.changed || install.changed || service_outcome.changed;

    write_run_receipt(
        receipt_dir,
        apply,
        ok,
        changed,
        first_missing_signal,
        repo,
        branch,
        &source_dir,
        Some(&source_sha_value),
    )?;

    println!("schema=harmonia.homeserver.coronatio_runtime.v1");
    println!("ok={ok}");
    println!("changed={changed}");
    println!("first_missing_signal={first_missing_signal}");
    println!("source_sha={source_sha_value}");
    println!("health_url={health_url}");
    println!("receipt_dir={}", receipt_dir.display());

    Ok(ModuleExecution::from_operations(
        vec![
            (
                "coronatio-source-git-artifact",
                OperationOutcome {
                    ok: true,
                    changed: git_outcome.changed,
                    skipped: false,
                    message: "coronatio source synced".to_string(),
                    command: None,
                },
            ),
            ("coronatio-managed-files", managed),
            ("coronatio-binary-install", install),
            ("coronatio-service", service_outcome),
            (
                "coronatio-health",
                OperationOutcome {
                    ok: health.ok,
                    changed: false,
                    skipped: false,
                    message: if health.ok {
                        "coronatio HTTP health proved".to_string()
                    } else {
                        "coronatio HTTP health failed".to_string()
                    },
                    command: None,
                },
            ),
        ],
        &module.id,
    ))
}
