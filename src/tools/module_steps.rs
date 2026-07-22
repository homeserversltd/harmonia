use crate::*;
use sha2::{Digest, Sha256};
use std::fs::{self};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[cfg(test)]
pub(crate) use crate::tools::package::set_test_pacman_path;

pub(crate) fn package_tool(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    packages: &[String],
    apply: bool,
) -> Result<OperationOutcome, String> {
    crate::tools::package::package_tool(receipt_dir, name, action, packages, apply)
}

pub(crate) fn command_tool(
    receipt_dir: &Path,
    name: &str,
    program: &str,
    args: &[String],
    cwd: Option<&str>,
) -> Result<OperationOutcome, String> {
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = command_capture_with_cwd(program, &arg_refs, cwd);
    write_command_receipt_with_change_observed(receipt_dir, name, &result, "unknown")?;
    Ok(OperationOutcome {
        ok: result.ok,
        changed: false,
        skipped: false,
        message: format!("command {program}; change_observed=unknown"),
        command: Some(result),
    })
}

#[allow(dead_code)]
pub(crate) fn systemd_tool(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    service: &str,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let mutating = matches!(
        action,
        "start" | "stop" | "restart" | "enable" | "disable" | "daemon-reload"
    );
    if mutating && !apply {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: format!("systemd {action} planned"),
            command: None,
        };
        write_tool_receipt(receipt_dir, name, "systemd", action, &outcome)?;
        return Ok(outcome);
    }
    let before_enabled = systemctl_state("is-enabled", service);
    let before_active = systemctl_state("is-active", service);
    let result = match action {
        "daemon-reload" => command_capture("/usr/bin/systemctl", &["daemon-reload"]),
        "active" | "is-active" => command_capture("/usr/bin/systemctl", &["is-active", service]),
        "status" => command_capture("/usr/bin/systemctl", &["status", service, "--no-pager"]),
        "start" | "stop" | "restart" | "enable" | "disable" => {
            command_capture("/usr/bin/systemctl", &[action, service])
        }
        other => {
            let outcome = OperationOutcome {
                ok: false,
                changed: false,
                skipped: false,
                message: format!("unsupported systemd action {other}"),
                command: None,
            };
            write_tool_receipt(receipt_dir, name, "systemd", action, &outcome)?;
            return Ok(outcome);
        }
    };
    let after_enabled = systemctl_state("is-enabled", service);
    let after_active = systemctl_state("is-active", service);
    let changed =
        mutating && result.ok && (before_enabled != after_enabled || before_active != after_active);
    write_systemd_command_receipt(
        receipt_dir,
        name,
        &result,
        before_enabled.as_deref(),
        before_active.as_deref(),
        after_enabled.as_deref(),
        after_active.as_deref(),
        changed,
    )?;
    Ok(OperationOutcome {
        ok: result.ok,
        changed,
        skipped: false,
        message: format!("systemd {action} {service}"),
        command: Some(result),
    })
}

#[allow(dead_code)]
pub(crate) fn artifact_promote_tool(
    receipt_dir: &Path,
    name: &str,
    artifact: &Path,
    install_bin: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let metadata = fs::metadata(artifact)
        .map_err(|e| format!("artifact-missing {}: {e}", artifact.display()))?;
    if !apply {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: format!("artifact planned bytes={}", metadata.len()),
            command: None,
        };
        write_tool_receipt(receipt_dir, name, "artifact", "promote", &outcome)?;
        return Ok(outcome);
    }
    if let Some(parent) = install_bin.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let before_sha = sha256_file(install_bin).ok();
    let artifact_sha = sha256_file(artifact)?;
    let tmp_install = install_bin.with_extension("harmonia-new");
    fs::copy(artifact, &tmp_install).map_err(|e| format!("artifact-copy-failed: {e}"))?;
    let mut perms = fs::metadata(&tmp_install)
        .map_err(|e| e.to_string())?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&tmp_install, perms).map_err(|e| e.to_string())?;
    fs::rename(&tmp_install, install_bin).map_err(|e| format!("artifact-promote-failed: {e}"))?;
    let outcome = OperationOutcome {
        ok: true,
        changed: before_sha.as_deref() != Some(artifact_sha.as_str()),
        skipped: false,
        message: format!("artifact promoted to {}", install_bin.display()),
        command: None,
    };
    write_tool_receipt(receipt_dir, name, "artifact", "promote", &outcome)?;
    Ok(outcome)
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|e| format!("sha256-read-failed {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

fn systemctl_state(kind: &str, service: &str) -> Option<String> {
    let result = command_capture("/usr/bin/systemctl", &[kind, service]);
    if result.code == -1 {
        None
    } else {
        Some(result.stdout.trim().to_string())
    }
}

fn write_command_receipt_with_change_observed(
    receipt_dir: &Path,
    name: &str,
    result: &CmdResult,
    change_observed: &str,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{}.json", name)),
        &serde_json::json!({
            "schema": "harmonia.command_receipt.v1",
            "name": name,
            "ok": result.ok,
            "exit_code": result.code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "change_observed": change_observed,
        }),
    )
}

#[allow(clippy::too_many_arguments)]
fn write_systemd_command_receipt(
    receipt_dir: &Path,
    name: &str,
    result: &CmdResult,
    enabled_before: Option<&str>,
    active_before: Option<&str>,
    enabled_after: Option<&str>,
    active_after: Option<&str>,
    changed: bool,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{}.json", name)),
        &serde_json::json!({
            "schema": "harmonia.command_receipt.v1",
            "name": name,
            "ok": result.ok,
            "exit_code": result.code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "enabled_before": enabled_before,
            "active_before": active_before,
            "enabled_after": enabled_after,
            "active_after": active_after,
            "changed": changed,
        }),
    )
}

pub(crate) fn git_artifact_tool(
    receipt_dir: &Path,
    name: &str,
    repo: Option<String>,
    path: PathBuf,
    branch: String,
    remote: String,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let request = crate::with_configured_https_credentials(tools::git_artifact::Request::new(
        repo, path, branch, remote,
    ))?;
    let outcome = if apply {
        tools::git_artifact::apply(&request)
    } else {
        tools::git_artifact::plan(&request)
    };
    let command = CmdResult {
        ok: outcome.command.ok,
        code: outcome.command.code,
        stdout: outcome.command.stdout,
        stderr: outcome.command.stderr,
    };
    write_command_receipt(receipt_dir, name, &command)?;
    Ok(OperationOutcome {
        ok: outcome.ok,
        changed: outcome.changed,
        skipped: false,
        message: outcome.message,
        command: Some(command),
    })
}

#[allow(dead_code)]
pub(crate) fn health_tool(
    receipt_dir: &Path,
    name: &str,
    url: Option<&str>,
    expected_contains: Option<&str>,
    command: Option<&str>,
    args: &[String],
    cwd: Option<&str>,
) -> Result<OperationOutcome, String> {
    if let Some(url) = url {
        let result = crate::tools::health::curl_probe(&crate::tools::health::ProbeRequest {
            url,
            retries: 0,
            timeout_secs: 3,
            expected_contains,
        });
        write_command_receipt(receipt_dir, name, &result)?;
        return Ok(OperationOutcome {
            ok: result.ok,
            changed: false,
            skipped: false,
            message: format!("health {url}"),
            command: Some(result),
        });
    }
    let program = command.ok_or_else(|| format!("health {name} missing command or url"))?;
    command_tool(receipt_dir, name, program, args, cwd)
}

#[allow(dead_code)]
pub(crate) fn cargo_tool(
    receipt_dir: &Path,
    name: &str,
    args: &[String],
    cwd: Option<&str>,
) -> Result<OperationOutcome, String> {
    let args = if args.is_empty() {
        vec!["build".to_string(), "--release".to_string()]
    } else {
        args.to_vec()
    };
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = command_capture_with_cwd("/usr/bin/cargo", &arg_refs, cwd);
    write_command_receipt(receipt_dir, name, &result)?;
    Ok(OperationOutcome {
        ok: result.ok,
        changed: false,
        skipped: false,
        message: "cargo".into(),
        command: Some(result),
    })
}

#[cfg(test)]
mod pacman_safety_tests {
    use super::*;

    #[test]
    fn sync_package_mutation_uses_full_upgrade_semantics() {
        let args = crate::tools::package::pacman_base_args(true);
        assert_eq!(args, vec!["-Syu", "--noconfirm"]);
    }

    #[test]
    fn overwrite_without_sidecar_allowance_remains_conflict_failure() {
        let result = CmdResult {
            ok: false,
            code: 1,
            stdout: String::new(),
            stderr: "error: failed to commit transaction (conflicting files)\nfoo: /usr/bin/foo exists in filesystem".to_string(),
        };
        assert!(!result.ok);
        assert_eq!(
            crate::tools::package::pacman_conflict_signal(&result).as_deref(),
            Some("pacman-package-file-conflict")
        );
        assert!(result.stderr.contains("exists in filesystem"));
    }

    #[test]
    fn overwrite_policy_rejects_wildcard_paths() {
        assert!(crate::tools::package::overwrite_allowed_args(
            &crate::tools::package::pacman_base_args(false),
            &["*".to_string()]
        )
        .is_none());
    }
}
