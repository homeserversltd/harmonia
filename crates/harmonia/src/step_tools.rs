use crate::*;
use std::fs::{self};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub(crate) fn execute_step(
    step: &Step,
    receipt_dir: &Path,
    apply: bool,
) -> Result<StepOutcome, String> {
    if step.apply_only && !apply {
        write_step_receipt(
            receipt_dir,
            step,
            true,
            false,
            true,
            "apply-only planned",
            None,
        )?;
        return Ok(StepOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "apply-only planned".into(),
            command: None,
        });
    }
    let outcome = match step.tool.as_str() {
        "command" => exec_command_step(step),
        "package" => exec_package_step(step, apply),
        "systemd" => exec_systemd_step(step, apply),
        "artifact" => exec_artifact_step(step, apply),
        "git-artifact" | "repo" => exec_git_artifact_step(step, apply),
        "health" => exec_health_step(step),
        "rust-build" => exec_cargo_step(step),
        "node-build" => exec_node_step(step),
        other => Ok(StepOutcome {
            ok: false,
            changed: false,
            skipped: false,
            message: format!("unknown tool {other}"),
            command: None,
        }),
    }?;
    write_step_receipt(
        receipt_dir,
        step,
        outcome.ok,
        outcome.changed,
        outcome.skipped,
        &outcome.message,
        outcome.command.as_ref(),
    )?;
    Ok(outcome)
}

pub(crate) fn exec_command_step(step: &Step) -> Result<StepOutcome, String> {
    let program = step
        .command
        .as_deref()
        .ok_or_else(|| format!("step {} missing command", step.id))?;
    let arg_refs: Vec<&str> = step.args.iter().map(String::as_str).collect();
    let result = command_capture_with_cwd(program, &arg_refs, step.cwd.as_deref());
    Ok(StepOutcome {
        ok: result.ok,
        changed: false,
        skipped: false,
        message: format!("command {}", program),
        command: Some(result),
    })
}

pub(crate) fn exec_package_step(step: &Step, apply: bool) -> Result<StepOutcome, String> {
    let action = if step.action.is_empty() {
        "check"
    } else {
        step.action.as_str()
    };
    if !Path::new("/usr/bin/pacman").exists() {
        return Ok(StepOutcome {
            ok: !apply,
            changed: false,
            skipped: !apply,
            message: if apply {
                "pacman missing for package mutation".to_string()
            } else {
                "package manager absent on scout host; planned only".to_string()
            },
            command: None,
        });
    }
    let result = match action {
        "update" if apply => command_capture("/usr/bin/pacman", &["-Syu", "--noconfirm"]),
        "update" | "check" => command_capture("/usr/bin/pacman", &["-Qu"]),
        "install" if apply => {
            let mut args = vec!["-S", "--noconfirm"];
            args.extend(step.args.iter().map(String::as_str));
            command_capture("/usr/bin/pacman", &args)
        }
        "install" => command_capture("/usr/bin/pacman", &["-Q"]),
        other => {
            return Ok(StepOutcome {
                ok: false,
                changed: false,
                skipped: false,
                message: format!("unsupported package action {other}"),
                command: None,
            })
        }
    };
    let changed =
        action == "update" && apply && result.ok && pacman_stdout_indicates_change(&result.stdout);
    Ok(StepOutcome {
        ok: action != "check" || result.ok || result.code == 1,
        changed,
        skipped: false,
        message: format!("package {action}"),
        command: Some(result),
    })
}

pub(crate) fn exec_systemd_step(step: &Step, apply: bool) -> Result<StepOutcome, String> {
    let action = if step.action.is_empty() {
        "status"
    } else {
        step.action.as_str()
    };
    let service = step.service.as_deref().unwrap_or("");
    let mutating = matches!(
        action,
        "start" | "stop" | "restart" | "enable" | "disable" | "daemon-reload"
    );
    if mutating && !apply {
        return Ok(StepOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: format!("systemd {action} planned"),
            command: None,
        });
    }
    let result = match action {
        "daemon-reload" => command_capture("/usr/bin/systemctl", &["daemon-reload"]),
        "active" | "is-active" => command_capture("/usr/bin/systemctl", &["is-active", service]),
        "status" => command_capture("/usr/bin/systemctl", &["status", service, "--no-pager"]),
        "start" | "stop" | "restart" | "enable" | "disable" => {
            command_capture("/usr/bin/systemctl", &[action, service])
        }
        other => {
            return Ok(StepOutcome {
                ok: false,
                changed: false,
                skipped: false,
                message: format!("unsupported systemd action {other}"),
                command: None,
            })
        }
    };
    Ok(StepOutcome {
        ok: result.ok,
        changed: mutating,
        skipped: false,
        message: format!("systemd {action} {service}"),
        command: Some(result),
    })
}

pub(crate) fn exec_artifact_step(step: &Step, apply: bool) -> Result<StepOutcome, String> {
    let artifact = PathBuf::from(
        step.artifact
            .as_deref()
            .ok_or_else(|| format!("step {} missing artifact", step.id))?,
    );
    let install_bin = PathBuf::from(
        step.install_bin
            .as_deref()
            .ok_or_else(|| format!("step {} missing install_bin", step.id))?,
    );
    let metadata = fs::metadata(&artifact)
        .map_err(|e| format!("artifact-missing {}: {e}", artifact.display()))?;
    if !apply {
        return Ok(StepOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: format!("artifact planned bytes={}", metadata.len()),
            command: None,
        });
    }
    if let Some(parent) = install_bin.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let before_len = fs::metadata(&install_bin).map(|m| m.len()).ok();
    let tmp_install = install_bin.with_extension("harmonia-new");
    fs::copy(&artifact, &tmp_install).map_err(|e| format!("artifact-copy-failed: {e}"))?;
    let mut perms = fs::metadata(&tmp_install)
        .map_err(|e| e.to_string())?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&tmp_install, perms).map_err(|e| e.to_string())?;
    fs::rename(&tmp_install, &install_bin).map_err(|e| format!("artifact-promote-failed: {e}"))?;
    Ok(StepOutcome {
        ok: true,
        changed: before_len != Some(metadata.len()),
        skipped: false,
        message: format!("artifact promoted to {}", install_bin.display()),
        command: None,
    })
}

pub(crate) fn exec_git_artifact_step(step: &Step, apply: bool) -> Result<StepOutcome, String> {
    let path = PathBuf::from(
        step.path
            .as_deref()
            .ok_or_else(|| format!("step {} missing path", step.id))?,
    );
    let request = tools::git_artifact::Request::new(
        step.repo.clone(),
        path,
        step.branch.clone().unwrap_or_else(|| "main".to_string()),
        step.remote.clone().unwrap_or_else(|| "origin".to_string()),
    );
    let outcome = if apply {
        tools::git_artifact::apply(&request)
    } else {
        tools::git_artifact::plan(&request)
    };
    Ok(StepOutcome {
        ok: outcome.ok,
        changed: outcome.changed,
        skipped: false,
        message: outcome.message,
        command: Some(CmdResult {
            ok: outcome.command.ok,
            code: outcome.command.code,
            stdout: outcome.command.stdout,
            stderr: outcome.command.stderr,
        }),
    })
}

pub(crate) fn exec_health_step(step: &Step) -> Result<StepOutcome, String> {
    if let Some(url) = &step.url {
        let result = command_capture("/usr/bin/curl", &["-fsS", "--max-time", "3", url]);
        let expected_ok = step
            .expected_contains
            .as_ref()
            .map(|needle| result.stdout.contains(needle))
            .unwrap_or(true);
        return Ok(StepOutcome {
            ok: result.ok && expected_ok,
            changed: false,
            skipped: false,
            message: format!("health {url}"),
            command: Some(result),
        });
    }
    exec_command_step(step)
}

pub(crate) fn exec_cargo_step(step: &Step) -> Result<StepOutcome, String> {
    let args = if step.args.is_empty() {
        vec!["build".to_string(), "--release".to_string()]
    } else {
        step.args.clone()
    };
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = command_capture_with_cwd("/usr/bin/cargo", &arg_refs, step.cwd.as_deref());
    Ok(StepOutcome {
        ok: result.ok,
        changed: false,
        skipped: false,
        message: "cargo".into(),
        command: Some(result),
    })
}

pub(crate) fn exec_node_step(step: &Step) -> Result<StepOutcome, String> {
    let command = step.command.as_deref().unwrap_or("/usr/bin/npm");
    let args = if step.args.is_empty() {
        vec!["run".to_string(), "build".to_string()]
    } else {
        step.args.clone()
    };
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = command_capture_with_cwd(command, &arg_refs, step.cwd.as_deref());
    Ok(StepOutcome {
        ok: result.ok,
        changed: false,
        skipped: false,
        message: "node-build".into(),
        command: Some(result),
    })
}
