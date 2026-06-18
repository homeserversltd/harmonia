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
        "receipt" | "config" | "version" | "backup" | "files" | "permissions" | "download"
        | "archive" | "cron-timer" | "migration" | "hotfix" | "interactable" | "venv" => {
            Ok(StepOutcome {
                ok: true,
                changed: false,
                skipped: true,
                message: format!("{} contract acknowledged", step.tool),
                command: None,
            })
        }
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
    let branch = step.branch.as_deref().unwrap_or("main");
    let remote = step.remote.as_deref().unwrap_or("origin");
    let repo = step.repo.as_deref();

    if !apply {
        let present = path.join(".git").exists();
        let result = if present {
            command_capture_with_cwd("/usr/bin/git", &["status", "--short"], path.to_str())
        } else {
            CmdResult {
                ok: true,
                code: 0,
                stdout: format!("planned clone/update path={}", path.display()),
                stderr: String::new(),
            }
        };
        return Ok(StepOutcome {
            ok: result.ok,
            changed: false,
            skipped: false,
            message: format!("git-artifact planned {}", path.display()),
            command: Some(result),
        });
    }

    let result = sync_git_repo(repo, &path, remote, branch);
    let changed = result.ok && git_sync_stdout_changed(&result.stdout);
    Ok(StepOutcome {
        ok: result.ok,
        changed,
        skipped: false,
        message: format!("git-artifact sync {}", path.display()),
        command: Some(result),
    })
}

pub(crate) fn sync_git_repo(
    repo: Option<&str>,
    path: &Path,
    remote: &str,
    branch: &str,
) -> CmdResult {
    let mut transcript = Vec::new();
    if !path.join(".git").exists() {
        let Some(repo) = repo else {
            return CmdResult {
                ok: false,
                code: 2,
                stdout: String::new(),
                stderr: format!(
                    "repo missing and no clone URL supplied for {}",
                    path.display()
                ),
            };
        };
        if let Some(parent) = path.parent() {
            if let Err(err) = fs::create_dir_all(parent) {
                return CmdResult {
                    ok: false,
                    code: 2,
                    stdout: String::new(),
                    stderr: format!("create parent failed {}: {err}", parent.display()),
                };
            }
        }
        let clone = command_capture(
            "/usr/bin/git",
            &[
                "clone",
                "--branch",
                branch,
                repo,
                path.to_string_lossy().as_ref(),
            ],
        );
        transcript.push(format!("clone exit={} ok={}", clone.code, clone.ok));
        if !clone.stdout.is_empty() {
            transcript.push(clone.stdout.clone());
        }
        if !clone.stderr.is_empty() {
            transcript.push(clone.stderr.clone());
        }
        if !clone.ok {
            return CmdResult {
                ok: false,
                code: clone.code,
                stdout: transcript.join("\n"),
                stderr: clone.stderr,
            };
        }
        return CmdResult {
            ok: true,
            code: 0,
            stdout: format!("changed=true\n{}", transcript.join("\n")),
            stderr: String::new(),
        };
    }

    let cwd = path.to_str();
    let before = command_capture_with_cwd("/usr/bin/git", &["rev-parse", "HEAD"], cwd);
    let dirty = command_capture_with_cwd("/usr/bin/git", &["status", "--porcelain"], cwd);
    if !dirty.ok {
        return dirty;
    }
    if !dirty.stdout.trim().is_empty() {
        return CmdResult {
            ok: false,
            code: 3,
            stdout: dirty.stdout,
            stderr: "working tree has local modifications; refusing repo sync".to_string(),
        };
    }
    let fetch = command_capture_with_cwd("/usr/bin/git", &["fetch", remote, branch], cwd);
    transcript.push(format!("fetch exit={} ok={}", fetch.code, fetch.ok));
    if !fetch.ok {
        return CmdResult {
            ok: false,
            code: fetch.code,
            stdout: transcript.join("\n"),
            stderr: fetch.stderr,
        };
    }
    let checkout = command_capture_with_cwd("/usr/bin/git", &["checkout", branch], cwd);
    transcript.push(format!(
        "checkout exit={} ok={}",
        checkout.code, checkout.ok
    ));
    if !checkout.ok {
        return CmdResult {
            ok: false,
            code: checkout.code,
            stdout: transcript.join("\n"),
            stderr: checkout.stderr,
        };
    }
    let pull_ref = format!("{remote}/{branch}");
    let merge = command_capture_with_cwd("/usr/bin/git", &["merge", "--ff-only", &pull_ref], cwd);
    transcript.push(format!("merge_ff exit={} ok={}", merge.code, merge.ok));
    if !merge.stdout.is_empty() {
        transcript.push(merge.stdout.clone());
    }
    if !merge.ok {
        return CmdResult {
            ok: false,
            code: merge.code,
            stdout: transcript.join("\n"),
            stderr: merge.stderr,
        };
    }
    let after = command_capture_with_cwd("/usr/bin/git", &["rev-parse", "HEAD"], cwd);
    let changed = before.stdout.trim() != after.stdout.trim();
    transcript.push(format!("before={}", before.stdout.trim()));
    transcript.push(format!("after={}", after.stdout.trim()));
    transcript.push(format!("changed={changed}"));
    CmdResult {
        ok: true,
        code: 0,
        stdout: transcript.join("\n"),
        stderr: String::new(),
    }
}

pub(crate) fn git_sync_stdout_changed(stdout: &str) -> bool {
    stdout.lines().any(|line| line.trim() == "changed=true")
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
