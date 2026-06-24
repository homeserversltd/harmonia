use crate::module_dispatch::{reject_executable_sidecar, require_path, ModuleExecution};
use crate::*;
use serde_json::json;
use std::env;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::UNIX_EPOCH;

pub(crate) const ID: &str = "harmonia-runtime";
const SELF_UPDATE_REEXEC_ENV: &str = "HARMONIA_SELF_UPDATE_REEXEC";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    reject_executable_sidecar(module)?;
    require_path(module, &module.repo, "repo")?;
    require_path(module, &module.source_dir, "source_dir")?;
    require_path(module, &module.install_bin, "install_bin")?;
    Ok(())
}

pub(crate) fn install_bin_fingerprint(path: &Path) -> Option<(u64, u64)> {
    let meta = fs::metadata(path).ok()?;
    let modified = meta
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some((meta.len(), modified))
}

pub(crate) fn self_update_reexec_guard_active() -> bool {
    env::var(SELF_UPDATE_REEXEC_ENV).as_deref() == Ok("1")
}

pub(crate) fn should_self_update_reexec(
    apply: bool,
    install_ok: bool,
    before: Option<(u64, u64)>,
    after: Option<(u64, u64)>,
) -> bool {
    apply
        && install_ok
        && !self_update_reexec_guard_active()
        && after.is_some()
        && before != after
}

pub(crate) fn reexec_installed_harmonia(install_bin: &Path, receipt_dir: &Path) -> Result<(), String> {
    write_json(
        &receipt_dir.join("harmonia-self-update-reexec.json"),
        &json!({
            "schema": "harmonia.runtime.self_update_reexec.v1",
            "ok": true,
            "install_bin": install_bin,
            "reason": "installed harmonia binary changed; re-exec same argv so downstream profile modules run on the fresh process",
        }),
    )?;
    let mut cmd = Command::new(install_bin);
    cmd.args(env::args().skip(1));
    cmd.env(SELF_UPDATE_REEXEC_ENV, "1");
    let err = cmd.exec();
    Err(format!("harmonia-self-update-reexec-failed: {err}"))
}

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<ModuleExecution, String> {
    validate(module)?;
    let repo = require_path(module, &module.repo, "repo")?.to_string();
    let source_dir = PathBuf::from(require_path(module, &module.source_dir, "source_dir")?);
    let install_bin = PathBuf::from(require_path(module, &module.install_bin, "install_bin")?);
    let branch = module.branch.as_deref().unwrap_or("main");
    let install_before = install_bin_fingerprint(&install_bin);

    write_json(
        &receipt_dir.join("harmonia-binary-explain.json"),
        &json!({
            "schema": "harmonia.runtime.explain_receipt.v1",
            "ok": true,
            "name": "harmonia",
            "version": env!("CARGO_PKG_VERSION"),
            "covenant": "Rust update manager and appliance-profile execution engine",
            "shell": "bootstrap-only",
            "python_helper_lane": false,
            "install_bin": install_bin,
            "source_dir": source_dir,
            "repo": repo,
            "branch": branch,
        }),
    )?;
    let explain = OperationOutcome {
        ok: true,
        changed: false,
        skipped: false,
        message: "harmonia runtime explained by current Rust process".to_string(),
        command: None,
    };

    let git_request = tools::git_artifact::Request::new(
        Some(repo),
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
    let git_cmd = CmdResult {
        ok: git_outcome.command.ok,
        code: git_outcome.command.code,
        stdout: git_outcome.command.stdout.clone(),
        stderr: git_outcome.command.stderr.clone(),
    };
    write_command_receipt(receipt_dir, "harmonia-source-repository", &git_cmd)?;
    let repo_outcome = OperationOutcome {
        ok: git_outcome.ok,
        changed: git_outcome.changed,
        skipped: false,
        message: if git_outcome.ok {
            "harmonia source repository possessed".to_string()
        } else {
            "harmonia source repository failed".to_string()
        },
        command: Some(git_cmd),
    };

    let install = if apply && git_outcome.ok {
        command_capture_with_cwd(
            "/usr/bin/python3",
            &[
                "-B",
                "./cli.py",
                "install",
                "--apply",
                "--profile",
                "homeconsole",
            ],
            source_dir.to_str(),
        )
    } else if git_outcome.ok {
        CmdResult {
            ok: true,
            code: 0,
            stdout: "planned: ./cli.py install --apply --profile homeconsole".to_string(),
            stderr: String::new(),
        }
    } else {
        CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: "skipped because source repository possession failed".to_string(),
        }
    };
    write_command_receipt(receipt_dir, "harmonia-installer", &install)?;
    let install_after = install_bin_fingerprint(&install_bin);
    let install_changed = should_self_update_reexec(apply, install.ok, install_before, install_after);
    let install_outcome = OperationOutcome {
        ok: install.ok,
        changed: install_changed,
        skipped: !apply,
        message: if install.ok {
            "harmonia binary/profile/module install path converged".to_string()
        } else {
            "harmonia installer failed".to_string()
        },
        command: Some(install.clone()),
    };

    write_json(
        &receipt_dir.join("harmonia-profile-inspect.json"),
        &json!({
            "schema": "harmonia.runtime.profile_inspect_receipt.v1",
            "ok": git_outcome.ok && install.ok,
            "profile_path": "/etc/harmonia/profiles/homeconsole/index.json",
            "profile_id": "homeconsole",
            "identity": "homeconsole",
            "source_dir": source_dir,
            "install_bin": install_bin,
        }),
    )?;

    let mut execution = ModuleExecution::from_operations(
        vec![
            ("harmonia-binary-explain", explain),
            ("harmonia-source-repository", repo_outcome),
            ("harmonia-installer", install_outcome),
        ],
        &module.id,
    );
    if !execution.ok {
        execution.first_missing_signal = Some(if !git_outcome.ok {
            "harmonia-source-repository-failed".to_string()
        } else {
            "harmonia-installer-failed".to_string()
        });
        return Ok(execution);
    }

    if install_changed {
        reexec_installed_harmonia(&install_bin, receipt_dir)?;
    }

    Ok(execution)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_update_reexec_requires_binary_fingerprint_change() {
        assert!(!should_self_update_reexec(
            true,
            true,
            Some((100, 1)),
            Some((100, 1)),
        ));
        assert!(should_self_update_reexec(
            true,
            true,
            Some((100, 1)),
            Some((200, 2)),
        ));
        assert!(!should_self_update_reexec(false, true, Some((1, 1)), Some((2, 2))));
        assert!(!should_self_update_reexec(true, false, Some((1, 1)), Some((2, 2))));
    }
}