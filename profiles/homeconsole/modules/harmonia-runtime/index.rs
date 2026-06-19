use crate::module_dispatch::{reject_executable_sidecar, require_path, ModuleExecution};
use crate::*;
use serde_json::json;
use std::path::{Path, PathBuf};

pub(crate) const ID: &str = "harmonia-runtime";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    reject_executable_sidecar(module)?;
    require_path(module, &module.repo, "repo")?;
    require_path(module, &module.source_dir, "source_dir")?;
    require_path(module, &module.install_bin, "install_bin")?;
    Ok(())
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
    let install_outcome = OperationOutcome {
        ok: install.ok,
        changed: apply && install.ok,
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
    }
    Ok(execution)
}
