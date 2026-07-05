use crate::*;
use serde_json::json;
use std::env;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::UNIX_EPOCH;

pub(crate) const PREFLIGHT_SCHEMA: &str = "harmonia.engine.preflight.v1";
const SELF_UPDATE_REEXEC_ENV: &str = "HARMONIA_SELF_UPDATE_REEXEC";

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
    apply && install_ok && !self_update_reexec_guard_active() && after.is_some() && before != after
}

pub(crate) fn run_engine_preflight(
    module_root: &Path,
    receipt_dir: &Path,
    apply: bool,
) -> Result<ModuleExecution, String> {
    let sidecar = module_root.join("harmonia-runtime/sidecar.json");
    if !sidecar.exists() {
        return Ok(ModuleExecution {
            ok: true,
            changed: false,
            operation_count: 0,
            first_missing_signal: None,
        });
    }
    let module = load_module(&sidecar)?;
    reject_executable_sidecar(&module)?;
    let preflight_dir = receipt_dir.join("engine-preflight");
    fs::create_dir_all(&preflight_dir).map_err(|e| e.to_string())?;
    let repo = require_path(&module, &module.repo, "repo")?.to_string();
    let source_dir = PathBuf::from(require_path(&module, &module.source_dir, "source_dir")?);
    let install_bin = PathBuf::from(require_path(&module, &module.install_bin, "install_bin")?);
    let branch = module.branch.as_deref().unwrap_or("main");
    let install_profile = module.install_profile.as_deref().unwrap_or("homeconsole");
    let install_before = install_bin_fingerprint(&install_bin);
    let bootstrap = if module.packages.is_empty() {
        OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "harmonia runtime bootstrap package set empty".into(),
            command: None,
        }
    } else {
        package_tool(
            &preflight_dir,
            "harmonia-runtime-bootstrap-packages",
            "install",
            &module.packages,
            apply,
        )?
    };
    let explain = OperationOutcome {
        ok: true,
        changed: false,
        skipped: false,
        message: "engine pre-flight explains current Rust process".into(),
        command: None,
    };
    write_json(
        &preflight_dir.join("harmonia-engine-preflight-explain.json"),
        &json!({
            "schema": PREFLIGHT_SCHEMA,
            "ok": true,
            "stage": "engine-preflight",
            "version": env!("CARGO_PKG_VERSION"),
            "repo": repo,
            "branch": branch,
            "source_dir": source_dir,
            "install_bin": install_bin,
            "install_profile": install_profile,
            "reexec_guard_active": self_update_reexec_guard_active(),
        }),
    )?;
    let git_request = tools::git_artifact::Request::new(
        Some(repo),
        source_dir.clone(),
        branch.to_string(),
        module.remote.clone().unwrap_or_else(|| "origin".into()),
    );
    let git_outcome = if apply && bootstrap.ok {
        tools::git_artifact::apply(&git_request)
    } else if apply {
        tools::git_artifact::Outcome {
            ok: false,
            changed: false,
            message: "harmonia source repository skipped because bootstrap packages failed".into(),
            command: tools::git_artifact::CommandReceipt {
                ok: false,
                code: -1,
                stdout: String::new(),
                stderr: "skipped because harmonia runtime bootstrap packages failed".into(),
            },
        }
    } else {
        tools::git_artifact::plan(&git_request)
    };
    let git_cmd = CmdResult {
        ok: git_outcome.command.ok,
        code: git_outcome.command.code,
        stdout: git_outcome.command.stdout.clone(),
        stderr: git_outcome.command.stderr.clone(),
    };
    write_command_receipt(&preflight_dir, "harmonia-source-repository", &git_cmd)?;
    let repo_outcome = OperationOutcome {
        ok: git_outcome.ok,
        changed: git_outcome.changed,
        skipped: false,
        message: if git_outcome.ok {
            "harmonia source repository possessed"
        } else {
            "harmonia source repository failed"
        }
        .into(),
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
                install_profile,
            ],
            source_dir.to_str(),
        )
    } else if git_outcome.ok {
        CmdResult {
            ok: true,
            code: 0,
            stdout: format!("planned: ./cli.py install --apply --profile {install_profile}"),
            stderr: String::new(),
        }
    } else {
        CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: "skipped because source repository possession failed".into(),
        }
    };
    write_command_receipt(&preflight_dir, "harmonia-installer", &install)?;
    let install_after = install_bin_fingerprint(&install_bin);
    let install_changed =
        should_self_update_reexec(apply, install.ok, install_before, install_after);
    write_json(
        &preflight_dir.join("run.json"),
        &json!({
            "schema": PREFLIGHT_SCHEMA,
            "ok": bootstrap.ok && git_outcome.ok && install.ok,
            "apply": apply,
            "changed": install_changed || git_outcome.changed,
            "reexec_once_guard_preserved": true,
            "reexec_planned": install_changed,
            "first_missing_signal": if bootstrap.ok && git_outcome.ok && install.ok { "none" } else if !bootstrap.ok { "harmonia-runtime-bootstrap-packages-failed" } else if !git_outcome.ok { "harmonia-source-repository-failed" } else { "harmonia-installer-failed" },
        }),
    )?;
    let mut execution = ModuleExecution::from_operations(
        vec![
            ("harmonia-binary-explain", explain),
            ("harmonia-runtime-bootstrap-packages", bootstrap),
            ("harmonia-source-repository", repo_outcome),
            (
                "harmonia-installer",
                OperationOutcome {
                    ok: install.ok,
                    changed: install_changed,
                    skipped: !apply,
                    message: if install.ok {
                        "harmonia binary/profile/module install path converged"
                    } else {
                        "harmonia installer failed"
                    }
                    .into(),
                    command: Some(install),
                },
            ),
        ],
        "engine-preflight",
    );
    if !execution.ok && execution.first_missing_signal.is_none() {
        execution.first_missing_signal = Some("harmonia-engine-preflight-failed".into());
    }
    if execution.ok && install_changed {
        write_json(
            &preflight_dir.join("harmonia-self-update-reexec.json"),
            &json!({"schema":"harmonia.runtime.self_update_reexec.v1","ok":true,"install_bin":install_bin,"reason":"engine pre-flight installed a changed harmonia binary; re-exec same argv before module convergence"}),
        )?;
        let mut cmd = Command::new(&install_bin);
        cmd.args(env::args().skip(1));
        cmd.env(SELF_UPDATE_REEXEC_ENV, "1");
        let err = cmd.exec();
        return Err(format!("harmonia-self-update-reexec-failed: {err}"));
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
            Some((100, 1))
        ));
        assert!(should_self_update_reexec(
            true,
            true,
            Some((100, 1)),
            Some((200, 2))
        ));
        assert!(!should_self_update_reexec(
            false,
            true,
            Some((1, 1)),
            Some((2, 2))
        ));
    }
    #[test]
    fn preflight_schema_names_engine_plane() {
        assert_eq!(PREFLIGHT_SCHEMA, "harmonia.engine.preflight.v1");
    }
}
