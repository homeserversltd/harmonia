use super::{reject_executable_sidecar, require_path, ModuleExecution};
use crate::*;
use std::path::{Path, PathBuf};

pub(crate) const ID: &str = "homeconsole-sync-runtime";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    reject_executable_sidecar(module)?;
    require_path(module, &module.repo, "repo")?;
    require_path(module, &module.path, "path")?;
    Ok(())
}

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<ModuleExecution, String> {
    validate(module)?;
    let repo = git_artifact_tool(
        receipt_dir,
        "homeconsole-sync-source-repository",
        module.repo.clone(),
        PathBuf::from(require_path(module, &module.path, "path")?),
        module.branch.clone().unwrap_or_else(|| "main".to_string()),
        module
            .remote
            .clone()
            .unwrap_or_else(|| "origin".to_string()),
        apply,
    )?;
    let install = if apply {
        command_tool(
            receipt_dir,
            "homeconsole-sync-install",
            "/opt/homeconsole-sync/source/cli.py",
            &["install".to_string(), "--apply".to_string()],
            None,
        )?
    } else {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "homeconsole-sync install planned".to_string(),
            command: None,
        };
        write_tool_receipt(
            receipt_dir,
            "homeconsole-sync-install",
            "command",
            "run",
            &outcome,
        )?;
        outcome
    };
    Ok(ModuleExecution::from_operations(
        vec![
            ("homeconsole-sync-source-repository", repo),
            ("homeconsole-sync-install", install),
        ],
        &module.id,
    ))
}
