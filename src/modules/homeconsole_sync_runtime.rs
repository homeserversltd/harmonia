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
    let source_path = PathBuf::from(require_path(module, &module.path, "path")?);
    let repo = git_artifact_tool(
        receipt_dir,
        "homeconsole-sync-source-repository",
        module.repo.clone(),
        source_path.clone(),
        module.branch.clone().unwrap_or_else(|| "main".to_string()),
        module
            .remote
            .clone()
            .unwrap_or_else(|| "origin".to_string()),
        apply,
    )?;
    let install = if apply && repo.ok {
        command_tool(
            receipt_dir,
            "homeconsole-sync-install",
            source_path.join("cli.py").to_string_lossy().as_ref(),
            &["install".to_string(), "--apply".to_string()],
            Some(source_path.to_string_lossy().as_ref()),
        )?
    } else {
        let outcome = OperationOutcome {
            ok: repo.ok,
            changed: false,
            skipped: true,
            message: if repo.ok {
                "homeconsole-sync install planned after source checkout".to_string()
            } else {
                "homeconsole-sync install skipped because source checkout failed".to_string()
            },
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
