use super::{reject_executable_sidecar, require_path, ModuleExecution};
use crate::*;
use std::path::{Path, PathBuf};

pub(crate) const ID: &str = "keyman-runtime";

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
        "keyman-source-repository",
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
            "keyman-runtime-install",
            "/usr/local/bin/harmonia",
            &[
                "homeconsole-keyman-update".to_string(),
                "/etc/harmonia/profiles/homeconsole/index.json".to_string(),
                "--source".to_string(),
                source_path.display().to_string(),
                "--store-dir".to_string(),
                source_path.display().to_string(),
                "--apply".to_string(),
                "--receipt-dir".to_string(),
                "/var/lib/harmonia/receipts/keyman-latest".to_string(),
            ],
            None,
        )?
    } else {
        let outcome = OperationOutcome {
            ok: repo.ok,
            changed: false,
            skipped: true,
            message: if repo.ok {
                "keyman runtime install planned after source checkout".to_string()
            } else {
                "keyman runtime install skipped because source checkout failed".to_string()
            },
            command: None,
        };
        write_tool_receipt(
            receipt_dir,
            "keyman-runtime-install",
            "command",
            "run",
            &outcome,
        )?;
        outcome
    };

    Ok(ModuleExecution::from_operations(
        vec![
            ("keyman-source-repository", repo),
            ("keyman-runtime-install", install),
        ],
        &module.id,
    ))
}
