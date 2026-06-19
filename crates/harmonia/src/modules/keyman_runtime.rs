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
    let outcome = git_artifact_tool(
        receipt_dir,
        "keyman-source-repository",
        module.repo.clone(),
        PathBuf::from(require_path(module, &module.path, "path")?),
        module.branch.clone().unwrap_or_else(|| "main".to_string()),
        module
            .remote
            .clone()
            .unwrap_or_else(|| "origin".to_string()),
        apply,
    )?;
    Ok(ModuleExecution::from_operations(
        vec![("keyman-source-repository", outcome)],
        &module.id,
    ))
}
