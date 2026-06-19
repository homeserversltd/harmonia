use super::{reject_executable_sidecar, ModuleExecution};
use crate::*;
use std::path::Path;

pub(crate) const ID: &str = "identity";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    reject_executable_sidecar(module)
}

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    _apply: bool,
) -> Result<ModuleExecution, String> {
    validate(module)?;
    let outcome = command_tool(
        receipt_dir,
        "uname",
        "/usr/bin/uname",
        &["-a".to_string()],
        None,
    )?;
    Ok(ModuleExecution::from_operations(
        vec![("uname", outcome)],
        &module.id,
    ))
}
