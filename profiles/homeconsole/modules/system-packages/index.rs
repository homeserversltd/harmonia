use crate::modules::{reject_executable_sidecar, ModuleExecution};
use crate::*;
use std::path::Path;

pub(crate) const ID: &str = "system-packages";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    reject_executable_sidecar(module)
}

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<ModuleExecution, String> {
    validate(module)?;
    let check = package_tool(receipt_dir, "pacman-check", "check", &[], apply)?;
    let update = package_tool(receipt_dir, "pacman-update", "update", &[], apply)?;
    Ok(ModuleExecution::from_operations(
        vec![("pacman-check", check), ("pacman-update", update)],
        &module.id,
    ))
}
