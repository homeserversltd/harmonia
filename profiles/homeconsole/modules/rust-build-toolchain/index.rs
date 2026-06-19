use crate::module_dispatch::{reject_executable_sidecar, require_packages, ModuleExecution};
use crate::*;
use std::path::Path;

pub(crate) const ID: &str = "rust-build-toolchain";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    reject_executable_sidecar(module)?;
    require_packages(module)
}

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<ModuleExecution, String> {
    validate(module)?;
    let outcome = package_tool(
        receipt_dir,
        "rust-package-install",
        "install",
        &module.packages,
        apply,
    )?;
    Ok(ModuleExecution::from_operations(
        vec![("rust-package-install", outcome)],
        &module.id,
    ))
}
