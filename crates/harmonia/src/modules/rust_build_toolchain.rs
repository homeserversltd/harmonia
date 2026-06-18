use super::{require_schema, require_step};
use crate::*;

pub(crate) const ID: &str = "rust-build-toolchain";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    require_schema(module)?;
    if module.steps.len() != 1 {
        return Err("rust-build-toolchain-module-step-count".to_string());
    }
    let step = &module.steps[0];
    require_step(step, "rust-package-install", "package", "install")?;
    if step.args != ["rust"] || !step.apply_only {
        return Err("rust-build-toolchain-package-contract".to_string());
    }
    Ok(())
}
