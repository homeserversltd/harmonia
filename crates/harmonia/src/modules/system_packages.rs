use super::{require_schema, require_step};
use crate::*;

pub(crate) const ID: &str = "system-packages";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    require_schema(module)?;
    if module.steps.len() != 2 {
        return Err("system-packages-module-step-count".to_string());
    }
    require_step(&module.steps[0], "pacman-check", "package", "check")?;
    require_step(&module.steps[1], "pacman-update", "package", "update")?;
    if !module.steps[1].apply_only {
        return Err("system-packages-update-must-be-apply-only".to_string());
    }
    Ok(())
}
