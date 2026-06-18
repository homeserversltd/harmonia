use super::{require_schema, require_step};
use crate::*;

pub(crate) const ID: &str = "identity";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    require_schema(module)?;
    if module.steps.len() != 1 {
        return Err("identity-module-step-count".to_string());
    }
    let step = &module.steps[0];
    require_step(step, "uname", "command", "run")?;
    if step.command.as_deref() != Some("/usr/bin/uname") || step.args != ["-a"] {
        return Err("identity-module-command-contract".to_string());
    }
    Ok(())
}
