use super::{require_schema, require_step};
use crate::*;

pub(crate) const ID: &str = "keyman-runtime";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    require_schema(module)?;
    if module.steps.len() != 1 {
        return Err("keyman-runtime-module-step-count".to_string());
    }
    let step = &module.steps[0];
    require_step(step, "keyman-source-repository", "git-artifact", "sync")?;
    if step.path.as_deref() != Some("/opt/keyman/source") || step.branch.as_deref() != Some("main")
    {
        return Err("keyman-runtime-repository-contract".to_string());
    }
    Ok(())
}
