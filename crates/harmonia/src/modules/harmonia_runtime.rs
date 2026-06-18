use super::{require_schema, require_step};
use crate::*;

pub(crate) const ID: &str = "harmonia-runtime";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    require_schema(module)?;
    if module.steps.len() != 2 {
        return Err("harmonia-runtime-module-step-count".to_string());
    }
    let explain = &module.steps[0];
    require_step(explain, "harmonia-binary-explain", "command", "run")?;
    if explain.command.as_deref() != Some("/usr/local/bin/harmonia")
        || explain.args != ["explain"]
        || !explain.apply_only
    {
        return Err("harmonia-runtime-explain-contract".to_string());
    }
    let inspect = &module.steps[1];
    require_step(inspect, "harmonia-profile-inspect", "command", "run")?;
    if inspect.command.as_deref() != Some("/usr/local/bin/harmonia")
        || inspect.args
            != [
                "inspect-profile",
                "/etc/harmonia/profiles/homeconsole/index.json",
            ]
        || !inspect.apply_only
    {
        return Err("harmonia-runtime-profile-contract".to_string());
    }
    Ok(())
}
