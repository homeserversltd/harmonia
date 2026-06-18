use super::{require_schema, require_step};
use crate::*;

pub(crate) const ID: &str = "arcadia-gui-runtime";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    require_schema(module)?;
    if module.steps.len() != 1 {
        return Err("arcadia-gui-runtime-module-step-count".to_string());
    }
    let step = &module.steps[0];
    require_step(step, "arcadia-gui-update", "command", "run")?;
    if step.command.as_deref() != Some("/usr/local/bin/harmonia")
        || step.args
            != [
                "homeconsole-arcadia-gui-update",
                "/etc/harmonia/profiles/homeconsole/index.json",
                "--apply",
                "--source-dir",
                "/opt/arcadia/source",
                "--receipt-dir",
                "/var/lib/harmonia/receipts/arcadia-gui-latest",
            ]
        || !step.apply_only
    {
        return Err("arcadia-gui-runtime-command-contract".to_string());
    }
    Ok(())
}
