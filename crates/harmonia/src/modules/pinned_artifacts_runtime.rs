use super::{require_schema, require_step};
use crate::*;

pub(crate) const ID: &str = "pinned-artifacts-runtime";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    require_schema(module)?;
    if module.steps.len() != 1 {
        return Err("pinned-artifacts-runtime-module-step-count".to_string());
    }
    let check = &module.steps[0];
    require_step(check, "pinned-artifacts-check", "command", "run")?;
    if check.command.as_deref() != Some("/usr/local/bin/harmonia")
        || check.args
            != [
                "pinned-artifacts",
                "check",
                "/etc/harmonia/profiles/homeconsole/index.json",
                "--lock",
                "/etc/harmonia/locks/homeconsole/pinned-artifacts.json",
                "--receipt-dir",
                "/var/lib/harmonia/receipts/pinned-artifacts-check-latest",
            ]
        || !check.apply_only
    {
        return Err("pinned-artifacts-runtime-check-contract".to_string());
    }
    Ok(())
}
