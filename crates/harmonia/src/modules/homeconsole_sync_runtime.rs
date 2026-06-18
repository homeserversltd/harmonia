use super::{require_schema, require_step};
use crate::*;

pub(crate) const ID: &str = "homeconsole-sync-runtime";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    require_schema(module)?;
    if module.steps.len() != 2 {
        return Err("homeconsole-sync-runtime-module-step-count".to_string());
    }
    let repo = &module.steps[0];
    require_step(
        repo,
        "homeconsole-sync-source-repository",
        "git-artifact",
        "sync",
    )?;
    if repo.path.as_deref() != Some("/opt/homeconsole-sync/source")
        || repo.branch.as_deref() != Some("main")
    {
        return Err("homeconsole-sync-runtime-repository-contract".to_string());
    }
    let install = &module.steps[1];
    require_step(install, "homeconsole-sync-install", "command", "run")?;
    if install.command.as_deref() != Some("/opt/homeconsole-sync/source/cli.py")
        || install.args != ["install", "--apply"]
        || !install.apply_only
    {
        return Err("homeconsole-sync-runtime-install-contract".to_string());
    }
    Ok(())
}
