use crate::*;
use std::fs;
use std::path::Path;

mod arcadia_gui_runtime;
mod homeconsole_sync_runtime;
mod identity;
mod keyman_runtime;
mod system_packages;

pub(crate) struct ModuleExecution {
    pub(crate) ok: bool,
    pub(crate) changed: bool,
    pub(crate) step_count: usize,
    pub(crate) first_missing_signal: Option<String>,
}

pub(crate) fn execute_profile_module(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<ModuleExecution, String> {
    validate_registered_module(module)?;
    let step_dir = receipt_dir.join("steps").join(&module.id);
    fs::create_dir_all(&step_dir).map_err(|e| e.to_string())?;

    let mut ok = true;
    let mut changed = false;
    let mut first_missing_signal = None;
    let mut step_count = 0usize;

    for step in &module.steps {
        step_count += 1;
        let outcome = execute_step(step, &step_dir, apply)?;
        if outcome.changed {
            changed = true;
        }
        if !outcome.ok {
            ok = false;
            if first_missing_signal.is_none() {
                first_missing_signal = Some(format!("{}-{}-failed", module.id, step.id));
            }
        }
    }

    Ok(ModuleExecution {
        ok,
        changed,
        step_count,
        first_missing_signal,
    })
}

pub(crate) fn validate_registered_module(module: &ModuleManifest) -> Result<(), String> {
    match module.id.as_str() {
        identity::ID => identity::validate(module),
        system_packages::ID => system_packages::validate(module),
        keyman_runtime::ID => keyman_runtime::validate(module),
        homeconsole_sync_runtime::ID => homeconsole_sync_runtime::validate(module),
        arcadia_gui_runtime::ID => arcadia_gui_runtime::validate(module),
        other => Err(format!("module-unregistered-{other}")),
    }
}

fn require_schema(module: &ModuleManifest) -> Result<(), String> {
    if module.steps.is_empty() {
        return Err(format!("module-empty-{}", module.id));
    }
    Ok(())
}

fn require_step(step: &Step, id: &str, tool: &str, action: &str) -> Result<(), String> {
    if step.id != id || step.tool != tool || step.action != action {
        return Err(format!(
            "module-step-contract-mismatch-{}-expected-{}-{}-{}",
            step.id, id, tool, action
        ));
    }
    Ok(())
}
