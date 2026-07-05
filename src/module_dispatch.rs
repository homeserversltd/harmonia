use crate::*;
use std::fs;
use std::path::Path;

pub(crate) struct ModuleExecution {
    pub(crate) ok: bool,
    pub(crate) changed: bool,
    pub(crate) operation_count: usize,
    pub(crate) first_missing_signal: Option<String>,
}

impl ModuleExecution {
    pub(crate) fn from_operations(
        outcomes: Vec<(&'static str, OperationOutcome)>,
        module_id: &str,
    ) -> Self {
        let mut ok = true;
        let mut changed = false;
        let mut first_missing_signal = None;
        for (operation_id, outcome) in &outcomes {
            if outcome.changed {
                changed = true;
            }
            if !outcome.ok {
                ok = false;
                if first_missing_signal.is_none() {
                    first_missing_signal = Some(format!("{}-{}-failed", module_id, operation_id));
                }
            }
        }
        Self {
            ok,
            changed,
            operation_count: outcomes.len(),
            first_missing_signal,
        }
    }
}

pub(crate) fn execute_profile_module(
    module: &ModuleManifest,
    module_root: &Path,
    receipt_dir: &Path,
    apply: bool,
    _harmonia_root: &Path,
) -> Result<ModuleExecution, String> {
    let module_dir = receipt_dir.join("modules").join(&module.id);
    fs::create_dir_all(&module_dir).map_err(|e| e.to_string())?;
    let manifest_path = module_root.join(&module.id).join("manifest.json");
    if manifest_path.exists() && is_ladder_manifest(&manifest_path) {
        let manifest = load_ladder_manifest(&manifest_path)?;
        if manifest.id != module.id {
            return Err(format!(
                "module-invalid step_id=manifest defect=id-mismatch-{}",
                manifest.id
            ));
        }
        execute_ladder_manifest(&manifest, &module_dir, apply)
    } else {
        Err(format!("module-unregistered-{}", module.id))
    }
}

pub(crate) fn is_registered_module_id(_module_id: &str) -> bool {
    false
}

pub(crate) fn validate_registered_module(module: &ModuleManifest) -> Result<(), String> {
    let manifest_path = std::path::Path::new("profiles/homeconsole/modules")
        .join(&module.id)
        .join("manifest.json");
    if manifest_path.exists() {
        Ok(())
    } else {
        Err(format!("module-unregistered-{}", module.id))
    }
}

pub(crate) fn reject_executable_sidecar(module: &ModuleManifest) -> Result<(), String> {
    if module.command.is_some() || !module.args.is_empty() || module.cwd.is_some() {
        return Err(format!("module-executable-sidecar-rejected-{}", module.id));
    }
    Ok(())
}

pub(crate) fn require_path<'a>(
    module: &'a ModuleManifest,
    value: &'a Option<String>,
    name: &str,
) -> Result<&'a str, String> {
    value
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| format!("module-sidecar-missing-{}-{}", module.id, name))
}

pub(crate) fn require_packages(module: &ModuleManifest) -> Result<(), String> {
    if module.packages.is_empty() {
        return Err(format!("module-sidecar-missing-{}-packages", module.id));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn homeconsole_sync_runtime_validate_for_test(
    _module: &ModuleManifest,
) -> Result<(), String> {
    Ok(())
}
