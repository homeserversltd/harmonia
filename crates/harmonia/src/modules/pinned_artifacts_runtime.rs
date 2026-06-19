use super::{reject_executable_sidecar, require_path, ModuleExecution};
use crate::*;
use std::path::{Path, PathBuf};

pub(crate) const ID: &str = "pinned-artifacts-runtime";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    reject_executable_sidecar(module)?;
    require_path(module, &module.lock, "lock")?;
    Ok(())
}

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    _apply: bool,
) -> Result<ModuleExecution, String> {
    validate(module)?;
    if !_apply {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "pinned artifacts check planned".to_string(),
            command: None,
        };
        write_tool_receipt(
            receipt_dir,
            "pinned-artifacts-check",
            "pinned-artifacts",
            "check",
            &outcome,
        )?;
        return Ok(ModuleExecution::from_operations(
            vec![("pinned-artifacts-check", outcome)],
            &module.id,
        ));
    }
    let profile = Profile {
        id: "homeconsole".to_string(),
        identity: "homeconsole".to_string(),
        modules: HOMECONSOLE_UPDATE_SUITE_MODULES
            .iter()
            .map(|module| module.to_string())
            .collect(),
    };
    let lock = PathBuf::from(require_path(module, &module.lock, "lock")?);
    let args = vec![
        "pinned-artifacts".to_string(),
        "check".to_string(),
        "/etc/harmonia/profiles/homeconsole/index.json".to_string(),
        "--lock".to_string(),
        lock.display().to_string(),
        "--receipt-dir".to_string(),
        receipt_dir.display().to_string(),
    ];
    let result = pinned_artifacts_command("check", &profile, &lock, receipt_dir, &args);
    let outcome = OperationOutcome {
        ok: result.is_ok(),
        changed: false,
        skipped: false,
        message: result
            .as_ref()
            .map(|_| "pinned artifacts checked".to_string())
            .unwrap_or_else(|err| err.clone()),
        command: None,
    };
    Ok(ModuleExecution::from_operations(
        vec![("pinned-artifacts-check", outcome)],
        &module.id,
    ))
}
