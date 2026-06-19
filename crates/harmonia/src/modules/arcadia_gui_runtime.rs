use super::{reject_executable_sidecar, require_path, ModuleExecution};
use crate::*;
use std::path::{Path, PathBuf};

pub(crate) const ID: &str = "arcadia-gui-runtime";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    reject_executable_sidecar(module)?;
    require_path(module, &module.repo, "repo")?;
    require_path(module, &module.source_dir, "source_dir")?;
    require_path(module, &module.install_bin, "install_bin")?;
    require_path(module, &module.service, "service")?;
    require_path(module, &module.source_sha_file, "source_sha_file")?;
    Ok(())
}

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<ModuleExecution, String> {
    validate(module)?;
    let profile = Profile {
        id: "homeconsole".to_string(),
        family: "arch-console".to_string(),
        modules: HOMECONSOLE_UPDATE_SUITE_MODULES
            .iter()
            .map(|module| module.to_string())
            .collect(),
    };
    if !apply {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "arcadia GUI runtime planned".to_string(),
            command: None,
        };
        write_tool_receipt(
            receipt_dir,
            "arcadia-gui-update",
            "arcadia-gui-runtime",
            "plan",
            &outcome,
        )?;
        return Ok(ModuleExecution::from_operations(
            vec![("arcadia-gui-update", outcome)],
            &module.id,
        ));
    }
    let result = homeconsole_arcadia_gui_update(
        &profile,
        receipt_dir,
        require_path(module, &module.repo, "repo")?,
        module.branch.as_deref().unwrap_or("main"),
        &PathBuf::from(require_path(module, &module.source_dir, "source_dir")?),
        &PathBuf::from(require_path(module, &module.install_bin, "install_bin")?),
        require_path(module, &module.service, "service")?,
        apply,
        &PathBuf::from(require_path(
            module,
            &module.source_sha_file,
            "source_sha_file",
        )?),
    );
    let outcome = OperationOutcome {
        ok: result.is_ok(),
        changed: apply,
        skipped: false,
        message: result
            .as_ref()
            .map(|_| "arcadia GUI runtime converged".to_string())
            .unwrap_or_else(|err| err.clone()),
        command: None,
    };
    if let Err(err) = result {
        return Ok(ModuleExecution::from_operations(
            vec![("arcadia-gui-update", outcome)],
            &module.id,
        ))
        .and_then(|execution| {
            if execution.ok {
                Ok(execution)
            } else {
                Ok(ModuleExecution {
                    first_missing_signal: Some(err),
                    ..execution
                })
            }
        });
    }
    Ok(ModuleExecution::from_operations(
        vec![("arcadia-gui-update", outcome)],
        &module.id,
    ))
}
