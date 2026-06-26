use crate::module_dispatch::{reject_executable_sidecar, require_path, ModuleExecution};
use crate::*;
use serde_json::json;
use std::path::{Path, PathBuf};

pub(crate) const ID: &str = "rebis-waybar-config";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    reject_executable_sidecar(module)?;
    require_path(module, &module.source_dir, "source-dir")?;
    require_path(module, &module.target_dir, "target-dir")?;
    if module.expected_files.is_empty() {
        return Err(format!(
            "module-sidecar-missing-{}-expected-files",
            module.id
        ));
    }
    for rel in &module.expected_files {
        crate::tools::files::validate_relative_path(Path::new(rel))?;
    }
    Ok(())
}

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
    harmonia_root: &Path,
) -> Result<ModuleExecution, String> {
    validate(module)?;
    let source_root =
        resolve_profile_source_dir(module.source_dir.as_deref().unwrap(), harmonia_root);
    let target_root = PathBuf::from(module.target_dir.as_deref().unwrap());
    let files = module
        .expected_files
        .iter()
        .map(|rel| crate::tools::files::FileSpec {
            relative_path: PathBuf::from(rel),
            mode: mode_for(rel),
        })
        .collect();
    let request = crate::tools::files::FileConvergenceRequest {
        source_root: source_root.clone(),
        target_root: target_root.clone(),
        files,
        backup_existing: true,
        receipt_name: "rebis-waybar-config-files".to_string(),
    };
    let files_outcome = crate::tools::files::converge_files(&request, receipt_dir, apply)?;
    let outcome = OperationOutcome {
        ok: files_outcome.ok,
        changed: files_outcome.changed,
        skipped: !apply,
        message: files_outcome.message.clone(),
        command: None,
    };
    write_json(
        &receipt_dir.join("rebis-waybar-config-install.json"),
        &json!({
            "schema": "harmonia.rebis.waybar_config.v1",
            "ok": files_outcome.ok,
            "apply": apply,
            "module": module.id,
            "source_dir": source_root,
            "target_dir": target_root,
            "checked_file_count": files_outcome.checked,
            "written_file_count": files_outcome.written,
            "backed_up_file_count": files_outcome.backed_up,
            "changed": files_outcome.changed,
            "missing": files_outcome.missing,
            "authority": "profiles/rebis/modules/rebis-waybar-config/files/waybar",
            "waybar_contract": {
                "module": "custom/land-guard",
                "exec": "$HOME/bin/rebis status",
                "toggle": "$HOME/bin/rebis toggle",
                "receipt": "$HOME/bin/rebis receipt"
            },
            "first_missing_signal": if files_outcome.ok { "none" } else { "rebis-waybar-config-files-incomplete" },
        }),
    )?;
    Ok(ModuleExecution::from_operations(
        vec![("files", outcome)],
        &module.id,
    ))
}

fn mode_for(relative_path: &str) -> Option<u32> {
    if relative_path.starts_with("bin/") {
        Some(0o755)
    } else {
        Some(0o644)
    }
}

fn resolve_profile_source_dir(source_dir: &str, harmonia_root: &Path) -> PathBuf {
    let candidate = PathBuf::from(source_dir);
    if candidate.is_absolute() {
        candidate
    } else {
        harmonia_root.join(candidate)
    }
}
