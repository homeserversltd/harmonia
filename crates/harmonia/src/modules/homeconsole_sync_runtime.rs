use super::{reject_executable_sidecar, require_path, ModuleExecution};
use crate::*;
use serde_json::json;
use std::path::{Path, PathBuf};

pub(crate) const ID: &str = "homeconsole-sync-runtime";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    reject_executable_sidecar(module)?;
    require_path(module, &module.path, "path")?;
    Ok(())
}

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<ModuleExecution, String> {
    validate(module)?;
    let source_path = PathBuf::from(require_path(module, &module.path, "path")?);
    let cli = source_path.join("cli.py");
    let package_dir = source_path.join("homeconsole_sync");
    let shape_ok = source_path.is_dir() && cli.is_file() && package_dir.is_dir();
    let source = OperationOutcome {
        ok: shape_ok,
        changed: false,
        skipped: false,
        message: format!(
            "homeconsole-sync copied payload source shape {}",
            source_path.display()
        ),
        command: None,
    };
    write_tool_receipt(
        receipt_dir,
        "homeconsole-sync-copied-payload-source",
        "files",
        "validate-source-shape",
        &source,
    )?;
    write_json(
        &receipt_dir.join("homeconsole-sync-copied-payload-source.json"),
        &json!({
            "schema": "harmonia.homeconsole_sync_runtime.payload_source.v1",
            "ok": shape_ok,
            "path": source_path,
            "source_kind": "copied-exported-payload",
            "shape": {
                "source_exists": source_path.is_dir(),
                "cli_py_present": cli.is_file(),
                "package_dir_present": package_dir.is_dir()
            },
            "git_required": false,
        }),
    )?;
    if !shape_ok {
        return Ok(ModuleExecution::from_operations(
            vec![("homeconsole-sync-copied-payload-source", source)],
            &module.id,
        ));
    }

    let install = if apply {
        command_tool(
            receipt_dir,
            "homeconsole-sync-install",
            cli.to_string_lossy().as_ref(),
            &["install".to_string(), "--apply".to_string()],
            Some(source_path.to_string_lossy().as_ref()),
        )?
    } else {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "homeconsole-sync install planned from copied payload".to_string(),
            command: None,
        };
        write_tool_receipt(
            receipt_dir,
            "homeconsole-sync-install",
            "command",
            "run",
            &outcome,
        )?;
        outcome
    };
    Ok(ModuleExecution::from_operations(
        vec![
            ("homeconsole-sync-copied-payload-source", source),
            ("homeconsole-sync-install", install),
        ],
        &module.id,
    ))
}
