use super::{reject_executable_sidecar, require_path, ModuleExecution};
use crate::*;
use serde_json::json;
use std::path::{Path, PathBuf};

pub(crate) const ID: &str = "keyman-runtime";

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
    let shape = keyman_source_shape(&source_path);
    let source = OperationOutcome {
        ok: shape.0,
        changed: false,
        skipped: false,
        message: format!(
            "keyman copied payload source shape {}",
            source_path.display()
        ),
        command: None,
    };
    write_tool_receipt(
        receipt_dir,
        "keyman-copied-payload-source",
        "files",
        "validate-source-shape",
        &source,
    )?;
    write_json(
        &receipt_dir.join("keyman-copied-payload-source.json"),
        &json!({
            "schema": "harmonia.keyman_runtime.payload_source.v1",
            "ok": shape.0,
            "path": source_path,
            "source_kind": "copied-exported-payload",
            "shape": shape.1,
            "git_required": false,
        }),
    )?;
    if !shape.0 {
        return Ok(ModuleExecution::from_operations(
            vec![("keyman-copied-payload-source", source)],
            &module.id,
        ));
    }

    let update = if apply {
        command_tool(
            receipt_dir,
            "keyman-runtime-install",
            "/usr/local/bin/harmonia",
            &[
                "homeconsole-keyman-update".to_string(),
                "/etc/harmonia/profiles/homeconsole/index.json".to_string(),
                "--source".to_string(),
                source_path.display().to_string(),
                "--store-dir".to_string(),
                source_path.display().to_string(),
                "--apply".to_string(),
                "--receipt-dir".to_string(),
                "/var/lib/harmonia/receipts/keyman-latest".to_string(),
            ],
            None,
        )?
    } else {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "keyman runtime install planned from copied payload".to_string(),
            command: None,
        };
        write_tool_receipt(
            receipt_dir,
            "keyman-runtime-install",
            "command",
            "run",
            &outcome,
        )?;
        outcome
    };

    Ok(ModuleExecution::from_operations(
        vec![
            ("keyman-copied-payload-source", source),
            ("keyman-runtime-install", update),
        ],
        &module.id,
    ))
}
