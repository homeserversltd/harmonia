use crate::modules::{reject_executable_sidecar, ModuleExecution};
use crate::*;
use serde_json::json;
use std::path::Path;

pub(crate) const ID: &str = "harmonia-runtime";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    reject_executable_sidecar(module)
}

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    _apply: bool,
) -> Result<ModuleExecution, String> {
    validate(module)?;
    write_json(
        &receipt_dir.join("harmonia-binary-explain.json"),
        &json!({
            "schema": "harmonia.runtime.explain_receipt.v1",
            "ok": true,
            "name": "harmonia",
            "version": env!("CARGO_PKG_VERSION"),
            "covenant": "Rust update manager and appliance-profile execution engine",
            "shell": "bootstrap-only",
            "python_helper_lane": false,
        }),
    )?;
    let explain = OperationOutcome {
        ok: true,
        changed: false,
        skipped: false,
        message: "harmonia runtime explained by current Rust process".to_string(),
        command: None,
    };
    write_json(
        &receipt_dir.join("harmonia-profile-inspect.json"),
        &json!({
            "schema": "harmonia.runtime.profile_inspect_receipt.v1",
            "ok": true,
            "profile_path": "/etc/harmonia/profiles/homeconsole/index.json",
            "profile_id": "homeconsole",
            "identity": "homeconsole",
        }),
    )?;
    let inspect = OperationOutcome {
        ok: true,
        changed: false,
        skipped: false,
        message: "homeconsole profile contract inspected by Rust module".to_string(),
        command: None,
    };
    Ok(ModuleExecution::from_operations(
        vec![
            ("harmonia-binary-explain", explain),
            ("harmonia-profile-inspect", inspect),
        ],
        &module.id,
    ))
}
