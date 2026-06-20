use crate::module_dispatch::{reject_executable_sidecar, require_path, ModuleExecution};
use crate::*;
use serde_json::json;
use std::fs::{self};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub(crate) const ID: &str = "desktop-config-payload";

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
    Ok(())
}

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<ModuleExecution, String> {
    validate(module)?;
    let source_dir = PathBuf::from(module.source_dir.as_deref().unwrap());
    let target_dir = PathBuf::from(module.target_dir.as_deref().unwrap());
    let verify = verify_payload_manifest(module, receipt_dir, &source_dir)?;
    let install = install_payload_tree(module, receipt_dir, &source_dir, &target_dir, apply)?;
    Ok(ModuleExecution::from_operations(
        vec![("manifest", verify), ("install", install)],
        &module.id,
    ))
}

fn verify_payload_manifest(
    module: &ModuleManifest,
    receipt_dir: &Path,
    source_dir: &Path,
) -> Result<OperationOutcome, String> {
    let missing: Vec<String> = module
        .expected_files
        .iter()
        .filter(|rel| !source_dir.join(rel).is_file())
        .cloned()
        .collect();
    let outcome = OperationOutcome {
        ok: source_dir.is_dir() && missing.is_empty(),
        changed: false,
        skipped: false,
        message: if missing.is_empty() {
            format!(
                "{} files present in {}",
                module.expected_files.len(),
                source_dir.display()
            )
        } else {
            format!("missing TV config files: {}", missing.join(","))
        },
        command: None,
    };
    let receipt = json!({
        "schema": "harmonia.tv.desktop_config_manifest.v1",
        "ok": outcome.ok,
        "module": module.id,
        "source_dir": source_dir,
        "expected_file_count": module.expected_files.len(),
        "missing": missing,
        "first_missing_signal": if outcome.ok { "none" } else { "tv-desktop-config-manifest-incomplete" },
    });
    write_json(
        &receipt_dir.join("tv-desktop-config-manifest.json"),
        &receipt,
    )?;
    Ok(outcome)
}

fn install_payload_tree(
    module: &ModuleManifest,
    receipt_dir: &Path,
    source_dir: &Path,
    target_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    if !apply {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: format!(
                "TV desktop config payload planned from {} to {}",
                source_dir.display(),
                target_dir.display()
            ),
            command: None,
        };
        let receipt = json!({
            "schema": "harmonia.tv.desktop_config_install.v1",
            "ok": true,
            "module": module.id,
            "apply": false,
            "source_dir": source_dir,
            "target_dir": target_dir,
            "planned_file_count": module.expected_files.len(),
            "first_missing_signal": "none",
        });
        write_json(
            &receipt_dir.join("tv-desktop-config-install.json"),
            &receipt,
        )?;
        return Ok(outcome);
    }

    let mut copied = Vec::new();
    let mut changed = false;
    for rel in &module.expected_files {
        let source = source_dir.join(rel);
        let target = target_dir.join(rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("tv-config-dir-create-failed: {e}"))?;
        }
        let data = fs::read(&source)
            .map_err(|e| format!("tv-config-read-failed {}: {e}", source.display()))?;
        let file_changed = fs::read(&target).map(|old| old != data).unwrap_or(true);
        if file_changed {
            fs::write(&target, &data)
                .map_err(|e| format!("tv-config-write-failed {}: {e}", target.display()))?;
            changed = true;
        }
        let mode = fs::metadata(&source)
            .map_err(|e| format!("tv-config-metadata-failed {}: {e}", source.display()))?
            .permissions()
            .mode()
            & 0o777;
        let mut permissions = fs::metadata(&target)
            .map_err(|e| format!("tv-config-target-metadata-failed {}: {e}", target.display()))?
            .permissions();
        permissions.set_mode(mode);
        fs::set_permissions(&target, permissions)
            .map_err(|e| format!("tv-config-permissions-failed {}: {e}", target.display()))?;
        copied.push(rel.clone());
    }
    let outcome = OperationOutcome {
        ok: true,
        changed,
        skipped: false,
        message: format!("installed {} TV config files", copied.len()),
        command: None,
    };
    let receipt = json!({
        "schema": "harmonia.tv.desktop_config_install.v1",
        "ok": true,
        "module": module.id,
        "apply": true,
        "source_dir": source_dir,
        "target_dir": target_dir,
        "file_count": copied.len(),
        "changed": changed,
        "files": copied,
        "first_missing_signal": "none",
    });
    write_json(
        &receipt_dir.join("tv-desktop-config-install.json"),
        &receipt,
    )?;
    Ok(outcome)
}
