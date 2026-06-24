use crate::module_dispatch::{reject_executable_sidecar, ModuleExecution};
use crate::*;
use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub(crate) const ID: &str = "homeconsole-update-runtime";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    reject_executable_sidecar(module)?;
    if module.managed_files.is_empty() {
        return Err(format!(
            "module-sidecar-missing-{}-managed_files",
            module.id
        ));
    }
    Ok(())
}

fn managed_files(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let mut missing = Vec::new();
    let mut written = Vec::new();
    let mut changed = false;
    for file in &module.managed_files {
        let path = PathBuf::from(&file.path);
        let existing = fs::read_to_string(&path).ok();
        let content_equal = existing.as_deref() == Some(file.content.as_str());
        if !content_equal {
            if apply {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("homeconsole-update-managed-file-parent-failed: {e}"))?;
                }
                fs::write(&path, file.content.as_bytes())
                    .map_err(|e| format!("homeconsole-update-managed-file-write-failed: {e}"))?;
                fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(file.mode.unwrap_or(0o644)),
                )
                .map_err(|e| format!("homeconsole-update-managed-file-mode-failed: {e}"))?;
                written.push(file.path.clone());
                changed = true;
            } else {
                missing.push(file.path.clone());
            }
        }
    }
    let ok = missing.is_empty() || !apply;
    write_json(
        &receipt_dir.join("homeconsole-update-managed-files.json"),
        &json!({
            "schema": "harmonia.homeconsole.update_runtime.managed_files.v1",
            "ok": ok,
            "module": module.id,
            "missing": missing,
            "written": written,
            "changed": changed,
        }),
    )?;
    Ok(OperationOutcome {
        ok,
        changed,
        skipped: !apply && !missing.is_empty(),
        message: format!("{} managed files checked", module.managed_files.len()),
        command: None,
    })
}

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<ModuleExecution, String> {
    validate(module)?;
    let files = managed_files(module, receipt_dir, apply)?;
    let mut operations = vec![("homeconsole-update-managed-files", files)];

    let alias = migrate_homeconsole_receipt_aliases(receipt_dir, apply)?;
    operations.push(("homeconsole-update-receipt-aliases", alias));

    if apply {
        let dropin_removed = remove_legacy_timer_dropin(receipt_dir)?;
        operations.push(("homeconsole-update-timer-dropin-cleanup", dropin_removed));

        let daemon_reload = command_capture("/usr/bin/systemctl", &["daemon-reload"]);
        write_command_receipt(receipt_dir, "homeconsole-update-daemon-reload", &daemon_reload)?;
        let reload_outcome = OperationOutcome {
            ok: daemon_reload.ok,
            changed: daemon_reload.ok,
            skipped: false,
            message: if daemon_reload.ok {
                "homeconsole update systemd units reloaded".to_string()
            } else {
                "homeconsole update systemd daemon-reload failed".to_string()
            },
            command: Some(daemon_reload.clone()),
        };
        operations.push(("homeconsole-update-daemon-reload", reload_outcome));

        let enable = if daemon_reload.ok {
            command_capture(
                "/usr/bin/systemctl",
                &["enable", "--now", "harmonia-homeconsole.timer"],
            )
        } else {
            CmdResult {
                ok: false,
                code: -1,
                stdout: String::new(),
                stderr: "skipped because daemon-reload failed".to_string(),
            }
        };
        write_command_receipt(receipt_dir, "homeconsole-update-timer-enable", &enable)?;
        let enable_outcome = OperationOutcome {
            ok: enable.ok,
            changed: enable.ok,
            skipped: false,
            message: if enable.ok {
                "harmonia-homeconsole.timer enabled".to_string()
            } else {
                "harmonia-homeconsole.timer enable failed".to_string()
            },
            command: Some(enable),
        };
        let timer_enabled = enable_outcome.ok;
        operations.push(("homeconsole-update-timer-enable", enable_outcome));

        let restart = if timer_enabled {
            command_capture("/usr/bin/systemctl", &["restart", "harmonia-homeconsole.timer"])
        } else {
            CmdResult {
                ok: false,
                code: -1,
                stdout: String::new(),
                stderr: "skipped because timer enable failed".to_string(),
            }
        };
        write_command_receipt(receipt_dir, "homeconsole-update-timer-restart", &restart)?;
        operations.push((
            "homeconsole-update-timer-restart",
            OperationOutcome {
                ok: restart.ok,
                changed: restart.ok,
                skipped: false,
                message: if restart.ok {
                    "harmonia-homeconsole.timer restarted".to_string()
                } else {
                    "harmonia-homeconsole.timer restart failed".to_string()
                },
                command: Some(restart),
            },
        ));
    } else {
        let planned = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "homeconsole update timer enable planned".to_string(),
            command: None,
        };
        operations.push(("homeconsole-update-timer-enable", planned));
    }

    let mut execution = ModuleExecution::from_operations(operations, &module.id);
    if !execution.ok {
        execution.first_missing_signal = Some("homeconsole-update-runtime-failed".to_string());
    }
    write_json(
        &receipt_dir.join("homeconsole-update-runtime.json"),
        &json!({
            "schema": "harmonia.homeconsole.update_runtime.v1",
            "ok": execution.ok,
            "changed": execution.changed,
            "receipt_latest": homeconsole_update_receipt_latest(),
            "timer": "harmonia-homeconsole.timer",
            "service": "harmonia-homeconsole.service",
            "field_runtime_boundary": "harmonia-profile-owned",
            "fulcrum_make_modern_boundary": "attachment-source-only",
        }),
    )?;
    Ok(execution)
}

fn remove_legacy_timer_dropin(receipt_dir: &Path) -> Result<OperationOutcome, String> {
    let dropin = PathBuf::from(
        "/etc/systemd/system/harmonia-homeconsole.timer.d/always-modern.conf",
    );
    let mut changed = false;
    if dropin.exists() {
        fs::remove_file(&dropin).map_err(|e| e.to_string())?;
        changed = true;
        if let Some(parent) = dropin.parent() {
            let _ = fs::remove_dir(parent);
        }
    }
    write_json(
        &receipt_dir.join("homeconsole-update-timer-dropin-cleanup.json"),
        &json!({
            "schema": "harmonia.homeconsole.timer_dropin_cleanup.v1",
            "ok": true,
            "dropin": dropin,
            "removed": changed,
        }),
    )?;
    Ok(OperationOutcome {
        ok: true,
        changed,
        skipped: false,
        message: if changed {
            "removed legacy always-modern timer drop-in".to_string()
        } else {
            "legacy timer drop-in already absent".to_string()
        },
        command: None,
    })
}

fn migrate_homeconsole_receipt_aliases(
    receipt_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let canonical = homeconsole_update_receipt_latest();
    let legacy = homeconsole_update_receipt_legacy();
    let mut changed = false;
    let mut messages = Vec::new();
    if apply {
        let run_id = run_id_from_stamp();
        if canonical.exists() && !canonical.is_symlink() {
            migrate_blocking_receipt_path(&canonical, &run_id)?;
            changed = true;
            messages.push(format!("migrated blocking dir {}", canonical.display()));
        }
        if link_legacy_receipt_alias(&legacy, &canonical)? {
            changed = true;
            messages.push(format!(
                "linked {} -> {}",
                legacy.display(),
                canonical.display()
            ));
        }
    }
    write_json(
        &receipt_dir.join("homeconsole-update-receipt-aliases.json"),
        &json!({
            "schema": "harmonia.homeconsole.receipt_aliases.v1",
            "ok": true,
            "canonical_latest": canonical,
            "legacy_latest": legacy,
            "changed": changed,
            "messages": messages,
        }),
    )?;
    Ok(OperationOutcome {
        ok: true,
        changed,
        skipped: !apply,
        message: if messages.is_empty() {
            "homeconsole receipt aliases already canonical".to_string()
        } else {
            messages.join("; ")
        },
        command: None,
    })
}