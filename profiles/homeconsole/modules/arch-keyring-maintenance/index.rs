use crate::module_dispatch::{reject_executable_sidecar, ModuleExecution};
use crate::*;
use serde_json::json;
use std::path::Path;

pub(crate) const ID: &str = "arch-keyring-maintenance";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    reject_executable_sidecar(module)?;
    if !module.packages.is_empty()
        && !module
            .packages
            .iter()
            .any(|package| package == "archlinux-keyring")
    {
        return Err("arch-keyring-maintenance-requires-archlinux-keyring-package".to_string());
    }
    Ok(())
}

pub(crate) fn pacman_keyring_refresh_needs_overwrite_retry(outcome: &OperationOutcome) -> bool {
    let Some(result) = outcome.command.as_ref() else {
        return false;
    };
    if result.ok {
        return false;
    }
    let combined = format!("{}\n{}", result.stdout, result.stderr);
    combined.contains("conflicting files") || combined.contains("exists in filesystem")
}

pub(crate) fn refresh_archlinux_keyring(
    receipt_dir: &Path,
    package_name: &str,
) -> Result<OperationOutcome, String> {
    let standard = command_tool(
        receipt_dir,
        "archlinux-keyring-refresh",
        "/usr/bin/pacman",
        &[
            "-Sy".to_string(),
            "--noconfirm".to_string(),
            package_name.to_string(),
        ],
        None,
    )?;
    if standard.ok || !pacman_keyring_refresh_needs_overwrite_retry(&standard) {
        return Ok(standard);
    }
    command_tool(
        receipt_dir,
        "archlinux-keyring-refresh-overwrite",
        "/usr/bin/pacman",
        &[
            "-Sy".to_string(),
            "--noconfirm".to_string(),
            "--overwrite".to_string(),
            "*".to_string(),
            package_name.to_string(),
        ],
        None,
    )
}

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<ModuleExecution, String> {
    validate(module)?;
    let mut operations: Vec<(&'static str, OperationOutcome)> = Vec::new();
    let mut package_name = "archlinux-keyring".to_string();
    if let Some(configured) = module.packages.first() {
        package_name = configured.clone();
    }

    let pacman_present = Path::new("/usr/bin/pacman").exists();
    let pacman_key_present = Path::new("/usr/bin/pacman-key").exists();

    if !pacman_present || !pacman_key_present {
        let outcome = OperationOutcome {
            ok: !apply,
            changed: false,
            skipped: true,
            message: if apply {
                "Arch keyring tools absent for mutation".to_string()
            } else {
                "Arch keyring tools absent on scout host; planned only".to_string()
            },
            command: None,
        };
        write_tool_receipt(
            receipt_dir,
            "arch-keyring-tool-presence",
            "package",
            "keyring-tool-presence",
            &outcome,
        )?;
        write_arch_keyring_receipt(
            module,
            receipt_dir,
            apply,
            &[outcome.clone()],
            pacman_present,
            pacman_key_present,
            &package_name,
        )?;
        operations.push(("tool-presence", outcome));
        return Ok(ModuleExecution::from_operations(operations, &module.id));
    }

    let version = command_tool(
        receipt_dir,
        "pacman-key-version",
        "/usr/bin/pacman-key",
        &["--version".to_string()],
        None,
    )?;
    operations.push(("pacman-key-version", version));

    let keyring_query = command_tool(
        receipt_dir,
        "archlinux-keyring-query",
        "/usr/bin/pacman",
        &["-Q".to_string(), package_name.clone()],
        None,
    )?;
    operations.push(("archlinux-keyring-query", keyring_query));

    if apply {
        let init = command_tool(
            receipt_dir,
            "pacman-key-init",
            "/usr/bin/pacman-key",
            &["--init".to_string()],
            None,
        )?;
        operations.push(("pacman-key-init", init));

        let populate = command_tool(
            receipt_dir,
            "pacman-key-populate",
            "/usr/bin/pacman-key",
            &["--populate".to_string(), "archlinux".to_string()],
            None,
        )?;
        operations.push(("pacman-key-populate", populate));

        let install_keyring = refresh_archlinux_keyring(receipt_dir, &package_name)?;
        operations.push(("archlinux-keyring-refresh", install_keyring));

        let updatedb = command_tool(
            receipt_dir,
            "pacman-key-updatedb",
            "/usr/bin/pacman-key",
            &["--updatedb".to_string()],
            None,
        )?;
        operations.push(("pacman-key-updatedb", updatedb));
    }

    let outcomes: Vec<OperationOutcome> = operations
        .iter()
        .map(|(_, outcome)| outcome.clone())
        .collect();
    write_arch_keyring_receipt(
        module,
        receipt_dir,
        apply,
        &outcomes,
        pacman_present,
        pacman_key_present,
        &package_name,
    )?;
    Ok(ModuleExecution::from_operations(operations, &module.id))
}

fn write_arch_keyring_receipt(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
    outcomes: &[OperationOutcome],
    pacman_present: bool,
    pacman_key_present: bool,
    package_name: &str,
) -> Result<(), String> {
    let ok = outcomes.iter().all(|outcome| outcome.ok);
    let changed = outcomes.iter().any(|outcome| outcome.changed) || apply && ok;
    let first_missing_signal = if ok {
        "none".to_string()
    } else if !pacman_present || !pacman_key_present {
        "arch-keyring-tools-missing".to_string()
    } else {
        outcomes
            .iter()
            .position(|outcome| !outcome.ok)
            .map(|index| format!("arch-keyring-operation-{index}-failed"))
            .unwrap_or_else(|| "arch-keyring-maintenance-failed".to_string())
    };
    write_json(
        &receipt_dir.join("arch-keyring-maintenance.json"),
        &json!({
            "schema": "harmonia.arch_keyring_maintenance.v1",
            "ok": ok,
            "module": module.id,
            "apply": apply,
            "package": package_name,
            "pacman_present": pacman_present,
            "pacman_key_present": pacman_key_present,
            "changed": changed,
            "operation_count": outcomes.len(),
            "first_missing_signal": first_missing_signal,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overwrite_retry_triggers_on_conflicting_files() {
        let outcome = OperationOutcome {
            ok: false,
            changed: false,
            skipped: false,
            message: String::new(),
            command: Some(CmdResult {
                ok: false,
                code: 1,
                stdout: String::new(),
                stderr: "error: failed to commit transaction (conflicting files)\narchlinux-keyring: /usr/share/pacman/keyrings/archlinux.gpg exists in filesystem".to_string(),
            }),
        };
        assert!(pacman_keyring_refresh_needs_overwrite_retry(&outcome));
    }

    #[test]
    fn overwrite_retry_skips_successful_refresh() {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: false,
            message: String::new(),
            command: Some(CmdResult {
                ok: true,
                code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }),
        };
        assert!(!pacman_keyring_refresh_needs_overwrite_retry(&outcome));
    }
}