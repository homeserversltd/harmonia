use crate::module_dispatch::{reject_executable_sidecar, require_path, ModuleExecution};
use crate::tools::files::{converge_files, FileConvergenceRequest, FileSpec};
use crate::*;
use serde_json::json;
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
    let source_dir =
        resolve_profile_source_dir(module.source_dir.as_deref().unwrap(), harmonia_root);
    let target_dir = PathBuf::from(module.target_dir.as_deref().unwrap());
    let verify = verify_payload_manifest(module, receipt_dir, &source_dir)?;
    let install = install_payload_tree(module, receipt_dir, &source_dir, &target_dir, apply)?;
    let refresh = refresh_launcher_cache(receipt_dir, apply)?;
    Ok(ModuleExecution::from_operations(
        vec![("manifest", verify), ("install", install), ("launcher-cache", refresh)],
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
    let request = FileConvergenceRequest {
        source_root: source_dir.to_path_buf(),
        target_root: target_dir.to_path_buf(),
        files: module
            .expected_files
            .iter()
            .map(|rel| FileSpec {
                relative_path: PathBuf::from(rel),
                mode: None,
            })
            .collect(),
        backup_existing: true,
        receipt_name: "tv-desktop-config-files".to_string(),
    };
    let files = converge_files(&request, receipt_dir, apply)?;
    let outcome = OperationOutcome {
        ok: files.ok,
        changed: files.changed,
        skipped: !apply,
        message: if apply {
            format!("converged {} TV config files", files.checked)
        } else {
            format!("planned {} TV config files", files.checked)
        },
        command: None,
    };
    let receipt = json!({
        "schema": "harmonia.tv.desktop_config_install.v1",
        "ok": files.ok,
        "module": module.id,
        "apply": apply,
        "source_dir": source_dir,
        "target_dir": target_dir,
        "planned_file_count": files.checked,
        "written_file_count": files.written,
        "backed_up_file_count": files.backed_up,
        "changed": files.changed,
        "missing": files.missing,
        "generic_convergence_receipt": receipt_dir.join("tv-desktop-config-files.json"),
        "first_missing_signal": if files.ok { "none" } else { "tv-desktop-config-files-incomplete" },
    });
    write_json(
        &receipt_dir.join("tv-desktop-config-install.json"),
        &receipt,
    )?;
    Ok(outcome)
}

fn refresh_launcher_cache(receipt_dir: &Path, apply: bool) -> Result<OperationOutcome, String> {
    if !apply {
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "launcher cache refresh planned for apply".to_string(),
            command: None,
        });
    }
    if !Path::new("/usr/bin/su").exists() {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "su absent on scout host; launcher cache refresh planned only".to_string(),
            command: None,
        };
        write_json(
            &receipt_dir.join("tv-launcher-cache-refresh.json"),
            &json!({
                "schema": "harmonia.tv.launcher_cache_refresh.v1",
                "ok": outcome.ok,
                "apply": apply,
                "skipped": outcome.skipped,
                "message": outcome.message,
                "first_missing_signal": "none",
            }),
        )?;
        return Ok(outcome);
    }
    let result = command_tool(
        receipt_dir,
        "tv-launcher-cache-refresh",
        "/usr/bin/su",
        &[
            "-".to_string(),
            "owner".to_string(),
            "-c".to_string(),
            "sh /home/owner/bin/refresh-launcher-cache.sh".to_string(),
        ],
        None,
    )?;
    write_json(
        &receipt_dir.join("tv-launcher-cache-refresh.json"),
        &json!({
            "schema": "harmonia.tv.launcher_cache_refresh.v1",
            "ok": result.ok,
            "apply": apply,
            "changed": result.ok,
            "message": "refreshed desktop database, ksycoca, and wofi drun cache",
            "first_missing_signal": if result.ok { "none" } else { "tv-launcher-cache-refresh-failed" },
        }),
    )?;
    Ok(OperationOutcome {
        ok: result.ok,
        changed: result.ok,
        skipped: false,
        message: "refreshed desktop database, ksycoca, and wofi drun cache".to_string(),
        command: result.command,
    })
}

fn resolve_profile_source_dir(source_dir: &str, harmonia_root: &Path) -> PathBuf {
    let candidate = PathBuf::from(source_dir);
    if candidate.is_absolute() {
        candidate
    } else {
        harmonia_root.join(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_source_dir_resolves_from_harmonia_root() {
        assert_eq!(
            resolve_profile_source_dir(
                "profiles/tv/config/desktop-config",
                Path::new("/etc/harmonia")
            ),
            PathBuf::from("/etc/harmonia/profiles/tv/config/desktop-config")
        );
    }

    #[test]
    fn absolute_source_dir_remains_absolute() {
        assert_eq!(
            resolve_profile_source_dir("/var/lib/harmonia/config", Path::new("/etc/harmonia")),
            PathBuf::from("/var/lib/harmonia/config")
        );
    }
}
