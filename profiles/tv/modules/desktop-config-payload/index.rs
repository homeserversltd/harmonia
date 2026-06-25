use crate::module_dispatch::{reject_executable_sidecar, require_path, ModuleExecution};
use crate::*;
use serde_json::json;
use std::fs;
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
        vec![
            ("manifest", verify),
            ("install", install),
            ("launcher-cache", refresh),
        ],
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
        .filter(|rel| !source_path_for_target(source_dir, rel).is_file())
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
    let mut planned = Vec::new();
    let mut missing = Vec::new();
    let mut written = Vec::new();
    let mut backed_up = Vec::new();
    let mut changed = false;
    for rel in &module.expected_files {
        let source = source_path_for_target(source_dir, rel);
        let target = target_dir.join(rel);
        if !source.is_file() {
            missing.push(rel.clone());
            continue;
        }
        let desired = fs::read(&source).map_err(|e| {
            format!(
                "tv-desktop-config-source-read-failed {}: {e}",
                source.display()
            )
        })?;
        let before = fs::read(&target).ok();
        let file_changed = before.as_deref() != Some(desired.as_slice());
        planned.push(json!({
            "intent": intent_folder_for_target(rel),
            "source": source,
            "target": target,
            "changed": file_changed,
        }));
        if apply && file_changed {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    format!(
                        "tv-desktop-config-target-parent-failed {}: {e}",
                        parent.display()
                    )
                })?;
            }
            if target.exists() {
                let backup = target.with_extension("harmonia-backup");
                fs::copy(&target, &backup).map_err(|e| {
                    format!("tv-desktop-config-backup-failed {}: {e}", target.display())
                })?;
                backed_up.push(backup.display().to_string());
            }
            let tmp = target.with_extension("harmonia-new");
            fs::write(&tmp, &desired)
                .map_err(|e| format!("tv-desktop-config-write-failed {}: {e}", tmp.display()))?;
            fs::rename(&tmp, &target).map_err(|e| {
                format!("tv-desktop-config-promote-failed {}: {e}", target.display())
            })?;
            written.push(rel.clone());
            changed = true;
        }
    }
    let ok = missing.is_empty();
    let checked = module.expected_files.len();
    let outcome = OperationOutcome {
        ok,
        changed,
        skipped: !apply,
        message: if apply {
            format!("converged {checked} TV config files from module intent folders")
        } else {
            format!("planned {checked} TV config files from module intent folders")
        },
        command: None,
    };
    let receipt = json!({
        "schema": "harmonia.tv.desktop_config_install.v1",
        "ok": ok,
        "module": module.id,
        "apply": apply,
        "source_dir": source_dir,
        "target_dir": target_dir,
        "planned_file_count": checked,
        "written_file_count": written.len(),
        "backed_up_file_count": backed_up.len(),
        "changed": changed,
        "missing": missing,
        "planned": planned,
        "written": written,
        "backed_up": backed_up,
        "source_locality": "profiles/tv/modules/desktop-config-payload/files/<intent>",
        "first_missing_signal": if ok { "none" } else { "tv-desktop-config-files-incomplete" },
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

fn source_path_for_target(source_dir: &Path, rel: &str) -> PathBuf {
    source_dir.join(intent_folder_for_target(rel)).join(rel)
}

fn intent_folder_for_target(rel: &str) -> &'static str {
    if rel.starts_with(".config/hypr/") {
        "hyprland"
    } else if rel.starts_with(".config/kitty/") {
        "kitty"
    } else if rel.starts_with(".config/waybar/") {
        "waybar"
    } else if rel.starts_with(".config/wofi/") {
        "wofi"
    } else if rel.starts_with(".config/dunst/") {
        "dunst"
    } else if rel.starts_with(".config/gtk-") {
        "gtk"
    } else if rel.starts_with(".config/kate") || rel.starts_with(".local/share/kate") {
        "kate"
    } else if matches!(
        rel,
        ".config/kdeglobals"
            | ".config/kde-mimeapps.list"
            | ".config/mimeapps.list"
            | ".local/share/applications/mimeapps.list"
            | ".local/share/applications/org.kde.kate.desktop"
    ) {
        "kde-applications"
    } else if rel.starts_with(".config/systemd/user/") {
        "systemd-user"
    } else if rel.starts_with("firefox/") || rel == ".config/chromium-flags.conf" {
        "browser"
    } else if rel.starts_with("bin/") {
        "launcher-bin"
    } else if matches!(
        rel,
        ".aliases"
            | ".functions"
            | ".inputrc"
            | ".nanorc"
            | ".profile"
            | ".zshrc"
            | ".zshrc.arch-install"
    ) {
        "shell-rc"
    } else if rel == "omp.json" {
        "prompt"
    } else if rel.starts_with(".config/xdg-desktop-portal/") {
        "portal"
    } else if matches!(rel, "MANIFEST.captured.txt" | "SANITIZATION.md") {
        "manifest"
    } else {
        "misc"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_source_dir_resolves_from_harmonia_root() {
        assert_eq!(
            resolve_profile_source_dir(
                "profiles/tv/modules/desktop-config-payload/files",
                Path::new("/etc/harmonia")
            ),
            PathBuf::from("/etc/harmonia/profiles/tv/modules/desktop-config-payload/files")
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
