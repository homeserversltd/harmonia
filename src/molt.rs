use crate::*;
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MoltMode {
    Copy,
    Symlink,
}

impl MoltMode {
    pub(crate) fn parse(value: Option<String>) -> Result<Self, String> {
        match value.as_deref().unwrap_or("copy") {
            "copy" => Ok(Self::Copy),
            "symlink" | "link" => Ok(Self::Symlink),
            other => Err(format!("molt-mode-unsupported-{other}")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Copy => "copy",
            Self::Symlink => "symlink",
        }
    }
}

#[derive(Debug, Serialize)]
struct MoltArtifact {
    kind: &'static str,
    source: String,
    output: String,
    mode: &'static str,
}

#[derive(Debug, Serialize)]
struct MoltReceipt {
    schema: &'static str,
    ok: bool,
    profile_id: String,
    identity: String,
    harmonia_root: String,
    output_dir: String,
    mode: &'static str,
    artifacts: Vec<MoltArtifact>,
    untouched_modules: Vec<String>,
    pruned_modules: Vec<String>,
    pruned_paths: Vec<String>,
    subscription_path: String,
    subscription_modules: Vec<SubscriptionModuleStatus>,
    subscription_updated: bool,
    first_missing_signal: &'static str,
}

pub(crate) fn molt(
    harmonia_root: &Path,
    profile_id: &str,
    output_dir: &Path,
    receipt_dir: &Path,
    mode: MoltMode,
) -> Result<(), String> {
    molt_at_subscription_path(
        harmonia_root,
        profile_id,
        output_dir,
        receipt_dir,
        &subscription_path(),
        mode,
    )
}

pub(crate) fn molt_at_subscription_path(
    harmonia_root: &Path,
    profile_id: &str,
    output_dir: &Path,
    receipt_dir: &Path,
    subscription_path: &Path,
    mode: MoltMode,
) -> Result<(), String> {
    validate_harmonia_config_root(harmonia_root)?;
    let profile_path = harmonia_root
        .join("profiles")
        .join(profile_id)
        .join("index.json");
    let profile = load_profile(&profile_path)
        .map_err(|e| format!("molt-profile-read-failed {}: {e}", profile_path.display()))?;
    if profile.id != profile_id {
        return Err(format!(
            "molt-profile-id-mismatch expected={} got={}",
            profile_id, profile.id
        ));
    }

    let subscription_modules = profile
        .modules
        .iter()
        .map(|id| {
            let module_dir = harmonia_root
                .join("profiles")
                .join(&profile.id)
                .join("modules")
                .join(id);
            Ok(SubscriptionModuleUpdate {
                id: id.clone(),
                version: installed_module_version(&module_dir)
                    .unwrap_or_else(|| "sidecar".to_string()),
                tree_sha256: module_tree_sha256(&module_dir)?,
                received_at_run_id: run_id_from_stamp(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let subscription_statuses =
        diff_subscription_modules(&subscription_path, &subscription_modules)?;
    let mut artifacts = Vec::new();
    let mut pruned_paths = Vec::new();
    let mut untouched_modules = Vec::new();
    export_one(
        &profile_path,
        &output_dir
            .join("profiles")
            .join(&profile.id)
            .join("index.json"),
        "profile-index",
        mode,
        &mut artifacts,
    )?;

    let module_root = harmonia_root
        .join("profiles")
        .join(&profile.id)
        .join("modules");
    for module in &profile.modules {
        let module_dir = module_root.join(module);
        let sidecar = module_dir.join("sidecar.json");
        let manifest = module_dir.join("manifest.json");
        let module_output_dir = output_dir
            .join("profiles")
            .join(&profile.id)
            .join("modules")
            .join(module);
        let source_tree_sha256 = module_tree_sha256(&module_dir)?;
        let installed_clean = module_output_dir.is_dir()
            && module_tree_sha256(&module_output_dir)? == source_tree_sha256;
        if installed_clean {
            untouched_modules.push(module.clone());
            continue;
        }
        if manifest.exists() && is_ladder_manifest(&manifest) {
            let ladder = load_ladder_manifest(&manifest)?;
            export_one(
                &manifest,
                &module_output_dir.join("manifest.json"),
                "module-ladder-manifest",
                mode,
                &mut artifacts,
            )?;
            if let Some(files_root) = ladder.files_root.as_deref() {
                export_tree(
                    &module_dir.join(files_root),
                    &module_output_dir.join(files_root),
                    "module-ladder-files-root",
                    mode,
                    &mut artifacts,
                    &mut pruned_paths,
                )?;
            }
            export_module_sibling_files(
                &module_dir,
                &module_output_dir,
                ladder.files_root.as_deref(),
                mode,
                &mut artifacts,
            )?;
        } else if sidecar.exists() {
            load_module(&sidecar)?;
            export_one(
                &sidecar,
                &module_output_dir.join("sidecar.json"),
                "module-sidecar",
                mode,
                &mut artifacts,
            )?;
        } else {
            return Err(format!(
                "molt-module-manifest-missing {}",
                module_dir.display()
            ));
        }
    }

    let lock_path = harmonia_root
        .join("locks")
        .join(&profile.id)
        .join("pinned-artifacts.json");
    if lock_path.exists() {
        export_one(
            &lock_path,
            &output_dir
                .join("locks")
                .join(&profile.id)
                .join("pinned-artifacts.json"),
            "profile-lock",
            mode,
            &mut artifacts,
        )?;
    }

    let output_module_root = output_dir
        .join("profiles")
        .join(&profile.id)
        .join("modules");
    let pruned_modules = prune_retired_module_dirs(&output_module_root, &profile.modules)?;

    let lane = preserve_existing_lane_or_default(&subscription_path);
    update_subscription_record(
        &subscription_path,
        SubscriptionUpdate {
            lane,
            source: format!("molt:{}", harmonia_root.display()),
            ref_name: "molt".to_string(),
            selected_profile: profile.id.clone(),
            engine_version_received: VERSION.to_string(),
            modules: subscription_modules,
        },
    )?;

    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let receipt = MoltReceipt {
        schema: "harmonia.molt.v1",
        ok: true,
        profile_id: profile.id.clone(),
        identity: profile.identity.clone(),
        harmonia_root: harmonia_root.display().to_string(),
        output_dir: output_dir.display().to_string(),
        mode: mode.as_str(),
        artifacts,
        untouched_modules,
        pruned_modules,
        pruned_paths,
        subscription_path: subscription_path.display().to_string(),
        subscription_modules: subscription_statuses,
        subscription_updated: true,
        first_missing_signal: "molt-none",
    };
    let receipt_text = serde_json::to_string_pretty(&receipt).map_err(|e| e.to_string())?;
    fs::write(receipt_dir.join("molt.json"), receipt_text).map_err(|e| e.to_string())?;

    println!("schema=harmonia.molt.v1");
    hyalos::forward_receipt(
        "schema=harmonia.molt.v1",
        &format!("schema=harmonia.molt.v1 ok={}", true),
        Some(serde_json::json!({"schema": "harmonia.molt.v1", "ok": true})),
        Some(true),
    );
    println!("ok=true");
    println!("profile_id={}", profile.id);
    println!("identity={}", profile.identity);
    println!("artifact_count={}", receipt.artifacts.len());
    println!("untouched_modules={}", receipt.untouched_modules.join(","));
    println!("pruned_count={}", receipt.pruned_paths.len());
    println!("pruned_module_count={}", receipt.pruned_modules.len());
    println!("pruned_modules={}", receipt.pruned_modules.join(","));
    println!("output_dir={}", output_dir.display());
    println!("receipt_dir={}", receipt_dir.display());
    println!("subscription_path={}", receipt.subscription_path);
    println!("subscription_updated={}", receipt.subscription_updated);
    println!("first_missing_signal=molt-none");
    Ok(())
}

fn prune_retired_module_dirs(
    output_module_root: &Path,
    declared_modules: &[String],
) -> Result<Vec<String>, String> {
    let root_metadata = match fs::symlink_metadata(output_module_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.to_string()),
    };
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Ok(Vec::new());
    }

    let declared_modules: BTreeSet<&str> = declared_modules.iter().map(String::as_str).collect();
    let mut pruned_modules = Vec::new();
    for entry in fs::read_dir(output_module_root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let file_type = entry.file_type().map_err(|e| e.to_string())?;
        let module_name = entry.file_name().to_string_lossy().into_owned();
        let module_path = entry.path();
        if !file_type.is_dir()
            || file_type.is_symlink()
            || declared_modules.contains(module_name.as_str())
            || !is_staged_module_dir(&module_path)?
        {
            continue;
        }
        fs::remove_dir_all(&module_path).map_err(|e| {
            format!(
                "molt-prune-module-dir-failed {}: {e}",
                module_path.display()
            )
        })?;
        pruned_modules.push(module_name);
    }
    Ok(pruned_modules)
}

fn is_staged_module_dir(path: &Path) -> Result<bool, String> {
    for metadata_path in [path.join("manifest.json"), path.join("sidecar.json")] {
        match fs::symlink_metadata(metadata_path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                return Ok(true)
            }
            Ok(_) | Err(_) => {}
        }
    }
    Ok(false)
}

fn validate_harmonia_config_root(harmonia_root: &Path) -> Result<(), String> {
    if !harmonia_root.join("Cargo.toml").exists() {
        return Err(format!(
            "molt-harmonia-root-rejected missing=Cargo.toml root={}",
            harmonia_root.display()
        ));
    }
    if !harmonia_root.join("src/tools").is_dir() {
        return Err(format!(
            "molt-harmonia-root-rejected missing=src/tools root={}",
            harmonia_root.display()
        ));
    }
    if !harmonia_root.join("profiles").is_dir() {
        return Err(format!(
            "molt-harmonia-root-rejected missing=profiles root={}",
            harmonia_root.display()
        ));
    }
    Ok(())
}

fn export_one(
    source: &Path,
    output: &Path,
    kind: &'static str,
    mode: MoltMode,
    artifacts: &mut Vec<MoltArtifact>,
) -> Result<(), String> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    if output.exists() || output.symlink_metadata().is_ok() {
        let metadata = fs::symlink_metadata(output).map_err(|e| e.to_string())?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            fs::remove_dir_all(output).map_err(|e| e.to_string())?;
        } else {
            fs::remove_file(output).map_err(|e| e.to_string())?;
        }
    }
    match mode {
        MoltMode::Copy => {
            fs::copy(source, output).map_err(|e| {
                format!(
                    "molt-copy-failed {} -> {}: {e}",
                    source.display(),
                    output.display()
                )
            })?;
        }
        MoltMode::Symlink => symlink_file(source, output)?,
    }
    artifacts.push(MoltArtifact {
        kind,
        source: source.display().to_string(),
        output: output.display().to_string(),
        mode: mode.as_str(),
    });
    Ok(())
}

fn export_module_sibling_files(
    module_dir: &Path,
    module_output_dir: &Path,
    files_root: Option<&str>,
    mode: MoltMode,
    artifacts: &mut Vec<MoltArtifact>,
) -> Result<(), String> {
    for entry in fs::read_dir(module_dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name_text = name.to_string_lossy();
        if name_text == "manifest.json" || name_text == "sidecar.json" {
            continue;
        }
        if files_root == Some(name_text.as_ref()) {
            continue;
        }
        let source = entry.path();
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        if kind.is_file() {
            export_one(
                &source,
                &module_output_dir.join(&name),
                "module-ladder-sibling-file",
                mode,
                artifacts,
            )?;
        }
    }
    Ok(())
}

fn export_tree(
    source_root: &Path,
    output_root: &Path,
    kind: &'static str,
    mode: MoltMode,
    artifacts: &mut Vec<MoltArtifact>,
    pruned_paths: &mut Vec<String>,
) -> Result<(), String> {
    if !source_root.is_dir() {
        return Err(format!("molt-files-root-missing {}", source_root.display()));
    }
    prune_deleted_tree_paths(source_root, output_root, pruned_paths)?;
    for entry in fs::read_dir(source_root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let source = entry.path();
        let output = output_root.join(entry.file_name());
        if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            export_tree(&source, &output, kind, mode, artifacts, pruned_paths)?;
        } else {
            export_one(&source, &output, kind, mode, artifacts)?;
        }
    }
    Ok(())
}

fn prune_deleted_tree_paths(
    source_root: &Path,
    output_root: &Path,
    pruned_paths: &mut Vec<String>,
) -> Result<(), String> {
    if !output_root.is_dir() {
        return Ok(());
    }
    let source_files = relative_files(source_root)?;
    let output_files = relative_files(output_root)?;
    for rel in output_files.difference(&source_files) {
        let path = output_root.join(rel);
        fs::remove_file(&path).map_err(|e| format!("molt-prune-failed {}: {e}", path.display()))?;
        pruned_paths.push(path.display().to_string());
    }
    prune_empty_dirs(output_root)?;
    Ok(())
}

fn relative_files(root: &Path) -> Result<BTreeSet<PathBuf>, String> {
    fn collect(root: &Path, current: &Path, files: &mut BTreeSet<PathBuf>) -> Result<(), String> {
        for entry in fs::read_dir(current).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                collect(root, &path, files)?;
            } else {
                files.insert(
                    path.strip_prefix(root)
                        .map_err(|e| e.to_string())?
                        .to_path_buf(),
                );
            }
        }
        Ok(())
    }

    let mut files = BTreeSet::new();
    collect(root, root, &mut files)?;
    Ok(files)
}

fn prune_empty_dirs(root: &Path) -> Result<bool, String> {
    let mut empty = true;
    for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            if prune_empty_dirs(&path)? {
                fs::remove_dir(&path)
                    .map_err(|e| format!("molt-prune-dir-failed {}: {e}", path.display()))?;
            } else {
                empty = false;
            }
        } else {
            empty = false;
        }
    }
    Ok(empty)
}

#[cfg(unix)]
fn symlink_file(source: &Path, output: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(source, output).map_err(|e| {
        format!(
            "molt-symlink-failed {} -> {}: {e}",
            source.display(),
            output.display()
        )
    })
}

#[cfg(not(unix))]
fn symlink_file(_source: &Path, _output: &Path) -> Result<(), String> {
    Err("molt-symlink-unsupported".to_string())
}
