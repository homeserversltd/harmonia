use crate::*;
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeployableConfigMode {
    Copy,
    Symlink,
}

impl DeployableConfigMode {
    pub(crate) fn parse(value: Option<String>) -> Result<Self, String> {
        match value.as_deref().unwrap_or("copy") {
            "copy" => Ok(Self::Copy),
            "symlink" | "link" => Ok(Self::Symlink),
            other => Err(format!("deployable-config-mode-unsupported-{other}")),
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
struct DeployableConfigArtifact {
    kind: &'static str,
    source: String,
    output: String,
    mode: &'static str,
}

#[derive(Debug, Serialize)]
struct DeployableConfigReceipt {
    schema: &'static str,
    ok: bool,
    profile_id: String,
    identity: String,
    harmonia_root: String,
    output_dir: String,
    mode: &'static str,
    artifacts: Vec<DeployableConfigArtifact>,
    first_missing_signal: &'static str,
}

pub(crate) fn export_deployable_config(
    harmonia_root: &Path,
    profile_id: &str,
    output_dir: &Path,
    receipt_dir: &Path,
    mode: DeployableConfigMode,
) -> Result<(), String> {
    validate_harmonia_config_root(harmonia_root)?;
    let profile_path = harmonia_root
        .join("profiles")
        .join(profile_id)
        .join("index.json");
    let profile = load_profile(&profile_path).map_err(|e| {
        format!(
            "deployable-config-profile-read-failed {}: {e}",
            profile_path.display()
        )
    })?;
    if profile.id != profile_id {
        return Err(format!(
            "deployable-config-profile-id-mismatch expected={} got={}",
            profile_id, profile.id
        ));
    }

    let mut artifacts = Vec::new();
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
                "deployable-config-module-manifest-missing {}",
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

    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let receipt = DeployableConfigReceipt {
        schema: "harmonia.deployable_config_export.v1",
        ok: true,
        profile_id: profile.id.clone(),
        identity: profile.identity.clone(),
        harmonia_root: harmonia_root.display().to_string(),
        output_dir: output_dir.display().to_string(),
        mode: mode.as_str(),
        artifacts,
        first_missing_signal: "none",
    };
    let receipt_text = serde_json::to_string_pretty(&receipt).map_err(|e| e.to_string())?;
    fs::write(
        receipt_dir.join("deployable-config-export.json"),
        receipt_text,
    )
    .map_err(|e| e.to_string())?;

    println!("schema=harmonia.deployable_config_export.v1");
    println!("ok=true");
    println!("profile_id={}", profile.id);
    println!("identity={}", profile.identity);
    println!("artifact_count={}", receipt.artifacts.len());
    println!("output_dir={}", output_dir.display());
    println!("receipt_dir={}", receipt_dir.display());
    println!("first_missing_signal=none");
    Ok(())
}

fn validate_harmonia_config_root(harmonia_root: &Path) -> Result<(), String> {
    if !harmonia_root.join("Cargo.toml").exists() {
        return Err(format!(
            "deployable-config-harmonia-root-rejected missing=Cargo.toml root={}",
            harmonia_root.display()
        ));
    }
    if !harmonia_root.join("src/tools").is_dir() {
        return Err(format!(
            "deployable-config-harmonia-root-rejected missing=src/tools root={}",
            harmonia_root.display()
        ));
    }
    if !harmonia_root.join("profiles").is_dir() {
        return Err(format!(
            "deployable-config-harmonia-root-rejected missing=profiles root={}",
            harmonia_root.display()
        ));
    }
    Ok(())
}

fn export_one(
    source: &Path,
    output: &Path,
    kind: &'static str,
    mode: DeployableConfigMode,
    artifacts: &mut Vec<DeployableConfigArtifact>,
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
        DeployableConfigMode::Copy => {
            fs::copy(source, output).map_err(|e| {
                format!(
                    "deployable-config-copy-failed {} -> {}: {e}",
                    source.display(),
                    output.display()
                )
            })?;
        }
        DeployableConfigMode::Symlink => symlink_file(source, output)?,
    }
    artifacts.push(DeployableConfigArtifact {
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
    mode: DeployableConfigMode,
    artifacts: &mut Vec<DeployableConfigArtifact>,
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
    mode: DeployableConfigMode,
    artifacts: &mut Vec<DeployableConfigArtifact>,
) -> Result<(), String> {
    if !source_root.is_dir() {
        return Err(format!(
            "deployable-config-files-root-missing {}",
            source_root.display()
        ));
    }
    for entry in fs::read_dir(source_root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let source = entry.path();
        let output = output_root.join(entry.file_name());
        if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            export_tree(&source, &output, kind, mode, artifacts)?;
        } else {
            export_one(&source, &output, kind, mode, artifacts)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn symlink_file(source: &Path, output: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(source, output).map_err(|e| {
        format!(
            "deployable-config-symlink-failed {} -> {}: {e}",
            source.display(),
            output.display()
        )
    })
}

#[cfg(not(unix))]
fn symlink_file(_source: &Path, _output: &Path) -> Result<(), String> {
    Err("deployable-config-symlink-unsupported".to_string())
}
