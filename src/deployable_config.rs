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
        let sidecar = module_root.join(module).join("sidecar.json");
        if !sidecar.exists() {
            return Err(format!(
                "deployable-config-module-sidecar-missing {}",
                sidecar.display()
            ));
        }
        load_module(&sidecar)?;
        export_one(
            &sidecar,
            &output_dir
                .join("profiles")
                .join(&profile.id)
                .join("modules")
                .join(module)
                .join("sidecar.json"),
            "module-sidecar",
            mode,
            &mut artifacts,
        )?;
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
