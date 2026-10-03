// Owned ask atom for build-venv
use crate::atoms;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
#[derive(Debug, Clone)]
pub(crate) struct Observation {
    pub(crate) dependency_files: Vec<PathBuf>,
    pub(crate) dependency_sha256: Option<String>,
    pub(crate) previous_dependency_sha256: Option<String>,
}
pub(crate) fn validate_installed_venv(venv: &Path) -> Result<(), String> {
    let invalid_venv = || format!("sbin-venv-absent-or-invalid {}", venv.display());
    let root = std::fs::metadata(venv).map_err(|error| format!("{}: {error}", invalid_venv()))?;
    let python = std::fs::metadata(venv.join("bin/python"))
        .map_err(|error| format!("{}: {error}", invalid_venv()))?;
    let config = std::fs::symlink_metadata(venv.join("pyvenv.cfg"))
        .map_err(|error| format!("{}: {error}", invalid_venv()))?;
    if !root.is_dir() || !python.is_file() || !config.file_type().is_file() {
        return Err(invalid_venv());
    }
    Ok(())
}
impl Observation {
    pub(crate) fn different(&self) -> bool {
        self.dependency_sha256.as_ref() != self.previous_dependency_sha256.as_ref()
    }
}
pub(crate) fn venv(request: &crate::build_venv::Request<'_>) -> Result<Observation, String> {
    validate_installed_venv(request.venv)?;
    let mut files = Vec::new();
    for path in atoms::ask::directory_entries(request.source_root)? {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let selected = (request
            .source_patterns
            .iter()
            .any(|p| p == "requirements*.txt")
            && name.starts_with("requirements")
            && name.ends_with(".txt"))
            || (request
                .source_patterns
                .iter()
                .any(|p| p == "pyproject.toml")
                && name == "pyproject.toml");
        if selected
            && matches!(
                atoms::ask::path_kind(&path)?,
                Some(atoms::ask::PathKind::RegularFile | atoms::ask::PathKind::Symlink)
            )
        {
            files.push(path);
        }
    }
    files.sort();
    let dependency_sha256 = if files.is_empty() {
        None
    } else {
        let mut digest = Sha256::new();
        for path in &files {
            let relative = path
                .strip_prefix(request.source_root)
                .map_err(|e| e.to_string())?;
            digest.update(relative.to_string_lossy().as_bytes());
            digest.update([0]);
            digest.update(Sha256::digest(atoms::ask::file(path)?.bytes));
            digest.update([0]);
        }
        Some(format!("{:x}", digest.finalize()))
    };
    let previous_dependency_sha256 =
        atoms::ask::file_if_present(&crate::build_venv::state_path(request.venv))?.and_then(|v| {
            String::from_utf8(v.bytes)
                .ok()
                .map(|s| s.trim().to_string())
        });
    Ok(Observation {
        dependency_files: files,
        dependency_sha256,
        previous_dependency_sha256,
    })
}
