//! Typed successor pre-image observation for process replacement.
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SuccessorObservation {
    pub successor: PathBuf,
    pub path_kind: Option<String>,
    pub canonical: PathBuf,
    pub regular_file: bool,
    pub sha256: String,
    #[cfg(unix)]
    pub dev: u64,
    #[cfg(unix)]
    pub ino: u64,
}

pub(crate) fn observe(successor: &Path) -> Result<SuccessorObservation, String> {
    let kind = crate::atoms::ask::path_kind(successor)?
        .ok_or_else(|| "replace-process-successor-missing".to_string())?;
    let canonical = std::fs::canonicalize(successor)
        .map_err(|e| format!("replace-process-successor-canonical: {e}"))?;
    let metadata = std::fs::metadata(&canonical)
        .map_err(|e| format!("replace-process-successor-stat: {e}"))?;
    let regular_file = metadata.is_file();
    if !regular_file {
        return Err("replace-process-successor-not-regular-file".into());
    }
    let file = crate::atoms::ask::file_if_present(&canonical)?
        .ok_or_else(|| "replace-process-successor-missing".to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        return Ok(SuccessorObservation {
            successor: successor.to_path_buf(),
            path_kind: Some(format!("{kind:?}")),
            canonical,
            regular_file,
            sha256: file.sha256,
            dev: metadata.dev(),
            ino: metadata.ino(),
        });
    }
    #[cfg(not(unix))]
    Ok(SuccessorObservation {
        successor: successor.to_path_buf(),
        path_kind: Some(format!("{kind:?}")),
        canonical,
        regular_file,
        sha256: file.sha256,
    })
}
