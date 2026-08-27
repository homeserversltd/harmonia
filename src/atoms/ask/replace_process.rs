use super::{file_if_present, path_kind, PathKind};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct ObservedIdentity {
    pub requested: PathBuf,
    pub canonical: PathBuf,
    pub kind: PathKind,
    pub dev: u64,
    pub ino: u64,
    pub sha256: Option<String>,
}

pub(crate) fn observe(path: &Path) -> Result<ObservedIdentity, String> {
    let kind = path_kind(path)?.ok_or("replace-process-successor-missing")?;
    let canonical = std::fs::canonicalize(path).map_err(|e| format!("replace-process-successor-canonical: {e}"))?;
    let metadata = std::fs::metadata(&canonical).map_err(|e| format!("replace-process-successor-stat: {e}"))?;
    let sha256 = file_if_present(&canonical)?.map(|file| file.sha256);
    Ok(ObservedIdentity { requested: path.to_path_buf(), canonical, kind, dev: metadata.dev(), ino: metadata.ino(), sha256 })
}
