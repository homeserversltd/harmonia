use crate::atoms;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub(super) struct Observation {
    pub(super) source_build_sha: String,
    pub(super) artifact_present: bool,
    pub(super) artifact_build_sha: Option<String>,
}

impl Observation {
    pub(super) fn identity_matches(&self) -> bool {
        !self.source_build_sha.is_empty()
            && self.artifact_present
            && self.artifact_build_sha.as_deref() == Some(self.source_build_sha.as_str())
    }
}

pub(super) fn build_identity(
    source_build_sha: &str,
    _installed_build_sha: Option<&str>,
    artifact: &Path,
) -> Result<Observation, String> {
    let source_build_sha = source_build_sha.trim().to_string();
    if !crate::arcadia_gui_runtime::is_hex_sha(&source_build_sha) {
        return Err("build-crate-source-build-sha-invalid".into());
    }
    let artifact_present = matches!(
        atoms::ask::path_kind(artifact)?,
        Some(atoms::ask::PathKind::RegularFile)
    );
    let artifact_build_sha = artifact_present
        .then(|| fs::read(artifact).ok())
        .flatten()
        .and_then(|bytes| {
            bytes
                .windows(source_build_sha.len())
                .any(|window| window == source_build_sha.as_bytes())
                .then(|| source_build_sha.clone())
        });
    Ok(Observation {
        source_build_sha,
        artifact_present,
        artifact_build_sha,
    })
}
