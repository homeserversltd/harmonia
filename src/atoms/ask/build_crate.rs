// Owned ask atom for build-crate
use crate::atoms;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityMode {
    EmbeddedSourceSha,
    RegularExecutable,
}

#[derive(Debug, Clone)]
pub(crate) struct Observation {
    pub(crate) source_build_sha: String,
    pub(crate) artifact_present: bool,
    pub(crate) artifact_build_sha: Option<String>,
    pub(crate) artifact_digest: Option<String>,
    pub(crate) artifact_executable: bool,
    pub(crate) identity_mode: IdentityMode,
}

impl Observation {
    pub(crate) fn identity_matches(&self) -> bool {
        if !self.artifact_present {
            return false;
        }
        match self.identity_mode {
            IdentityMode::EmbeddedSourceSha => {
                !self.source_build_sha.is_empty()
                    && self.artifact_build_sha.as_deref() == Some(self.source_build_sha.as_str())
            }
            IdentityMode::RegularExecutable => {
                self.artifact_executable && self.artifact_digest.is_some()
            }
        }
    }
}

pub(crate) fn build_identity(
    source_build_sha: &str,
    installed_build_sha: Option<&str>,
    artifact: &Path,
) -> Result<Observation, String> {
    build_identity_with_mode(
        source_build_sha,
        installed_build_sha,
        artifact,
        IdentityMode::EmbeddedSourceSha,
    )
}

pub(crate) fn build_identity_with_mode(
    source_build_sha: &str,
    _installed_build_sha: Option<&str>,
    artifact: &Path,
    identity_mode: IdentityMode,
) -> Result<Observation, String> {
    let source_build_sha = source_build_sha.trim().to_string();
    if !crate::bands::compare::is_hex_sha(&source_build_sha) {
        return Err("build-crate-source-build-sha-invalid".into());
    }
    let artifact_present = matches!(
        atoms::ask::path_kind(artifact)?,
        Some(atoms::ask::PathKind::RegularFile)
    );
    let bytes = artifact_present.then(|| fs::read(artifact).ok()).flatten();
    let artifact_build_sha = (identity_mode == IdentityMode::EmbeddedSourceSha)
        .then(|| bytes.as_deref())
        .flatten()
        .and_then(|bytes| {
            bytes
                .windows(source_build_sha.len())
                .any(|window| window == source_build_sha.as_bytes())
                .then(|| source_build_sha.clone())
        });
    let artifact_digest = (identity_mode == IdentityMode::RegularExecutable)
        .then(|| bytes.as_deref())
        .flatten()
        .map(atoms::file_sha256);
    let artifact_executable = artifact_present
        && fs::metadata(artifact)
            .map(|metadata| {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode() & 0o111 != 0
            })
            .unwrap_or(false);
    Ok(Observation {
        source_build_sha,
        artifact_present,
        artifact_build_sha,
        artifact_digest,
        artifact_executable,
        identity_mode,
    })
}
