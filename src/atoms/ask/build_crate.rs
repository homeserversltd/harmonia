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
    pub(crate) artifact_environment_sha: Option<String>,
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
                self.artifact_executable
                    && crate::bands::compare::is_hex_sha(&self.source_build_sha)
                    && self.artifact_build_sha.as_deref() == Some(self.source_build_sha.as_str())
                    && self.artifact_environment_sha.is_some()
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
    installed_build_sha: Option<&str>,
    artifact: &Path,
    identity_mode: IdentityMode,
) -> Result<Observation, String> {
    build_identity_with_environment(
        source_build_sha,
        installed_build_sha,
        artifact,
        identity_mode,
        &[],
    )
}

pub(crate) fn build_identity_with_environment(
    source_build_sha: &str,
    _installed_build_sha: Option<&str>,
    artifact: &Path,
    identity_mode: IdentityMode,
    environment: &[(String, String)],
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
    let artifact_build_sha = match identity_mode {
        IdentityMode::EmbeddedSourceSha => bytes.as_deref().and_then(|bytes| {
            bytes
                .windows(source_build_sha.len())
                .any(|window| window == source_build_sha.as_bytes())
                .then(|| source_build_sha.clone())
        }),
        IdentityMode::RegularExecutable => artifact
            .with_file_name(format!(
                "{}.source-build-sha",
                artifact
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("artifact")
            ))
            .is_file()
            .then(|| {
                artifact.with_file_name(format!(
                    "{}.source-build-sha",
                    artifact
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("artifact")
                ))
            })
            .and_then(|stamp| fs::read_to_string(stamp).ok())
            .map(|stamp| stamp.trim().to_string())
            .filter(|stamp| crate::bands::compare::is_hex_sha(stamp)),
    };
    let artifact_environment_sha = (identity_mode == IdentityMode::RegularExecutable)
        .then(|| {
            artifact.with_file_name(format!(
                "{}.build-environment-sha",
                artifact
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("artifact")
            ))
        })
        .and_then(|stamp| fs::read_to_string(stamp).ok())
        .map(|stamp| stamp.trim().to_string())
        .filter(|stamp| stamp == &environment_sha(environment));
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
        artifact_environment_sha,
        artifact_digest,
        artifact_executable,
        identity_mode,
    })
}

pub(crate) fn environment_sha(environment: &[(String, String)]) -> String {
    let environment = environment
        .iter()
        .cloned()
        .collect::<std::collections::BTreeMap<_, _>>();
    let encoded = serde_json::to_vec(&environment).expect("build environment is serializable");
    atoms::file_sha256(&encoded)
}
