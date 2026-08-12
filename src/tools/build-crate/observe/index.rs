use crate::atoms;
use std::path::Path;

#[derive(Debug, Clone)]
pub(super) struct Observation {
    pub(super) source_build_sha: String,
    pub(super) installed_build_sha: Option<String>,
    pub(super) installed_binary_present: bool,
}

impl Observation {
    pub(super) fn identity_matches(&self) -> bool {
        !self.source_build_sha.is_empty()
            && self.installed_binary_present
            && self.installed_build_sha.as_deref() == Some(self.source_build_sha.as_str())
    }
}

pub(super) fn build_identity(
    source_build_sha: &str,
    installed_build_sha: Option<&str>,
    binary: &Path,
) -> Result<Observation, String> {
    let installed_binary_present = matches!(
        atoms::ask::path_kind(binary)?,
        Some(atoms::ask::PathKind::RegularFile)
    );
    Ok(Observation {
        source_build_sha: source_build_sha.trim().to_string(),
        installed_build_sha: installed_build_sha
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        installed_binary_present,
    })
}
