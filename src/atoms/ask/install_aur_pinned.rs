//! Typed pinned-artifact observations; this module owns the named Ask facade.
pub(crate) use super::build_aur_pinned::probe::sha256_file;
pub(crate) use super::build_aur_pinned::probe::{
    ArtifactLockObservation, PinnedArtifactsCheckObservation,
};
use std::path::Path;

pub(crate) fn artifact_lock(
    lock_path: &Path,
    profile: Option<&str>,
    receipt_dir: &Path,
    apply: bool,
) -> Result<ArtifactLockObservation, String> {
    super::build_aur_pinned::probe::artifact_lock(lock_path, profile, receipt_dir, apply)
}

pub(crate) fn pinned_artifacts_check(
    profile: &crate::Profile,
    lock_path: &Path,
) -> Result<PinnedArtifactsCheckObservation, String> {
    super::build_aur_pinned::probe::pinned_artifacts_check(profile, lock_path)
}
