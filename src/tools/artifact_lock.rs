use super::{ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::OperationOutcome;
use std::path::Path;

pub const NAME: &str = "artifact-lock";
pub const DESCRIPTION: &str =
    "Compatibility entry point for artifact integrity observation owned by ratchet-aur-package.";
pub const PERMUTATIONS: &[ToolPermutation] = &[ToolPermutation::new(
    "verify",
    "forward declared artifact lock verification to ratchet-aur-package observe",
    &[
        ToolArg::required("lock", ToolArgKind::String),
        ToolArg::optional("profile", ToolArgKind::String),
    ],
).in_band(crate::tools::Placement::Compare)];
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION, PERMUTATIONS);

pub(crate) fn verify(
    lock_path: &Path,
    profile: Option<&str>,
    receipt_dir: &Path,
) -> Result<OperationOutcome, String> {
    crate::ratchet_aur_package::verify_artifact_lock(lock_path, profile, receipt_dir)
}
