use crate::OperationOutcome;
use std::path::Path;


pub(crate) fn verify(
    lock_path: &Path,
    profile: Option<&str>,
    receipt_dir: &Path,
) -> Result<OperationOutcome, String> {
    crate::ratchet_aur_package::verify_artifact_lock(lock_path, profile, receipt_dir)
}

pub(crate) fn execute_validated_step(step: &crate::ladder::ValidatedStep, module_dir: &Path) -> Result<OperationOutcome, String> {
    verify(Path::new(step.args.get("lock").and_then(serde_json::Value::as_str).unwrap_or("")), step.args.get("profile").and_then(serde_json::Value::as_str), module_dir)
}
