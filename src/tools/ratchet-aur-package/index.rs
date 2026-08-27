pub(crate) fn pinned_artifacts_command(
    action: &str,
    profile: &crate::Profile,
    lock_path: &std::path::Path,
    receipt_dir: &std::path::Path,
    args: &[String],
) -> Result<(), String> {
    crate::atoms::r#do::build_aur_pinned::aur_ops::pinned_artifacts_command(
        action,
        profile,
        lock_path,
        receipt_dir,
        args,
    )
}

pub(crate) fn verify_artifact_lock(
    lock_path: &std::path::Path,
    profile: Option<&str>,
    receipt_dir: &std::path::Path,
) -> Result<crate::OperationOutcome, String> {
    crate::atoms::r#do::build_aur_pinned::aur_ops::verify_artifact_lock(
        lock_path,
        profile,
        receipt_dir,
    )
}

pub fn declaration() -> Result<Option<&'static crate::tools::declaration::Declaration>, String> {
    crate::tools::declaration::get("ratchet-aur-package")
}
