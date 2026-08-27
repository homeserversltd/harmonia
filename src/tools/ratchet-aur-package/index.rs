pub fn declaration() -> Result<Option<&'static crate::tools::declaration::Declaration>, String> {
    crate::tools::declaration::get("ratchet-aur-package")
}

pub(crate) fn pinned_artifacts_command(
    action: &str, profile: &crate::Profile, lock_path: &std::path::Path,
    receipt_dir: &std::path::Path, args: &[String],
) -> Result<(), String> {
    std::fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    match action {
        "check" => crate::atoms::ask::aur_package::probe::pinned_artifacts_check(profile, lock_path, receipt_dir),
        "nudge" => crate::atoms::r#do::aur_package::pinned_artifacts_nudge(profile, lock_path, receipt_dir, args),
        "bless" => crate::atoms::r#do::aur_package::pinned_artifacts_bless(profile, lock_path, receipt_dir, args),
        other => Err(format!("unsupported pinned-artifacts action {other}")),
    }
}

pub(crate) fn verify_artifact_lock(lock_path: &std::path::Path, profile: Option<&str>, receipt_dir: &std::path::Path) -> Result<crate::OperationOutcome, String> {
    crate::atoms::r#do::aur_package::verify_artifact_lock(lock_path, profile, receipt_dir)
}
