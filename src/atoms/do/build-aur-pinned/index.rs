use crate::OperationOutcome;
use crate::atoms::aur::{bounded_timeout, current_pkg_tar, first_blocker, meaningful_stderr_tail, prepare_and_build, prepare_current_build, read_lock, write_build_receipt, AurBuildReceipt, DEFAULT_BUILD_ROOT};
use crate::CmdResult;
use crate::write_json;
use std::path::{Path, PathBuf};
pub(crate) fn aur_build_pinned_action(
    receipt_dir: &Path,
    receipt_name: &str,
    package: &str,
    lock_path: &Path,
    build_root: &Path,
    source_dir: Option<&str>,
    builder_user: Option<&str>,
    timeout_secs: u64,
    _install: bool,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let lock = read_lock(lock_path, package)?;
    let timeout_secs = bounded_timeout(timeout_secs);
    let build_dir = build_root.join(package);
    let safety_posture = "bounded-timeout;no-curl-pipe-bash;no-partial-db-sync;exact-pkgbuild-sha;unprivileged-makepkg";
    let unprivileged_builder = if unsafe { libc::geteuid() } == 0 {
        builder_user.unwrap_or("nobody").to_string()
    } else {
        "current-user".to_string()
    };
    let mut receipt = AurBuildReceipt {
        schema: "harmonia.aur.build_pinned.v1",
        package: package.to_string(),
        pinned_version: lock.pinned_version.clone(),
        pinned_pkgbuild_sha: lock.pkgbuild_sha.clone(),
        build_dir: build_dir.clone(),
        produced_package_path: None,
        artifact_sha256: None,
        installed_version_before: None,
        install_requested: false,
        installed_converged: false,
        first_blocker: None,
        pkgver_neutralized: false,
        timeout_policy: format!("bounded-timeout-seconds={timeout_secs}"),
        safety_posture: safety_posture.into(),
        unprivileged_builder: unprivileged_builder.clone(),
        ok: false,
        changed: false,
        command: None,
        install_command: None,
        install_verify_command: None,
    };

    if !apply {
        receipt.ok = true;
        receipt.first_blocker = Some("planned-only".into());
        write_build_receipt(receipt_dir, receipt_name, &receipt)?;
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: format!("aur build-pinned planned {package}"),
            command: None,
        });
    }

    let result = prepare_and_build(
        &lock,
        package,
        &build_dir,
        source_dir,
        &unprivileged_builder,
        timeout_secs,
    );
    match result {
        Ok((command, package_path, pkgver_neutralized)) => {
            receipt.pkgver_neutralized = pkgver_neutralized;
            receipt.ok = command.ok;
            receipt.changed = command.ok;
            receipt.command = Some(command.clone());
            if command.ok {
                receipt.produced_package_path = package_path.clone();
                receipt.artifact_sha256 = package_path
                    .as_ref()
                    .and_then(|path| std::fs::read(path).ok())
                    .map(|bytes| crate::atoms::file_sha256(&bytes));
            } else {
                receipt.first_blocker = Some(first_blocker(&command));
            }
        }
        Err(err) => {
            receipt.first_blocker = Some(err);
        }
    }
    write_build_receipt(receipt_dir, receipt_name, &receipt)?;
    Ok(OperationOutcome {
        ok: receipt.ok,
        changed: receipt.changed,
        skipped: false,
        message: format!("aur build-pinned {package}"),
        command: receipt.command,
    })
}
use crate::atoms::r#do::InvocationKey;
use crate::atoms::comparison::ActionAuthorization;
pub(crate) fn aur_build_pinned(_authorization: ActionAuthorization, _invocation: InvocationKey, callback: impl FnOnce() -> Result<crate::OperationOutcome, String>) -> Result<crate::OperationOutcome, String> { callback() }
