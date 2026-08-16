use crate::OperationOutcome;
use crate::tools::aur::{bounded_timeout, current_pkg_tar, first_blocker, installed_version, installed_version_command, install_built_package, meaningful_stderr_tail, write_install_failure, prepare_and_build, prepare_current_build, read_lock, write_build_receipt, installed_version_from_result, AurBuildReceipt, DEFAULT_BUILD_ROOT};
use crate::CmdResult;
use serde_json::Value;
use crate::write_json;
use std::path::{Path, PathBuf};
pub(crate) fn aur_install_action(
    receipt_dir: &Path,
    receipt_name: &str,
    package: &str,
    timeout_secs: u64,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let timeout_secs = bounded_timeout(timeout_secs);
    let build_dir = Path::new(DEFAULT_BUILD_ROOT).join(package);
    let builder = if unsafe { libc::geteuid() } == 0 {
        "nobody"
    } else {
        "current-user"
    };
    let mut receipt = serde_json::json!({
        "schema": "harmonia.aur.install.v1",
        "package": package,
        "build_dir": build_dir,
        "timeout_policy": format!("bounded-timeout-seconds={timeout_secs}"),
        "safety_posture": "current-aur-head;no-pin;no-upstream-check-cycle;unprivileged-makepkg",
        "unprivileged_builder": builder,
        "ok": false,
        "changed": false,
        "installed_converged": false,
        "first_blocker": null,
    });
    if !apply {
        receipt["ok"] = Value::Bool(true);
        receipt["first_blocker"] = Value::String("planned-only".into());
        write_json(&receipt_dir.join(format!("{receipt_name}.json")), &receipt)?;
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: format!("aur install planned {package}"),
            command: None,
        });
    }
    if installed_version(package).is_some() {
        receipt["ok"] = Value::Bool(true);
        receipt["installed_converged"] = Value::Bool(true);
        write_json(&receipt_dir.join(format!("{receipt_name}.json")), &receipt)?;
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: false,
            message: format!("aur install idle {package}"),
            command: None,
        });
    }
    let outcome = prepare_current_build(package, &build_dir, builder, timeout_secs)?;
    if !outcome.0.ok {
        return write_install_failure(receipt_dir, receipt_name, package, receipt, outcome.0);
    }
    let Some(package_path) = outcome.1 else {
        receipt["first_blocker"] = Value::String("aur-produced-package-missing".into());
        write_json(&receipt_dir.join(format!("{receipt_name}.json")), &receipt)?;
        return Ok(OperationOutcome {
            ok: false,
            changed: false,
            skipped: false,
            message: format!("aur install {package}"),
            command: Some(outcome.0),
        });
    };
    let install = install_built_package(&package_path, timeout_secs);
    let verified = installed_version_command(package);
    let ok = install.ok && verified.ok;
    receipt["ok"] = Value::Bool(ok);
    receipt["changed"] = Value::Bool(install.ok);
    receipt["installed_converged"] = Value::Bool(ok);
    if !ok {
        receipt["first_blocker"] = Value::String(first_blocker(if !install.ok {
            &install
        } else {
            &verified
        }));
    }
    write_json(&receipt_dir.join(format!("{receipt_name}.json")), &receipt)?;
    Ok(OperationOutcome {
        ok,
        changed: install.ok,
        skipped: false,
        message: format!("aur install {package}"),
        command: Some(outcome.0),
    })
}
use crate::atoms::r#do::InvocationKey;
use crate::tools::comparison::ActionAuthorization;
pub(crate) fn aur_install(_authorization: ActionAuthorization, _invocation: InvocationKey, callback: impl FnOnce() -> Result<crate::OperationOutcome, String>) -> Result<crate::OperationOutcome, String> { callback() }
