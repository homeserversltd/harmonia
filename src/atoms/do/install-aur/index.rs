use crate::atoms::aur::{augment_comparison_receipt, first_blocker, meaningful_stderr_tail, DEFAULT_AUR_BASE_URL, DEFAULT_BUILD_ROOT};
use crate::atoms::r#do::build_aur_pinned::{current_pkg_tar, makepkg_command, prepare_build_dir_for_builder};
use crate::atoms::comparison;
use crate::write_json;
use crate::CmdResult;
use crate::OperationOutcome;

pub(crate) fn bounded_timeout(timeout_secs: u64) -> u64 { match timeout_secs { 1..=14400 => timeout_secs, _ => 3600 } }
use crate::atoms::command;
use std::fs;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
pub(crate) fn aur_install_action(
    receipt_dir: &Path,
    receipt_name: &str,
    package: &str,
    timeout_secs: u64,
    apply: bool,
    pins: &BTreeMap<String, String>,
) -> Result<OperationOutcome, String> {
    let timeout_secs = bounded_timeout(timeout_secs);
    let target_pinned = pins.contains_key(package);
    package_pin_witness(
        receipt_dir,
        receipt_name,
        package,
        pins,
        target_pinned,
        false,
    )?;
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
        "package_pin_exclusion_set": pins.keys().filter(|name| name.as_str() != package).cloned().collect::<Vec<_>>(),
        "package_pin_target_pinned": target_pinned,
    });
    if target_pinned {
        receipt["first_blocker"] = Value::String("profile-pinned-target-witness-only".into());
        receipt["ok"] = Value::Bool(true);
        write_json(&receipt_dir.join(format!("{receipt_name}.json")), &receipt)?;
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: format!("aur install pinned target witnessed {package}"),
            command: None,
        });
    }
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
    let ignored: Vec<String> = pins
        .keys()
        .filter(|name| name.as_str() != package)
        .cloned()
        .collect();
    let install = install_built_package_with_ignores(
        &package_path,
        timeout_secs,
        &ignored,
    );
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
pub(crate) fn install(
    receipt_dir: &Path,
    receipt_name: &str,
    package: &str,
    timeout_secs: u64,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
    pins: &BTreeMap<String, String>,
) -> Result<OperationOutcome, String> {
    let timeout_secs = bounded_timeout(timeout_secs);
    let build_dir = Path::new(DEFAULT_BUILD_ROOT).join(package);
    let builder = if unsafe { libc::geteuid() } == 0 {
        "nobody"
    } else {
        "current-user"
    };
    let run = crate::atoms::r#do::ratchet_aur::compare_install(
        receipt_dir,
        receipt_name,
        package,
        timeout_secs,
        apply,
        invocation,
        pins,
    )?;
    let decision = run.decision();
    let observed = run.observation().clone();
    let movement = match &run {
        comparison::ComparisonRun::Current { .. } => None,
        comparison::ComparisonRun::Moved { movement, .. } => Some(movement),
    };
    let outcome = match movement {
        Some(movement) => movement.clone(),
        None => {
            let receipt = serde_json::json!({
                "schema": "harmonia.aur.install.v1", "package": package, "build_dir": build_dir,
                "timeout_policy": format!("bounded-timeout-seconds={timeout_secs}"),
                "safety_posture": "current-aur-head;no-pin;no-upstream-check-cycle;unprivileged-makepkg",
                "unprivileged_builder": builder, "ok": true, "changed": false,
                "installed_converged": true, "first_blocker": null,
            });
            write_json(&receipt_dir.join(format!("{receipt_name}.json")), &receipt)?;
            OperationOutcome {
                ok: true,
                changed: false,
                skipped: false,
                message: format!("aur install idle {package}"),
                command: None,
            }
        }
    };
    let receipt_path = receipt_dir.join(format!("{receipt_name}.json"));
    augment_comparison_receipt(
        &receipt_path,
        serde_json::json!({"installed_version": observed}),
        serde_json::json!({"package_installed": true}),
        decision,
        movement,
        outcome.changed,
    )?;
    Ok(outcome)
}

use crate::atoms::comparison::ActionAuthorization;
use crate::atoms::r#do::InvocationKey;
pub(crate) fn aur_install(
    _authorization: &ActionAuthorization,
    _invocation: Option<&InvocationKey>,
    callback: impl FnOnce() -> Result<crate::OperationOutcome, String>,
) -> Result<crate::OperationOutcome, String> {
    callback()
}

pub(crate) fn write_install_failure(
    receipt_dir: &Path,
    receipt_name: &str,
    package: &str,
    mut receipt: Value,
    command: CmdResult,
) -> Result<OperationOutcome, String> {
    receipt["first_blocker"] = Value::String(meaningful_stderr_tail(&command));
    write_json(&receipt_dir.join(format!("{receipt_name}.json")), &receipt)?;
    Ok(OperationOutcome {
        ok: false,
        changed: false,
        skipped: false,
        message: format!("aur install {package}"),
        command: Some(command),
    })
}
pub(crate) fn installed_version(package: &str) -> Option<String> {
    installed_version_from_result(&installed_version_command(package))
}

pub(crate) fn installed_version_command(package: &str) -> CmdResult {
    let pacman = crate::atoms::package::pacman_program();
    if !Path::new(&pacman).exists() {
        return CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: format!("pacman-not-found {pacman}"),
        };
    }
    command::capture(&pacman, &["-Q", package])
}

pub(crate) fn installed_version_from_result(result: &CmdResult) -> Option<String> {
    if !result.ok {
        return None;
    }
    let mut fields = result.stdout.split_whitespace();
    let _name = fields.next()?;
    fields.next().map(ToString::to_string)
}

pub(crate) fn install_built_package(path: &Path, timeout_secs: u64) -> CmdResult {
    install_built_package_with_ignores(path, timeout_secs, &[])
}

pub(crate) fn install_built_package_with_ignores(
    path: &Path,
    timeout_secs: u64,
    ignored: &[String],
) -> CmdResult {
    let pacman = crate::atoms::package::pacman_program();
    let path = path.to_string_lossy().to_string();
    let mut args: Vec<String> = vec!["-U".into(), "--noconfirm".into()];
    for package in ignored {
        args.push("--ignore".into());
        args.push(package.clone());
    }
    args.push(path);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    command::capture_with_timeout(&pacman, &refs, timeout_secs)
}

pub(crate) fn package_pin_witness(
    receipt_dir: &Path,
    receipt_name: &str,
    target: &str,
    pins: &BTreeMap<String, String>,
    target_pinned: bool,
    mutation: bool,
) -> Result<(), String> {
    let exclusion_set: Vec<&String> = pins.keys().filter(|name| name.as_str() != target).collect();
    write_json(
        &receipt_dir.join(format!("{receipt_name}.pin-witness.json")),
        &serde_json::json!({
            "schema": "harmonia.package_pin_witness.v1", "target": target,
            "target_pinned": target_pinned, "mutation": mutation,
            "exclusion_set": exclusion_set, "witness": "aur-local-package-install-guard",
            "pin_scope_limitation": crate::atoms::package::PACKAGE_PIN_SCOPE_LIMITATION
        }),
    )
}
pub(crate) fn prepare_current_build(
    package: &str,
    build_dir: &Path,
    builder: &str,
    timeout_secs: u64,
) -> Result<(CmdResult, Option<PathBuf>), String> {
    if build_dir.exists() {
        fs::remove_dir_all(build_dir).map_err(|e| format!("aur-build-dir-clean-failed: {e}"))?;
    }
    fs::create_dir_all(build_dir.parent().unwrap_or_else(|| Path::new(".")))
        .map_err(|e| format!("aur-build-root-create-failed: {e}"))?;
    let target = build_dir.to_string_lossy().to_string();
    let url = format!("{DEFAULT_AUR_BASE_URL}/{package}.git");
    let clone =
        command::capture_with_timeout("/usr/bin/git", &["clone", &url, &target], timeout_secs);
    if !clone.ok {
        return Ok((clone, None));
    }
    prepare_build_dir_for_builder(build_dir, builder)?;
    let makepkg = makepkg_command(builder, timeout_secs, build_dir)?;
    let produced = if makepkg.ok {
        current_pkg_tar(build_dir, package)?
    } else {
        None
    };
    Ok((makepkg, produced))
}
