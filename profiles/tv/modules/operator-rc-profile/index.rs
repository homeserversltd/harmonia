#[path = "../tv-runtime-support.rs"]
mod tv_runtime_support;

use crate::*;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use tv_runtime_support::TvModuleSpec;

pub(crate) const ID: &str = "operator-rc-profile";
const OH_MY_POSH_INSTALL_URL: &str = "https://ohmyposh.dev/install.sh";
const OH_MY_POSH_TARGET: &str = "/home/owner/bin/oh-my-posh";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    tv_runtime_support::validate(module)
}

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<ModuleExecution, String> {
    let base = tv_runtime_support::execute(
        module,
        receipt_dir,
        apply,
        TvModuleSpec {
            phase: 4,
            schema: "harmonia.tv.operator_rc_profile.v1",
            meaning: "operator rc files, zsh login shell helpers, Oh My Posh config path, and bin helpers are maintained",
        },
    )?;
    let oh_my_posh = ensure_oh_my_posh(receipt_dir, apply)?;
    Ok(ModuleExecution {
        ok: base.ok && oh_my_posh.ok,
        changed: base.changed || oh_my_posh.changed,
        operation_count: base.operation_count + 1,
        first_missing_signal: base.first_missing_signal.or_else(|| {
            (!oh_my_posh.ok).then(|| "operator-rc-profile-oh-my-posh-install-failed".to_string())
        }),
    })
}

fn ensure_oh_my_posh(receipt_dir: &Path, apply: bool) -> Result<OperationOutcome, String> {
    let target = PathBuf::from(OH_MY_POSH_TARGET);
    let already_present = target.is_file() || command_exists("oh-my-posh");
    if already_present {
        let version = command_capture("oh-my-posh", &["--version"]);
        let ok = target.is_file() || version.ok;
        let outcome = OperationOutcome {
            ok,
            changed: false,
            skipped: false,
            message: "Oh My Posh already installed outside git payload".to_string(),
            command: Some(version),
        };
        write_oh_my_posh_receipt(receipt_dir, apply, &target, &outcome)?;
        return Ok(outcome);
    }
    if !apply {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "Oh My Posh will be installed at deployment time; binary is not vendored"
                .to_string(),
            command: None,
        };
        write_oh_my_posh_receipt(receipt_dir, apply, &target, &outcome)?;
        return Ok(outcome);
    }

    let installer = PathBuf::from("/tmp/harmonia-oh-my-posh-install.sh");
    let curl_args = vec![
        "-fsSL".to_string(),
        OH_MY_POSH_INSTALL_URL.to_string(),
        "-o".to_string(),
        installer.display().to_string(),
    ];
    let download = command_tool(
        receipt_dir,
        "oh-my-posh-installer-download",
        "/usr/bin/curl",
        &curl_args,
        None,
    )?;
    if !download.ok {
        write_oh_my_posh_receipt(receipt_dir, apply, &target, &download)?;
        return Ok(download);
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "oh-my-posh-target-parent-create-failed {}: {e}",
                parent.display()
            )
        })?;
    }
    let bash_args = vec![
        installer.display().to_string(),
        "-d".to_string(),
        target
            .parent()
            .unwrap_or_else(|| Path::new("/home/owner/bin"))
            .display()
            .to_string(),
    ];
    let install = command_tool(
        receipt_dir,
        "oh-my-posh-installer-run",
        "/usr/bin/bash",
        &bash_args,
        None,
    )?;
    let verify = command_capture(OH_MY_POSH_TARGET, &["--version"]);
    write_command_receipt(receipt_dir, "oh-my-posh-version", &verify)?;
    let outcome = OperationOutcome {
        ok: install.ok && verify.ok && target.is_file(),
        changed: install.ok,
        skipped: false,
        message: "Oh My Posh installed at deployment time from upstream installer".to_string(),
        command: Some(verify),
    };
    write_oh_my_posh_receipt(receipt_dir, apply, &target, &outcome)?;
    Ok(outcome)
}

fn command_exists(binary: &str) -> bool {
    command_capture(
        "/usr/bin/env",
        &["sh", "-c", &format!("command -v {binary}")],
    )
    .ok
}

fn write_oh_my_posh_receipt(
    receipt_dir: &Path,
    apply: bool,
    target: &Path,
    outcome: &OperationOutcome,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join("oh-my-posh-runtime-install.json"),
        &json!({
            "schema": "harmonia.tv.oh_my_posh_runtime_install.v1",
            "ok": outcome.ok,
            "apply": apply,
            "install_url": OH_MY_POSH_INSTALL_URL,
            "target": target,
            "binary_vendored_in_git": false,
            "changed": outcome.changed,
            "skipped": outcome.skipped,
            "message": outcome.message,
            "first_missing_signal": if outcome.ok { "none" } else { "oh-my-posh-runtime-install-failed" }
        }),
    )
}
