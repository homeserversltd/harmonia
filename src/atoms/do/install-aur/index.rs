use crate::atoms::attest::install_aur::write as write_install_receipt;
use crate::CmdResult;

pub(crate) fn bounded_timeout(timeout_secs: u64) -> u64 { match timeout_secs { 1..=14400 => timeout_secs, _ => 3600 } }
use crate::atoms::command;
use std::collections::BTreeMap;
use std::path::Path;

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
    write_install_receipt(
        &receipt_dir.join(format!("{receipt_name}.pin-witness.json")),
        &serde_json::json!({
            "schema": "harmonia.package_pin_witness.v1", "target": target,
            "target_pinned": target_pinned, "mutation": mutation,
            "exclusion_set": exclusion_set, "witness": "aur-local-package-install-guard",
            "pin_scope_limitation": crate::atoms::package::PACKAGE_PIN_SCOPE_LIMITATION
        }),
    )
}
