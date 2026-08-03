use crate::*;
use serde::Deserialize;
use serde_json::json;
use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};

const DEVICE_PROFILE_CERTIFICATE: &str = "/etc/profile.json";
const DEVICE_PROFILE_SCHEMA: &str = "homeserver.device-profile.v1";
const HARMONIA_MODULE_ROOT: &str = "/etc/harmonia";

thread_local! {
    static RUN_IDENTITY_SOURCE: Cell<&'static str> = const { Cell::new("asserted-verb") };
}

#[derive(Debug, Deserialize)]
struct DeviceProfileCertificate {
    schema: String,
    kernel: DeviceProfileKernel,
}

#[derive(Debug, Deserialize)]
struct DeviceProfileKernel {
    profile: String,
}

pub(crate) fn run_identity_source() -> &'static str {
    RUN_IDENTITY_SOURCE.with(Cell::get)
}

fn set_run_identity_source(source: &'static str) {
    RUN_IDENTITY_SOURCE.with(|current| current.set(source));
}

fn certificate_profile() -> Result<String, String> {
    let path = Path::new(DEVICE_PROFILE_CERTIFICATE);
    if !path.exists() {
        return Err("device-profile-certificate-missing".to_string());
    }
    let text = fs::read_to_string(path).map_err(|err| {
        format!(
            "device-profile-certificate-read-failed {}: {err}",
            path.display()
        )
    })?;
    let certificate: DeviceProfileCertificate = serde_json::from_str(&text).map_err(|err| {
        format!(
            "device-profile-certificate-parse-failed {}: {err}",
            path.display()
        )
    })?;
    if certificate.schema != DEVICE_PROFILE_SCHEMA {
        return Err(format!(
            "device-profile-certificate-schema-foreign expected={} got={}",
            DEVICE_PROFILE_SCHEMA, certificate.schema
        ));
    }
    let profile = certificate.kernel.profile.trim();
    if profile.is_empty() {
        return Err("device-profile-certificate-profile-empty".to_string());
    }
    if profile.contains('/') || profile.contains('\\') || profile == "." || profile == ".." {
        return Err(format!(
            "device-profile-certificate-profile-invalid profile={profile}"
        ));
    }
    Ok(profile.to_string())
}

pub(crate) fn verify_asserted_profile(asserted_profile: &str) -> Result<(), String> {
    let path = Path::new(DEVICE_PROFILE_CERTIFICATE);
    if !path.exists() {
        set_run_identity_source("asserted-verb");
        return Ok(());
    }
    let certificate_profile = certificate_profile()?;
    if certificate_profile != asserted_profile {
        return Err(format!(
            "device-profile-certificate-profile-mismatch certificate={} asserted={}",
            certificate_profile, asserted_profile
        ));
    }
    set_run_identity_source("certificate");
    Ok(())
}

pub(crate) fn resolve_certificate_profile() -> Result<(Profile, PathBuf), String> {
    let profile_id = certificate_profile()?;
    let profile_dir = Path::new(HARMONIA_MODULE_ROOT)
        .join("profiles")
        .join(&profile_id);
    if !profile_dir.is_dir() {
        return Err(format!(
            "device-profile-profile-directory-absent profile={} path={}",
            profile_id,
            profile_dir.display()
        ));
    }
    let profile_path = profile_dir.join("index.json");
    let profile = load_profile(&profile_path).map_err(|err| {
        format!(
            "device-profile-profile-read-failed {}: {err}",
            profile_path.display()
        )
    })?;
    if profile.id != profile_id {
        return Err(format!(
            "device-profile-certificate-profile-id-mismatch certificate={} profile_file={}",
            profile_id, profile.id
        ));
    }
    set_run_identity_source("certificate");
    Ok((profile, profile_path))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RunMode {
    ReportOnly,
    HardAll,
    HardModule(String),
}

impl RunMode {
    pub(crate) fn is_hard(&self) -> bool {
        !matches!(self, Self::ReportOnly)
    }

    pub(crate) fn hard_selection(&self) -> Option<&str> {
        match self {
            Self::ReportOnly => None,
            Self::HardAll => Some("all"),
            Self::HardModule(module_id) => Some(module_id),
        }
    }
}

fn parse_run_mode(args: &[String]) -> Result<RunMode, String> {
    let mut hard = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--apply" => {
                return Err("legacy --apply refused; use --hard all|<module-id>".to_string())
            }
            "--hard" if index + 1 < args.len() && hard.is_none() => {
                hard = Some(args[index + 1].clone());
                index += 2;
            }
            "--hard" => {
                return Err("update --hard requires exactly one all|<module-id> value".to_string())
            }
            "--receipt-dir" if index + 1 < args.len() => index += 2,
            _ => {
                return Err(
                    "update accepts [--hard all|<module-id>] and --receipt-dir only".to_string(),
                )
            }
        }
    }
    Ok(match hard.as_deref() {
        None => RunMode::ReportOnly,
        Some("all") => RunMode::HardAll,
        Some(module_id) if !module_id.is_empty() && !module_id.starts_with('-') => {
            RunMode::HardModule(module_id.to_string())
        }
        _ => return Err("update --hard requires exactly one all|<module-id> value".to_string()),
    })
}

pub(crate) fn update_from_certificate(args: &[String]) -> Result<(), String> {
    let receipt_dir = receipt_dir_arg(args)
        .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/receipts/update-latest"));
    let mode = match parse_run_mode(args) {
        Ok(mode) => mode,
        Err(reason) => {
            write_json(
                &receipt_dir.join("run.json"),
                &json!({
                    "schema": "harmonia.run_profile.v1",
                    "ok": false,
                    "mutation": false,
                    "mode": "refused",
                    "hard_selection": serde_json::Value::Null,
                    "profile_id": serde_json::Value::Null,
                    "identity": serde_json::Value::Null,
                    "identity_source": "certificate",
                    "first_missing_signal": reason,
                }),
            )
            .map_err(|err| format!("{reason}; update-refusal-receipt-failed: {err}"))?;
            return Err(reason);
        }
    };
    if let Err(reason) = validate_declared_sources(Path::new(DEVICE_PROFILE_CERTIFICATE)) {
        write_json(
            &receipt_dir.join("run.json"),
            &json!({
                "schema": "harmonia.run_profile.v1",
                "ok": false,
                "mutation": mode.is_hard(),
                "mode": if mode.is_hard() { "hard" } else { "report-only" },
                "hard_selection": mode.hard_selection(),
                "profile_id": serde_json::Value::Null,
                "identity": serde_json::Value::Null,
                "identity_source": "certificate",
                "source_validation": "blocked-before-module-mutation",
                "first_missing_signal": reason,
            }),
        )
        .map_err(|err| format!("{reason}; source-validation-refusal-receipt-failed: {err}"))?;
        return Err(reason);
    }
    let (profile, profile_path) = match resolve_certificate_profile() {
        Ok(resolved) => resolved,
        Err(reason) => {
            write_json(
                &receipt_dir.join("run.json"),
                &json!({
                    "schema": "harmonia.run_profile.v1",
                    "ok": false,
                    "mutation": mode.is_hard(),
                "mode": if mode.is_hard() { "hard" } else { "report-only" },
                "hard_selection": mode.hard_selection(),
                    "profile_id": serde_json::Value::Null,
                    "identity": serde_json::Value::Null,
                    "identity_source": "certificate",
                    "first_missing_signal": reason,
                }),
            )
            .map_err(|err| format!("{reason}; device-profile-refusal-receipt-failed: {err}"))?;
            return Err(reason);
        }
    };
    let receipt_dir = receipt_dir_arg(args).unwrap_or_else(|| {
        PathBuf::from("/var/lib/harmonia/receipts").join(format!("{}-update-latest", profile.id))
    });
    let module_root = default_module_root(&profile_path);
    if let Some(selected) = mode
        .hard_selection()
        .filter(|selection| *selection != "all")
    {
        if !profile
            .modules
            .iter()
            .any(|module_id| module_id == selected)
        {
            write_json(
                &receipt_dir.join("run.json"),
                &json!({
                    "schema": "harmonia.run_profile.v1",
                    "ok": false,
                    "mutation": false,
                    "mode": "hard",
                    "hard_selection": selected,
                    "profile_id": profile.id,
                    "identity": profile.identity,
                    "identity_source": run_identity_source(),
                    "first_missing_signal": format!("hard-selection-unselected-{selected}"),
                }),
            )?;
            return Err(format!("hard-selection-unselected-{selected}"));
        }
    }
    run_profile_engine_selected(
        &profile,
        &module_root,
        &receipt_dir,
        mode.is_hard(),
        mode.hard_selection()
            .filter(|selection| *selection != "all"),
    )
}
