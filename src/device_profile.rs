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

pub(crate) fn update_from_certificate(args: &[String]) -> Result<(), String> {
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--apply" => index += 1,
            "--receipt-dir" if index + 1 < args.len() => index += 2,
            _ => {
                return Err(
                    "update accepts no profile argument; use --apply and --receipt-dir only"
                        .to_string(),
                )
            }
        }
    }
    let receipt_dir = receipt_dir_arg(args)
        .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/receipts/update-latest"));
    let (profile, profile_path) = match resolve_certificate_profile() {
        Ok(resolved) => resolved,
        Err(reason) => {
            write_json(
                &receipt_dir.join("run.json"),
                &json!({
                    "schema": "harmonia.run_profile.v1",
                    "ok": false,
                    "mutation": args.iter().any(|arg| arg == "--apply"),
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
    let apply = args.iter().any(|arg| arg == "--apply");
    let module_root = default_module_root(&profile_path);
    if profile.id == "homeserver" && profile.identity == "homeserver" {
        homeserver_update(&profile, &module_root, &receipt_dir, apply)
    } else if profile.id == "homeconsole" && profile.identity == "homeconsole" {
        homeconsole_update(&profile, &module_root, &receipt_dir, apply)
    } else if profile.id == "tv" && profile.identity == "arch-tv" {
        tv_update(&profile, &module_root, &receipt_dir, apply)
    } else {
        run_profile_engine(&profile, &module_root, &receipt_dir, apply)
    }
}
