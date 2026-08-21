use crate::*;
use serde::Deserialize;
use serde_json::json;
use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};

const DEVICE_PROFILE_CERTIFICATE: &str = "/etc/appliance/profile.json";
const DEVICE_PROFILE_SCHEMA: &str = "homeserver.device-profile.v1";
const HARMONIA_MODULE_ROOT: &str = "/etc/harmonia";

thread_local! {
    static RUN_IDENTITY_SOURCE: Cell<&'static str> = const { Cell::new("asserted-verb") };
}

#[derive(Debug, Deserialize)]
struct DeviceProfileCertificate {
    schema: String,
    kernel: DeviceProfileKernel,
    #[serde(default, alias = "syzygy_declaration")]
    syzygy: Option<crate::SyzygyDeclaration>,
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

pub(crate) fn device_profile_certificate_path() -> PathBuf {
    PathBuf::from(DEVICE_PROFILE_CERTIFICATE)
}

fn load_certificate() -> Result<DeviceProfileCertificate, String> {
    let path = device_profile_certificate_path();
    if !path.exists() {
        return Err("device-profile-certificate-missing".to_string());
    }
    let text = fs::read_to_string(&path).map_err(|err| {
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
    if let Some(declaration) = certificate.syzygy.as_ref() {
        validate_syzygy_declaration(declaration)?;
    }
    Ok(certificate)
}

fn validate_syzygy_declaration(declaration: &crate::SyzygyDeclaration) -> Result<(), String> {
    if declaration.schema != "appliance.syzygy.v1" {
        return Err(format!(
            "device-profile-syzygy-schema-unsupported {}",
            declaration.schema
        ));
    }
    if let Some(face) = declaration.gui_face.as_deref() {
        if !matches!(face, "Hyprland" | "Arcadia" | "Coronatio") {
            return Err(format!("device-profile-syzygy-gui-face-unsupported {face}"));
        }
    }
    Ok(())
}

fn certificate_profile() -> Result<String, String> {
    let certificate = load_certificate()?;
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
    let certificate = load_certificate()?;
    let profile_id = certificate.kernel.profile.trim().to_string();
    if profile_id.is_empty()
        || profile_id.contains('/')
        || profile_id.contains('\\')
        || profile_id == "."
        || profile_id == ".."
    {
        return Err(format!(
            "device-profile-certificate-profile-invalid profile={profile_id}"
        ));
    }
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
    let mut profile = profile;
    if let Some(declaration) = certificate.syzygy {
        validate_syzygy_declaration(&declaration)?;
        profile.syzygy_declaration = Some(declaration);
    }
    set_run_identity_source("certificate");
    Ok((profile, profile_path))
}

/// Capability for the software plane only. Its field remains private so only
/// update argument parsing can mint it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SoftwareApplyAuthorization(());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpdateMode {
    Observe,
    ApplySoftware(
        SoftwareApplyAuthorization,
        Option<crate::atoms::r#do::InvocationKey>,
    ),
}

impl UpdateMode {
    pub(crate) fn from_apply_flag_with_invocation(
        apply: bool,
        invocation: Option<crate::atoms::r#do::InvocationKey>,
    ) -> Self {
        if apply {
            Self::ApplySoftware(SoftwareApplyAuthorization(()), invocation)
        } else {
            Self::Observe
        }
    }

    pub(crate) fn software_authorization(&self) -> Option<&SoftwareApplyAuthorization> {
        match self {
            Self::Observe => None,
            Self::ApplySoftware(authorization, _) => Some(authorization),
        }
    }

    pub(crate) fn invocation(&self) -> Option<crate::atoms::r#do::InvocationKey> {
        match self {
            Self::Observe => None,
            Self::ApplySoftware(_, key) => *key,
        }
    }

    pub(crate) fn is_software_apply(&self) -> bool {
        self.software_authorization().is_some()
    }
}

fn parse_update_mode(
    args: &[String],
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<UpdateMode, String> {
    let mut apply = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--apply" if !apply => {
                apply = true;
                index += 1;
            }
            "--receipt-dir" if index + 1 < args.len() => index += 2,
            _ => return Err("update accepts [--apply] and --receipt-dir only".to_string()),
        }
    }
    Ok(UpdateMode::from_apply_flag_with_invocation(
        apply, invocation,
    ))
}

pub(crate) fn update_from_certificate(
    args: &[String],
    invocation: crate::Invocation,
) -> Result<(), String> {
    let context = invocation.1.clone();
    let receipt_dir = receipt_dir_arg(args)
        .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/receipts/update-latest"));
    let mode = match parse_update_mode(args, invocation.0) {
        Ok(mode) => mode,
        Err(reason) => {
            write_json(
                &receipt_dir.join("run.json"),
                &json!({
                    "schema": "harmonia.run_profile.v1",
                    "ok": false,
                    "mutation": false,
                    "mode": "refused",
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
    let _run_lock = match try_acquire_engine_run_lock() {
        Ok(guard) => guard,
        Err(EngineRunLockFailure::Busy) => {
            let reason = "run-in-progress";
            write_json(
                &receipt_dir.join("run.json"),
                &json!({
                    "schema": "harmonia.run_profile.v1",
                    "ok": false,
                    "mutation": mode.is_software_apply(),
                    "mode": "refused",
                    "profile_id": serde_json::Value::Null,
                    "identity": serde_json::Value::Null,
                    "identity_source": "certificate",
                    "lock_path": engine_run_lock_path(),
                    "first_missing_signal": reason,
                }),
            )
            .map_err(|err| format!("{reason}; update-refusal-receipt-failed: {err}"))?;
            return Err(reason.to_string());
        }
        Err(EngineRunLockFailure::Unavailable(reason)) => {
            write_json(
                &receipt_dir.join("run.json"),
                &json!({
                    "schema": "harmonia.run_profile.v1",
                    "ok": false,
                    "mutation": mode.is_software_apply(),
                    "mode": if mode.is_software_apply() { "apply" } else { "report-only" },
                    "profile_id": serde_json::Value::Null,
                    "identity": serde_json::Value::Null,
                    "identity_source": "certificate",
                    "lock_path": engine_run_lock_path(),
                    "first_missing_signal": reason,
                }),
            )
            .map_err(|err| format!("{reason}; update-lock-receipt-failed: {err}"))?;
            return Err(reason);
        }
    };
    let certificate_path = device_profile_certificate_path();
    if let Err(reason) = crate::bands::pull_source::validate_declared_sources(&certificate_path) {
        write_json(
            &receipt_dir.join("run.json"),
            &json!({
                "schema": "harmonia.run_profile.v1",
                "ok": false,
                "mutation": mode.is_software_apply(),
                "mode": if mode.is_software_apply() { "apply" } else { "report-only" },
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
                    "mutation": mode.is_software_apply(),
                    "mode": if mode.is_software_apply() { "apply" } else { "report-only" },
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
    crate::atoms::r#do::transaction::rolling_update_from_certificate_with_context(
        &profile,
        &module_root,
        &receipt_dir,
        mode,
        context,
    )
}

pub(crate) fn homeconsole_update(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.identity != "homeconsole" {
        return Err(format!(
            "homeconsole-update requires homeconsole/homeconsole profile, got {}/{}",
            profile.id, profile.identity
        ));
    }
    let suite_debt = enforce_update_suite(profile, module_root)?;
    crate::atoms::r#do::transaction::rolling_update_run(
        profile,
        module_root,
        receipt_dir,
        mode,
        None,
        suite_debt,
        homeconsole_update_lock_path(),
        materialize_homeconsole_receipt_dir,
        try_acquire_homeconsole_update_lock,
    )
}

pub(crate) fn lawful_module_manifest_exists(module_dir: &Path) -> bool {
    (module_dir.join("index.rs").exists() && module_dir.join("sidecar.json").exists())
        || module_dir.join("manifest.json").exists()
}

pub(crate) fn enforce_update_suite(
    profile: &Profile,
    module_root: &Path,
) -> Result<Option<String>, String> {
    Ok(profile.modules.iter().find_map(|module_id| {
        (!lawful_module_manifest_exists(&module_root.join(module_id))).then(|| {
            format!(
                "profile-module-manifest-missing module_root={} module_id={module_id}",
                module_root.display(),
            )
        })
    }))
}

pub(crate) fn homeserver_update(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
) -> Result<(), String> {
    if profile.id != "homeserver" || profile.identity != "homeserver" {
        return Err(format!(
            "homeserver-update requires homeserver/homeserver profile, got {}/{}",
            profile.id, profile.identity
        ));
    }
    let suite_debt = enforce_update_suite(profile, module_root)?;
    crate::atoms::r#do::transaction::rolling_update_run(
        profile,
        module_root,
        receipt_dir,
        mode,
        None,
        suite_debt,
        homeserver_update_lock_path(),
        materialize_homeserver_receipt_dir,
        try_acquire_homeserver_update_lock,
    )
}

pub(crate) fn tv_update(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
) -> Result<(), String> {
    if profile.id != "tv" || profile.identity != "arch-tv" {
        return Err(format!(
            "tv-update requires tv/arch-tv profile, got {}/{}",
            profile.id, profile.identity
        ));
    }
    let suite_debt = enforce_update_suite(profile, module_root)?;
    crate::atoms::r#do::transaction::rolling_update_run(
        profile,
        module_root,
        receipt_dir,
        mode,
        None,
        suite_debt,
        tv_update_lock_path(),
        materialize_tv_receipt_dir,
        try_acquire_tv_update_lock,
    )
}
