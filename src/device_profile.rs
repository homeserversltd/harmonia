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
}

#[derive(Debug, Deserialize)]
struct DeviceProfileKernel {
    profile: String,
    #[serde(default)]
    engine_component: Option<String>,
}

pub(crate) fn run_identity_source() -> &'static str {
    RUN_IDENTITY_SOURCE.with(Cell::get)
}

fn set_run_identity_source(source: &'static str) {
    RUN_IDENTITY_SOURCE.with(|current| current.set(source));
}

fn emit_fixed_refusal_stdout(receipt: &serde_json::Value) {
    let schema = receipt
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("harmonia.run_profile.v1");
    let ok = receipt.get("ok").and_then(serde_json::Value::as_bool).unwrap_or(false);
    let reason = receipt
        .get("first_missing_signal")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("refused");
    println!("schema={schema}");
    let bounded_schema = crate::hyalos::bounded_json_string(schema, 96);
    let bounded_reason = crate::hyalos::bounded_json_string(reason, 320);
    let mut metadata = json!({
        "schema": bounded_schema,
        "outcome": "refused",
        "ok": ok,
        "first_missing_signal": bounded_reason,
    });
    for field in ["changed", "mutation"] {
        if let Some(value) = receipt.get(field).and_then(serde_json::Value::as_bool) {
            metadata[field] = json!(value);
        }
    }
    for field in ["mode", "profile_id", "identity_source"] {
        if let Some(value) = receipt.get(field).and_then(serde_json::Value::as_str) {
            metadata[field] = json!(crate::hyalos::bounded_json_string(value, 96));
        }
    }
    crate::hyalos::forward_bounded_receipt(
        &bounded_schema,
        &format!("schema={bounded_schema} outcome=refused"),
        Some(metadata),
        Some(ok),
        None,
    );
    println!("ok={ok}");
    if let Some(changed) = receipt.get("changed").and_then(serde_json::Value::as_bool) {
        println!("changed={changed}");
    }
    for field in ["profile_id", "identity", "identity_source"] {
        if let Some(value) = receipt.get(field).and_then(serde_json::Value::as_str) {
            println!("{field}={value}");
        }
    }
    println!("first_missing_signal={reason}");
}

pub(crate) fn persist_fixed_refusal(
    receipt_dir: &Path,
    fallback_stem: &str,
    receipt: &serde_json::Value,
    reason: &str,
    failure_label: &str,
) -> Result<(), String> {
    let write_result = crate::atoms::attest::convergence_receipts::write_fixed_refusal_receipt(
        receipt_dir,
        fallback_stem,
        receipt,
    );
    emit_fixed_refusal_stdout(receipt);
    match write_result {
        Ok(()) => Ok(()),
        Err(error) => {
            eprintln!("{failure_label}: {error}");
            Err(format!("{reason}; {failure_label}: {error}"))
        }
    }
}

pub(crate) fn validate_receipt_retention_or_refuse(
    receipt_dir: &Path,
    fallback_stem: &str,
    apply: bool,
    profile_id: Option<&str>,
    identity_source: &str,
) -> Result<usize, String> {
    match crate::bands::stage_profile::groups::read_device_receipt_retention() {
        Ok(retention) => Ok(retention),
        Err(reason) => {
            let receipt = json!({
                "schema": "harmonia.run_profile.v1", "ok": false, "changed": false,
                "mutation": apply, "mode": "refused", "profile_id": profile_id,
                "identity": serde_json::Value::Null, "identity_source": identity_source,
                "first_missing_signal": reason,
            });
            persist_fixed_refusal(
                receipt_dir,
                fallback_stem,
                &receipt,
                &reason,
                "update-config-refusal-receipt-failed",
            )?;
            Err(reason)
        }
    }
}

fn write_profile_update_refusal(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
    reason: &str,
) -> Result<(), String> {
    let receipt = json!({
        "schema": "harmonia.run_profile.v1", "ok": false, "changed": false,
        "mutation": apply, "mode": "refused", "profile_id": profile.id,
        "identity": profile.identity, "identity_source": run_identity_source(),
        "first_missing_signal": reason,
    });
    persist_fixed_refusal(
        receipt_dir,
        &format!("{}-update", profile.id),
        &receipt,
        reason,
        "update-refusal-receipt-failed",
    )
}

pub(crate) fn validate_update_dispatch(
    args: &[String],
    key: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<(), String> {
    let requested_receipt_dir = receipt_dir_arg(args)
        .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/receipts/update-latest"));
    if let Err(reason) = parse_update_mode(args, key) {
        let receipt = json!({
            "schema": "harmonia.run_profile.v1", "ok": false, "changed": false,
            "mutation": update_apply_requested(args, key), "mode": "refused",
            "profile_id": serde_json::Value::Null, "identity": serde_json::Value::Null,
            "identity_source": "certificate", "first_missing_signal": reason,
        });
        persist_fixed_refusal(
            &requested_receipt_dir,
            "update",
            &receipt,
            &reason,
            "update-refusal-receipt-failed",
        )?;
        return Err(reason);
    }
    Ok(())
}

fn update_apply_requested(args: &[String], key: Option<&crate::atoms::r#do::InvocationKey>) -> bool {
    args.iter().any(|arg| arg == "--apply") || key.is_some()
}

pub(crate) fn device_profile_certificate_path() -> PathBuf {
    #[cfg(any(test, feature = "test-facade"))]
    if let Some(path) = std::env::var_os("HARMONIA_DEVICE_PROFILE_PATH") {
        return PathBuf::from(path);
    }
    PathBuf::from(DEVICE_PROFILE_CERTIFICATE)
}

fn load_certificate_at(path: &Path) -> Result<DeviceProfileCertificate, String> {
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
    Ok(certificate)
}

fn load_certificate() -> Result<DeviceProfileCertificate, String> {
    load_certificate_at(&device_profile_certificate_path())
}

/// Preserve the legacy certificate field as optional compatibility metadata.
/// It is never used to select or gate an engine source.
pub(crate) fn legacy_engine_component_at(path: &Path) -> Result<Option<String>, String> {
    let certificate = load_certificate_at(path)?;
    Ok(certificate.kernel.engine_component)
}

pub(crate) fn certificate_source_policy() -> Result<String, String> {
    let path = device_profile_certificate_path();
    let text = fs::read_to_string(&path).map_err(|err| {
        format!(
            "device-profile-certificate-read-failed {}: {err}",
            path.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|err| format!("device-profile-certificate-parse-failed: {err}"))?;
    Ok(value
        .get("source_policy")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("artifact")
        .to_string())
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
    #[cfg(any(test, feature = "test-facade"))]
    let module_root = std::env::var_os("HARMONIA_MODULE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(HARMONIA_MODULE_ROOT));
    #[cfg(not(any(test, feature = "test-facade")))]
    let module_root = PathBuf::from(HARMONIA_MODULE_ROOT);
    let profile_dir = module_root
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
    profile.syzygy_declaration =
        crate::bands::stage_profile::groups::read_device_syzygy_declaration()?;
    set_run_identity_source("certificate");
    Ok((profile, profile_path))
}

#[cfg(test)]
mod tests {
    use super::{
        is_tv_update_profile, load_certificate_at, DeviceProfileCertificate, Profile,
        DEVICE_PROFILE_SCHEMA,
    };
    use std::fs;

    #[test]
    fn device_profile_tv_dispatches_tv_update() {
        let profile = Profile {
            id: "tv".to_string(),
            identity: "tv".to_string(),
            package_authority: None,
            modules: Vec::new(),
            hotfixes: Vec::new(),
            syzygy_declaration: None,
        };

        assert!(is_tv_update_profile(&profile));
    }

    #[test]
    fn certificate_ignores_foreign_syzygy_field() {
        let file = tempfile::NamedTempFile::new().expect("certificate file");
        fs::write(
            file.path(),
            r#"{
                "schema": "homeserver.device-profile.v1",
                "kernel": {
                    "profile": "homeserver",
                    "engine_component": "harmonia"
                },
                "syzygy": {
                    "schema": "foreign.invalid.syzygy.v99",
                    "gui_face": "not-a-real-face",
                    "credential_path": "/foreign/credential"
                }
            }"#,
        )
        .expect("certificate contents");
        let certificate: DeviceProfileCertificate =
            load_certificate_at(file.path()).expect("foreign syzygy is ignored");

        assert_eq!(certificate.schema, DEVICE_PROFILE_SCHEMA);
        assert_eq!(certificate.kernel.profile, "homeserver");
        assert_eq!(
            certificate.kernel.engine_component.as_deref(),
            Some("harmonia")
        );
    }
}

/// Capability for the software plane only. Its field remains private so only
/// update argument parsing can mint it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SoftwareApplyAuthorization(());

#[derive(Debug)]
pub(crate) enum UpdateMode<'a> {
    Observe,
    ApplySoftware(
        SoftwareApplyAuthorization,
        Option<&'a crate::atoms::r#do::InvocationKey>,
    ),
}

impl<'a> UpdateMode<'a> {
    pub(crate) fn from_apply_flag_with_invocation(
        apply: bool,
        invocation: Option<&'a crate::atoms::r#do::InvocationKey>,
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

    pub(crate) fn invocation(&self) -> Option<&crate::atoms::r#do::InvocationKey> {
        match self {
            Self::Observe => None,
            Self::ApplySoftware(_, key) => *key,
        }
    }

    pub(crate) fn is_software_apply(&self) -> bool {
        self.software_authorization().is_some()
    }
}

fn parse_update_mode<'a>(
    args: &[String],
    invocation: Option<&'a crate::atoms::r#do::InvocationKey>,
) -> Result<UpdateMode<'a>, String> {
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
    let context = invocation.context();
    let refused_run_id = context
        .map(|context| context.run_id.clone())
        .unwrap_or_else(crate::receipts::run_id_from_stamp);
    let _run_id_guard = crate::receipts::RunIdGuard::enter(&refused_run_id);
    let requested_receipt_dir = receipt_dir_arg(args)
        .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/receipts/update-latest"));
    let write_early_refusal = |receipt: serde_json::Value,
                               reason: &str,
                               failure_label: &str,
                               _promote_latest: bool|
     -> Result<(), String> {
        persist_fixed_refusal(
            &requested_receipt_dir,
            "update",
            &receipt,
            reason,
            failure_label,
        )
    };
    let mode = match parse_update_mode(args, invocation.key()) {
        Ok(mode) => mode,
        Err(reason) => {
            write_early_refusal(
                json!({
                    "schema": "harmonia.run_profile.v1",
                    "ok": false,
                    "mutation": false,
                    "mode": "refused",
                    "profile_id": serde_json::Value::Null,
                    "identity": serde_json::Value::Null,
                    "identity_source": "certificate",
                    "first_missing_signal": reason,
                }),
                &reason,
                "update-refusal-receipt-failed",
                true,
            )?;
            return Err(reason);
        }
    };
    let _run_lock = match try_acquire_engine_run_lock() {
        Ok(guard) => guard,
        Err(EngineRunLockFailure::Busy) => {
            let reason = "run-in-progress";
            write_early_refusal(
                json!({
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
                reason,
                "update-refusal-receipt-failed",
                false,
            )?;
            return Err(reason.to_string());
        }
        Err(EngineRunLockFailure::Unavailable(reason)) => {
            write_early_refusal(
                json!({
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
                &reason,
                "update-lock-receipt-failed",
                true,
            )?;
            return Err(reason);
        }
    };
    let receipt_retention = match crate::bands::stage_profile::groups::read_device_receipt_retention() {
        Ok(retention) => retention,
        Err(reason) => {
            write_early_refusal(
                json!({
                    "schema": "harmonia.run_profile.v1", "ok": false, "changed": false,
                    "mutation": mode.is_software_apply(), "mode": "refused",
                    "profile_id": serde_json::Value::Null, "identity": serde_json::Value::Null,
                    "identity_source": "certificate", "first_missing_signal": reason,
                }),
                &reason,
                "update-config-refusal-receipt-failed",
                false,
            )?;
            return Err(reason);
        }
    };
    let certificate_path = device_profile_certificate_path();
    let (profile, profile_path) = match resolve_certificate_profile() {
        Ok(resolved) => resolved,
        Err(reason) => {
            write_early_refusal(
                json!({
                    "schema": "harmonia.run_profile.v1",
                    "ok": false,
                    "mutation": mode.is_software_apply(),
                    "mode": if mode.is_software_apply() { "apply" } else { "report-only" },
                    "profile_id": serde_json::Value::Null,
                    "identity": serde_json::Value::Null,
                    "identity_source": "certificate",
                    "first_missing_signal": reason,
                }),
                &reason,
                "device-profile-refusal-receipt-failed",
                true,
            )?;
            return Err(reason);
        }
    };
    if profile.id == "homeserver" && profile.identity == "homeserver" {
        crate::interactables::homeserver_clock_utc::reconcile_for_update(&profile)?;
    }
    if let Err(reason) = crate::bands::pull_source::validate_declared_sources(&certificate_path) {
        write_early_refusal(
            json!({
                "schema": "harmonia.run_profile.v1",
                "ok": false,
                "mutation": mode.is_software_apply(),
                "mode": if mode.is_software_apply() { "apply" } else { "report-only" },
                "profile_id": profile.id,
                "identity": profile.identity,
                "identity_source": "certificate",
                "source_validation": "blocked-before-module-mutation",
                "first_missing_signal": reason,
            }),
            &reason,
            "source-validation-refusal-receipt-failed",
            true,
        )?;
        return Err(reason);
    }
    let receipt_dir = receipt_dir_arg(args).unwrap_or_else(|| {
        PathBuf::from("/var/lib/harmonia/receipts").join(format!("{}-update-latest", profile.id))
    });
    let module_root = default_module_root(&profile_path);
    let applied = mode.is_software_apply();
    let refusal_stem = crate::atoms::attest::convergence_receipts::latest_receipt_stem(
        &requested_receipt_dir,
        "update",
    );
    let refusal_has_parent = requested_receipt_dir
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty());
    let result = crate::atoms::r#do::transaction::rolling_update_from_certificate_with_context(
        &profile,
        &module_root,
        &receipt_dir,
        mode,
        context,
        receipt_retention,
    );
    if applied && refusal_has_parent && result.is_ok() {
        if let Some(stem) = refusal_stem {
            if let Err(error) = crate::atoms::attest::convergence_receipts::clear_fixed_refusal_after_green(
                &requested_receipt_dir,
                &receipt_dir,
                &stem,
            ) {
                eprintln!("receipt-refusal-clear-warning: {error}");
            }
        }
    }
    result
}

pub(crate) fn homeconsole_update(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode<'_>,
    receipt_retention: usize,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.identity != "homeconsole" {
        let reason = format!(
            "homeconsole-update requires homeconsole/homeconsole profile, got {}/{}",
            profile.id, profile.identity
        );
        write_profile_update_refusal(receipt_dir, profile, mode.is_software_apply(), &reason)?;
        return Err(reason);
    }
    let suite_debt = match enforce_update_suite(profile, module_root) {
        Ok(debt) => debt,
        Err(reason) => {
            write_profile_update_refusal(receipt_dir, profile, mode.is_software_apply(), &reason)?;
            return Err(reason);
        }
    };
    crate::atoms::r#do::transaction::rolling_update_run(
        profile,
        module_root,
        receipt_dir,
        mode,
        None,
        suite_debt,
        receipt_retention,
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
    for module_id in &profile.modules {
        let module_dir = crate::bands::stage_profile::resolve_module_dir(module_root, module_id)?;
        if !lawful_module_manifest_exists(&module_dir) {
            return Ok(Some(format!(
                "profile-module-manifest-missing module_root={} module_id={module_id}",
                module_root.display(),
            )));
        }
    }
    Ok(None)
}

pub(crate) fn homeserver_update(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode<'_>,
    receipt_retention: usize,
) -> Result<(), String> {
    if profile.id != "homeserver" || profile.identity != "homeserver" {
        let reason = format!(
            "homeserver-update requires homeserver/homeserver profile, got {}/{}",
            profile.id, profile.identity
        );
        write_profile_update_refusal(receipt_dir, profile, mode.is_software_apply(), &reason)?;
        return Err(reason);
    }
    let suite_debt = match enforce_update_suite(profile, module_root) {
        Ok(debt) => debt,
        Err(reason) => {
            write_profile_update_refusal(receipt_dir, profile, mode.is_software_apply(), &reason)?;
            return Err(reason);
        }
    };
    crate::atoms::r#do::transaction::rolling_update_run(
        profile,
        module_root,
        receipt_dir,
        mode,
        None,
        suite_debt,
        receipt_retention,
        homeserver_update_lock_path(),
        materialize_homeserver_receipt_dir,
        try_acquire_homeserver_update_lock,
    )
}

pub(crate) fn is_tv_update_profile(profile: &Profile) -> bool {
    profile.id == "tv" && profile.identity == "tv"
}

pub(crate) fn tv_update(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode<'_>,
    receipt_retention: usize,
) -> Result<(), String> {
    if !is_tv_update_profile(profile) {
        let reason = format!(
            "tv-update requires tv/tv profile, got {}/{}",
            profile.id, profile.identity
        );
        write_profile_update_refusal(receipt_dir, profile, mode.is_software_apply(), &reason)?;
        return Err(reason);
    }
    let suite_debt = match enforce_update_suite(profile, module_root) {
        Ok(debt) => debt,
        Err(reason) => {
            write_profile_update_refusal(receipt_dir, profile, mode.is_software_apply(), &reason)?;
            return Err(reason);
        }
    };
    crate::atoms::r#do::transaction::rolling_update_run(
        profile,
        module_root,
        receipt_dir,
        mode,
        None,
        suite_debt,
        receipt_retention,
        tv_update_lock_path(),
        materialize_tv_receipt_dir,
        try_acquire_tv_update_lock,
    )
}
