//! Pinned AUR install atom. Installation is gated by a successful pinned-build proof.
use crate::atoms::r#do::InvocationKey;
use crate::tools::aur::{
    first_blocker, install_built_package, installed_version_command, installed_version_from_result,
};
use crate::tools::comparison::ActionAuthorization;
use crate::write_json;
use crate::OperationOutcome;
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub receipt_dir: PathBuf,
    pub receipt_name: String,
    pub build_receipt: PathBuf,
    pub package: String,
    pub expected_version: String,
    pub timeout_secs: u64,
}

pub(crate) fn run(p: &Plan, apply: bool) -> Result<OperationOutcome, String> {
    let mut receipt = serde_json::json!({
        "schema": "harmonia.aur.install_pinned.v1", "package": p.package,
        "expected_version": p.expected_version, "ok": false, "changed": false,
        "first_blocker": null, "build_proof": p.build_receipt,
    });
    let proof: Value = match std::fs::read(&p.build_receipt) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(proof) => proof,
            Err(error) => {
                receipt["first_blocker"] =
                    Value::String(format!("pinned-build-proof-invalid: {error}"));
                write_json(
                    &p.receipt_dir.join(format!("{}.json", p.receipt_name)),
                    &receipt,
                )?;
                return Ok(OperationOutcome {
                    ok: false,
                    changed: false,
                    skipped: false,
                    message: "aur install-pinned refused before successful build proof".into(),
                    command: None,
                });
            }
        },
        Err(error) => {
            receipt["first_blocker"] =
                Value::String(format!("pinned-build-proof-missing: {error}"));
            write_json(
                &p.receipt_dir.join(format!("{}.json", p.receipt_name)),
                &receipt,
            )?;
            return Ok(OperationOutcome {
                ok: false,
                changed: false,
                skipped: false,
                message: "aur install-pinned refused before successful build proof".into(),
                command: None,
            });
        }
    };
    let proof_ok = proof.get("ok").and_then(Value::as_bool) == Some(true)
        && proof.get("schema").and_then(Value::as_str) == Some("harmonia.aur.build_pinned.v1")
        && proof
            .get("produced_package_path")
            .and_then(Value::as_str)
            .is_some()
        && proof
            .get("artifact_sha256")
            .and_then(Value::as_str)
            .is_some();
    if !proof_ok {
        receipt["first_blocker"] = Value::String("pinned-build-proof-not-successful".into());
        write_json(
            &p.receipt_dir.join(format!("{}.json", p.receipt_name)),
            &receipt,
        )?;
        return Ok(OperationOutcome {
            ok: false,
            changed: false,
            skipped: false,
            message: "aur install-pinned refused before successful build proof".into(),
            command: None,
        });
    }
    let package_path = Path::new(proof["produced_package_path"].as_str().unwrap());
    let artifact_bytes =
        std::fs::read(package_path).map_err(|e| format!("pinned-build-artifact-missing: {e}"))?;
    let artifact_sha256 = crate::atoms::file_sha256(&artifact_bytes);
    if proof["artifact_sha256"].as_str() != Some(artifact_sha256.as_str()) {
        receipt["first_blocker"] = Value::String("pinned-build-artifact-hash-mismatch".into());
        write_json(
            &p.receipt_dir.join(format!("{}.json", p.receipt_name)),
            &receipt,
        )?;
        return Ok(OperationOutcome {
            ok: false,
            changed: false,
            skipped: false,
            message: "aur install-pinned refused artifact hash mismatch".into(),
            command: None,
        });
    }
    receipt["artifact_sha256"] = Value::String(artifact_sha256);
    if !apply {
        receipt["ok"] = Value::Bool(true);
        receipt["first_blocker"] = Value::String("planned-only".into());
        write_json(
            &p.receipt_dir.join(format!("{}.json", p.receipt_name)),
            &receipt,
        )?;
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "aur install-pinned planned".into(),
            command: None,
        });
    }
    let install = install_built_package(package_path, p.timeout_secs);
    let verify = installed_version_command(&p.package);
    let version = installed_version_from_result(&verify);
    let ok = install.ok && version.as_deref() == Some(p.expected_version.as_str());
    receipt["ok"] = Value::Bool(ok);
    receipt["changed"] = Value::Bool(install.ok);
    if !ok {
        receipt["first_blocker"] =
            Value::String(first_blocker(if !install.ok { &install } else { &verify }));
    }
    write_json(
        &p.receipt_dir.join(format!("{}.json", p.receipt_name)),
        &receipt,
    )?;
    Ok(OperationOutcome {
        ok,
        changed: install.ok,
        skipped: false,
        message: "aur install-pinned".into(),
        command: Some(install),
    })
}

pub(crate) fn aur_install_pinned(
    _authorization: ActionAuthorization,
    _invocation: InvocationKey,
    callback: impl FnOnce() -> Result<crate::OperationOutcome, String>,
) -> Result<crate::OperationOutcome, String> {
    callback()
}
