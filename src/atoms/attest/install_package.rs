// Owned attest atom for install-package
use crate::atoms;
use crate::atoms::ask::install_package::PackageObservation;
use crate::atoms::comparison::DiffDecision;
use crate::{OperationOutcome, PackageBackend};
use crate::write_json;
use std::fs;
use std::path::Path;

const NAME: &str = "package";

pub(crate) fn package_receipt_fields(
    observation: &PackageObservation,
    decision: DiffDecision,
    movement: Option<&OperationOutcome>,
    changed: bool,
) -> serde_json::Value {
    let lawful_no_pending = matches!(decision, DiffDecision::Empty)
        && (observation.current.as_ref().is_some_and(|current| current.ok)
            || observation.observed_state == "empty"
            || observation
                .observed_state
                .starts_with("pacman-query-no-pending-exit-"));
    let absent_package = observation
        .desired_state
        .strip_prefix("packages-present:")
        .and_then(|declared| {
            let current = observation.current.as_ref().filter(|current| current.ok)?;
            let installed = current.stdout.lines()
                .filter_map(|line| line.split_whitespace().next())
                .collect::<std::collections::BTreeSet<_>>();
            declared.split(',').find(|package| !package.is_empty() && !installed.contains(package))
        });
    let converged = absent_package.is_none()
        && movement.map_or(lawful_no_pending, |movement| movement.ok);
    let first_missing_signal = if converged {
        "none".to_string()
    } else if let Some(package) = absent_package {
        format!("package-absent:{package}")
    } else if let Some(current) = observation.current.as_ref().filter(|current| !current.ok) {
        format!("pacman-package-probe-failed:code={}", current.code)
    } else if movement.is_some_and(|movement| !movement.ok) {
        "package-operation-failed".to_string()
    } else if observation.current.is_none() {
        "package-probe-unavailable".to_string()
    } else if matches!(decision, DiffDecision::Different) {
        "pending-package-updates-report-only".to_string()
    } else {
        "package-state-not-converged".to_string()
    };
    serde_json::json!({
        "observed_state": observation.observed_state,
        "desired_state": observation.desired_state,
        "diff_decision": match decision { DiffDecision::Empty => "empty", DiffDecision::Different => "different" },
        "movement": movement.map(|movement| serde_json::json!({
            "ok": movement.ok,
            "changed": movement.changed,
            "skipped": movement.skipped,
            "message": movement.message,
            "command": movement.command,
        })),
        "observed_before": serde_json::Value::Null,
        "act": serde_json::Value::Null,
        "observed_after": serde_json::Value::Null,
        "converged": converged,
        "first_missing_signal": first_missing_signal,
        "changed": changed,
    })
}

pub(crate) fn write_install_package_guard_receipt(
    receipt_dir: &Path,
    name: &str,
    before: &PackageObservation,
    movement: &OperationOutcome,
    after: &PackageObservation,
) -> Result<(), String> {
    write_guard_receipts(receipt_dir, name, before, movement, after)
}

pub(crate) fn write_guard_receipts(
    receipt_dir: &Path,
    name: &str,
    before: &PackageObservation,
    movement: &OperationOutcome,
    after: &PackageObservation,
) -> Result<(), String> {
    let after_decision = if after.current.as_ref().is_some_and(|current| current.ok)
        && !package_receipt_fields(after, DiffDecision::Empty, None, false)["first_missing_signal"]
            .as_str()
            .is_some_and(|signal| signal.starts_with("package-absent:"))
    {
        DiffDecision::Empty
    } else {
        DiffDecision::Different
    };
    let mut comparison = package_receipt_fields(
        after,
        after_decision,
        Some(movement),
        movement.changed,
    );
    let fields = comparison
        .as_object_mut()
        .ok_or_else(|| "package-receipt-not-object".to_string())?;
    fields.insert(
        "observed_before".into(),
        serde_json::to_value(before).map_err(|e| e.to_string())?,
    );
    fields.insert("act".into(), serde_json::json!({"ok": movement.ok, "changed": movement.changed, "skipped": movement.skipped, "message": movement.message, "command": movement.command}));
    fields.insert(
        "observed_after".into(),
        serde_json::to_value(after).map_err(|e| e.to_string())?,
    );
    let after_is_converged = after_decision == DiffDecision::Empty && movement.ok;
    fields.insert("converged".into(), serde_json::json!(after_is_converged));
    write_json(
        &receipt_dir.join(format!("{name}.comparison.json")),
        &comparison,
    )?;
    let mut standard = serde_json::json!({"schema":"harmonia.package_tool.v1","name":name,"tool":NAME,"ok":after_is_converged,"changed":movement.changed,"skipped":movement.skipped,"message":movement.message,"command":movement.command});
    if let Some(obj) = standard.as_object_mut() {
        for key in ["observed_state", "desired_state", "diff_decision", "movement", "first_missing_signal", "observed_before", "act", "observed_after", "converged"] {
            obj.insert(key.into(), comparison[key].clone());
        }
    }
    write_json(&receipt_dir.join(format!("{name}.json")), &standard)
}


pub(crate) fn write_package_receipt(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    outcome: &OperationOutcome,
) -> Result<(), String> {
    write_package_receipt_with_backend(receipt_dir, name, action, outcome, PackageBackend::Pacman)
}

pub(crate) fn write_package_receipt_with_backend(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    outcome: &OperationOutcome,
    backend: PackageBackend,
) -> Result<(), String> {
    let comparison = fs::read(receipt_dir.join(format!("{name}.comparison.json")))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    let mut receipt = serde_json::json!({
        "schema": "harmonia.package_tool.v1",
        "name": name,
        "tool": NAME,
        "permutation": action,
        "declared_package_backend": backend.name(),
        "ok": outcome.ok,
        "changed": outcome.changed,
        "skipped": outcome.skipped,
        "message": outcome.message,
        "command": outcome.command,
    });
    if let Some(comparison) = comparison {
        for field in [
            "observed_state",
            "desired_state",
            "diff_decision",
            "movement",
            "observed_before",
            "act",
            "observed_after",
            "converged",
            "first_missing_signal",
            "backend",
            "probe_ok",
            "pending_count",
            "pending",
            "db_synced_at",
            "refresh_command",
            "upgraded_count",
            "upgraded",
            "backend_log_tail",
            "act_refresh_command",
            "release_info_change_accepted",
            "act_release_info_change_accepted",
            "exclusion_set",
            "pin_witness",
        ] {
            if let Some(value) = comparison.get(field) {
                receipt[field] = value.clone();
            }
        }
    }
    write_json(&receipt_dir.join(format!("{}.json", name)), &receipt)
}

pub(crate) fn write_keyring_receipt(
    receipt_dir: &Path,
    name: &str,
    package_name: &str,
    apply: bool,
    pacman_present: bool,
    pacman_key_present: bool,
    operation_count: usize,
    outcome: &OperationOutcome,
) -> Result<(), String> {
    let comparison = fs::read(receipt_dir.join(format!("{name}.comparison.json")))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    let mut receipt = serde_json::json!({
        "schema": "harmonia.package_keyring_repair.v1",
        "name": name,
        "tool": NAME,
        "permutation": "keyring-repair",
        "ok": outcome.ok,
        "changed": outcome.changed,
        "skipped": outcome.skipped,
        "apply": apply,
        "package": package_name,
        "pacman_present": pacman_present,
        "pacman_key_present": pacman_key_present,
        "operation_count": operation_count,
        "first_missing_signal": if !pacman_present {
            "pacman-probe-unavailable"
        } else if !pacman_key_present {
            "pacman-key-probe-unavailable"
        } else if outcome.ok || outcome.skipped {
            "none"
        } else {
            "package-keyring-repair-failed"
        },
    });
    if let Some(comparison) = comparison {
        for field in [
            "observed_state",
            "desired_state",
            "diff_decision",
            "movement",
            "observed_before",
            "act",
            "observed_after",
            "converged",
        ] {
            if let Some(value) = comparison.get(field) {
                receipt[field] = value.clone();
            }
        }
    }
    write_json(&receipt_dir.join(format!("{}.json", name)), &receipt)
}


pub(crate) fn write_guard_receipt(
    receipt_dir: &Path, name: &str, before: &PackageObservation, movement: &OperationOutcome, after: &PackageObservation,
) -> Result<(), String> {
    write_install_package_guard_receipt(receipt_dir, name, before, movement, after)
}

pub(crate) fn write_receipts(
    receipt_dir: &Path, name: &str, observation: &PackageObservation, decision: DiffDecision, movement: Option<&OperationOutcome>, outcome: &OperationOutcome,
) -> Result<(), String> {
    write_json(&receipt_dir.join(format!("{name}.comparison.json")), &package_receipt_fields(observation, decision, movement, outcome.changed))?;
    write_package_receipt(receipt_dir, name, "update-installed-packages", outcome)?;
    attest_step(receipt_dir, name, "update-installed-packages", Ok(outcome))
}

pub(crate) fn attest_step(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    outcome: Result<&OperationOutcome, &str>,
) -> Result<(), String> {
    let comparison = fs::read(receipt_dir.join(format!("{name}.comparison.json")))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .unwrap_or(serde_json::Value::Null);
    let ceiling = fs::read(receipt_dir.join(format!("{name}.ceiling.json")))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .unwrap_or(serde_json::Value::Null);
    let pin_witness = fs::read(receipt_dir.join(format!("{name}.pin-witness.json")))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .unwrap_or(serde_json::Value::Null);
    let (ok, result) = match outcome {
        Ok(outcome) => (outcome.ok, serde_json::json!({"ok":outcome.ok,"changed":outcome.changed,"skipped":outcome.skipped,"message":outcome.message,"command":outcome.command})),
        Err(error) => (false, serde_json::json!({"error":error})),
    };
    let drift = if ok {
        atoms::Drift::Current
    } else {
        atoms::Drift::Command {
            expected_code: 0,
            actual_code: comparison["current"]["code"]
                .as_i64()
                .or_else(|| result["command"]["code"].as_i64())
                .and_then(|code| i32::try_from(code).ok()),
        }
    };
    let message = serde_json::json!({"action":action,"result":result,"comparison":comparison,"ceiling":ceiling,"pin_witness":pin_witness}).to_string();
    atoms::attest::attest(
        &receipt_dir.join(format!("{name}.attest.jsonl")),
        &atoms::Receipt { atom: "install-package".into(), ok, drift, message },
        &[],
    )
}

pub(crate) fn attest(log: &Path, message: &str, ok: bool) -> Result<(), String> {
    atoms::attest::attest(
        log,
        &atoms::Receipt {
            atom: "install-package".into(),
            ok,
            drift: atoms::Drift::Current,
            message: message.into(),
        },
        &[],
    )
}
