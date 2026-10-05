use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

const INSTALL_MODE: u32 = 0o755;
const INSTALL_UID: u32 = 0;
const INSTALL_GID: u32 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
struct InstalledObservation {
    sha256: Option<String>,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
}

impl InstalledObservation {
    fn current(&self, wanted_sha256: &str) -> bool {
        self.sha256.as_deref() == Some(wanted_sha256)
            && self.mode == Some(INSTALL_MODE)
            && self.uid == Some(INSTALL_UID)
            && self.gid == Some(INSTALL_GID)
    }

    fn receipt_value(&self) -> Value {
        json!({
            "sha256": self.sha256,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
        })
    }
}

fn required_string<'a>(args: &'a BTreeMap<String, Value>, name: &str) -> Result<&'a str, String> {
    args.get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("release-binary-missing-{name}"))
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn safe_asset(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn clean_absolute_path(path: &Path) -> bool {
    path.to_str().is_some_and(|raw| {
        raw.starts_with('/')
            && raw != "/"
            && raw
                .split('/')
                .skip(1)
                .all(|part| !part.is_empty() && part != "." && part != "..")
    })
}

fn validate_destination_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() || !clean_absolute_path(path) {
        return Err("release-binary-path-must-be-clean-absolute-path".into());
    }
    if path.file_name().filter(|name| !name.is_empty()).is_none() {
        return Err("release-binary-path-file-name-missing".into());
    }
    Ok(())
}

fn vault_is_mounted() -> Result<bool, String> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("release-binary-vault-mount-observation-failed: {error}"))?;
    Ok(mountinfo
        .lines()
        .any(|line| line.split_whitespace().nth(4) == Some("/vault")))
}

fn proven_candidate_exhaustion(candidates: &[Value]) -> bool {
    !candidates.is_empty()
        && candidates.iter().enumerate().all(|(index, candidate)| {
            let attempt = candidate.get("attempt");
            let final_state = candidate.get("final-state");
            let attempt_state = attempt
                .and_then(|value| value.get("state"))
                .and_then(Value::as_str);
            let disposition = final_state
                .and_then(|value| value.get("disposition"))
                .and_then(Value::as_str);
            candidate.get("candidate_index").and_then(Value::as_u64) == Some((index + 1) as u64)
                && candidate
                    .get("observed")
                    .and_then(|value| value.get("configured"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && candidate.get("could-change").and_then(Value::as_bool) == Some(false)
                && attempt
                    .and_then(|value| value.get("operation"))
                    .and_then(Value::as_str)
                    == Some("inspect-flag-and-digest-verified-binary")
                && final_state
                    .and_then(|value| value.get("selected"))
                    .and_then(Value::as_bool)
                    == Some(false)
                && final_state
                    .and_then(|value| value.get("blocker"))
                    .and_then(Value::as_str)
                    .is_some_and(|blocker| !blocker.trim().is_empty())
                && matches!(
                    (attempt_state, disposition),
                    (Some("candidate-refused"), Some("refused"))
                        | (Some("completed"), Some("unavailable"))
                )
        })
}

fn stable_installed_observation(path: &Path) -> Result<InstalledObservation, String> {
    let first = inspect_installed(path)?;
    let second = inspect_installed(path)?;
    if first != second {
        return Err("release-binary-standing-target-observation-unstable".into());
    }
    Ok(second)
}

fn standing_receipt(path: &Path, observation: &InstalledObservation) -> Value {
    let present = observation.sha256.is_some();
    json!({
        "path": path,
        "observed": true,
        "state": if present { "present" } else { "absent" },
        "regular": present,
        "readable": present,
        "unchanged": true,
        "sha256": observation.sha256,
        "mode": observation.mode,
        "uid": observation.uid,
        "gid": observation.gid,
    })
}

/// Inspect every path prefix without following a symbolic link. Destination
/// parents are an explicit birth prerequisite: this tool never creates them.
fn inspect_installed(path: &Path) -> Result<InstalledObservation, String> {
    if !path.is_absolute() || !clean_absolute_path(path) {
        return Err("release-binary-path-must-be-clean-absolute-path".into());
    }
    if path.file_name().filter(|name| !name.is_empty()).is_none() {
        return Err("release-binary-path-file-name-missing".into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "release-binary-parent-missing".to_string())?;

    let mut prefix = PathBuf::from("/");
    for part in parent.components() {
        match part {
            Component::RootDir => continue,
            Component::Normal(name) => prefix.push(name),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err("release-binary-path-must-be-clean-absolute-path".into());
            }
        }
        let metadata = match fs::symlink_metadata(&prefix) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(format!(
                    "release-binary-parent-missing birth_debt=destination-parent-must-be-created-by-appliance-birth path={}",
                    prefix.display()
                ));
            }
            Err(error) => {
                return Err(format!(
                    "release-binary-parent-observation-failed path={} error={error}",
                    prefix.display()
                ));
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "release-binary-symlink-traversal-refused path={}",
                prefix.display()
            ));
        }
        if !metadata.file_type().is_dir() {
            return Err(format!(
                "release-binary-parent-not-directory path={}",
                prefix.display()
            ));
        }
    }

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(format!(
                "release-binary-target-observation-failed path={} error={error}",
                path.display()
            ));
        }
    };
    let Some(metadata) = metadata else {
        return Ok(InstalledObservation {
            sha256: None,
            mode: None,
            uid: None,
            gid: None,
        });
    };
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "release-binary-symlink-traversal-refused path={}",
            path.display()
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "release-binary-target-not-regular-file path={}",
            path.display()
        ));
    }
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "release-binary-target-read-failed path={} error={error}",
            path.display()
        )
    })?;
    Ok(InstalledObservation {
        sha256: Some(crate::atoms::file_sha256(&bytes)),
        mode: Some(metadata.mode() & 0o7777),
        uid: Some(metadata.uid()),
        gid: Some(metadata.gid()),
    })
}

fn ensure_receipt_outside_vault(receipt_dir: &Path) -> Result<(), String> {
    let absolute = if receipt_dir.is_absolute() {
        receipt_dir.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("release-binary-receipt-path-observation-failed: {error}"))?
            .join(receipt_dir)
    };
    if absolute.starts_with("/vault") {
        return Err("release-binary-receipt-path-inside-vault".into());
    }
    let canonical = fs::canonicalize(receipt_dir)
        .map_err(|error| format!("release-binary-receipt-path-observation-failed: {error}"))?;
    if canonical.starts_with("/vault") {
        return Err("release-binary-receipt-path-inside-vault".into());
    }
    Ok(())
}

fn write_receipt(receipt_dir: &Path, value: &Value) -> Result<(), String> {
    ensure_receipt_outside_vault(receipt_dir)?;
    crate::write_json(&receipt_dir.join("release-binary.json"), value)
}

fn write_exhaustion_receipt(receipt_dir: &Path, value: &Value) -> Result<(), String> {
    ensure_receipt_outside_vault(receipt_dir)?;
    crate::write_json(&receipt_dir.join("module-artifact-exhaustion.json"), value)
}

pub(crate) fn execute(
    args: &BTreeMap<String, Value>,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
    module_id: &str,
    routine_id: Option<&str>,
    step_id: &str,
) -> Result<crate::OperationOutcome, String> {
    let component = required_string(args, "component")?;
    if !safe_component(component) {
        return Err("release-binary-component-invalid".into());
    }
    let asset = required_string(args, "asset")?;
    if !safe_asset(asset) {
        return Err("release-binary-asset-invalid".into());
    }
    let path = Path::new(required_string(args, "path")?);
    validate_destination_path(path)?;
    let mode = args
        .get("mode")
        .and_then(Value::as_u64)
        .filter(|mode| *mode == u64::from(INSTALL_MODE))
        .ok_or_else(|| "release-binary-mode-must-be-0755".to_string())? as u32;
    match crate::atoms::files::classify_target(path) {
        crate::atoms::files::TargetClass::Software => {}
        crate::atoms::files::TargetClass::Config => {
            return Err(format!(
                "release-binary-target-not-software path={}",
                path.display()
            ));
        }
        crate::atoms::files::TargetClass::Refused(reason) => return Err(reason),
    }

    // Vault paths are inert until the exact mountpoint exists. This gate runs
    // before target-parent inspection and before opening the release-flag seat.
    if path.starts_with("/vault") && !vault_is_mounted()? {
        let signal = "release-binary-vault-not-mounted";
        write_receipt(
            receipt_dir,
            &json!({
                "component": component,
                "asset": asset,
                "path": path,
                "module_id": module_id,
                "routine_id": routine_id,
                "step_id": step_id,
                "observed": {"vault_mount": false, "installed_artifact": "not-observed"},
                "could_change": {"path": path, "mode": mode, "uid": INSTALL_UID, "gid": INSTALL_GID},
                "attempt": "vault-mount-gate-skip",
                "final": {"state": "vault-not-mounted"},
                "state": "vault-not-mounted",
                "changed": false,
                "skipped": true,
                "ok": true,
                "first_missing_signal": signal,
                "effect": null,
            }),
        )?;
        return Ok(crate::OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: signal.into(),
            command: None,
        });
    }

    // A missing birth parent is established before any schema or network door.
    let observed = stable_installed_observation(path)?;
    let seat = crate::atoms::ask::mint_seats::at_start()
        .release_flag
        .as_ref()
        .map_err(|error| format!("release-binary-release-flag-seat-unavailable: {error}"))?;
    let binary_observation =
        crate::atoms::ask::member_flag::resolve_binary_component(component, asset, seat);
    let release_evidence = binary_observation.evidence();
    let post_resolution_observed = stable_installed_observation(path)?;
    if post_resolution_observed != observed {
        return Err("release-binary-standing-target-changed-during-resolution".into());
    }
    if binary_observation.selected.is_none() {
        if proven_candidate_exhaustion(&binary_observation.candidate_receipts) {
            let first_missing_signal = format!(
                "module-artifact-candidates-exhausted module={module_id} component={component} candidate_count={}",
                binary_observation.candidate_receipts.len()
            );
            let standing_artifact = standing_receipt(path, &observed);
            let debt = json!({
                "schema": "harmonia.module_artifact_exhaustion.v1",
                "tool": "release-binary",
                "ok": false,
                "changed": false,
                "module_id": module_id,
                "component": component,
                "routine_id": routine_id,
                "step_id": step_id,
                "first_missing_signal": first_missing_signal,
                "candidate_count": binary_observation.candidate_receipts.len(),
                "candidates": binary_observation.candidate_receipts.clone(),
                "standing_artifact": standing_artifact,
                "installed_artifact_state": if observed.sha256.is_some() { "present" } else { "absent" },
                "installed_artifact_preserved": observed.sha256.is_some(),
                "could-change": false,
                "release_evidence": release_evidence.clone(),
            });
            write_exhaustion_receipt(receipt_dir, &debt)?;
            write_receipt(
                receipt_dir,
                &json!({
                    "component": component,
                    "asset": asset,
                    "path": path,
                    "module_id": module_id,
                    "routine_id": routine_id,
                    "step_id": step_id,
                    "observed": observed.receipt_value(),
                    "standing_artifact": standing_receipt(path, &observed),
                    "candidate_receipts": binary_observation.candidate_receipts.clone(),
                    "release_evidence": release_evidence.clone(),
                    "could_change": {"path": path, "mode": mode, "uid": INSTALL_UID, "gid": INSTALL_GID},
                    "attempt": "resolve-configured-release-candidates",
                    "final": {"state": "candidate-exhausted", "sha256": observed.sha256, "mode": observed.mode, "uid": observed.uid, "gid": observed.gid},
                    "state": "candidate-exhausted",
                    "changed": false,
                    "skipped": true,
                    "ok": true,
                    "first_missing_signal": first_missing_signal,
                    "effect": null,
                }),
            )?;
            return Ok(crate::OperationOutcome {
                ok: true,
                changed: false,
                skipped: true,
                message: first_missing_signal,
                command: None,
            });
        }
        return Err(format!(
            "release-binary-release-flag-unresolvable component={component} signal={}",
            binary_observation.signal
        ));
    }
    let flag = binary_observation
        .selected
        .as_ref()
        .ok_or_else(|| format!("release-binary-release-flag-absent component={component}"))?;
    if flag.get("component").and_then(Value::as_str) != Some(component) {
        return Err("release-binary-release-flag-component-mismatch".into());
    }
    let source_sha = flag
        .get("source_sha")
        .and_then(Value::as_str)
        .filter(|value| crate::atoms::ask::fetch_artifact::validate_source_sha(value))
        .ok_or_else(|| "release-binary-release-flag-source-sha-invalid".to_string())?;
    let flag_sha256 = flag
        .get("sha256")
        .and_then(Value::as_str)
        .filter(|value| valid_sha256(value))
        .ok_or_else(|| "release-binary-release-flag-sha256-missing-or-invalid".to_string())?;
    let expected_sha256 = flag_sha256.to_ascii_lowercase();
    let selected_tag = crate::atoms::ask::fetch_artifact::release_tag_for_source_sha(source_sha)
        .ok_or_else(|| "release-binary-selected-tag-invalid".to_string())?;
    let download = binary_observation
        .download
        .ok_or_else(|| "release-binary-verified-download-missing".to_string())?;
    if download.manifest.component != component
        || download.manifest.source_sha != source_sha
        || download.manifest.sha256 != expected_sha256
    {
        return Err("release-binary-release-identity-or-digest-mismatch".into());
    }
    let downloaded_sha256 = crate::atoms::file_sha256(&download.bytes);
    if !valid_sha256(&downloaded_sha256)
        || downloaded_sha256 != expected_sha256
        || download.manifest.sha256 != downloaded_sha256
    {
        return Err("release-binary-digest-mismatch-sidecar-flag-bytes".into());
    }

    let release_repo = format!("HOMESERVERSLTD/{component}");
    if observed.current(&expected_sha256) {
        write_receipt(
            receipt_dir,
            &json!({
                "component": component,
                "repository": format!("HOMESERVERSLTD/{component}"),
                "asset": asset,
                "path": path,
                "module_id": module_id,
                "routine_id": routine_id,
                "step_id": step_id,
                "candidate_receipts": binary_observation.candidate_receipts.clone(),
                "release_evidence": release_evidence.clone(),
                "selected_tag": selected_tag,
                "flag_sha256": flag_sha256,
                "installed_sha256": observed.sha256,
                "observed": observed.receipt_value(),
                "could_change": {"path": path, "mode": mode, "uid": INSTALL_UID, "gid": INSTALL_GID},
                "attempt": "none-current",
                "final": {"state": "current", "sha256": observed.sha256, "mode": observed.mode, "uid": observed.uid, "gid": observed.gid},
                "state": "current",
                "changed": false,
                "skipped": true,
                "effect": null,
            }),
        )?;
        return Ok(crate::OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "release-binary-current".into(),
            command: None,
        });
    }

    if !apply {
        write_receipt(
            receipt_dir,
            &json!({
                "component": component,
                "repository": format!("HOMESERVERSLTD/{component}"),
                "asset": asset,
                "path": path,
                "module_id": module_id,
                "routine_id": routine_id,
                "step_id": step_id,
                "candidate_receipts": binary_observation.candidate_receipts.clone(),
                "release_evidence": release_evidence.clone(),
                "selected_tag": selected_tag,
                "flag_sha256": flag_sha256,
                "installed_sha256": observed.sha256,
                "observed": observed.receipt_value(),
                "could_change": {"path": path, "mode": mode, "uid": INSTALL_UID, "gid": INSTALL_GID},
                "attempt": "planned-no-download-or-placement",
                "final": {"state": "planned", "sha256": observed.sha256, "mode": observed.mode, "uid": observed.uid, "gid": observed.gid},
                "state": "planned",
                "changed": false,
                "skipped": true,
                "effect": null,
            }),
        )?;
        return Ok(crate::OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "release-binary-planned".into(),
            command: None,
        });
    }

    let invocation = invocation.ok_or("release-binary-invocation-key-missing")?;

    // Recheck all destination prefixes after release resolution and immediately
    // before the existing atomic file actuator is allowed to promote bytes.
    let pre_placement_observed = stable_installed_observation(path)?;
    if pre_placement_observed != observed {
        return Err("release-binary-standing-target-changed-before-placement".into());
    }
    let placed = crate::place_file::execute(crate::place_file::PlaceFileRequest {
        path,
        declared_bytes: &download.bytes,
        mode: Some(mode),
        ownership: crate::place_file::DeclaredOwnership {
            uid: Some(INSTALL_UID),
            gid: Some(INSTALL_GID),
        },
        backup: crate::place_file::BackupPolicy::None,
        invocation: Some(invocation),
    })?;
    crate::atoms::attest::attest(&receipt_dir.join("atoms.jsonl"), &placed.receipt, &[])?;

    let final_observation = stable_installed_observation(path)?;
    if !final_observation.current(&expected_sha256) {
        return Err("release-binary-installed-readback-mismatch".into());
    }
    let changed = placed.movement.changed();
    let state = if changed { "installed" } else { "current" };
    write_receipt(
        receipt_dir,
        &json!({
            "component": component,
            "repository": release_repo,
            "asset": asset,
            "path": path,
            "selected_tag": selected_tag,
            "flag_sha256": flag_sha256,
            "candidate_receipts": binary_observation.candidate_receipts.clone(),
            "release_evidence": release_evidence.clone(),
            "downloaded_sha256": downloaded_sha256,
            "installed_sha256": final_observation.sha256,
            "observed": observed.receipt_value(),
            "could_change": {"path": path, "mode": mode, "uid": INSTALL_UID, "gid": INSTALL_GID},
            "attempt": "place-file-atomic",
            "final": {"state": state, "sha256": final_observation.sha256, "mode": final_observation.mode, "uid": final_observation.uid, "gid": final_observation.gid},
            "state": state,
            "changed": changed,
            "skipped": !changed,
            "effect": placed.receipt,
        }),
    )?;
    Ok(crate::OperationOutcome {
        ok: true,
        changed,
        skipped: !changed,
        message: if changed {
            "release-binary-installed".into()
        } else {
            "release-binary-current".into()
        },
        command: None,
    })
}
