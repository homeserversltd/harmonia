use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

const INSTALL_MODE: u32 = 0o755;
const INSTALL_UID: u32 = 0;
const INSTALL_GID: u32 = 0;

#[derive(Debug, Clone)]
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

/// Inspect every path prefix without following a symbolic link. Destination
/// parents are an explicit birth prerequisite: this tool never creates them.
fn inspect_installed(path: &Path) -> Result<InstalledObservation, String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
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

fn write_receipt(receipt_dir: &Path, value: &Value) -> Result<(), String> {
    crate::write_json(&receipt_dir.join("release-binary.json"), value)
}

pub(crate) fn execute(
    args: &BTreeMap<String, Value>,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
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

    // Resolve the selected source identity through the process-retained public
    // release-flag seat; the repository path is never declaration-controlled.
    let seat = crate::atoms::ask::mint_seats::at_start()
        .release_flag
        .as_ref()
        .map_err(|error| format!("release-binary-release-flag-seat-unavailable: {error}"))?;
    let flag_observation = crate::atoms::ask::member_flag::resolve_component(component, seat);
    if flag_observation.signal != "none" {
        return Err(format!(
            "release-binary-release-flag-unresolvable component={component} signal={}",
            flag_observation.signal
        ));
    }
    let flag = flag_observation
        .selected
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

    let observed = inspect_installed(path)?;
    if observed.current(&expected_sha256) {
        write_receipt(
            receipt_dir,
            &json!({
                "component": component,
                "repository": format!("HOMESERVERSLTD/{component}"),
                "asset": asset,
                "path": path,
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
    let release_repo = format!("HOMESERVERSLTD/{component}");
    let sidecar = format!("{asset}.sha256");
    let download = crate::atoms::ask::fetch_artifact::download_release(
        component,
        asset,
        Path::new("."),
        &release_repo,
        Some(&selected_tag),
        crate::atoms::ask::fetch_artifact::DEFAULT_FORGE_API_ROOT,
        Some(asset),
        Some(&sidecar),
        "release-binary",
        source_sha,
    )?
    .ok_or_else(|| format!("release-binary-release-absent tag={selected_tag}"))?;

    let expected_metadata_url = crate::atoms::ask::fetch_artifact::release_metadata_url(
        crate::atoms::ask::fetch_artifact::DEFAULT_FORGE_API_ROOT,
        &release_repo,
        &selected_tag,
    );
    if download.manifest.pipeline_url != expected_metadata_url {
        return Err(format!(
            "release-binary-release-tag-mismatch expected={selected_tag} observed_url={}",
            download.manifest.pipeline_url
        ));
    }
    if download.manifest.component != component || download.manifest.source_sha != source_sha {
        return Err("release-binary-release-identity-mismatch".into());
    }
    let downloaded_sha256 = crate::atoms::file_sha256(&download.bytes);
    if !valid_sha256(&downloaded_sha256)
        || download.manifest.sha256 != downloaded_sha256
        || downloaded_sha256 != expected_sha256
    {
        return Err("release-binary-digest-mismatch-sidecar-flag-bytes".into());
    }

    // Recheck all destination prefixes after the network operation and directly
    // before the existing atomic file actuator is allowed to promote bytes.
    let _ = inspect_installed(path)?;
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

    let final_observation = inspect_installed(path)?;
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
