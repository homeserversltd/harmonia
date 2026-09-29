pub(crate) fn execute_validated_step(
    step: &crate::tools::ladder::ValidatedStep,
    manifest: &crate::tools::ladder::LadderManifest,
    module_dir: &std::path::Path,
    software_authorization: Option<&crate::SoftwareApplyAuthorization>,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<crate::OperationOutcome, String> {
    let apply = software_authorization.is_some();
    match step.permutation.as_str() {
        "managed-files" => managed_files_step_with_authorization(
            step,
            manifest,
            module_dir,
            software_authorization,
            invocation,
        )
        .map(|execution| execution.outcome),
        "metadata" => files_metadata_step(step, module_dir, software_authorization, invocation),
        "validated-symlink" => validated_symlink_step(step, module_dir, false, invocation),
        "symlink-converge" => symlink_converge_step(step, module_dir, apply, invocation),
        "validated-file-symlink" => {
            validated_file_symlink_step(step, manifest, module_dir, false, invocation)
        }
        "remove" => files_remove_step(step, module_dir, apply, invocation),
        "executable-present" => files_executable_present_step(step, module_dir),
        "source-shelf-sweep" => {
            files_source_shelf_sweep_step(step, manifest, module_dir, apply, invocation)
        }
        "validated-sudoers-converge" => files_validated_sudoers_converge_step(
            step,
            manifest,
            module_dir,
            software_authorization,
            invocation,
        ),
        "compile-fragments" => {
            compile_fragments_step(step, manifest, module_dir, apply, invocation)
        }
        "hotfix-file-backfill" => {
            hotfix_file_backfill_step(step, module_dir, software_authorization, invocation)
        }
        "converge" | "directory-sync" => files_converge_step(
            step,
            manifest,
            module_dir,
            software_authorization,
            invocation,
        ),
        _ => Err(format!(
            "ladder-executor-missing tool=files permutation={}",
            step.permutation
        )),
    }
}

pub(crate) fn interactable_policy(
    manifest: &crate::tools::ladder::LadderManifest,
) -> crate::atoms::files::InteractablePolicy {
    if manifest.suppress_interactable {
        crate::atoms::files::InteractablePolicy::SuppressInteractable
    } else {
        crate::atoms::files::InteractablePolicy::Default
    }
}

pub(crate) fn structural_file_blocker(
    step: &crate::tools::routine::ValidatedStep,
    _manifest: &crate::tools::ladder::LadderManifest,
) -> Option<String> {
    if step.tool != "files" {
        return None;
    }
    let mut targets = Vec::new();
    for key in [
        "target_root",
        "target",
        "target_path",
        "target_shelf",
        "launcher_target_root",
    ] {
        if let Some(value) = step.args.get(key).and_then(serde_json::Value::as_str) {
            targets.push(PathBuf::from(value));
        }
    }
    if let Some(value) = step.args.get("files").and_then(serde_json::Value::as_array) {
        for item in value {
            if let Some(path) = item.as_str() {
                targets.push(PathBuf::from(path));
            }
            if let Some(path) = item.get("path").and_then(serde_json::Value::as_str) {
                targets.push(PathBuf::from(path));
            }
        }
    }
    if let Some(value) = step
        .args
        .get("directories")
        .and_then(serde_json::Value::as_array)
    {
        for item in value {
            if let Some(path) = item.get("path").and_then(serde_json::Value::as_str) {
                targets.push(PathBuf::from(path));
            }
        }
    }
    for target in targets {
        match crate::atoms::files::classify_target(&target) {
            crate::atoms::files::TargetClass::Config
                if !matches!(
                        step.permutation.as_str(),
                        "managed-files"
                            | "converge"
                            | "directory-sync"
                            | "validated-sudoers-converge"
                            | "validated-symlink"
                            | "compile-fragments"
                    ) =>
            {
                return Some(format!(
                    "configuration-actuator-authority-refused {}",
                    target.display()
                ))
            }
            crate::atoms::files::TargetClass::Config => {}
            crate::atoms::files::TargetClass::Refused(reason) => return Some(reason),
            crate::atoms::files::TargetClass::Software => {}
        }
    }
    None
}

// File permutation preflight and operation ownership.
use crate::atoms;
use crate::atoms::command;
use crate::tools::ladder::{LadderManifest, ProjectedRoutineChild};
use crate::tools::routine::ValidatedStep;
use crate::OperationOutcome;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_os = "linux")]
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs;
#[cfg(target_os = "linux")]
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(target_os = "linux")]
use std::os::unix::fs::DirBuilderExt;
#[cfg(target_os = "linux")]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn validate_fragment_path_component(component: &str, kind: &str) -> Result<(), String> {
    if component.is_empty()
        || component.contains('/')
        || component.contains('\\')
        || matches!(component, "." | "..")
    {
        return Err(format!("compile-fragments-{kind}-invalid"));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct SudoersFragment {
    pub(crate) name: String,
    pub(crate) source_path: PathBuf,
}

/// Select `all/` plus exactly one appliance pool for sudoers. Both the
/// actuator and member projection use this compiler.
pub(crate) fn compile_sudoers_fragments(
    source_root: &Path,
    appliance: &str,
) -> Result<Vec<SudoersFragment>, String> {
    validate_fragment_path_component(appliance, "sudoers-appliance")?;
    let mut selected = BTreeMap::<String, PathBuf>::new();
    for pool in ["all", appliance] {
        let directory = source_root.join(pool);
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "validated-sudoers-pool-read-failed {}: {error}",
                    directory.display()
                ));
            }
        };
        if !metadata.file_type().is_dir() {
            return Err(format!(
                "validated-sudoers-declared-path-refused {}",
                directory.display()
            ));
        }
        let mut entries = fs::read_dir(&directory)
            .map_err(|error| {
                format!(
                    "validated-sudoers-pool-read-failed {}: {error}",
                    directory.display()
                )
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                format!(
                    "validated-sudoers-pool-read-failed {}: {error}",
                    directory.display()
                )
            })?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let name = entry.file_name().into_string().map_err(|_| {
                format!(
                    "validated-sudoers-declared-path-refused {}",
                    path.display()
                )
            })?;
            let relative = Path::new(&name);
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                format!(
                    "validated-sudoers-declared-path-refused {}: {error}",
                    path.display()
                )
            })?;
            if relative.components().count() != 1
                || !name.starts_with("caduceus-")
                || !metadata.file_type().is_file()
            {
                return Err(format!(
                    "validated-sudoers-declared-path-refused {}",
                    path.display()
                ));
            }
            if selected.insert(name.clone(), path).is_some() {
                return Err(format!("validated-sudoers-pool-collision {name}"));
            }
        }
    }
    if selected.is_empty() {
        return Err("validated-sudoers-files-empty".into());
    }
    Ok(selected
        .into_iter()
        .map(|(name, source_path)| SudoersFragment { name, source_path })
        .collect())
}

fn profile_fragment_selectors<'a>(
    profile: &'a Value,
    profile_index: &Path,
) -> Result<(&'a str, &'a str, &'a str), String> {
    let profile_id = profile
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            format!(
                "compile-fragments-profile-id-missing {}",
                profile_index.display()
            )
        })?;
    let platform = profile
        .get("package_authority")
        .and_then(|authority| authority.get("os_family"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            format!(
                "compile-fragments-profile-platform-missing {}",
                profile_index.display()
            )
        })?;
    let behavioral_pool = match profile.get("dotfile_pool") {
        Some(value) if !value.is_null() => value.as_str().ok_or_else(|| {
            format!(
                "compile-fragments-profile-dotfile-pool-invalid {}",
                profile_index.display()
            )
        })?,
        _ => profile_id,
    };
    Ok((profile_id, platform, behavioral_pool))
}

/// Concatenate static fragments in deterministic order without injecting bytes.
pub(crate) fn compile_fragments(
    source_root: &Path,
    platform: &str,
    behavioral_pool: &str,
) -> Result<Vec<u8>, String> {
    validate_fragment_path_component(platform, "platform")?;
    validate_fragment_path_component(behavioral_pool, "behavioral-pool")?;
    let mut bytes = Vec::new();
    for directory in [
        source_root.join("all"),
        source_root.join("platform").join(platform),
        source_root.join(behavioral_pool),
    ] {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "compile-fragments-read-dir-{}: {error}",
                    directory.display()
                ));
            }
        };
        let mut paths = entries
            .map(|entry| entry.map(|e| e.path()).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        paths.retain(|path| path.is_file());
        paths.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
        for path in paths {
            bytes.extend(
                fs::read(&path)
                    .map_err(|e| format!("compile-fragments-read-{}: {e}", path.display()))?,
            );
        }
    }
    Ok(bytes)
}

pub(crate) fn compile_fragments_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let source_root = step
        .args
        .get("source_root")
        .and_then(Value::as_str)
        .map(|path| resolve_ladder_path(manifest, path))
        .ok_or("compile-fragments-source-root-missing")?;
    let profile_index = manifest
        .base_dir
        .parent()
        .and_then(Path::parent)
        .ok_or("compile-fragments-profile-root-missing")?
        .join("index.json");
    let profile: serde_json::Value =
        serde_json::from_slice(&fs::read(&profile_index).map_err(|error| {
            format!(
                "compile-fragments-profile-index-read-failed {}: {error}",
                profile_index.display()
            )
        })?)
        .map_err(|error| {
            format!(
                "compile-fragments-profile-index-parse-failed {}: {error}",
                profile_index.display()
            )
        })?;
    let (appliance, platform, behavioral_pool) =
        profile_fragment_selectors(&profile, &profile_index)?;
    let target = step
        .args
        .get("target_path")
        .or_else(|| step.args.get("output_path"))
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or("compile-fragments-target-path-missing")?;
    if step.args.get("backup_existing").and_then(Value::as_bool) != Some(true) {
        return Err("compile-fragments-backup-existing-required".into());
    }
    let bytes = compile_fragments(&source_root, platform, behavioral_pool)?;
    if bytes.is_empty() {
        crate::place_file::write_compile_fragments_no_claim_projection(
            module_dir,
            &target,
            &appliance,
        )?;
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "compile-fragments-no-claim".into(),
            command: None,
        });
    }
    let target_class = crate::atoms::files::classify_target(&target);
    if let crate::atoms::files::TargetClass::Refused(reason) = &target_class {
        return Err(reason.clone());
    }
    if matches!(target_class, crate::atoms::files::TargetClass::Config) {
        let artifact_root = module_dir.join("compiled-fragments");
        crate::atoms::attest::prepare_receipt_parent(&artifact_root)?;
        let artifact_name = target
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("compile-fragments-target-name-missing")?
            .to_string();
        let artifact = artifact_root.join(&artifact_name);
        crate::atoms::attest::write_bytes_atomic(&artifact, &bytes)?;
        let request = crate::atoms::files::FileConvergenceRequest {
            source_root: artifact_root,
            target_root: target
                .parent()
                .ok_or("compile-fragments-target-parent-missing")?
                .to_path_buf(),
            files: vec![crate::atoms::files::FileSpec {
                mode: step
                    .args
                    .get("mode")
                    .and_then(Value::as_u64)
                    .map(|v| v as u32),
                relative_path: PathBuf::from(artifact_name),
            }],
            backup_existing: true,
            receipt_name: step.step_id.clone(),
            owner: None,
            group: None,
        };
        let outcome = crate::atoms::files::converge_files_authorized_with_interactable_policy(
            &request,
            module_dir,
            None,
            None,
            interactable_policy(manifest),
        )?;
        let recognitions =
            crate::bands::propose_edits::refresh_interactables_for_compiled_convergence(
                manifest, &request, &outcome,
            )?;
        let target_is_regular_file = fs::symlink_metadata(&target)
            .map(|metadata| metadata.file_type().is_file())
            .unwrap_or(false);
        let config_state = if outcome.config_state
            == Some(crate::atoms::files::ConfigConvergenceState::InteractableExempt)
        {
            "interactable-exempt"
        } else if !target_is_regular_file
            || recognitions
                .iter()
                .any(|recognition| recognition.config_state == "refused-unrecognized")
        {
            "refused-unrecognized"
        } else if recognitions
            .iter()
            .any(|recognition| recognition.config_state == "interactable")
        {
            "interactable"
        } else {
            "converged"
        };
        let skipped = config_state != "interactable";
        let message = format!("compile-fragments-config-{config_state}");
        crate::place_file::write_compile_fragments_config_projection(
            module_dir,
            &target,
            &appliance,
            bytes.len(),
            &outcome,
            config_state,
            skipped,
        )?;
        return Ok(OperationOutcome {
            ok: outcome.ok,
            changed: outcome.changed,
            skipped,
            message,
            command: None,
        });
    }
    let backup_path = module_dir.join("backups/compile-fragments");
    let request = crate::place_file::PlaceFileRequest {
        path: &target,
        declared_bytes: &bytes,
        mode: step
            .args
            .get("mode")
            .and_then(Value::as_u64)
            .map(|v| v as u32),
        ownership: crate::place_file::DeclaredOwnership {
            uid: step
                .args
                .get("uid")
                .and_then(Value::as_u64)
                .map(|v| v as u32),
            gid: step
                .args
                .get("gid")
                .and_then(Value::as_u64)
                .map(|v| v as u32),
        },
        backup: crate::place_file::BackupPolicy::To(&backup_path),
        invocation,
    };
    let placed = crate::place_file::execute(request)?;
    let changed = placed.movement.changed();
    let ok = placed.receipt.ok;
    let skipped = !apply;
    let message = placed.receipt.message.clone();
    crate::place_file::write_compile_fragments_place_file_projection(
        module_dir,
        &target,
        &appliance,
        bytes.len(),
        &placed,
        skipped,
    )?;
    Ok(OperationOutcome {
        ok,
        changed,
        skipped,
        message,
        command: None,
    })
}

pub(crate) fn preflight_file_targets(
    manifest: &LadderManifest,
    steps: &[ValidatedStep],
    projected_routines: &BTreeMap<String, Vec<ProjectedRoutineChild>>,
    band: Option<crate::bands::Band>,
) -> Result<(), String> {
    for step in steps {
        if step.tool != "routine" {
            if band.is_none() || crate::tools::routine::placement_for_step(step)? == band.unwrap() {
                if let Some(blocker) = structural_file_blocker(step, manifest) {
                    return Err(blocker);
                }
            }
            continue;
        }
        for child in projected_routines
            .get(&step.step_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            if band.is_none() || child.band == band.unwrap() {
                let child_step = ValidatedStep {
                    step_id: child.name.clone(),
                    tool: child.tool.clone(),
                    permutation: child.permutation.clone(),
                    args: child.args.clone(),
                    on_failure: child.on_failure,
                };
                if let Some(blocker) = structural_file_blocker(&child_step, manifest) {
                    return Err(blocker);
                }
            }
        }
    }
    Ok(())
}
struct ManagedFileDisposition {
    known_good: Vec<crate::ManagedFileManifest>,
    proposals: Vec<crate::ManagedFileManifest>,
    ignored: Vec<crate::ManagedFileManifest>,
}

fn partition_managed_files(
    files: Vec<crate::ManagedFileManifest>,
) -> Result<ManagedFileDisposition, String> {
    let mut disposition = ManagedFileDisposition {
        known_good: Vec::new(),
        proposals: Vec::new(),
        ignored: Vec::new(),
    };
    for file in files {
        // Validation treats an omitted category as known-good; keep this
        // execution seam aligned for directly-resolved managed-file entries.
        match file.category.as_deref().unwrap_or("known-good") {
            "interactable" => {
                let path = Path::new(&file.path);
                if !matches!(
                    crate::atoms::files::classify_target(path),
                    crate::atoms::files::TargetClass::Config
                ) {
                    return Err(format!(
                        "managed-file-interactable-off-config-plane:{}",
                        file.path
                    ));
                }
                disposition.proposals.push(file);
            }
            "known-good" => {
                let path = Path::new(&file.path);
                if matches!(
                    crate::atoms::files::classify_target(path),
                    crate::atoms::files::TargetClass::Config
                )
                {
                    disposition.proposals.push(file);
                } else {
                    disposition.known_good.push(file);
                }
            }
            _ => disposition.ignored.push(file),
        }
    }
    Ok(disposition)
}

fn config_plane_witness(
    file: &crate::ManagedFileManifest,
    module_id: &str,
    observed: &crate::atoms::files::FileConvergenceOutcome,
    recognitions: &[crate::bands::propose_edits::ConfigRecognition],
    interactable_exempt: bool,
) -> Result<Option<crate::atoms::attest::ConfigPlaneWitness>, String> {
    let target = Path::new(&file.path);
    if !matches!(
        crate::atoms::files::classify_target(target),
        crate::atoms::files::TargetClass::Config
    ) {
        return Ok(None);
    }
    let category = match file.category.as_deref().unwrap_or("known-good") {
        "known-good" => crate::atoms::attest::ConfigPlaneCategory::KnownGood,
        "interactable" => crate::atoms::attest::ConfigPlaneCategory::Interactable,
        _ => return Ok(None),
    };
    let entry = observed
        .entries
        .iter()
        .find(|entry| entry.target.as_path() == target)
        .ok_or_else(|| "config-plane-target-observation-missing".to_string())?;
    if !entry.target_exists_after {
        // A missing managed target is a named step failure, not one of the
        // ConfigPlane disposition values.
        return Ok(None);
    }
    let recognition = recognitions
        .iter()
        .find(|record| record.target.as_path() == target);
    let disposition = if interactable_exempt {
        crate::atoms::attest::ConfigPlaneDisposition::InteractableExempt
    } else if recognition.is_some_and(|record| record.config_state == "refused-unrecognized") {
        crate::atoms::attest::ConfigPlaneDisposition::RefusedUnrecognized
    } else if recognition.is_some_and(|record| record.config_state == "interactable") {
        crate::atoms::attest::ConfigPlaneDisposition::InteractableOffered
    } else {
        let converged = entry.source_exists
            && entry.content_equal_after
            && entry.mode_equal_after
            && !entry.ownership_changed;
        if converged {
            match category {
                crate::atoms::attest::ConfigPlaneCategory::KnownGood => {
                    crate::atoms::attest::ConfigPlaneDisposition::Converged
                }
                crate::atoms::attest::ConfigPlaneCategory::Interactable => {
                    crate::atoms::attest::ConfigPlaneDisposition::InteractableConverged
                }
            }
        } else {
            // Recognition refusal is reserved for an explicit low-score
            // receipt. Any other unclassified drift has no truthful disposition.
            return Err("config-plane-disposition-unresolved".into());
        }
    };
    Ok(Some(crate::atoms::attest::ConfigPlaneWitness::new(
        target.to_string_lossy().into_owned(),
        module_id.to_string(),
        category,
        disposition,
    )))
}

pub(crate) fn managed_files_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    _apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    managed_files_step_with_authorization(step, manifest, module_dir, None, invocation)
        .map(|execution| execution.outcome)
}

#[derive(Debug, Deserialize)]
struct ProfileSourceManifest {
    source: String,
    path: String,
    #[serde(default)]
    mode: Option<u32>,
    #[serde(default)]
    append: String,
}

fn materialize_profile_sources(
    step: &ValidatedStep,
) -> Result<Vec<crate::ManagedFileManifest>, String> {
    let Some(sources) = step.args.get("profile_sources").and_then(Value::as_object) else {
        return Ok(Vec::new());
    };
    let source_dir = step
        .args
        .get("source_dir")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .ok_or_else(|| "managed-files-source_dir-missing".to_string())?;
    let mut files = Vec::new();
    for (key, value) in sources {
        let descriptor: ProfileSourceManifest = serde_json::from_value(value.clone())
            .map_err(|error| format!("managed-files-profile-source-{key}-invalid: {error}"))?;
        if descriptor.source.is_empty() || descriptor.path.is_empty() {
            return Err(format!("managed-files-profile-source-{key}-path-invalid"));
        }
        let source = Path::new(source_dir).join(&descriptor.source);
        let text = fs::read_to_string(&source).map_err(|error| {
            format!(
                "managed-files-profile-source-{key}-read-failed {}: {error}",
                source.display()
            )
        })?;
        let mut rendered = text
            .lines()
            .filter(|line| !line.starts_with("profile:") && !line.starts_with("mode:"))
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        if !descriptor.append.trim().is_empty() {
            rendered.push_str(descriptor.append.trim_start());
            if !rendered.ends_with('\n') {
                rendered.push('\n');
            }
        }
        files.push(crate::ManagedFileManifest {
            path: descriptor.path,
            content: rendered,
            mode: descriptor.mode,
            category: Some("interactable".into()),
            legacy_transition_note: None,
        });
    }
    Ok(files)
}

pub(crate) struct ManagedFilesExecution {
    pub(crate) outcome: OperationOutcome,
    pub(crate) truthful_changed: bool,
}

pub(crate) fn managed_files_step_with_authorization(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    software_authorization: Option<&crate::SoftwareApplyAuthorization>,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<ManagedFilesExecution, String> {
    let apply = software_authorization.is_some();
    let files: Vec<crate::ManagedFileManifest> = if let Some(files_value) = step.args.get("files") {
        serde_json::from_value(files_value.clone())
            .map_err(|e| format!("managed-files-args-invalid: {e}"))?
    } else if let Some(files_root) = &manifest.files_root {
        managed_files_from_files_root(
            &manifest.base_dir.join(files_root),
            manifest.category.as_deref(),
        )?
    } else {
        Vec::new()
    };
    let mut files = files;
    files.extend(materialize_profile_sources(step)?);
    let disposition = partition_managed_files(files)?;
    let hold = disposition.known_good;
    let proposals = disposition.proposals;
    let mut truthful_changed = false;
    let mut first_missing_signal: Option<String> = None;
    let mut result = crate::OperationOutcome {
        ok: true,
        changed: false,
        skipped: !apply,
        message: "managed-files".into(),
        command: None,
    };
    let attest_log = module_dir.join("managed-files.attest.jsonl");
    for file in hold {
        let path = Path::new(&file.path);
        crate::atoms::ask::backfill_file::validate_target(path)?;
        let target_exists = path.exists();
        let actual = fs::read(path)
            .ok()
            .map(|bytes| crate::atoms::file_sha256(&bytes));
        let expected = crate::atoms::file_sha256(file.content.as_bytes());
        let missing_signal = format!("managed-file-target-absent:{}", path.display());
        result.ok &= target_exists;
        if !target_exists {
            first_missing_signal.get_or_insert(missing_signal.clone());
        }
        atoms::attest::attest(
            &attest_log,
            &crate::atoms::Receipt {
                atom: "managed-files".into(),
                ok: target_exists,
                drift: crate::atoms::Drift::File {
                    expected_sha256: expected,
                    actual_sha256: actual,
                },
                message: format!(
                    "state=known-good path={} target_exists={} apply=false{}{}",
                    path.display(),
                    target_exists,
                    if target_exists {
                        String::new()
                    } else {
                        format!(" first_missing_signal={missing_signal}")
                    },
                    file.legacy_transition_note
                        .as_deref()
                        .map(|note| format!(" {note}"))
                        .unwrap_or_default()
                ),
            },
            &[],
        )?;
    }
    for file in proposals {
        let target = PathBuf::from(&file.path);
        let relative = target
            .strip_prefix("/")
            .map_err(|_| "managed-file-propose-target-invalid")?;
        let source_root = module_dir.join("proposals").join("sources");
        let source = source_root.join(relative);
        if let Some(parent) = source.parent() {
            atoms::attest::prepare_receipt_parent(parent)?;
        }
        atoms::attest::write_bytes_atomic(&source, file.content.as_bytes())?;
        let request = crate::atoms::files::FileConvergenceRequest {
            source_root,
            target_root: PathBuf::from("/"),
            files: vec![crate::atoms::files::FileSpec {
                mode: file.mode,
                relative_path: relative.to_path_buf(),
            }],
            backup_existing: false,
            receipt_name: format!(
                "{}-interactable-{}",
                step.step_id,
                target
                    .file_name()
                    .and_then(|v| v.to_str())
                    .unwrap_or("managed")
            ),
            owner: step
                .args
                .get("owner")
                .and_then(Value::as_str)
                .map(str::to_owned),
            group: step
                .args
                .get("group")
                .and_then(Value::as_str)
                .map(str::to_owned),
        };
        let observed = crate::atoms::files::converge_files_authorized_with_interactable_policy(
            &request,
            module_dir,
            None,
            invocation,
            interactable_policy(manifest),
        )?;
        let target_exists = target.exists();
        let file_ok = observed.ok && target_exists;
        let missing_signal = format!("managed-file-target-absent:{}", target.display());
        result.ok &= file_ok;
        if !target_exists {
            first_missing_signal.get_or_insert(missing_signal.clone());
        }
        let recognitions = crate::bands::propose_edits::refresh_interactables_for_convergence(
            manifest, &request, &observed,
        )?;
        let interactable_exempt = observed.config_state
            == Some(crate::atoms::files::ConfigConvergenceState::InteractableExempt);
        result.changed |= observed.changed;
        truthful_changed |= crate::atoms::files::convergence_truthful_changed(
            &observed.entries,
            false,
            observed.config_state,
        );
        if interactable_exempt {
            result.message = "managed-files-interactable-exempt".into();
        }
        let witness = config_plane_witness(
            &file,
            &manifest.id,
            &observed,
            &recognitions,
            interactable_exempt,
        )?;
        let attestation_message = if let Some(witness) = witness.as_ref() {
            let serialized = serde_json::to_value(witness)
                .map_err(|error| format!("config-plane-witness-serialization-failed: {error}"))?;
            let disposition = serialized
                .get("disposition")
                .and_then(Value::as_str)
                .ok_or_else(|| "config-plane-witness-disposition-missing".to_string())?;
            let category = serialized
                .get("category")
                .and_then(Value::as_str)
                .ok_or_else(|| "config-plane-witness-category-missing".to_string())?;
            format!(
                "state={} category={} path={} proposal_count={} target_write=false changed={} ownership_changed={}",
                disposition,
                category,
                witness.path,
                recognitions
                    .iter()
                    .filter(|recognition| recognition.config_state == "interactable")
                    .count(),
                observed.changed,
                observed.ownership_changed,
            )
        } else if !target_exists {
            missing_signal.clone()
        } else {
            return Err(format!("config-plane-witness-missing:{}", target.display()));
        };
        let receipt = crate::atoms::Receipt {
            atom: "managed-files".into(),
            ok: file_ok,
            drift: crate::atoms::Drift::Current,
            message: attestation_message,
        };
        if let Some(witness) = witness {
            atoms::attest::attest_config_plane(&attest_log, &receipt, &[], &witness)?;
        } else {
            atoms::attest::attest(&attest_log, &receipt, &[])?;
        }
    }
    if let Some(signal) = first_missing_signal {
        result.message = signal;
    }
    Ok(ManagedFilesExecution {
        outcome: result,
        truthful_changed,
    })
}

fn managed_files_from_files_root(
    root: &Path,
    module_category: Option<&str>,
) -> Result<Vec<crate::ManagedFileManifest>, String> {
    let mut files = Vec::new();
    if !root.exists() {
        return Err(format!("managed-files-root-missing {}", root.display()));
    }
    fn walk(
        root: &Path,
        path: &Path,
        out: &mut Vec<crate::ManagedFileManifest>,
        module_category: Option<&str>,
    ) -> Result<(), String> {
        for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let p = entry.path();
            if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                walk(root, &p, out, module_category)?;
            } else {
                let rel = p.strip_prefix(root).map_err(|e| e.to_string())?;
                let content = fs::read_to_string(&p)
                    .map_err(|e| format!("managed-files-root-read-failed {}: {e}", p.display()))?;
                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::PermissionsExt;
                    Some(
                        fs::metadata(&p)
                            .map_err(|e| e.to_string())?
                            .permissions()
                            .mode()
                            & 0o777,
                    )
                };
                #[cfg(not(unix))]
                let mode = Some(0o644);
                out.push(crate::ManagedFileManifest {
                    path: format!("/{}", rel.to_string_lossy()),
                    content,
                    mode,
                    category: Some(
                        crate::tools::ladder::managed_file_category(module_category)?
                            .ok_or_else(|| "managed-file-category-missing".to_string())?
                            .into(),
                    ),
                    legacy_transition_note: None,
                });
            }
        }
        Ok(())
    }
    walk(root, root, &mut files, module_category)?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}
pub(crate) fn validated_symlink_step(
    step: &ValidatedStep,
    module_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    crate::atoms::files::validated_symlink(
        module_dir,
        &step.step_id,
        &PathBuf::from(string_arg(&step.args, "source")),
        &PathBuf::from(string_arg(&step.args, "target")),
        string_arg(&step.args, "validator_program"),
        &string_array_arg(&step.args, "validator_args"),
        optional_string_arg(&step.args, "reload_program"),
        &string_array_arg(&step.args, "reload_args"),
        integer_arg(&step.args, "timeout_secs", 30),
        apply,
        invocation,
    )
}
pub(crate) fn symlink_converge_step(
    step: &ValidatedStep,
    module_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let required_source_kind = match string_arg(&step.args, "required_source_kind") {
        "regular-executable" => crate::atoms::files::SymlinkSourceKind::RegularExecutable,
        other => return Err(format!("symlink-converge-source-kind-unsupported {other}")),
    };
    let conflict_policy = match optional_string_arg(&step.args, "conflict_policy")
        .unwrap_or("refuse-non-symlink")
    {
        "refuse-non-symlink" => crate::atoms::files::SymlinkConflictPolicy::RefuseNonSymlink,
        "replace-regular-file" => crate::atoms::files::SymlinkConflictPolicy::ReplaceRegularFile,
        "replace-empty-directory" => {
            crate::atoms::files::SymlinkConflictPolicy::ReplaceEmptyDirectory
        }
        other => {
            return Err(format!(
                "symlink-converge-conflict-policy-unsupported {other}"
            ))
        }
    };
    crate::atoms::r#do::symlink_converge::symlink_converge(
        &crate::atoms::files::SymlinkConvergeRequest {
            source: PathBuf::from(string_arg(&step.args, "source")),
            target: PathBuf::from(string_arg(&step.args, "target")),
            required_source_kind,
            conflict_policy,
            owner: optional_string_arg(&step.args, "owner").map(ToString::to_string),
            group: optional_string_arg(&step.args, "group").map(ToString::to_string),
            receipt_name: step.step_id.clone(),
        },
        module_dir,
        apply,
        invocation,
    )
}
pub(crate) fn validated_file_symlink_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let desired_source = resolve_ladder_path(manifest, string_arg(&step.args, "desired_source"));
    let source = PathBuf::from(string_arg(&step.args, "source"));
    let target = PathBuf::from(string_arg(&step.args, "target"));
    let validator_args = string_array_arg(&step.args, "validator_args");
    let reload_args = string_array_arg(&step.args, "reload_args");
    crate::tools::make_symlink::execute(
        crate::tools::make_symlink::ValidatedFileSymlinkRequest {
            receipt_dir: module_dir,
            name: &step.step_id,
            desired_source: &desired_source,
            source: &source,
            target: &target,
            validator_program: string_arg(&step.args, "validator_program"),
            validator_args: &validator_args,
            reload_program: optional_string_arg(&step.args, "reload_program"),
            reload_args: &reload_args,
            timeout_secs: integer_arg(&step.args, "timeout_secs", 30),
            apply,
        },
        invocation,
    )
}
pub(crate) fn files_remove_step(
    step: &ValidatedStep,
    module_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let outcome = crate::atoms::files::remove_declared_files(
        &PathBuf::from(string_arg(&step.args, "target_root")),
        &string_array_arg(&step.args, "paths"),
        module_dir,
        &step.step_id,
        apply,
        invocation,
    )?;
    Ok(OperationOutcome {
        ok: outcome.ok,
        changed: outcome.changed,
        skipped: !apply,
        message: outcome.message,
        command: None,
    })
}
pub(crate) fn files_executable_present_step(
    step: &ValidatedStep,
    module_dir: &Path,
) -> Result<OperationOutcome, String> {
    let search_scope = crate::atoms::files::ExecutableSearchScope::parse(optional_string_arg(
        &step.args,
        "search_scope",
    ))?;
    let outcome = crate::atoms::files::executable_present(
        &crate::atoms::files::ExecutablePresentRequest {
            executable: string_arg(&step.args, "executable").to_string(),
            search_scope,
            receipt_name: step.step_id.clone(),
            receipt_label: optional_string_arg(&step.args, "receipt_label")
                .map(ToString::to_string),
        },
        module_dir,
    )?;
    Ok(OperationOutcome {
        ok: outcome.ok,
        changed: false,
        skipped: false,
        message: outcome.message,
        command: None,
    })
}
pub(crate) fn files_source_shelf_sweep_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let source_root = resolve_ladder_path(manifest, string_arg(&step.args, "source_root"));
    let target_shelf = PathBuf::from(string_arg(&step.args, "target_shelf"));
    let launcher_source_root = optional_string_arg(&step.args, "launcher_source_root")
        .map(|path| resolve_ladder_path(manifest, path))
        .unwrap_or_else(|| source_root.clone());
    let launcher_target_root = optional_string_arg(&step.args, "launcher_target_root")
        .map(PathBuf::from)
        .or_else(|| target_shelf.parent().map(Path::to_path_buf))
        .ok_or_else(|| "source-shelf-sweep-target-shelf-parent-missing".to_string())?;
    let shelf_file_mode = integer_arg(&step.args, "shelf_file_mode", 0) as u32;
    let request = crate::atoms::r#do::source_shelf::SourceShelfSweepRequest {
        source_root,
        shelf_source: PathBuf::from(string_arg(&step.args, "shelf_source")),
        target_shelf,
        launcher_source_root,
        launcher_target_root,
        launcher_pattern: optional_string_arg(&step.args, "launcher_pattern")
            .unwrap_or(".harmonia-no-flat-launchers")
            .to_string(),
        shelf_owner: string_arg(&step.args, "shelf_owner").to_string(),
        shelf_group: string_arg(&step.args, "shelf_group").to_string(),
        shelf_directory_mode: integer_arg(&step.args, "shelf_directory_mode", 0) as u32,
        shelf_file_mode,
        launcher_mode: integer_arg(&step.args, "launcher_mode", shelf_file_mode as u64) as u32,
        prune: step
            .args
            .get("prune")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        launcher_exclude: string_array_arg(&step.args, "launcher_exclude"),
        provenance_state: optional_string_arg(&step.args, "provenance_state").map(PathBuf::from),
        owned_recursive: step
            .args
            .get("owned_recursive")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        receipt_name: step.step_id.clone(),
    };
    let outcome = crate::atoms::r#do::source_shelf::source_shelf_sweep(
        &request, module_dir, apply, invocation,
    )?;
    Ok(OperationOutcome {
        ok: outcome.ok,
        changed: outcome.changed,
        skipped: !apply,
        message: outcome.message,
        command: None,
    })
}
pub(crate) fn files_validated_sudoers_converge_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    authorization: Option<&crate::SoftwareApplyAuthorization>,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    files_validated_sudoers_converge_step_at(
        step,
        manifest,
        module_dir,
        authorization,
        invocation,
        Path::new("/etc/sudoers.d"),
        command::capture_with_timeout,
    )
}

fn files_validated_sudoers_converge_step_at<F>(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    authorization: Option<&crate::SoftwareApplyAuthorization>,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
    declared_target_root: &Path,
    mut validator: F,
) -> Result<OperationOutcome, String>
where
    F: FnMut(&str, &[&str], u64) -> crate::CmdResult,
{
    let source_root = resolve_ladder_path(manifest, string_arg(&step.args, "source_root"));
    let target_root = PathBuf::from(string_arg(&step.args, "target_root"));
    let owned_prefix = string_arg(&step.args, "owned_prefix");
    let validator_program = string_arg(&step.args, "validator_program");
    let validator_args = string_array_arg(&step.args, "validator_args");
    let appliance = string_arg(&step.args, "appliance");
    let selected_fragments = string_array_arg(&step.args, "selected_fragments");

    if target_root != declared_target_root {
        return Err("validated-sudoers-target-root-refused".into());
    }
    if owned_prefix != "caduceus-"
        || !matches!(validator_program, "/usr/bin/visudo" | "/usr/sbin/visudo")
        || validator_args.len() != 1
        || validator_args[0] != "-cf"
        || string_arg(&step.args, "owner") != "root"
        || string_arg(&step.args, "group") != "root"
    {
        return Err("validated-sudoers-contract-refused".into());
    }
    if step.args.contains_key("files") {
        return Err("validated-sudoers-contract-refused".into());
    }
    let source_metadata = fs::symlink_metadata(&source_root).map_err(|error| {
        format!(
            "validated-sudoers-pool-read-failed {}: {error}",
            source_root.display()
        )
    })?;
    if !source_metadata.file_type().is_dir() {
        return Err(format!(
            "validated-sudoers-declared-path-refused {}",
            source_root.display()
        ));
    }
    let expected = compile_sudoers_fragments(&source_root, appliance)?;
    let files = expected
        .iter()
        .map(|fragment| fragment.name.clone())
        .collect::<Vec<_>>();
    if selected_fragments != files {
        return Err("validated-sudoers-pool-selection-drift".into());
    }
    let mut unique = BTreeSet::new();
    for fragment in &expected {
        let name = &fragment.name;
        let relative = Path::new(name.as_str());
        if relative.components().count() != 1
            || !name.starts_with(owned_prefix)
            || !unique.insert(name)
        {
            return Err(format!("validated-sudoers-declared-path-refused {name}"));
        }
        let metadata = fs::symlink_metadata(&fragment.source_path).map_err(|error| {
            format!(
                "validated-sudoers-declared-path-refused {}: {error}",
                fragment.source_path.display()
            )
        })?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "validated-sudoers-declared-path-refused {}",
                fragment.source_path.display()
            ));
        }
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("validated-sudoers-staging-clock-failed: {error}"))?
        .as_nanos();
    let staged_root = module_dir.join(format!(".sudoers-staging-{}-{nonce}", std::process::id()));
    fs::create_dir(&staged_root).map_err(|error| {
        format!(
            "validated-sudoers-staging-create-failed {}: {error}",
            staged_root.display()
        )
    })?;
    struct StagedSudoersSource(PathBuf);
    impl Drop for StagedSudoersSource {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _staged_source = StagedSudoersSource(staged_root.clone());
    for fragment in &expected {
        let bytes = fs::read(&fragment.source_path).map_err(|error| {
            format!(
                "validated-sudoers-source-read-failed {}: {error}",
                fragment.source_path.display()
            )
        })?;
        fs::write(staged_root.join(&fragment.name), bytes).map_err(|error| {
            format!(
                "validated-sudoers-staging-write-failed {}: {error}",
                fragment.name
            )
        })?;
    }

    // Validate the staged bytes that the actuator will promote; no target is
    // promoted until every selected fragment has a successful visudo receipt.
    for fragment in &expected {
        let candidate = staged_root.join(&fragment.name);
        let candidate_text = candidate.to_string_lossy();
        let refs = ["-cf", candidate_text.as_ref()];
        let result = validator(validator_program, &refs, 30);
        crate::write_command_receipt(
            module_dir,
            &format!("{}-{}-validation", step.step_id, fragment.name),
            &result,
        )?;
        if !result.ok {
            return Err(format!(
                "validated-sudoers-visudo-rejected {}",
                fragment.name
            ));
        }
    }

    let request = crate::atoms::files::FileConvergenceRequest {
        source_root: staged_root,
        target_root,
        files: expected
            .iter()
            .map(|fragment| crate::atoms::files::FileSpec {
                relative_path: PathBuf::from(&fragment.name),
                mode: Some(0o440),
            })
            .collect(),
        backup_existing: false,
        receipt_name: optional_string_arg(&step.args, "receipt_name")
            .unwrap_or(&step.step_id)
            .to_string(),
        owner: Some("root".to_string()),
        group: Some("root".to_string()),
    };
    let outcome =
        crate::atoms::r#do::place_file::converge_declared_sudoers_fragments_authorized_at(
            &request,
            module_dir,
            authorization,
            invocation,
            declared_target_root,
        )?;
    let mut outcome = OperationOutcome {
        ok: outcome.ok,
        changed: outcome.changed,
        skipped: authorization.is_none(),
        message: format!(
            "validated-sudoers-fragments={} {}",
            files.join(","),
            outcome.message
        ),
        command: None,
    };
    let selected_message = outcome.message.clone();
    if authorization.is_some() && !outcome.ok {
        outcome.message = format!(
            "{}; prune=not-attempted-selected-fragments-not-converged",
            selected_message
        );
        return Ok(outcome);
    }
    match prune_unselected_sudoers(
        &request.target_root,
        &files,
        module_dir,
        &step.step_id,
        validator_program,
        authorization.is_some(),
        &mut validator,
    ) {
        Ok(prune) => {
            outcome.ok &= prune.ok;
            outcome.changed |= prune.changed;
            outcome.message = format!("{}; {}", selected_message, prune.message);
        }
        Err(error) => {
            outcome.ok = false;
            outcome.message = format!("{}; prune-refused={error}", selected_message);
        }
    }
    Ok(outcome)
}

#[derive(Clone, Debug)]
struct SudoersPruneResult {
    ok: bool,
    changed: bool,
    message: String,
}

#[cfg(target_os = "linux")]
struct SudoersPruneCandidate {
    name: OsString,
    display_name: String,
    device: u64,
    inode: u64,
    size: i64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    bytes: Vec<u8>,
    sha256: String,
    backup_file: String,
    final_state: String,
    final_detail: Option<String>,
    opened: Option<fs::File>,
}

#[cfg(target_os = "linux")]
struct SudoersRestoreOutcome {
    index: usize,
    name: String,
    restored: bool,
    detail: String,
}

#[cfg(target_os = "linux")]
fn prune_unselected_sudoers<F>(
    target_root: &Path,
    selected_names: &[String],
    module_dir: &Path,
    step_id: &str,
    validator_program: &str,
    apply: bool,
    validator: &mut F,
) -> Result<SudoersPruneResult, String>
where
    F: FnMut(&str, &[&str], u64) -> crate::CmdResult,
{
    if apply && unsafe { libc::geteuid() } != 0 {
        return Err("validated-sudoers-prune-root-required".into());
    }
    if module_dir.starts_with(target_root) {
        return Err("validated-sudoers-prune-receipt-inside-target-refused".into());
    }
    let target_dir = open_sudoers_directory(target_root)?;
    let selected = selected_names
        .iter()
        .map(|name| name.as_bytes().to_vec())
        .collect::<BTreeSet<_>>();
    let mut candidates = scan_sudoers_prune_candidates(&target_dir, target_root, &selected, apply)?;
    let planned = candidates
        .iter()
        .map(|candidate| candidate.display_name.clone())
        .collect::<Vec<_>>();
    if !apply {
        if !planned.is_empty() {
            let receipt_path = module_dir.join(format!("{step_id}-sudoers-prune-report.json"));
            crate::atoms::attest::write_json_atomic(
                &receipt_path,
                &serde_json::json!({
                    "step_id": step_id,
                    "mode": "report-only",
                    "planned_prunes": planned,
                    "planned_prune_name_bytes_hex": candidates
                        .iter()
                        .map(|candidate| bytes_hex(candidate.name.as_bytes()))
                        .collect::<Vec<_>>(),
                    "target_root": target_root.display().to_string(),
                    "target_unchanged": true,
                }),
            )
            .map_err(|error| {
                format!(
                    "validated-sudoers-prune-report-receipt-write-failed path={} {error}",
                    receipt_path.display()
                )
            })?;
        }
        return Ok(SudoersPruneResult {
            ok: true,
            changed: false,
            message: format!(
                "report-only planned-prunes={}; target-unchanged",
                if planned.is_empty() {
                    "none".to_string()
                } else {
                    planned.join(",")
                }
            ),
        });
    }
    if candidates.is_empty() {
        return Ok(SudoersPruneResult {
            ok: true,
            changed: false,
            message: "applied planned-prunes=none; no-unlink; visudo-not-needed".into(),
        });
    }

    let (receipt_path, receipt_dir) = create_sudoers_prune_receipt_dir(module_dir, target_root)?;
    for (index, candidate) in candidates.iter_mut().enumerate() {
        candidate.backup_file = format!("pruned-{index:04}.bin");
        write_private_receipt_file(&receipt_dir, &candidate.backup_file, &candidate.bytes, true)
            .map_err(|error| {
                format!(
                    "validated-sudoers-prune-backup-write-failed path={} receipt={} {error}",
                    target_root.join(&candidate.name).display(),
                    receipt_path.display()
                )
            })?;
        verify_private_backup(&receipt_dir, candidate).map_err(|error| {
            format!(
                "validated-sudoers-prune-backup-verify-failed path={} receipt={} {error}",
                target_root.join(&candidate.name).display(),
                receipt_path.display()
            )
        })?;
    }
    write_sudoers_prune_manifest(
        &receipt_dir,
        &receipt_path,
        target_root,
        &candidates,
        "prepared",
        None,
        &[],
    )
    .map_err(|error| {
        format!(
            "validated-sudoers-prune-receipt-write-failed receipt={} {error}",
            receipt_path.display()
        )
    })?;
    sync_directory(&receipt_dir).map_err(|error| {
        format!(
            "validated-sudoers-prune-receipt-sync-failed receipt={} {error}",
            receipt_path.display()
        )
    })?;

    let mut removed = Vec::new();
    for index in 0..candidates.len() {
        let unlink_result = {
            let candidate = &candidates[index];
            verify_sudoers_candidate_unchanged(&target_dir, candidate)
                .and_then(|name| unlink_sudoers_name(&target_dir, &name))
        };
        if let Err(error) = unlink_result {
            let failed_path = target_root
                .join(&candidates[index].name)
                .display()
                .to_string();
            let restorations = restore_sudoers_candidates(&target_dir, &candidates, &removed);
            apply_sudoers_restoration_states(&mut candidates, &restorations);
            let receipt_error = write_sudoers_prune_manifest(
                &receipt_dir,
                &receipt_path,
                target_root,
                &candidates,
                "unlink-failed-restored",
                None,
                &restorations,
            )
            .err();
            return Ok(SudoersPruneResult {
                ok: false,
                changed: restorations.iter().any(|restore| !restore.restored),
                message: format!(
                    "prune-refused path={failed_path} reason={error}; {}; backup-receipt={}; receipt-finalize={}",
                    format_sudoers_restorations(&restorations),
                    receipt_path.display(),
                    receipt_error.as_deref().unwrap_or("written")
                ),
            });
        }
        removed.push(index);
        candidates[index].final_state = "removed".into();
        candidates[index].final_detail = None;
    }
    if let Err(error) = sync_directory(&target_dir) {
        let restorations = restore_sudoers_candidates(&target_dir, &candidates, &removed);
        apply_sudoers_restoration_states(&mut candidates, &restorations);
        let receipt_error = write_sudoers_prune_manifest(
            &receipt_dir,
            &receipt_path,
            target_root,
            &candidates,
            "target-sync-failed-restored",
            None,
            &restorations,
        )
        .err();
        return Ok(SudoersPruneResult {
            ok: false,
            changed: restorations.iter().any(|restore| !restore.restored),
            message: format!(
                "prune-refused after-unlink-directory-sync-failed={error}; {}; backup-receipt={}; receipt-finalize={}",
                format_sudoers_restorations(&restorations),
                receipt_path.display(),
                receipt_error.as_deref().unwrap_or("written")
            ),
        });
    }

    let validation = validator(validator_program, &["-c"], 30);
    let validation_receipt = crate::write_command_receipt(
        module_dir,
        &format!("{step_id}-unselected-prune-validation"),
        &validation,
    );
    let validation_accepted = validation.ok && validation.stderr.is_empty();
    let validation_diagnostic = if validation_receipt.is_err() {
        Some("whole-tree validation command receipt could not be written".to_string())
    } else if !validation.ok && !validation.stderr.is_empty() {
        Some(format!(
            "visudo -c rejected exit_code={} and emitted stderr diagnostics",
            validation.code
        ))
    } else if !validation.ok {
        Some(format!("visudo -c rejected exit_code={}", validation.code))
    } else if !validation.stderr.is_empty() {
        Some(format!(
            "visudo -c emitted stderr diagnostics despite exit_code={} (stderr must be empty)",
            validation.code
        ))
    } else {
        None
    };
    let validation_value = serde_json::json!({
        "attempted": true,
        "program": validator_program,
        "args": ["-c"],
        "ok": validation.ok,
        "exit_code": validation.code,
        "stderr": validation.stderr.as_str(),
        "stderr_diagnostics_present": !validation.stderr.is_empty(),
        "accepted": validation_accepted && validation_receipt.is_ok(),
        "diagnostic": validation_diagnostic.as_deref(),
        "command_receipt_written": validation_receipt.is_ok(),
        "command_receipt_error": validation_receipt.as_ref().err(),
    });
    if !validation.ok || !validation.stderr.is_empty() || validation_receipt.is_err() {
        let restorations = restore_sudoers_candidates(&target_dir, &candidates, &removed);
        apply_sudoers_restoration_states(&mut candidates, &restorations);
        let status = if validation_receipt.is_err() {
            "validation-receipt-write-failed-restored"
        } else if validation.ok && !validation.stderr.is_empty() {
            "visudo-diagnostics-rejected-restored"
        } else {
            "visudo-rejected-restored"
        };
        let manifest_error = write_sudoers_prune_manifest(
            &receipt_dir,
            &receipt_path,
            target_root,
            &candidates,
            status,
            Some(&validation_value),
            &restorations,
        )
        .err();
        let validation_reason =
            validation_diagnostic.unwrap_or_else(|| "whole-tree validation rejected".to_string());
        return Ok(SudoersPruneResult {
            ok: false,
            changed: restorations.iter().any(|restore| !restore.restored),
            message: format!(
                "prune-refused names={}; {validation_reason}; {}; backup-receipt={}; receipt-finalize={}",
                planned.join(","),
                format_sudoers_restorations(&restorations),
                receipt_path.display(),
                manifest_error.as_deref().unwrap_or("written")
            ),
        });
    }

    if let Err(error) = write_sudoers_prune_manifest(
        &receipt_dir,
        &receipt_path,
        target_root,
        &candidates,
        "visudo-passed-prunes-retained",
        Some(&validation_value),
        &[],
    ) {
        let restorations = restore_sudoers_candidates(&target_dir, &candidates, &removed);
        apply_sudoers_restoration_states(&mut candidates, &restorations);
        let recovery_receipt = write_sudoers_prune_manifest(
            &receipt_dir,
            &receipt_path,
            target_root,
            &candidates,
            "receipt-finalization-failed-restored",
            Some(&validation_value),
            &restorations,
        )
        .err();
        return Ok(SudoersPruneResult {
            ok: false,
            changed: restorations.iter().any(|restore| !restore.restored),
            message: format!(
                "prune-refused receipt-finalization-failed={error}; {}; backup-receipt={}; recovery-receipt={}",
                format_sudoers_restorations(&restorations),
                receipt_path.display(),
                recovery_receipt.as_deref().unwrap_or("written")
            ),
        });
    }

    Ok(SudoersPruneResult {
        ok: true,
        changed: true,
        message: format!(
            "pruned={}; visudo -c passed; backup-receipt={}",
            planned.join(","),
            receipt_path.display()
        ),
    })
}

#[cfg(target_os = "linux")]
fn open_sudoers_directory(path: &Path) -> Result<fs::File, String> {
    let path_c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("validated-sudoers-directory-invalid {}", path.display()))?;
    let fd = unsafe {
        libc::open(
            path_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "validated-sudoers-directory-open-failed {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let directory = unsafe { fs::File::from_raw_fd(fd) };
    let metadata = fstat_fd(directory.as_raw_fd()).map_err(|error| {
        format!(
            "validated-sudoers-directory-stat-failed {}: {error}",
            path.display()
        )
    })?;
    if !is_regular_directory(&metadata) {
        return Err(format!(
            "validated-sudoers-directory-refused {}",
            path.display()
        ));
    }
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn is_regular_directory(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFDIR
}

#[cfg(target_os = "linux")]
fn read_sudoers_directory_names(
    directory: &fs::File,
    path: &Path,
) -> Result<Vec<OsString>, String> {
    let duplicate = unsafe { libc::dup(directory.as_raw_fd()) };
    if duplicate < 0 {
        return Err(format!(
            "validated-sudoers-directory-dup-failed {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(duplicate) };
        return Err(format!(
            "validated-sudoers-directory-read-open-failed {}: {error}",
            path.display()
        ));
    }
    let mut names = Vec::new();
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = unsafe { *libc::__errno_location() };
            if error != 0 {
                unsafe { libc::closedir(stream) };
                return Err(format!(
                    "validated-sudoers-directory-read-failed {}: {}",
                    path.display(),
                    std::io::Error::from_raw_os_error(error)
                ));
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(OsString::from_vec(name.to_vec()));
        }
    }
    unsafe { libc::closedir(stream) };
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok(names)
}

#[cfg(target_os = "linux")]
fn fstat_fd(fd: i32) -> std::io::Result<libc::stat> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(stat)
}

#[cfg(target_os = "linux")]
fn fstatat_nofollow(directory: &fs::File, name: &OsStr) -> std::io::Result<libc::stat> {
    let name_c = CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in filename"))?;
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name_c.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(stat)
}

#[cfg(target_os = "linux")]
fn same_stat_version(left: &libc::stat, right: &libc::stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

#[cfg(target_os = "linux")]
fn scan_sudoers_prune_candidates(
    directory: &fs::File,
    target_root: &Path,
    selected: &BTreeSet<Vec<u8>>,
    capture_bytes: bool,
) -> Result<Vec<SudoersPruneCandidate>, String> {
    let mut candidates = Vec::new();
    for name in read_sudoers_directory_names(directory, target_root)? {
        if !name.as_bytes().starts_with(b"caduceus-") {
            continue;
        }
        let full_path = target_root.join(&name);
        let path_display = full_path.display().to_string();
        let initial = fstatat_nofollow(directory, &name).map_err(|error| {
            format!("validated-sudoers-prune-observe-failed {path_display}: {error}")
        })?;
        if initial.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(format!(
                "validated-sudoers-prune-nonregular-refused {path_display}; no-unlinks-attempted"
            ));
        }
        if selected.contains(name.as_bytes()) {
            continue;
        }
        let (bytes, sha256, opened) = if capture_bytes {
            let name_c = CString::new(name.as_bytes()).map_err(|_| {
                format!("validated-sudoers-prune-invalid-name-refused {path_display}")
            })?;
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name_c.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                return Err(format!(
                    "validated-sudoers-prune-open-nofollow-failed {path_display}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut file = unsafe { fs::File::from_raw_fd(fd) };
            let opened_stat = fstat_fd(file.as_raw_fd()).map_err(|error| {
                format!("validated-sudoers-prune-file-stat-failed {path_display}: {error}")
            })?;
            if opened_stat.st_mode & libc::S_IFMT != libc::S_IFREG
                || !same_stat_version(&initial, &opened_stat)
            {
                return Err(format!(
                    "validated-sudoers-prune-file-changed-before-backup {path_display}; no-unlinks-attempted"
                ));
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).map_err(|error| {
                format!("validated-sudoers-prune-file-read-failed {path_display}: {error}")
            })?;
            let after_read = fstat_fd(file.as_raw_fd()).map_err(|error| {
                format!("validated-sudoers-prune-file-stat-failed {path_display}: {error}")
            })?;
            if !same_stat_version(&opened_stat, &after_read) {
                return Err(format!(
                    "validated-sudoers-prune-file-changed-during-backup {path_display}; no-unlinks-attempted"
                ));
            }
            let sha256 = sha256_hex(&bytes);
            (bytes, sha256, Some(file))
        } else {
            (Vec::new(), String::new(), None)
        };
        candidates.push(SudoersPruneCandidate {
            name: name.clone(),
            display_name: name.to_string_lossy().into_owned(),
            device: initial.st_dev as u64,
            inode: initial.st_ino as u64,
            size: initial.st_size,
            mode: (initial.st_mode as u32) & 0o7777,
            uid: initial.st_uid as u32,
            gid: initial.st_gid as u32,
            mtime: initial.st_mtime,
            mtime_nsec: initial.st_mtime_nsec,
            ctime: initial.st_ctime,
            ctime_nsec: initial.st_ctime_nsec,
            bytes,
            sha256,
            backup_file: String::new(),
            final_state: "untouched".into(),
            final_detail: None,
            opened,
        });
    }
    Ok(candidates)
}

#[cfg(target_os = "linux")]
fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(target_os = "linux")]
fn create_sudoers_prune_receipt_dir(
    module_dir: &Path,
    target_root: &Path,
) -> Result<(PathBuf, fs::File), String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("validated-sudoers-prune-receipt-clock-failed: {error}"))?
        .as_nanos();
    let receipt_path = module_dir.join(format!(".sudoers-prune-{}-{nonce}", std::process::id()));
    if receipt_path.starts_with(target_root) || target_root.starts_with(&receipt_path) {
        return Err("validated-sudoers-prune-receipt-outside-target-refused".into());
    }
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(&receipt_path).map_err(|error| {
        format!(
            "validated-sudoers-prune-receipt-dir-create-failed {}: {error}",
            receipt_path.display()
        )
    })?;
    let directory = open_sudoers_directory(&receipt_path)?;
    if unsafe { libc::fchown(directory.as_raw_fd(), 0, 0) } != 0
        || unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0
    {
        return Err(format!(
            "validated-sudoers-prune-receipt-dir-protect-failed {}: {}",
            receipt_path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let stat = fstat_fd(directory.as_raw_fd()).map_err(|error| {
        format!(
            "validated-sudoers-prune-receipt-dir-stat-failed {}: {error}",
            receipt_path.display()
        )
    })?;
    if stat.st_uid != 0 || stat.st_gid != 0 || (stat.st_mode as u32) & 0o7777 != 0o700 {
        return Err(format!(
            "validated-sudoers-prune-receipt-dir-not-root-only {}",
            receipt_path.display()
        ));
    }
    Ok((receipt_path, directory))
}

#[cfg(target_os = "linux")]
fn write_private_receipt_file(
    directory: &fs::File,
    name: &str,
    bytes: &[u8],
    create_new: bool,
) -> Result<(), String> {
    let name_c = CString::new(name)
        .map_err(|_| "validated-sudoers-prune-receipt-name-invalid".to_string())?;
    let flags = libc::O_WRONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | if create_new {
            libc::O_CREAT | libc::O_EXCL
        } else {
            libc::O_TRUNC
        };
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name_c.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return Err(format!(
            "openat {name}: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    file.write_all(bytes)
        .map_err(|error| format!("write {name}: {error}"))?;
    if unsafe { libc::fchown(file.as_raw_fd(), 0, 0) } != 0
        || unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0
    {
        return Err(format!(
            "protect {name}: {}",
            std::io::Error::last_os_error()
        ));
    }
    file.sync_all()
        .map_err(|error| format!("sync {name}: {error}"))
}

#[cfg(target_os = "linux")]
fn verify_private_backup(
    directory: &fs::File,
    candidate: &SudoersPruneCandidate,
) -> Result<(), String> {
    let name_c = CString::new(candidate.backup_file.as_str())
        .map_err(|_| "validated-sudoers-prune-backup-name-invalid".to_string())?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut backup = unsafe { fs::File::from_raw_fd(fd) };
    let stat = fstat_fd(backup.as_raw_fd()).map_err(|error| error.to_string())?;
    if stat.st_uid != 0
        || stat.st_gid != 0
        || (stat.st_mode as u32) & 0o7777 != 0o600
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
    {
        return Err("backup-not-root-only-regular-file".into());
    }
    let mut bytes = Vec::new();
    backup
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes != candidate.bytes || sha256_hex(&bytes) != candidate.sha256 {
        return Err("backup-bytes-or-sha256-mismatch".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn sudoers_prune_manifest_value(
    receipt_path: &Path,
    target_root: &Path,
    candidates: &[SudoersPruneCandidate],
    status: &str,
    validation: Option<&serde_json::Value>,
    restorations: &[SudoersRestoreOutcome],
) -> serde_json::Value {
    let entries = candidates
        .iter()
        .map(|candidate| {
            serde_json::json!({
                "name": candidate.display_name,
                "name_bytes_hex": bytes_hex(candidate.name.as_bytes()),
                "backup_file": candidate.backup_file,
                "record_path": receipt_path.join(&candidate.backup_file).display().to_string(),
                "bytes": candidate.bytes.len(),
                "mode": candidate.mode,
                "uid": candidate.uid,
                "gid": candidate.gid,
                "sha256": candidate.sha256,
                "final_state": candidate.final_state,
                "final_detail": candidate.final_detail,
            })
        })
        .collect::<Vec<_>>();
    let restore_values = restorations
        .iter()
        .map(|restore| {
            serde_json::json!({
                "name": restore.name,
                "restored": restore.restored,
                "outcome": restore.detail,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "target_root": target_root.display().to_string(),
        "status": status,
        "entries": entries,
        "validation": validation,
        "restoration": restore_values,
    })
}

#[cfg(target_os = "linux")]
fn write_sudoers_prune_manifest(
    directory: &fs::File,
    receipt_path: &Path,
    target_root: &Path,
    candidates: &[SudoersPruneCandidate],
    status: &str,
    validation: Option<&serde_json::Value>,
    restorations: &[SudoersRestoreOutcome],
) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(&sudoers_prune_manifest_value(
        receipt_path,
        target_root,
        candidates,
        status,
        validation,
        restorations,
    ))
    .map_err(|error| format!("manifest-serialize: {error}"))?;
    bytes.push(b'\n');
    write_private_receipt_file(directory, "run.json", &bytes, status == "prepared")?;
    sync_directory(directory)
}

#[cfg(target_os = "linux")]
fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(target_os = "linux")]
fn sync_directory(directory: &fs::File) -> Result<(), String> {
    if unsafe { libc::fsync(directory.as_raw_fd()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_sudoers_candidate_unchanged(
    directory: &fs::File,
    candidate: &SudoersPruneCandidate,
) -> Result<CString, String> {
    let current = fstatat_nofollow(directory, &candidate.name).map_err(|error| {
        format!(
            "validated-sudoers-prune-recheck-failed {}: {error}",
            candidate.display_name
        )
    })?;
    let opened = candidate.opened.as_ref().ok_or_else(|| {
        format!(
            "validated-sudoers-prune-open-handle-missing {}",
            candidate.display_name
        )
    })?;
    let descriptor = fstat_fd(opened.as_raw_fd()).map_err(|error| {
        format!(
            "validated-sudoers-prune-descriptor-recheck-failed {}: {error}",
            candidate.display_name
        )
    })?;
    if current.st_mode & libc::S_IFMT != libc::S_IFREG
        || !same_candidate_stat(&current, candidate)
        || !same_candidate_stat(&descriptor, candidate)
    {
        return Err(format!(
            "validated-sudoers-prune-path-changed-before-unlink {}",
            candidate.display_name
        ));
    }
    let mut verify = opened.try_clone().map_err(|error| {
        format!(
            "validated-sudoers-prune-handle-clone-failed {}: {error}",
            candidate.display_name
        )
    })?;
    verify.seek(SeekFrom::Start(0)).map_err(|error| {
        format!(
            "validated-sudoers-prune-rewind-failed {}: {error}",
            candidate.display_name
        )
    })?;
    let mut bytes = Vec::new();
    verify.read_to_end(&mut bytes).map_err(|error| {
        format!(
            "validated-sudoers-prune-recheck-read-failed {}: {error}",
            candidate.display_name
        )
    })?;
    let after_read = fstat_fd(opened.as_raw_fd()).map_err(|error| {
        format!(
            "validated-sudoers-prune-descriptor-recheck-failed {}: {error}",
            candidate.display_name
        )
    })?;
    if bytes != candidate.bytes
        || sha256_hex(&bytes) != candidate.sha256
        || !same_candidate_stat(&after_read, candidate)
    {
        return Err(format!(
            "validated-sudoers-prune-bytes-changed-before-unlink {}",
            candidate.display_name
        ));
    }
    CString::new(candidate.name.as_bytes()).map_err(|_| {
        format!(
            "validated-sudoers-prune-invalid-name-refused {}",
            candidate.display_name
        )
    })
}

#[cfg(target_os = "linux")]
fn same_candidate_stat(stat: &libc::stat, candidate: &SudoersPruneCandidate) -> bool {
    stat.st_dev as u64 == candidate.device
        && stat.st_ino as u64 == candidate.inode
        && stat.st_size == candidate.size
        && (stat.st_mode as u32) & 0o7777 == candidate.mode
        && stat.st_uid as u32 == candidate.uid
        && stat.st_gid as u32 == candidate.gid
        && stat.st_mtime == candidate.mtime
        && stat.st_mtime_nsec == candidate.mtime_nsec
        && stat.st_ctime == candidate.ctime
        && stat.st_ctime_nsec == candidate.ctime_nsec
}

#[cfg(target_os = "linux")]
fn unlink_sudoers_name(directory: &fs::File, name: &CString) -> Result<(), String> {
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn restore_sudoers_candidates(
    directory: &fs::File,
    candidates: &[SudoersPruneCandidate],
    removed: &[usize],
) -> Vec<SudoersRestoreOutcome> {
    let mut outcomes = removed
        .iter()
        .rev()
        .map(|index| restore_sudoers_candidate(directory, &candidates[*index], *index))
        .collect::<Vec<_>>();
    if let Err(error) = sync_directory(directory) {
        for outcome in &mut outcomes {
            outcome.restored = false;
            outcome
                .detail
                .push_str(&format!("; directory-sync-failed={error}"));
        }
    }
    outcomes
}

#[cfg(target_os = "linux")]
fn restore_sudoers_candidate(
    directory: &fs::File,
    candidate: &SudoersPruneCandidate,
    index: usize,
) -> SudoersRestoreOutcome {
    let name_c = match CString::new(candidate.name.as_bytes()) {
        Ok(name) => name,
        Err(error) => {
            return SudoersRestoreOutcome {
                index,
                name: candidate.display_name.clone(),
                restored: false,
                detail: format!("restore-name-invalid={error}"),
            }
        }
    };
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return SudoersRestoreOutcome {
            index,
            name: candidate.display_name.clone(),
            restored: false,
            detail: format!("restore-open-failed={}", std::io::Error::last_os_error()),
        };
    }
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let created = fstat_fd(file.as_raw_fd()).ok();
    let attempt = (|| -> Result<(), String> {
        file.write_all(&candidate.bytes)
            .map_err(|error| format!("restore-write-failed={error}"))?;
        if unsafe {
            libc::fchown(
                file.as_raw_fd(),
                candidate.uid as libc::uid_t,
                candidate.gid as libc::gid_t,
            )
        } != 0
        {
            return Err(format!(
                "restore-owner-failed={}",
                std::io::Error::last_os_error()
            ));
        }
        if unsafe { libc::fchmod(file.as_raw_fd(), candidate.mode as libc::mode_t) } != 0 {
            return Err(format!(
                "restore-mode-failed={}",
                std::io::Error::last_os_error()
            ));
        }
        file.sync_all()
            .map_err(|error| format!("restore-sync-failed={error}"))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| format!("restore-rewind-failed={error}"))?;
        let mut restored_bytes = Vec::new();
        file.read_to_end(&mut restored_bytes)
            .map_err(|error| format!("restore-readback-failed={error}"))?;
        let stat =
            fstat_fd(file.as_raw_fd()).map_err(|error| format!("restore-stat-failed={error}"))?;
        if restored_bytes != candidate.bytes
            || sha256_hex(&restored_bytes) != candidate.sha256
            || (stat.st_mode as u32) & 0o7777 != candidate.mode
            || stat.st_uid as u32 != candidate.uid
            || stat.st_gid as u32 != candidate.gid
        {
            return Err("restore-readback-bytes-mode-or-owner-mismatch".into());
        }
        Ok(())
    })();
    match attempt {
        Ok(()) => SudoersRestoreOutcome {
            index,
            name: candidate.display_name.clone(),
            restored: true,
            detail: format!(
                "restored-exact-bytes-mode-owner sha256={}",
                candidate.sha256
            ),
        },
        Err(error) => {
            let cleanup = created
                .and_then(|created| {
                    let current = fstatat_nofollow(directory, &candidate.name).ok()?;
                    (current.st_dev == created.st_dev && current.st_ino == created.st_ino)
                        .then_some(())
                })
                .and_then(|()| {
                    (unsafe { libc::unlinkat(directory.as_raw_fd(), name_c.as_ptr(), 0) } == 0)
                        .then_some("partial-restore-removed")
                })
                .unwrap_or("partial-restore-cleanup-not-proven");
            SudoersRestoreOutcome {
                index,
                name: candidate.display_name.clone(),
                restored: false,
                detail: format!("{error}; cleanup={cleanup}"),
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn apply_sudoers_restoration_states(
    candidates: &mut [SudoersPruneCandidate],
    restorations: &[SudoersRestoreOutcome],
) {
    for restoration in restorations {
        if let Some(candidate) = candidates.get_mut(restoration.index) {
            candidate.final_state = if restoration.restored {
                "restored"
            } else {
                "failed"
            }
            .into();
            candidate.final_detail = Some(restoration.detail.clone());
        }
    }
}

#[cfg(target_os = "linux")]
fn format_sudoers_restorations(restorations: &[SudoersRestoreOutcome]) -> String {
    if restorations.is_empty() {
        return "restore=not-needed".into();
    }
    restorations
        .iter()
        .map(|restore| {
            format!(
                "{}:{} ({})",
                restore.name,
                if restore.restored {
                    "restored"
                } else {
                    "restore-failed"
                },
                restore.detail
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(not(target_os = "linux"))]
fn prune_unselected_sudoers<F>(
    _target_root: &Path,
    _selected_names: &[String],
    _module_dir: &Path,
    _step_id: &str,
    _validator_program: &str,
    _apply: bool,
    _validator: &mut F,
) -> Result<SudoersPruneResult, String>
where
    F: FnMut(&str, &[&str], u64) -> crate::CmdResult,
{
    Err("validated-sudoers-prune-requires-unix-dirfd".into())
}

pub(crate) fn files_converge_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    software_authorization: Option<&crate::SoftwareApplyAuthorization>,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let source_root = resolve_ladder_path(manifest, string_arg(&step.args, "source_root"));
    let target_root = PathBuf::from(string_arg(&step.args, "target_root"));
    let apply = software_authorization.is_some();
    let mode = step
        .args
        .get("mode")
        .map(|value| {
            value
                .as_u64()
                .and_then(|mode| u32::try_from(mode).ok())
                .ok_or_else(|| "files-mode-invalid".to_string())
        })
        .transpose()?;
    let same_root_allowed = step.permutation == "directory-sync"
        && !step.args.contains_key("owner")
        && !step.args.contains_key("group")
        && step
            .args
            .get("allow_same_root")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    if let Some(outcome) = crate::atoms::r#do::place_file::same_root_directory_sync(
        &source_root,
        &target_root,
        module_dir,
        &step.step_id,
        apply,
        same_root_allowed,
    )? {
        return Ok(outcome);
    }
    let rels = if step.permutation == "directory-sync" && !step.args.contains_key("files") {
        files_under_root(&source_root)?
    } else {
        string_array_arg(&step.args, "files")
    };
    let files = rels
        .into_iter()
        .map(|rel| crate::atoms::files::FileSpec {
            mode,
            relative_path: PathBuf::from(rel),
        })
        .collect();
    let request = crate::atoms::files::FileConvergenceRequest {
        source_root,
        target_root,
        files,
        backup_existing: step
            .args
            .get("backup_existing")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        receipt_name: optional_string_arg(&step.args, "receipt_name")
            .unwrap_or(&step.step_id)
            .to_string(),
        owner: optional_string_arg(&step.args, "owner").map(ToString::to_string),
        group: optional_string_arg(&step.args, "group").map(ToString::to_string),
    };
    let classes = request
        .files
        .iter()
        .map(|file| {
            crate::atoms::files::classify_target(&request.target_root.join(&file.relative_path))
        })
        .collect::<Vec<_>>();
    if let Some(reason) = classes.iter().find_map(|class| match class {
        crate::atoms::files::TargetClass::Refused(reason) => Some(reason.clone()),
        _ => None,
    }) {
        return Err(reason);
    }
    let (software_files, config_files): (Vec<_>, Vec<_>) = request
        .files
        .iter()
        .cloned()
        .zip(classes.iter())
        .partition(|(_, class)| matches!(class, crate::atoms::files::TargetClass::Software));
    let software_files = software_files
        .into_iter()
        .map(|(file, _)| file)
        .collect::<Vec<_>>();
    let config_files = config_files
        .into_iter()
        .map(|(file, _)| file)
        .collect::<Vec<_>>();
    let receipt_name = request.receipt_name.clone();
    let software_request = (!software_files.is_empty()).then(|| {
        let mut request = request.clone();
        request.files = software_files;
        request.receipt_name = receipt_name.clone();
        request
    });
    let config_request = (!config_files.is_empty()).then(|| {
        let mut request = request.clone();
        request.files = config_files;
        request.receipt_name = format!("{receipt_name}-config");
        request
    });
    let software_outcome = software_request
        .as_ref()
        .map(|request| {
            crate::atoms::files::converge_files_authorized_with_interactable_policy(
                request,
                module_dir,
                software_authorization,
                invocation,
                interactable_policy(manifest),
            )
        })
        .transpose()?
        .unwrap_or_else(|| crate::atoms::files::FileConvergenceOutcome {
            ok: true,
            changed: false,
            ownership_changed: false,
            config_state: None,
            checked: 0,
            written: 0,
            backed_up: 0,
            missing: Vec::new(),
            entries: Vec::new(),
            message: "software files absent".to_string(),
        });
    let mut config_recognitions = Vec::new();
    let config_outcome = config_request
        .as_ref()
        .map(|request| {
            // Configuration is observed through the recognition wall. A
            // recognized divergence is parked as an interactable; it never
            // enters the software transaction or its rollback path.
            crate::atoms::files::converge_files_authorized_with_interactable_policy(
                request,
                module_dir,
                None,
                None,
                interactable_policy(manifest),
            )
        })
        .transpose()?;
    if let (Some(request), Some(outcome)) = (config_request.as_ref(), config_outcome.as_ref()) {
        config_recognitions = crate::bands::propose_edits::refresh_interactables_for_convergence(
            manifest, request, outcome,
        )?;
    }
    let config_outcome =
        config_outcome.unwrap_or_else(|| crate::atoms::files::FileConvergenceOutcome {
            ok: true,
            changed: false,
            ownership_changed: false,
            config_state: None,
            checked: 0,
            written: 0,
            backed_up: 0,
            missing: Vec::new(),
            entries: Vec::new(),
            message: "config files absent".to_string(),
        });
    let effective_apply = apply && software_request.is_some();
    let outcome_ok = software_outcome.ok && config_outcome.ok;
    let outcome_changed = software_outcome.changed || config_outcome.changed;
    let outcome_ownership_changed =
        software_outcome.ownership_changed || config_outcome.ownership_changed;
    let outcome_checked = software_outcome.checked + config_outcome.checked;
    let outcome_written = software_outcome.written + config_outcome.written;
    let outcome_backed_up = software_outcome.backed_up + config_outcome.backed_up;
    let outcome_missing = software_outcome
        .missing
        .iter()
        .chain(config_outcome.missing.iter())
        .cloned()
        .collect::<Vec<_>>();
    let outcome_message = format!(
        "software: {}; config: {}",
        software_outcome.message, config_outcome.message
    );
    if let Some(summary) = step.args.get("summary_receipt").and_then(Value::as_object) {
        let name = summary
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("files-summary");
        let schema = summary
            .get("schema")
            .and_then(Value::as_str)
            .unwrap_or("harmonia.files.summary.v1");
        let aggregate_state = if config_outcome.config_state
            == Some(crate::atoms::files::ConfigConvergenceState::InteractableExempt)
        {
            "interactable-exempt"
        } else if config_recognitions
            .iter()
            .any(|r| r.config_state == "refused-unrecognized")
        {
            "refused-unrecognized"
        } else if !config_recognitions.is_empty() {
            "interactable"
        } else {
            "converged"
        };
        let (score, reference_id) = if config_recognitions.len() == 1 {
            config_recognitions.first().map_or((None, None), |record| {
                (
                    Some(serde_json::json!(record.score)),
                    Some(serde_json::json!(record.reference_id)),
                )
            })
        } else {
            (None, None)
        };
        crate::place_file::write_files_summary_compatibility_projection(
            module_dir,
            crate::place_file::FilesSummaryProjection {
                name: name.to_string(),
                schema: schema.to_string(),
                ok: outcome_ok,
                apply: effective_apply,
                config_state: aggregate_state.to_string(),
                config_surfaces: serde_json::json!(config_recognitions.clone()),
                module: manifest.id.clone(),
                source_dir: request.source_root.clone(),
                target_dir: request.target_root.clone(),
                checked_file_count: outcome_checked,
                written_file_count: outcome_written,
                backed_up_file_count: outcome_backed_up,
                changed: outcome_changed,
                ownership_changed: outcome_ownership_changed,
                missing: outcome_missing,
                authority: summary
                    .get("authority")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                waybar_contract: summary
                    .get("waybar_contract")
                    .cloned()
                    .unwrap_or(Value::Null),
                first_missing_signal: if outcome_ok {
                    "none".to_string()
                } else {
                    summary
                        .get("first_missing_signal")
                        .and_then(Value::as_str)
                        .unwrap_or("files-convergence-incomplete")
                        .to_string()
                },
                score,
                reference_id,
            },
        )?;
    }
    Ok(OperationOutcome {
        ok: outcome_ok,
        changed: outcome_changed,
        skipped: !effective_apply,
        message: outcome_message,
        command: None,
    })
}

fn hotfix_file_backfill_step(
    step: &ValidatedStep,
    module_dir: &Path,
    software_authorization: Option<&crate::SoftwareApplyAuthorization>,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let declared_bytes = step
        .args
        .get("file_bytes")
        .and_then(Value::as_array)
        .ok_or("hotfix-payload-file-bytes-missing")?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .filter(|byte| *byte <= u8::MAX as u64)
                .map(|byte| byte as u8)
                .ok_or_else(|| "hotfix-payload-file-bytes-invalid".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let target = step
        .args
        .get("target_path")
        .and_then(Value::as_str)
        .filter(|path| !path.trim().is_empty())
        .map(PathBuf::from)
        .ok_or("hotfix-payload-target-path-missing")?;
    let mode = step
        .args
        .get("mode")
        .map(|value| {
            value
                .as_u64()
                .filter(|mode| *mode <= 0o777)
                .map(|mode| mode as u32)
                .ok_or_else(|| "hotfix-payload-mode-invalid".to_string())
        })
        .transpose()?;
    let owner = step
        .args
        .get("owner")
        .map(|value| {
            value
                .as_str()
                .filter(|owner| !owner.trim().is_empty())
                .map(ToString::to_string)
                .ok_or_else(|| "hotfix-payload-owner-invalid".to_string())
        })
        .transpose()?;
    let uid = owner
        .as_deref()
        .map(crate::atoms::files::resolve_uid)
        .transpose()?;
    crate::atoms::r#do::place_file::hotfix_file_backfill(
        &target,
        &declared_bytes,
        mode,
        crate::place_file::DeclaredOwnership { uid, gid: None },
        owner.as_deref(),
        software_authorization.is_some(),
        invocation,
        module_dir,
        &step.step_id,
    )
}

fn files_under_root(root: &Path) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    fn walk(root: &Path, path: &Path, out: &mut Vec<String>) -> Result<(), String> {
        for entry in fs::read_dir(path)
            .map_err(|e| format!("directory-sync-read-failed {}: {e}", path.display()))?
        {
            let entry = entry.map_err(|e| e.to_string())?;
            let p = entry.path();
            if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                walk(root, &p, out)?;
            } else {
                out.push(
                    p.strip_prefix(root)
                        .map_err(|e| e.to_string())?
                        .to_string_lossy()
                        .to_string(),
                );
            }
        }
        Ok(())
    }
    walk(root, root, &mut out)?;
    out.sort();
    Ok(out)
}
pub(crate) fn resolve_ladder_path(manifest: &LadderManifest, path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    if p.is_absolute() {
        p
    } else {
        manifest.base_dir.join(p)
    }
}

fn files_metadata_step(
    step: &ValidatedStep,
    module_dir: &Path,
    software_authorization: Option<&crate::SoftwareApplyAuthorization>,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let specs = step
        .args
        .get("files")
        .and_then(Value::as_array)
        .ok_or("files-metadata-files-missing")?
        .iter()
        .cloned()
        .map(serde_json::from_value::<crate::atoms::r#do::change_mode::MetadataFileSpec>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("files-metadata-spec-invalid: {error}"))?;
    crate::atoms::r#do::change_mode::converge_metadata(
        &specs,
        module_dir,
        &step.step_id,
        software_authorization.is_some(),
        invocation,
    )
}

fn string_arg<'a>(
    a: &'a std::collections::BTreeMap<String, serde_json::Value>,
    n: &str,
) -> &'a str {
    a.get(n).and_then(serde_json::Value::as_str).unwrap_or("")
}
fn optional_string_arg<'a>(
    a: &'a std::collections::BTreeMap<String, serde_json::Value>,
    n: &str,
) -> Option<&'a str> {
    a.get(n).and_then(serde_json::Value::as_str)
}
fn string_array_arg(
    a: &std::collections::BTreeMap<String, serde_json::Value>,
    n: &str,
) -> Vec<String> {
    a.get(n)
        .and_then(serde_json::Value::as_array)
        .map(|xs| {
            xs.iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}
fn integer_arg(a: &std::collections::BTreeMap<String, serde_json::Value>, n: &str, d: u64) -> u64 {
    a.get(n).and_then(serde_json::Value::as_u64).unwrap_or(d)
}

#[cfg(test)]
mod validated_sudoers_convergence_tests {
    use super::files_validated_sudoers_converge_step_at;
    use crate::tools::ladder::{LadderManifest, OnFailure};
    use crate::tools::routine::ValidatedStep;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;

    const FRAGMENT: &str = "90-harmonia-fixture";

    fn run_in_isolated_child(sentinel: &str, test_name: &str) -> bool {
        if std::env::var_os(sentinel).is_some() {
            return false;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg(test_name)
            .arg("--exact")
            .arg("--nocapture")
            .env(sentinel, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child test failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        true
    }

    fn manifest(module_dir: &Path) -> LadderManifest {
        LadderManifest {
            schema: "test".into(),
            id: "sudoers-fixture".into(),
            version: "1".into(),
            description: String::new(),
            role: None,
            optional: false,
            optional_warning: None,
            category: None,
            group: None,
            constants: BTreeMap::new(),
            package_pins: BTreeMap::new(),
            package_ceilings: BTreeMap::new(),
            caduceus_commands: Vec::new(),
            files_root: None,
            config_deploy: None,
            suppress_interactable: false,
            isolation: None,
            module_observation: None,
            plan_refusals: Vec::new(),
            ladder: Vec::new(),
            base_dir: module_dir.to_path_buf(),
        }
    }

    fn step(source_root: &Path, target_root: &Path) -> ValidatedStep {
        ValidatedStep {
            step_id: "validated-sudoers".into(),
            tool: "files".into(),
            permutation: "validated-sudoers-converge".into(),
            args: BTreeMap::from([
                ("source_root".into(), json!(source_root)),
                ("target_root".into(), json!(target_root)),
                ("owned_prefix".into(), json!("90-harmonia-")),
                ("validator_program".into(), json!("/usr/bin/visudo")),
                ("validator_args".into(), json!(["-cf"])),
                ("files".into(), json!([FRAGMENT])),
                ("backup_existing".into(), json!(false)),
                ("owner".into(), json!("root")),
                ("group".into(), json!("root")),
            ]),
            on_failure: OnFailure::Stop,
        }
    }

    fn validator_result(ok: bool) -> crate::CmdResult {
        crate::CmdResult {
            ok,
            code: if ok { 0 } else { 1 },
            stdout: String::new(),
            stderr: if ok {
                String::new()
            } else {
                "fixture syntax rejected".into()
            },
        }
    }

    #[test]
    fn validated_sudoers_apply_replaces_drift_after_validator_without_interactable_when_root() {
        const SENTINEL: &str = "HARMONIA_VALIDATED_SUDOERS_APPLY_TEST_CHILD";
        if run_in_isolated_child(
            SENTINEL,
            "tools::files::managed_files_lane::validated_sudoers_convergence_tests::validated_sudoers_apply_replaces_drift_after_validator_without_interactable_when_root",
        ) {
            return;
        }
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let module_dir = root.path().join("module");
        let source_root = root.path().join("source");
        let target_root = root.path().join("sudoers.d");
        fs::create_dir_all(&module_dir).unwrap();
        fs::create_dir_all(&source_root).unwrap();
        fs::create_dir_all(&target_root).unwrap();
        fs::write(source_root.join(FRAGMENT), b"declared\n").unwrap();
        fs::write(target_root.join(FRAGMENT), b"drifted\n").unwrap();
        let interactables = root.path().join("interactables.json");
        std::env::set_var("HARMONIA_INTERACTABLES_PATH", &interactables);
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let mode = crate::UpdateMode::from_apply_flag_with_invocation(true, Some(&invocation));

        let outcome = files_validated_sudoers_converge_step_at(
            &step(&source_root, &target_root),
            &manifest(&module_dir),
            &module_dir,
            mode.software_authorization(),
            Some(&invocation),
            &target_root,
            |program, args, timeout| {
                assert_eq!(program, "/usr/bin/visudo");
                assert_eq!(args[0], "-cf");
                assert_eq!(args[1], source_root.join(FRAGMENT).to_string_lossy());
                assert_eq!(timeout, 30);
                validator_result(true)
            },
        )
        .unwrap();

        let target = target_root.join(FRAGMENT);
        let metadata = fs::metadata(&target).unwrap();
        assert!(outcome.ok);
        assert!(outcome.changed);
        assert!(!outcome.skipped);
        assert_eq!(fs::read(&target).unwrap(), b"declared\n");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o440);
        assert_eq!(metadata.uid(), 0);
        assert_eq!(metadata.gid(), 0);
        assert!(!interactables.exists());
        assert!(module_dir
            .join(format!("validated-sudoers-{FRAGMENT}-validation.json"))
            .is_file());
        assert!(module_dir.join("validated-sudoers.json").is_file());
    }

    #[test]
    fn validated_sudoers_validator_failure_preserves_prior_bytes_without_interactable() {
        const SENTINEL: &str = "HARMONIA_VALIDATED_SUDOERS_REJECTION_TEST_CHILD";
        if run_in_isolated_child(
            SENTINEL,
            "tools::files::managed_files_lane::validated_sudoers_convergence_tests::validated_sudoers_validator_failure_preserves_prior_bytes_without_interactable",
        ) {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let module_dir = root.path().join("module");
        let source_root = root.path().join("source");
        let target_root = root.path().join("sudoers.d");
        fs::create_dir_all(&module_dir).unwrap();
        fs::create_dir_all(&source_root).unwrap();
        fs::create_dir_all(&target_root).unwrap();
        fs::write(source_root.join(FRAGMENT), b"invalid candidate\n").unwrap();
        fs::write(target_root.join(FRAGMENT), b"prior live bytes\n").unwrap();
        let interactables = root.path().join("interactables.json");
        std::env::set_var("HARMONIA_INTERACTABLES_PATH", &interactables);
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let mode = crate::UpdateMode::from_apply_flag_with_invocation(true, Some(&invocation));

        let error = files_validated_sudoers_converge_step_at(
            &step(&source_root, &target_root),
            &manifest(&module_dir),
            &module_dir,
            mode.software_authorization(),
            Some(&invocation),
            &target_root,
            |_, _, _| validator_result(false),
        )
        .unwrap_err();

        assert_eq!(
            error,
            format!("validated-sudoers-visudo-rejected {FRAGMENT}")
        );
        assert_eq!(
            fs::read(target_root.join(FRAGMENT)).unwrap(),
            b"prior live bytes\n"
        );
        assert!(!interactables.exists());
        assert!(module_dir
            .join(format!("validated-sudoers-{FRAGMENT}-validation.json"))
            .is_file());
        assert!(!module_dir.join("validated-sudoers.json").exists());
    }
}

#[cfg(test)]
mod managed_file_disposition_tests {
    use super::{managed_files_from_files_root, partition_managed_files};
    use std::fs;

    #[test]
    fn files_root_inherits_interactable_module_category_as_proposal() {
        let module_dir = std::env::temp_dir().join(format!(
            "harmonia-managed-files-root-category-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&module_dir);
        let files_root = module_dir.join("files");
        fs::create_dir_all(&files_root).unwrap();
        fs::write(files_root.join("settings.conf"), "setting=true\n").unwrap();
        let manifest_path = module_dir.join("manifest.json");
        fs::write(
            &manifest_path,
            r#"{
                "schema": "harmonia.module.ladder.v1",
                "id": "category-regression",
                "version": "1",
                "category": "interactable",
                "files_root": "files",
                "ladder": [
                    {
                        "step_id": "routine",
                        "tool": "routine",
                        "permutation": "execute",
                        "steps": [
                            {
                                "name": "files",
                                "tool": "files",
                                "permutation": "managed-files",
                                "args": {}
                            }
                        ]
                    }
                ]
            }"#,
        )
        .unwrap();

        let manifest = crate::tools::ladder::load_ladder_manifest(&manifest_path).unwrap();
        assert_eq!(manifest.category.as_deref(), Some("interactable"));
        assert_eq!(manifest.files_root.as_deref(), Some("files"));
        assert_eq!(manifest.ladder[0].steps[0].tool, "files");
        assert_eq!(
            manifest.ladder[0].steps[0].permutation.as_deref(),
            Some("managed-files")
        );
        let files = managed_files_from_files_root(
            &manifest
                .base_dir
                .join(manifest.files_root.as_deref().unwrap()),
            manifest.category.as_deref(),
        )
        .unwrap();
        let disposition = partition_managed_files(files).expect("managed-file partition succeeds");
        assert!(disposition.known_good.is_empty());
        assert_eq!(disposition.proposals.len(), 1);
        assert_eq!(disposition.proposals[0].path, "/settings.conf");
        assert_eq!(
            disposition.proposals[0].category.as_deref(),
            Some("interactable")
        );
        fs::remove_dir_all(module_dir).unwrap();
    }

    #[test]
    fn interactable_divergence_is_proposal_only() {
        let files = vec![
            crate::ManagedFileManifest {
                path: "/usr/local/bin/good".into(),
                content: "g".into(),
                mode: None,
                category: Some("known-good".into()),
                legacy_transition_note: None,
            },
            crate::ManagedFileManifest {
                path: "/etc/proposal".into(),
                content: "p".into(),
                mode: None,
                category: Some("interactable".into()),
                legacy_transition_note: None,
            },
            crate::ManagedFileManifest {
                path: "/etc/ignored".into(),
                content: "i".into(),
                mode: None,
                category: Some("unsupported".into()),
                legacy_transition_note: None,
            },
        ];
        let disposition = partition_managed_files(files).expect("managed-file partition succeeds");
        assert_eq!(
            disposition
                .known_good
                .iter()
                .map(|f| f.path.as_str())
                .collect::<Vec<_>>(),
            ["/usr/local/bin/good"]
        );
        assert_eq!(
            disposition
                .proposals
                .iter()
                .map(|f| f.path.as_str())
                .collect::<Vec<_>>(),
            ["/etc/proposal"]
        );
        assert!(disposition
            .ignored
            .iter()
            .all(|f| f.path != "/etc/proposal"));
    }
}

#[cfg(test)]
mod managed_files_proposal_tests {
    use super::managed_files_step_with_authorization;
    use crate::atoms::files::{classify_target, TargetClass};
    use crate::tools::ladder::{LadderManifest, OnFailure};
    use crate::tools::routine::ValidatedStep;
    use std::collections::BTreeMap;
    use std::fs;
    #[test]
    fn known_good_non_home_config_is_a_pending_proposal_without_target_write() {
        const CHILD_SENTINEL: &str = "HARMONIA_MANAGED_FILES_PROPOSAL_TEST_CHILD";
        if std::env::var_os(CHILD_SENTINEL).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("tools::files::managed_files_lane::managed_files_proposal_tests::known_good_non_home_config_is_a_pending_proposal_without_target_write")
                .arg("--exact")
                .arg("--nocapture")
                .env(CHILD_SENTINEL, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child test failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let root = tempfile::tempdir().unwrap();
        let module_dir = root.path().join("module");
        let target = root
            .path()
            .join("config_deploy:interactable")
            .join("etc/systemd/system/woodpecker-agent.service");
        let feed_path = root.path().join("interactables.json");
        const CURRENT_UNIT: &str = r#"[Unit]
Description=Woodpecker CI agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=woodpecker
ExecStart=/usr/bin/woodpecker-agent --server grpc://woodpecker-server:8000 --token fixture-token
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"#;
        const DESIRED_UNIT: &str = r#"[Unit]
Description=Woodpecker CI agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=woodpecker
ExecStart=/usr/bin/woodpecker-agent --server grpc://woodpecker-server:9000 --token fixture-token
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"#;
        fs::create_dir_all(&module_dir).unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, CURRENT_UNIT.as_bytes()).unwrap();
        let original = fs::read(&target).unwrap();
        assert!(matches!(classify_target(&target), TargetClass::Config));
        std::env::set_var("HARMONIA_INTERACTABLES_PATH", &feed_path);

        let step = ValidatedStep {
            step_id: "managed-files".into(),
            tool: "files".into(),
            permutation: "managed-files".into(),
            args: BTreeMap::from([(
                "files".into(),
                serde_json::json!([{
                    "path": target.display().to_string(),
                    "content": DESIRED_UNIT,
                    "category": "known-good"
                }]),
            )]),
            on_failure: OnFailure::Stop,
        };
        let manifest = LadderManifest {
            schema: "test".into(),
            id: "test".into(),
            version: "1".into(),
            description: String::new(),
            role: None,
            optional: false,
            optional_warning: None,
            category: Some("known-good".into()),
            group: None,
            constants: BTreeMap::new(),
            package_pins: BTreeMap::new(),
            package_ceilings: BTreeMap::new(),
            caduceus_commands: Vec::new(),
            files_root: None,
            config_deploy: None,
            suppress_interactable: false,
            isolation: None,
            module_observation: None,
            plan_refusals: Vec::new(),
            ladder: Vec::new(),
            base_dir: module_dir.clone(),
        };

        managed_files_step_with_authorization(&step, &manifest, &module_dir, None, None).unwrap();

        assert_eq!(fs::read(&target).unwrap(), original);
        let feed: crate::interactables::InteractablesFeed =
            crate::interactables::load_feed(&feed_path).unwrap();
        assert_eq!(feed.interactables.len(), 1);
        assert_eq!(
            feed.interactables
                .iter()
                .filter(|item| {
                    !item.has_run && item.target_path.as_deref() == Some(target.as_path())
                })
                .count(),
            1
        );
        std::env::remove_var("HARMONIA_INTERACTABLES_PATH");
    }
}

#[cfg(test)]
mod compile_fragments_tests {
    use super::{compile_fragments, compile_fragments_step, profile_fragment_selectors};
    use crate::tools::ladder::{LadderManifest, OnFailure};
    use crate::tools::routine::ValidatedStep;
    use serde_json::Value;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn fixture(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "harmonia-compile-fragments-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn compile_step(source_root: &Path, target: &Path) -> ValidatedStep {
        ValidatedStep {
            step_id: "compile-fragments-test".into(),
            tool: "files".into(),
            permutation: "compile-fragments".into(),
            args: BTreeMap::from([
                (
                    "source_root".into(),
                    Value::String(source_root.display().to_string()),
                ),
                (
                    "target_path".into(),
                    Value::String(target.display().to_string()),
                ),
                ("backup_existing".into(), Value::Bool(true)),
            ]),
            on_failure: OnFailure::Stop,
        }
    }

    fn test_manifest(module_dir: &Path) -> LadderManifest {
        LadderManifest {
            schema: "test".into(),
            id: "test".into(),
            version: "1".into(),
            description: String::new(),
            role: None,
            optional: false,
            optional_warning: None,
            category: None,
            group: None,
            constants: BTreeMap::new(),
            package_pins: BTreeMap::new(),
            package_ceilings: BTreeMap::new(),
            caduceus_commands: Vec::new(),
            files_root: None,
            config_deploy: None,
            suppress_interactable: false,
            isolation: None,
            module_observation: None,
            plan_refusals: Vec::new(),
            ladder: Vec::new(),
            base_dir: module_dir.to_path_buf(),
        }
    }
    #[test]
    fn compiles_sorted_all_then_platform_then_pool_without_separator() {
        let root = fixture("normal");
        fs::create_dir_all(root.join("all")).unwrap();
        fs::create_dir_all(root.join("platform/arch")).unwrap();
        fs::create_dir_all(root.join("tv")).unwrap();
        fs::write(root.join("all/z"), b"z").unwrap();
        fs::write(root.join("all/a"), b"a").unwrap();
        fs::write(root.join("platform/arch/2"), b"2").unwrap();
        fs::write(root.join("platform/arch/1"), b"1").unwrap();
        fs::write(root.join("tv/2"), b"4").unwrap();
        fs::write(root.join("tv/1"), b"3").unwrap();
        assert_eq!(compile_fragments(&root, "arch", "tv").unwrap(), b"az1234");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn missing_pools_are_empty() {
        let root = fixture("missing-all");
        fs::create_dir_all(root.join("tv")).unwrap();
        fs::write(root.join("tv/only"), b"only").unwrap();
        assert_eq!(compile_fragments(&root, "arch", "tv").unwrap(), b"only");
        fs::remove_dir_all(&root).unwrap();

        let root = fixture("missing-platform");
        fs::create_dir_all(root.join("all")).unwrap();
        fs::write(root.join("all/only"), b"only").unwrap();
        assert_eq!(compile_fragments(&root, "arch", "tv").unwrap(), b"only");
        fs::remove_dir_all(&root).unwrap();

        let root = fixture("missing-pool");
        fs::create_dir_all(root.join("all")).unwrap();
        fs::create_dir_all(root.join("platform/arch")).unwrap();
        fs::write(root.join("all/10"), b"all").unwrap();
        fs::write(root.join("platform/arch/20"), b"platform").unwrap();
        assert_eq!(
            compile_fragments(&root, "arch", "tv").unwrap(),
            b"allplatform"
        );
        fs::remove_dir_all(&root).unwrap();

        let root = fixture("missing-both");
        assert!(compile_fragments(&root, "arch", "tv").unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn profile_id_fallback_selects_generated_profile_pool() {
        let root = fixture("profile-id-fallback");
        let profile_root = root.join("profile");
        let module_dir = profile_root.join("modules/dot-files");
        let source_root = root.join("source");
        let target = root.join("target.conf");
        let profile_id = ["laptop", "02"].join("-");
        fs::create_dir_all(&module_dir).unwrap();
        fs::create_dir_all(source_root.join("all")).unwrap();
        fs::create_dir_all(source_root.join("platform/arch")).unwrap();
        fs::create_dir_all(source_root.join(&profile_id)).unwrap();
        let profile = serde_json::json!({
            "id": profile_id.clone(),
            "package_authority": {"os_family": "arch"}
        });
        fs::write(
            profile_root.join("index.json"),
            serde_json::to_vec(&profile).unwrap(),
        )
        .unwrap();
        fs::write(source_root.join("all/20"), b"all").unwrap();
        fs::write(source_root.join("platform/arch/10"), b"platform").unwrap();
        fs::write(source_root.join(&profile_id).join("30"), b"pool").unwrap();

        let step = compile_step(&source_root, &target);
        let manifest = test_manifest(&module_dir);
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome =
            compile_fragments_step(&step, &manifest, &module_dir, true, Some(&invocation)).unwrap();

        assert!(outcome.ok);
        assert_eq!(fs::read(&target).unwrap(), b"allplatformpool");
        let receipt: Value =
            serde_json::from_slice(&fs::read(module_dir.join("compile-fragments.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["selected_appliance"], profile_id);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn profile_dotfile_pool_selects_declared_pool() {
        let root = fixture("declared-dotfile-pool");
        let profile_root = root.join("profile");
        let module_dir = profile_root.join("modules/dot-files");
        let source_root = root.join("source");
        let target = root.join("target.conf");
        fs::create_dir_all(&module_dir).unwrap();
        fs::create_dir_all(source_root.join("all")).unwrap();
        fs::create_dir_all(source_root.join("platform/arch")).unwrap();
        fs::create_dir_all(source_root.join("tv")).unwrap();
        fs::write(
            profile_root.join("index.json"),
            br#"{"id":"fixture-profile","package_authority":{"os_family":"arch"},"dotfile_pool":"tv"}"#,
        )
        .unwrap();
        fs::write(source_root.join("all/10"), b"all").unwrap();
        fs::write(source_root.join("platform/arch/20"), b"platform").unwrap();
        fs::write(source_root.join("tv/30"), b"tv").unwrap();

        let step = compile_step(&source_root, &target);
        let manifest = test_manifest(&module_dir);
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome =
            compile_fragments_step(&step, &manifest, &module_dir, true, Some(&invocation)).unwrap();

        assert!(outcome.ok);
        assert_eq!(fs::read(&target).unwrap(), b"allplatformtv");
        let receipt: Value =
            serde_json::from_slice(&fs::read(module_dir.join("compile-fragments.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["selected_appliance"], "fixture-profile");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn empty_compilation_is_a_skipped_no_claim_without_touching_target() {
        let root = fixture("step-empty");
        let profile_root = root.join("profile");
        let module_dir = profile_root.join("modules/dot-files");
        let source_root = root.join("source");
        let target = root.join("target.conf");
        fs::create_dir_all(&module_dir).unwrap();
        fs::create_dir_all(&source_root).unwrap();
        fs::write(
            profile_root.join("index.json"),
            br#"{"id":"homeconsole","package_authority":{"os_family":"arch"}}"#,
        )
        .unwrap();
        fs::write(&target, b"pre-existing").unwrap();

        let mut args = BTreeMap::new();
        args.insert(
            "source_root".into(),
            Value::String(source_root.display().to_string()),
        );
        args.insert(
            "target_path".into(),
            Value::String(target.display().to_string()),
        );
        args.insert("backup_existing".into(), Value::Bool(true));
        let step = ValidatedStep {
            step_id: "compile-fragments".into(),
            tool: "files".into(),
            permutation: "compile-fragments".into(),
            args,
            on_failure: OnFailure::Stop,
        };
        let manifest = LadderManifest {
            schema: "test".into(),
            id: "test".into(),
            version: "1".into(),
            description: String::new(),
            role: None,
            optional: false,
            optional_warning: None,
            category: None,
            group: None,
            constants: BTreeMap::new(),
            package_pins: BTreeMap::new(),
            package_ceilings: BTreeMap::new(),
            caduceus_commands: Vec::new(),
            files_root: None,
            config_deploy: None,
            suppress_interactable: false,
            isolation: None,
            module_observation: None,
            plan_refusals: Vec::new(),
            ladder: Vec::new(),
            base_dir: module_dir.clone(),
        };

        let outcome = compile_fragments_step(&step, &manifest, &module_dir, true, None).unwrap();
        assert!(outcome.ok);
        assert!(!outcome.changed);
        assert!(outcome.skipped);
        assert_eq!(outcome.message, "compile-fragments-no-claim");
        assert_eq!(fs::read(&target).unwrap(), b"pre-existing");
        let receipt: Value =
            serde_json::from_slice(&fs::read(module_dir.join("compile-fragments.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["artifact"], "no-claim");
        assert_eq!(receipt["skipped"], true);
        assert_eq!(receipt["bytes"], 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn zshrc_compiles_from_explicit_platform_and_pool() {
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("shared/modules/dot-files/files_root/zshrc");
        let compiled = compile_fragments(&source, "arch", "tv").unwrap();
        assert!(!compiled.is_empty());
    }

    #[test]
    fn tv_and_homeserver_profiles_preserve_previous_compiled_bytes() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let source_root = repo_root.join("shared/modules/dot-files/files_root");
        let mut artifact_roots = fs::read_dir(&source_root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.is_dir())
            .collect::<Vec<_>>();
        artifact_roots.sort();

        for (profile_id, previous_platform, previous_pool) in
            [("tv", "arch", "tv"), ("homeserver", "debian", "homeserver")]
        {
            let profile_index = repo_root
                .join("profiles")
                .join(profile_id)
                .join("index.json");
            let profile: Value =
                serde_json::from_slice(&fs::read(&profile_index).unwrap()).unwrap();
            let (selected_profile, platform, behavioral_pool) =
                profile_fragment_selectors(&profile, &profile_index).unwrap();
            assert_eq!(selected_profile, profile_id);
            assert_eq!(platform, previous_platform);
            assert_eq!(behavioral_pool, previous_pool);

            for artifact_root in &artifact_roots {
                let previous =
                    compile_fragments(artifact_root, previous_platform, previous_pool).unwrap();
                let declared = compile_fragments(artifact_root, platform, behavioral_pool).unwrap();
                assert!(!previous.is_empty(), "{}", artifact_root.display());
                assert_eq!(
                    declared,
                    previous,
                    "profile {profile_id} changed compiled bytes for {}",
                    artifact_root.display()
                );
            }
        }
    }

    #[test]
    fn config_compile_is_an_interactable_without_failing_backfill_or_run() {
        const CHILD_SENTINEL: &str = "HARMONIA_CONFIG_COMPILE_TEST_CHILD";
        if std::env::var_os(CHILD_SENTINEL).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("tools::files::managed_files_lane::compile_fragments_tests::config_compile_is_an_interactable_without_failing_backfill_or_run")
                .arg("--exact")
                .arg("--nocapture")
                .env(CHILD_SENTINEL, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child test failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let root = fixture("config-interactable");
        let profile_root = root.join("profile");
        let module_dir = profile_root.join("modules/dot-files");
        let source_root = root.join("source");
        let target = root.join("config_deploy:interactable").join("target.conf");
        let feed = root.join("interactables.json");
        fs::create_dir_all(&module_dir).unwrap();
        fs::create_dir_all(source_root.join("all")).unwrap();
        fs::create_dir_all(source_root.join("tv")).unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(
            profile_root.join("index.json"),
            br#"{"id":"tv","package_authority":{"os_family":"arch"}}"#,
        )
        .unwrap();
        fs::write(source_root.join("all/00"), b"all\n").unwrap();
        fs::write(source_root.join("tv/20"), b"tv\n").unwrap();
        fs::write(&target, b"divergent\n").unwrap();

        let args = BTreeMap::from([
            (
                "source_root".into(),
                Value::String(source_root.display().to_string()),
            ),
            (
                "target_path".into(),
                Value::String(target.display().to_string()),
            ),
            ("backup_existing".into(), Value::Bool(true)),
        ]);
        let step = ValidatedStep {
            step_id: "compile-fragments".into(),
            tool: "files".into(),
            permutation: "compile-fragments".into(),
            args,
            on_failure: OnFailure::Stop,
        };
        let manifest = LadderManifest {
            schema: "test".into(),
            id: "test".into(),
            version: "1".into(),
            description: String::new(),
            role: None,
            optional: false,
            optional_warning: None,
            category: None,
            group: None,
            constants: BTreeMap::new(),
            package_pins: BTreeMap::new(),
            package_ceilings: BTreeMap::new(),
            caduceus_commands: Vec::new(),
            files_root: None,
            config_deploy: Some("interactable".into()),
            suppress_interactable: false,
            isolation: None,
            module_observation: None,
            plan_refusals: Vec::new(),
            ladder: Vec::new(),
            base_dir: module_dir.clone(),
        };
        std::env::set_var("HARMONIA_INTERACTABLES_PATH", &feed);
        let mut routine_states = BTreeMap::new();
        let execution = crate::bands::backfill_files::execute_files(
            &manifest,
            &module_dir,
            None,
            None,
            None,
            true,
            false,
            &mut routine_states,
            &[step],
            &BTreeMap::new(),
            &mut BTreeMap::new(),
        )
        .unwrap();
        assert!(execution.ok);
        assert!(execution.first_missing_signal.is_none());
        assert_eq!(execution.placements.len(), 1);
        assert_eq!(execution.placements[0]["status"], "completed");
        assert_eq!(fs::read(&target).unwrap(), b"divergent\n");
        let feed: Value = serde_json::from_slice(&fs::read(&feed).unwrap()).unwrap();
        assert_eq!(feed["interactables"].as_array().unwrap().len(), 1);
        assert_eq!(
            feed["interactables"][0]["target_path"],
            target.display().to_string()
        );
        let receipt: Value =
            serde_json::from_slice(&fs::read(module_dir.join("compile-fragments.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["ok"], true);
        assert_eq!(receipt["config_state"], "interactable");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn config_compile_without_config_deploy_mints_interactable() {
        const CHILD_SENTINEL: &str = "HARMONIA_CONFIG_COMPILE_DEFAULT_NATIVE_TEST_CHILD";
        if std::env::var_os(CHILD_SENTINEL).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("tools::files::managed_files_lane::compile_fragments_tests::config_compile_without_config_deploy_mints_interactable")
                .arg("--exact")
                .arg("--nocapture")
                .env(CHILD_SENTINEL, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child test failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let root = fixture("config-default-native");
        let profile_root = root.join("profile");
        let module_dir = profile_root.join("modules/dot-files");
        let source_root = root.join("source");
        let target = root.join("config_deploy:interactable").join("target.conf");
        let feed_path = root.join("interactables.json");
        fs::create_dir_all(&module_dir).unwrap();
        fs::create_dir_all(source_root.join("all")).unwrap();
        fs::create_dir_all(source_root.join("tv")).unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(
            profile_root.join("index.json"),
            br#"{"id":"tv","package_authority":{"os_family":"arch"}}"#,
        )
        .unwrap();
        fs::write(source_root.join("all/00"), b"all\n").unwrap();
        fs::write(source_root.join("tv/20"), b"tv\n").unwrap();
        fs::write(&target, b"genuinely drifting\n").unwrap();

        let step = ValidatedStep {
            step_id: "compile-fragments-default-native".into(),
            tool: "files".into(),
            permutation: "compile-fragments".into(),
            args: BTreeMap::from([
                (
                    "source_root".into(),
                    Value::String(source_root.display().to_string()),
                ),
                (
                    "target_path".into(),
                    Value::String(target.display().to_string()),
                ),
                ("backup_existing".into(), Value::Bool(true)),
            ]),
            on_failure: OnFailure::Stop,
        };
        let manifest = LadderManifest {
            schema: "test".into(),
            id: "test".into(),
            version: "1".into(),
            description: String::new(),
            role: None,
            optional: false,
            optional_warning: None,
            category: None,
            group: None,
            constants: BTreeMap::new(),
            package_pins: BTreeMap::new(),
            package_ceilings: BTreeMap::new(),
            caduceus_commands: Vec::new(),
            files_root: None,
            config_deploy: None,
            suppress_interactable: false,
            isolation: None,
            module_observation: None,
            plan_refusals: Vec::new(),
            ladder: Vec::new(),
            base_dir: module_dir.clone(),
        };
        std::env::set_var("HARMONIA_INTERACTABLES_PATH", &feed_path);

        let outcome = compile_fragments_step(&step, &manifest, &module_dir, false, None).unwrap();

        assert!(outcome.ok);
        assert!(outcome.changed);
        assert!(!outcome.skipped);
        assert_eq!(outcome.message, "compile-fragments-config-interactable");
        assert_eq!(fs::read(&target).unwrap(), b"genuinely drifting\n");
        let feed = crate::interactables::load_feed(&feed_path).unwrap();
        assert_eq!(feed.interactables.len(), 1);
        assert_eq!(
            feed.interactables[0].target_path.as_deref(),
            Some(target.as_path())
        );
        let receipt: Value =
            serde_json::from_slice(&fs::read(module_dir.join("compile-fragments.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["ok"], true);
        assert_eq!(receipt["changed"], true);
        assert_eq!(receipt["config_state"], "interactable");
        std::env::remove_var("HARMONIA_INTERACTABLES_PATH");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn config_compile_with_suppression_is_exempt_without_proposal() {
        const CHILD_SENTINEL: &str = "HARMONIA_CONFIG_COMPILE_EXEMPT_TEST_CHILD";
        if std::env::var_os(CHILD_SENTINEL).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("tools::files::managed_files_lane::compile_fragments_tests::config_compile_with_suppression_is_exempt_without_proposal")
                .arg("--exact")
                .arg("--nocapture")
                .env(CHILD_SENTINEL, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child test failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let root = fixture("config-interactable-exempt");
        let profile_root = root.join("profile");
        let module_dir = profile_root.join("modules/dot-files");
        let source_root = root.join("source");
        let target = root.join("config_deploy:interactable").join("target.conf");
        let feed_path = root.join("interactables.json");
        fs::create_dir_all(&module_dir).unwrap();
        fs::create_dir_all(source_root.join("all")).unwrap();
        fs::create_dir_all(source_root.join("tv")).unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(
            profile_root.join("index.json"),
            br#"{"id":"tv","package_authority":{"os_family":"arch"}}"#,
        )
        .unwrap();
        fs::write(source_root.join("all/00"), b"all\n").unwrap();
        fs::write(source_root.join("tv/20"), b"tv\n").unwrap();
        fs::write(&target, b"genuinely drifting\n").unwrap();

        let step = ValidatedStep {
            step_id: "compile-fragments-interactable-exempt".into(),
            tool: "files".into(),
            permutation: "compile-fragments".into(),
            args: BTreeMap::from([
                (
                    "source_root".into(),
                    Value::String(source_root.display().to_string()),
                ),
                (
                    "target_path".into(),
                    Value::String(target.display().to_string()),
                ),
                ("backup_existing".into(), Value::Bool(true)),
            ]),
            on_failure: OnFailure::Stop,
        };
        let manifest = LadderManifest {
            schema: "test".into(),
            id: "test".into(),
            version: "1".into(),
            description: String::new(),
            role: None,
            optional: false,
            optional_warning: None,
            category: None,
            group: None,
            constants: BTreeMap::new(),
            package_pins: BTreeMap::new(),
            package_ceilings: BTreeMap::new(),
            caduceus_commands: Vec::new(),
            files_root: None,
            config_deploy: None,
            suppress_interactable: true,
            isolation: None,
            module_observation: None,
            plan_refusals: Vec::new(),
            ladder: Vec::new(),
            base_dir: module_dir.clone(),
        };
        std::env::set_var("HARMONIA_INTERACTABLES_PATH", &feed_path);

        let outcome = compile_fragments_step(&step, &manifest, &module_dir, false, None).unwrap();

        assert!(outcome.ok);
        assert!(outcome.changed);
        assert!(outcome.skipped);
        assert_eq!(
            outcome.message,
            "compile-fragments-config-interactable-exempt"
        );
        assert_eq!(fs::read(&target).unwrap(), b"genuinely drifting\n");
        let feed = crate::interactables::load_feed(&feed_path).unwrap();
        assert!(feed.interactables.is_empty());
        let receipt: Value =
            serde_json::from_slice(&fs::read(module_dir.join("compile-fragments.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["ok"], true);
        assert_eq!(receipt["changed"], true);
        assert_eq!(receipt["config_state"], "interactable-exempt");
        std::env::remove_var("HARMONIA_INTERACTABLES_PATH");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn registry_exposes_compile_fragments_in_backfill_files() {
        let permutation = crate::tools::get("files")
            .unwrap()
            .permutation("compile-fragments")
            .unwrap();
        assert_eq!(
            permutation.placement,
            Some(crate::tools::Placement::BackfillFiles)
        );
    }
}

#[cfg(test)]
mod profile_source_render_tests {
    use super::materialize_profile_sources;
    use crate::tools::ladder::OnFailure;
    use crate::tools::routine::ValidatedStep;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn rereads_source_and_renders_interactable_strip_append() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("profile.conf");
        std::fs::write(&source, "keep\nprofile: old\nmode: 0644\n").unwrap();
        let step = ValidatedStep {
            step_id: "managed-files".into(),
            tool: "files".into(),
            permutation: "managed-files".into(),
            args: BTreeMap::from([
                ("source_dir".into(), json!(dir.path())),
                (
                    "profile_sources".into(),
                    json!({
                        "caduceus_profile_source": {
                            "source": "profile.conf",
                            "path": "/etc/profile.conf",
                            "append": "  append"
                        }
                    }),
                ),
            ]),
            on_failure: OnFailure::Stop,
        };
        let first = materialize_profile_sources(&step).unwrap();
        assert_eq!(first[0].category.as_deref(), Some("interactable"));
        assert_eq!(first[0].content, "keep\nappend\n");
        std::fs::write(&source, "changed\nprofile: new\n").unwrap();
        let second = materialize_profile_sources(&step).unwrap();
        assert!(second[0].content.starts_with("changed\n"));
    }
}
