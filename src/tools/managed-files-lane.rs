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
        ),
        "managed-directories" => managed_directories_step(step, module_dir, apply, invocation),
        "validated-symlink" => validated_symlink_step(step, module_dir, false, invocation),
        "symlink-converge" => symlink_converge_step(step, module_dir, false, invocation),
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
        "ensure-present" => {
            files_ensure_present_step(step, manifest, module_dir, false, invocation)
        }
        "compile-fragments" => {
            compile_fragments_step(step, manifest, module_dir, apply, invocation)
        }
        "hotfix-file-backfill" | "converge" | "directory-sync" => files_converge_step(
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
        let managed_directory_under_home =
            step.permutation == "managed-directories" && target.starts_with("/home/");
        match crate::atoms::files::classify_target(&target) {
            crate::atoms::files::TargetClass::Config
                if !managed_directory_under_home
                    && !matches!(
                        step.permutation.as_str(),
                        "managed-files"
                            | "converge"
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
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Concatenate static fragments in deterministic order without injecting bytes.
pub(crate) fn compile_fragments(
    source_root: &Path,
    selected_appliance: &str,
) -> Result<Vec<u8>, String> {
    if selected_appliance == "all" {
        return Err("compile-fragments-selected-appliance-all-rejected".into());
    }
    if selected_appliance.is_empty()
        || selected_appliance.contains('/')
        || matches!(selected_appliance, "." | "..")
    {
        return Err("compile-fragments-appliance-invalid".into());
    }
    let mut bytes = Vec::new();
    for pool in ["all", selected_appliance] {
        let directory = source_root.join(pool);
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
    let appliance = profile
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            format!(
                "compile-fragments-profile-id-missing {}",
                profile_index.display()
            )
        })?;
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
    let bytes = compile_fragments(&source_root, appliance)?;
    if bytes.is_empty() {
        crate::write_json(
            &module_dir.join("compile-fragments.json"),
            &serde_json::json!({"schema":"harmonia.compile-fragments.receipt.v1","ok":true,"changed":false,"skipped":true,"artifact":"no-claim","target":target,"selected_appliance":appliance,"bytes":0}),
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
    let changed = fs::read(&target)
        .map(|current| current != bytes)
        .unwrap_or(true);
    if matches!(target_class, crate::atoms::files::TargetClass::Config) {
        if manifest.config_deploy.as_deref() != Some("interactable") {
            return Err("configuration-actuator-authority-refused".into());
        }
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
        let outcome = crate::atoms::files::converge_files_authorized_with_config_policy(
            &request, module_dir, None, invocation, true,
        )?;
        crate::bands::propose_edits::refresh_interactables_for_convergence(
            manifest, &request, &outcome,
        )?;
        crate::write_json(
            &module_dir.join("compile-fragments.json"),
            &serde_json::json!({"schema":"harmonia.compile-fragments.receipt.v1","ok":outcome.ok,"changed":false,"skipped":false,"state":"proposal","target":target,"selected_appliance":appliance,"bytes":bytes.len()}),
        )?;
        return Ok(OperationOutcome {
            ok: outcome.ok,
            changed: false,
            skipped: false,
            message: "compile-fragments-config-proposal".into(),
            command: None,
        });
    }
    if apply && changed {
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
        crate::place_file::execute(request)?;
    }
    crate::write_json(
        &module_dir.join("compile-fragments.json"),
        &serde_json::json!({"schema":"harmonia.compile-fragments.receipt.v1","ok":true,"changed":apply && changed,"skipped":!apply,"target":target,"selected_appliance":appliance,"bytes":bytes.len()}),
    )?;
    Ok(OperationOutcome {
        ok: true,
        changed: apply && changed,
        skipped: !apply,
        message: "compile-fragments".into(),
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
) -> ManagedFileDisposition {
    let mut disposition = ManagedFileDisposition {
        known_good: Vec::new(),
        proposals: Vec::new(),
        ignored: Vec::new(),
    };
    for file in files {
        match file.category.as_deref() {
            Some("interactable") => disposition.proposals.push(file),
            None | Some("known-good") => disposition.known_good.push(file),
            Some(_) => disposition.ignored.push(file),
        }
    }
    disposition
}

pub(crate) fn managed_files_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    _apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    managed_files_step_with_authorization(step, manifest, module_dir, None, invocation)
}

pub(crate) fn managed_files_step_with_authorization(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    software_authorization: Option<&crate::SoftwareApplyAuthorization>,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let apply = software_authorization.is_some();
    let files: Vec<crate::ManagedFileManifest> = if let Some(files_value) = step.args.get("files") {
        serde_json::from_value(files_value.clone())
            .map_err(|e| format!("managed-files-args-invalid: {e}"))?
    } else if let Some(files_root) = &manifest.files_root {
        managed_files_from_files_root(&manifest.base_dir.join(files_root))?
    } else {
        Vec::new()
    };
    let disposition = partition_managed_files(files);
    let hold = disposition.known_good;
    let proposals = disposition.proposals;
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
        let actual = fs::read(path)
            .ok()
            .map(|bytes| crate::atoms::file_sha256(&bytes));
        let expected = crate::atoms::file_sha256(file.content.as_bytes());
        atoms::attest::attest(
            &attest_log,
            &crate::atoms::Receipt {
                atom: "managed-files".into(),
                ok: true,
                drift: crate::atoms::Drift::File {
                    expected_sha256: expected,
                    actual_sha256: actual,
                },
                message: format!(
                    "state=known-good path={} target_exists={} apply=false{}",
                    path.display(),
                    path.exists(),
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
        let observed = crate::atoms::files::converge_files_authorized_with_config_policy(
            &request, module_dir, None, invocation, true,
        )?;
        crate::bands::propose_edits::refresh_interactables_for_convergence(
            manifest, &request, &observed,
        )?;
        atoms::attest::attest(
            &attest_log,
            &crate::atoms::Receipt {
                atom: "managed-files".into(),
                ok: true,
                drift: crate::atoms::Drift::Current,
                message: format!(
                    "state=interactable path={} proposal_count=1 target_write=false",
                    target.display()
                ),
            },
            &[],
        )?;
    }
    Ok(result)
}
pub(crate) fn is_configuration_path(path: &Path) -> bool {
    let path = path.to_string_lossy();
    path == "/etc"
        || path.starts_with("/etc/")
        || path == "/home"
        || path.starts_with("/home/")
        || path == "/root"
        || path.starts_with("/root/")
        || path == "$HOME"
        || path.starts_with("$HOME/")
}
pub(crate) fn managed_directories_step(
    step: &ValidatedStep,
    module_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let directories: Vec<atoms::files::ManagedDirectorySpec> = serde_json::from_value(
        step.args
            .get("directories")
            .cloned()
            .ok_or("managed-directories-args-missing")?,
    )
    .map_err(|e| format!("managed-directories-args-invalid: {e}"))?;
    atoms::files::converge_managed_directories(
        &directories,
        module_dir,
        &step.step_id,
        apply,
        invocation,
    )
}
fn managed_files_from_files_root(root: &Path) -> Result<Vec<crate::ManagedFileManifest>, String> {
    let mut files = Vec::new();
    if !root.exists() {
        return Err(format!("managed-files-root-missing {}", root.display()));
    }
    fn walk(
        root: &Path,
        path: &Path,
        out: &mut Vec<crate::ManagedFileManifest>,
    ) -> Result<(), String> {
        for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let p = entry.path();
            if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                walk(root, &p, out)?;
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
                    category: Some("known-good".into()),
                    legacy_transition_note: None,
                });
            }
        }
        Ok(())
    }
    walk(root, root, &mut files)?;
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
    let source_root = resolve_ladder_path(manifest, string_arg(&step.args, "source_root"));
    let target_root = PathBuf::from(string_arg(&step.args, "target_root"));
    let owned_prefix = string_arg(&step.args, "owned_prefix");
    let validator_program = string_arg(&step.args, "validator_program");
    let validator_args = string_array_arg(&step.args, "validator_args");
    let files: Vec<String> = string_array_arg(&step.args, "files");

    if target_root != PathBuf::from("/etc/sudoers.d") {
        return Err("validated-sudoers-target-root-refused".into());
    }
    if owned_prefix.is_empty()
        || owned_prefix.contains('/')
        || owned_prefix.contains('\\')
        || !matches!(validator_program, "/usr/bin/visudo" | "/usr/sbin/visudo")
        || validator_args.len() != 1
        || validator_args[0] != "-cf"
        || string_arg(&step.args, "owner") != "root"
        || string_arg(&step.args, "group") != "root"
    {
        return Err("validated-sudoers-contract-refused".into());
    }
    if files.is_empty() {
        return Err("validated-sudoers-files-empty".into());
    }

    for name in &files {
        let relative = Path::new(name.as_str());
        if relative.components().count() != 1
            || relative.file_name().and_then(|value| value.to_str()) != Some(name.as_str())
            || !name.starts_with(owned_prefix)
        {
            return Err(format!("validated-sudoers-declared-path-refused {name}"));
        }
        let candidate = source_root.join(relative);
        let candidate_text = candidate.to_string_lossy();
        let refs = ["-cf", candidate_text.as_ref()];
        let result = command::capture_with_timeout(validator_program, &refs, 30);
        crate::write_command_receipt(
            module_dir,
            &format!("{}-{}-validation", step.step_id, name),
            &result,
        )?;
        if !result.ok {
            return Err(format!("validated-sudoers-visudo-rejected {name}"));
        }
    }

    let request = crate::atoms::files::FileConvergenceRequest {
        source_root,
        target_root,
        files: files
            .into_iter()
            .map(|relative_path| crate::atoms::files::FileSpec {
                relative_path: PathBuf::from(relative_path),
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
    let outcome = crate::atoms::files::converge_files_authorized(
        &request,
        module_dir,
        authorization,
        invocation,
    )?;
    Ok(OperationOutcome {
        ok: outcome.ok,
        changed: outcome.changed,
        skipped: !authorization.is_some(),
        message: outcome.message,
        command: None,
    })
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
    if step.permutation == "directory-sync"
        && source_root == target_root
        && !step.args.contains_key("owner")
        && !step.args.contains_key("group")
        && step
            .args
            .get("allow_same_root")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        let run = crate::atoms::comparison::execute(
            "ladder",
            || Ok::<_, String>((source_root.clone(), target_root.clone())),
            |_| crate::atoms::comparison::DiffDecision::Empty,
            |_, _| Ok::<_, String>(()),
        )?;
        let (observed_source_root, observed_target_root) = match run {
            crate::atoms::comparison::ComparisonRun::Current { observation, .. } => observation,
            crate::atoms::comparison::ComparisonRun::Moved { .. } => {
                return Err("directory-sync-same-root-unexpected-movement".into());
            }
        };
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: !apply,
            message: format!(
                "directory-sync same-root verified {}",
                observed_source_root.display()
            ),
            command: None,
        };
        crate::write_tool_receipt(
            module_dir,
            &step.step_id,
            "files",
            "directory-sync",
            &outcome,
        )?;
        let receipt_path = module_dir.join(format!("{}.json", step.step_id));
        let mut receipt: serde_json::Value = serde_json::from_slice(
            &fs::read(&receipt_path)
                .map_err(|error| format!("directory-sync-receipt-read-failed: {error}"))?,
        )
        .map_err(|error| format!("directory-sync-receipt-parse-failed: {error}"))?;
        let object = receipt
            .as_object_mut()
            .ok_or_else(|| "directory-sync-receipt-not-object".to_string())?;
        object.insert(
            "observed_state".into(),
            serde_json::json!({"source_root": observed_source_root, "target_root": observed_target_root, "same_root": true}),
        );
        object.insert(
            "desired_state".into(),
            serde_json::json!({"directory_sync": "verified"}),
        );
        object.insert("diff_decision".into(), serde_json::json!("empty"));
        object.insert("movement".into(), serde_json::json!("none"));
        object.insert("truthful_changed".into(), serde_json::json!(false));
        crate::atoms::attest::write_json_atomic(&receipt_path, &receipt)?;
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
            mode: if rel.starts_with("bin/") || rel.starts_with("usr/local/bin/") {
                Some(0o755)
            } else {
                Some(0o644)
            },
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
            crate::atoms::files::converge_files_authorized_with_config_policy(
                request,
                module_dir,
                software_authorization,
                invocation,
                false,
            )
        })
        .transpose()?
        .unwrap_or_else(|| crate::atoms::files::FileConvergenceOutcome {
            ok: true,
            changed: false,
            ownership_changed: false,
            checked: 0,
            written: 0,
            backed_up: 0,
            missing: Vec::new(),
            missing_target_birth_debts: Vec::new(),
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
            crate::atoms::files::converge_files_authorized_with_config_policy(
                request, module_dir, None, None, true,
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
            checked: 0,
            written: 0,
            backed_up: 0,
            missing: Vec::new(),
            missing_target_birth_debts: Vec::new(),
            entries: Vec::new(),
            message: "config files absent".to_string(),
        });
    let effective_apply = apply && software_request.is_some();
    let lawful_config_proposal = config_request.is_some();
    let outcome_ok = software_outcome.ok && config_outcome.ok;
    let outcome_changed = software_outcome.changed;
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
        let aggregate_state = if config_recognitions
            .iter()
            .any(|r| r.config_state == "refused-unrecognized")
        {
            "refused-unrecognized"
        } else if !config_recognitions.is_empty() {
            "interactable"
        } else {
            "converged"
        };
        let mut summary_value = serde_json::json!({
            "schema": schema, "ok": outcome_ok, "apply": effective_apply,
            "config_state": aggregate_state,
            "config_surfaces": config_recognitions.clone(),
            "module": manifest.id,
            "source_dir": request.source_root,
            "target_dir": request.target_root,
            "checked_file_count": outcome_checked,
            "written_file_count": outcome_written,
            "backed_up_file_count": outcome_backed_up,
            "changed": outcome_changed,
            "missing": outcome_missing,
            "authority": summary.get("authority").and_then(Value::as_str).unwrap_or(""),
            "waybar_contract": summary.get("waybar_contract").cloned().unwrap_or(Value::Null),
            "first_missing_signal": if lawful_config_proposal { "none" } else if config_request.is_some() { "authority-refused" } else if outcome_ok { "none" } else { summary.get("first_missing_signal").and_then(Value::as_str).unwrap_or("files-convergence-incomplete") },
        });
        if config_recognitions.len() == 1 {
            if let Some(record) = config_recognitions.first() {
                let object = summary_value.as_object_mut().expect("summary object");
                object.insert("score".into(), serde_json::json!(record.score));
                object.insert(
                    "reference_id".into(),
                    serde_json::json!(record.reference_id),
                );
            }
        }
        crate::atoms::attest::write_json_atomic(
            &module_dir.join(format!("{name}.json")),
            &summary_value,
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
pub(crate) fn files_ensure_present_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let files = string_array_arg(&step.args, "files")
        .into_iter()
        .map(|relative_path| crate::atoms::files::FileSpec {
            mode: Some(0o644),
            relative_path: PathBuf::from(relative_path),
        })
        .collect();
    let outcome = crate::atoms::files::ensure_files_present_with_invocation(
        &crate::atoms::files::FileConvergenceRequest {
            source_root: resolve_ladder_path(manifest, string_arg(&step.args, "source_root")),
            target_root: PathBuf::from(string_arg(&step.args, "target_root")),
            files,
            backup_existing: false,
            receipt_name: optional_string_arg(&step.args, "receipt_name")
                .unwrap_or(&step.step_id)
                .to_string(),
            owner: optional_string_arg(&step.args, "owner").map(ToString::to_string),
            group: optional_string_arg(&step.args, "group").map(ToString::to_string),
        },
        module_dir,
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
mod managed_file_disposition_tests {
    use super::partition_managed_files;

    #[test]
    fn interactable_divergence_is_proposal_only() {
        let files = vec![
            crate::ManagedFileManifest {
                path: "/etc/good".into(),
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
        let disposition = partition_managed_files(files);
        assert_eq!(
            disposition
                .known_good
                .iter()
                .map(|f| f.path.as_str())
                .collect::<Vec<_>>(),
            ["/etc/good"]
        );
        assert_eq!(
            disposition
                .proposals
                .iter()
                .map(|f| f.path.as_str())
                .collect::<Vec<_>>(),
            ["/etc/proposal"]
        );
        assert!(disposition.ignored.iter().all(|f| f.path != "/etc/proposal"));
    }
}

#[cfg(test)]
mod compile_fragments_tests {
    use super::{compile_fragments, compile_fragments_step};
    use crate::tools::ladder::{LadderManifest, OnFailure};
    use crate::tools::routine::ValidatedStep;
    use serde_json::Value;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "harmonia-compile-fragments-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn compiles_sorted_all_then_appliance_without_separator() {
        let root = fixture("normal");
        fs::create_dir_all(root.join("all")).unwrap();
        fs::create_dir_all(root.join("tv")).unwrap();
        fs::write(root.join("all/z"), b"z").unwrap();
        fs::write(root.join("all/a"), b"a").unwrap();
        fs::write(root.join("tv/2"), b"2").unwrap();
        fs::write(root.join("tv/1"), b"1").unwrap();
        assert_eq!(compile_fragments(&root, "tv").unwrap(), b"az12");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn missing_pools_are_empty() {
        let root = fixture("missing-all");
        fs::create_dir_all(root.join("tv")).unwrap();
        fs::write(root.join("tv/only"), b"only").unwrap();
        assert_eq!(compile_fragments(&root, "tv").unwrap(), b"only");
        fs::remove_dir_all(&root).unwrap();

        let root = fixture("missing-appliance");
        fs::create_dir_all(root.join("all")).unwrap();
        fs::write(root.join("all/only"), b"only").unwrap();
        assert_eq!(compile_fragments(&root, "homeserver").unwrap(), b"only");
        fs::remove_dir_all(&root).unwrap();

        let root = fixture("missing-both");
        assert!(compile_fragments(&root, "homeconsole").unwrap().is_empty());
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
        fs::write(profile_root.join("index.json"), br#"{"id":"homeconsole"}"#).unwrap();
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
            group: None,
            constants: BTreeMap::new(),
            package_pins: BTreeMap::new(),
            caduceus_commands: Vec::new(),
            files_root: None,
            config_deploy: None,
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
