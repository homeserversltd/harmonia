pub(crate) fn execute_validated_step(
    step: &crate::ladder::ValidatedStep,
    manifest: &crate::ladder::LadderManifest,
    module_dir: &std::path::Path,
    software_authorization: Option<&crate::SoftwareApplyAuthorization>,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<crate::OperationOutcome, String> {
    let apply = software_authorization.is_some();
    match step.permutation.as_str() {
        "managed-files" => managed_files_step(step, manifest, module_dir, apply, invocation),
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
    _manifest: &crate::ladder::LadderManifest,
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
        let managed_directory_under_home = step.permutation == "managed-directories"
            && target.starts_with("/home/");
        match crate::atoms::files::classify_target(&target) {
            crate::atoms::files::TargetClass::Config
                if !managed_directory_under_home
                    && !matches!(
                        step.permutation.as_str(),
                        "managed-files" | "validated-sudoers-converge"
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
use crate::ladder::{LadderManifest, ProjectedRoutineChild};
use crate::tools::routine::ValidatedStep;
use crate::OperationOutcome;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

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
pub(crate) fn managed_files_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let files: Vec<crate::ManagedFileManifest> = if let Some(files_value) = step.args.get("files") {
        serde_json::from_value(files_value.clone())
            .map_err(|e| format!("managed-files-args-invalid: {e}"))?
    } else if let Some(files_root) = &manifest.files_root {
        managed_files_from_files_root(&manifest.base_dir.join(files_root))?
    } else {
        Vec::new()
    };
    let config_write = files.iter().any(|file| {
        matches!(
            crate::atoms::files::classify_target(Path::new(&file.path)),
            crate::atoms::files::TargetClass::Config
        )
    });
    atoms::files::converge_managed_files(
        &atoms::files::ManagedFilesRequest {
            module_id: "ladder",
            files: &files,
            owner: step.args.get("owner").and_then(|value| value.as_str()),
            group: step.args.get("group").and_then(|value| value.as_str()),
            receipt_name: &step.step_id,
            schema: "harmonia.ladder.files.v1",
            first_missing_signal: "managed-files-drift",
        },
        module_dir,
        apply && !config_write,
        invocation,
    )
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
    invocation: Option<crate::atoms::r#do::InvocationKey>,
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
    invocation: Option<crate::atoms::r#do::InvocationKey>,
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
    invocation: Option<crate::atoms::r#do::InvocationKey>,
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
    crate::atoms::files::symlink_converge(
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
    invocation: Option<crate::atoms::r#do::InvocationKey>,
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
    invocation: Option<crate::atoms::r#do::InvocationKey>,
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
    invocation: Option<crate::atoms::r#do::InvocationKey>,
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
    let request = crate::atoms::files::SourceShelfSweepRequest {
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
    let outcome = crate::atoms::files::source_shelf_sweep(&request, module_dir, apply, invocation)?;
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
    invocation: Option<crate::atoms::r#do::InvocationKey>,
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
    invocation: Option<crate::atoms::r#do::InvocationKey>,
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
    let config_write = classes
        .iter()
        .any(|class| matches!(class, crate::atoms::files::TargetClass::Config));
    let tier_two = manifest.config_deploy.as_deref() == Some("interactable");
    let mut outcome = crate::atoms::files::converge_files_authorized(
        &request,
        module_dir,
        if config_write || tier_two {
            None
        } else {
            software_authorization
        },
        invocation,
    )?;
    if config_write || tier_two {
        crate::bands::propose_edits::refresh_interactables_for_convergence(
            manifest, &request, &outcome,
        )?;
        outcome.changed = false;
        outcome.ownership_changed = false;
    }
    if let Some(summary) = step.args.get("summary_receipt").and_then(Value::as_object) {
        let name = summary
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("files-summary");
        let schema = summary
            .get("schema")
            .and_then(Value::as_str)
            .unwrap_or("harmonia.files.summary.v1");
        crate::atoms::attest::write_json_atomic(
            &module_dir.join(format!("{name}.json")),
            &serde_json::json!({
                "schema": schema,
                "ok": outcome.ok,
                "apply": apply,
                "module": manifest.id,
                "source_dir": request.source_root,
                "target_dir": request.target_root,
                "checked_file_count": outcome.checked,
                "written_file_count": outcome.written,
                "backed_up_file_count": outcome.backed_up,
                "changed": outcome.changed,
                "missing": outcome.missing,
                "authority": summary.get("authority").and_then(Value::as_str).unwrap_or(""),
                "waybar_contract": summary.get("waybar_contract").cloned().unwrap_or(Value::Null),
                "first_missing_signal": if outcome.ok { "none" } else { summary.get("first_missing_signal").and_then(Value::as_str).unwrap_or("files-convergence-incomplete") },
            }),
        )?;
    }
    Ok(OperationOutcome {
        ok: outcome.ok,
        changed: outcome.changed,
        skipped: !apply,
        message: outcome.message,
        command: None,
    })
}
pub(crate) fn files_ensure_present_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
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
