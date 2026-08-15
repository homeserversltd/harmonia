use crate::OperationOutcome;
use crate::ladder::{LadderManifest, OnFailure, ProjectedRoutineChild, RoutineStep, ValidatedStep};
use crate::ModuleExecution;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use super::Band;

pub(crate) fn execute_files(
    manifest: &LadderManifest,
    module_dir: &Path,
    software_authorization: Option<&crate::SoftwareApplyAuthorization>,
    package_authority: Option<&crate::PackageAuthority>,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
    mode_apply: bool,
    module_changed_before_step: bool,
    routine_states: &mut BTreeMap<String, crate::ModuleWalkState>,
    projected_steps: &[ValidatedStep],
    projected_routines: &BTreeMap<String, Vec<ProjectedRoutineChild>>,
) -> Result<ModuleExecution, String> {
    let band = crate::bands::Band::BackfillFiles;
    let steps = projected_steps.to_vec();
    crate::tools::files::preflight_file_targets(manifest, &steps, projected_routines, Some(band))?;
    fs::create_dir_all(module_dir).map_err(|e| e.to_string())?;
    let mut result = ModuleExecution {
        ok: true,
        changed: false,
        operation_count: 0,
        first_missing_signal: None,
        placements: Vec::new(),
    };
    for step in steps {
        if step.tool == "routine" {
            let children = projected_routines
                .get(&step.step_id)
                .ok_or_else(|| "routine-step-missing".to_string())?;
            if !children.iter().any(|child| child.band == band) {
                continue;
            }
        } else if crate::tools::routine::placement_for_step(&step)? != band {
            continue;
        }
        let precondition = if step.tool == "routine" {
            None
        } else {
            crate::tools::routine::command_precondition(&step.args)?
        };
        if let Some(precondition) = precondition {
            result.operation_count += 1;
            let probe = crate::bands::compare::execute_command_precondition(
                &step,
                &precondition,
                manifest,
                module_dir,
            )?;
            if !probe.ok {
                result.ok = false;
                let probe_error = probe
                    .command
                    .as_ref()
                    .map(|r| format!("exit_code={} stderr={}", r.code, r.stderr))
                    .unwrap_or_else(|| probe.message.clone());
                let signal = format!(
                    "step_id={} state=blocked probe_error={probe_error}",
                    step.step_id
                );
                result.first_missing_signal.get_or_insert(signal.clone());
                result.placements.push(serde_json::json!({"step_id":step.step_id,"tool":step.tool,"permutation":step.permutation,"band":format!("{:?}", band),"status":"blocked","module":manifest.id}));
                break;
            }
        }
        result.operation_count += 1;
        let outcome = if step.tool == "routine" {
            crate::tools::routine::execute_routine(
                &step,
                manifest,
                module_dir,
                software_authorization,
                package_authority,
                mode_apply,
                invocation,
                Some(routine_states),
                band,
                projected_routines
                    .get(&step.step_id)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            )?
        } else {
            crate::tools::routine::execute_validated_step(
                &step,
                manifest,
                module_dir,
                software_authorization,
                package_authority,
                module_changed_before_step || result.changed,
                invocation,
            )?
        };
        if step.tool == "routine" {
            let routine = routine_states
                .get(step.step_id.as_str())
                .ok_or_else(|| "routine-state-missing".to_string())?;
            for child in projected_routines
                .get(&step.step_id)
                .map(Vec::as_slice)
                .unwrap_or(&[])
            {
                if child.band == band {
                    let receipt = routine
                        .children
                        .iter()
                        .find(|r| {
                            r.get("name").and_then(Value::as_str) == Some(child.name.as_str())
                        })
                        .ok_or_else(|| format!("routine-child-receipt-missing-{}", child.name))?;
                    let status = receipt
                        .get("state")
                        .and_then(Value::as_str)
                        .unwrap_or("failed");
                    result.placements.push(serde_json::json!({"step_id":child.name,"tool":child.tool,"permutation":child.permutation,"band":format!("{:?}",band),"status":status,"ok":receipt.get("ok").and_then(Value::as_bool).unwrap_or(false),"changed":receipt.get("changed").and_then(Value::as_bool).unwrap_or(false),"module":manifest.id,"routine":step.step_id}));
                }
            }
        } else {
            result.placements.push(serde_json::json!({"step_id":step.step_id,"tool":step.tool,"permutation":step.permutation,"band":format!("{:?}", band),"status":if outcome.ok {"completed"} else {"failed"},"module":manifest.id}));
        }
        result.changed |= outcome.changed;
        if !outcome.ok {
            result.ok = false;
            if result.first_missing_signal.is_none() {
                result.first_missing_signal = Some(format!(
                    "step_id={} defect={}",
                    step.step_id, outcome.message
                ));
            }
            if step.on_failure == OnFailure::Stop {
                break;
            }
        }
    }
    Ok(result)
}

pub(crate) fn enter(enter: &mut impl FnMut(Band) -> Result<(), String>) -> Result<(), String> {
    enter(Band::BackfillFiles)
}

pub(crate) fn lower_service_runtime_steps(manifest: &mut LadderManifest) {
    for step in &mut manifest.ladder {
        if step.tool != "routine" || step.permutation != "execute" {
            continue;
        }
        let Some(index) = step
            .steps
            .iter()
            .position(|c| c.name == "managed-files" && c.tool == "files")
        else {
            continue;
        };
        let original = step.steps[index].clone();
        let declarations = original
            .args
            .get("files")
            .or_else(|| original.args.get("managed_files"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut configuration = Vec::new();
        let mut replacement = Vec::with_capacity(declarations.len() + 1);
        for declaration in declarations {
            let Some(path) = declaration.get("path").and_then(Value::as_str) else {
                continue;
            };
            if matches!(
                crate::tools::files::classify_target(Path::new(path)),
                crate::tools::files::TargetClass::Config
            ) {
                configuration.push(declaration);
                continue;
            }
            let mut args = BTreeMap::new();
            args.insert("path".into(), Value::String(path.into()));
            args.insert(
                "declared_bytes".into(),
                declaration
                    .get("content")
                    .cloned()
                    .unwrap_or_else(|| Value::String(String::new())),
            );
            for key in ["mode", "uid", "gid"] {
                if let Some(value) = declaration.get(key) {
                    args.insert(key.into(), value.clone());
                }
            }
            replacement.push(RoutineStep {
                name: format!("managed-file-{}", replacement.len()),
                tool: "place-file".into(),
                permutation: Some("place".into()),
                args,
                extra: BTreeMap::new(),
            });
        }
        if let Some(source) = original.args.get("caduceus_profile_source") {
            if let Some(path) = source.get("path").and_then(Value::as_str) {
                if matches!(
                    crate::tools::files::classify_target(Path::new(path)),
                    crate::tools::files::TargetClass::Config
                ) {
                    configuration.push(serde_json::json!({
                        "path": path,
                        "content": "",
                        "mode": source.get("mode").cloned().unwrap_or(Value::Null)
                    }));
                }
            }
        }
        // Keep the proposal after the retained RestartServices suffix. The
        // place-file children remain the BackfillFiles mutation lane.
        let proposal = if !configuration.is_empty() {
            let mut config = original;
            config
                .args
                .insert("files".into(), Value::Array(configuration));
            config.tool = "files".into();
            config.permutation = Some("managed-files".into());
            Some(config)
        } else {
            None
        };
        step.steps.splice(index..=index, replacement);
        if let Some(proposal) = proposal {
            step.steps.push(proposal);
        }
    }
}

use crate::receipts::event;
use crate::{LoadedModule, Profile, ProfileProjection, UpdateMode};
use std::collections::BTreeSet;
use std::fs::File;
pub(crate) fn execute_manifest_modules(
    profile: &Profile,
    receipt_dir: &Path,
    mode: UpdateMode,
    mode_apply: bool,
    disabled_modules: &BTreeSet<String>,
    projection: &ProfileProjection,
    states: &mut BTreeMap<String, ModuleExecution>,
    routines: &mut BTreeMap<String, BTreeMap<String, crate::ModuleWalkState>>,
    halted: &mut BTreeSet<String>,
    module_count: &mut usize,
    operation_count: &mut usize,
    changed: &mut bool,
    ok: &mut bool,
    first_missing_signal: &mut String,
    events: &mut File,
) -> Result<(), String> {
    for module_id in &profile.modules {
        if disabled_modules.contains(module_id) || halted.contains(module_id) {
            continue;
        }
        let Some(projected) = projection.modules.get(module_id) else {
            let err = projection
                .errors
                .get(module_id)
                .cloned()
                .unwrap_or_else(|| format!("module-not-in-projection-{module_id}"));
            let state = states.entry(module_id.clone()).or_insert(ModuleExecution {
                ok: true,
                changed: false,
                operation_count: 0,
                first_missing_signal: None,
                placements: Vec::new(),
            });
            state.ok = false;
            state.first_missing_signal.get_or_insert(err.clone());
            halted.insert(module_id.clone());
            *ok = false;
            if *first_missing_signal == "none" {
                *first_missing_signal = err.clone();
            }
            event(events, "module-rejected", false, &err)?;
            continue;
        };
        *module_count = profile.modules.len();
        let result = match &projected.loaded {
            LoadedModule::Ladder(manifest) => execute_files(
                manifest,
                &receipt_dir.join("modules").join(module_id),
                mode.software_authorization(),
                profile.package_authority.as_ref(),
                mode.invocation(),
                mode_apply,
                states.get(module_id).map(|s| s.changed).unwrap_or(false),
                routines.entry(module_id.clone()).or_default(),
                &projected.steps,
                &projected.routines,
            ),
            LoadedModule::Sidecar(_) => Err("module-sidecar-not-band-executable".to_string()),
        };
        let state = states.entry(module_id.clone()).or_insert(ModuleExecution {
            ok: true,
            changed: false,
            operation_count: 0,
            first_missing_signal: None,
            placements: Vec::new(),
        });
        match result {
            Ok(part) => {
                state.operation_count += part.operation_count;
                state.changed |= part.changed;
                state.placements.extend(part.placements);
                *operation_count += part.operation_count;
                *changed |= part.changed;
                if !part.ok {
                    state.ok = false;
                    state.first_missing_signal = state
                        .first_missing_signal
                        .take()
                        .or(part.first_missing_signal);
                    *ok = false;
                    halted.insert(module_id.clone());
                    if *first_missing_signal == "none" {
                        *first_missing_signal = state
                            .first_missing_signal
                            .clone()
                            .unwrap_or_else(|| format!("module-failed-{module_id}"));
                    }
                }
                event(
                    events,
                    "module-band",
                    part.ok,
                    &format!(
                        "{} band=BackfillFiles steps={}",
                        module_id, part.operation_count
                    ),
                )?;
            }
            Err(err) => {
                state.ok = false;
                state.first_missing_signal.get_or_insert(err.clone());
                halted.insert(module_id.clone());
                *ok = false;
                if *first_missing_signal == "none" {
                    *first_missing_signal = err.clone();
                }
                event(events, "module-rejected", false, &err)?;
            }
        }
    }
    Ok(())
}


pub(crate) fn execute_routine_child(
    tool: &str,
    requested_permutation: Option<&str>,
    args: &std::collections::BTreeMap<String, serde_json::Value>,
    manifest: &crate::ladder::LadderManifest,
    receipt_dir: &std::path::Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<(crate::OperationOutcome, std::collections::BTreeMap<String, serde_json::Value>), String> {
    let contract = crate::tools::get(tool).ok_or_else(|| format!("routine-tool-not-found-{tool}"))?;
    let permutation = requested_permutation.and_then(|name| contract.permutation(name)).or_else(|| contract.permutations.first()).ok_or_else(|| format!("routine-tool-no-permutation-{tool}"))?;
    std::fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let name = tool.to_string();
    match tool {
        "place-file" => {
            let path = Path::new(
                args.get("path")
                    .and_then(Value::as_str)
                    .ok_or("place-file-path-missing")?,
            );
            let source = args.get("source_path").and_then(Value::as_str);
            let declared = args.get("declared_bytes").and_then(Value::as_str);
            if source.is_some() == declared.is_some() {
                return Err("place-file-requires-exactly-one-source".into());
            }
            let bytes = if let Some(source) = source {
                std::fs::read(source).map_err(|e| format!("place-file-source-read:{e}"))?
            } else {
                declared.unwrap().as_bytes().to_vec()
            };
            let default_backup = receipt_dir.join("backups/prior-binary");
            let request = crate::place_file::PlaceFileRequest {
                path,
                declared_bytes: &bytes,
                mode: args.get("mode").and_then(Value::as_u64).map(|x| x as u32),
                ownership: crate::place_file::DeclaredOwnership {
                    uid: args.get("uid").and_then(Value::as_u64).map(|x| x as u32),
                    gid: args.get("gid").and_then(Value::as_u64).map(|x| x as u32),
                },
                backup: args
                    .get("backup_path")
                    .and_then(Value::as_str)
                    .map(Path::new)
                    .map(crate::place_file::BackupPolicy::To)
                    .unwrap_or(crate::place_file::BackupPolicy::To(&default_backup)),
                invocation: invocation,
            };
            let placed = crate::place_file::execute(request)?;
            let changed = apply && placed.movement.changed();
            if permutation.name == "binary-promotion" {
                if let Some(legacy_name) = args
                    .get("legacy_binary_install_receipt")
                    .and_then(Value::as_str)
                {
                    let mut legacy = serde_json::json!({"schema":"harmonia.service-runtime.binary-install.v1","artifact":source.unwrap_or(""),"install_bin":path,"apply":apply,"ok":placed.receipt.ok,"changed":changed,"state":if changed { "binary-swapped" } else { "converged-quiet" }});
                    if !changed {
                        if let Some(object) = legacy.as_object_mut() {
                            object.remove("artifact");
                            object.insert(
                                "reason".into(),
                                serde_json::json!("source-sha-gate-preserved-installed-binary"),
                            );
                        }
                    }
                    crate::write_json(&receipt_dir.join(format!("{legacy_name}.json")), &legacy)?;
                }
            }
            crate::write_json(
                &receipt_dir.join(format!("{name}.json")),
                &serde_json::json!({"schema":"harmonia.routine_tool.receipt.v1","ok":placed.receipt.ok,"changed":changed,"skipped":!apply,"effect":placed.receipt,"movement":{"bytes":placed.movement.bytes,"mode":placed.movement.mode,"owner":placed.movement.owner,"created":placed.movement.created,"backed_up":placed.movement.backed_up}}),
            )?;
            Ok((
                OperationOutcome {
                    ok: true,
                    changed,
                    skipped: !apply,
                    message: "place-file".into(),
                    command: None,
                },
                [
                    ("path".into(), serde_json::json!(path)),
                    ("changed".into(), serde_json::json!(changed)),
                    (
                        "sha256".into(),
                        serde_json::json!(crate::atoms::file_sha256(&bytes)),
                    ),
                ]
                .into_iter()
                .collect(),
            ))
        }
        "backfill-file" => {
            let path = Path::new(
                args.get("path")
                    .and_then(Value::as_str)
                    .ok_or("backfill-file-path-missing")?,
            );
            let bytes = args
                .get("declared_bytes")
                .and_then(Value::as_str)
                .ok_or("backfill-file-bytes-missing")?
                .as_bytes();
            let request = crate::backfill_file::BackfillFileRequest {
                path,
                declared_bytes: bytes,
                mode: args.get("mode").and_then(Value::as_u64).map(|v| v as u32),
                ownership: crate::backfill_file::DeclaredOwnership {
                    uid: args.get("uid").and_then(Value::as_u64).map(|v| v as u32),
                    gid: args.get("gid").and_then(Value::as_u64).map(|v| v as u32),
                },
                backup: crate::backfill_file::BackupPolicy::None,
                invocation,
            };
            let out = crate::backfill_file::execute(request)?;
            crate::write_json(
                &receipt_dir.join(format!("{name}.json")),
                &serde_json::json!({"schema":"harmonia.routine_tool.receipt.v1","ok":out.receipt.ok,"changed":out.movement.changed(),"skipped":!apply}),
            )?;
            Ok((
                OperationOutcome {
                    ok: out.receipt.ok,
                    changed: apply && out.movement.changed(),
                    skipped: !apply,
                    message: "backfill-file".into(),
                    command: None,
                },
                [
                    ("path".into(), serde_json::json!(path)),
                    (
                        "sha256".into(),
                        serde_json::json!(crate::atoms::file_sha256(bytes)),
                    ),
                ]
                .into_iter()
                .collect(),
            ))
        }
        _ => Err(format!("routine-tool-not-summonable-{tool}")),
    }
}
