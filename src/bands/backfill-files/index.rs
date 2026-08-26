use crate::tools::ladder::{LadderManifest, OnFailure, ProjectedRoutineChild, RoutineStep, ValidatedStep};
use crate::ModuleExecution;
use crate::OperationOutcome;
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
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
    mode_apply: bool,
    module_changed_before_step: bool,
    routine_states: &mut BTreeMap<String, crate::ModuleWalkState>,
    projected_steps: &[ValidatedStep],
    projected_routines: &BTreeMap<String, Vec<ProjectedRoutineChild>>,
) -> Result<ModuleExecution, String> {
    let band = crate::bands::Band::BackfillFiles;
    let steps = projected_steps.to_vec();
    crate::tools::files::preflight_file_targets(manifest, &steps, projected_routines, Some(band))?;
    crate::atoms::attest::prepare_receipt_parent(module_dir)?;
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
                None,
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

pub(crate) fn lower_service_runtime_steps(manifest: &mut LadderManifest) -> Result<(), String> {
    for step in &mut manifest.ladder {
        if step.tool != "routine" || step.permutation != "execute" {
            continue;
        }
        let Some(index) = step
            .steps
            .iter()
            .position(|child| child.name == "managed-files" && child.tool == "files")
        else {
            for child in &mut step.steps {
                if matches!(
                    child.name.as_str(),
                    "service-daemon-reload"
                        | "service-enable"
                        | "service-restart"
                        | "service-active"
                ) {
                    child
                        .args
                        .insert("managed_files_changed".into(), Value::Bool(false));
                }
            }
            continue;
        };
        let original = step.steps[index].clone();
        let declarations = original
            .args
            .get("files")
            .or_else(|| original.args.get("managed_files"))
            .and_then(Value::as_array)
            .ok_or_else(|| "managed-files-declaration-array-missing".to_string())?
            .clone();
        let mut configuration = Vec::new();
        let mut replacement = Vec::new();
        for (ordinal, declaration) in declarations.into_iter().enumerate() {
            let object = declaration
                .as_object()
                .ok_or_else(|| format!("managed-file-declaration-{ordinal}-not-object"))?;
            let category = match object.get("category").and_then(Value::as_str) {
                None | Some("known-good") => "known-good",
                Some("interactable") => "interactable",
                Some(category) => {
                    return Err(format!(
                        "managed-file-declaration-{ordinal}-category-unsupported-{category}"
                    ));
                }
            };
            let known_good = category == "known-good";
            let operation = object
                .get("operation")
                .and_then(Value::as_str)
                .unwrap_or("place");
            let Some(path) = object.get("path").and_then(Value::as_str) else {
                return Err(format!("managed-file-declaration-{ordinal}-path-missing"));
            };
            if path.is_empty() {
                return Err(format!("managed-file-declaration-{ordinal}-path-invalid"));
            }
            if category == "interactable" {
                let mut declaration = declaration;
                if let Some(object) = declaration.as_object_mut() {
                    object.insert("category".into(), Value::String(category.into()));
                }
                configuration.push(declaration);
                continue;
            }
            if matches!(operation, "present" | "hotfix" | "untouchable")
                || (operation == "place"
                    && !known_good
                    && matches!(
                        crate::tools::files::classify_target(Path::new(path)),
                        crate::tools::files::TargetClass::Config
                    ))
            {
                let mut declaration = declaration;
                configuration.push(declaration);
                continue;
            }
            if operation == "place" {
                if !known_good
                    && matches!(
                        crate::tools::files::classify_target(Path::new(path)),
                        crate::tools::files::TargetClass::Config
                    )
                {
                    configuration.push(declaration);
                    continue;
                }
                let mut args = BTreeMap::new();
                args.insert("path".into(), Value::String(path.into()));
                args.insert(
                    "declared_bytes".into(),
                    object
                        .get("content")
                        .cloned()
                        .unwrap_or_else(|| Value::String(String::new())),
                );
                args.insert("xattrs".into(), Value::Object(serde_json::Map::new()));
                args.insert("no_follow".into(), Value::Bool(true));
                args.insert("collision_policy".into(), Value::String("refuse".into()));
                args.insert("rollback_policy".into(), Value::String("exact".into()));
                for key in ["mode", "uid", "gid"] {
                    if let Some(value) = object.get(key) {
                        args.insert(key.into(), value.clone());
                    }
                }
                replacement.push(RoutineStep {
                    name: format!("managed-place-{ordinal}"),
                    tool: "place-file".into(),
                    permutation: Some("place".into()),
                    args,
                    extra: BTreeMap::from([(
                        "canonical_atom".into(),
                        Value::String("place-file:place".into()),
                    )]),
                });
                continue;
            }
            let xattrs = object
                .get("xattrs")
                .ok_or_else(|| format!("managed-file-declaration-{ordinal}-xattrs-missing"))?;
            let no_follow = object
                .get("no_follow")
                .and_then(Value::as_bool)
                .ok_or_else(|| format!("managed-file-declaration-{ordinal}-no_follow-missing"))?;
            let collision_policy = object
                .get("collision_policy")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!("managed-file-declaration-{ordinal}-collision_policy-missing")
                })?;
            let rollback_policy = object
                .get("rollback_policy")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!("managed-file-declaration-{ordinal}-rollback_policy-missing")
                })?;
            if !no_follow {
                return Err(format!(
                    "managed-file-declaration-{ordinal}-no_follow-unsupported-false"
                ));
            }
            if collision_policy != "refuse" {
                return Err(format!("managed-file-declaration-{ordinal}-collision_policy-unsupported-{collision_policy}"));
            }
            if !xattrs.as_object().is_some_and(|object| object.is_empty()) {
                return Err(format!(
                    "managed-file-declaration-{ordinal}-xattrs-unsupported"
                ));
            }
            if rollback_policy != "exact" {
                return Err(format!("managed-file-declaration-{ordinal}-rollback_policy-unsupported-{rollback_policy}"));
            }
            let kind = operation;
            let (tool, permutation) = match kind {
                "place" => ("place-file", "place"),
                "backfill" => ("backfill-file", "backfill"),
                "remove" => ("remove-file", "remove-file"),
                "symlink" => ("files", "symlink-converge"),
                other => {
                    return Err(format!(
                        "managed-file-declaration-{ordinal}-operation-unsupported-{other}"
                    ))
                }
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
            args.insert("xattrs".into(), Value::Object(serde_json::Map::new()));
            args.insert("no_follow".into(), Value::Bool(true));
            args.insert("collision_policy".into(), Value::String("refuse".into()));
            args.insert("rollback_policy".into(), Value::String("exact".into()));
            match kind {
                "place" | "backfill" => {
                    let bytes = object
                        .get("content")
                        .or_else(|| object.get("declared_bytes"));
                    let source = object.get("source_path");
                    if kind == "backfill" && source.is_some() {
                        return Err(format!(
                            "managed-file-declaration-{ordinal}-backfill-source_path-unsupported"
                        ));
                    }
                    if bytes.is_none() == source.is_none() {
                        return Err(format!(
                            "managed-file-declaration-{ordinal}-source-tail-ambiguous"
                        ));
                    }
                    if let Some(value) = bytes {
                        args.insert("declared_bytes".into(), value.clone());
                    }
                    if let Some(value) = source {
                        args.insert("source_path".into(), value.clone());
                    }
                    for key in ["mode", "uid", "gid"] {
                        let value = object.get(key).ok_or_else(|| {
                            format!("managed-file-declaration-{ordinal}-{key}-missing")
                        })?;
                        args.insert(key.into(), value.clone());
                    }
                }
                "remove" => {}
                "symlink" => {
                    for key in [
                        "source",
                        "target",
                        "required_source_kind",
                        "conflict_policy",
                    ] {
                        let value = object.get(key).ok_or_else(|| {
                            format!("managed-file-declaration-{ordinal}-{key}-missing")
                        })?;
                        args.insert(key.into(), value.clone());
                    }
                }
                _ => unreachable!(),
            }
            replacement.push(RoutineStep {
                name: format!("managed-{kind}-{ordinal}"),
                tool: tool.into(),
                permutation: Some(permutation.into()),
                args,
                extra: BTreeMap::from([(
                    "canonical_atom".into(),
                    Value::String(format!("{tool}:{permutation}")),
                )]),
            });
        }
        step.steps.splice(index..=index, replacement);
        if !configuration.is_empty() {
            let mut proposal = original;
            proposal
                .args
                .insert("files".into(), Value::Array(configuration));
            proposal.name = "managed-place-0".into();
            proposal.tool = "files".into();
            proposal.permutation = Some("managed-files".into());
            // Keep the configuration-only proposal before the service epilogue;
            // it is not an executable managed-file producer for those consumers.
            let service_index = step
                .steps
                .iter()
                .position(|child| child.name == "service-daemon-reload")
                .unwrap_or(step.steps.len());
            step.steps.insert(service_index, proposal);
            for child in &mut step.steps {
                if matches!(
                    child.name.as_str(),
                    "service-daemon-reload"
                        | "service-enable"
                        | "service-restart"
                        | "service-active"
                ) {
                    child.args.insert(
                        "managed_files_changed".into(),
                        serde_json::json!({"from":"managed-files.changed"}),
                    );
                }
            }
        }
        // A stamp is valid when the exact managed-files producer is declared in
        // BackfillFiles; its changed state is carried to RestartServices consumers.
        let same_band_managed_file_producer = step.steps.iter().any(|child| {
            let managed_identity = ((child.name == "managed-files"
                || child.name.starts_with("managed-place-"))
                && child.tool == "files"
                && child.permutation.as_deref() == Some("managed-files"))
                || (child.name.starts_with("managed-place-")
                    && child.tool == "place-file"
                    && child.permutation.as_deref() == Some("place"))
                || (child.name.starts_with("managed-backfill-")
                    && child.tool == "backfill-file"
                    && child.permutation.as_deref() == Some("backfill"))
                || (child.name.starts_with("managed-remove-")
                    && child.tool == "remove-file"
                    && child.permutation.as_deref() == Some("remove-file"))
                || (child.name.starts_with("managed-symlink-")
                    && child.tool == "files"
                    && child.permutation.as_deref() == Some("symlink-converge"));
            let placement = child
                .permutation
                .as_deref()
                .and_then(|permutation| {
                    crate::tools::get(&child.tool).and_then(|tool| tool.permutation(permutation))
                })
                .and_then(|permutation| permutation.placement)
                .map(crate::tools::Placement::band);
            managed_identity && placement == Some(crate::bands::Band::BackfillFiles)
        });
        for child in &mut step.steps {
            if matches!(
                child.name.as_str(),
                "service-daemon-reload" | "service-enable" | "service-restart" | "service-active"
            ) {
                child.args.insert(
                    "managed_files_changed".into(),
                    if same_band_managed_file_producer {
                        serde_json::json!({"from":"managed-files.changed"})
                    } else {
                        Value::Bool(false)
                    },
                );
            }
        }
    }
    Ok(())
}

use crate::receipts::event;
use crate::{LoadedModule, Profile, ProfileProjection, UpdateMode};
use std::collections::BTreeSet;
use std::fs::File;
pub(crate) fn execute_manifest_modules(
    profile: &Profile,
    receipt_dir: &Path,
    mode: &UpdateMode,
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
    manifest: &crate::tools::ladder::LadderManifest,
    receipt_dir: &std::path::Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<
    (
        crate::OperationOutcome,
        std::collections::BTreeMap<String, serde_json::Value>,
    ),
    String,
> {
    let contract =
        crate::tools::get(tool).ok_or_else(|| format!("routine-tool-not-found-{tool}"))?;
    let permutation = requested_permutation
        .and_then(|name| contract.permutation(name))
        .or_else(|| contract.permutations.first())
        .ok_or_else(|| format!("routine-tool-no-permutation-{tool}"))?;
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
    if matches!(tool, "place-file" | "backfill-file" | "remove-file") {
        if args.get("no_follow").and_then(Value::as_bool) != Some(true) {
            return Err(format!("{tool}-no_follow-unsupported"));
        }
        if args.get("collision_policy").and_then(Value::as_str) != Some("refuse") {
            return Err(format!("{tool}-collision-policy-unsupported"));
        }
        if args.get("rollback_policy").and_then(Value::as_str) != Some("exact") {
            return Err(format!("{tool}-rollback-policy-unsupported"));
        }
        if !args.get("xattrs").is_some_and(Value::is_object) {
            return Err(format!("{tool}-xattrs-invalid"));
        }
        if !args
            .get("xattrs")
            .and_then(Value::as_object)
            .is_some_and(|x| x.is_empty())
        {
            return Err(format!("{tool}-xattrs-unsupported"));
        }
    }
    let name = tool.to_string();
    match tool {
        "files" if permutation.name == "managed-files" => {
            let step = crate::tools::ladder::ValidatedStep {
                step_id: "managed-files".into(),
                tool: "files".into(),
                permutation: "managed-files".into(),
                args: args.clone(),
                on_failure: crate::tools::ladder::OnFailure::Stop,
            };
            // Managed-file configuration remains proposal-only for routine children.
            let out = match crate::tools::files::managed_files_step(
                &step,
                manifest,
                receipt_dir,
                apply,
                invocation,
            ) {
                Ok(out) => out,
                Err(error) if error == "files-act-did-not-converge" => crate::OperationOutcome {
                    ok: true,
                    changed: true,
                    skipped: true,
                    message: "files-proposal-observed".to_string(),
                    command: None,
                },
                Err(error) => return Err(error),
            };
            Ok((out, std::collections::BTreeMap::new()))
        }
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
            // Binary promotion is content-addressed: an identical installed
            // image is already converged, even if metadata differs.
            let binary_current = if permutation.name == "binary-promotion" {
                source
                    .map(|source| {
                        crate::bands::restart_services::binary_content_matches(
                            Path::new(source),
                            path,
                        )
                    })
                    .transpose()?
                    .unwrap_or(false)
            } else {
                false
            };
            if binary_current {
                let sha256 = crate::atoms::file_sha256(&bytes);
                crate::write_json(
                    &receipt_dir.join(format!("{name}.json")),
                    &serde_json::json!({"schema":"harmonia.routine_tool.receipt.v1","ok":true,"changed":false,"skipped":!apply,"message":"binary-promotion-current","movement":{"bytes":false,"mode":false,"owner":false,"created":false,"backed_up":null}}),
                )?;
                return Ok((
                    OperationOutcome {
                        ok: true,
                        changed: false,
                        skipped: !apply,
                        message: "binary-promotion-current".into(),
                        command: None,
                    },
                    [
                        ("path".into(), serde_json::json!(path)),
                        ("installed_path".into(), serde_json::json!(path)),
                        ("changed".into(), serde_json::json!(false)),
                        ("sha256".into(), serde_json::json!(sha256)),
                    ]
                    .into_iter()
                    .collect(),
                ));
            }
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
        "remove-file" => {
            let path = Path::new(
                args.get("path")
                    .and_then(Value::as_str)
                    .ok_or("remove-file-path-missing")?,
            );
            let root = path.parent().ok_or("remove-file-parent-missing")?;
            let name = path
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or("remove-file-name-missing")?
                .to_string();
            let out = crate::atoms::r#do::remove_file_organ::execute(
                root,
                &[name],
                receipt_dir,
                &tool.to_string(),
                apply,
                invocation,
                args.get("no_follow")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                args.get("collision_policy")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                args.get("rollback_policy")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            )?;
            Ok((
                crate::OperationOutcome {
                    ok: out.ok,
                    changed: out.changed,
                    skipped: !apply,
                    message: out.message,
                    command: None,
                },
                [
                    ("path".into(), serde_json::json!(path)),
                    ("changed".into(), serde_json::json!(out.changed)),
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
