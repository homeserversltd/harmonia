use serde_json::Value;
use std::fs::{self};
use std::path::Path;

use crate::ladder::{
    CommandPrecondition, LadderManifest, LadderStep, LadderValidationError, OnFailure,
};

use crate::tools::files::structural_file_blocker;
use crate::{tools, OperationOutcome};
use serde_json::{json, Map};
use std::collections::BTreeMap;

pub(crate) fn resolve_args(
    args: &BTreeMap<String, Value>,
    constants: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, Value>, String> {
    let mut out = BTreeMap::new();
    for (key, value) in args {
        out.insert(key.clone(), resolve_value(value, constants)?);
    }
    Ok(out)
}

fn resolve_value(value: &Value, constants: &BTreeMap<String, Value>) -> Result<Value, String> {
    match value {
        Value::String(s) => {
            if let Some(name) = s.strip_prefix("$constants.") {
                constants
                    .get(name)
                    .cloned()
                    .ok_or_else(|| format!("dangling-constant-{}", name))
            } else if let Some(name) = s.strip_prefix("${").and_then(|rest| rest.strip_suffix('}'))
            {
                constants
                    .get(name)
                    .cloned()
                    .ok_or_else(|| format!("dangling-constant-{}", name))
            } else {
                Ok(value.clone())
            }
        }
        Value::Array(items) => Ok(Value::Array(
            items
                .iter()
                .map(|item| resolve_value(item, constants))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, item) in map {
                out.insert(key.clone(), resolve_value(item, constants)?);
            }
            Ok(Value::Object(out))
        }
        _ => Ok(value.clone()),
    }
}

pub(crate) fn validate_args(
    step_id: &str,
    permutation: &tools::ToolPermutation,
    args: &BTreeMap<String, Value>,
) -> Result<(), LadderValidationError> {
    for arg in permutation.args {
        if arg.required && !args.contains_key(arg.name) {
            return Err(LadderValidationError {
                step_id: step_id.into(),
                defect: format!("missing-argument-{}", arg.name),
            });
        }
        if let Some(value) = args.get(arg.name) {
            if value
                .as_object()
                .is_some_and(|map| map.len() == 1 && map.contains_key("from"))
            {
                continue;
            }
            if !arg.kind.matches(value) {
                return Err(LadderValidationError {
                    step_id: step_id.into(),
                    defect: format!("type-mismatch-{}-expected-{}", arg.name, arg.kind.name()),
                });
            }
        }
    }
    Ok(())
}

pub(crate) fn command_precondition(
    args: &BTreeMap<String, Value>,
) -> Result<Option<CommandPrecondition>, String> {
    let Some(value) = args.get("precondition") else {
        return Ok(None);
    };
    let precondition = serde_json::from_value(value.clone())
        .map_err(|error| format!("precondition-invalid: {error}"))?;
    Ok(Some(precondition))
}

pub(crate) fn validate_command_precondition(
    step_id: &str,
    tool: &str,
    permutation: &str,
    args: &BTreeMap<String, Value>,
) -> Result<(), LadderValidationError> {
    let Some(precondition) =
        command_precondition(args).map_err(|defect| LadderValidationError {
            step_id: step_id.into(),
            defect,
        })?
    else {
        return Ok(());
    };
    if tool != "command" || permutation != "capture" {
        return Err(LadderValidationError {
            step_id: step_id.into(),
            defect: "precondition-requires-command-capture".into(),
        });
    }
    if precondition.program.trim().is_empty() {
        return Err(LadderValidationError {
            step_id: step_id.into(),
            defect: "precondition-program-empty".into(),
        });
    }
    if precondition.timeout_secs == Some(0) {
        return Err(LadderValidationError {
            step_id: step_id.into(),
            defect: "precondition-timeout-secs-zero".into(),
        });
    }
    Ok(())
}

pub(crate) fn validate_tool_semantics(
    step_id: &str,
    tool: &str,
    permutation: &str,
    args: &BTreeMap<String, Value>,
) -> Result<(), LadderValidationError> {
    match (tool, permutation) {
        ("systemd", "enable-first-present-now") => tools::systemd::validate_candidate_units(args)
            .map_err(|defect| LadderValidationError {
                step_id: step_id.into(),
                defect,
            }),
        ("service-runtime", "converge") => tools::service_runtime::validate_ladder_args(args)
            .map_err(|defect| LadderValidationError {
                step_id: step_id.into(),
                defect,
            }),
        ("aur", permutation) => {
            tools::aur::validate_ladder_args(permutation, args).map_err(|defect| {
                LadderValidationError {
                    step_id: step_id.into(),
                    defect,
                }
            })
        }
        ("household-time", permutation) => {
            tools::household_time::validate_ladder_args(permutation, args).map_err(|defect| {
                LadderValidationError {
                    step_id: step_id.into(),
                    defect,
                }
            })
        }
        ("files", "executable-present") => tools::files::validate_executable_present_args(args)
            .map_err(|defect| LadderValidationError {
                step_id: step_id.into(),
                defect,
            }),
        ("files", "symlink-converge") => tools::files::validate_symlink_converge_args(args)
            .map_err(|defect| LadderValidationError {
                step_id: step_id.into(),
                defect,
            }),
        ("venv", "converge") => {
            tools::venv::validate_ladder_args(args).map_err(|defect| LadderValidationError {
                step_id: step_id.into(),
                defect,
            })
        }
        _ => Ok(()),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ValidatedStep {
    pub step_id: String,
    pub tool: String,
    pub permutation: String,
    pub args: BTreeMap<String, Value>,
    pub on_failure: OnFailure,
}

#[derive(Debug, Clone)]
pub(crate) struct ProjectedRoutineChild {
    pub name: String,
    pub tool: String,
    pub permutation: String,
    pub args: BTreeMap<String, Value>,
    pub on_failure: OnFailure,
    pub band: crate::bands::Band,
}

pub(crate) fn project_routine_children(
    step: &LadderStep,
    constants: &BTreeMap<String, Value>,
) -> Result<Vec<ProjectedRoutineChild>, LadderValidationError> {
    step.steps
        .iter()
        .map(|child| {
            let contract = tools::get(&child.tool).ok_or_else(|| LadderValidationError {
                step_id: step.step_id.clone(),
                defect: format!("routine-tool-not-found-{}", child.tool),
            })?;
            let permutation = child
                .permutation
                .as_deref()
                .or_else(|| contract.permutations.first().map(|p| p.name))
                .unwrap_or("");
            let declaration =
                contract
                    .permutation(permutation)
                    .ok_or_else(|| LadderValidationError {
                        step_id: step.step_id.clone(),
                        defect: format!(
                            "routine-undeclared-permutation-{}-{}",
                            child.tool, permutation
                        ),
                    })?;
            let args =
                resolve_args(&child.args, constants).map_err(|defect| LadderValidationError {
                    step_id: step.step_id.clone(),
                    defect,
                })?;
            validate_args(&step.step_id, declaration, &args)?;
            validate_tool_semantics(&step.step_id, &child.tool, permutation, &args)?;
            validate_command_precondition(&step.step_id, &child.tool, permutation, &args)?;
            let band = declaration
                .placement
                .map(crate::tools::Placement::band)
                .ok_or_else(|| LadderValidationError {
                    step_id: step.step_id.clone(),
                    defect: format!(
                        "unknown-tool-band tool={} permutation={}",
                        child.tool, permutation
                    ),
                })?;
            Ok(ProjectedRoutineChild {
                name: child.name.clone(),
                tool: child.tool.clone(),
                permutation: permutation.into(),
                args,
                on_failure: step.on_failure,
                band,
            })
        })
        .collect()
}

pub(crate) fn placement_for_step(step: &ValidatedStep) -> Result<crate::bands::Band, String> {
    if step.tool == "routine" {
        return Err(format!("routine-has-no-band step_id={}", step.step_id));
    }
    let permutation = tools::get(&step.tool)
        .and_then(|tool| tool.permutation(&step.permutation))
        .ok_or_else(|| {
            format!(
                "unknown-tool-band tool={} permutation={}",
                step.tool, step.permutation
            )
        })?;
    permutation
        .placement
        .map(crate::tools::Placement::band)
        .ok_or_else(|| {
            format!(
                "unknown-tool-band tool={} permutation={}",
                step.tool, step.permutation
            )
        })
}

pub(crate) fn project_manifest_routines(
    manifest: &LadderManifest,
    steps: &[ValidatedStep],
) -> Result<BTreeMap<String, Vec<ProjectedRoutineChild>>, String> {
    let mut projected = BTreeMap::new();
    for step in steps.iter().filter(|step| step.tool == "routine") {
        let source = manifest
            .ladder
            .iter()
            .find(|candidate| candidate.step_id == step.step_id)
            .ok_or_else(|| format!("routine-step-missing-{}", step.step_id))?;
        let children = project_routine_children(source, &manifest.constants)
            .map_err(|error| format!("module-invalid {}", error.first_missing_signal()))?;
        projected.insert(step.step_id.clone(), children);
    }
    Ok(projected)
}

fn execute_routine_tool(
    tool: &str,
    requested_permutation: Option<&str>,
    args: &std::collections::BTreeMap<String, serde_json::Value>,
    manifest: &crate::ladder::LadderManifest,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<
    (
        OperationOutcome,
        std::collections::BTreeMap<String, serde_json::Value>,
    ),
    String,
> {
    if tool == "files" && requested_permutation == Some("managed-files") {
        let step = ValidatedStep {
            step_id: "managed-files".into(),
            tool: "files".into(),
            permutation: "managed-files".into(),
            args: args.clone(),
            on_failure: OnFailure::Stop,
        };
        // ConfigPlane comparison is proposal-only: never pass apply authority
        // through this routine child, even when the surrounding ladder applies.
        let outcome = tools::files::managed_files_step(
            &step,
            manifest,
            receipt_dir,
            false,
            invocation,
        )?;
        return Ok((outcome, BTreeMap::new()));
    }
    match tool {
        "pull-repo" => crate::bands::pull_source::execute_routine_child(
            "pull-repo",
            requested_permutation,
            args,
            manifest,
            receipt_dir,
            apply,
            invocation,
        ),
        "build-crate" => crate::bands::ratchet_binaries::execute_routine_child(
            "build-crate",
            requested_permutation,
            args,
            manifest,
            receipt_dir,
            apply,
            invocation,
        ),
        "place-file" | "backfill-file" => crate::bands::backfill_files::execute_routine_child(
            tool,
            requested_permutation,
            args,
            manifest,
            receipt_dir,
            apply,
            invocation,
        ),
        "check-health" | "systemd" | "enable-unit" => {
            crate::bands::restart_services::execute_routine_child(
                tool,
                requested_permutation,
                args,
                manifest,
                receipt_dir,
                apply,
                invocation,
            )
        }
        "service-runtime" => Err("service-runtime-execution-removed".into()),
        _ => Err(format!("routine-tool-not-summonable-{tool}")),
    }
}

pub(crate) fn execute_validated_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    software_authorization: Option<&crate::SoftwareApplyAuthorization>,
    package_authority: Option<&crate::PackageAuthority>,
    module_changed_before_step: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
    active_lane: Option<&str>,
) -> Result<OperationOutcome, String> {
    if let Some(blocker) = structural_file_blocker(step, manifest) {
        return Err(blocker);
    }
    // Apply is a SoftwarePlane capability. Configuration and identity steps
    // remain report-only; only these explicit software permutations receive it.
    let software_apply = software_authorization.is_some()
        && matches!(
            (step.tool.as_str(), step.permutation.as_str()),
            ("package", "install")
                | ("package", "upgrade")
                | ("package", "keyring-repair")
                | ("git-artifact", "sync")
                | ("files", "source-shelf-sweep")
                | ("files", "validated-sudoers-converge")
                | ("files", "converge")
                | ("files", "directory-sync")
                | ("venv", "converge")
                | ("aur", "install")
                | ("aur", "build-pinned")
                | ("command", "capture")
        );
    match (step.tool.as_str(), step.permutation.as_str()) {
        ("routine", "execute") => Err("routine-dispatch-internal".into()),
        ("command", "capture") => {
            tools::command::execute_validated_step(step, module_dir, software_apply, active_lane)
        }
        ("artifact-lock", "verify") => {
            tools::artifact_lock::execute_validated_step(step, module_dir)
        }
        ("health", "probe") => tools::health::execute_validated_step(step, module_dir, false),
        ("household-time", _) => tools::household_time::execute_validated_step(
            step,
            module_dir,
            software_apply,
            invocation,
        ),
        ("files", _) => tools::files::execute_validated_step(
            step,
            manifest,
            module_dir,
            software_authorization,
            invocation,
        ),
        ("systemd", _) => tools::systemd::execute_validated_step(
            step,
            module_dir,
            software_authorization.is_some() && step.permutation.ends_with("restart"),
            module_changed_before_step,
            invocation,
        ),
        ("git-artifact", "sync") => crate::bands::pull_source::execute_git_artifact_step(
            step,
            manifest,
            module_dir,
            software_apply,
            invocation,
        ),
        _ => Err(format!(
            "ladder-executor-missing tool={} permutation={}",
            step.tool, step.permutation
        )),
    }
}
fn resolve_routine_value(
    value: &Value,
    context: &BTreeMap<String, Value>,
) -> Result<Value, String> {
    match value {
        Value::Object(map) if map.len() == 1 && map.contains_key("from") => {
            let reference = map
                .get("from")
                .and_then(Value::as_str)
                .ok_or_else(|| "invalid-routine-reference".to_string())?;
            context
                .get(reference)
                .cloned()
                .ok_or_else(|| reference.to_string())
        }
        Value::Object(map) => map
            .iter()
            .map(|(key, value)| {
                resolve_routine_value(value, context).map(|resolved| (key.clone(), resolved))
            })
            .collect::<Result<Map<_, _>, _>>()
            .map(Value::Object),
        Value::Array(items) => items
            .iter()
            .map(|item| resolve_routine_value(item, context))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        _ => Ok(value.clone()),
    }
}

fn collect_routine_receipts(child_dir: &Path) -> Result<Vec<Value>, String> {
    let mut paths = fs::read_dir(child_dir)
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|v| v.to_str()) == Some("json"))
        .filter(|p| p.file_name().and_then(|v| v.to_str()) != Some("routine-child.json"))
        .collect::<Vec<_>>();
    paths.sort();
    paths
        .into_iter()
        .map(|p| {
            serde_json::from_slice(&fs::read(&p).map_err(|e| e.to_string())?)
                .map_err(|e| format!("routine-receipt-parse-{}: {e}", p.display()))
        })
        .collect()
}

fn is_managed_child_name(name: &str) -> bool {
    name == "managed-files"
        || name.starts_with("managed-file-")
        || name.starts_with("managed-place-")
        || name.starts_with("managed-backfill-")
        || name.starts_with("managed-remove-")
        || name.starts_with("managed-symlink-")
}

pub(crate) fn execute_routine(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    _software_authorization: Option<&crate::SoftwareApplyAuthorization>,
    _package_authority: Option<&crate::PackageAuthority>,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
    mut states: Option<&mut BTreeMap<String, crate::ModuleWalkState>>,
    band: crate::bands::Band,
    projected_children: &[ProjectedRoutineChild],
) -> Result<OperationOutcome, String> {
    let source = manifest
        .ladder
        .iter()
        .find(|s| s.step_id == step.step_id)
        .ok_or_else(|| format!("routine-step-missing-{}", step.step_id))?;
    let mut projected = BTreeMap::new();
    projected.insert(step.step_id.clone(), projected_children.to_vec());
    crate::tools::files::preflight_file_targets(
        manifest,
        std::slice::from_ref(step),
        &projected,
        Some(band),
    )?;
    let routine_dir = module_dir.join(&source.step_id);
    crate::atoms::attest::prepare_receipt_parent(&routine_dir)?;
    let local = states.is_none();
    let mut owned;
    let state = if let Some(map) = states.as_deref_mut() {
        map.entry(source.step_id.clone())
            .or_insert_with(|| crate::ModuleWalkState {
                context: BTreeMap::new(),
                children: Vec::new(),
                blocked_by: None,
                ok: true,
                changed: false,
                first_missing_signal: None,
            })
    } else {
        owned = crate::ModuleWalkState {
            context: BTreeMap::new(),
            children: Vec::new(),
            blocked_by: None,
            ok: true,
            changed: false,
            first_missing_signal: None,
        };
        &mut owned
    };
    for child in projected_children {
        if !local && child.band != band {
            continue;
        }
        if state
            .children
            .iter()
            .any(|r| r.get("name").and_then(Value::as_str) == Some(child.name.as_str()))
        {
            continue;
        }
        let child_dir = routine_dir.join(&child.name);
        crate::atoms::attest::prepare_receipt_parent(&child_dir)?;
        if let Some(parent) = state.blocked_by.clone() {
            let receipt = json!({"schema":"harmonia.routine.child-receipt.v1","name":child.name,"tool":child.tool,"state":"blocked","ok":false,"changed":false,"outputs":{},"blocked_by":parent});
            crate::write_json(&child_dir.join("routine-child.json"), &receipt)?;
            state.children.push(receipt);
            continue;
        }
        let mut args = child.args.clone();
        let mut missing = None;
        for value in args.values_mut() {
            match resolve_routine_value(value, &state.context) {
                Ok(resolved) => *value = resolved,
                Err(reference) => {
                    missing = Some(reference);
                    break;
                }
            }
        }
        let (status, child_ok, child_changed, outputs, extra) = if let Some(reference) = missing {
            let signal = format!("step_id={} defect=missing-stamp-{}", child.name, reference);
            state.ok = false;
            state.first_missing_signal.get_or_insert(signal.clone());
            state.blocked_by = Some(child.name.clone());
            (
                "missing",
                false,
                false,
                BTreeMap::new(),
                json!({"first_missing_signal":signal}),
            )
        } else {
            let child_step = ValidatedStep {
                step_id: child.name.clone(),
                tool: child.tool.clone(),
                permutation: child.permutation.clone(),
                args: args.clone(),
                on_failure: child.on_failure,
            };
            // Independently declared routine file children must cross the
            // canonical final-target membrane immediately before actuation.
            let target_gate = match child.tool.as_str() {
                "place-file" | "backfill-file" => args
                    .get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("{}-path-missing", child.tool))
                    .and_then(|path| {
                        crate::tools::files::authorize_routine_target(Path::new(path), apply)
                            .map(|_| ())
                    }),
                _ => Ok(()),
            };
            match target_gate.and_then(|_| {
                crate::tools::files::structural_file_blocker(&child_step, manifest).map_or_else(
                    || {
                        tools::routine::execute_routine_tool(
                            &child.tool,
                            Some(child.permutation.as_str()),
                            &args,
                            manifest,
                            &child_dir,
                            apply,
                            invocation,
                        )
                    },
                    |error| Err(error),
                )
            }) {
                Ok((outcome, outputs)) => {
                    if !outcome.ok {
                        state.ok = false;
                        state.first_missing_signal.get_or_insert(format!(
                            "step_id={} defect={}",
                            child.name, outcome.message
                        ));
                        state.blocked_by = Some(child.name.clone());
                    }
                    state.changed |= outcome.changed;
                    (
                        if outcome.ok { "completed" } else { "failed" },
                        outcome.ok,
                        outcome.changed,
                        outputs,
                        json!({"skipped":outcome.skipped,"message":outcome.message}),
                    )
                }
                Err(error) => {
                    let signal = format!("step_id={} defect={}", child.name, error);
                    state.ok = false;
                    state.first_missing_signal.get_or_insert(signal);
                    state.blocked_by = Some(child.name.clone());
                    (
                        "failed",
                        false,
                        false,
                        BTreeMap::new(),
                        json!({"message":error}),
                    )
                }
            }
        };
        if child_ok {
            for (key, value) in &outputs {
                state
                    .context
                    .entry(format!("{}.{}", child.name, key))
                    .or_insert(value.clone());
            }
            if is_managed_child_name(&child.name) {
                let aggregate_changed = state.children.iter().any(|receipt| {
                    receipt
                        .get("name")
                        .and_then(Value::as_str)
                        .is_some_and(is_managed_child_name)
                        && receipt
                            .get("changed")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                }) || child_changed;
                state.context.insert(
                    "managed-files.changed".into(),
                    Value::Bool(aggregate_changed),
                );
            }
        }
        let receipts = collect_routine_receipts(&child_dir)?;
        let mut receipt = json!({"schema":"harmonia.routine.child-receipt.v1","name":child.name,"tool":child.tool,"state":status,"ok":child_ok,"changed":child_changed,"outputs":outputs,"receipts":receipts});
        if let (Some(obj), Some(extra_obj)) = (receipt.as_object_mut(), extra.as_object()) {
            for (k, v) in extra_obj {
                obj.insert(k.clone(), v.clone());
            }
        }
        crate::write_json(&child_dir.join("routine-child.json"), &receipt)?;
        state.children.push(receipt);
    }
    let aggregate = json!({"schema":"harmonia.routine.receipt.v1","routine_id":source.step_id,"ok":state.ok,"changed":state.changed,"skipped":!apply,"first_missing_signal":state.first_missing_signal,"context":state.context,"children":state.children});
    crate::write_json(
        &module_dir.join(format!("{}.routine.json", source.step_id)),
        &aggregate,
    )?;
    Ok(OperationOutcome {
        ok: state.ok,
        changed: state.changed,
        skipped: !apply,
        message: state
            .first_missing_signal
            .clone()
            .unwrap_or_else(|| "routine-complete".into()),
        command: None,
    })
}
