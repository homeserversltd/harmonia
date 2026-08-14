use crate::{tools, CmdResult, ModuleExecution, OperationOutcome};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) const SCHEMA: &str = "harmonia.module.ladder.v1";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LadderManifest {
    pub schema: String,
    pub id: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub optional_warning: Option<String>,
    #[serde(default)]
    pub group: Option<LadderGroup>,
    #[serde(default)]
    pub constants: BTreeMap<String, Value>,
    #[serde(default)]
    pub caduceus_commands: Vec<String>,
    #[serde(default)]
    pub files_root: Option<String>,
    #[serde(default)]
    pub config_deploy: Option<String>,
    pub ladder: Vec<LadderStep>,
    #[serde(skip)]
    pub(crate) base_dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LadderGroup {
    pub group_id: String,
    pub group_order: i64,
    pub live_probe: LadderProbe,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LadderProbe {
    pub tool: String,
    pub permutation: String,
    #[serde(default)]
    pub args: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct LadderStep {
    pub step_id: String,
    pub tool: String,
    #[serde(default = "default_execute_permutation")]
    pub permutation: String,
    #[serde(default)]
    pub args: BTreeMap<String, Value>,
    #[serde(default)]
    pub steps: Vec<RoutineStep>,
    #[serde(default = "default_on_failure")]
    pub on_failure: OnFailure,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct RoutineStep {
    pub name: String,
    pub tool: String,
    #[serde(default)]
    pub permutation: Option<String>,
    #[serde(default)]
    pub args: BTreeMap<String, Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

fn default_execute_permutation() -> String {
    "execute".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommandPrecondition {
    program: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum OnFailure {
    Stop,
    ContinueOptional,
}

fn default_on_failure() -> OnFailure {
    OnFailure::Stop
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LadderValidationError {
    pub step_id: String,
    pub defect: String,
}

impl LadderValidationError {
    pub(crate) fn first_missing_signal(&self) -> String {
        format!("step_id={} defect={}", self.step_id, self.defect)
    }
}

pub(crate) fn load_ladder_manifest(path: &Path) -> Result<LadderManifest, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("ladder-manifest-read-failed {}: {e}", path.display()))?;
    serde_json::from_str::<LadderManifest>(&text)
        .map_err(|e| format!("ladder-manifest-parse-failed {}: {e}", path.display()))
        .and_then(|mut manifest| {
            if manifest.schema == SCHEMA {
                lower_service_runtime_steps(&mut manifest);
                manifest.base_dir = path.parent().unwrap_or_else(|| Path::new("")).to_path_buf();
                Ok(manifest)
            } else {
                Err(format!(
                    "ladder-manifest-schema-unsupported {} schema={}",
                    path.display(),
                    manifest.schema
                ))
            }
        })
}

fn lower_service_runtime_steps(manifest: &mut LadderManifest) {
    crate::bands::restart_services::lower_service_runtime_steps(manifest);
    crate::bands::backfill_files::lower_service_runtime_steps(manifest);
}

pub(crate) fn is_lowered_service_runtime_converge(step: &LadderStep) -> bool {
    let stages = [
        ("pull-repo", "pull-repo", "acquire"),
        ("build", "build-crate", "build"),
        ("binary-install", "place-file", "binary-promotion"),
        ("managed-files", "service-runtime", "managed-files"),
        ("service-daemon-reload", "systemd", "daemon-reload"),
        ("service-enable", "enable-unit", "enable"),
        ("service-restart", "systemd", "restart"),
        ("service-active", "systemd", "is-active-probe"),
        ("health-proof", "check-health", "probe"),
    ];
    // The managed-files proposal is optional: the bounded shape is either
    // pull/build/install + suffix, or the same with one proposal child.
    if step.tool != "routine"
        || step.permutation != "execute"
        || step.steps.len() < stages.len() - 1
    {
        return false;
    }
    if !step
        .steps
        .iter()
        .take(3)
        .zip(stages.iter().take(3))
        .all(|(c, (n, t, p))| c.name == *n && c.tool == *t && c.permutation.as_deref() == Some(*p))
    {
        return false;
    }
    let suffix_start = step
        .steps
        .iter()
        .position(|c| c.name == stages[4].0)
        .unwrap_or(usize::MAX);
    if suffix_start == usize::MAX || suffix_start < 3 {
        return false;
    }
    let has_proposal = step.steps.last().is_some_and(|child| {
        child.name == "managed-files"
            && child.tool == "service-runtime"
            && child.permutation.as_deref() == Some("configuration-proposal")
    });
    let suffix_end = if has_proposal {
        step.steps.len() - 1
    } else {
        step.steps.len()
    };
    if suffix_end != suffix_start + 5 {
        return false;
    }
    let mut config_count = 0;
    for child in &step.steps[3..suffix_start] {
        if child.name == "managed-files"
            && child.tool == "service-runtime"
            && child.permutation.as_deref() == Some("managed-files")
        {
            config_count += 1;
        } else if !(child.name.starts_with("managed-file-")
            && child.tool == "place-file"
            && child.permutation.as_deref() == Some("place"))
        {
            return false;
        }
    }
    if config_count > 1
        || !step.steps[suffix_start..]
            .iter()
            .zip(stages.iter().skip(4))
            .all(|(c, (n, t, p))| {
                c.name == *n && c.tool == *t && c.permutation.as_deref() == Some(*p)
            })
    {
        return false;
    }
    let (Some(pull), Some(build), Some(install), Some(epilogue)) = (
        step.steps.get(0),
        step.steps.get(1),
        step.steps.get(2),
        step.steps.get(5),
    ) else {
        return false;
    };
    let required = [
        "component",
        "source_dir",
        "install_bin",
        "service",
        "url",
        "binary_name",
        "op_prefix",
        "run_schema",
        "managed_files_schema",
    ];
    if required.iter().any(|key| !epilogue.args.contains_key(*key)) {
        return false;
    }
    pull.args.get("component") == epilogue.args.get("component")
        && pull.args.get("bearer") == epilogue.args.get("bearer")
        && pull
            .args
            .get("path")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
        && build.args.get("cwd") == Some(&serde_json::json!({"from":"pull-repo.path"}))
        && build.args.get("source_build_sha")
            == Some(&serde_json::json!({"from":"pull-repo.resolved_commit"}))
        && install.args.get("source_path") == Some(&serde_json::json!({"from":"build.artifact"}))
        && epilogue.args.get("source_dir") == Some(&serde_json::json!({"from":"pull-repo.path"}))
        && epilogue.args.get("source_sha")
            == Some(&serde_json::json!({"from":"pull-repo.resolved_commit"}))
        && epilogue.args.get("source_changed")
            == Some(&serde_json::json!({"from":"pull-repo.changed"}))
        && epilogue.args.get("binary_changed")
            == Some(&serde_json::json!({"from":"binary-install.changed"}))
        && build.args.get("op_prefix") == epilogue.args.get("op_prefix")
        && install.args.get("install_bin") == epilogue.args.get("install_bin")
}

pub(crate) fn service_runtime_converge_args(step: &LadderStep) -> Option<&BTreeMap<String, Value>> {
    if step.tool == "service-runtime" && step.permutation == "converge" {
        Some(&step.args)
    } else if is_lowered_service_runtime_converge(step) {
        step.steps
            .iter()
            .find(|c| c.name == "service-enable")
            .map(|c| &c.args)
    } else {
        None
    }
}

pub(crate) fn is_ladder_manifest(path: &Path) -> bool {
    let Ok(text) = fs::read_to_string(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return false;
    };
    value.get("schema").and_then(Value::as_str) == Some(SCHEMA)
}

pub(crate) fn validate_ladder(
    manifest: &LadderManifest,
) -> Result<Vec<ValidatedStep>, LadderValidationError> {
    if manifest.schema != SCHEMA {
        return Err(LadderValidationError {
            step_id: "manifest".into(),
            defect: format!("unsupported-schema-{}", manifest.schema),
        });
    }
    if manifest
        .config_deploy
        .as_deref()
        .is_some_and(|tier| tier != "interactable")
    {
        return Err(LadderValidationError {
            step_id: "manifest".into(),
            defect: "config-deploy-unsupported".into(),
        });
    }
    if let Some(group) = &manifest.group {
        validate_group(group, &manifest.constants)?;
    }
    let mut seen = BTreeSet::new();
    let mut validated = Vec::new();
    for step in &manifest.ladder {
        if !seen.insert(step.step_id.clone()) {
            return Err(LadderValidationError {
                step_id: step.step_id.clone(),
                defect: "duplicate-step_id".into(),
            });
        }
        if step.on_failure == OnFailure::ContinueOptional && !manifest.optional {
            return Err(LadderValidationError {
                step_id: step.step_id.clone(),
                defect: "continue-optional-on-non-optional-module".into(),
            });
        }
        if step.tool == "routine" {
            validate_routine(step, manifest)?;
            validated.push(ValidatedStep {
                step_id: step.step_id.clone(),
                tool: step.tool.clone(),
                permutation: step.permutation.clone(),
                args: step.args.clone(),
                on_failure: step.on_failure,
            });
            continue;
        }
        let Some(tool) = tools::get(&step.tool) else {
            return Err(LadderValidationError {
                step_id: step.step_id.clone(),
                defect: format!("unknown-tool-{}", step.tool),
            });
        };
        let Some(permutation) = tool.permutation(&step.permutation) else {
            return Err(LadderValidationError {
                step_id: step.step_id.clone(),
                defect: format!("undeclared-permutation-{}", step.permutation),
            });
        };
        let resolved = resolve_args(&step.args, &manifest.constants).map_err(|defect| {
            LadderValidationError {
                step_id: step.step_id.clone(),
                defect,
            }
        })?;
        if resolved.contains_key("repo") {
            return Err(LadderValidationError {
                step_id: step.step_id.clone(),
                defect: "legacy-repo-forbidden".into(),
            });
        }
        if matches!(step.tool.as_str(), "git-artifact" | "service-runtime")
            && (resolved.contains_key("branch") || resolved.contains_key("ref"))
        {
            return Err(LadderValidationError {
                step_id: step.step_id.clone(),
                defect: "legacy-source-ref-forbidden".into(),
            });
        }
        validate_args(&step.step_id, permutation, &resolved)?;
        validate_tool_semantics(&step.step_id, &step.tool, &step.permutation, &resolved)?;
        validate_command_precondition(&step.step_id, &step.tool, &step.permutation, &resolved)?;
        validated.push(ValidatedStep {
            step_id: step.step_id.clone(),
            tool: step.tool.clone(),
            permutation: step.permutation.clone(),
            args: resolved,
            on_failure: step.on_failure,
        });
    }
    Ok(validated)
}

fn validate_routine(
    step: &LadderStep,
    _manifest: &LadderManifest,
) -> Result<(), LadderValidationError> {
    if step.permutation != "execute" {
        return Err(LadderValidationError {
            step_id: step.step_id.clone(),
            defect: "routine-permutation-must-be-execute".into(),
        });
    }
    if step.steps.is_empty() {
        return Err(LadderValidationError {
            step_id: step.step_id.clone(),
            defect: "routine-steps-empty".into(),
        });
    }
    let mut names = BTreeSet::new();
    for child in &step.steps {
        if child.name.trim().is_empty() {
            return Err(LadderValidationError {
                step_id: step.step_id.clone(),
                defect: "routine-child-name-blank".into(),
            });
        }
        if !names.insert(child.name.clone()) {
            return Err(LadderValidationError {
                step_id: step.step_id.clone(),
                defect: format!("duplicate-routine-step-{}", child.name),
            });
        }
        if !tools::routine_summonable(&child.tool) {
            return Err(LadderValidationError {
                step_id: step.step_id.clone(),
                defect: format!("routine-tool-not-summonable-{}", child.tool),
            });
        }
        let contract = tools::get(&child.tool).ok_or_else(|| LadderValidationError {
            step_id: step.step_id.clone(),
            defect: format!("routine-tool-not-found-{}", child.tool),
        })?;
        let permutation_name = child
            .permutation
            .as_deref()
            .unwrap_or(contract.permutations.first().map(|p| p.name).unwrap_or(""));
        if contract.permutation(permutation_name).is_none() {
            return Err(LadderValidationError {
                step_id: step.step_id.clone(),
                defect: format!(
                    "routine-undeclared-permutation-{}-{}",
                    child.tool, permutation_name
                ),
            });
        }
        if child.extra.contains_key("program") {
            return Err(LadderValidationError {
                step_id: step.step_id.clone(),
                defect: format!("routine-child-key-forbidden-{}", child.name),
            });
        }
        for value in child.args.values() {
            if let Value::Object(map) = value {
                if map.len() == 1
                    && map.contains_key("from")
                    && !map.get("from").and_then(Value::as_str).is_some_and(|r| {
                        r.contains('.') && !r.starts_with('.') && !r.ends_with('.')
                    })
                {
                    return Err(LadderValidationError {
                        step_id: step.step_id.clone(),
                        defect: format!("routine-reference-malformed-{}", child.name),
                    });
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_group(
    group: &LadderGroup,
    constants: &BTreeMap<String, Value>,
) -> Result<ValidatedStep, LadderValidationError> {
    if group.group_id.trim().is_empty() {
        return Err(LadderValidationError {
            step_id: "group".into(),
            defect: "missing-group_id".into(),
        });
    }
    let step_id = "group.live_probe";
    let Some(tool) = tools::get(&group.live_probe.tool) else {
        return Err(LadderValidationError {
            step_id: step_id.into(),
            defect: format!("unknown-tool-{}", group.live_probe.tool),
        });
    };
    let Some(permutation) = tool.permutation(&group.live_probe.permutation) else {
        return Err(LadderValidationError {
            step_id: step_id.into(),
            defect: format!("undeclared-permutation-{}", group.live_probe.permutation),
        });
    };
    let resolved = resolve_args(&group.live_probe.args, constants).map_err(|defect| {
        LadderValidationError {
            step_id: step_id.into(),
            defect,
        }
    })?;
    validate_args(step_id, permutation, &resolved)?;
    validate_tool_semantics(
        step_id,
        &group.live_probe.tool,
        &group.live_probe.permutation,
        &resolved,
    )?;
    Ok(ValidatedStep {
        step_id: step_id.into(),
        tool: group.live_probe.tool.clone(),
        permutation: group.live_probe.permutation.clone(),
        args: resolved,
        on_failure: OnFailure::Stop,
    })
}

pub(crate) fn execute_group_live_probe_validated(
    manifest: &LadderManifest,
    step: &ValidatedStep,
    receipt_dir: &Path,
) -> Result<OperationOutcome, String> {
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    execute_validated_step(step, manifest, receipt_dir, None, None, false, None)
}

pub(crate) fn execute_group_live_probe(
    manifest: &LadderManifest,
    receipt_dir: &Path,
) -> Result<OperationOutcome, String> {
    let Some(group) = &manifest.group else {
        return Err(format!("module-{}-has-no-group", manifest.id));
    };
    let step = validate_group(group, &manifest.constants)
        .map_err(|err| format!("module-invalid {}", err.first_missing_signal()))?;
    execute_group_live_probe_validated(manifest, &step, receipt_dir)
}

fn resolve_args(
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

fn validate_args(
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

fn validate_command_precondition(
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

fn validate_tool_semantics(
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

pub(crate) fn execute_ladder_manifest_band(
    manifest: &LadderManifest,
    module_dir: &Path,
    band: crate::bands::Band,
    software_authorization: Option<&crate::SoftwareApplyAuthorization>,
    package_authority: Option<&crate::PackageAuthority>,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
    module_changed_before_step: bool,
    routine_states: &mut BTreeMap<String, crate::ModuleWalkState>,
    projected_steps: &[ValidatedStep],
    projected_routines: &BTreeMap<String, Vec<ProjectedRoutineChild>>,
) -> Result<ModuleExecution, String> {
    let steps = projected_steps.to_vec();
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
        } else if placement_for_step(&step)? != band {
            continue;
        }
        let precondition = if step.tool == "routine" {
            None
        } else {
            command_precondition(&step.args)?
        };
        if let Some(precondition) = precondition {
            result.operation_count += 1;
            let probe = command_precondition_step(&step, &precondition, manifest, module_dir)?;
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
            execute_routine(
                &step,
                manifest,
                module_dir,
                software_authorization,
                package_authority,
                software_authorization.is_some(),
                invocation,
                Some(routine_states),
                band,
                projected_routines
                    .get(&step.step_id)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            )?
        } else {
            execute_validated_step(
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

pub(crate) fn execute_ladder_manifest(
    manifest: &LadderManifest,
    module_dir: &Path,
    software_authorization: Option<&crate::SoftwareApplyAuthorization>,
    package_authority: Option<&crate::PackageAuthority>,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<ModuleExecution, String> {
    let steps = validate_ladder(manifest)
        .map_err(|err| format!("module-invalid {}", err.first_missing_signal()))?;
    fs::create_dir_all(module_dir).map_err(|e| e.to_string())?;
    let mut ok = true;
    let mut changed = false;
    let mut first_missing_signal = None;
    let mut operation_count = 0usize;
    for step in steps {
        if step.tool == "routine" {
            let outcome = execute_routine(
                &step,
                manifest,
                module_dir,
                software_authorization,
                package_authority,
                software_authorization.is_some(),
                invocation,
                None,
                crate::bands::Band::ProposeEdits,
                &[],
            )?;
            operation_count += 1;
            changed |= outcome.changed;
            if !outcome.ok {
                ok = false;
                first_missing_signal = Some(outcome.message.clone());
            }
            continue;
        }
        if let Some(precondition) = command_precondition(&step.args)? {
            operation_count += 1;
            let outcome = command_precondition_step(&step, &precondition, manifest, module_dir)?;
            if !outcome.ok {
                ok = false;
                let probe_error = outcome
                    .command
                    .as_ref()
                    .map(|result| format!("exit_code={} stderr={}", result.code, result.stderr))
                    .unwrap_or_else(|| outcome.message.clone());
                first_missing_signal = Some(format!(
                    "step_id={} state=blocked probe_error={probe_error}",
                    step.step_id
                ));
                break;
            }
        }
        operation_count += 1;
        let outcome = if matches!(
            (step.tool.as_str(), step.permutation.as_str()),
            ("package", _) | ("aur", _) | ("venv", "converge")
        ) {
            // Legacy full-manifest entry remains a thin compatibility route;
            // package-family execution is owned by the InstallPackages band.
            crate::bands::install_packages::execute_step(
                &step,
                manifest,
                module_dir,
                software_authorization,
                package_authority,
                invocation,
            )?
        } else {
            execute_validated_step(
                &step,
                manifest,
                module_dir,
                software_authorization,
                package_authority,
                changed,
                invocation,
            )?
        };
        if outcome.changed {
            changed = true;
        }
        if !outcome.ok {
            ok = false;
            if first_missing_signal.is_none() {
                let defect = if step.tool == "files" && step.permutation == "executable-present" {
                    outcome
                        .message
                        .split_whitespace()
                        .next()
                        .unwrap_or("tool-step-failed")
                } else {
                    "tool-step-failed"
                };
                first_missing_signal = Some(format!("step_id={} defect={defect}", step.step_id));
            }
            if step.on_failure == OnFailure::Stop {
                break;
            }
        }
    }
    Ok(ModuleExecution {
        ok,
        changed,
        operation_count,
        first_missing_signal,
        placements: Vec::new(),
    })
}

#[cfg(test)]
pub(crate) fn receipt_families(receipt_dir: &Path) -> Result<Vec<String>, String> {
    let mut families = BTreeSet::new();
    if !receipt_dir.exists() {
        return Ok(Vec::new());
    }
    for entry in fs::read_dir(receipt_dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_type().map_err(|e| e.to_string())?.is_file()
            && entry.path().extension().and_then(|e| e.to_str()) == Some("json")
        {
            let text = fs::read_to_string(entry.path()).map_err(|e| e.to_string())?;
            if let Ok(value) = serde_json::from_str::<Value>(&text) {
                if let Some(schema) = value.get("schema").and_then(Value::as_str) {
                    families.insert(schema.to_string());
                }
            }
        }
    }
    Ok(families.into_iter().collect())
}

#[cfg(test)]
pub(crate) fn shadow_diff_receipt_families(
    ladder_receipt_dir: &Path,
    compiled_receipt_dir: &Path,
) -> Result<Vec<String>, String> {
    let ladder = receipt_families(ladder_receipt_dir)?;
    let compiled = receipt_families(compiled_receipt_dir)?;
    let ladder_set: BTreeSet<_> = ladder.iter().cloned().collect();
    let compiled_set: BTreeSet<_> = compiled.iter().cloned().collect();
    Ok(ladder_set
        .symmetric_difference(&compiled_set)
        .cloned()
        .collect())
}

fn execute_validated_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    software_authorization: Option<&crate::SoftwareApplyAuthorization>,
    package_authority: Option<&crate::PackageAuthority>,
    module_changed_before_step: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
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
        ("command", "capture") => command_capture_step(step, module_dir, software_apply),
        ("artifact-lock", "verify") => artifact_lock_step(step, module_dir, false),
        ("health", "probe") => health_probe_step(step, module_dir, false),
        ("household-time", _) => household_time_step(step, module_dir, software_apply, invocation),
        ("files", "managed-files") => managed_files_step(step, manifest, module_dir, false),
        ("files", "managed-directories") => managed_directories_step(step, module_dir, false),
        ("files", "validated-symlink") => validated_symlink_step(step, module_dir, false),
        ("files", "symlink-converge") => symlink_converge_step(step, module_dir, false),
        ("files", "validated-file-symlink") => {
            validated_file_symlink_step(step, manifest, module_dir, false)
        }
        ("files", "remove") => files_remove_step(step, module_dir, software_apply, invocation),
        ("files", "executable-present") => files_executable_present_step(step, module_dir),
        ("files", "source-shelf-sweep") => {
            files_source_shelf_sweep_step(step, manifest, module_dir, software_apply, invocation)
        }
        ("files", "validated-sudoers-converge") => files_validated_sudoers_converge_step(
            step,
            manifest,
            module_dir,
            software_apply,
            invocation,
        ),
        ("files", "ensure-present") => files_ensure_present_step(step, manifest, module_dir, false),
        ("files", "converge") | ("files", "directory-sync") => {
            files_converge_step(step, manifest, module_dir, software_apply, invocation)
        }
        ("systemd", _) => systemd_step(
            step,
            module_dir,
            software_authorization.is_some() && step.permutation.ends_with("restart"),
            module_changed_before_step,
            invocation,
        ),
        ("git-artifact", "sync") => {
            git_artifact_step(step, manifest, module_dir, software_apply, invocation)
        }
        _ => Err(format!(
            "ladder-executor-missing tool={} permutation={}",
            step.tool, step.permutation
        )),
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
    let routine_dir = module_dir.join(&source.step_id);
    fs::create_dir_all(&routine_dir).map_err(|e| e.to_string())?;
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
                service_runtime: None,
            })
    } else {
        owned = crate::ModuleWalkState {
            context: BTreeMap::new(),
            children: Vec::new(),
            blocked_by: None,
            ok: true,
            changed: false,
            first_missing_signal: None,
            service_runtime: None,
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
        fs::create_dir_all(&child_dir).map_err(|e| e.to_string())?;
        if let Some(parent) = state.blocked_by.clone() {
            let receipt = json!({"schema":"harmonia.routine.child-receipt.v1","name":child.name,"tool":child.tool,"state":"blocked","ok":false,"changed":false,"outputs":{},"blocked_by":parent});
            crate::write_json(&child_dir.join("routine-child.json"), &receipt)?;
            state.children.push(receipt);
            continue;
        }
        let mut args = child.args.clone();
        let mut missing = None;
        for value in args.values_mut() {
            if let Value::Object(map) = value {
                if map.len() == 1 {
                    if let Some(reference) = map.get("from").and_then(Value::as_str) {
                        match state.context.get(reference) {
                            Some(v) => *value = v.clone(),
                            None => missing = Some(reference.to_string()),
                        }
                    }
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
            match tools::module_steps::execute_routine_tool(
                &child.tool,
                Some(child.permutation.as_str()),
                &args,
                manifest,
                &child_dir,
                apply,
                invocation,
                &mut state.service_runtime,
            ) {
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
            if child.name == "managed-files" || child.name.starts_with("managed-file-") {
                let aggregate_changed = state.children.iter().any(|receipt| {
                    receipt
                        .get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|name| {
                            name == "managed-files" || name.starts_with("managed-file-")
                        })
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

fn string_arg<'a>(args: &'a BTreeMap<String, Value>, name: &str) -> &'a str {
    args.get(name).and_then(Value::as_str).unwrap_or("")
}

fn optional_string_arg<'a>(args: &'a BTreeMap<String, Value>, name: &str) -> Option<&'a str> {
    args.get(name).and_then(Value::as_str)
}

fn string_array_arg(args: &BTreeMap<String, Value>, name: &str) -> Vec<String> {
    args.get(name)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn integer_arg(args: &BTreeMap<String, Value>, name: &str, default: u64) -> u64 {
    args.get(name).and_then(Value::as_u64).unwrap_or(default)
}

fn artifact_lock_step(
    step: &ValidatedStep,
    module_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    tools::artifact_lock::verify(
        &PathBuf::from(string_arg(&step.args, "lock")),
        optional_string_arg(&step.args, "profile"),
        module_dir,
    )
}

fn command_capture_step(
    step: &ValidatedStep,
    module_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let program = string_arg(&step.args, "program");
    let argv = string_array_arg(&step.args, "args");
    let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let result = if apply {
        tools::command::capture_with_options(
            program,
            &argv_refs,
            tools::command::CaptureOptions::new()
                .cwd(optional_string_arg(&step.args, "cwd"))
                .timeout_secs(integer_arg(
                    &step.args,
                    "timeout_secs",
                    tools::command::DEFAULT_TIMEOUT_SECS,
                )),
        )
    } else {
        CmdResult {
            ok: true,
            code: 0,
            stdout: format!("planned command {}", program),
            stderr: String::new(),
        }
    };
    crate::write_command_receipt_with_request(
        module_dir,
        &step.step_id,
        program,
        &argv,
        optional_string_arg(&step.args, "cwd"),
        &result,
    )?;
    Ok(OperationOutcome {
        ok: result.ok,
        changed: false,
        skipped: !apply,
        message: format!("command capture {}", program),
        command: Some(result),
    })
}

pub(crate) fn command_precondition_step(
    step: &ValidatedStep,
    precondition: &CommandPrecondition,
    manifest: &LadderManifest,
    module_dir: &Path,
) -> Result<OperationOutcome, String> {
    let argv_refs: Vec<&str> = precondition.args.iter().map(String::as_str).collect();
    let result = tools::command::capture_with_options(
        &precondition.program,
        &argv_refs,
        tools::command::CaptureOptions::new()
            .cwd(precondition.cwd.as_deref())
            .timeout_secs(
                precondition
                    .timeout_secs
                    .unwrap_or(tools::command::DEFAULT_TIMEOUT_SECS),
            ),
    );
    crate::write_json(
        &module_dir.join(format!("{}-precondition.json", step.step_id)),
        &json!({
            "schema": "harmonia.command_precondition.v1",
            "module": manifest.id,
            "step_id": step.step_id,
            "state": if result.ok { "satisfied" } else { "blocked" },
            "program": precondition.program,
            "args": precondition.args,
            "cwd": precondition.cwd,
            "timeout_secs": precondition.timeout_secs.unwrap_or(tools::command::DEFAULT_TIMEOUT_SECS),
            "raw_command_ran": false,
            "probe": result,
            "probe_error": if result.ok { "none".to_string() } else { format!("exit_code={} stderr={}", result.code, result.stderr) },
            "first_missing_signal": if result.ok { "none" } else { "command-precondition-blocked" },
        }),
    )?;
    Ok(OperationOutcome {
        ok: result.ok,
        changed: false,
        skipped: false,
        message: format!("command precondition {}", precondition.program),
        command: Some(result),
    })
}

fn household_time_step(
    step: &ValidatedStep,
    module_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    tools::household_time::execute(
        module_dir,
        &step.step_id,
        &step.permutation,
        &step.args,
        apply,
        invocation,
    )
}

fn health_probe_step(
    step: &ValidatedStep,
    module_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let url = string_arg(&step.args, "url");
    let result = if apply {
        let mut request = tools::health::ProbeRequest::new(url);
        request.expected_contains = optional_string_arg(&step.args, "expected_contains");
        request.timeout_secs = integer_arg(&step.args, "timeout_secs", 3);
        request.retries = integer_arg(&step.args, "retries", 0) as usize;
        tools::health::curl_probe(&request)
    } else {
        CmdResult {
            ok: true,
            code: 0,
            stdout: format!("planned health probe {}", url),
            stderr: String::new(),
        }
    };
    crate::write_command_receipt(module_dir, &step.step_id, &result)?;
    Ok(OperationOutcome {
        ok: result.ok,
        changed: false,
        skipped: !apply,
        message: format!("health probe {}", url),
        command: Some(result),
    })
}

fn managed_files_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let files: Vec<crate::ManagedFileManifest> = if let Some(files_value) = step.args.get("files") {
        serde_json::from_value(files_value.clone())
            .map_err(|e| format!("managed-files-args-invalid: {e}"))?
    } else if let Some(files_root) = &manifest.files_root {
        managed_files_from_files_root(&manifest.base_dir.join(files_root))?
    } else {
        Vec::new()
    };
    let config_write = files
        .iter()
        .any(|file| is_configuration_path(Path::new(&file.path)));
    tools::files::converge_managed_files(
        &tools::files::ManagedFilesRequest {
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

fn managed_directories_step(
    step: &ValidatedStep,
    module_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let directories: Vec<tools::files::ManagedDirectorySpec> = serde_json::from_value(
        step.args
            .get("directories")
            .cloned()
            .ok_or("managed-directories-args-missing")?,
    )
    .map_err(|e| format!("managed-directories-args-invalid: {e}"))?;
    tools::files::converge_managed_directories(&directories, module_dir, &step.step_id, apply)
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

fn validated_symlink_step(
    step: &ValidatedStep,
    module_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    crate::tools::files::validated_symlink(
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
    )
}

fn symlink_converge_step(
    step: &ValidatedStep,
    module_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let required_source_kind = match string_arg(&step.args, "required_source_kind") {
        "regular-executable" => crate::tools::files::SymlinkSourceKind::RegularExecutable,
        other => return Err(format!("symlink-converge-source-kind-unsupported {other}")),
    };
    let conflict_policy = match optional_string_arg(&step.args, "conflict_policy")
        .unwrap_or("refuse-non-symlink")
    {
        "refuse-non-symlink" => crate::tools::files::SymlinkConflictPolicy::RefuseNonSymlink,
        "replace-regular-file" => crate::tools::files::SymlinkConflictPolicy::ReplaceRegularFile,
        "replace-empty-directory" => {
            crate::tools::files::SymlinkConflictPolicy::ReplaceEmptyDirectory
        }
        other => {
            return Err(format!(
                "symlink-converge-conflict-policy-unsupported {other}"
            ))
        }
    };
    crate::tools::files::symlink_converge(
        &crate::tools::files::SymlinkConvergeRequest {
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
    )
}

fn validated_file_symlink_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    apply: bool,
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
        None,
    )
}

fn files_remove_step(
    step: &ValidatedStep,
    module_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let outcome = crate::tools::files::remove_declared_files(
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

fn files_executable_present_step(
    step: &ValidatedStep,
    module_dir: &Path,
) -> Result<OperationOutcome, String> {
    let search_scope = crate::tools::files::ExecutableSearchScope::parse(optional_string_arg(
        &step.args,
        "search_scope",
    ))?;
    let outcome = crate::tools::files::executable_present(
        &crate::tools::files::ExecutablePresentRequest {
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

fn files_source_shelf_sweep_step(
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
    let request = crate::tools::files::SourceShelfSweepRequest {
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
    let outcome = crate::tools::files::source_shelf_sweep(&request, module_dir, apply, invocation)?;
    Ok(OperationOutcome {
        ok: outcome.ok,
        changed: outcome.changed,
        skipped: !apply,
        message: outcome.message,
        command: None,
    })
}

fn files_validated_sudoers_converge_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let source_root = resolve_ladder_path(manifest, string_arg(&step.args, "source_root"));
    let target_root = PathBuf::from(string_arg(&step.args, "target_root"));
    let owned_prefix = string_arg(&step.args, "owned_prefix");
    let validator_program = string_arg(&step.args, "validator_program");
    let validator_args = string_array_arg(&step.args, "validator_args");
    let files = string_array_arg(&step.args, "files");

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
        let relative = Path::new(name);
        if relative.components().count() != 1
            || relative.file_name().and_then(|value| value.to_str()) != Some(name.as_str())
            || !name.starts_with(owned_prefix)
        {
            return Err(format!("validated-sudoers-declared-path-refused {name}"));
        }
        let candidate = source_root.join(relative);
        let candidate_text = candidate.to_string_lossy();
        let refs = ["-cf", candidate_text.as_ref()];
        let result = tools::command::capture_with_timeout(validator_program, &refs, 30);
        crate::write_command_receipt(
            module_dir,
            &format!("{}-{}-validation", step.step_id, name),
            &result,
        )?;
        if !result.ok {
            return Err(format!("validated-sudoers-visudo-rejected {name}"));
        }
    }

    let request = crate::tools::files::FileConvergenceRequest {
        source_root,
        target_root,
        files: files
            .into_iter()
            .map(|relative_path| crate::tools::files::FileSpec {
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
    let outcome = crate::tools::files::converge_files_with_invocation(
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

fn files_converge_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let source_root = resolve_ladder_path(manifest, string_arg(&step.args, "source_root"));
    let target_root = PathBuf::from(string_arg(&step.args, "target_root"));
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
        let run = crate::tools::comparison::execute(
            "ladder",
            || Ok::<_, String>((source_root.clone(), target_root.clone())),
            |_| crate::tools::comparison::DiffDecision::Empty,
            |_, _| Ok::<_, String>(()),
        )?;
        let (observed_source_root, observed_target_root) = match run {
            crate::tools::comparison::ComparisonRun::Current { observation, .. } => observation,
            crate::tools::comparison::ComparisonRun::Moved { .. } => {
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
        crate::write_json(&receipt_path, &receipt)?;
        return Ok(outcome);
    }
    let rels = if step.permutation == "directory-sync" && !step.args.contains_key("files") {
        files_under_root(&source_root)?
    } else {
        string_array_arg(&step.args, "files")
    };
    let files = rels
        .into_iter()
        .map(|rel| crate::tools::files::FileSpec {
            mode: if rel.starts_with("bin/") || rel.starts_with("usr/local/bin/") {
                Some(0o755)
            } else {
                Some(0o644)
            },
            relative_path: PathBuf::from(rel),
        })
        .collect();
    let request = crate::tools::files::FileConvergenceRequest {
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
    let config_write = request
        .files
        .iter()
        .any(|file| is_configuration_path(&request.target_root.join(&file.relative_path)));
    let tier_two = manifest.config_deploy.as_deref() == Some("interactable");
    let mut outcome = crate::tools::files::converge_files_with_invocation(
        &request,
        module_dir,
        apply && !config_write && !tier_two,
        invocation,
    )?;
    if config_write || tier_two {
        crate::refresh_interactables_for_convergence(manifest, &request, &outcome)?;
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
        crate::write_json(
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

fn files_ensure_present_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let files = string_array_arg(&step.args, "files")
        .into_iter()
        .map(|relative_path| crate::tools::files::FileSpec {
            mode: Some(0o644),
            relative_path: PathBuf::from(relative_path),
        })
        .collect();
    let outcome = crate::tools::files::ensure_files_present(
        &crate::tools::files::FileConvergenceRequest {
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

fn resolve_ladder_path(manifest: &LadderManifest, path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    if p.is_absolute() {
        p
    } else {
        manifest.base_dir.join(p)
    }
}

fn systemd_step(
    step: &ValidatedStep,
    module_dir: &Path,
    apply: bool,
    module_changed_before_step: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    tools::systemd::run_permutation(
        module_dir,
        &step.step_id,
        &step.permutation,
        optional_string_arg(&step.args, "service"),
        &string_array_arg(&step.args, "candidate_units"),
        optional_string_arg(&step.args, "user"),
        integer_arg(&step.args, "timeout_secs", 30),
        apply,
        module_changed_before_step,
        invocation,
    )
}

fn git_artifact_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let source_plan = routine_source_plan(step, manifest)?;
    let outcome = if apply {
        tools::git_artifact::acquire_source(&source_plan, invocation)
    } else {
        tools::git_artifact::SourceOutcome {
            ok: true,
            changed: false,
            receipt: tools::git_artifact::SourceReceipt {
                attempts: Vec::new(),
                served_index: None,
                resolved_commit: None,
                promotion: "planned source acquisition".to_string(),
            },
        }
    };
    let command = source_outcome_command(&outcome);
    crate::write_tool_receipt(
        module_dir,
        &step.step_id,
        "git-artifact",
        "sync",
        &OperationOutcome {
            ok: outcome.ok,
            changed: outcome.changed,
            skipped: !apply,
            message: outcome.receipt.promotion.clone(),
            command: Some(command.clone()),
        },
    )?;
    let receipt_path = module_dir.join(format!("{}.json", step.step_id));
    let mut receipt: Value = serde_json::from_slice(
        &fs::read(&receipt_path)
            .map_err(|error| format!("git-artifact-receipt-read-failed: {error}"))?,
    )
    .map_err(|error| format!("git-artifact-receipt-parse-failed: {error}"))?;
    let object = receipt
        .as_object_mut()
        .ok_or_else(|| "git-artifact-receipt-not-object".to_string())?;
    object.insert(
        "attempts".into(),
        json!(outcome
            .receipt
            .attempts
            .iter()
            .map(|attempt| json!({
                "index": attempt.index,
                "kind": format!("{:?}", attempt.kind).to_ascii_lowercase(),
                "locator": attempt.locator,
                "credential_selector": attempt.credential_selector,
                "disposition": attempt.disposition,
                "resolved_commit": attempt.resolved_commit,
                "external_freshness": attempt.external_freshness,
                "detail": attempt.detail,
            }))
            .collect::<Vec<_>>()),
    );
    object.insert("served_index".into(), json!(outcome.receipt.served_index));
    if let Some(commit) = &outcome.receipt.resolved_commit {
        object.insert("resolved_commit".into(), json!(commit));
    }
    object.insert("promotion".into(), json!(outcome.receipt.promotion));
    crate::write_json(&receipt_path, &receipt)?;
    Ok(OperationOutcome {
        ok: outcome.ok,
        changed: outcome.changed,
        skipped: !apply,
        message: outcome.receipt.promotion,
        command: Some(command),
    })
}

pub(crate) fn routine_source_plan(
    step: &ValidatedStep,
    manifest: &LadderManifest,
) -> Result<tools::git_artifact::SourcePlan, String> {
    let component = string_arg(&step.args, "component");
    if component.trim().is_empty() {
        return Err(format!(
            "source-component-missing module={} step_id={}",
            manifest.id, step.step_id
        ));
    }
    let destination = optional_string_arg(&step.args, "path")
        .or_else(|| optional_string_arg(&step.args, "source_dir"))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            format!(
                "source-destination-missing module={} step_id={}",
                manifest.id, step.step_id
            )
        })?;
    let config = crate::load_engine_plane_config(&crate::engine_config_path())?;
    let certificate = crate::device_profile_certificate_path();
    let certificate_resolution =
        crate::resolve_source(&certificate, component, &manifest.id, &step.step_id);
    let resolution = match certificate_resolution.resolution {
        Some(resolution) => resolution,
        None if certificate_resolution
            .blocker
            .as_deref()
            .is_some_and(|blocker| {
                blocker == format!("source-component-undeclared component={component}")
            }) =>
        {
            let config = config.as_ref().ok_or_else(|| {
                format!("source-resolution-blocked module={} step_id={} component={} blocker=engine-config-missing", manifest.id, step.step_id, component)
            })?;
            engine_source_resolution(component, config)?
        }
        None => {
            let blocker = certificate_resolution
                .blocker
                .unwrap_or_else(|| "source-resolution-plan-missing".to_string());
            return Err(format!(
                "source-resolution-blocked module={} step_id={} component={} blocker={blocker}",
                manifest.id, step.step_id, component
            ));
        }
    };
    let credentials = config
        .as_ref()
        .map(crate::credential_scopes)
        .unwrap_or_default();
    let expected_commit = (resolution.requested_ref.len() == 40
        && resolution
            .requested_ref
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()))
    .then(|| resolution.requested_ref.clone());
    Ok(crate::bridge_acquisition_plan(
        &resolution,
        PathBuf::from(destination),
        optional_string_arg(&step.args, "bearer")
            .unwrap_or("owner")
            .to_string(),
        expected_commit,
        credentials,
    ))
}

fn engine_source_resolution(
    component: &str,
    config: &crate::EnginePlaneConfig,
) -> Result<crate::source_resolver::SourceResolution, String> {
    let declared = config.source_components.get(component);
    let (source_repo_url, branch) = if let Some(declared) = declared {
        (&declared.repo_url, &declared.branch)
    } else {
        (&config.source_repo_url, &config.branch)
    };
    let source_component = config
        .source_components
        .get(component)
        .map(|_| component)
        .unwrap_or_else(|| {
            config
                .source_repo_url
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .and_then(|segment| segment.rsplit(':').next())
                .unwrap_or_default()
                .trim_end_matches(".git")
        });
    if source_component != component {
        return Err(format!(
            "source-component-undeclared component={component}; engine-source-component={source_component}"
        ));
    }
    let credential_selector = match config.credential_scopes.len() {
        0 => None,
        1 => config.credential_scopes.keys().next().cloned(),
        _ => {
            return Err(format!(
                "engine-source-credential-selector-ambiguous component={component} scopes={}",
                config.credential_scopes.len()
            ));
        }
    };
    Ok(crate::source_resolver::SourceResolution {
        schema: crate::source_resolver::SOURCE_PLAN_SCHEMA,
        component: component.to_string(),
        requested_ref: branch.clone(),
        candidates: vec![crate::source_resolver::SourceCandidatePlan {
            kind: "git".to_string(),
            locator: source_repo_url.clone(),
            credential_selector,
            freshness_authority: None,
        }],
    })
}

fn source_outcome_command(outcome: &tools::git_artifact::SourceOutcome) -> CmdResult {
    CmdResult {
        ok: outcome.ok,
        code: if outcome.ok { 0 } else { 1 },
        stdout: outcome.receipt.promotion.clone(),
        stderr: if outcome.ok {
            String::new()
        } else {
            outcome.receipt.promotion.clone()
        },
    }
}

#[cfg(test)]
pub(crate) fn shadow_proof_receipt_family_diff_for_test(
    ladder_manifest: &LadderManifest,
    ladder_receipt_dir: &Path,
    compiled_receipt_dir: &Path,
    compiled: impl FnOnce(&Path) -> Result<ModuleExecution, String>,
) -> Result<Vec<String>, String> {
    let _ladder = execute_ladder_manifest(ladder_manifest, ladder_receipt_dir, false, None)?;
    let _compiled = compiled(compiled_receipt_dir)?;
    shadow_diff_receipt_families(ladder_receipt_dir, compiled_receipt_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{run_profile_engine, write_command_receipt, ModuleExecution, Profile};
    use serde_json::json;
    use std::process;

    fn base_manifest() -> LadderManifest {
        LadderManifest {
            schema: SCHEMA.into(),
            id: "synthetic-ladder".into(),
            version: "1.2.3".into(),
            description: "synthetic ladder".into(),
            role: None,
            optional: false,
            optional_warning: None,
            group: None,
            constants: BTreeMap::new(),
            caduceus_commands: Vec::new(),
            files_root: None,
            base_dir: PathBuf::new(),
            ladder: vec![LadderStep {
                step_id: "say-ok".into(),
                tool: "command".into(),
                permutation: "capture".into(),
                args: BTreeMap::from([
                    ("program".into(), json!("/usr/bin/true")),
                    ("args".into(), json!([])),
                ]),
                on_failure: OnFailure::Stop,
            }],
        }
    }

    fn defect(manifest: LadderManifest) -> String {
        validate_ladder(&manifest)
            .unwrap_err()
            .first_missing_signal()
    }

    #[test]
    fn validator_rejects_unknown_tool() {
        let mut manifest = base_manifest();
        manifest.ladder[0].tool = "missing-tool".into();
        assert_eq!(
            defect(manifest),
            "step_id=say-ok defect=unknown-tool-missing-tool"
        );
    }

    #[test]
    fn validator_rejects_undeclared_permutation() {
        let mut manifest = base_manifest();
        manifest.ladder[0].permutation = "bogus".into();
        assert_eq!(
            defect(manifest),
            "step_id=say-ok defect=undeclared-permutation-bogus"
        );
    }

    #[test]
    fn validator_rejects_missing_extra_and_type_mismatched_args() {
        let mut missing = base_manifest();
        missing.ladder[0].args.remove("program");
        assert_eq!(
            defect(missing),
            "step_id=say-ok defect=missing-argument-program"
        );

        let mut extra = base_manifest();
        extra.ladder[0].args.insert("surprise".into(), json!(true));
        assert!(validate_ladder(&extra).is_ok());

        let mut bad_type = base_manifest();
        bad_type.ladder[0].args.insert("program".into(), json!(123));
        assert_eq!(
            defect(bad_type),
            "step_id=say-ok defect=type-mismatch-program-expected-string"
        );
    }

    #[test]
    fn validator_rejects_duplicate_step_and_non_optional_continue_optional() {
        let mut duplicate = base_manifest();
        duplicate.ladder.push(duplicate.ladder[0].clone());
        assert_eq!(defect(duplicate), "step_id=say-ok defect=duplicate-step_id");

        let mut non_optional = base_manifest();
        non_optional.ladder[0].on_failure = OnFailure::ContinueOptional;
        assert_eq!(
            defect(non_optional),
            "step_id=say-ok defect=continue-optional-on-non-optional-module"
        );
    }

    #[test]
    fn constants_resolve_and_dangling_reference_is_named() {
        let mut manifest = base_manifest();
        manifest
            .constants
            .insert("program".into(), json!("/usr/bin/true"));
        manifest.ladder[0]
            .args
            .insert("program".into(), json!("${program}"));
        let steps = validate_ladder(&manifest).unwrap();
        assert_eq!(steps[0].args.get("program"), Some(&json!("/usr/bin/true")));

        manifest.ladder[0]
            .args
            .insert("program".into(), json!("$constants.absent"));
        assert_eq!(
            defect(manifest),
            "step_id=say-ok defect=dangling-constant-absent"
        );
    }

    #[test]
    fn serde_rejects_unknown_manifest_field_by_name() {
        let text = r#"{"schema":"harmonia.module.ladder.v1","id":"x","version":"1","description":"x","optional":false,"constants":{},"ladder":[],"stray":true}"#;
        let err = serde_json::from_str::<LadderManifest>(text)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown field `stray`"), "{err}");
    }

    #[test]
    fn managed_files_validator_accepts_string_owner_and_group() {
        let mut manifest = base_manifest();
        manifest.ladder[0].tool = "files".into();
        manifest.ladder[0].permutation = "managed-files".into();
        manifest.ladder[0].args = BTreeMap::from([
            ("files".into(), json!([])),
            ("owner".into(), json!("owner")),
            ("group".into(), json!("owner")),
        ]);
        validate_ladder(&manifest).unwrap();

        manifest.ladder[0].args.insert("group".into(), json!(1000));
        assert_eq!(
            defect(manifest),
            "step_id=say-ok defect=type-mismatch-group-expected-string"
        );
    }

    #[test]
    fn validator_accepts_group_live_probe_and_rejects_unknown_group_field_by_name() {
        let mut manifest = base_manifest();
        manifest.group = Some(LadderGroup {
            group_id: "git-host".into(),
            group_order: 1,
            live_probe: LadderProbe {
                tool: "systemd".into(),
                permutation: "is-active-probe".into(),
                args: BTreeMap::from([("service".into(), json!("forgejo.service"))]),
            },
        });
        validate_ladder(&manifest).unwrap();

        let text = r#"{"schema":"harmonia.module.ladder.v1","id":"x","version":"1","description":"x","group":{"group_id":"git-host","group_order":1,"live_probe":{"tool":"systemd","permutation":"is-active-probe","args":{"service":"forgejo.service"}},"stray":true},"constants":{},"ladder":[]}"#;
        let err = serde_json::from_str::<LadderManifest>(text)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown field `stray`"), "{err}");
    }

    #[test]
    fn executor_happy_path_stop_and_optional_continue() {
        let scratch = std::env::temp_dir().join(format!("harmonia-ladder-exec-{}", process::id()));
        let _ = fs::remove_dir_all(&scratch);
        let happy = base_manifest();
        let result = execute_ladder_manifest(&happy, &scratch.join("happy"), true, None).unwrap();
        assert!(result.ok);
        assert_eq!(result.operation_count, 1);

        let mut stop = base_manifest();
        stop.ladder[0]
            .args
            .insert("program".into(), json!("/usr/bin/false"));
        stop.ladder.push(LadderStep {
            step_id: "never".into(),
            tool: "command".into(),
            permutation: "capture".into(),
            args: BTreeMap::from([("program".into(), json!("/usr/bin/true"))]),
            on_failure: OnFailure::Stop,
        });
        let stopped = execute_ladder_manifest(&stop, &scratch.join("stop"), true, None).unwrap();
        assert!(!stopped.ok);
        assert_eq!(stopped.operation_count, 1);

        let mut optional = stop.clone();
        optional.optional = true;
        optional.ladder[0].on_failure = OnFailure::ContinueOptional;
        let continued =
            execute_ladder_manifest(&optional, &scratch.join("optional"), true, None).unwrap();
        assert!(!continued.ok);
        assert_eq!(continued.operation_count, 2);
        let _ = fs::remove_dir_all(&scratch);
    }

    #[test]
    fn relative_desired_source_uses_manifest_base_dir_and_keeps_receipts_separate() {
        let root = std::env::temp_dir().join(format!(
            "harmonia-relative-desired-source-{}",
            process::id()
        ));
        let manifest_dir = root.join("profiles/homeserver/modules/nginx");
        let receipt_dir = root.join("receipts/modules/nginx");
        let source = root.join("live/etc/nginx/sites-available/harmonia-shared");
        let target = root.join("live/etc/nginx/sites-enabled/harmonia-shared");
        let desired_source =
            manifest_dir.join("files_root/etc/nginx/sites-available/harmonia-shared");
        fs::create_dir_all(desired_source.parent().unwrap()).unwrap();
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&desired_source, b"manifest-authority bytes\n").unwrap();
        fs::write(
            manifest_dir.join("manifest.json"),
            format!(
                r#"{{"schema":"{SCHEMA}","id":"nginx","version":"1","description":"fixture","ladder":[{{"step_id":"validated","tool":"files","permutation":"validated-file-symlink","args":{{"desired_source":"files_root/etc/nginx/sites-available/harmonia-shared","source":"{}","target":"{}","validator_program":"/bin/true","validator_args":[],"reload_program":"","reload_args":[],"timeout_secs":5}},"on_failure":"stop"}}]}}"#,
                source.display(),
                target.display()
            ),
        )
        .unwrap();
        let manifest = load_ladder_manifest(&manifest_dir.join("manifest.json")).unwrap();
        assert_eq!(manifest.base_dir, manifest_dir);

        let result = execute_ladder_manifest(&manifest, &receipt_dir, true, None).unwrap();

        assert!(result.ok && result.changed);
        assert_eq!(
            fs::read(&source).unwrap(),
            fs::read(&desired_source).unwrap()
        );
        assert!(receipt_dir.join("validated.json").is_file());
        assert!(!receipt_dir
            .join("files_root/etc/nginx/sites-available/harmonia-shared")
            .exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn nginx_manifest_desired_source_is_a_regular_manifest_relative_file() {
        let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("profiles/homeserver/modules/nginx/manifest.json");
        let manifest = load_ladder_manifest(&manifest_path).unwrap();
        let step = manifest
            .ladder
            .iter()
            .find(|step| step.step_id == "nginx-shared-transaction")
            .unwrap();
        let desired_source =
            resolve_ladder_path(&manifest, string_arg(&step.args, "desired_source"));
        assert!(
            desired_source.is_file(),
            "expected regular desired source at {}",
            desired_source.display()
        );
    }

    #[test]
    fn engine_runs_unregistered_ladder_and_ledger_carries_version() {
        let scratch =
            std::env::temp_dir().join(format!("harmonia-ladder-engine-{}", process::id()));
        let module_root = scratch.join("profiles/test/modules");
        let module_dir = module_root.join("synthetic-ladder");
        let receipts = scratch.join("receipts/run-one");
        fs::create_dir_all(&module_dir).unwrap();
        fs::write(
            module_dir.join("manifest.json"),
            serde_json::to_string_pretty(&base_manifest()).unwrap(),
        )
        .unwrap();
        let profile = Profile {
            package_authority: None,
            id: "test".into(),
            identity: "test".into(),
            modules: vec!["synthetic-ladder".into()],
        };
        run_profile_engine(&profile, &module_root, &receipts, false).unwrap();
        let ledger = fs::read_to_string(scratch.join("receipts/test-ledger.jsonl")).unwrap();
        assert!(ledger.contains("\"module_version\":\"1.2.3\""), "{ledger}");
        let _ = fs::remove_dir_all(&scratch);
    }

    fn fixture_group_manifest(id: &str, group_order: i64, probe_program: &str) -> LadderManifest {
        LadderManifest {
            schema: SCHEMA.into(),
            id: id.into(),
            version: "1.0.0".into(),
            description: format!("{id} fixture"),
            role: None,
            optional: false,
            optional_warning: None,
            group: Some(LadderGroup {
                group_id: "git-host".into(),
                group_order,
                live_probe: LadderProbe {
                    tool: "command".into(),
                    permutation: "capture".into(),
                    args: BTreeMap::from([
                        ("program".into(), json!(probe_program)),
                        ("args".into(), json!([])),
                    ]),
                },
            }),
            constants: BTreeMap::new(),
            caduceus_commands: Vec::new(),
            files_root: None,
            base_dir: PathBuf::new(),
            ladder: vec![LadderStep {
                step_id: format!("{id}-runs"),
                tool: "command".into(),
                permutation: "capture".into(),
                args: BTreeMap::from([
                    ("program".into(), json!("/usr/bin/true")),
                    ("args".into(), json!([])),
                ]),
                on_failure: OnFailure::Stop,
            }],
        }
    }

    fn write_fixture_manifest(module_root: &Path, manifest: &LadderManifest) {
        let dir = module_root.join(&manifest.id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("manifest.json"),
            serde_json::to_string_pretty(manifest).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn group_selection_live_winner_runs_and_loser_skips_with_receipt() {
        let scratch = std::env::temp_dir().join(format!("harmonia-group-live-{}", process::id()));
        let module_root = scratch.join("modules");
        let receipts = scratch.join("receipts");
        write_fixture_manifest(
            &module_root,
            &fixture_group_manifest("forgejo", 1, "/usr/bin/true"),
        );
        write_fixture_manifest(
            &module_root,
            &fixture_group_manifest("gogs", 2, "/usr/bin/false"),
        );
        let profile = Profile {
            package_authority: None,
            id: "test".into(),
            identity: "test".into(),
            modules: vec!["forgejo".into(), "gogs".into()],
        };
        run_profile_engine(&profile, &module_root, &receipts, false).unwrap();
        assert!(receipts.join("modules/forgejo/forgejo-runs.json").exists());
        assert!(!receipts.join("modules/gogs/gogs-runs.json").exists());
        let selection =
            fs::read_to_string(receipts.join("groups/git-host-selection.json")).unwrap();
        assert!(
            selection.contains("harmonia.group.selection.v1"),
            "{selection}"
        );
        assert!(selection.contains("\"winner\": \"forgejo\""), "{selection}");
        assert!(
            selection.contains("\"losers\": [\n    \"gogs\"\n  ]"),
            "{selection}"
        );
        let ledger = fs::read_to_string(scratch.join("test-ledger.jsonl")).unwrap();
        assert!(ledger.contains("group-lost-to:forgejo"), "{ledger}");
        let _ = fs::remove_dir_all(&scratch);
    }

    #[test]
    fn group_selection_all_probes_failing_still_runs_lowest_order_winner() {
        let scratch = std::env::temp_dir().join(format!("harmonia-group-dead-{}", process::id()));
        let module_root = scratch.join("modules");
        let receipts = scratch.join("receipts");
        write_fixture_manifest(
            &module_root,
            &fixture_group_manifest("forgejo", 1, "/usr/bin/false"),
        );
        write_fixture_manifest(
            &module_root,
            &fixture_group_manifest("gogs", 2, "/usr/bin/false"),
        );
        let profile = Profile {
            package_authority: None,
            id: "test".into(),
            identity: "test".into(),
            modules: vec!["forgejo".into(), "gogs".into()],
        };
        run_profile_engine(&profile, &module_root, &receipts, false).unwrap();
        assert!(receipts.join("modules/forgejo/forgejo-runs.json").exists());
        assert!(!receipts.join("modules/gogs/gogs-runs.json").exists());
        let selection =
            fs::read_to_string(receipts.join("groups/git-host-selection.json")).unwrap();
        assert!(selection.contains("\"winner\": \"forgejo\""), "{selection}");
        assert!(selection.contains("\"ok\": false"), "{selection}");
        let _ = fs::remove_dir_all(&scratch);
    }

    #[test]
    fn shadow_proof_harness_diffs_receipt_families_on_synthetic_fixture() {
        let scratch = std::env::temp_dir().join(format!("harmonia-shadow-{}", process::id()));
        let ladder_dir = scratch.join("ladder");
        let compiled_dir = scratch.join("compiled");
        let diff = shadow_proof_receipt_family_diff_for_test(
            &base_manifest(),
            &ladder_dir,
            &compiled_dir,
            |dir| {
                let result = CmdResult {
                    ok: true,
                    code: 0,
                    stdout: "compiled".into(),
                    stderr: String::new(),
                };
                write_command_receipt(dir, "say-ok", &result)?;
                Ok(ModuleExecution {
                    ok: true,
                    changed: false,
                    operation_count: 1,
                    first_missing_signal: None,
                    placements: Vec::new(),
                })
            },
        )
        .unwrap();
        assert!(
            diff.is_empty(),
            "receipt family diff should be empty: {diff:?}"
        );
        let _ = fs::remove_dir_all(&scratch);
    }
}
