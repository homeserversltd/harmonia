use crate::tools;
use crate::tools::routine::{
    resolve_args, validate_args, validate_command_precondition, validate_tool_semantics,
};
pub(crate) use crate::tools::routine::{ProjectedRoutineChild, ValidatedStep};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) const SCHEMA: &str = "harmonia.module.ladder.v1";

#[derive(Debug, Clone, Deserialize, Serialize)]
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
    /// Package names mapped to the exact installed version Harmonia must hold.
    #[serde(default)]
    pub package_pins: BTreeMap<String, String>,
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
pub(crate) struct LadderGroup {
    pub group_id: String,
    pub group_order: i64,
    pub live_probe: LadderProbe,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
pub(crate) struct CommandPrecondition {
    pub(crate) program: String,
    #[serde(default)]
    pub(crate) args: Vec<String>,
    #[serde(default)]
    pub(crate) cwd: Option<String>,
    #[serde(default)]
    pub(crate) timeout_secs: Option<u64>,
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
    load_ladder_manifest_with_category_requirement(path, false)
}

pub(crate) fn load_ladder_manifest_with_category_requirement(
    path: &Path,
    categories_required: bool,
) -> Result<LadderManifest, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("ladder-manifest-read-failed {}: {e}", path.display()))?;
    let mut raw = serde_json::from_str::<Value>(&text)
        .map_err(|e| format!("ladder-manifest-parse-failed {}: {e}", path.display()))?;
    let module_category = raw
        .get("category")
        .and_then(Value::as_str)
        .map(str::to_owned);
    raw.as_object_mut()
        .and_then(|object| object.remove("category"));
    normalize_managed_file_categories(&mut raw, module_category.as_deref())?;
    validate_raw_managed_file_categories(&raw, categories_required)?;
    serde_json::from_value::<LadderManifest>(raw)
        .map_err(|e| format!("ladder-manifest-parse-failed {}: {e}", path.display()))
        .and_then(|mut manifest| {
            if manifest.schema == SCHEMA {
                validate_package_pins(&manifest.package_pins)
                    .map_err(|e| format!("ladder-manifest-pin-validation-failed {e}"))?;
                let module_name = path
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|name| name.to_str())
                    .unwrap_or_default();
                validate_package_pin_module(module_name, &manifest.id, &manifest.package_pins)?;
                lower_service_runtime_steps(&mut manifest)
                    .map_err(|e| format!("ladder-manifest-lowering-failed {e}"))?;
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

const MANAGED_FILE_CATEGORIES: [&str; 2] = ["known-good", "interactable"];

fn managed_file_category(category: Option<&str>) -> Result<Option<&'static str>, String> {
    let canonical = match category {
        None | Some("known-good") => "known-good",
        Some("interactable") => "interactable",
        Some(value) => return Err(format!("managed-file-category-unsupported-{value}")),
    };
    Ok(MANAGED_FILE_CATEGORIES
        .iter()
        .copied()
        .find(|candidate| *candidate == canonical))
}

fn normalize_managed_file_categories(
    value: &mut Value,
    module_category: Option<&str>,
) -> Result<(), String> {
    if let Some(object) = value.as_object_mut() {
        let target = (object.get("tool").and_then(Value::as_str) == Some("files")
            && object.get("permutation").and_then(Value::as_str) == Some("managed-files"))
            || object.get("tool").and_then(Value::as_str) == Some("service-runtime");
        if target {
            if let Some(args) = object.get_mut("args").and_then(Value::as_object_mut) {
                let key = if args.contains_key("files") {
                    "files"
                } else {
                    "managed_files"
                };
                if let Some(files) = args.get_mut(key).and_then(Value::as_array_mut) {
                    for file in files {
                        if let Some(file) = file.as_object_mut() {
                            let source = file
                                .get("category")
                                .and_then(Value::as_str)
                                .map(str::to_owned)
                                .or_else(|| module_category.map(str::to_owned));
                            let category = managed_file_category(source.as_deref())?
                                .ok_or_else(|| "managed-file-category-missing".to_string())?;
                            file.insert("category".into(), Value::String(category.into()));
                            if file.contains_key("on_drift") {
                                return Err("managed-file-on-drift-retired".into());
                            }
                        }
                    }
                }
            }
        }
        for child in object.values_mut() {
            normalize_managed_file_categories(child, module_category)?;
        }
    } else if let Some(items) = value.as_array_mut() {
        for item in items {
            normalize_managed_file_categories(item, module_category)?;
        }
    }
    Ok(())
}

fn validate_raw_managed_file_categories(_raw: &Value, _required: bool) -> Result<(), String> {
    // Unknown/retired fields are intentionally ignored; legacy aliases are
    // projected by normalize_managed_file_categories before deserialization.
    Ok(())
}

pub(crate) fn validate_profile_managed_file_categories(
    profile: &crate::Profile,
    module_root: &Path,
    required: bool,
) -> Result<(), String> {
    for module in &profile.modules {
        let path = crate::bands::stage_profile::resolve_module_dir(module_root, module)?
            .join("manifest.json");
        if path.exists() && is_ladder_manifest(&path) {
            load_ladder_manifest_with_category_requirement(&path, required)?;
        }
    }
    Ok(())
}

pub(crate) fn validate_package_pins(pins: &BTreeMap<String, String>) -> Result<(), String> {
    for (name, version) in pins {
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@._+:-".contains(&b))
        {
            return Err(format!("package-pin-name-unsafe-{name}"));
        }
        if version.is_empty()
            || version.chars().any(|c| {
                c.is_whitespace()
                    || c.is_control()
                    || matches!(
                        c,
                        ';' | '&' | '|' | '$' | '`' | '>' | '<' | '\\' | '\'' | '"'
                    )
            })
        {
            return Err(format!("package-pin-version-unsafe-{name}"));
        }
    }
    Ok(())
}

pub(crate) fn validate_package_pin_module(
    module_name: &str,
    manifest_id: &str,
    pins: &BTreeMap<String, String>,
) -> Result<(), String> {
    if !pins.is_empty() && (module_name != "pins" || manifest_id != "pins") {
        return Err("pin-declared-outside-pins-module".into());
    }
    Ok(())
}

fn lower_service_runtime_steps(manifest: &mut LadderManifest) -> Result<(), String> {
    crate::bands::restart_services::lower_service_runtime_steps(manifest);
    crate::bands::backfill_files::lower_service_runtime_steps(manifest)?;
    Ok(())
}

pub(crate) fn is_lowered_service_runtime_converge(step: &LadderStep) -> bool {
    let stages = [
        ("pull-repo", "pull-repo", "acquire"),
        ("build", "build-crate", "build"),
        ("binary-install", "place-file", "binary-promotion"),
        ("managed-files", "files", "managed-files"),
        ("service-daemon-reload", "systemd", "daemon-reload"),
        ("service-enable", "enable-unit", "enable"),
        ("service-restart", "systemd", "restart"),
        ("service-active", "systemd", "is-active-probe"),
        ("unit-authority-proof", "systemd", "show-assert"),
        ("health-proof", "check-health", "probe"),
        ("source-sha-record", "place-file", "source-sha-record"),
    ];
    // The managed-files proposal is optional: the bounded shape is either
    // pull/build/install + suffix, or the same with one proposal child.
    if step.tool != "routine"
        || step.permutation != "execute"
        || step.steps.len() < stages.len() - 1
    {
        return false;
    }
    let Some((pull, build, install)) = step
        .steps
        .first()
        .zip(step.steps.get(1))
        .zip(step.steps.get(2))
        .map(|((pull, build), install)| (pull, build, install))
    else {
        return false;
    };
    let legacy_build =
        build.tool == "build-crate" && build.permutation.as_deref() == Some("build");
    let caduceus_build = build.tool == "fetch-artifact"
        && build.permutation.as_deref() == Some("fetch")
        && build.args.get("component").and_then(Value::as_str) == Some("caduceus")
        && build
            .args
            .get("registry_base")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
        && build
            .args
            .get("destination")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
        && build.args.get("installed_binary").is_some();
    if pull.name != stages[0].0
        || pull.tool != stages[0].1
        || pull.permutation.as_deref() != Some(stages[0].2)
        || install.name != stages[2].0
        || install.tool != stages[2].1
        || install.permutation.as_deref() != Some(stages[2].2)
        || (!legacy_build && !caduceus_build)
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
            && child.tool == "files"
            && child.permutation.as_deref() == Some("managed-files")
    });
    let suffix_end = if has_proposal {
        step.steps.len() - 1
    } else {
        step.steps.len()
    };
    let suffix = &step.steps[suffix_start..suffix_end];
    let authority_present = suffix.get(4).is_some_and(|child| {
        child.name == "unit-authority-proof"
            && child.tool == "systemd"
            && child.permutation.as_deref() == Some("show-assert")
    });
    let source_sha_present = suffix.last().is_some_and(|child| {
        child.name == "source-sha-record"
            && child.tool == "place-file"
            && child.permutation.as_deref() == Some("source-sha-record")
    });
    let expected_suffix = if authority_present {
        if source_sha_present {
            &stages[4..]
        } else {
            &stages[4..10]
        }
    } else if source_sha_present {
        &[
            stages[4], stages[5], stages[6], stages[7], stages[9], stages[10],
        ][..]
    } else {
        &[stages[4], stages[5], stages[6], stages[7], stages[9]][..]
    };
    if suffix.len() != expected_suffix.len() {
        return false;
    }
    let mut config_count = 0;
    for child in &step.steps[3..suffix_start] {
        if child.name == "managed-files"
            && child.tool == "files"
            && child.permutation.as_deref() == Some("managed-files")
        {
            config_count += 1;
        } else if !((child.name.starts_with("managed-file-")
            || child.name.starts_with("managed-place-")
            || child.name.starts_with("managed-backfill-")
            || child.name.starts_with("managed-remove-")
            || child.name.starts_with("managed-symlink-"))
            && child.tool == "place-file"
            && child.permutation.as_deref() == Some("place"))
        {
            return false;
        }
    }
    if config_count > 1 {
        return false;
    }
    if !suffix
        .iter()
        .zip(expected_suffix.iter())
        .all(|(c, (n, t, p))| c.name == *n && c.tool == *t && c.permutation.as_deref() == Some(*p))
    {
        return false;
    }
    let (Some(pull), Some(build), Some(install), Some(epilogue)) = (
        step.steps.get(0),
        step.steps.get(1),
        step.steps.get(2),
        step.steps.iter().find(|child| {
            child.name == "service-enable"
                && child.tool == "enable-unit"
                && child.permutation.as_deref() == Some("enable")
        }),
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
    let pull_bearer = pull
        .args
        .get("bearer")
        .map(Value::as_str)
        .unwrap_or(Some(crate::tools::service_runtime::DEFAULT_BEARER));
    let epilogue_bearer = epilogue
        .args
        .get("bearer")
        .map(Value::as_str)
        .unwrap_or(Some(crate::tools::service_runtime::DEFAULT_BEARER));
    pull.args.get("component") == epilogue.args.get("component")
        && pull_bearer.is_some()
        && pull_bearer == epilogue_bearer
        && pull
            .args
            .get("path")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
        && (caduceus_build
            || build.args.get("cwd") == Some(&serde_json::json!({"from":"pull-repo.path"})))
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
        && (if caduceus_build {
            build.args.get("artifact_name") == Some(&Value::String("caduceus".into()))
                && build.args.get("installed_binary") == epilogue.args.get("install_bin")
        } else {
            build.args.get("op_prefix") == epilogue.args.get("op_prefix")
        })
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
    crate::tools::declaration::all().map_err(|defect| LadderValidationError {
        step_id: "declaration-validation".into(),
        defect,
    })?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }
    fn manifest_path() -> PathBuf {
        root().join("profiles/homeconsole/modules/rust-build-toolchain/manifest.json")
    }

    #[test]
    fn homeconsole_rust_build_toolchain_manifest_loads_and_validates() {
        let root = root();
        let index: Value = serde_json::from_str(
            &fs::read_to_string(root.join("profiles/homeconsole/index.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(index["categories_required"], true);
        assert_eq!(
            index["package_authority"],
            json!({"os_family":"arch", "package_manager":"pacman"})
        );
        let path = manifest_path();
        let raw: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(raw["category"], "known-good");
        assert_eq!(raw["version"], "1.1.0");
        assert_eq!(raw["optional"], false);
        assert_eq!(raw["constants"]["packages"], json!(["rust"]));
        let manifest = load_ladder_manifest_with_category_requirement(&path, true).unwrap();
        let validated = validate_ladder(&manifest).unwrap();
        assert_eq!(validated.len(), 2);
        assert_eq!(
            validated
                .iter()
                .map(|s| s.step_id.as_str())
                .collect::<Vec<_>>(),
            vec!["rust-toolchain-directories", "rust-wrapper-shims"]
        );
    }

    #[test]
    fn homeconsole_rust_build_toolchain_surface_is_exact() {
        let manifest =
            load_ladder_manifest_with_category_requirement(&manifest_path(), true).unwrap();
        let dirs = json!([{"path":"/opt/rustup","mode":493,"owner":"owner","group":"owner"},{"path":"/opt/cargo","mode":493,"owner":"owner","group":"owner"}]);
        assert_eq!(manifest.ladder[0].args.get("directories"), Some(&dirs));
        assert_eq!(manifest.ladder[0].on_failure, OnFailure::Stop);
        assert_eq!(manifest.ladder[1].args, BTreeMap::new());
        assert_eq!(manifest.ladder[1].on_failure, OnFailure::Stop);
        assert_eq!(manifest.files_root.as_deref(), Some("files_root"));
        let wrappers = root()
            .join("profiles/homeconsole/modules/rust-build-toolchain/files_root/usr/local/bin");
        for (name, target) in [("rustc", "/usr/bin/rustc"), ("cargo", "/usr/bin/cargo")] {
            let path = wrappers.join(name);
            let expected = format!("#!/bin/sh\nexport RUSTUP_HOME=/opt/rustup\nexport CARGO_HOME=/opt/cargo\nexec {} \"$@\"\n", target);
            assert_eq!(fs::read(&path).unwrap(), expected.as_bytes());
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        assert!(!wrappers.join("rustup").exists());
    }

    #[test]
    fn homeconsole_rust_build_toolchain_precedes_arcadia() {
        let index: Value = serde_json::from_str(
            &fs::read_to_string(root().join("profiles/homeconsole/index.json")).unwrap(),
        )
        .unwrap();
        let modules = index["modules"].as_array().unwrap();
        let rust = modules
            .iter()
            .position(|m| m == "rust-build-toolchain")
            .unwrap();
        let arcadia = modules
            .iter()
            .position(|m| m == "arcadia-gui-runtime")
            .unwrap();
        assert!(rust < arcadia);
    }
}
