use crate::{tools, CmdResult, ModuleExecution, OperationOutcome};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
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
#[serde(deny_unknown_fields)]
pub(crate) struct LadderStep {
    pub step_id: String,
    pub tool: String,
    pub permutation: String,
    #[serde(default)]
    pub args: BTreeMap<String, Value>,
    #[serde(default = "default_on_failure")]
    pub on_failure: OnFailure,
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

pub(crate) fn execute_group_live_probe(
    manifest: &LadderManifest,
    receipt_dir: &Path,
) -> Result<OperationOutcome, String> {
    let Some(group) = &manifest.group else {
        return Err(format!("module-{}-has-no-group", manifest.id));
    };
    let step = validate_group(group, &manifest.constants)
        .map_err(|err| format!("module-invalid {}", err.first_missing_signal()))?;
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    execute_validated_step(&step, manifest, receipt_dir, true, None, false)
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

fn validate_tool_semantics(
    step_id: &str,
    tool: &str,
    permutation: &str,
    args: &BTreeMap<String, Value>,
) -> Result<(), LadderValidationError> {
    match (tool, permutation) {
        ("systemd", "enable-first-present-now") => {
            tools::systemd::validate_candidate_units(args).map_err(|defect| LadderValidationError {
                step_id: step_id.into(),
                defect,
            })
        }
        ("service-runtime", "converge") => tools::service_runtime::validate_ladder_args(args)
            .map_err(|defect| LadderValidationError {
                step_id: step_id.into(),
                defect,
            }),
        ("aur", permutation) => {
            tools::aur::validate_ladder_args(permutation, args).map_err(|defect| {
                LadderValidationError { step_id: step_id.into(), defect }
            })
        }
        ("household-time", permutation) => tools::household_time::validate_ladder_args(permutation, args)
            .map_err(|defect| LadderValidationError { step_id: step_id.into(), defect }),
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

pub(crate) fn execute_ladder_manifest(
    manifest: &LadderManifest,
    module_dir: &Path,
    apply: bool,
    package_authority: Option<&crate::PackageAuthority>,
) -> Result<ModuleExecution, String> {
    let steps = validate_ladder(manifest)
        .map_err(|err| format!("module-invalid {}", err.first_missing_signal()))?;
    fs::create_dir_all(module_dir).map_err(|e| e.to_string())?;
    let mut ok = true;
    let mut changed = false;
    let mut first_missing_signal = None;
    let mut operation_count = 0usize;
    for step in steps {
        operation_count += 1;
        let outcome = execute_validated_step(
            &step,
            manifest,
            module_dir,
            apply,
            package_authority,
            changed,
        )?;
        if outcome.changed {
            changed = true;
        }
        if !outcome.ok {
            ok = false;
            if first_missing_signal.is_none() {
                first_missing_signal =
                    Some(format!("step_id={} defect=tool-step-failed", step.step_id));
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
    apply: bool,
    package_authority: Option<&crate::PackageAuthority>,
    module_changed_before_step: bool,
) -> Result<OperationOutcome, String> {
    match (step.tool.as_str(), step.permutation.as_str()) {
        ("command", "capture") => command_capture_step(step, module_dir, apply),
        ("artifact-lock", "verify") => artifact_lock_step(step, module_dir, apply),
        ("health", "probe") => health_probe_step(step, module_dir, apply),
        ("household-time", _) => household_time_step(step, module_dir, apply),
        ("files", "managed-files") => managed_files_step(step, manifest, module_dir, apply),
        ("files", "validated-symlink") => validated_symlink_step(step, module_dir, apply),
        ("files", "validated-file-symlink") => {
            validated_file_symlink_step(step, manifest, module_dir, apply)
        }
        ("files", "remove") => files_remove_step(step, module_dir, apply),
        ("files", "converge") | ("files", "directory-sync") => {
            files_converge_step(step, manifest, module_dir, apply)
        }
        ("systemd", _) => systemd_step(step, module_dir, apply, module_changed_before_step),
        ("service-runtime", "converge") => {
            let source_plan = source_plan_for_step(step, manifest)?;
            tools::service_runtime::execute_ladder_step(
                &step.args,
                module_dir,
                apply,
                &source_plan,
            )
        }
        .map(|execution| OperationOutcome {
            ok: execution.ok,
            changed: execution.changed,
            skipped: false,
            message: format!(
                "service-runtime converge operations={}",
                execution.operation_count
            ),
            command: None,
        }),
        ("git-artifact", "sync") => git_artifact_step(step, manifest, module_dir, apply),
        ("ai-coding-harness", "reconcile") => ai_coding_harness_step(step, module_dir, apply),
        ("machine-id", "truncate") => machine_id_step(step, module_dir, apply),
        ("aur", "install") | ("aur", "check") | ("aur", "build-pinned") => {
            aur_step(step, manifest, module_dir, apply)
        }
        ("package", "check")
        | ("package", "install")
        | ("package", "upgrade")
        | ("package", "keyring-repair") => package_step(step, module_dir, apply, package_authority),
        _ => Err(format!(
            "ladder-executor-missing tool={} permutation={}",
            step.tool, step.permutation
        )),
    }
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
        apply,
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

fn household_time_step(
    step: &ValidatedStep,
    module_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    tools::household_time::execute(module_dir, &step.step_id, &step.permutation, &step.args, apply)
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
        apply,
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
    crate::tools::validated_file_symlink::execute(
        crate::tools::validated_file_symlink::ValidatedFileSymlinkRequest {
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
    )
}

fn files_remove_step(
    step: &ValidatedStep,
    module_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let outcome = crate::tools::files::remove_declared_files(
        &PathBuf::from(string_arg(&step.args, "target_root")),
        &string_array_arg(&step.args, "paths"),
        module_dir,
        &step.step_id,
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

fn files_converge_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    apply: bool,
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
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: !apply,
            message: format!(
                "directory-sync same-root verified {}",
                source_root.display()
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
    let outcome = crate::tools::files::converge_files(&request, module_dir, apply)?;
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
    )
}

fn package_step(
    step: &ValidatedStep,
    module_dir: &Path,
    apply: bool,
    package_authority: Option<&crate::PackageAuthority>,
) -> Result<OperationOutcome, String> {
    let backend = package_authority
        .ok_or_else(|| "profile-package-authority-missing".to_string())?
        .backend()?;
    let packages = string_array_arg(&step.args, "packages");
    let timeout_secs = integer_arg(&step.args, "timeout_secs", 1800);
    match step.permutation.as_str() {
        "check" => crate::tools::package::package_tool_for_backend(
            module_dir,
            &step.step_id,
            "check",
            &packages,
            apply,
            backend,
        ),
        "install" => {
            let conflict_paths = string_array_arg(&step.args, "conflict_paths");
            crate::tools::package::package_tool_with_policy_for_backend(
                module_dir,
                &step.step_id,
                "install",
                &packages,
                apply,
                optional_string_arg(&step.args, "conflict_policy"),
                &conflict_paths,
                timeout_secs,
                backend,
            )
        }
        "upgrade" => crate::tools::package::package_tool_with_policy_for_backend(
            module_dir,
            &step.step_id,
            "upgrade",
            &[],
            apply,
            None,
            &[],
            timeout_secs,
            backend,
        ),
        "keyring-repair" if backend == crate::PackageBackend::Pacman => {
            crate::tools::package::keyring_repair_tool(
                module_dir,
                &step.step_id,
                optional_string_arg(&step.args, "package").unwrap_or("archlinux-keyring"),
                apply,
                timeout_secs,
            )
        }
        "keyring-repair" => Err("package-keyring-repair-backend-unsupported".to_string()),
        other => Err(format!("package-permutation-unsupported-{other}")),
    }
}

fn machine_id_step(
    step: &ValidatedStep,
    module_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    tools::machine_id::truncate(
        module_dir,
        &step.step_id,
        optional_string_arg(&step.args, "etc_machine_id"),
        optional_string_arg(&step.args, "dbus_machine_id"),
        apply,
    )
}

fn aur_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let package = string_arg(&step.args, "package");
    match step.permutation.as_str() {
        "install" => crate::tools::aur::install(
            module_dir,
            &step.step_id,
            package,
            integer_arg(&step.args, "timeout_secs", 3600),
            apply,
        ),
        "check" => crate::tools::aur::check(
            module_dir,
            &step.step_id,
            package,
            &resolve_ladder_path(manifest, string_arg(&step.args, "lock")),
            optional_string_arg(&step.args, "upstream_state"),
        ),
        "build-pinned" => crate::tools::aur::build_pinned(
            module_dir,
            &step.step_id,
            package,
            &resolve_ladder_path(manifest, string_arg(&step.args, "lock")),
            &PathBuf::from(string_arg(&step.args, "build_root")),
            optional_string_arg(&step.args, "source_dir"),
            optional_string_arg(&step.args, "builder_user"),
            integer_arg(&step.args, "timeout_secs", 3600),
            step.args
                .get("install")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            apply,
        ),
        other => Err(format!("aur-permutation-unsupported-{other}")),
    }
}

fn ai_coding_harness_step(
    step: &ValidatedStep,
    module_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    tools::ai_coding_harness::reconcile(
        string_arg(&step.args, "owner"),
        string_arg(&step.args, "claude_bin"),
        string_arg(&step.args, "honcho_repo"),
        string_arg(&step.args, "honcho_remote"),
        string_arg(&step.args, "honcho_branch"),
        integer_arg(&step.args, "timeout_secs", 900),
        module_dir,
        apply,
    )
}

fn git_artifact_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let source_plan = source_plan_for_step(step, manifest)?;
    let outcome = if apply {
        tools::git_artifact::acquire_source(&source_plan)
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
    Ok(OperationOutcome {
        ok: outcome.ok,
        changed: outcome.changed,
        skipped: !apply,
        message: outcome.receipt.promotion,
        command: Some(command),
    })
}

fn source_plan_for_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
) -> Result<tools::git_artifact::SourcePlan, String> {
    let component = string_arg(&step.args, "component");
    if component.trim().is_empty() {
        return Err(format!("source-component-missing module={} step_id={}", manifest.id, step.step_id));
    }
    let destination = optional_string_arg(&step.args, "path")
        .or_else(|| optional_string_arg(&step.args, "source_dir"))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("source-destination-missing module={} step_id={}", manifest.id, step.step_id))?;
    let certificate = std::env::var_os("HARMONIA_DEVICE_PROFILE_CERTIFICATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/profile.json"));
    let resolution = crate::resolve_source(&certificate, component, &manifest.id, &step.step_id);
    if let Some(blocker) = resolution.blocker {
        return Err(format!("source-resolution-blocked module={} step_id={} component={} blocker={blocker}", manifest.id, step.step_id, component));
    }
    let resolution = resolution
        .resolution
        .ok_or_else(|| format!("source-resolution-plan-missing module={} step_id={} component={component}", manifest.id, step.step_id))?;
    let config = crate::load_engine_plane_config(&crate::engine_config_path())?;
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
        optional_string_arg(&step.args, "bearer").unwrap_or("owner").to_string(),
        expected_commit,
        credentials,
    ))
}

fn source_outcome_command(outcome: &tools::git_artifact::SourceOutcome) -> CmdResult {
    CmdResult {
        ok: outcome.ok,
        code: if outcome.ok { 0 } else { 1 },
        stdout: outcome.receipt.promotion.clone(),
        stderr: if outcome.ok { String::new() } else { outcome.receipt.promotion.clone() },
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
