use crate::tools::routine::{
    resolve_args, validate_args, validate_command_precondition, validate_tool_semantics,
};
pub(crate) use crate::tools::routine::{ProjectedRoutineChild, ValidatedStep};
use crate::tools;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
        ("managed-files", "files", "managed-files"),
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
            && child.tool == "files"
            && child.permutation.as_deref() == Some("managed-files")
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
            && child.tool == "files"
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
    use crate::CmdResult;
    use serde_json::{json, Map};
    use crate::tools::routine::*;
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
