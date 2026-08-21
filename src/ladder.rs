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

pub(crate) fn slice4_bench(
    root: &Path,
    _key: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<serde_json::Value, String> {
    let profile_root = root.join("profiles/synthetic-ladder");
    let module_dir = profile_root.join("modules/synthetic-ladder");
    let output_dir = root.join("molt-output");
    let receipts = root.join("receipts");
    let first_receipts = receipts.join("run-one");
    let second_receipts = receipts.join("run-two");
    let subscription = root.join("subscription.json");
    fs::create_dir_all(&module_dir).map_err(|e| e.to_string())?;
    fs::create_dir_all(root.join("src/tools")).map_err(|e| e.to_string())?;
    fs::write(
        root.join("Cargo.toml"),
        b"[package]\nname=\"scratch\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        profile_root.join("index.json"),
        br#"{"id":"synthetic-ladder","identity":"synthetic-ladder","modules":["synthetic-ladder"]}"#,
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        module_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": SCHEMA,
            "id": "synthetic-ladder",
            "version": "1.2.3",
            "description": "complete scratch ladder fixture",
            "optional": false,
            "constants": {},
            "ladder": []
        }))
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    crate::bands::stage_profile::molt::molt_at_subscription_path(
        root,
        "synthetic-ladder",
        &output_dir,
        &first_receipts,
        &subscription,
        crate::bands::stage_profile::molt::MoltMode::Copy,
    )?;
    crate::bands::stage_profile::molt::molt_at_subscription_path(
        root,
        "synthetic-ladder",
        &output_dir,
        &second_receipts,
        &subscription,
        crate::bands::stage_profile::molt::MoltMode::Copy,
    )?;

    let read_json = |path: &Path| -> Result<serde_json::Value, String> {
        serde_json::from_slice(&fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?)
            .map_err(|e| format!("{}: {e}", path.display()))
    };
    let first = read_json(&first_receipts.join("molt.json"))?;
    let witness_root = receipts.join("report-home-proof");
    fs::create_dir_all(witness_root.join("modules/alpha/deep")).map_err(|e| e.to_string())?;
    fs::create_dir_all(witness_root.join("modules/beta")).map_err(|e| e.to_string())?;
    fs::write(
        witness_root.join("root.pin-witness.json"),
        r#"{"exclusion_set":["ignored"]}"#,
    )
    .map_err(|e| e.to_string())?;
    for (path, name, state) in [
        (
            "modules/alpha/alpha.pin-witness.json",
            "exact",
            "held/green",
        ),
        (
            "modules/alpha/deep/deep.pin-witness.json",
            "absent",
            "absent",
        ),
        (
            "modules/beta/beta.pin-witness.json",
            "divergent",
            "divergent",
        ),
    ] {
        fs::write(
            witness_root.join(path),
            serde_json::json!({
                "exclusion_set": [name, "shared"],
                "witness": [{"name": name, "state": state}],
                "pin_scope_limitation": crate::atoms::package::PACKAGE_PIN_SCOPE_LIMITATION,
            })
            .to_string(),
        )
        .map_err(|e| e.to_string())?;
    }
    let (report_witnesses, report_exclusions) = crate::bands::report_home::collect_package_pin_witnesses(&witness_root);
    let report_home_nested_witnesses = report_witnesses.len() == 3;
    let report_home_root_ignored = !report_witnesses.iter().any(|v| {
        v["exclusion_set"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "ignored"))
    });
    let report_home_exclusions_deduped = report_exclusions.into_iter().collect::<Vec<_>>()
        == ["absent", "divergent", "exact", "shared"];
    let report_home_states = ["held/green", "absent", "divergent"]
        .iter()
        .all(|state| {
            report_witnesses
                .iter()
                .any(|v| v["witness"][0]["state"] == *state)
        });
    let exact_scope_limitation = "Harmonia's pin excludes names only from Harmonia-owned package transactions; it cannot stop the operator's own hand or a bare pacman/apt command run outside Harmonia (for example, `pacman -Syu`).";
    let report_home_scope_limitation = report_witnesses.iter().all(|v| {
        v["pin_scope_limitation"] == crate::atoms::package::PACKAGE_PIN_SCOPE_LIMITATION
    });
    let report_home_scope_exact_literal = report_witnesses
        .iter()
        .all(|v| v["pin_scope_limitation"] == exact_scope_limitation);
    let second = read_json(&second_receipts.join("molt.json"))?;
    let subscription_record = read_json(&subscription)?;
    let output_manifest = read_json(&output_dir.join("modules/synthetic-ladder/manifest.json"))?;
    let first_production_run_ok = first["ok"].as_bool() == Some(true)
        && first["profile_id"] == "synthetic-ladder"
        && first["subscription_updated"].as_bool() == Some(true)
        && output_manifest["version"] == "1.2.3";
    let second_production_run_quiet = second["ok"].as_bool() == Some(true)
        && second["untouched_modules"]
            .as_array()
            .is_some_and(|modules| modules.iter().any(|module| module == "synthetic-ladder"));
    let ledger_carries_version =
        subscription_record["modules"]["synthetic-ladder"]["version"] == "1.2.3";
    Ok(serde_json::json!({
        "first_production_run_ok": first_production_run_ok,
        "second_production_run_quiet": second_production_run_quiet,
        "ledger_carries_version": ledger_carries_version,
        "report_home_nested_witnesses": report_home_nested_witnesses,
        "report_home_root_ignored": report_home_root_ignored,
        "report_home_exclusions_deduped": report_home_exclusions_deduped,
        "report_home_states": report_home_states,
        "report_home_scope_limitation": report_home_scope_limitation,
        "report_home_scope_exact_literal": report_home_scope_exact_literal,
        "production_route": "crate::bands::stage_profile::molt::molt_at_subscription_path",
        "receipt_paths": [first_receipts.join("molt.json"), second_receipts.join("molt.json")],
        "ledger_path": subscription,
        "ok": first_production_run_ok && second_production_run_quiet && ledger_carries_version && report_home_nested_witnesses && report_home_root_ignored && report_home_exclusions_deduped && report_home_states
            && report_home_scope_limitation
            && report_home_scope_exact_literal
    }))
}

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
