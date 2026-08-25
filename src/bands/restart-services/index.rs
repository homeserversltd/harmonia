use super::Band;
use crate::tools::ladder::RoutineStep;
use crate::tools::ladder::{LadderManifest, ProjectedRoutineChild, ValidatedStep};
use crate::ModuleExecution;
use crate::OperationOutcome;
use crate::{
    LoadedModule, PackageAuthority, Profile, ProfileProjection, SoftwareApplyAuthorization,
    UpdateMode,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::Path;

pub(crate) fn enter(enter: &mut impl FnMut(Band) -> Result<(), String>) -> Result<(), String> {
    enter(Band::RestartServices)
}

pub(crate) fn lower_service_runtime_steps(manifest: &mut LadderManifest) {
    for step in &mut manifest.ladder {
        if step.tool != "service-runtime" || step.permutation != "converge" {
            continue;
        }
        let args = step.args.clone();
        let mut pull = BTreeMap::new();
        if let Some(v) = args.get("component") {
            pull.insert("component".into(), v.clone());
        }
        pull.insert(
            "bearer".into(),
            args.get("bearer")
                .cloned()
                .unwrap_or_else(|| Value::String("owner".into())),
        );
        pull.insert(
            "path".into(),
            args.get("source_dir")
                .cloned()
                .unwrap_or_else(|| Value::String(String::new())),
        );
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
        ];
        let has_managed_files = args
            .get("managed_files")
            .and_then(Value::as_array)
            .is_some_and(|files| !files.is_empty());
        step.tool = "routine".into();
        step.permutation = "execute".into();
        step.args.clear();
        step.steps = stages
            .into_iter()
            .filter(|(name, _, _)| {
                (*name != "managed-files" || has_managed_files)
                    && (*name != "unit-authority-proof"
                        || args
                            .get("expected_unit_properties")
                            .and_then(Value::as_object)
                            .is_some())
            })
            .map(|(name, tool, permutation)| {
                let child_args = match name {
                    "pull-repo" => pull.clone(),
                    "build" => {
                        let mut c = args.clone();
                        c.insert("cwd".into(), serde_json::json!({"from":"pull-repo.path"}));
                        c.insert(
                            "source_build_sha".into(),
                            serde_json::json!({"from":"pull-repo.resolved_commit"}),
                        );
                        c.insert(
                            "installed_binary".into(),
                            args.get("install_bin")
                                .cloned()
                                .unwrap_or(Value::String(String::new())),
                        );
                        c.insert(
                            "artifact_name".into(),
                            args.get("binary_name")
                                .cloned()
                                .unwrap_or(Value::String(String::new())),
                        );
                        c.insert(
                            "bearer".into(),
                            args.get("bearer")
                                .cloned()
                                .unwrap_or_else(|| Value::String("owner".into())),
                        );
                        let component = args
                            .get("component")
                            .and_then(Value::as_str)
                            .unwrap_or("component");
                        let build_sha_key = format!(
                            "{}_BUILD_SHA",
                            component
                                .chars()
                                .map(|ch| if ch.is_ascii_alphanumeric() {
                                    ch.to_ascii_uppercase()
                                } else {
                                    '_'
                                })
                                .collect::<String>()
                        );
                        let source_sha_ref =
                            serde_json::json!({"from":"pull-repo.resolved_commit"});
                        let mut environment = args
                            .get("build_environment")
                            .and_then(Value::as_object)
                            .cloned()
                            .unwrap_or_default();
                        environment.insert(build_sha_key, source_sha_ref.clone());
                        if component == "coronatio" {
                            environment.insert("CORONATIO_SOURCE_SHA".into(), source_sha_ref);
                        }
                        c.insert("environment".into(), Value::Object(environment));
                        c
                    }
                    "managed-files" => {
                        let mut c = BTreeMap::new();
                        c.insert(
                            "files".into(),
                            args.get("managed_files")
                                .cloned()
                                .unwrap_or_else(|| Value::Array(Vec::new())),
                        );
                        c
                    }
                    "binary-install" => {
                        let mut c = args.clone();
                        c.insert(
                            "path".into(),
                            args.get("install_bin")
                                .cloned()
                                .unwrap_or(Value::String(String::new())),
                        );
                        c.insert(
                            "source_path".into(),
                            serde_json::json!({"from":"build.artifact"}),
                        );
                        c.insert("mode".into(), Value::from(493_u64));
                        c.insert("no_follow".into(), Value::Bool(true));
                        c.insert("collision_policy".into(), Value::String("refuse".into()));
                        c.insert("rollback_policy".into(), Value::String("exact".into()));
                        c.insert("xattrs".into(), Value::Object(serde_json::Map::new()));
                        c
                    }
                    "service-daemon-reload"
                    | "service-enable"
                    | "service-restart"
                    | "service-active"
                    | "unit-authority-proof" => {
                        let mut c = args.clone();
                        let managed_files_changed = if has_managed_files {
                            serde_json::json!({"from":"managed-files.changed"})
                        } else {
                            Value::Bool(false)
                        };
                        for (k, r) in [
                            ("source_dir", "pull-repo.path"),
                            ("source_sha", "pull-repo.resolved_commit"),
                            ("source_reference", "pull-repo.source_reference"),
                            ("source_remote", "pull-repo.source_remote"),
                            ("source_changed", "pull-repo.changed"),
                            ("build_changed", "build.changed"),
                            ("binary_changed", "binary-install.changed"),
                        ] {
                            c.insert(k.into(), serde_json::json!({"from":r}));
                        }
                        c.insert("managed_files_changed".into(), managed_files_changed);
                        if name == "unit-authority-proof" {
                            if let Some(expected) = args.get("expected_unit_properties") {
                                c.insert("expected".into(), expected.clone());
                            }
                        }
                        c.insert(
                            "user".into(),
                            args.get("user").cloned().unwrap_or(Value::Bool(false)),
                        );
                        if let Some(policy) = args.get("restart_policy") {
                            c.insert("restart_policy".into(), policy.clone());
                        }
                        c
                    }
                    _ => {
                        let mut c = args.clone();
                        let url = args.get("url").and_then(Value::as_str).unwrap_or("");
                        let health_url =
                            if args.get("component").and_then(Value::as_str) == Some("coronatio") {
                                let base = url.trim_end_matches('/');
                                if base.ends_with("/health") {
                                    base.to_string()
                                } else {
                                    format!("{base}/health")
                                }
                            } else {
                                url.to_string()
                            };
                        c.insert("url".into(), Value::String(health_url));
                        if let Some(v) = args.get("health_expected_contains") {
                            c.insert("expected_contains".into(), v.clone());
                        } else {
                            c.insert(
                                "expected_contains".into(),
                                serde_json::json!({"from":"pull-repo.resolved_commit"}),
                            );
                        }
                        c
                    }
                };
                RoutineStep {
                    name: name.into(),
                    tool: tool.into(),
                    permutation: Some(permutation.into()),
                    args: child_args,
                    extra: BTreeMap::new(),
                }
            })
            .collect();
    }
}

/// Execute the complete RestartServices band lifecycle for one projected module.
/// Selection, preconditions, authority gating, failure policy, and accumulation
/// intentionally live here rather than in the ladder compatibility executor.
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_manifest_band(
    manifest: &LadderManifest,
    module_dir: &Path,
    auth: Option<&SoftwareApplyAuthorization>,
    pa: Option<&PackageAuthority>,
    key: Option<&crate::tools::files::InvocationKey>,
    mode_apply: bool,
    routine_states: &mut BTreeMap<String, crate::ModuleWalkState>,
    projected_steps: &[ValidatedStep],
    projected_routines: &BTreeMap<String, Vec<ProjectedRoutineChild>>,
) -> Result<ModuleExecution, String> {
    crate::atoms::attest::prepare_receipt_parent(module_dir)?;
    let mut result = ModuleExecution {
        ok: true,
        changed: false,
        operation_count: 0,
        first_missing_signal: None,
        placements: Vec::new(),
    };
    for step in projected_steps {
        if step.tool == "routine" {
            let children = projected_routines
                .get(&step.step_id)
                .ok_or_else(|| "routine-step-missing".to_string())?;
            if !children
                .iter()
                .any(|child| child.band == crate::bands::Band::RestartServices)
            {
                continue;
            }
        } else if crate::tools::routine::placement_for_step(step)?
            != crate::bands::Band::RestartServices
        {
            continue;
        }
        if let Some(precondition) = if step.tool == "routine" {
            None
        } else {
            crate::tools::routine::command_precondition(&step.args)?
        } {
            result.operation_count += 1;
            let probe = crate::bands::compare::execute_command_precondition(
                step,
                &precondition,
                manifest,
                module_dir,
            )?;
            if !probe.ok {
                result.ok = false;
                let detail = probe
                    .command
                    .as_ref()
                    .map(|r| format!("exit_code={} stderr={}", r.code, r.stderr))
                    .unwrap_or_else(|| probe.message.clone());
                let signal = format!(
                    "step_id={} state=blocked probe_error={detail}",
                    step.step_id
                );
                result.first_missing_signal.get_or_insert(signal);
                result.placements.push(serde_json::json!({"step_id":step.step_id,"tool":step.tool,"permutation":step.permutation,"band":"RestartServices","status":"blocked","module":manifest.id}));
                break;
            }
        }
        result.operation_count += 1;
        let outcome = if step.tool == "routine" {
            crate::tools::routine::execute_routine(
                step,
                manifest,
                module_dir,
                auth,
                pa,
                mode_apply,
                key,
                Some(routine_states),
                crate::bands::Band::RestartServices,
                projected_routines
                    .get(&step.step_id)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            )?
        } else {
            crate::tools::routine::execute_validated_step(
                step, manifest, module_dir, auth, pa, false, key, None,
            )?
        };
        if step.tool == "routine" {
            let routine = routine_states
                .get(&step.step_id)
                .ok_or_else(|| "routine-state-missing".to_string())?;
            for child in projected_routines
                .get(&step.step_id)
                .map(Vec::as_slice)
                .unwrap_or(&[])
            {
                if child.band != crate::bands::Band::RestartServices {
                    continue;
                }
                let receipt = routine
                    .children
                    .iter()
                    .find(|r| r.get("name").and_then(Value::as_str) == Some(child.name.as_str()))
                    .ok_or_else(|| format!("routine-child-receipt-missing-{}", child.name))?;
                result.placements.push(serde_json::json!({"step_id":child.name,"tool":child.tool,"permutation":child.permutation,"band":"RestartServices","status":receipt.get("state").and_then(Value::as_str).unwrap_or("failed"),"ok":receipt.get("ok").and_then(Value::as_bool).unwrap_or(false),"changed":receipt.get("changed").and_then(Value::as_bool).unwrap_or(false),"module":manifest.id,"routine":step.step_id}));
            }
        } else {
            result.placements.push(serde_json::json!({"step_id":step.step_id,"tool":step.tool,"permutation":step.permutation,"band":"RestartServices","status":if outcome.ok {"completed"} else {"failed"},"module":manifest.id}));
        }
        result.changed |= outcome.changed;
        if !outcome.ok {
            result.ok = false;
            result.first_missing_signal.get_or_insert_with(|| {
                format!("step_id={} defect={}", step.step_id, outcome.message)
            });
            if step.on_failure == crate::tools::ladder::OnFailure::Stop {
                break;
            }
        }
    }
    Ok(result)
}

use crate::receipts::event;
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
            LoadedModule::Ladder(manifest) => execute_manifest_band(
                manifest,
                &receipt_dir.join("modules").join(module_id),
                mode.software_authorization(),
                profile.package_authority.as_ref(),
                mode.invocation(),
                mode_apply,
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
                        "{} band=RestartServices steps={}",
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
    invocation: Option<&crate::tools::files::InvocationKey>,
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
    let name = tool.to_string();
    match tool {
        "check-health" => {
            let url = args
                .get("url")
                .and_then(Value::as_str)
                .ok_or("check-health-url-missing")?;
            let request = crate::tools::health::ProbeRequest {
                url,
                retries: args.get("retries").and_then(Value::as_u64).unwrap_or(0) as usize,
                timeout_secs: args
                    .get("timeout_secs")
                    .and_then(Value::as_u64)
                    .unwrap_or(3),
                expected_contains: args.get("expected_contains").and_then(Value::as_str),
            };
            let result = crate::tools::health::curl_probe(&request);

            crate::write_json(
                &receipt_dir.join(format!("{name}.json")),
                &serde_json::json!({"schema":"harmonia.routine_tool.receipt.v1","ok":result.ok,"changed":false,"skipped":!apply,"stdout":result.stdout,"stderr":result.stderr}),
            )?;
            Ok((
                OperationOutcome {
                    ok: result.ok,
                    changed: false,
                    skipped: !apply,
                    message: "check-health".into(),
                    command: Some(result),
                },
                [("url".into(), serde_json::json!(url))]
                    .into_iter()
                    .collect(),
            ))
        }
        "systemd" if permutation.name == "show-assert" => {
            let service = args
                .get("service")
                .and_then(Value::as_str)
                .ok_or("systemd-show-assert-service-missing")?;
            let expected = args
                .get("expected")
                .and_then(Value::as_object)
                .ok_or("systemd-show-assert-expected-missing")?;
            let expected = expected
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            let outcome =
                crate::tools::systemd::show_assert(receipt_dir, &name, service, &expected)?;
            Ok((
                outcome,
                [("service".into(), serde_json::json!(service))]
                    .into_iter()
                    .collect(),
            ))
        }
        "systemd" => {
            let service = args.get("service").and_then(Value::as_str);
            let user = args.get("user").and_then(Value::as_bool).unwrap_or(false);
            let target = args.get("target_user").and_then(Value::as_str);
            let timeout = args
                .get("timeout_secs")
                .and_then(Value::as_u64)
                .unwrap_or(30);
            let binary_changed = args
                .get("binary_changed")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let build_changed = args
                .get("build_changed")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let managed_files_changed = args
                .get("managed_files_changed")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let material_changed = match permutation.name {
                "daemon-reload" => managed_files_changed,
                "restart" => build_changed || binary_changed || managed_files_changed,
                _ => false,
            };
            let restart_policy = args.get("restart_policy").and_then(Value::as_str);
            let effective = if user {
                format!("user-{}", permutation.name)
            } else {
                permutation.name.to_string()
            };
            let observation_only = matches!(permutation.name, "is-active-probe");
            let o = crate::tools::systemd::run_permutation_with_policy(
                receipt_dir,
                &name,
                &effective,
                service,
                &[],
                target,
                timeout,
                if observation_only { false } else { apply },
                material_changed,
                restart_policy,
                invocation,
            )?;

            Ok((
                o,
                [("service".into(), serde_json::json!(service.unwrap_or("")))]
                    .into_iter()
                    .collect(),
            ))
        }
        "enable-unit" => {
            let service = args
                .get("service")
                .and_then(Value::as_str)
                .ok_or("enable-unit-service-missing")?;
            let user = args.get("user").and_then(Value::as_bool).unwrap_or(false);
            let target = args.get("target_user").and_then(Value::as_str);
            let timeout = args
                .get("timeout_secs")
                .and_then(Value::as_u64)
                .unwrap_or(30);
            let o = crate::tools::systemd::run_action(
                receipt_dir,
                &name,
                "enable",
                Some(service),
                user,
                target,
                timeout,
                apply,
                false,
                invocation,
            )?;

            Ok((
                o,
                [
                    ("service".into(), serde_json::json!(service)),
                    ("enabled".into(), serde_json::json!(true)),
                ]
                .into_iter()
                .collect(),
            ))
        }
        _ => Err(format!("routine-tool-not-summonable-{tool}")),
    }
}
