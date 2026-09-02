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

/// Compare a built binary with its installed counterpart by content digest.
/// Missing or unreadable files are different so promotion remains authoritative.
pub(crate) fn service_runtime_material_gates(
    permutation: &str,
    binary_changed: bool,
    managed_files_changed: bool,
) -> (bool, bool) {
    match permutation {
        "daemon-reload" => (false, managed_files_changed),
        "restart" => (binary_changed || managed_files_changed, false),
        _ => (false, false),
    }
}

pub(crate) fn binary_content_matches(built: &Path, installed: &Path) -> Result<bool, String> {
    let built_bytes = std::fs::read(built).map_err(|error| {
        format!(
            "binary-promotion-built-read-failed {}: {error}",
            built.display()
        )
    })?;
    let installed_bytes = match std::fs::read(installed) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(format!(
                "binary-promotion-installed-read-failed {}: {error}",
                installed.display()
            ))
        }
    };
    Ok(crate::atoms::file_sha256(&built_bytes) == crate::atoms::file_sha256(&installed_bytes))
}

pub(crate) fn enter(enter: &mut impl FnMut(Band) -> Result<(), String>) -> Result<(), String> {
    enter(Band::RestartServices)
}

fn collect_profile_sources(args: &BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    args.iter()
        .filter(|(key, value)| key.ends_with("_profile_source") && !value.is_null())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
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
        let native_release = args.get("release_repo").and_then(Value::as_str).is_some_and(|v| !v.trim().is_empty());
        let registry_fetch = args.get("registry_base").and_then(Value::as_str).is_some_and(|v| !v.trim().is_empty());
        let release_fetch = registry_fetch || native_release;
        let stages = [
            ("pull-repo", "pull-repo", "acquire"),
            ("build", if release_fetch { "fetch-artifact" } else { "build-crate" }, if release_fetch { "fetch" } else { "build" }),
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
        let profile_sources = collect_profile_sources(&args);
        let has_managed_files = args
            .get("managed_files")
            .and_then(Value::as_array)
            .is_some_and(|files| !files.is_empty())
            || !profile_sources.is_empty();
        step.tool = "routine".into();
        step.permutation = "execute".into();
        step.args.clear();
        step.steps = stages
            .into_iter()
            .filter(|(name, _, _)| {
                (*name != "managed-files" || has_managed_files)
                    && (*name != "source-sha-record"
                        || args
                            .get("source_sha_file")
                            .and_then(Value::as_str)
                            .is_some_and(|path| !path.is_empty()))
                    && (*name != "unit-authority-proof"
                        || args
                            .get("expected_unit_properties")
                            .and_then(Value::as_object)
                            .is_some())
            })
            .map(|(name, tool, permutation)| {
                let child_args = match name {
                    "pull-repo" => pull.clone(),
                    "build" if tool == "fetch-artifact" => {
                        let component = args.get("component").cloned().unwrap_or(Value::String(String::new()));
                        let source_dir = args.get("source_dir").and_then(Value::as_str).unwrap_or("");
                        let binary_name = args.get("binary_name").cloned().unwrap_or_else(|| Value::String("caduceus".into()));
                        let destination_root = if native_release { "target/harmonia-release" } else { "target/harmonia-registry" };
                        let destination = Value::String(Path::new(source_dir).join(destination_root).join(binary_name.as_str().unwrap_or("caduceus")).to_string_lossy().into_owned());
                        let mut child = BTreeMap::from([
                            ("component".into(), component),
                            ("registry_base".into(), args.get("registry_base").cloned().unwrap_or(Value::String(String::new()))),
                            ("release_repo".into(), args.get("release_repo").cloned().unwrap_or(Value::String(String::new()))),
                            ("release_tag".into(), args.get("release_tag").cloned().unwrap_or(Value::Null)),
                            ("api_root".into(), args.get("api_root").cloned().unwrap_or(Value::String("https://git.home.arpa/api/v1".into()))),
                            ("asset_name".into(), args.get("asset_name").cloned().unwrap_or(Value::Null)),
                            ("sidecar_name".into(), args.get("sidecar_name").cloned().unwrap_or(Value::Null)),
                            ("source_build_sha".into(), serde_json::json!({"from":"pull-repo.resolved_commit"})),
                            ("source_dir".into(), serde_json::json!({"from":"pull-repo.path"})),
                            ("identity".into(), args.get("identity").cloned().unwrap_or_else(|| Value::String(if native_release { "embedded-sha" } else { "liveness-marker" }.into()))),
                            ("destination".into(), destination),
                            ("installed_binary".into(), args.get("install_bin").cloned().unwrap_or(Value::String(String::new()))),
                            ("artifact_name".into(), binary_name),
                        ]);
                        child.insert("source_policy".into(), serde_json::json!({"from":"pull-repo.source_policy","default":"artifact"}));
                        child
                    }
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
                        if !profile_sources.is_empty() {
                            c.insert(
                                "profile_sources".into(),
                                Value::Object(profile_sources.clone().into_iter().collect()),
                            );
                            c.insert(
                                "source_dir".into(),
                                serde_json::json!({"from":"pull-repo.path"}),
                            );
                        }
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
                    "source-sha-record" => {
                        let mut c = BTreeMap::new();
                        c.insert(
                            "path".into(),
                            args.get("source_sha_file")
                                .cloned()
                                .unwrap_or(Value::String(String::new())),
                        );
                        c.insert(
                            "declared_bytes".into(),
                            serde_json::json!({"from":"pull-repo.resolved_commit"}),
                        );
                        c.insert("mode".into(), Value::from(420_u64));
                        c.insert("no_follow".into(), Value::Bool(true));
                        c.insert("collision_policy".into(), Value::String("refuse".into()));
                        c.insert("rollback_policy".into(), Value::String("exact".into()));
                        c.insert("xattrs".into(), Value::Object(serde_json::Map::new()));
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

fn health_probe_request<'a>(
    url: &'a str,
    args: &'a std::collections::BTreeMap<String, serde_json::Value>,
) -> crate::tools::health::ProbeRequest<'a> {
    crate::tools::health::ProbeRequest {
        url,
        retries: args.get("retries").and_then(Value::as_u64).unwrap_or(5) as usize,
        timeout_secs: args
            .get("timeout_secs")
            .and_then(Value::as_u64)
            .unwrap_or(3),
        expected_contains: args.get("expected_contains").and_then(Value::as_str),
    }
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
            let request = health_probe_request(url, args);
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
            let managed_files_changed = args
                .get("managed_files_changed")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let (restart_changed, reload_changed) = service_runtime_material_gates(
                permutation.name,
                binary_changed,
                managed_files_changed,
            );
            let material_changed = if permutation.name == "daemon-reload" {
                reload_changed
            } else {
                restart_changed
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

#[cfg(test)]
mod tests {
    use super::health_probe_request;
    use crate::tools::ladder::load_ladder_manifest;
    use crate::tools::routine::project_routine_children;
    use serde_json::{json, Value};
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    #[test]
    fn service_runtime_material_gates_ignore_build_only_changes_and_cover_quiet_binary_and_managed() {
        assert_eq!(
            super::service_runtime_material_gates("restart", false, false),
            (false, false)
        );
        assert_eq!(
            super::service_runtime_material_gates("restart", true, false),
            (true, false)
        );
        assert_eq!(
            super::service_runtime_material_gates("restart", false, true),
            (true, false)
        );
        assert_eq!(
            super::service_runtime_material_gates("daemon-reload", false, true),
            (false, true)
        );
        assert_eq!(
            super::service_runtime_material_gates("restart", false, false),
            (false, false)
        );
    }

    #[test]
    fn binary_content_matches_distinguishes_quiet_changed_and_missing_images() {
        let root =
            std::env::temp_dir().join(format!("harmonia-binary-content-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let built = root.join("built");
        let installed = root.join("installed");
        std::fs::write(&built, b"same image").unwrap();
        std::fs::write(&installed, b"same image").unwrap();
        assert!(super::binary_content_matches(&built, &installed).unwrap());
        std::fs::write(&installed, b"changed image").unwrap();
        assert!(!super::binary_content_matches(&built, &installed).unwrap());
        std::fs::remove_file(&installed).unwrap();
        assert!(!super::binary_content_matches(&built, &installed).unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn health_probe_request_defaults_absent_retries_to_five() {
        let args = BTreeMap::new();
        let request = health_probe_request("https://example.test/health", &args);

        assert_eq!(request.retries, 5);
        assert_eq!(request.timeout_secs, 3);
    }

    #[test]
    fn health_probe_request_honors_declared_retries() {
        let args = BTreeMap::from([(String::from("retries"), json!(0))]);
        let request = health_probe_request("https://example.test/health", &args);

        assert_eq!(request.retries, 0);
    }
    #[test]
    fn coronatio_lowering_derives_native_release_artifact_and_destination() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles/homeserver/modules/coronatio/manifest.json");
        let manifest = load_ladder_manifest(&path).unwrap();
        let mut manifest = manifest;
        super::lower_service_runtime_steps(&mut manifest);
        let routine = manifest.ladder.iter().find(|s| s.step_id == "coronatio-service-runtime").unwrap();
        let build = routine.steps.iter().find(|s| s.name == "build").unwrap();
        assert_eq!(build.tool, "fetch-artifact");
        assert_eq!(build.args.get("artifact_name").and_then(Value::as_str), Some("coronatio"));
        assert_eq!(build.args.get("destination").and_then(Value::as_str), Some("/opt/coronatio/source/target/harmonia-release/coronatio"));
    }

    #[test]
    fn caduceus_real_manifest_lowers_fetch_artifact_build_child() {
        let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("profiles/tv/modules/install-caduceus/manifest.json");
        let manifest = load_ladder_manifest(&manifest_path).unwrap();
        let routine = manifest
            .ladder
            .iter()
            .find(|step| step.step_id == "caduceus-service-runtime")
            .expect("real Caduceus lowered routine");
        assert!(crate::tools::ladder::is_lowered_service_runtime_converge(routine));
        assert!(crate::tools::ladder::service_runtime_converge_args(routine).is_some());

        let build = routine
            .steps
            .iter()
            .find(|child| child.name == "build")
            .expect("lowered fetch-artifact build child");
        assert_eq!(build.tool, "fetch-artifact");
        assert_eq!(build.permutation.as_deref(), Some("fetch"));
        assert_eq!(build.args.get("component").and_then(Value::as_str), Some("caduceus"));
        assert_eq!(
            build.args.get("source_build_sha"),
            Some(&json!({"from":"pull-repo.resolved_commit"}))
        );
        assert_eq!(
            build.args.get("source_policy"),
            Some(&json!({
                "from": "pull-repo.source_policy",
                "default": "artifact"
            }))
        );
        assert_eq!(
            build.args.get("registry_base").and_then(Value::as_str),
            Some("https://git.home.arpa/api/packages/HOMESERVERSLTD/generic")
        );
        assert_eq!(
            build.args.get("destination").and_then(Value::as_str),
            Some("/opt/caduceus/source/target/harmonia-registry/caduceus")
        );
        assert_eq!(
            build.args.get("installed_binary").and_then(Value::as_str),
            Some("/usr/local/bin/caduceus")
        );
        assert_eq!(build.args.get("artifact_name").and_then(Value::as_str), Some("caduceus"));
        assert!(routine
            .steps
            .iter()
            .all(|child| child.tool != "build-crate"));
    }

    #[test]
    fn arcadia_real_manifest_lowers_binary_promotion_source_artifact_reference() {
        let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("profiles/homeconsole/modules/arcadia-gui-runtime/manifest.json");
        let manifest = load_ladder_manifest(&manifest_path).unwrap();
        let routine = manifest
            .ladder
            .iter()
            .find(|step| step.step_id == "arcadia-gui-service-runtime")
            .expect("real Arcadia lowered routine");
        let build = routine
            .steps
            .iter()
            .find(|child| child.name == "build")
            .expect("lowered build child");
        assert_eq!(build.tool, "build-crate");
        assert_eq!(build.permutation.as_deref(), Some("build"));

        let lowered = routine
            .steps
            .iter()
            .find(|child| child.name == "binary-install")
            .expect("lowered binary-promotion child");
        assert_eq!(lowered.tool, "place-file");
        assert_eq!(lowered.permutation.as_deref(), Some("binary-promotion"));
        assert_eq!(
            lowered.args.get("source_path"),
            Some(&json!({"from":"build.artifact"}))
        );
        let projected = project_routine_children(routine, &manifest.constants).unwrap();
        let projected_install = projected
            .iter()
            .find(|child| child.name == "binary-install")
            .expect("projected binary-promotion child");
        assert_eq!(
            projected_install.args.get("source_path"),
            Some(&json!({"from":"build.artifact"}))
        );
    }

    #[test]
    fn caduceus_real_manifest_lowers_managed_profile_source() {
        let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("profiles/homeconsole/modules/install-caduceus/manifest.json");
        let manifest = load_ladder_manifest(&manifest_path).unwrap();
        let routine = manifest
            .ladder
            .iter()
            .find(|step| step.step_id == "caduceus-service-runtime")
            .expect("real Caduceus lowered routine");
        let routine_child_names = routine
            .steps
            .iter()
            .map(|child| child.name.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            routine_child_names.len(),
            routine.steps.len(),
            "routine child names must be unique"
        );
        let managed = routine
            .steps
            .iter()
            .find(|child| child.name == "managed-files")
            .expect("managed profile-source child");
        assert_eq!(managed.tool, "files");
        assert_eq!(managed.permutation.as_deref(), Some("managed-files"));
        assert_eq!(
            managed.args.get("source_dir"),
            Some(&json!({"from": "pull-repo.path"}))
        );
        assert_eq!(
            managed
                .args
                .get("profile_sources")
                .and_then(Value::as_object)
                .and_then(|sources| sources.get("caduceus_profile_source"))
                .and_then(Value::as_object)
                .and_then(|source| source.get("path"))
                .and_then(Value::as_str),
            Some("/etc/caduceus/profile.yaml")
        );
    }

    #[test]
    fn arcadia_health_window_lowers_into_health_probe_request() {
        let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("profiles/homeconsole/modules/arcadia-gui-runtime/manifest.json");
        let manifest = load_ladder_manifest(&manifest_path).unwrap();
        let routine = manifest
            .ladder
            .iter()
            .find(|step| step.tool == "routine")
            .expect("lowered routine step");
        let health = routine
            .steps
            .iter()
            .find(|child| child.name == "health-proof")
            .expect("lowered health-proof child");
        let source_record = routine
            .steps
            .iter()
            .find(|child| child.name == "source-sha-record")
            .expect("lowered source-sha-record child");
        assert_eq!(source_record.tool, "place-file");
        assert_eq!(
            source_record.permutation.as_deref(),
            Some("source-sha-record")
        );
        assert_eq!(
            source_record.args.get("path").and_then(Value::as_str),
            Some("/var/lib/harmonia/state/arcadia.sha")
        );
        assert_eq!(
            source_record.args.get("declared_bytes"),
            Some(&json!({"from":"pull-repo.resolved_commit"}))
        );
        assert!(
            routine
                .steps
                .iter()
                .position(|child| child.name == "health-proof")
                < routine
                    .steps
                    .iter()
                    .position(|child| child.name == "source-sha-record")
        );

        assert_eq!(health.tool, "check-health");
        assert_eq!(
            health.args.get("retries").and_then(|value| value.as_u64()),
            Some(30)
        );
        assert!(!health.args.contains_key("timeout_secs"));

        let url = health
            .args
            .get("url")
            .and_then(|value| value.as_str())
            .expect("health-proof URL");
        let request = health_probe_request(url, &health.args);
        assert_eq!(request.retries, 30);
        assert_eq!(request.timeout_secs, 3);
    }
}

#[cfg(test)]
mod profile_source_collection_tests {
    use super::collect_profile_sources;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn collects_two_suffix_generic_profile_sources() {
        let args = BTreeMap::from([
            ("alpha_profile_source".into(), json!({"source": "a"})),
            ("beta_profile_source".into(), json!({"source": "b"})),
            ("ordinary".into(), json!(true)),
        ]);
        let collected = collect_profile_sources(&args);
        assert_eq!(collected.len(), 2);
        assert_eq!(
            collected["alpha_profile_source"],
            json!({"source": "a"})
        );
        assert_eq!(
            collected["beta_profile_source"],
            json!({"source": "b"})
        );
    }
}
