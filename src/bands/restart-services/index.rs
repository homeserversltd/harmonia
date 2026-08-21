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
    key: Option<crate::tools::files::InvocationKey>,
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
    invocation: Option<crate::tools::files::InvocationKey>,
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
            if let Some(legacy) = args.get("legacy_receipt").and_then(Value::as_str) {
                crate::write_command_receipt(receipt_dir, legacy, &result)?;
            }
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
            if let Some(legacy) = args.get("legacy_receipt").and_then(Value::as_str) {
                crate::atoms::attest::copy_artifact(
                    &receipt_dir.join(format!("{name}.json")),
                    &receipt_dir.join(format!("{legacy}.json")),
                )
                .map_err(|e| e.to_string())?;
            }
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
            if let Some(legacy) = args.get("legacy_receipt").and_then(Value::as_str) {
                crate::atoms::attest::copy_artifact(
                    &receipt_dir.join(format!("{name}.json")),
                    &receipt_dir.join(format!("{legacy}.json")),
                )
                .map_err(|e| e.to_string())?;
            }
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

const ARCADIA_CONTROL_DROPIN_DIR: &str = "/etc/systemd/system/arcadia.service.d";
const ARCADIA_CONTROL_DROPIN_PATH: &str =
    "/etc/systemd/system/arcadia.service.d/10-control-surface-authority.conf";
const ARCADIA_CONTROL_DROPIN_CONTENT: &str = "[Service]\nUser=\nGroup=\nNoNewPrivileges=false\n";
use crate::tools;
use crate::{
    command_capture, write_artifact_receipt, write_command_receipt, write_json, write_run_receipt,
};
use crate::{hyalos, CmdResult};

// Arcadia-specific runtime ownership. This is intentionally not the generic
// service-runtime lowering: the direct Arcadia order remains authoritative.
use serde_json::json;
use sha2::{Digest, Sha256};

fn ensure_arcadia_control_surface_authority(
    receipt_dir: &Path,
    apply: bool,
    authorization: Option<crate::tools::comparison::ActionAuthorization>,
    invocation: Option<crate::tools::files::InvocationKey>,
) -> Result<bool, String> {
    let existing = fs::read_to_string(ARCADIA_CONTROL_DROPIN_PATH).unwrap_or_default();
    let changed = existing != ARCADIA_CONTROL_DROPIN_CONTENT;
    if apply && changed {
        let authorization = authorization.ok_or("arcadia-control-dropin-authorization-missing")?;
        let invocation = invocation.ok_or("arcadia-control-dropin-invocation-missing")?;
        crate::tools::files::make_dir(
            authorization,
            invocation,
            Path::new(ARCADIA_CONTROL_DROPIN_DIR),
        )?;
        let tmp = Path::new(ARCADIA_CONTROL_DROPIN_PATH).with_extension("harmonia-new");
        crate::tools::files::file_write(
            authorization,
            invocation,
            &tmp,
            ARCADIA_CONTROL_DROPIN_CONTENT.as_bytes(),
            crate::tools::files::FileWriteOptions {
                write_bytes: true,
                mode: Some(0o644),
                uid: None,
                gid: None,
                backup_to: None,
            },
        )?;
        crate::tools::files::rename(
            authorization,
            invocation,
            &tmp,
            Path::new(ARCADIA_CONTROL_DROPIN_PATH),
        )?;
    }
    write_json(
        &receipt_dir.join("arcadia-control-surface-authority.json"),
        &json!({
            "schema": "harmonia.arcadia_control_surface_authority.v1",
            "ok": !changed || apply,
            "mutation": apply && changed,
            "changed": changed,
            "dropin_path": ARCADIA_CONTROL_DROPIN_PATH,
            "desired": {
                "user": "root",
                "group": "root",
                "no_new_privileges": false,
                "reason": "Arcadia is the HomeConsole front panel and must execute declared local appliance controls through Harmonia/systemd."
            }
        }),
    )?;
    if changed && !apply {
        return Err("arcadia-control-surface-authority-drift".to_string());
    }
    Ok(changed)
}

fn read_arcadia_control_surface_authority(service: &str) -> CmdResult {
    command_capture(
        "/usr/bin/systemctl",
        &[
            "show",
            service,
            "-p",
            "User",
            "-p",
            "Group",
            "-p",
            "NoNewPrivileges",
            "--no-pager",
        ],
    )
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|e| format!("sha256-read-failed {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

fn keyed_arcadia_command(
    authorization: crate::tools::comparison::ActionAuthorization,
    invocation: crate::tools::files::InvocationKey,
    args: &[&str],
    timeout_secs: u64,
) -> CmdResult {
    let args = args
        .iter()
        .map(|arg| (*arg).to_string())
        .collect::<Vec<_>>();
    match crate::tools::command::authorized_capture(
        authorization,
        invocation,
        "/usr/bin/systemctl",
        &args,
        std::time::Duration::from_secs(timeout_secs),
    ) {
        Ok(result) => CmdResult {
            ok: result.ok,
            code: result.code.unwrap_or(if result.ok { 0 } else { -1 }),
            stdout: result.stdout,
            stderr: result.stderr,
        },
        Err(error) => CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: error,
        },
    }
}

pub(crate) fn homeconsole_arcadia_update(
    profile: &Profile,
    receipt_dir: &Path,
    artifact: &Path,
    install_bin: &Path,
    service: &str,
    apply: bool,
    source_sha: Option<&str>,
    invocation: Option<crate::tools::files::InvocationKey>,
) -> Result<(), String> {
    if !apply {
        return homeconsole_arcadia_update_check(
            profile,
            receipt_dir,
            artifact,
            install_bin,
            service,
            false,
            source_sha,
        );
    }
    let key = invocation.ok_or("homeconsole-arcadia-update-invocation-key-missing")?;
    let run = crate::tools::comparison::execute(
        "arcadia-update",
        || Ok::<_, String>(()),
        |_| crate::tools::comparison::DiffDecision::Different,
        move |authorization, _| {
            homeconsole_arcadia_update_apply(
                profile,
                receipt_dir,
                artifact,
                install_bin,
                service,
                true,
                source_sha,
                authorization,
                key,
            )
        },
    )?;
    match run {
        crate::tools::comparison::ComparisonRun::Moved { movement, .. } => Ok(movement),
        crate::tools::comparison::ComparisonRun::Current { .. } => {
            Err("arcadia-update-apply-boundary-empty".into())
        }
    }
}

fn homeconsole_arcadia_update_check(
    profile: &Profile,
    receipt_dir: &Path,
    artifact: &Path,
    install_bin: &Path,
    service: &str,
    apply: bool,
    _source_sha: Option<&str>,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.identity != "homeconsole" {
        return Err(format!(
            "homeconsole-arcadia-update requires homeconsole/homeconsole profile, got {}/{}",
            profile.id, profile.identity
        ));
    }
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
    let mut events = crate::atoms::attest::open_event_stream(&receipt_dir.join("events.jsonl"))?;
    event(&mut events, "arcadia-start", true, "Arcadia update started")?;
    let metadata = fs::metadata(artifact).map_err(|e| format!("artifact-missing: {e}"))?;
    let artifact_len = metadata.len();
    let artifact_sha = sha256_file(artifact)?;
    event(&mut events, "artifact", true, "Arcadia artifact present")?;
    let mut ok = true;
    let mut changed = false;
    let mut first_missing_signal = "none".to_string();
    if apply {
        return Err("arcadia-check-apply-forbidden".into());
    }
    if !apply {
        if let Err(signal) =
            ensure_arcadia_control_surface_authority(receipt_dir, false, None, None)
        {
            ok = false;
            if first_missing_signal == "none" {
                first_missing_signal = signal;
            }
        }
    }
    let status = command_capture("/usr/bin/systemctl", &["is-active", service]);
    write_command_receipt(receipt_dir, "arcadia-service-active", &status)?;
    if apply && !status.ok {
        ok = false;
        if first_missing_signal == "none" {
            first_missing_signal = "arcadia-service-not-active".to_string();
        }
    }
    let authority_readback = read_arcadia_control_surface_authority(service);
    write_command_receipt(
        receipt_dir,
        "arcadia-control-surface-authority-readback",
        &authority_readback,
    )?;
    if apply
        && (!authority_readback.ok || !authority_readback.stdout.contains("NoNewPrivileges=no"))
    {
        ok = false;
        if first_missing_signal == "none" {
            first_missing_signal = "arcadia-control-surface-authority-unproven".to_string();
        }
    }
    let installed_sha = sha256_file(install_bin).ok();
    write_artifact_receipt(
        receipt_dir,
        artifact,
        install_bin,
        service,
        apply,
        ok,
        changed,
        &first_missing_signal,
        artifact_len,
        &artifact_sha,
        installed_sha.as_deref(),
    )?;
    write_run_receipt(receipt_dir, profile, apply, ok, &first_missing_signal)?;
    println!("schema=harmonia.homeconsole_arcadia_update.v1");
    hyalos::forward_receipt(
        "schema=harmonia.homeconsole_arcadia_update.v1",
        &format!("schema=harmonia.homeconsole_arcadia_update.v1 ok={}", ok),
        Some(serde_json::json!({"schema": "harmonia.homeconsole_arcadia_update.v1", "ok": ok})),
        Some(ok),
    );
    println!("ok={}", ok);
    println!("changed={}", changed);
    println!("first_missing_signal={}", first_missing_signal);
    println!("artifact={}", artifact.display());
    println!("install_bin={}", install_bin.display());
    println!("service={}", service);
    println!("receipt_dir={}", receipt_dir.display());
    if ok {
        Ok(())
    } else {
        Err(first_missing_signal)
    }
}

fn homeconsole_arcadia_update_apply(
    profile: &Profile,
    receipt_dir: &Path,
    artifact: &Path,
    install_bin: &Path,
    service: &str,
    apply: bool,
    _source_sha: Option<&str>,
    authorization: crate::tools::comparison::ActionAuthorization,
    invocation: crate::tools::files::InvocationKey,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.identity != "homeconsole" {
        return Err(format!(
            "homeconsole-arcadia-update requires homeconsole/homeconsole profile, got {}/{}",
            profile.id, profile.identity
        ));
    }
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
    let mut events = crate::atoms::attest::open_event_stream(&receipt_dir.join("events.jsonl"))?;
    event(&mut events, "arcadia-start", true, "Arcadia update started")?;
    let metadata = fs::metadata(artifact).map_err(|e| format!("artifact-missing: {e}"))?;
    let artifact_len = metadata.len();
    let artifact_sha = sha256_file(artifact)?;
    event(&mut events, "artifact", true, "Arcadia artifact present")?;
    let mut ok = true;
    let mut changed = false;
    let mut first_missing_signal = "none".to_string();
    if apply {
        if let Some(parent) = install_bin.parent() {
            crate::tools::files::make_dir(authorization, invocation, parent)?;
        }
        let before_sha = sha256_file(install_bin).ok();
        let binary_changed = before_sha.as_deref() != Some(artifact_sha.as_str());
        if binary_changed {
            changed = crate::bands::ratchet_binaries::promote_arcadia_artifact(
                artifact,
                install_bin,
                invocation,
            )?;
            event(
                &mut events,
                "artifact-installed",
                true,
                "Arcadia artifact installed",
            )?;
        } else {
            event(&mut events, "artifact-current", true, "converged-quiet")?;
        }
        let authority_changed = ensure_arcadia_control_surface_authority(
            receipt_dir,
            true,
            Some(authorization),
            Some(invocation),
        )?;
        changed = changed || authority_changed;
        event(
            &mut events,
            "control-surface-authority",
            true,
            "Arcadia control-surface authority installed",
        )?;
        if authority_changed {
            let daemon_reload =
                keyed_arcadia_command(authorization, invocation, &["daemon-reload"], 30);
            write_command_receipt(receipt_dir, "arcadia-daemon-reload", &daemon_reload)?;
            if !daemon_reload.ok {
                ok = false;
                first_missing_signal = "systemd-daemon-reload-failed".to_string();
            }
        }
        if changed {
            let restart =
                keyed_arcadia_command(authorization, invocation, &["restart", service], 30);
            write_command_receipt(receipt_dir, "arcadia-service-restart", &restart)?;
            if !restart.ok {
                ok = false;
                if first_missing_signal == "none" {
                    first_missing_signal = "arcadia-service-restart-failed".to_string();
                }
            }
        } else {
            event(&mut events, "service", true, "converged-quiet")?;
        }
    }
    if !apply {
        if let Err(signal) =
            ensure_arcadia_control_surface_authority(receipt_dir, false, None, None)
        {
            ok = false;
            if first_missing_signal == "none" {
                first_missing_signal = signal;
            }
        }
    }
    let status = command_capture("/usr/bin/systemctl", &["is-active", service]);
    write_command_receipt(receipt_dir, "arcadia-service-active", &status)?;
    if apply && !status.ok {
        ok = false;
        if first_missing_signal == "none" {
            first_missing_signal = "arcadia-service-not-active".to_string();
        }
    }
    let authority_readback = read_arcadia_control_surface_authority(service);
    write_command_receipt(
        receipt_dir,
        "arcadia-control-surface-authority-readback",
        &authority_readback,
    )?;
    if apply
        && (!authority_readback.ok || !authority_readback.stdout.contains("NoNewPrivileges=no"))
    {
        ok = false;
        if first_missing_signal == "none" {
            first_missing_signal = "arcadia-control-surface-authority-unproven".to_string();
        }
    }
    let installed_sha = sha256_file(install_bin).ok();
    write_artifact_receipt(
        receipt_dir,
        artifact,
        install_bin,
        service,
        apply,
        ok,
        changed,
        &first_missing_signal,
        artifact_len,
        &artifact_sha,
        installed_sha.as_deref(),
    )?;
    write_run_receipt(receipt_dir, profile, apply, ok, &first_missing_signal)?;
    println!("schema=harmonia.homeconsole_arcadia_update.v1");
    hyalos::forward_receipt(
        "schema=harmonia.homeconsole_arcadia_update.v1",
        &format!("schema=harmonia.homeconsole_arcadia_update.v1 ok={}", ok),
        Some(serde_json::json!({"schema": "harmonia.homeconsole_arcadia_update.v1", "ok": ok})),
        Some(ok),
    );
    println!("ok={}", ok);
    println!("changed={}", changed);
    println!("first_missing_signal={}", first_missing_signal);
    println!("artifact={}", artifact.display());
    println!("install_bin={}", install_bin.display());
    println!("service={}", service);
    println!("receipt_dir={}", receipt_dir.display());
    if ok {
        Ok(())
    } else {
        Err(first_missing_signal)
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn homeconsole_arcadia_gui_update(
    profile: &Profile,
    receipt_dir: &Path,
    component: &str,
    source_dir: &Path,
    install_bin: &Path,
    service: &str,
    apply: bool,
    invocation: Option<crate::tools::files::InvocationKey>,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.identity != "homeconsole" {
        return Err(format!(
            "homeconsole-arcadia-gui-update requires homeconsole/homeconsole profile, got {}/{}",
            profile.id, profile.identity
        ));
    }
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;

    let certificate = crate::device_profile_certificate_path();
    let resolution = crate::bands::pull_source::resolve_source(
        &certificate,
        component,
        "arcadia-gui-runtime",
        "arcadia-source-git-artifact",
    );
    if let Some(blocker) = resolution.blocker {
        return Err(format!(
            "arcadia-source-resolution-blocked component={component} blocker={blocker}"
        ));
    }
    let resolution = resolution
        .resolution
        .ok_or_else(|| "arcadia-source-resolution-plan-missing".to_string())?;
    let config = crate::bands::renew_self::load_engine_plane_config(
        &crate::bands::renew_self::engine_config_path(),
    )?;
    let credentials = config
        .as_ref()
        .map(crate::bands::renew_self::credential_scopes)
        .unwrap_or_default();
    let expected_commit = (resolution.requested_ref.len() == 40
        && resolution
            .requested_ref
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()))
    .then(|| resolution.requested_ref.clone());
    let source_plan = crate::bands::pull_source::bridge_acquisition_plan(
        &resolution,
        source_dir.to_path_buf(),
        "owner".to_string(),
        expected_commit,
        credentials,
    );
    let git_outcome =
        crate::bands::pull_source::acquire_arcadia_source(&source_plan, apply, invocation);
    let repo = component;
    let branch = source_plan.reference.as_str();
    let git_cmd = crate::bands::pull_source::source_outcome_cmd(&git_outcome);
    write_command_receipt(receipt_dir, "arcadia-source-git-artifact", &git_cmd)?;
    if !git_outcome.ok {
        write_arcadia_gui_run_receipt(
            receipt_dir,
            profile,
            apply,
            false,
            git_outcome.changed,
            "arcadia-source-git-artifact-failed",
            repo,
            branch,
            source_dir,
            None,
        )?;
        return Err("arcadia-source-git-artifact-failed".to_string());
    }

    let source_sha = crate::bands::compare::observe_arcadia_source_sha(source_dir);
    write_command_receipt(receipt_dir, "arcadia-source-sha", &source_sha)?;
    let source_sha_value = source_sha.stdout.trim().to_string();
    if !source_sha.ok || !crate::bands::compare::is_hex_sha(&source_sha_value) {
        write_arcadia_gui_run_receipt(
            receipt_dir,
            profile,
            apply,
            false,
            git_outcome.changed,
            "arcadia-source-sha-missing",
            repo,
            branch,
            source_dir,
            None,
        )?;
        return Err("arcadia-source-sha-missing".to_string());
    }

    if !apply {
        write_arcadia_gui_run_receipt(
            receipt_dir,
            profile,
            apply,
            true,
            git_outcome.changed,
            "none",
            repo,
            branch,
            source_dir,
            Some(&source_sha_value),
        )?;
        println!("schema=harmonia.homeconsole_arcadia_gui_update.v1");
        hyalos::forward_receipt(
            "schema=harmonia.homeconsole_arcadia_gui_update.v1",
            &format!(
                "schema=harmonia.homeconsole_arcadia_gui_update.v1 ok={}",
                true
            ),
            Some(
                serde_json::json!({"schema": "harmonia.homeconsole_arcadia_gui_update.v1", "ok": true}),
            ),
            Some(true),
        );
        println!("ok=true");
        println!("changed={}", git_outcome.changed);
        println!("first_missing_signal=none");
        println!("source_sha={}", source_sha_value);
        println!("receipt_dir={}", receipt_dir.display());
        return Ok(());
    }

    let build = crate::bands::ratchet_binaries::build_arcadia(
        source_dir,
        invocation.ok_or("homeconsole-arcadia-update-invocation-key-missing")?,
    );
    write_command_receipt(receipt_dir, "arcadia-cargo-build", &build)?;
    if !build.ok {
        write_arcadia_gui_run_receipt(
            receipt_dir,
            profile,
            apply,
            false,
            git_outcome.changed,
            "arcadia-cargo-build-failed",
            repo,
            branch,
            source_dir,
            Some(&source_sha_value),
        )?;
        return Err("arcadia-cargo-build-failed".to_string());
    }

    let artifact = source_dir.join("target/release/arcadia");
    homeconsole_arcadia_update(
        profile,
        receipt_dir,
        &artifact,
        install_bin,
        service,
        true,
        Some(&source_sha_value),
        invocation,
    )?;

    let health = arcadia_health_with_retry();
    write_command_receipt(receipt_dir, "arcadia-health", &health)?;
    let ok = health.ok;
    let first_missing_signal = if ok { "none" } else { "arcadia-health-failed" };
    write_arcadia_gui_run_receipt(
        receipt_dir,
        profile,
        apply,
        ok,
        true,
        first_missing_signal,
        repo,
        branch,
        source_dir,
        Some(&source_sha_value),
    )?;
    println!("schema=harmonia.homeconsole_arcadia_gui_update.v1");
    hyalos::forward_receipt(
        "schema=harmonia.homeconsole_arcadia_gui_update.v1",
        &format!(
            "schema=harmonia.homeconsole_arcadia_gui_update.v1 ok={}",
            ok
        ),
        Some(serde_json::json!({"schema": "harmonia.homeconsole_arcadia_gui_update.v1", "ok": ok})),
        Some(ok),
    );
    println!("ok={}", ok);
    println!("changed=true");
    println!("first_missing_signal={}", first_missing_signal);
    println!("source_sha={}", source_sha_value);
    println!("receipt_dir={}", receipt_dir.display());
    if ok {
        Ok(())
    } else {
        Err(first_missing_signal.to_string())
    }
}

fn arcadia_health_with_retry() -> CmdResult {
    tools::health::curl_probe(&tools::health::ProbeRequest::new(
        "http://127.0.0.1:8080/health",
    ))
}

#[allow(clippy::too_many_arguments)]
fn write_arcadia_gui_run_receipt(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
    ok: bool,
    changed: bool,
    first_missing_signal: &str,
    repo: &str,
    branch: &str,
    source_dir: &Path,
    source_sha: Option<&str>,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema": "harmonia.homeconsole_arcadia_gui_update.v1",
            "ok": ok,
            "changed": changed,
            "mutation": apply,
            "profile_id": profile.id,
            "profile_family": profile.identity,
            "repo": repo,
            "branch": branch,
            "source_dir": source_dir,
            "source_sha": source_sha,
            "first_missing_signal": first_missing_signal,
        }),
    )
}
