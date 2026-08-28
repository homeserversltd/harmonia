use std::path::PathBuf;
use crate::OperationOutcome;
use super::Band;
use crate::tools::ladder::{LadderManifest, ProjectedRoutineChild, ValidatedStep};
use crate::ModuleExecution;
use crate::{
    LoadedModule, PackageAuthority, Profile, ProfileProjection, SoftwareApplyAuthorization,
    UpdateMode,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::Path;
pub(crate) fn enter(enter: &mut impl FnMut(Band) -> Result<(), String>) -> Result<(), String> {
    enter(Band::RatchetBinaries)
}


/// Execute the complete RatchetBinaries band lifecycle for one projected module.
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
                .any(|child| child.band == crate::bands::Band::RatchetBinaries)
            {
                continue;
            }
        } else if crate::tools::routine::placement_for_step(step)?
            != crate::bands::Band::RatchetBinaries
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
                result.placements.push(serde_json::json!({"step_id":step.step_id,"tool":step.tool,"permutation":step.permutation,"band":"RatchetBinaries","status":"blocked","module":manifest.id}));
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
                crate::bands::Band::RatchetBinaries,
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
                if child.band != crate::bands::Band::RatchetBinaries {
                    continue;
                }
                let receipt = routine
                    .children
                    .iter()
                    .find(|r| r.get("name").and_then(Value::as_str) == Some(child.name.as_str()))
                    .ok_or_else(|| format!("routine-child-receipt-missing-{}", child.name))?;
                result.placements.push(serde_json::json!({"step_id":child.name,"tool":child.tool,"permutation":child.permutation,"band":"RatchetBinaries","status":receipt.get("state").and_then(Value::as_str).unwrap_or("failed"),"ok":receipt.get("ok").and_then(Value::as_bool).unwrap_or(false),"changed":receipt.get("changed").and_then(Value::as_bool).unwrap_or(false),"module":manifest.id,"routine":step.step_id}));
            }
        } else {
            result.placements.push(serde_json::json!({"step_id":step.step_id,"tool":step.tool,"permutation":step.permutation,"band":"RatchetBinaries","status":if outcome.ok {"completed"} else {"failed"},"module":manifest.id}));
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
                        "{} band=RatchetBinaries steps={}",
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
) -> Result<(crate::OperationOutcome, std::collections::BTreeMap<String, serde_json::Value>), String> {
    let contract = crate::tools::get(tool).ok_or_else(|| format!("routine-tool-not-found-{tool}"))?;
    let permutation = requested_permutation.and_then(|name| contract.permutation(name)).or_else(|| contract.permutations.first()).ok_or_else(|| format!("routine-tool-no-permutation-{tool}"))?;
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
    let name = tool.to_string();
    match tool {
        "fetch-artifact" => {
            let outcome = crate::tools::fetch_artifact::execute(args, receipt_dir, apply, invocation)?;
            let changed = outcome.changed;
            let artifact = if outcome.skipped {
                args.get("installed_binary").cloned().unwrap_or(Value::Null)
            } else {
                args.get("destination").cloned().unwrap_or(Value::Null)
            };
            Ok((outcome, [("artifact".into(), artifact), ("changed".into(), serde_json::json!(changed))].into_iter().collect()))
        }
        "build-crate" => {
            let cwd = Path::new(
                args.get("cwd")
                    .and_then(|v| v.as_str())
                    .ok_or("build-crate-cwd-missing")?,
            );
            let source_sha = args
                .get("source_build_sha")
                .and_then(|v| v.as_str())
                .ok_or("build-crate-source-build-sha-missing")?;
            let installed_sha = args.get("installed_build_sha").and_then(|v| v.as_str());
            let binary_path = args
                .get("installed_binary")
                .and_then(|v| v.as_str())
                .ok_or("build-crate-installed-binary-missing")?;
            let binary = Path::new(binary_path);
            let mut artifact_path = args
                .get("artifact")
                .and_then(Value::as_str)
                .map(PathBuf::from)
                .or_else(|| {
                    args.get("artifact_name")
                        .and_then(Value::as_str)
                        .map(|name| cwd.join("target/release").join(name))
                })
                .unwrap_or_else(|| binary.to_path_buf());
            let env_value = args.get("environment");
            let env: Vec<(String, String)> = match env_value {
                None => Vec::new(),
                Some(Value::Object(m)) => m
                    .iter()
                    .map(|(k, v)| {
                        v.as_str()
                            .map(|x| (k.clone(), x.to_string()))
                            .ok_or_else(|| format!("build-crate-environment-nonstring-{k}"))
                            .map_err(|e| e)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                Some(_) => return Err("build-crate-environment-not-object".into()),
            };
            let timeout = args
                .get("timeout_secs")
                .and_then(Value::as_u64)
                .unwrap_or(crate::atoms::r#do::build_crate::DEFAULT_TIMEOUT_SECS);
            let bearer = args
                .get("bearer")
                .and_then(Value::as_str)
                .unwrap_or("owner");
            // A current installed image is the truthful artifact for a quiet pass.
            // Reusing it prevents a stale/non-reproducible target image from
            // manufacturing promotion and restart after source convergence.
            let (identity_matches, observed_sha_present, artifact_present, error) =
                match crate::atoms::ask::build_crate::build_identity_with_environment(
                    source_sha,
                    installed_sha,
                    binary,
                    crate::build_crate::IdentityMode::EmbeddedSourceSha,
                    &env,
                ) {
                    Ok(observation) => (
                        observation.identity_matches(),
                        observation.artifact_build_sha.is_some(),
                        observation.artifact_present,
                        None,
                    ),
                    Err(error) => (false, false, binary.is_file(), Some(error)),
                };
            let probe_receipt = serde_json::json!({
                "schema": "harmonia.build-crate.probe.v1",
                "source_build_sha": source_sha,
                "installed_binary": binary,
                "identity_matches": identity_matches,
                "observed_sha_present": observed_sha_present,
                "artifact_present": artifact_present,
                "error": error,
            });
            // Persist the exact probe before any non-matching image can enter
            // the fallback build path (including a fallback error).
            crate::write_json(&receipt_dir.join("build-probe.json"), &probe_receipt)?;
            let installed_current = identity_matches;
            let moved = if installed_current {
                artifact_path = binary.to_path_buf();
                None
            } else {
                crate::build_crate::run_build_with_mode(
                    cwd,
                    source_sha,
                    installed_sha,
                    binary,
                    &artifact_path,
                    apply,
                    &env,
                    timeout,
                    &receipt_dir.join("harmonia-atoms.log"),
                    bearer,
                    invocation,
                    crate::build_crate::IdentityMode::RegularExecutable,
                )?
            };

            let result = OperationOutcome {
                ok: moved.as_ref().map_or(true, |x| x.ok),
                changed: apply && moved.is_some(),
                skipped: !apply,
                message: "build-crate".into(),
                command: None,
            };
            let result_changed = result.changed;
            Ok((
                result,
                [
                    ("artifact".into(), serde_json::json!(artifact_path)),
                    ("installed_path".into(), serde_json::json!(binary)),
                    ("source_build_sha".into(), serde_json::json!(source_sha)),
                    ("probe".into(), probe_receipt),
                    ("changed".into(), serde_json::json!(result_changed)),
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
    use super::*;
    use std::fs;

    #[test]
    fn lowered_real_manifest_build_child_resolves_pull_context_and_quiets_install() {
        let root = std::env::temp_dir().join(format!(
            "harmonia-ratchet-lowered-child-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let source = root.join("source");
        let installed = root.join("installed");
        fs::create_dir_all(source.join("target/release")).unwrap();
        let source_sha = "0123456789abcdef0123456789abcdef01234567";
        let built = root.join("built");
        let image = format!("fixture:{source_sha}:image");
        fs::write(&installed, &image).unwrap();
        fs::write(&built, &image).unwrap();

        // Keep the real module's lowering and child declarations, changing only
        // its filesystem endpoints so the production routine can run in a
        // hermetic fixture.
        let mut manifest: LadderManifest = serde_json::from_str(include_str!(
            "../../../profiles/homeconsole/modules/arcadia-gui-runtime/manifest.json"
        ))
        .expect("real manifest parses");
        let service = manifest
            .ladder
            .iter_mut()
            .find(|step| step.tool == "service-runtime")
            .expect("real service-runtime declaration");
        service.args.insert(
            "source_dir".into(),
            Value::String(source.to_string_lossy().into_owned()),
        );
        service.args.insert(
            "install_bin".into(),
            Value::String(installed.to_string_lossy().into_owned()),
        );
        crate::bands::restart_services::lower_service_runtime_steps(&mut manifest);
        crate::bands::backfill_files::lower_service_runtime_steps(&mut manifest)
            .expect("real manifest lowers");

        let validated = crate::tools::ladder::validate_ladder(&manifest).expect("valid lowered manifest");
        let routine_step = validated
            .iter()
            .find(|step| step.tool == "routine" && step.permutation == "execute")
            .expect("lowered routine");
        let projected = crate::tools::routine::project_manifest_routines(&manifest, &validated)
            .expect("production routine projection");
        let children = projected.get(&routine_step.step_id).expect("projected children");
        let build = children
            .iter()
            .find(|child| child.name == "build" && child.tool == "build-crate")
            .expect("lowered build child");
        assert_eq!(
            build.args.get("source_build_sha"),
            Some(&serde_json::json!({"from":"pull-repo.resolved_commit"}))
        );
        assert_eq!(
            build.args.get("installed_binary").and_then(Value::as_str),
            Some(installed.to_string_lossy().as_ref())
        );
        let environment = build.args.get("environment").and_then(Value::as_object).unwrap();
        assert_eq!(
            environment.get("ARCADIA_BUILD_SHA"),
            Some(&serde_json::json!({"from":"pull-repo.resolved_commit"}))
        );

        let routine_dir = root.join("receipts").join(&routine_step.step_id);
        let mut states = std::collections::BTreeMap::new();
        let state = crate::ModuleWalkState {
            context: [
                ("pull-repo.path".into(), Value::String(source.to_string_lossy().into_owned())),
                ("pull-repo.resolved_commit".into(), Value::String(source_sha.into())),
            ]
            .into_iter()
            .collect(),
            children: vec![serde_json::json!({
                "name":"pull-repo", "tool":"pull-repo", "state":"completed",
                "ok":true, "changed":false, "outputs":{
                    "path":source, "resolved_commit":source_sha
                }
            })],
            blocked_by: None,
            ok: true,
            changed: false,
            first_missing_signal: None,
        };
        states.insert(routine_step.step_id.clone(), state);
        let outcome = crate::tools::routine::execute_routine(
            routine_step,
            &manifest,
            &root.join("receipts"),
            None,
            None,
            true,
            None,
            Some(&mut states),
            crate::bands::Band::RatchetBinaries,
            children,
        )
        .expect("production routine execution");
        assert!(outcome.ok);
        assert!(!outcome.changed);

        let routine = states.get(&routine_step.step_id).unwrap();
        let build_receipt = routine.children.iter().find(|receipt| {
            receipt.get("name").and_then(Value::as_str) == Some("build")
        }).unwrap();
        assert_eq!(build_receipt.get("changed"), Some(&Value::Bool(false)));
        assert!(crate::bands::restart_services::binary_content_matches(&built, &installed).unwrap());
        let probe = build_receipt.get("outputs").and_then(|v| v.get("probe")).unwrap();
        assert_eq!(probe.get("source_build_sha").and_then(Value::as_str), Some(source_sha));
        assert_eq!(probe.get("installed_binary").and_then(Value::as_str), Some(installed.to_string_lossy().as_ref()));
        assert_eq!(probe.get("identity_matches"), Some(&Value::Bool(true)));
        assert_eq!(probe.get("observed_sha_present"), Some(&Value::Bool(true)));
        assert_eq!(probe.get("artifact_present"), Some(&Value::Bool(true)));
        assert_eq!(probe.get("error"), Some(&Value::Null));
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(routine_dir.join("build/build-probe.json")).unwrap()).unwrap(),
            *probe
        );

        let install = children.iter().find(|child| child.name == "binary-install").unwrap();
        assert_eq!(install.args.get("source_path"), Some(&serde_json::json!({"from":"build.artifact"})));
        let restart = children.iter().find(|child| child.name == "service-restart").unwrap();
        assert_eq!(restart.args.get("service").and_then(Value::as_str), Some("arcadia.service"));
        assert_eq!(
            crate::bands::restart_services::service_runtime_material_gates("restart", false, false),
            (false, false)
        );
        assert!(!crate::bands::restart_services::service_runtime_material_gates("restart", false, false).0);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn invalid_source_sha_writes_probe_before_fallback_error_without_mutation() {
        let root = std::env::temp_dir().join(format!(
            "harmonia-ratchet-invalid-probe-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let cwd = root.join("source");
        fs::create_dir_all(&cwd).unwrap();
        let installed = root.join("installed");
        let artifact = root.join("artifact");
        let receipt_dir = root.join("receipts");
        let source_build_sha = "unresolved-source-sha";
        let args = [
            (
                "cwd".into(),
                Value::String(cwd.to_string_lossy().into_owned()),
            ),
            (
                "source_build_sha".into(),
                Value::String(source_build_sha.into()),
            ),
            (
                "installed_binary".into(),
                Value::String(installed.to_string_lossy().into_owned()),
            ),
            (
                "artifact".into(),
                Value::String(artifact.to_string_lossy().into_owned()),
            ),
            ("environment".into(), Value::Object(serde_json::Map::new())),
        ]
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
        let manifest: LadderManifest = serde_json::from_str(include_str!(
            "../../../profiles/homeconsole/modules/arcadia-gui-runtime/manifest.json"
        ))
        .expect("real manifest parses");

        let result = execute_routine_child(
            "build-crate",
            None,
            &args,
            &manifest,
            &receipt_dir,
            true,
            None,
        );
        assert!(!installed.exists());
        assert!(!artifact.exists());

        let probe: Value =
            serde_json::from_slice(&fs::read(receipt_dir.join("build-probe.json")).unwrap())
                .unwrap();
        assert_eq!(probe.get("identity_matches"), Some(&Value::Bool(false)));
        assert_eq!(probe.get("observed_sha_present"), Some(&Value::Bool(false)));
        assert_eq!(probe.get("artifact_present"), Some(&Value::Bool(false)));
        assert_eq!(
            probe.get("error"),
            Some(&Value::String(
                "build-crate-source-build-sha-invalid".into()
            ))
        );
        assert_eq!(
            result.expect_err("invalid source SHA must stop fallback before mutation"),
            "build-crate-source-build-sha-invalid"
        );
        assert_eq!(
            probe.get("source_build_sha").and_then(Value::as_str),
            Some(source_build_sha)
        );
        assert_eq!(
            probe.get("installed_binary").and_then(Value::as_str),
            Some(installed.to_string_lossy().as_ref())
        );
        let _ = fs::remove_dir_all(root);
    }
}
