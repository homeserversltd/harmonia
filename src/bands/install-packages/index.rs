use super::Band;
use crate::ladder::{LadderManifest, ProjectedRoutineChild, ValidatedStep};
use crate::ModuleExecution;
use crate::{OperationOutcome, PackageAuthority, PackageBackend, SoftwareApplyAuthorization};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn enter(enter: &mut impl FnMut(Band) -> Result<(), String>) -> Result<(), String> {
    enter(Band::InstallPackages)
}
fn string_arg<'a>(a: &'a std::collections::BTreeMap<String, Value>, n: &str) -> &'a str {
    a.get(n).and_then(Value::as_str).unwrap_or_default()
}
fn optional_string_arg<'a>(
    a: &'a std::collections::BTreeMap<String, Value>,
    n: &str,
) -> Option<&'a str> {
    a.get(n).and_then(Value::as_str)
}
fn string_array_arg(a: &std::collections::BTreeMap<String, Value>, n: &str) -> Vec<String> {
    a.get(n)
        .and_then(Value::as_array)
        .map(|v| {
            v.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}
fn integer_arg(a: &std::collections::BTreeMap<String, Value>, n: &str, d: u64) -> u64 {
    a.get(n).and_then(Value::as_u64).unwrap_or(d)
}
fn resolve_path(m: &LadderManifest, p: &str) -> PathBuf {
    let p = PathBuf::from(p);
    if p.is_absolute() {
        p
    } else {
        m.base_dir.join(p)
    }
}

/// Sole chartered owner of package-family selection, authority gating, and policy.
pub(crate) fn execute_step(
    s: &ValidatedStep,
    m: &LadderManifest,
    d: &Path,
    auth: Option<&SoftwareApplyAuthorization>,
    pa: Option<&PackageAuthority>,
    key: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let apply = auth.is_some()
        && matches!(
            (s.tool.as_str(), s.permutation.as_str()),
            ("package", "install")
                | ("package", "upgrade")
                | ("package", "keyring-repair")
                | ("aur", "install")
                | ("aur", "build-pinned")
                | ("venv", "converge")
        );
    match (s.tool.as_str(), s.permutation.as_str()) {
        ("package", p) => package_step(s, d, apply, pa, key, p),
        ("aur", p) => aur_step(s, m, d, apply, key, p),
        ("venv", "converge") => {
            crate::tools::venv::execute_ladder_step(&s.args, d, &s.step_id, apply, key)
        }
        _ => Err(format!(
            "install-packages-unsupported-{}-{}",
            s.tool, s.permutation
        )),
    }
}
fn package_step(
    s: &ValidatedStep,
    d: &Path,
    apply: bool,
    pa: Option<&PackageAuthority>,
    key: Option<crate::atoms::r#do::InvocationKey>,
    p: &str,
) -> Result<OperationOutcome, String> {
    let backend = pa
        .ok_or_else(|| "profile-package-authority-missing".to_string())?
        .backend()?;
    let packages = string_array_arg(&s.args, "packages");
    let timeout = integer_arg(&s.args, "timeout_secs", 1800);
    match p {
        "check" => crate::tools::package::package_tool_for_backend(
            d, &s.step_id, "check", &packages, apply, backend, key,
        ),
        "install" => crate::tools::package::package_tool_with_policy_for_backend(
            d,
            &s.step_id,
            "install",
            &packages,
            apply,
            optional_string_arg(&s.args, "conflict_policy"),
            &string_array_arg(&s.args, "conflict_paths"),
            timeout,
            backend,
            key,
        ),
        "upgrade" => crate::tools::package::package_tool_with_policy_for_backend(
            d,
            &s.step_id,
            "upgrade",
            &[],
            apply,
            None,
            &[],
            timeout,
            backend,
            key,
        ),
        "keyring-repair" if backend == PackageBackend::Pacman => {
            crate::tools::package::keyring_repair_tool(
                d,
                &s.step_id,
                optional_string_arg(&s.args, "package").unwrap_or("archlinux-keyring"),
                apply,
                timeout,
            )
        }
        "keyring-repair" => Err("package-keyring-repair-backend-unsupported".into()),
        other => Err(format!("package-permutation-unsupported-{other}")),
    }
}
fn aur_step(
    s: &ValidatedStep,
    m: &LadderManifest,
    d: &Path,
    apply: bool,
    key: Option<crate::atoms::r#do::InvocationKey>,
    p: &str,
) -> Result<OperationOutcome, String> {
    let package = string_arg(&s.args, "package");
    match p {
        "install" => crate::tools::aur::install(
            d,
            &s.step_id,
            package,
            integer_arg(&s.args, "timeout_secs", 3600),
            apply,
            key,
        ),
        "check" => crate::tools::aur::check(
            d,
            &s.step_id,
            package,
            &resolve_path(m, string_arg(&s.args, "lock")),
            optional_string_arg(&s.args, "upstream_state"),
        ),
        "build-pinned" => crate::tools::aur::build_pinned(
            d,
            &s.step_id,
            package,
            &resolve_path(m, string_arg(&s.args, "lock")),
            &PathBuf::from(string_arg(&s.args, "build_root")),
            optional_string_arg(&s.args, "source_dir"),
            optional_string_arg(&s.args, "builder_user"),
            integer_arg(&s.args, "timeout_secs", 3600),
            s.args
                .get("install")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            apply,
            key,
        ),
        other => Err(format!("aur-permutation-unsupported-{other}")),
    }
}

/// Execute the complete InstallPackages band lifecycle for one projected module.
/// Selection, preconditions, authority gating, failure policy, and accumulation
/// intentionally live here rather than in the ladder compatibility executor.
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_manifest_band(
    manifest: &LadderManifest,
    module_dir: &Path,
    auth: Option<&SoftwareApplyAuthorization>,
    pa: Option<&PackageAuthority>,
    key: Option<crate::atoms::r#do::InvocationKey>,
    routine_states: &mut BTreeMap<String, crate::ModuleWalkState>,
    projected_steps: &[ValidatedStep],
    projected_routines: &BTreeMap<String, Vec<ProjectedRoutineChild>>,
) -> Result<ModuleExecution, String> {
    fs::create_dir_all(module_dir).map_err(|e| e.to_string())?;
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
                .any(|child| child.band == crate::bands::Band::InstallPackages)
            {
                continue;
            }
        } else if crate::ladder::placement_for_step(step)? != crate::bands::Band::InstallPackages {
            continue;
        }
        if let Some(precondition) = if step.tool == "routine" {
            None
        } else {
            crate::ladder::command_precondition(&step.args)?
        } {
            result.operation_count += 1;
            let probe = crate::ladder::command_precondition_step(
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
                result.placements.push(serde_json::json!({"step_id":step.step_id,"tool":step.tool,"permutation":step.permutation,"band":"InstallPackages","status":"blocked","module":manifest.id}));
                break;
            }
        }
        result.operation_count += 1;
        let outcome = if step.tool == "routine" {
            crate::ladder::execute_routine(
                step,
                manifest,
                module_dir,
                auth,
                pa,
                auth.is_some(),
                key,
                Some(routine_states),
                crate::bands::Band::InstallPackages,
                projected_routines
                    .get(&step.step_id)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            )?
        } else {
            execute_step(step, manifest, module_dir, auth, pa, key)?
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
                if child.band != crate::bands::Band::InstallPackages {
                    continue;
                }
                let receipt = routine
                    .children
                    .iter()
                    .find(|r| r.get("name").and_then(Value::as_str) == Some(child.name.as_str()))
                    .ok_or_else(|| format!("routine-child-receipt-missing-{}", child.name))?;
                result.placements.push(serde_json::json!({"step_id":child.name,"tool":child.tool,"permutation":child.permutation,"band":"InstallPackages","status":receipt.get("state").and_then(Value::as_str).unwrap_or("failed"),"ok":receipt.get("ok").and_then(Value::as_bool).unwrap_or(false),"changed":receipt.get("changed").and_then(Value::as_bool).unwrap_or(false),"module":manifest.id,"routine":step.step_id}));
            }
        } else {
            result.placements.push(serde_json::json!({"step_id":step.step_id,"tool":step.tool,"permutation":step.permutation,"band":"InstallPackages","status":if outcome.ok {"completed"} else {"failed"},"module":manifest.id}));
        }
        result.changed |= outcome.changed;
        if !outcome.ok {
            result.ok = false;
            result.first_missing_signal.get_or_insert_with(|| {
                format!("step_id={} defect={}", step.step_id, outcome.message)
            });
            if step.on_failure == crate::ladder::OnFailure::Stop {
                break;
            }
        }
    }
    Ok(result)
}

use crate::receipts::event;
use crate::{LoadedModule, Profile, ProfileProjection, UpdateMode};
use std::collections::BTreeSet;
use std::fs::File;
pub(crate) fn execute_manifest_modules(
    profile: &Profile,
    receipt_dir: &Path,
    mode: UpdateMode,
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
                        "{} band=InstallPackages steps={}",
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
