use crate::update_set::{ServiceBinding, Target, UpdatePlan};
use crate::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Clone, Debug)]
pub(crate) enum LoadedModule {
    Sidecar(ModuleManifest),
    Ladder(LadderManifest),
}

#[derive(Clone, Debug)]
pub(crate) struct ProjectedModule {
    pub(crate) loaded: LoadedModule,
    pub(crate) steps: Vec<crate::ladder::ValidatedStep>,
    group_probe: Option<crate::ladder::ValidatedStep>,
    pub(crate) routines: BTreeMap<String, Vec<crate::ladder::ProjectedRoutineChild>>,
}

#[derive(Clone, Debug)]
pub(crate) struct ProfileProjection {
    pub(crate) modules: BTreeMap<String, ProjectedModule>,
    pub(crate) errors: BTreeMap<String, String>,
}

impl ProfileProjection {
    pub(crate) fn derive_update_plan(&self, profile: &Profile, module_root: &Path) -> Result<crate::update_set::UpdatePlan, String> {
        projection_derive_plan_inner(self, profile, module_root)
    }
}

pub(crate) fn load_profile_projection(profile: &Profile, module_root: &Path, disabled: &BTreeSet<String>) -> Result<ProfileProjection, String> {
    let mut modules = BTreeMap::new();
    let mut errors = BTreeMap::new();
    for id in &profile.modules {
        if disabled.contains(id) { continue; }
        let loaded = match load_profile_module(module_root, id) { Ok(v) => v, Err(e) => { errors.insert(id.clone(), e); continue; } };
        let (steps, group_probe, routines) = match &loaded {
            LoadedModule::Ladder(m) => {
                let steps = match crate::ladder::validate_ladder(m) {
                    Ok(steps) => steps,
                    Err(e) => { errors.insert(id.clone(), format!("module-invalid {}", e.first_missing_signal())); continue; }
                };
                let group_probe = match m.group.as_ref().map(|g| crate::ladder::validate_group(g, &m.constants)).transpose() {
                    Ok(probe) => probe,
                    Err(e) => { errors.insert(id.clone(), format!("module-invalid {}", e.first_missing_signal())); continue; }
                };
                let mut routines = BTreeMap::new();
                let mut routine_error = None;
                for step in m.ladder.iter().filter(|step| step.tool == "routine") {
                    match crate::ladder::project_routine_children(step, &m.constants) {
                        Ok(children) => { routines.insert(step.step_id.clone(), children); }
                        Err(e) => { routine_error = Some(format!("module-invalid {}", e.first_missing_signal())); break; }
                    }
                }
                if let Some(error) = routine_error { errors.insert(id.clone(), error); continue; }
                (steps, group_probe, routines)
            }
            LoadedModule::Sidecar(_) => (Vec::new(), None, BTreeMap::new()),
        };
        modules.insert(id.clone(), ProjectedModule { loaded, steps, group_probe, routines });
    }
    Ok(ProfileProjection { modules, errors })
}

fn projection_text(v: &BTreeMap<String, Value>, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_owned)
}
fn projection_value_path(v: &Value, k: &str) -> Option<PathBuf> {
    v.get(k).and_then(Value::as_str).map(PathBuf::from)
}
fn projection_component_face(component: &str) -> Option<&'static str> {
    match component {
        "arcadia" => Some("Arcadia"),
        "coronatio" => Some("Coronatio"),
        _ => None,
    }
}
fn projection_safe_target(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!("update-set-target-invalid {}", path.display()));
    }
    for broad in [
        "/",
        "/etc",
        "/home",
        "/home/owner",
        "/usr",
        "/usr/local",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/var",
        "/var/lib",
    ] {
        if path == Path::new(broad) {
            return Err(format!("update-set-target-too-broad {}", path.display()));
        }
    }
    Ok(())
}
fn projection_add_target(out: &mut Vec<Target>, path: PathBuf, member: &str) -> Result<(), String> {
    projection_safe_target(&path)?;
    out.push(Target {
        path,
        member: member.into(),
    });
    Ok(())
}
fn projection_add_service(
    out: &mut Vec<ServiceBinding>,
    name: String,
    user: bool,
    target_user: Option<String>,
    member: &str,
) {
    if !out
        .iter()
        .any(|s| s.name == name && s.user == user && s.target_user == target_user)
    {
        out.push(ServiceBinding {
            name,
            user,
            target_user,
        });
    }
}
fn projection_derive_plan_inner(
    self_: &ProfileProjection,
    profile: &Profile,
    _module_root: &Path,
) -> Result<UpdatePlan, String> {
    let projected: Vec<(&String, &ProjectedModule)> = profile
        .modules
        .iter()
        .filter_map(|id| self_.modules.get_key_value(id))
        .collect();
    let runtime_faces: Vec<String> = projected
        .iter()
        .flat_map(|(_, p)| {
            let mut faces = Vec::new();
            for args in projected_runtime_args(p) {
                if let Some(face) = args
                    .get("component")
                    .and_then(Value::as_str)
                    .and_then(projection_component_face)
                {
                    faces.push(face.to_owned());
                }
            }
            faces
        })
        .collect();
    let faces: BTreeSet<String> = runtime_faces.into_iter().collect();
    let face = if faces.len() == 1 {
        faces.iter().next().unwrap().clone()
    } else if faces.is_empty()
        && projected
            .iter()
            .any(|(_, p)| p.loaded.id().to_ascii_lowercase().contains("hyprland"))
    {
        "Hyprland".into()
    } else {
        return Err(format!("gui-selection-ambiguous count={}", faces.len()));
    };
    let mut targets = Vec::new();
    let mut services = Vec::new();
    let mut caduceus_count = 0;
    for (_, projected) in &projected {
        let constants = match &projected.loaded {
            LoadedModule::Ladder(m) => Some(&m.constants),
            LoadedModule::Sidecar(_) => None,
        };
        let module_id = projected.loaded.id();
        let steps = &projected.steps;
        let is_gui = projected_gui_module(projected, &face);
        for args in projected_runtime_args(projected) {
            let component = args.get("component").and_then(Value::as_str).unwrap_or("");
            let member = if component == "caduceus" {
                caduceus_count += 1;
                "caduceus"
            } else if projection_component_face(component) == Some(face.as_str()) {
                face.as_str()
            } else {
                continue;
            };
            if let Some(p) = projection_text(args, "install_bin") {
                projection_add_target(&mut targets, p.into(), member)?;
            }
            if let Some(a) = args.get("managed_files").and_then(Value::as_array) {
                for x in a {
                    if let Some(p) = projection_value_path(x, "path") {
                        projection_add_target(&mut targets, p, member)?;
                    }
                }
            }
            if let Some(p) = args
                .get("caduceus_profile_source")
                .and_then(|x| projection_value_path(x, "path"))
            {
                projection_add_target(&mut targets, p, member)?;
            }
            if let Some(name) = projection_text(args, "service") {
                projection_add_service(&mut services, name, false, None, member);
            }
        }
        for s in steps {
            if s.tool == "files"
                && s.permutation == "source-shelf-sweep"
                && (module_id == "sbin"
                    || projected_runtime_args(projected).iter().any(|args| {
                        args.get("component").and_then(Value::as_str) == Some("caduceus")
                    }))
            {
                if let Some(p) = projection_text(&s.args, "target_shelf") {
                    projection_add_target(&mut targets, p.into(), "agathodaimon")?;
                }
                if projection_text(&s.args, "launcher_pattern").is_none() {
                    continue;
                }
                let tr = projection_text(&s.args, "launcher_target_root")
                    .map(PathBuf::from)
                    .ok_or("staff-target-root-missing")?;
                let sr = projection_text(&s.args, "launcher_source_root")
                    .map(PathBuf::from)
                    .ok_or("staff-source-root-missing")?;
                let pat =
                    projection_text(&s.args, "launcher_pattern").ok_or("staff-pattern-missing")?;
                let mut names = BTreeSet::new();
                for r in [&tr, &sr] {
                    if r.is_dir() {
                        for e in fs::read_dir(r).map_err(|e| e.to_string())? {
                            let p = e.map_err(|e| e.to_string())?.path();
                            if p.file_name()
                                .and_then(|n| n.to_str())
                                .is_some_and(|n| projection_glob(&pat, n))
                            {
                                names.insert(p.file_name().unwrap().to_os_string());
                            }
                        }
                    }
                }
                for n in names {
                    projection_add_target(&mut targets, tr.join(n), "agathodaimon")?;
                }
            }
            if is_gui && s.tool == "files" && s.permutation == "converge" {
                if let (Some(r), Some(files)) = (
                    projection_text(&s.args, "target_root"),
                    s.args.get("files").and_then(Value::as_array),
                ) {
                    for f in files.iter().filter_map(Value::as_str) {
                        projection_add_target(&mut targets, PathBuf::from(&r).join(f), &face)?;
                    }
                }
            }
            if is_gui && s.tool == "systemd" {
                let user = s.permutation.starts_with("user-");
                let target_user = projection_text(&s.args, "user");
                if let Some(name) = projection_text(&s.args, "service") {
                    projection_add_service(&mut services, name, user, target_user, &face);
                }
            }
        }
        if is_gui {
            let target_root = constants
                .and_then(|c| c.get("target_dir"))
                .and_then(Value::as_str)
                .map(PathBuf::from);
            if let Some(a) = constants
                .and_then(|c| c.get("expected_files"))
                .and_then(Value::as_array)
            {
                for f in a.iter().filter_map(Value::as_str) {
                    let p = PathBuf::from(f);
                    let p = if p.is_absolute() {
                        p
                    } else if let Some(r) = &target_root {
                        r.join(p)
                    } else {
                        continue;
                    };
                    projection_add_target(&mut targets, p, &face)?;
                }
            }
            for (key, user) in [("services", false), ("user_services", true)] {
                if let Some(a) = constants.and_then(|c| c.get(key)).and_then(Value::as_array) {
                    for name in a.iter().filter_map(Value::as_str) {
                        projection_add_service(
                            &mut services,
                            name.into(),
                            user,
                            if user { Some("owner".into()) } else { None },
                            &face,
                        );
                    }
                }
            }
        }
    }
    if caduceus_count != 1 {
        return Err(format!(
            "caduceus-selection-ambiguous count={caduceus_count}"
        ));
    }
    targets.sort_by(|a, b| a.path.cmp(&b.path));
    targets.dedup_by(|a, b| a.path == b.path);
    services.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(UpdatePlan {
        targets,
        services,
        gui_face: face.clone(),
        gui_member: face,
        caduceus_count,
    })
}
fn projection_glob(pattern: &str, name: &str) -> bool {
    if let Some((a, b)) = pattern.split_once('*') {
        name.starts_with(a) && name.ends_with(b)
    } else {
        pattern == name
    }
}
fn projected_runtime_args(projected: &ProjectedModule) -> Vec<&BTreeMap<String, Value>> {
    projected
        .steps
        .iter()
        .filter(|s| s.tool == "service-runtime" && s.permutation == "converge")
        .map(|s| &s.args)
        .chain(
            projected
                .routines
                .values()
                .flatten()
                .filter(|c| c.tool == "service-runtime" && c.name == "build")
                .map(|c| &c.args),
        )
        .collect()
}
fn projected_gui_module(projected: &ProjectedModule, face: &str) -> bool {
    match &projected.loaded {
        LoadedModule::Ladder(m) => {
            if face != "Hyprland" {
                projected_runtime_args(projected).iter().any(|a| {
                    a.get("component")
                        .and_then(Value::as_str)
                        .and_then(projection_component_face)
                        == Some(face)
                })
            } else {
                let mut h = m.id.to_ascii_lowercase();
                if let Some(x) = m.constants.get("meaning").and_then(Value::as_str) {
                    h.push_str(&x.to_ascii_lowercase());
                }
                h.contains("hyprland") || h.contains("desktop config") || h.contains("user session")
            }
        }
        LoadedModule::Sidecar(_) => false,
    }
}

impl LoadedModule {
    fn id(&self) -> &str {
        match self {
            Self::Sidecar(module) => &module.id,
            Self::Ladder(manifest) => &manifest.id,
        }
    }

    fn version(&self) -> Option<&str> {
        match self {
            Self::Sidecar(_) => None,
            Self::Ladder(manifest) => Some(&manifest.version),
        }
    }
}

#[derive(Debug, Clone)]
struct GroupProbeObservation {
    module_id: String,
    ok: bool,
    tool: String,
    permutation: String,
    signal: String,
}

#[derive(Debug, Clone)]
struct GroupSelection {
    group_id: String,
    winner: String,
    losers: Vec<String>,
    observations: Vec<GroupProbeObservation>,
}

const APPLIANCE_CONFIG_PATH: &str = "/etc/appliance/config.json";

#[derive(Default)]
struct DeviceModulePolicy {
    disabled_modules: BTreeSet<String>,
}

fn read_device_module_policy() -> Result<DeviceModulePolicy, String> {
    let path = Path::new(APPLIANCE_CONFIG_PATH);
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(DeviceModulePolicy::default())
        }
        Err(err) => {
            return Err(format!(
                "appliance-config-read-failed {}: {err}",
                path.display()
            ))
        }
    };
    let config: serde_json::Value = serde_json::from_str(&text)
        .map_err(|err| format!("appliance-config-parse-failed {}: {err}", path.display()))?;
    let disabled_modules = config
        .get("harmonia")
        .and_then(|harmonia| harmonia.get("disabled_modules"))
        .and_then(serde_json::Value::as_array)
        .map(|modules| {
            modules
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok(DeviceModulePolicy { disabled_modules })
}

pub(crate) fn default_pinned_lock_path(profile: &Profile) -> PathBuf {
    PathBuf::from("/etc/harmonia/locks")
        .join(&profile.id)
        .join("pinned-artifacts.json")
}

pub(crate) fn load_profile(path: &Path) -> io::Result<Profile> {
    let text = fs::read_to_string(path)?;
    let profile: Profile = serde_json::from_str(&text).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("profile-parse-failed {}: {err}", path.display()),
        )
    })?;
    // Profiles evolve independently from the installed engine. Keep parsing
    // backward-compatible; consumers that execute package work require
    // package_authority at that operation boundary.
    if let Some(package_authority) = profile.package_authority.as_ref() {
        package_authority
            .backend()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    }
    Ok(profile)
}

pub(crate) fn load_module(path: &Path) -> Result<ModuleManifest, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("module-read-failed {}: {e}", path.display()))?;
    let raw: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("module-parse-failed {}: {e}", path.display()))?;
    for field in [
        "steps",
        "tool",
        "command",
        "action",
        "actions",
        "args",
        "cwd",
        "apply_only",
    ] {
        if raw.get(field).is_some() {
            return Err(format!(
                "module-sidecar-behavior-field-rejected {} field={}",
                path.display(),
                field
            ));
        }
    }
    serde_json::from_value(raw).map_err(|e| format!("module-parse-failed {}: {e}", path.display()))
}

fn load_profile_module(module_root: &Path, module_id: &str) -> Result<LoadedModule, String> {
    let module_dir = module_root.join(module_id);
    let manifest_path = module_dir.join("manifest.json");
    if manifest_path.exists() && is_ladder_manifest(&manifest_path) {
        return load_ladder_manifest(&manifest_path).map(LoadedModule::Ladder);
    }
    let sidecar_path = module_dir.join("sidecar.json");
    if sidecar_path.exists() {
        return load_module(&sidecar_path).map(LoadedModule::Sidecar);
    }
    load_module(&sidecar_path).map(LoadedModule::Sidecar)
}

fn resolve_group_selections(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    projection: &ProfileProjection,
) -> Result<BTreeMap<String, GroupSelection>, String> {
    let mut groups: BTreeMap<String, Vec<(String, LadderManifest)>> = BTreeMap::new();
    for module_id in &profile.modules {
        let Some(projected) = projection.modules.get(module_id) else {
            continue;
        };
        let LoadedModule::Ladder(module) = &projected.loaded else {
            continue;
        };
        let Some(group_id) = module.group.as_ref().map(|group| group.group_id.clone()) else {
            continue;
        };
        groups
            .entry(group_id)
            .or_default()
            .push((module_id.clone(), module.clone()));
    }

    let mut selections = BTreeMap::new();
    for (group_id, mut members) in groups {
        if members.len() < 2 {
            continue;
        }
        members.sort_by(|(left_id, left), (right_id, right)| {
            left.group
                .as_ref()
                .map(|group| group.group_order)
                .unwrap_or(i64::MAX)
                .cmp(
                    &right
                        .group
                        .as_ref()
                        .map(|group| group.group_order)
                        .unwrap_or(i64::MAX),
                )
                .then_with(|| left_id.cmp(right_id))
        });
        let group_receipt_dir = receipt_dir.join("groups").join(&group_id);
        let mut observations = Vec::new();
        let mut live_winners = Vec::new();
        for (module_id, manifest) in &members {
            let group = manifest.group.as_ref().expect("grouped manifest");
            let probe_dir = group_receipt_dir.join("probes").join(module_id);
            let projected = projection
                .modules
                .get(module_id)
                .ok_or_else(|| format!("module-not-in-projection-{module_id}"))?;
            let probe = projected
                .group_probe
                .as_ref()
                .ok_or_else(|| format!("module-{}-has-no-group", module_id))?;
            let outcome =
                crate::ladder::execute_group_live_probe_validated(manifest, probe, &probe_dir)?;
            let signal = if outcome.ok {
                "probe-live".to_string()
            } else {
                outcome.message.clone()
            };
            if outcome.ok {
                live_winners.push(module_id.clone());
            }
            observations.push(GroupProbeObservation {
                module_id: module_id.clone(),
                ok: outcome.ok,
                tool: group.live_probe.tool.clone(),
                permutation: group.live_probe.permutation.clone(),
                signal,
            });
        }
        let winner = live_winners
            .first()
            .cloned()
            .unwrap_or_else(|| members[0].0.clone());
        let losers: Vec<String> = members
            .iter()
            .map(|(module_id, _)| module_id.clone())
            .filter(|module_id| module_id != &winner)
            .collect();
        let selection = GroupSelection {
            group_id: group_id.clone(),
            winner: winner.clone(),
            losers: losers.clone(),
            observations,
        };
        write_group_selection_receipt(receipt_dir, &selection)?;
        selections.insert(group_id, selection);
    }
    Ok(selections)
}

fn group_loser_winners(selections: &BTreeMap<String, GroupSelection>) -> BTreeMap<String, String> {
    let mut losers = BTreeMap::new();
    for selection in selections.values() {
        for loser in &selection.losers {
            losers.insert(loser.clone(), selection.winner.clone());
        }
    }
    losers
}

fn caduceus_commands_for_profile(
    profile: &Profile,
    module_root: &Path,
) -> Result<Vec<String>, String> {
    caduceus_commands_for_profile_with_policy(profile, module_root, &BTreeSet::new())
}

fn caduceus_commands_for_profile_with_policy(
    profile: &Profile,
    module_root: &Path,
    disabled_modules: &BTreeSet<String>,
) -> Result<Vec<String>, String> {
    let mut commands = Vec::new();
    for module_id in &profile.modules {
        if disabled_modules.contains(module_id) {
            continue;
        }
        let Ok(LoadedModule::Ladder(module)) = load_profile_module(module_root, module_id) else {
            continue;
        };
        for command in module.caduceus_commands {
            if !commands.contains(&command) {
                commands.push(command);
            }
        }
    }
    Ok(commands)
}

fn compose_caduceus_commands(
    profile: &Profile,
    module_root: &Path,
    manifest: &mut LadderManifest,
) -> Result<(), String> {
    compose_caduceus_commands_with_policy(profile, module_root, manifest, &BTreeSet::new())
}

fn compose_caduceus_commands_with_policy(
    profile: &Profile,
    module_root: &Path,
    manifest: &mut LadderManifest,
    disabled_modules: &BTreeSet<String>,
) -> Result<(), String> {
    let is_caduceus = manifest.ladder.iter().any(|step| {
        crate::ladder::service_runtime_converge_args(step)
            .and_then(|args| args.get("component"))
            .and_then(|value| value.as_str())
            == Some("caduceus")
    });
    if !is_caduceus {
        return Ok(());
    }
    let commands =
        caduceus_commands_for_profile_with_policy(profile, module_root, disabled_modules)?;
    for step in &mut manifest.ladder {
        if step.tool == "service-runtime" && step.permutation == "converge" {
            step.args
                .insert("caduceus_commands".to_string(), json!(commands));
        } else if crate::ladder::is_lowered_service_runtime_converge(step) {
            for child in &mut step.steps {
                if child.tool == "service-runtime" {
                    child
                        .args
                        .insert("caduceus_commands".to_string(), json!(commands));
                }
            }
        }
    }
    Ok(())
}

fn write_group_selection_receipt(
    receipt_dir: &Path,
    selection: &GroupSelection,
) -> Result<(), String> {
    fs::create_dir_all(receipt_dir.join("groups")).map_err(|e| e.to_string())?;
    write_json(
        &receipt_dir
            .join("groups")
            .join(format!("{}-selection.json", selection.group_id)),
        &json!({
            "schema": "harmonia.group.selection.v1",
            "group_id": selection.group_id,
            "probes_observed": selection.observations.iter().map(|probe| json!({
                "module_id": probe.module_id,
                "ok": probe.ok,
                "tool": probe.tool,
                "permutation": probe.permutation,
                "signal": probe.signal,
            })).collect::<Vec<_>>(),
            "winner": selection.winner,
            "losers": selection.losers,
        }),
    )
}

fn execute_band_modules(
    band: crate::bands::Band,
    profile: &Profile,
    module_root: &Path,
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
        let loaded = match projection.modules.get(module_id).map(|p| p.loaded.clone()) {
            Some(value) => value,
            None => {
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
            }
        };
        *module_count = profile.modules.len();
        let result = match loaded {
            LoadedModule::Ladder(manifest) => execute_ladder_manifest_band(
                &manifest,
                &receipt_dir.join("modules").join(module_id),
                band,
                mode.software_authorization(),
                profile.package_authority.as_ref(),
                mode.invocation(),
                states.get(module_id).map(|s| s.changed).unwrap_or(false),
                routines.entry(module_id.clone()).or_default(),
                projection
                    .modules
                    .get(module_id)
                    .map(|p| p.steps.as_slice())
                    .unwrap_or(&[]),
                &projection
                    .modules
                    .get(module_id)
                    .expect("projected module")
                    .routines,
            ),
            LoadedModule::Sidecar(_) => {
                let mut state = ModuleExecution {
                    ok: false,
                    changed: false,
                    operation_count: 0,
                    first_missing_signal: Some("module-sidecar-not-band-executable".to_string()),
                    placements: Vec::new(),
                };
                Ok(state)
            }
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
                if part.changed {
                    *changed = true;
                }
                if !part.ok {
                    state.ok = false;
                    if state.first_missing_signal.is_none() {
                        state.first_missing_signal = part.first_missing_signal;
                    }
                    *ok = false;
                    halted.insert(module_id.clone());
                    if *first_missing_signal == "none" {
                        *first_missing_signal = state
                            .first_missing_signal
                            .clone()
                            .unwrap_or_else(|| format!("module-failed-{module_id}"));
                    }
                }
                *operation_count += part.operation_count;
                event(
                    events,
                    "module-band",
                    part.ok,
                    &format!(
                        "{} band={:?} steps={}",
                        module_id, band, part.operation_count
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

pub(crate) fn run_profile_engine(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
) -> Result<(), String> {
    run_profile_engine_with_preflight(profile, module_root, receipt_dir, mode, false, None, None)
}

pub(crate) fn run_profile_engine_with_preflight(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
    skip_preflight: bool,
    completed_preflight: Option<ModuleExecution>,
    suite_debt: Option<&str>,
) -> Result<(), String> {
    let policy = read_device_module_policy()?;
    let projection = load_profile_projection(profile, module_root, &policy.disabled_modules)?;
    run_profile_engine_with_projection(
        profile,
        module_root,
        receipt_dir,
        mode,
        skip_preflight,
        completed_preflight,
        suite_debt,
        &projection,
        None,
        None,
        false,
    )
}

pub(crate) fn run_profile_engine_with_projection(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
    skip_preflight: bool,
    mut completed_preflight: Option<ModuleExecution>,
    suite_debt: Option<&str>,
    projection: &ProfileProjection,
    context: Option<&crate::RunContext>,
    carrier: Option<&crate::atoms::r#do::transaction::RunCarrierRef>,
    materialize_on_stage: bool,
) -> Result<(), String> {
    let mut active_profile = profile.clone();
    let mut active_projection = projection.clone();
    let apply = mode.is_software_apply();
    let invocation = mode.invocation();
    let run_started = Instant::now();
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let mut events = File::create(receipt_dir.join("events.jsonl")).map_err(|e| e.to_string())?;
    event(
        &mut events,
        "engine-start",
        true,
        &format!("profile {}", active_profile.id),
    )?;
    let run_id = run_id_from_stamp();
    let mut ok = true;
    let mut suite_ok = true;
    let mut changed = false;
    let mut first_missing_signal = "none".to_string();
    let mut module_count = active_profile.modules.len();
    let mut operation_count = 0usize;
    let mut module_states: BTreeMap<String, ModuleExecution> = BTreeMap::new();
    let mut halted_modules: BTreeSet<String> = BTreeSet::new();
    let mut routine_states: BTreeMap<String, BTreeMap<String, crate::ModuleWalkState>> =
        BTreeMap::new();
    let mut visited_bands = Vec::new();
    let device_module_policy = read_device_module_policy()?;
    let harmonia_root = harmonia_root_from_module_root(module_root);

    let mut group_losers = BTreeMap::new();
    let mut final_result = None;
    crate::bands::walk(|band| {
        visited_bands.push(format!("{:?}", band));
        match band {
            crate::bands::Band::RenewSelf => {
                run_profile_hotfixes(profile, receipt_dir, invocation);

                if let Some(suite_debt) = suite_debt {
                    ok = false;
                    suite_ok = false;
                    first_missing_signal = suite_debt.to_string();
                    event(&mut events, "profile-suite-spine-debt", false, suite_debt)?;
                }

                if skip_preflight {
                    event(
                        &mut events,
                        "engine-preflight-skipped",
                        true,
                        "already completed by update suite",
                    )?;
                    if let Some(preflight) = completed_preflight.take() {
                        operation_count += preflight.operation_count;
                        if preflight.changed {
                            changed = true;
                        }
                        if !preflight.ok {
                            let preflight_signal = preflight
                                .first_missing_signal
                                .unwrap_or_else(|| "harmonia-engine-preflight-failed".to_string());
                            event(
                                &mut events,
                                "engine-preflight-honest-staleness",
                                false,
                                &preflight_signal,
                            )?;
                            ok = false;
                            if first_missing_signal == "none" {
                                first_missing_signal = preflight_signal;
                            }
                        }
                    }
                } else {
                    // Engine-plane self-update is automatic in every profile run. It has its
                    // own receipt and never derives from, nor widens, module hard consent.
                    let preflight =
                        run_engine_preflight(module_root, receipt_dir, apply, invocation)?;
                    operation_count += preflight.operation_count;
                    if preflight.changed {
                        changed = true;
                    }
                    if !preflight.ok {
                        let preflight_signal = preflight
                            .first_missing_signal
                            .unwrap_or_else(|| "harmonia-engine-preflight-failed".to_string());
                        event(
                            &mut events,
                            "engine-preflight-honest-staleness",
                            false,
                            &preflight_signal,
                        )?;
                        if apply {
                            ok = false;
                            first_missing_signal = preflight_signal;
                        }
                    }
                }

                if active_profile.modules.is_empty() {
                    ok = false;
                    first_missing_signal = "profile-modules-empty".to_string();
                    event(
                        &mut events,
                        "profile-modules",
                        false,
                        "profile module spine is empty",
                    )?;
                }
            }
            crate::bands::Band::PullSource => {
                // Primitive rolling-update acquisition already ran; routine children still visit this band.
                execute_band_modules(
                    band,
                    &active_profile,
                    module_root,
                    receipt_dir,
                    mode,
                    &device_module_policy.disabled_modules,
                    &active_projection,
                    &mut module_states,
                    &mut routine_states,
                    &mut halted_modules,
                    &mut module_count,
                    &mut operation_count,
                    &mut changed,
                    &mut ok,
                    &mut first_missing_signal,
                    &mut events,
                )?;
            }
            crate::bands::Band::StageProfile => {
                if apply && materialize_on_stage {
                    let engine = load_engine_plane_config(&engine_config_path())?
                        .ok_or_else(|| "engine-self-possession-unconfigured".to_string())?;
                    let refreshed = crate::bands::stage_profile::materialize(
                        &engine.source_dir,
                        &active_profile.id,
                        module_root,
                        receipt_dir,
                        &engine.git_bearer,
                        context,
                        carrier,
                    )?;
                    active_profile = refreshed;
                    let target_carrier = carrier.or_else(|| context.map(|value| &value.carrier));
                    let Some(target_carrier) = target_carrier else {
                        return Err("stage-profile-transaction-carrier-missing".to_string());
                    };
                    let value = target_carrier.borrow();
                    active_profile = value
                        .refreshed_profile_value
                        .clone()
                        .unwrap_or(active_profile.clone());
                    active_projection = value
                        .projection
                        .clone()
                        .ok_or_else(|| "stage-profile-projection-not-sealed".to_string())?;
                }
            }
            crate::bands::Band::Compare => {
                if let Some(target_carrier) =
                    carrier.or_else(|| context.map(|value| &value.carrier))
                {
                    let value = target_carrier.borrow();
                    if let Some(refreshed) = value.refreshed_profile_value.as_ref() {
                        active_profile = refreshed.clone();
                    }
                    if let Some(refreshed) = value.projection.as_ref() {
                        active_projection = refreshed.clone();
                    }
                }
                let group_selections = resolve_group_selections(
                    &active_profile,
                    module_root,
                    receipt_dir,
                    &active_projection,
                )?;
                group_losers = group_loser_winners(&group_selections);
                execute_band_modules(
                    band,
                    &active_profile,
                    module_root,
                    receipt_dir,
                    mode,
                    &device_module_policy.disabled_modules,
                    &active_projection,
                    &mut module_states,
                    &mut routine_states,
                    &mut halted_modules,
                    &mut module_count,
                    &mut operation_count,
                    &mut changed,
                    &mut ok,
                    &mut first_missing_signal,
                    &mut events,
                )?;
            }
            crate::bands::Band::InstallPackages => {
                crate::bands::install_packages::execute_manifest_modules(
                    &active_profile,
                    receipt_dir,
                    mode,
                    &device_module_policy.disabled_modules,
                    &active_projection,
                    &mut module_states,
                    &mut routine_states,
                    &mut halted_modules,
                    &mut module_count,
                    &mut operation_count,
                    &mut changed,
                    &mut ok,
                    &mut first_missing_signal,
                    &mut events,
                )?;
            }
            crate::bands::Band::RatchetBinaries
            | crate::bands::Band::RestartServices
            | crate::bands::Band::BackfillFiles
            | crate::bands::Band::ProposeEdits => {
                execute_band_modules(
                    band,
                    &active_profile,
                    module_root,
                    receipt_dir,
                    mode,
                    &device_module_policy.disabled_modules,
                    &active_projection,
                    &mut module_states,
                    &mut routine_states,
                    &mut halted_modules,
                    &mut module_count,
                    &mut operation_count,
                    &mut changed,
                    &mut ok,
                    &mut first_missing_signal,
                    &mut events,
                )?;
            }
            crate::bands::Band::ReportHome => {
                for module_id in &active_profile.modules {
                    if let Some(state) = module_states.get(module_id) {
                        let signal = state.first_missing_signal.as_deref().unwrap_or("none");
                        let module = active_projection.modules.get(module_id).map(|p| &p.loaded);
                        append_profile_ledger_entry(
                            receipt_dir,
                            &active_profile,
                            ProfileLedgerEntry {
                                run_id: &run_id,
                                module_id,
                                ok: state.ok,
                                changed: state.changed,
                                operation_count: state.operation_count,
                                first_missing_signal: signal,
                                receipt_dir,
                                module_version: module.as_ref().and_then(|loaded| loaded.version()),
                            },
                        )?;
                    }
                }
                write_json(
                    &receipt_dir.join("band-walk.receipt.json"),
                    &json!({
                        "schema": "harmonia.band-walk.receipt.v1",
                        "bands": visited_bands,
                        "module_steps": module_states.iter().map(|(id, state)| json!({
                            "module_id": id, "operation_count": state.operation_count,
                            "ok": state.ok, "changed": state.changed,
                            "first_missing_signal": state.first_missing_signal,
                            "steps": state.placements,
                        })).collect::<Vec<_>>(),
                    }),
                )?;
                write_engine_run_receipt_with_duration(
                    receipt_dir,
                    &active_profile,
                    apply,
                    ok,
                    changed,
                    module_count,
                    operation_count,
                    &first_missing_signal,
                    module_root,
                    suite_ok,
                    run_started.elapsed().as_millis(),
                )?;
                println!("schema=harmonia.run_profile.v1");
                hyalos::forward_receipt(
                    "schema=harmonia.run_profile.v1",
                    &format!("schema=harmonia.run_profile.v1 ok={}", ok),
                    Some(serde_json::json!({"schema": "harmonia.run_profile.v1", "ok": ok})),
                    Some(ok),
                );
                println!("ok={}", ok);
                println!("changed={}", changed);
                println!("profile_id={}", active_profile.id);
                println!("module_count={}", module_count);
                println!("operation_count={}", operation_count);
                println!("first_missing_signal={}", first_missing_signal);
                println!("receipt_dir={}", receipt_dir.display());
                // A report-only sweep is a census, not a systemd failure: its written
                // aggregate receipt carries all drift/blocker/failure truth. Hard runs
                // return failure only after that receipt has been emitted.
                final_result = Some(if ok || !apply {
                    Ok(())
                } else {
                    Err(first_missing_signal.clone())
                });
            }
        }
        Ok(())
    })?;
    final_result.unwrap_or_else(|| Err("band-walk-report-home-missing".to_string()))
}

const DEFAULT_HARMONIA_SOURCE_REPO: &str = "https://github.com/homeserversltd/harmonia.git";
const DEFAULT_HARMONIA_INSTALL_BIN: &str = "/usr/local/bin/harmonia";

pub(crate) fn ensure_engine_config_for_rolling() -> Result<(), String> {
    let engine_path = engine_config_path();
    if engine_path.exists() {
        return Ok(());
    }
    let ratchet_lock = engine_path
        .parent()
        .map(|parent| parent.join("engine-ratchet-lock.json"))
        .unwrap_or_else(|| PathBuf::from("/etc/harmonia/engine-ratchet-lock.json"));
    write_json_value_atomic(
        &engine_path,
        &json!({
            "source_repo_url": DEFAULT_HARMONIA_SOURCE_REPO,
            "branch": "main",
            "source_dir": SOURCE_ROOT,
            "install_bin": DEFAULT_HARMONIA_INSTALL_BIN,
            "enabled": true,
            "ratchet_lock": ratchet_lock,
        }),
    )
}

pub(crate) fn normalize_engine_branch_upstream() -> Result<(), String> {
    if preserve_existing_lane_or_default(&subscription_path()) != "upstream" {
        return Ok(());
    }
    let engine_path = engine_config_path();
    if !engine_path.exists() {
        return Ok(());
    }
    let text = fs::read_to_string(&engine_path)
        .map_err(|e| format!("engine-config-read-failed {}: {e}", engine_path.display()))?;
    let mut engine: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("engine-config-parse-failed {}: {e}", engine_path.display()))?;
    let object = engine.as_object_mut().ok_or_else(|| {
        format!(
            "engine-config-parse-failed {}: root-not-object",
            engine_path.display()
        )
    })?;
    if object.get("branch").and_then(serde_json::Value::as_str) != Some("main") {
        object.insert("branch".to_string(), json!("main"));
        write_json_value_atomic(&engine_path, &engine)?;
    }
    Ok(())
}

fn rolling_update_run(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
    context: Option<&crate::RunContext>,
    suite_debt: Option<String>,
    lock_path: PathBuf,
    materialize_receipt: fn(&Path, &str) -> Result<PathBuf, String>,
    try_acquire_lock: fn(&Path) -> Result<ConvergenceLockGuard, ConvergenceLockBusy>,
) -> Result<(), String> {
    let apply = mode.is_software_apply();
    let run_id = run_id_from_stamp();
    let effective_receipt_dir = materialize_receipt(receipt_dir, &run_id)?;
    fs::create_dir_all(&effective_receipt_dir).map_err(|e| e.to_string())?;
    let run = || {
        let carrier = context
            .map(|value| value.carrier.clone())
            .unwrap_or_else(|| {
                std::rc::Rc::new(std::cell::RefCell::new(
                    crate::atoms::r#do::transaction::RunCarrier::default(),
                ))
            });
        let projection = load_profile_projection(profile, module_root, &BTreeSet::new())?;
        let execution_projection = projection.clone();
        let preflight = run_engine_preflight(
            module_root,
            &effective_receipt_dir,
            apply,
            mode.invocation(),
        )?;
        if !apply {
            return run_profile_engine_with_projection(
                profile,
                module_root,
                &effective_receipt_dir,
                mode,
                true,
                Some(preflight),
                suite_debt.as_deref(),
                &execution_projection,
                context,
                Some(&carrier),
                false,
            );
        }
        let transaction = run_profile_engine_with_projection(
            profile,
                module_root,
                &effective_receipt_dir,
                mode,
                true,
                Some(preflight),
                suite_debt.as_deref(),
                &execution_projection,
            context,
            Some(&carrier),
            true,
        );
        let value = carrier.borrow();
        let census = value.transaction_census.clone();
        let saved = value.sealed_snapshot.clone();
        let service_states = value.sealed_services.clone();
        drop(value);
        if let Err(error) = transaction {
            let Some(saved) = saved else {
                return Err(error);
            };
            let Some(service_states) = service_states else {
                return Err(error);
            };
            let Some(census) = census else {
                return Err(error);
            };
            let artifact_rollback = crate::update_set::restore(&saved);
            let service_rollback = crate::update_set::restore_services(&service_states);
            let rollback_ok = artifact_rollback.is_ok() && service_rollback.is_ok();
            let verdict = if rollback_ok {
                "failed-rolled-back"
            } else {
                "failed-rollback-incomplete"
            };
            crate::update_set::update_set_receipt(
                &effective_receipt_dir,
                &census.gui_face,
                verdict,
                Some(&census.gui_member),
                Some(&error),
            )?;
            return Err(error);
        }
        let census =
            census.ok_or_else(|| "stage-profile-transaction-census-missing".to_string())?;
        crate::update_set::update_set_receipt(
            &effective_receipt_dir,
            &census.gui_face,
            "ok",
            None,
            None,
        )?;
        Ok(())
    };
    if apply {
        match try_acquire_lock(&lock_path) {
            Ok(_guard) => run(),
            Err(ConvergenceLockBusy) => {
                write_convergence_skipped_receipt(
                    &effective_receipt_dir,
                    profile,
                    apply,
                    "lock-held",
                    &lock_path,
                    receipt_dir,
                )?;
                emit_convergence_skipped_stdout(&effective_receipt_dir, "lock-held", &profile.id);
                Ok(())
            }
        }
    } else {
        run()
    }
}

pub(crate) fn rolling_update_from_certificate(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
) -> Result<(), String> {
    rolling_update_from_certificate_with_context(profile, module_root, receipt_dir, mode, None)
}

pub(crate) fn rolling_update_from_certificate_with_context(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
    context: Option<crate::RunContext>,
) -> Result<(), String> {
    rolling_update_run(
        profile,
        module_root,
        receipt_dir,
        mode,
        context.as_ref(),
        enforce_update_suite(profile, module_root)?,
        engine_run_lock_path(),
        materialize_tv_receipt_dir,
        try_acquire_homeconsole_update_lock,
    )
}

pub(crate) fn homeconsole_update(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.identity != "homeconsole" {
        return Err(format!(
            "homeconsole-update requires homeconsole/homeconsole profile, got {}/{}",
            profile.id, profile.identity
        ));
    }
    let suite_debt = enforce_update_suite(profile, module_root)?;
    rolling_update_run(
        profile,
        module_root,
        receipt_dir,
        mode,
        None,
        suite_debt,
        homeconsole_update_lock_path(),
        materialize_homeconsole_receipt_dir,
        try_acquire_homeconsole_update_lock,
    )
}

pub(crate) fn homeconsole_module_root() -> std::path::PathBuf {
    Path::new("profiles/homeconsole/modules").to_path_buf()
}

pub(crate) fn lawful_module_manifest_exists(module_dir: &Path) -> bool {
    (module_dir.join("index.rs").exists() && module_dir.join("sidecar.json").exists())
        || module_dir.join("manifest.json").exists()
}

pub(crate) fn enforce_update_suite(
    profile: &Profile,
    module_root: &Path,
) -> Result<Option<String>, String> {
    Ok(profile.modules.iter().find_map(|module_id| {
        (!lawful_module_manifest_exists(&module_root.join(module_id))).then(|| {
            format!(
                "profile-module-manifest-missing module_root={} module_id={module_id}",
                module_root.display(),
            )
        })
    }))
}

pub(crate) fn homeserver_update(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
) -> Result<(), String> {
    if profile.id != "homeserver" || profile.identity != "homeserver" {
        return Err(format!(
            "homeserver-update requires homeserver/homeserver profile, got {}/{}",
            profile.id, profile.identity
        ));
    }
    let suite_debt = enforce_update_suite(profile, module_root)?;
    rolling_update_run(
        profile,
        module_root,
        receipt_dir,
        mode,
        None,
        suite_debt,
        homeserver_update_lock_path(),
        materialize_homeserver_receipt_dir,
        try_acquire_homeserver_update_lock,
    )
}

pub(crate) fn tv_update(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
) -> Result<(), String> {
    if profile.id != "tv" || profile.identity != "arch-tv" {
        return Err(format!(
            "tv-update requires tv/arch-tv profile, got {}/{}",
            profile.id, profile.identity
        ));
    }
    let suite_debt = enforce_update_suite(profile, module_root)?;
    rolling_update_run(
        profile,
        module_root,
        receipt_dir,
        mode,
        None,
        suite_debt,
        tv_update_lock_path(),
        materialize_tv_receipt_dir,
        try_acquire_tv_update_lock,
    )
}

pub(crate) fn profile_update(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: UpdateMode,
) -> Result<(), String> {
    let suite_debt = enforce_update_suite(profile, module_root)?;
    let profile_id = profile.id.clone();
    rolling_update_run(
        profile,
        module_root,
        receipt_dir,
        mode,
        None,
        suite_debt,
        profile_update_lock_path(&profile_id)?,
        materialize_profile_receipt_dir,
        try_acquire_homeconsole_update_lock,
    )
}

pub(crate) fn normalize_homeserver_engine_branch() -> Result<(), String> {
    normalize_engine_branch_upstream()
}

pub(crate) fn sync_homeserver_profile(
    source_root: &Path,
    installed_module_root: &Path,
    receipt_dir: &Path,
) -> Result<(), String> {
    sync_homeserver_profile_as_bearer(source_root, installed_module_root, receipt_dir, "owner")
}

fn sync_homeserver_profile_as_bearer(
    source_root: &Path,
    installed_module_root: &Path,
    receipt_dir: &Path,
    git_bearer: &str,
) -> Result<(), String> {
    crate::bands::stage_profile::materialize(
        source_root,
        "homeserver",
        installed_module_root,
        receipt_dir,
        git_bearer,
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn sync_homeconsole_profile(
    source_root: &Path,
    installed_module_root: &Path,
    receipt_dir: &Path,
) -> Result<(), String> {
    sync_homeconsole_profile_as_bearer(source_root, installed_module_root, receipt_dir, "owner")
}

fn sync_homeconsole_profile_as_bearer(
    source_root: &Path,
    installed_module_root: &Path,
    receipt_dir: &Path,
    git_bearer: &str,
) -> Result<(), String> {
    crate::bands::stage_profile::materialize(
        source_root,
        "homeconsole",
        installed_module_root,
        receipt_dir,
        git_bearer,
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn sync_tv_profile(
    source_root: &Path,
    installed_module_root: &Path,
    receipt_dir: &Path,
) -> Result<(), String> {
    sync_tv_profile_as_bearer(source_root, installed_module_root, receipt_dir, "owner")
}

fn sync_tv_profile_as_bearer(
    source_root: &Path,
    installed_module_root: &Path,
    receipt_dir: &Path,
    git_bearer: &str,
) -> Result<(), String> {
    crate::bands::stage_profile::materialize(
        source_root,
        "tv",
        installed_module_root,
        receipt_dir,
        git_bearer,
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn homeserver_module_root() -> PathBuf {
    Path::new("profiles/homeserver/modules").to_path_buf()
}

pub(crate) fn tv_module_root() -> PathBuf {
    Path::new("profiles/tv/modules").to_path_buf()
}

pub(crate) fn command_capture(program: &str, args: &[&str]) -> CmdResult {
    tools::command::capture(program, args)
}

#[allow(dead_code)]
pub(crate) fn command_capture_with_timeout(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
) -> CmdResult {
    tools::command::capture_with_timeout(program, args, timeout_secs)
}

pub(crate) fn command_capture_with_cwd(
    program: &str,
    args: &[&str],
    cwd: Option<&str>,
) -> CmdResult {
    tools::command::capture_with_cwd(program, args, cwd)
}

pub(crate) fn harmonia_root_from_module_root(module_root: &Path) -> PathBuf {
    module_root
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod profile_authority_tests {
    use super::*;

    #[test]
    fn homeserver_caduceus_runtime_composes_firewall_commands_exactly_once() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile = load_profile(&root.join("profiles/homeserver/index.json")).unwrap();
        let module_root = root.join("profiles/homeserver/modules");
        let existing = caduceus_commands_for_profile(&profile, &module_root).unwrap();
        let mut caduceus =
            load_ladder_manifest(&module_root.join("caduceus/manifest.json")).unwrap();

        compose_caduceus_commands(&profile, &module_root, &mut caduceus).unwrap();

        let runtime = caduceus
            .ladder
            .iter()
            .find(|step| step.tool == "service-runtime" && step.permutation == "converge")
            .expect("homeserver caduceus service-runtime step");
        let commands = runtime.args["caduceus_commands"]
            .as_array()
            .expect("composed caduceus commands array");
        for command in [
            "caduceus.network.firewall.read",
            "caduceus.network.firewall.put",
            "caduceus.network.firewall.delete",
        ] {
            assert_eq!(
                commands
                    .iter()
                    .filter(|value| value.as_str() == Some(command))
                    .count(),
                1,
                "{command} must appear exactly once in service-runtime args"
            );
        }
        for command in existing {
            assert_eq!(
                commands
                    .iter()
                    .filter(|value| value.as_str() == Some(command.as_str()))
                    .count(),
                1,
                "existing composed command {command} must remain exactly once"
            );
        }
    }

    #[test]
    fn module_root_yields_absolute_installed_harmonia_root() {
        assert_eq!(
            harmonia_root_from_module_root(Path::new("/etc/harmonia/profiles/tv/modules")),
            PathBuf::from("/etc/harmonia")
        );
    }

    #[test]
    fn module_root_yields_relative_repo_harmonia_root() {
        assert_eq!(
            harmonia_root_from_module_root(Path::new("profiles/tv/modules")),
            PathBuf::from("")
        );
    }

    #[test]
    fn command_timeout_kills_sleeping_child() {
        let result = command_capture_with_timeout("/usr/bin/sh", &["-c", "sleep 2"], 1);
        assert!(!result.ok);
        assert!(
            result.stderr.contains("command-timeout-after-1s"),
            "{}",
            result.stderr
        );
        assert!(
            result.stderr.contains("/usr/bin/sh -c sleep 2"),
            "{}",
            result.stderr
        );
    }
}
