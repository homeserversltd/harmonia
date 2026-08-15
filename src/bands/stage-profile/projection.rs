use crate::atoms::r#do::transaction::{ServiceBinding, Target, UpdatePlan};
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
    pub(crate) steps: Vec<crate::tools::routine::ValidatedStep>,
    pub(crate) group_probe: Option<crate::tools::routine::ValidatedStep>,
    pub(crate) routines: BTreeMap<String, Vec<crate::tools::routine::ProjectedRoutineChild>>,
}

#[derive(Clone, Debug)]
pub(crate) struct ProfileProjection {
    pub(crate) modules: BTreeMap<String, ProjectedModule>,
    pub(crate) errors: BTreeMap<String, String>,
}

impl ProfileProjection {
    pub(crate) fn derive_update_plan(
        &self,
        profile: &Profile,
        module_root: &Path,
    ) -> Result<UpdatePlan, String> {
        projection_derive_plan_inner(self, profile, module_root)
    }
}

pub(crate) fn load_profile_projection(
    profile: &Profile,
    module_root: &Path,
    disabled: &BTreeSet<String>,
) -> Result<ProfileProjection, String> {
    let mut modules = BTreeMap::new();
    let mut errors = BTreeMap::new();
    for id in &profile.modules {
        if disabled.contains(id) {
            continue;
        }
        let loaded = match crate::bands::stage_profile::groups::load_profile_module(module_root, id) {
            Ok(v) => v,
            Err(e) => {
                errors.insert(id.clone(), e);
                continue;
            }
        };
        let (steps, group_probe, routines) = match &loaded {
            LoadedModule::Ladder(m) => {
                let steps = match crate::ladder::validate_ladder(m) {
                    Ok(steps) => steps,
                    Err(e) => {
                        errors.insert(
                            id.clone(),
                            format!("module-invalid {}", e.first_missing_signal()),
                        );
                        continue;
                    }
                };
                let group_probe = match m
                    .group
                    .as_ref()
                    .map(|g| crate::ladder::validate_group(g, &m.constants))
                    .transpose()
                {
                    Ok(probe) => probe,
                    Err(e) => {
                        errors.insert(
                            id.clone(),
                            format!("module-invalid {}", e.first_missing_signal()),
                        );
                        continue;
                    }
                };
                let mut routines = BTreeMap::new();
                let mut routine_error = None;
                for step in m.ladder.iter().filter(|step| step.tool == "routine") {
                    match crate::tools::routine::project_routine_children(step, &m.constants) {
                        Ok(children) => {
                            routines.insert(step.step_id.clone(), children);
                        }
                        Err(e) => {
                            routine_error =
                                Some(format!("module-invalid {}", e.first_missing_signal()));
                            break;
                        }
                    }
                }
                if let Some(error) = routine_error {
                    errors.insert(id.clone(), error);
                    continue;
                }
                (steps, group_probe, routines)
            }
            LoadedModule::Sidecar(_) => (Vec::new(), None, BTreeMap::new()),
        };
        modules.insert(
            id.clone(),
            ProjectedModule {
                loaded,
                steps,
                group_probe,
                routines,
            },
        );
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
    match crate::tools::files::classify_target(&path) {
        crate::tools::files::TargetClass::Software => {}
        crate::tools::files::TargetClass::Config => {
            return Err(format!(
                "configuration-actuator-authority-refused {}",
                path.display()
            ))
        }
        crate::tools::files::TargetClass::Refused(reason) => return Err(reason),
    }
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
                        if matches!(
                            crate::tools::files::classify_target(&p),
                            crate::tools::files::TargetClass::Config
                        ) {
                            println!("census-config-skip path={}", p.display());
                            continue;
                        }
                        projection_add_target(&mut targets, p, member)?;
                    }
                }
            }
            if let Some(p) = args
                .get("caduceus_profile_source")
                .and_then(|x| projection_value_path(x, "path"))
            {
                if matches!(
                    crate::tools::files::classify_target(&p),
                    crate::tools::files::TargetClass::Config
                ) {
                    println!("census-config-skip path={}", p.display());
                } else {
                    projection_add_target(&mut targets, p, member)?;
                }
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
                        let p = PathBuf::from(&r).join(f);
                        if matches!(
                            crate::tools::files::classify_target(&p),
                            crate::tools::files::TargetClass::Config
                        ) {
                            println!("census-config-skip path={}", p.display());
                            continue;
                        }
                        projection_add_target(&mut targets, p, &face)?;
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
                    if matches!(
                        crate::tools::files::classify_target(&p),
                        crate::tools::files::TargetClass::Config
                    ) {
                        println!("census-config-skip path={}", p.display());
                        continue;
                    }
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
    let mut out = Vec::new();
    if let LoadedModule::Ladder(manifest) = &projected.loaded {
        out.extend(
            manifest
                .ladder
                .iter()
                .filter_map(crate::ladder::service_runtime_converge_args),
        );
    }
    for children in projected.routines.values() {
        out.extend(
            children
                .iter()
                .filter(|c| {
                    c.args.contains_key("component")
                        && c.args.contains_key("op_prefix")
                        && c.args.contains_key("install_bin")
                        && matches!(
                            c.tool.as_str(),
                            "pull-repo"
                                | "build-crate"
                                | "place-file"
                                | "service-runtime"
                                | "enable-unit"
                                | "systemd"
                                | "check-health"
                        )
                })
                .map(|c| &c.args),
        );
    }
    let mut seen = BTreeSet::new();
    out.retain(|args| {
        args.get("component")
            .and_then(Value::as_str)
            .is_some_and(|component| seen.insert(component.to_string()))
    });
    out
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
