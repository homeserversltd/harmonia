use crate::{
    ladder::{validate_ladder, LadderManifest},
    tools::systemd::ServiceStateSnapshot,
    Profile,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct Target {
    pub path: PathBuf,
    pub member: String,
}
#[derive(Clone, Debug)]
pub struct ServiceBinding {
    pub name: String,
    pub user: bool,
    pub target_user: Option<String>,
}
#[derive(Clone, Debug)]
pub struct UpdatePlan {
    pub targets: Vec<Target>,
    pub services: Vec<ServiceBinding>,
    pub gui_face: String,
    pub gui_member: String,
}
#[derive(Clone, Debug)]
enum Kind {
    Missing,
    File(Vec<u8>),
    Symlink(PathBuf),
    Dir,
}
#[derive(Clone, Debug)]
struct Node {
    path: PathBuf,
    kind: Kind,
    mode: u32,
    uid: u32,
    gid: u32,
}
#[derive(Clone, Debug)]
pub(crate) struct Snapshot {
    roots: Vec<PathBuf>,
    nodes: Vec<Node>,
}

fn module(root: &Path, id: &str) -> Result<LadderManifest, String> {
    crate::ladder::load_ladder_manifest(&root.join(id).join("manifest.json"))
}
fn text(v: &BTreeMap<String, Value>, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_owned)
}
fn value_path(v: &Value, k: &str) -> Option<PathBuf> {
    v.get(k).and_then(Value::as_str).map(PathBuf::from)
}
fn safe_target(path: &Path) -> Result<(), String> {
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
fn add_target(out: &mut Vec<Target>, path: PathBuf, member: &str) -> Result<(), String> {
    safe_target(&path)?;
    out.push(Target {
        path,
        member: member.into(),
    });
    Ok(())
}
fn add_service(
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
fn component_face(component: &str) -> Option<&'static str> {
    match component {
        "arcadia" => Some("Arcadia"),
        "coronatio" => Some("Coronatio"),
        _ => None,
    }
}
fn resolved_steps(m: &LadderManifest) -> Result<Vec<crate::ladder::ValidatedStep>, String> {
    validate_ladder(m).map_err(|e| format!("module-invalid {}", e.first_missing_signal()))
}
fn gui_module(m: &LadderManifest, face: &str) -> bool {
    if face != "Hyprland" {
        return resolved_steps(m).ok().is_some_and(|steps| {
            steps.iter().any(|s| {
                s.tool == "service-runtime"
                    && s.args
                        .get("component")
                        .and_then(Value::as_str)
                        .and_then(component_face)
                        == Some(face)
            })
        });
    }
    let mut hay = m.id.to_ascii_lowercase();
    if let Some(x) = m.constants.get("meaning").and_then(Value::as_str) {
        hay.push_str(&x.to_ascii_lowercase());
    }
    hay.contains("hyprland") || hay.contains("desktop config") || hay.contains("user session")
}
fn derive_plan_inner(profile: &Profile, root: &Path) -> Result<UpdatePlan, String> {
    let manifests = profile
        .modules
        .iter()
        .map(|id| Ok((id.clone(), module(root, id)?)))
        .collect::<Result<Vec<_>, String>>()?;
    let runtime_faces: Vec<String> = manifests
        .iter()
        .flat_map(|(_, m)| m.ladder.iter())
        .filter(|s| s.tool == "service-runtime")
        .filter_map(|s| {
            s.args
                .get("component")
                .and_then(Value::as_str)
                .and_then(component_face)
                .map(str::to_owned)
        })
        .collect();
    let faces: BTreeSet<String> = runtime_faces.into_iter().collect();
    let face = if faces.len() == 1 {
        faces.iter().next().unwrap().clone()
    } else if faces.is_empty()
        && manifests
            .iter()
            .any(|(_, m)| m.id.to_ascii_lowercase().contains("hyprland"))
    {
        "Hyprland".into()
    } else {
        return Err(format!("gui-selection-ambiguous count={}", faces.len()));
    };
    let mut targets = Vec::new();
    let mut services = Vec::new();
    let mut caduceus_count = 0;
    for (_, m) in &manifests {
        let steps = resolved_steps(m)?;
        let is_gui = gui_module(m, &face);
        for s in &steps {
            if s.tool == "service-runtime" && s.permutation == "converge" {
                let component = s
                    .args
                    .get("component")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let member = if component == "caduceus" {
                    caduceus_count += 1;
                    "caduceus"
                } else if component_face(component) == Some(face.as_str()) {
                    face.as_str()
                } else {
                    continue;
                };
                if let Some(p) = text(&s.args, "install_bin") {
                    add_target(&mut targets, p.into(), member)?;
                }
                if let Some(a) = s.args.get("managed_files").and_then(Value::as_array) {
                    for x in a {
                        if let Some(p) = value_path(x, "path") {
                            add_target(&mut targets, p, member)?;
                        }
                    }
                }
                if let Some(p) = s
                    .args
                    .get("caduceus_profile_source")
                    .and_then(|x| value_path(x, "path"))
                {
                    add_target(&mut targets, p, member)?;
                }
                if let Some(name) = text(&s.args, "service") {
                    add_service(&mut services, name, false, None, member);
                }
            }
            if s.tool == "files"
                && s.permutation == "source-shelf-sweep"
                && steps.iter().any(|x| {
                    x.tool == "service-runtime"
                        && x.args.get("component").and_then(Value::as_str) == Some("caduceus")
                })
            {
                if let Some(p) = text(&s.args, "target_shelf") {
                    add_target(&mut targets, p.into(), "caduceus_staff")?;
                }
                let tr = text(&s.args, "launcher_target_root")
                    .map(PathBuf::from)
                    .ok_or("staff-target-root-missing")?;
                let sr = text(&s.args, "launcher_source_root")
                    .map(PathBuf::from)
                    .ok_or("staff-source-root-missing")?;
                let pat = text(&s.args, "launcher_pattern").ok_or("staff-pattern-missing")?;
                let mut names = BTreeSet::new();
                for r in [&tr, &sr] {
                    if r.is_dir() {
                        for e in fs::read_dir(r).map_err(|e| e.to_string())? {
                            let p = e.map_err(|e| e.to_string())?.path();
                            if p.file_name()
                                .and_then(|n| n.to_str())
                                .is_some_and(|n| glob(&pat, n))
                            {
                                names.insert(p.file_name().unwrap().to_os_string());
                            }
                        }
                    }
                }
                for n in names {
                    add_target(&mut targets, tr.join(n), "caduceus_staff")?;
                }
            }
            if is_gui && s.tool == "files" && s.permutation == "converge" {
                if let (Some(r), Some(files)) = (
                    text(&s.args, "target_root"),
                    s.args.get("files").and_then(Value::as_array),
                ) {
                    for f in files.iter().filter_map(Value::as_str) {
                        add_target(&mut targets, PathBuf::from(&r).join(f), &face)?;
                    }
                }
            }
            if is_gui && s.tool == "systemd" {
                let user = s.permutation.starts_with("user-");
                let target_user = text(&s.args, "user");
                if let Some(name) = text(&s.args, "service") {
                    add_service(&mut services, name, user, target_user, &face);
                }
            }
        }
        if is_gui {
            let target_root = m
                .constants
                .get("target_dir")
                .and_then(Value::as_str)
                .map(PathBuf::from);
            if let Some(a) = m.constants.get("expected_files").and_then(Value::as_array) {
                for f in a.iter().filter_map(Value::as_str) {
                    let p = PathBuf::from(f);
                    let p = if p.is_absolute() {
                        p
                    } else if let Some(r) = &target_root {
                        r.join(p)
                    } else {
                        continue;
                    };
                    add_target(&mut targets, p, &face)?;
                }
            }
            for (key, user) in [("services", false), ("user_services", true)] {
                if let Some(a) = m.constants.get(key).and_then(Value::as_array) {
                    for name in a.iter().filter_map(Value::as_str) {
                        add_service(
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
    })
}
fn glob(pattern: &str, name: &str) -> bool {
    if let Some((a, b)) = pattern.split_once('*') {
        name.starts_with(a) && name.ends_with(b)
    } else {
        pattern == name
    }
}
pub fn derive_plan(
    profile: &Profile,
    module_root: &Path,
    projection_root: Option<&Path>,
) -> Result<UpdatePlan, String> {
    let mut p = derive_plan_inner(profile, module_root)?;
    if let Some(scratch) = projection_root {
        for t in &mut p.targets {
            let rel = t
                .path
                .strip_prefix("/")
                .map_err(|_| "projection-target-not-absolute")?;
            t.path = scratch.join(rel);
        }
        p.services.clear();
    }
    Ok(p)
}

fn capture(p: &Path, n: &mut Vec<Node>) -> Result<(), String> {
    let m = match fs::symlink_metadata(p) {
        Ok(x) => x,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            n.push(Node {
                path: p.into(),
                kind: Kind::Missing,
                mode: 0,
                uid: 0,
                gid: 0,
            });
            return Ok(());
        }
        Err(e) => return Err(e.to_string()),
    };
    let kind = if m.file_type().is_symlink() {
        Kind::Symlink(fs::read_link(p).map_err(|e| e.to_string())?)
    } else if m.is_dir() {
        Kind::Dir
    } else {
        Kind::File(fs::read(p).map_err(|e| e.to_string())?)
    };
    let dir = matches!(kind, Kind::Dir);
    n.push(Node {
        path: p.into(),
        kind,
        mode: m.mode(),
        uid: m.uid(),
        gid: m.gid(),
    });
    if dir {
        for e in fs::read_dir(p).map_err(|e| e.to_string())? {
            capture(&e.map_err(|e| e.to_string())?.path(), n)?;
        }
    }
    Ok(())
}
pub(crate) fn snapshot(ts: &[Target]) -> Result<Snapshot, String> {
    let mut roots = BTreeSet::new();
    for t in ts {
        safe_target(&t.path)?;
        roots.insert(t.path.clone());
    }
    let mut nodes = Vec::new();
    for r in &roots {
        capture(r, &mut nodes)?;
    }
    Ok(Snapshot {
        roots: roots.into_iter().collect(),
        nodes,
    })
}
fn rm(p: &Path) -> Result<(), String> {
    match fs::symlink_metadata(p) {
        Ok(m) => {
            if m.is_dir() && !m.file_type().is_symlink() {
                fs::remove_dir_all(p)
            } else {
                fs::remove_file(p)
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
    .map_err(|e| e.to_string())
}
fn restore_owner(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if m.uid() == uid && m.gid() == gid {
        return Ok(());
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("ownership-restore-open-failed {}: {e}", path.display()))?;
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(format!(
            "ownership-restore-failed {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}
pub(crate) fn restore(s: &Snapshot) -> Result<(), String> {
    for r in s.roots.iter().rev() {
        safe_target(r)?;
        rm(r)?;
    }
    for n in &s.nodes {
        match &n.kind {
            Kind::Missing => continue,
            Kind::Dir => fs::create_dir_all(&n.path).map_err(|e| e.to_string())?,
            Kind::File(b) => {
                if let Some(p) = n.path.parent() {
                    fs::create_dir_all(p).map_err(|e| e.to_string())?;
                }
                crate::tools::files::atomic_write_bytes(&n.path, b, Some(n.mode & 0o7777))?
            }
            Kind::Symlink(t) => {
                if let Some(p) = n.path.parent() {
                    fs::create_dir_all(p).map_err(|e| e.to_string())?;
                }
                std::os::unix::fs::symlink(t, &n.path).map_err(|e| e.to_string())?
            }
        }
        if !matches!(n.kind, Kind::Symlink(_)) {
            restore_owner(&n.path, n.uid, n.gid)?;
            fs::set_permissions(&n.path, fs::Permissions::from_mode(n.mode & 0o7777))
                .map_err(|e| e.to_string())?;
        }
    }
    verify(s)
}
fn verify(s: &Snapshot) -> Result<(), String> {
    let mut got = Vec::new();
    for r in &s.roots {
        capture(r, &mut got)?;
    }
    got.sort_by(|a, b| a.path.cmp(&b.path));
    let mut expected = s.nodes.clone();
    expected.sort_by(|a, b| a.path.cmp(&b.path));
    if got.len() != expected.len() {
        return Err("rollback-tree-mismatch".into());
    }
    for (a, b) in got.iter().zip(&expected) {
        if a.path != b.path
            || a.mode != b.mode
            || a.uid != b.uid
            || a.gid != b.gid
            || std::mem::discriminant(&a.kind) != std::mem::discriminant(&b.kind)
        {
            return Err(format!("rollback-metadata-mismatch {}", a.path.display()));
        }
        match (&a.kind, &b.kind) {
            (Kind::File(x), Kind::File(y)) if x != y => {
                return Err("rollback-bytes-mismatch".into())
            }
            (Kind::Symlink(x), Kind::Symlink(y)) if x != y => {
                return Err("rollback-symlink-target-mismatch".into())
            }
            _ => {}
        }
    }
    Ok(())
}
pub(crate) fn snapshot_services(plan: &UpdatePlan) -> Result<Vec<ServiceStateSnapshot>, String> {
    plan.services
        .iter()
        .map(|s| {
            crate::tools::systemd::snapshot_service_state(&s.name, s.user, s.target_user.as_deref())
        })
        .collect()
}
pub(crate) fn restore_services(states: &[ServiceStateSnapshot]) -> Result<(), String> {
    for s in states {
        crate::tools::systemd::restore_service_state(s)?;
    }
    Ok(())
}
pub(crate) fn update_set_receipt(
    dir: &Path,
    face: &str,
    verdict: &str,
    failed: Option<&str>,
    failed_step: Option<&str>,
) -> Result<(), String> {
    let ms=["caduceus","caduceus_staff",face].into_iter().map(|m|json!({"member":m,"status":if verdict=="ok"{"ok"}else if failed==Some(m){"failed"}else{"rolled-back"}})).collect::<Vec<_>>();
    let mut v = json!({"schema":"harmonia.update-set.v1","set_name":"appliance-syzygy","gui":face,"set_verdict":verdict,"members":ms});
    if let Some(x) = failed_step {
        v["failed_step"] = json!(x);
    }
    crate::receipts::write_json(&dir.join("update-set.json"), &v)
}

pub(crate) fn bench(args: &[String]) -> Result<(), String> {
    let fail = args
        .windows(2)
        .find(|w| w[0] == "--fail")
        .map(|w| w[1].clone());
    let root = std::env::temp_dir().join(format!(
        "harmonia-update-set-bench-{}",
        crate::run_id_from_stamp()
    ));
    let modules = root.join("modules");
    fs::create_dir_all(&modules).map_err(|e| e.to_string())?;
    let shelf = root.join("usr/local/sbin/caduceus_staff");
    fs::create_dir_all(shelf.join("child")).map_err(|e| e.to_string())?;
    fs::write(shelf.join("child/prior"), b"prior").map_err(|e| e.to_string())?;
    let bin = root.join("usr/local/bin/caduceus");
    fs::create_dir_all(bin.parent().unwrap()).map_err(|e| e.to_string())?;
    fs::write(&bin, b"old").map_err(|e| e.to_string())?;
    for (id, manifest) in [
        (
            "caduceus",
            json!({"schema":"harmonia.module.ladder.v1","id":"caduceus","version":"1","ladder":[{"step_id":"r","tool":"service-runtime","permutation":"converge","args":{"module_id":"caduceus","component":"caduceus","source_dir":"/opt/caduceus/source","install_bin":"/usr/local/bin/caduceus","service":"caduceus.service","url":"http://127.0.0.1:1/","binary_name":"caduceus","op_prefix":"caduceus","run_schema":"bench.caduceus.v1","managed_files_schema":"bench.caduceus.files.v1","managed_files":[]}},{"step_id":"s","tool":"files","permutation":"source-shelf-sweep","args":{"source_root":"/nonexistent","shelf_source":"caduceus_staff","target_shelf":"/usr/local/sbin/caduceus_staff","launcher_target_root":"/usr/local/sbin","launcher_source_root":"/nonexistent","launcher_pattern":"caduceus-*","shelf_owner":"root","shelf_group":"root","shelf_directory_mode":493,"shelf_file_mode":420,"launcher_mode":493,"prune":true}}]}),
        ),
        (
            "arcadia-gui-runtime",
            json!({"schema":"harmonia.module.ladder.v1","id":"arcadia-gui-runtime","version":"1","ladder":[{"step_id":"r","tool":"service-runtime","permutation":"converge","args":{"module_id":"arcadia-gui-runtime","component":"arcadia","source_dir":"/opt/arcadia/source","install_bin":"/usr/local/bin/arcadia","service":"arcadia.service","url":"http://127.0.0.1:2/","binary_name":"arcadia","op_prefix":"arcadia","run_schema":"bench.arcadia.v1","managed_files_schema":"bench.arcadia.files.v1","managed_files":[]}}]}),
        ),
    ] {
        let d = modules.join(id);
        fs::create_dir_all(&d).map_err(|e| e.to_string())?;
        fs::write(d.join("manifest.json"), manifest.to_string()).map_err(|e| e.to_string())?;
    }
    let p = Profile {
        id: "bench".into(),
        identity: "bench".into(),
        package_authority: None,
        modules: vec!["caduceus".into(), "arcadia-gui-runtime".into()],
        hotfixes: vec![],
    };
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut bindings = Vec::new();
    for profile_id in ["tv", "homeconsole", "homeserver"] {
        let profile_path = source_root
            .join("profiles")
            .join(profile_id)
            .join("index.json");
        let source_profile = crate::load_profile(&profile_path).map_err(|e| e.to_string())?;
        let source_modules = profile_path.parent().unwrap().join("modules");
        let source_plan = derive_plan(
            &source_profile,
            &source_modules,
            Some(&root.join("profile-projection")),
        )?;
        bindings.push(format!("{}={}", profile_id, source_plan.gui_face));
    }
    let plan = derive_plan(&p, &modules, Some(&root))?;
    let snap = snapshot(&plan.targets)?;
    for t in &plan.targets {
        if fail.as_deref() != Some(t.member.as_str()) {
            if matches!(fs::symlink_metadata(&t.path),Ok(m)if m.is_file()) {
                crate::tools::files::atomic_write_bytes(&t.path, b"mutated", None)?;
            }
        }
    }
    let dir = root.join("receipts");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let verdict = if fail.is_some() {
        restore(&snap)?;
        "failed-rolled-back"
    } else {
        "ok"
    };
    update_set_receipt(
        &dir,
        &plan.gui_face,
        verdict,
        fail.as_deref(),
        fail.as_ref().map(|_| "gui-forced"),
    )?;
    let receipt = fs::read_to_string(dir.join("update-set.json")).map_err(|e| e.to_string())?;
    println!(
        "update-set-bench root={} receipt={} rollback_verified={} receipt_line={}",
        root.display(),
        dir.join("update-set.json").display(),
        fail.is_none() || verdict == "failed-rolled-back",
        receipt.replace('\n', "")
    );
    println!("profile_gui_bindings={}", bindings.join(","));
    if fail.is_some() {
        Err("forced GUI failure".into())
    } else {
        Ok(())
    }
}
