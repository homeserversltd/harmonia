//! Durable transactional atom: capsule first, ordered JSONL journal, guarded rollback.
use crate::atoms::r#do::InvocationKey;
use crate::Profile;
use crate::tools::systemd::ServiceStateSnapshot;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
#[derive(Clone, Debug, Default)]
pub(crate) struct RefreshedProfileIdentity {
    pub profile_id: String,
    pub identity: String,
    pub source_head: String,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ModuleRootConsistency {
    pub source_root: String,
    pub installed_root: String,
    pub source_tree_sha256: String,
    pub installed_tree_sha256: String,
    pub matches: bool,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct TransactionCensus {
    pub profile_id: String,
    pub profile_identity: String,
    pub source_head: String,
    pub target_count: usize,
    pub service_count: usize,
    pub caduceus_count: usize,
    pub gui_face: String,
    pub gui_member: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct TransactionCensusSnapshot {
    pub profile_id: String,
    pub profile_identity: String,
    pub source_head: String,
    pub target_count: usize,
    pub service_count: usize,
    pub caduceus_count: usize,
    pub gui_face: String,
    pub gui_member: String,
}

impl From<&TransactionCensus> for TransactionCensusSnapshot {
    fn from(value: &TransactionCensus) -> Self {
        Self {
            profile_id: value.profile_id.clone(),
            profile_identity: value.profile_identity.clone(),
            source_head: value.source_head.clone(),
            target_count: value.target_count,
            service_count: value.service_count,
            caduceus_count: value.caduceus_count,
            gui_face: value.gui_face.clone(),
            gui_member: value.gui_member.clone(),
        }
    }
}

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    ffi::{CString, OsStr},
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
    rc::Rc,
};

#[derive(Clone, Debug)]
pub(crate) struct Target {
    pub path: PathBuf,
    pub member: String,
}
#[derive(Clone, Debug)]
pub(crate) struct ServiceBinding {
    pub name: String,
    pub user: bool,
    pub target_user: Option<String>,
}
#[derive(Clone, Debug)]
pub(crate) struct UpdatePlan {
    pub targets: Vec<Target>,
    pub services: Vec<ServiceBinding>,
    pub gui_face: String,
    pub gui_member: String,
    pub caduceus_count: usize,
}
pub(crate) fn derive_plan(
    profile: &Profile,
    module_root: &Path,
    projection_root: Option<&Path>,
) -> Result<UpdatePlan, String> {
    let projection =
        crate::profile_engine::load_profile_projection(profile, module_root, &BTreeSet::new())?;
    let mut plan = projection.derive_update_plan(profile, module_root)?;
    if let Some(scratch) = projection_root {
        for target in &mut plan.targets {
            let rel = target
                .path
                .strip_prefix("/")
                .map_err(|_| "projection-target-not-absolute")?;
            target.path = scratch.join(rel);
        }
        plan.services.clear();
    }
    Ok(plan)
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RunCarrier {
    pub projection: Option<crate::profile_engine::ProfileProjection>,
    pub update_plan: Option<UpdatePlan>,
    pub refreshed_profile: Option<RefreshedProfileIdentity>,
    pub module_root_consistency: Option<ModuleRootConsistency>,
    pub transaction_census: Option<TransactionCensus>,
    pub refreshed_profile_value: Option<crate::Profile>,
    pub sealed_snapshot: Option<Snapshot>,
    pub sealed_services: Option<Vec<crate::tools::systemd::ServiceStateSnapshot>>,
    pub sealed_projection: Option<ProjectionTransaction>,
}

pub(crate) type RunCarrierRef = Rc<RefCell<RunCarrier>>;

#[derive(Clone, Debug)]
pub(crate) struct RunContext {
    pub run_id: String,
    pub profile: String,
    pub face: String,
    pub(crate) key: InvocationKey,
    pub(crate) carrier: RunCarrierRef,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RunIdentity {
    run_id: String,
    profile: String,
    face: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum AtomKind {
    Leaf,
    Compound,
    Envelope,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum Reversibility {
    Exact,
    Weak,
    ForwardOnly,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Atom {
    pub name: String,
    pub kind: AtomKind,
    pub reversibility: Reversibility,
    pub children: Vec<Atom>,
}
impl Atom {
    fn leaf(n: &str, r: Reversibility) -> Self {
        Self {
            name: n.into(),
            kind: AtomKind::Leaf,
            reversibility: r,
            children: vec![],
        }
    }
    fn compound(n: &str, c: Vec<Self>) -> Self {
        Self {
            name: n.into(),
            kind: AtomKind::Compound,
            reversibility: Reversibility::Exact,
            children: c,
        }
    }
    fn envelope(c: Vec<Self>) -> Self {
        Self {
            name: "envelope".into(),
            kind: AtomKind::Envelope,
            reversibility: Reversibility::Exact,
            children: c,
        }
    }
    fn validate_strict(&self) -> Result<(), String> {
        if self.reversibility != Reversibility::Exact {
            return Err(format!("non-exact:{}", self.name));
        }
        for c in &self.children {
            c.validate_strict()?
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ServiceImage {
    pub name: String,
    pub enabled: bool,
    pub active: bool,
}
pub(crate) trait ServiceState {
    fn observe(&self, name: &str) -> Result<ServiceImage, String>;
    fn restore(&mut self, image: &ServiceImage) -> Result<(), String>;
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct RestorationImage {
    pub path: String,
    pub exists: bool,
    pub kind: String,
    pub bytes: Vec<u8>,
    pub link: Option<Vec<u8>>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub xattrs: BTreeMap<String, Vec<u8>>,
    pub service: Option<ServiceImage>,
}
#[derive(Serialize, Deserialize)]
struct Event {
    event: String,
    status: Option<String>,
    post: Option<RestorationImage>,
}
fn cp(p: &Path) -> Result<CString, String> {
    CString::new(p.as_os_str().as_bytes()).map_err(|e| e.to_string())
}
fn xattrs(p: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let c = cp(p)?;
    let n = unsafe { libc::llistxattr(c.as_ptr(), std::ptr::null_mut(), 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut b = vec![0; n as usize];
    if n > 0 && unsafe { libc::llistxattr(c.as_ptr(), b.as_mut_ptr() as *mut _, b.len()) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut o = BTreeMap::new();
    for k in b.split(|x| *x == 0).filter(|x| !x.is_empty()) {
        let k = String::from_utf8(k.to_vec()).map_err(|e| e.to_string())?;
        let ck = CString::new(k.clone()).map_err(|e| e.to_string())?;
        let z = unsafe { libc::lgetxattr(c.as_ptr(), ck.as_ptr(), std::ptr::null_mut(), 0) };
        if z < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut v = vec![0; z as usize];
        if z > 0
            && unsafe {
                libc::lgetxattr(c.as_ptr(), ck.as_ptr(), v.as_mut_ptr() as *mut _, v.len())
            } < 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        o.insert(k, v);
    }
    Ok(o)
}
fn capture(
    p: &Path,
    s: Option<&dyn ServiceState>,
    service_name: Option<&str>,
) -> Result<RestorationImage, String> {
    let m = match fs::symlink_metadata(p) {
        Ok(x) => x,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RestorationImage {
                path: p.display().to_string(),
                exists: false,
                kind: "absent".into(),
                bytes: vec![],
                link: None,
                mode: 0,
                uid: 0,
                gid: 0,
                xattrs: BTreeMap::new(),
                service: None,
            })
        }
        Err(e) => return Err(e.to_string()),
    };
    let ft = m.file_type();
    let (k, b, l) = if ft.is_symlink() {
        (
            "symlink".into(),
            vec![],
            Some(
                fs::read_link(p)
                    .map_err(|e| e.to_string())?
                    .as_os_str()
                    .as_bytes()
                    .to_vec(),
            ),
        )
    } else if ft.is_file() {
        ("file".into(), fs::read(p).map_err(|e| e.to_string())?, None)
    } else {
        ("other".into(), vec![], None)
    };
    Ok(RestorationImage {
        path: p.display().to_string(),
        exists: true,
        kind: k,
        bytes: b,
        link: l,
        mode: m.mode(),
        uid: m.uid(),
        gid: m.gid(),
        xattrs: xattrs(p)?,
        service: s
            .map(|x| x.observe(service_name.unwrap_or("bench.service")))
            .transpose()?,
    })
}
fn sync(p: &Path) -> Result<(), String> {
    if let Some(d) = p.parent() {
        File::open(d)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?
    }
    Ok(())
}
fn append(p: &Path, e: &Event) -> Result<(), String> {
    if let Some(d) = p.parent() {
        fs::create_dir_all(d).map_err(|e| e.to_string())?
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)
        .map_err(|e| e.to_string())?;
    serde_json::to_writer(&mut f, e).map_err(|e| e.to_string())?;
    f.write_all(b"\n").map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    sync(p)
}
fn capsule(p: &Path, v: &RestorationImage) -> Result<(), String> {
    if let Some(d) = p.parent() {
        fs::create_dir_all(d).map_err(|e| e.to_string())?
    }
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(p)
        .map_err(|e| e.to_string())?;
    serde_json::to_writer(&mut f, v).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    sync(p)
}
fn restore_image(i: &RestorationImage, s: &mut dyn ServiceState) -> Result<(), String> {
    let p = Path::new(&i.path);
    if i.exists {
        if fs::symlink_metadata(p).is_ok() {
            fs::remove_file(p)
                .or_else(|_| fs::remove_dir_all(p))
                .map_err(|e| e.to_string())?
        }
        if i.kind == "symlink" {
            std::os::unix::fs::symlink(OsStr::from_bytes(i.link.as_ref().ok_or("link")?), p)
                .map_err(|e| e.to_string())?
        } else if i.kind == "file" {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(p)
                .map_err(|e| e.to_string())?;
            f.write_all(&i.bytes).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
            fs::set_permissions(p, fs::Permissions::from_mode(i.mode))
                .map_err(|e| e.to_string())?;
            let c = cp(p)?;
            if unsafe { libc::lchown(c.as_ptr(), i.uid, i.gid) } != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let now = xattrs(p)?;
            for k in now.keys().filter(|k| !i.xattrs.contains_key(*k)) {
                let k = CString::new(k.as_str()).map_err(|e| e.to_string())?;
                if unsafe { libc::lremovexattr(c.as_ptr(), k.as_ptr()) } != 0 {
                    return Err(std::io::Error::last_os_error().to_string());
                }
            }
            for (k, v) in &i.xattrs {
                let k = CString::new(k.as_str()).map_err(|e| e.to_string())?;
                if unsafe {
                    libc::lsetxattr(c.as_ptr(), k.as_ptr(), v.as_ptr() as *const _, v.len(), 0)
                } != 0
                {
                    return Err(std::io::Error::last_os_error().to_string());
                }
            }
        }
    } else if fs::symlink_metadata(p).is_ok() {
        fs::remove_file(p)
            .or_else(|_| fs::remove_dir_all(p))
            .map_err(|e| e.to_string())?
    }
    if let Some(v) = &i.service {
        s.restore(v)?
    }
    sync(p)
}
#[derive(Clone)]
struct ForwardAuthority {
    key: InvocationKey,
    target: PathBuf,
    old: RestorationImage,
    new: RestorationImage,
}
#[derive(Clone)]
struct RollbackAuthority(RestorationImage);
struct Transaction {
    ctx: RunContext,
    journal: PathBuf,
    capsule: PathBuf,
    target: PathBuf,
    old: RestorationImage,
    post: Option<RestorationImage>,
    service: Box<dyn ServiceState>,
}
impl Transaction {
    fn compare(
        &self,
        key: InvocationKey,
        old: &RestorationImage,
        new: &RestorationImage,
    ) -> Option<ForwardAuthority> {
        (old != new).then(|| ForwardAuthority {
            key,
            target: self.target.clone(),
            old: old.clone(),
            new: new.clone(),
        })
    }
    fn admit(
        ctx: RunContext,
        root: &Path,
        mut service: Box<dyn ServiceState>,
    ) -> Result<Self, String> {
        let j = root.join("journal.jsonl");
        let c = root.join("capsule.json");
        recover_open(&j, &c, &mut *service)?;
        let t = root.join("fixture.txt");
        let old = capture(&t, Some(&*service), None)?;
        Atom::envelope(vec![Atom::compound(
            "do",
            vec![Atom::leaf("write", Reversibility::Exact)],
        )])
        .validate_strict()?;
        capsule(&c, &old)?;
        append(
            &j,
            &Event {
                event: "open".into(),
                status: None,
                post: None,
            },
        )?;
        Ok(Self {
            ctx,
            journal: j,
            capsule: c,
            target: t,
            old,
            post: None,
            service,
        })
    }
    fn apply(&mut self, a: ForwardAuthority) -> Result<(), String> {
        if a.target != self.target || a.old != self.old || a.new.bytes != b"after" {
            return Err("path-mismatch".into());
        }
        fs::write(&self.target, b"after").map_err(|e| e.to_string())?;
        let mut changed_service = self.service.observe("bench.service")?;
        changed_service.enabled = false;
        changed_service.active = false;
        self.service.restore(&changed_service)?;
        let p = capture(&self.target, Some(&*self.service), None)?;
        self.post = Some(p.clone());
        append(
            &self.journal,
            &Event {
                event: "apply".into(),
                status: None,
                post: Some(p),
            },
        )
    }
    fn commit(&mut self) -> Result<Value, String> {
        append(
            &self.journal,
            &Event {
                event: "commit".into(),
                status: Some("committed".into()),
                post: self.post.clone(),
            },
        )?;
        Ok(serde_json::json!({"file":"after","status":"committed"}))
    }
    fn rollback(&mut self) -> Result<Value, String> {
        let p = self.post.clone().ok_or("apply")?;
        if capture(&self.target, Some(&*self.service), None)? != p {
            append(
                &self.journal,
                &Event {
                    event: "rollback".into(),
                    status: Some("failed-rollback-incomplete".into()),
                    post: None,
                },
            )?;
            return Err("foreign".into());
        }
        let a = RollbackAuthority(self.old.clone());
        restore_image(&a.0, &mut *self.service)?;
        append(
            &self.journal,
            &Event {
                event: "rollback".into(),
                status: Some("failed-rolled-back".into()),
                post: None,
            },
        )?;
        Ok(serde_json::json!({"file":"before","service_restored":true}))
    }
}
fn recover_open(j: &Path, c: &Path, s: &mut dyn ServiceState) -> Result<(), String> {
    if !j.exists() {
        return Ok(());
    }
    let mut last = None;
    for l in fs::read_to_string(j).map_err(|e| e.to_string())?.lines() {
        last = Some(serde_json::from_str::<Event>(l).map_err(|e| e.to_string())?)
    }
    let Some(e) = last else { return Ok(()) };
    if e.event == "commit" || e.event == "rollback" {
        return Ok(());
    }
    if let Some(post) = e.post {
        let old: RestorationImage =
            serde_json::from_str(&fs::read_to_string(c).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        if capture(Path::new(&old.path), Some(&*s), None)? != post {
            append(
                j,
                &Event {
                    event: "rollback".into(),
                    status: Some("failed-rollback-incomplete".into()),
                    post: None,
                },
            )?;
            return Err("recovery-rollback-incomplete".into());
        }
        restore_image(&old, s)?;
        append(
            j,
            &Event {
                event: "rollback".into(),
                status: Some("recovered-rolled-back".into()),
                post: None,
            },
        )?
    } else {
        append(
            j,
            &Event {
                event: "rollback".into(),
                status: Some("recovered-open-without-apply".into()),
                post: None,
            },
        )?
    }
    Ok(())
}
#[derive(Clone)]
struct BenchService {
    image: Rc<RefCell<ServiceImage>>,
}
impl BenchService {
    fn new(name: &str) -> (Self, Rc<RefCell<ServiceImage>>) {
        let shared = Rc::new(RefCell::new(ServiceImage {
            name: name.into(),
            enabled: true,
            active: true,
        }));
        (
            Self {
                image: shared.clone(),
            },
            shared,
        )
    }
}
impl ServiceState for BenchService {
    fn observe(&self, _n: &str) -> Result<ServiceImage, String> {
        Ok(self.image.borrow().clone())
    }
    fn restore(&mut self, i: &ServiceImage) -> Result<(), String> {
        *self.image.borrow_mut() = i.clone();
        Ok(())
    }
}

// Exact target custody is owned by the admitted atom.
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
fn capture_tree(p: &Path, n: &mut Vec<Node>) -> Result<(), String> {
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
            capture_tree(&e.map_err(|e| e.to_string())?.path(), n)?;
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
        capture_tree(r, &mut nodes)?;
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
fn root_matches_snapshot(root: &Path, expected: &[Node]) -> Result<bool, String> {
    let mut current = Vec::new();
    capture_tree(root, &mut current)?;
    let mut wanted = expected.iter().filter(|node| node.path == root || node.path.starts_with(root.join(""))).cloned().collect::<Vec<_>>();
    current.sort_by(|a, b| a.path.cmp(&b.path));
    wanted.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(current.len() == wanted.len() && current.iter().zip(&wanted).all(|(a, b)| a.path == b.path && a.mode == b.mode && a.uid == b.uid && a.gid == b.gid && std::mem::discriminant(&a.kind) == std::mem::discriminant(&b.kind) && match (&a.kind, &b.kind) { (Kind::File(x), Kind::File(y)) => x == y, (Kind::Symlink(x), Kind::Symlink(y)) => x == y, _ => true }))
}

pub(crate) fn restore(s: &Snapshot) -> Result<(), String> {
    let mut changed = Vec::new();
    for root in &s.roots {
        safe_target(root)?;
        if !root_matches_snapshot(root, &s.nodes)? { changed.push(root.clone()); }
    }
    let changed_roots = changed.clone();
    changed.retain(|root| !changed_roots.iter().any(|parent| parent != root && root.starts_with(parent)));
    for root in changed.iter().rev() { rm(root)?; }
    for n in &s.nodes {
        if !changed.iter().any(|root| n.path == *root || n.path.starts_with(root.join(""))) { continue; }
        match &n.kind {
            Kind::Missing => continue,
            Kind::Dir => fs::create_dir_all(&n.path).map_err(|e| e.to_string())?,
            Kind::File(b) => { if let Some(p) = n.path.parent() { fs::create_dir_all(p).map_err(|e| e.to_string())?; } crate::tools::files::atomic_write_bytes(&n.path, b, Some(n.mode & 0o7777))? }
            Kind::Symlink(t) => { if let Some(p) = n.path.parent() { fs::create_dir_all(p).map_err(|e| e.to_string())?; } std::os::unix::fs::symlink(t, &n.path).map_err(|e| e.to_string())? }
        }
        if !matches!(n.kind, Kind::Symlink(_)) {
            restore_owner(&n.path, n.uid, n.gid)?;
            fs::set_permissions(&n.path, fs::Permissions::from_mode(n.mode & 0o7777)).map_err(|e| e.to_string())?;
        }
    }
    verify(s)
}

fn verify(s: &Snapshot) -> Result<(), String> {
    let mut got = Vec::new();
    for r in &s.roots {
        capture_tree(r, &mut got)?;
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
    for sealed in states {
        let observed = crate::tools::systemd::snapshot_service_state(&sealed.name, sealed.user, sealed.target_user.as_deref())?;
        if observed.enabled != sealed.enabled || observed.active != sealed.active {
            crate::tools::systemd::restore_service_state(sealed)?;
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum TransactionState { Open, Applied, Committed, RolledBack, RollbackIncomplete, RefusedForeignPostImage }
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ProjectionChild { pub ordinal: usize, pub member: String, pub target_indices: Vec<usize>, pub service_indices: Vec<usize> }
#[derive(Clone, Debug)]
pub(crate) struct SealedProjection { pub profile_id: String, pub profile_identity: String, pub source_head: String, pub children: Vec<ProjectionChild>, pub snapshot: Snapshot, pub services: Vec<ServiceStateSnapshot>, pub gui_face: String, pub gui_member: String, pub caduceus_count: usize }
#[derive(Clone, Debug)]
pub(crate) struct ProjectionTransaction { pub sealed: SealedProjection, pub state: TransactionState }
#[derive(Clone, Debug, Serialize)]
pub(crate) struct TransactionReceipt { pub schema: &'static str, pub state: TransactionState, pub profile_id: String, pub profile_identity: String, pub source_head: String, pub gui: String, pub children: Vec<ProjectionChild>, pub target_count: usize, pub service_count: usize, pub caduceus_count: usize }
pub(crate) fn validate_exact_root(path: &Path) -> Result<(), String> { safe_target(path)?; let mut cur=PathBuf::from("/"); for c in path.components().skip(1) { cur.push(c.as_os_str()); if let Ok(m)=fs::symlink_metadata(&cur) { if m.file_type().is_symlink() { return Err(format!("update-set-root-symlink {}",cur.display())); } } } Ok(()) }
pub(crate) fn seal_projection(plan: &UpdatePlan, profile_id: &str, profile_identity: &str, source_head: &str) -> Result<ProjectionTransaction, String> { if plan.gui_member.is_empty() || plan.gui_face.is_empty() { return Err("sealed-projection-gui-missing".into()); } for t in &plan.targets { validate_exact_root(&t.path)?; } let snapshot=snapshot(&plan.targets)?; let services=snapshot_services(plan)?; let mut members=Vec::new(); for t in &plan.targets { if !members.contains(&t.member) { members.push(t.member.clone()); } } for m in ["caduceus","agathodaimon",plan.gui_member.as_str()] { if !members.iter().any(|x| x==m) { members.push(m.to_string()); } } let children=members.into_iter().enumerate().map(|(ordinal,member)| ProjectionChild { ordinal, target_indices: plan.targets.iter().enumerate().filter_map(|(i,t)|(t.member==member).then_some(i)).collect(), service_indices: plan.services.iter().enumerate().filter_map(|(i,s)|(s.name==member).then_some(i)).collect(), member }).collect(); Ok(ProjectionTransaction { sealed: SealedProjection { profile_id:profile_id.into(), profile_identity:profile_identity.into(), source_head:source_head.into(), children, snapshot, services, gui_face:plan.gui_face.clone(), gui_member:plan.gui_member.clone(), caduceus_count:plan.caduceus_count }, state:TransactionState::Open }) }
pub(crate) fn apply_projection(txn: &mut ProjectionTransaction, child: usize, _key: InvocationKey) -> Result<(), String> { if txn.state!=TransactionState::Open { return Err("transaction-not-open".into()); } if child>=txn.sealed.children.len() { return Err("sealed-child-out-of-range".into()); } txn.state=TransactionState::Applied; Ok(()) }
fn receipt_for(t:&ProjectionTransaction)->TransactionReceipt { TransactionReceipt { schema:"harmonia.transaction.v1", state:t.state.clone(), profile_id:t.sealed.profile_id.clone(), profile_identity:t.sealed.profile_identity.clone(), source_head:t.sealed.source_head.clone(), gui:t.sealed.gui_face.clone(), children:t.sealed.children.clone(), target_count:t.sealed.snapshot.roots.len(), service_count:t.sealed.services.len(), caduceus_count:t.sealed.caduceus_count } }
pub(crate) fn commit_projection(t:&mut ProjectionTransaction)->Result<TransactionReceipt,String> { if t.state==TransactionState::Committed { return Ok(receipt_for(t)); } if t.state!=TransactionState::Applied { return Err("transaction-not-applied".into()); } t.state=TransactionState::Committed; Ok(receipt_for(t)) }
pub(crate) fn rollback_projection(t:&mut ProjectionTransaction)->Result<TransactionReceipt,String> { if t.state==TransactionState::RolledBack { return Ok(receipt_for(t)); } if t.state==TransactionState::Committed { return Err("committed-transaction-not-rollbackable".into()); } let a=restore(&t.sealed.snapshot); let b=restore_services(&t.sealed.services); if a.is_ok() && b.is_ok() { t.state=TransactionState::RolledBack; Ok(receipt_for(t)) } else { t.state=TransactionState::RollbackIncomplete; Err("rollback-incomplete".into()) } }
pub(crate) fn project_update_set_v1(r:&TransactionReceipt)->Value { let verdict=match r.state { TransactionState::Committed=>"ok", TransactionState::RolledBack=>"failed-rolled-back", TransactionState::RollbackIncomplete=>"failed-rollback-incomplete", TransactionState::RefusedForeignPostImage=>"refused-foreign-post-image", _=>"failed" }; json!({"schema":"harmonia.update-set.v1","set_name":"appliance-syzygy","profile_id":r.profile_id,"profile_identity":r.profile_identity,"source_head":r.source_head,"gui":r.gui,"set_verdict":verdict,"members":r.children.iter().map(|c|json!({"ordinal":c.ordinal,"member":c.member,"status":if r.state==TransactionState::Committed {"standing"} else {"rolled-back"}})).collect::<Vec<_>>(),"targets":r.target_count,"services":r.service_count,"caduceus_count":r.caduceus_count}) }

pub(crate) fn update_set_bench(args: &[String], _ctx: RunContext) -> Result<(), String> {
    if args.iter().any(|arg| arg == "--broad-parent") {
        let error = crate::atoms::r#do::transaction::snapshot(&[Target {
            path: PathBuf::from("/etc"),
            member: "bench".into(),
        }])
        .expect_err("broad parent must be refused");
        println!("no_broad_parent={error}");
        return Ok(());
    }
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
    let shelf = root.join("usr/local/sbin/agathodaimon");
    fs::create_dir_all(shelf.join("child")).map_err(|e| e.to_string())?;
    fs::write(shelf.join("child/prior"), b"prior").map_err(|e| e.to_string())?;
    let bin = root.join("usr/local/bin/caduceus");
    fs::create_dir_all(bin.parent().unwrap()).map_err(|e| e.to_string())?;
    fs::write(&bin, b"old").map_err(|e| e.to_string())?;
    for (id, manifest) in [
        (
            "caduceus",
            json!({"schema":"harmonia.module.ladder.v1","id":"caduceus","version":"1","ladder":[{"step_id":"r","tool":"service-runtime","permutation":"converge","args":{"module_id":"caduceus","component":"caduceus","source_dir":"/opt/caduceus/source","install_bin":"/usr/local/bin/caduceus","service":"caduceus.service","url":"http://127.0.0.1:1/","binary_name":"caduceus","op_prefix":"caduceus","run_schema":"bench.caduceus.v1","managed_files_schema":"bench.caduceus.files.v1","managed_files":[]}},{"step_id":"s","tool":"files","permutation":"source-shelf-sweep","args":{"source_root":"/nonexistent","shelf_source":"agathodaimon","target_shelf":"/usr/local/sbin/agathodaimon","launcher_target_root":"/usr/local/sbin","launcher_source_root":"/nonexistent","launcher_pattern":"caduceus-*","shelf_owner":"root","shelf_group":"root","shelf_directory_mode":493,"shelf_file_mode":420,"launcher_mode":493,"prune":true}}]}),
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
    if args.iter().any(|arg| arg == "--config-census") {
        let manifest_path = modules.join("caduceus/manifest.json");
        let config_manifest = fs::read_to_string(&manifest_path)
            .map_err(|e| e.to_string())?
            .replace("/usr/local/bin/caduceus", "/home/owner/.config/hypr/harmonia.conf");
        fs::write(&manifest_path, config_manifest).map_err(|e| e.to_string())?;
        match derive_plan(&p, &modules, None) {
            Err(error) if error.starts_with("configuration-actuator-authority-refused ") => {
                println!("no_config_in_census={error}");
                return Ok(());
            }
            Ok(_) => return Err("config target admitted into update census".into()),
            Err(error) => return Err(format!("unexpected config census result: {error}")),
        }
    }
    if args.iter().any(|arg| arg == "--managed-config-census") {
        let manifest_path = modules.join("caduceus/manifest.json");
        let managed_manifest = fs::read_to_string(&manifest_path)
            .map_err(|e| e.to_string())?
            .replace(
                "\"managed_files\":[]",
                "\"managed_files\":[{\"path\":\"/home/owner/.config/hypr/harmonia.conf\",\"content\":\"bench\"}]",
            );
        fs::write(&manifest_path, managed_manifest).map_err(|e| e.to_string())?;
        let plan = derive_plan(&p, &modules, Some(&root))?;
        let _sealed = seal_projection(&plan, "bench", "bench", "bench")?;
        println!("config_skipped_census_sealed=true");
        return Ok(());
    }
    if args.iter().any(|arg| arg == "--gui-converge-config-census") {
        let manifest_path = modules.join("arcadia-gui-runtime/manifest.json");
        let gui_manifest = fs::read_to_string(&manifest_path)
            .map_err(|e| e.to_string())?
            .replace(
                "\"version\":\"1\"",
                "\"version\":\"1\",\"constants\":{\"target_dir\":\"/home/owner\",\"expected_files\":[\".config/hypr/autostart.conf\"]}",
            )
            .replace(
                r##""ladder":[{"##,
                r##""ladder":[{"step_id":"g","tool":"files","permutation":"converge","args":{"source_root":"/opt/arcadia/source","target_root":"/home/owner/.config/hypr","files":["harmonia.conf"]}},{"##,
            );
        fs::write(&manifest_path, gui_manifest).map_err(|e| e.to_string())?;
        let caduceus_manifest_path = modules.join("caduceus/manifest.json");
        let caduceus_manifest = fs::read_to_string(&caduceus_manifest_path)
            .map_err(|e| e.to_string())?
            .replace(
                "\"service\":\"caduceus.service\"",
                "\"service\":\"caduceus.service\",\"caduceus_profile_source\":{\"path\":\"/home/owner/.config/hypr/profile.conf\"}",
            );
        fs::write(&caduceus_manifest_path, caduceus_manifest)
            .map_err(|e| e.to_string())?;
        let plan = derive_plan(&p, &modules, None)?;
        let _sealed = seal_projection(&plan, "bench", "bench", "bench")?;
        let expected_files_config_skipped = !plan.targets.iter().any(|target| {
            target.path == PathBuf::from("/home/owner/.config/hypr/autostart.conf")
        });
        let service_census_preserved = plan
            .services
            .iter()
            .any(|service| service.name == "caduceus.service");
        if !expected_files_config_skipped || !service_census_preserved {
            return Err("config census proof failed".into());
        }
        println!("gui_converge_config_skipped=true");
        println!("expected_files_config_skipped={expected_files_config_skipped}");
        println!("service_census_preserved={service_census_preserved}");
        return Ok(());
    }
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut bindings = Vec::new();
    for profile_id in ["tv", "homeconsole", "homeserver"] {
        let profile_path = source_root
            .join("profiles")
            .join(profile_id)
            .join("index.json");
        let source_profile = crate::load_profile(&profile_path).map_err(|e| e.to_string())?;
        let source_modules = profile_path.parent().unwrap().join("modules");
        let source_plan = match derive_plan(
            &source_profile,
            &source_modules,
            Some(&root.join("profile-projection")),
        ) {
            Ok(plan) => plan,
            Err(error) if error.starts_with("configuration-actuator-authority-refused ") => {
                bindings.push(format!("{}=configuration-refused", profile_id));
                continue;
            }
            Err(error) => return Err(error),
        };
        bindings.push(format!("{}={}", profile_id, source_plan.gui_face));
        if profile_id == "tv" {
            let agathodaimon_targets = source_plan
                .targets
                .iter()
                .filter(|target| target.member == "agathodaimon")
                .map(|target| target.path.display().to_string())
                .collect::<Vec<_>>();
            let gui_targets = source_plan
                .targets
                .iter()
                .filter(|target| target.member == source_plan.gui_member)
                .map(|target| target.path.display().to_string())
                .collect::<Vec<_>>();
            let gui_services = source_plan
                .services
                .iter()
                .map(|service| service.name.clone())
                .collect::<Vec<_>>();
            println!(
                "profile_update_set=tv caduceus_count={} agathodaimon_targets={} gui_face={} gui_targets={} gui_services={}",
                source_plan.caduceus_count,
                agathodaimon_targets.join(","),
                source_plan.gui_face,
                gui_targets.join(","),
                gui_services.join(",")
            );
        }
    }
    let plan = derive_plan(&p, &modules, Some(&root))?;
    let pre_absent = plan
        .targets
        .iter()
        .filter(|target| fs::symlink_metadata(&target.path).is_err())
        .count();
    println!("pre_absent_targets={pre_absent}");
    let snap = crate::atoms::r#do::transaction::snapshot(&plan.targets)?;
    let failed_member_identity = fail.as_deref().map(|member| plan.targets.iter().filter(|target| target.member == member).filter_map(|target| fs::symlink_metadata(&target.path).ok().map(|m| (target.path.clone(), m.ino(), m.mtime(), m.mtime_nsec()))).collect::<Vec<_>>());
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
        crate::atoms::r#do::transaction::restore(&snap)?;
        "failed-rolled-back"
    } else {
        "ok"
    };
    crate::atoms::attest::update_set_receipt(
        &dir,
        &plan.gui_face,
        verdict,
        fail.as_deref(),
        fail.as_ref().map(|_| "gui-forced"),
    )?;
    let receipt = fs::read_to_string(dir.join("update-set.json")).map_err(|e| e.to_string())?;
    let failed_member_unchanged = failed_member_identity.as_ref().map(|before| before.iter().all(|(path, ino, mtime, mtime_nsec)| fs::symlink_metadata(path).map(|m| m.ino() == *ino && m.mtime() == *mtime && m.mtime_nsec() == *mtime_nsec).unwrap_or(false))).unwrap_or(true);
    println!(
        "update-set-bench root={} receipt={} rollback_verified={} failed_member_unchanged={} receipt_line={}",
        root.display(),
        dir.join("update-set.json").display(),
        (fail.is_none() || verdict == "failed-rolled-back") && failed_member_unchanged,
        failed_member_unchanged,
        receipt.replace('\n', "")
    );
    println!("profile_gui_bindings={}", bindings.join(","));
    if fail.is_some() {
        Err("forced GUI failure".into())
    } else {
        Ok(())
    }
}


pub(crate) fn bench(args: &[String], ctx: RunContext) -> Result<(), String> {
    let root = PathBuf::from(args.first().cloned().unwrap_or_else(|| {
        std::env::temp_dir()
            .join(format!("harmonia-{}", ctx.run_id))
            .display()
            .to_string()
    }));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let target = root.join("fixture.txt");
    fs::write(&target, b"before").map_err(|e| e.to_string())?;
    let (service, _shared) =
        BenchService::new(args.get(1).map(String::as_str).unwrap_or("bench.service"));
    let mut t = Transaction::admit(ctx.clone(), &root, Box::new(service))?;
    let desired = RestorationImage {
        bytes: b"after".to_vec(),
        ..t.old.clone()
    };
    let a = t
        .compare(ctx.key, &t.old.clone(), &desired)
        .ok_or("no diff")?;
    t.apply(a)?;
    let committed = t.commit()?;
    // A committed journal is a terminal no-op even if the on-disk target is left at after.
    let committed_before = fs::read(&target).map_err(|e| e.to_string())?;
    recover_open(&t.journal, &t.capsule, &mut BenchService::new("ignored").0)?;
    let terminal_commit_readmission =
        fs::read(&target).map_err(|e| e.to_string())? == committed_before;

    let normal_root = root.join("forced-failure");
    fs::create_dir_all(&normal_root).map_err(|e| e.to_string())?;
    let normal_target = normal_root.join("fixture.txt");
    fs::write(&normal_target, b"before").map_err(|e| e.to_string())?;
    #[cfg(unix)]
    fs::set_permissions(&normal_target, fs::Permissions::from_mode(0o640))
        .map_err(|e| e.to_string())?;
    let xattr_supported = set_bench_xattr(&normal_target, b"before-xattr");
    let (normal_service, normal_shared) = BenchService::new("bench.service");
    let mut normal = Transaction::admit(ctx.clone(), &normal_root, Box::new(normal_service))?;
    let desired = RestorationImage {
        bytes: b"after".to_vec(),
        ..normal.old.clone()
    };
    normal.apply(
        normal
            .compare(ctx.key, &normal.old.clone(), &desired)
            .ok_or("no diff")?,
    )?;
    let normal_after_service = normal_shared.borrow().clone();
    *normal_shared.borrow_mut() = ServiceImage {
        name: "bench.service".into(),
        enabled: false,
        active: false,
    };
    let rollback = normal.rollback()?;
    let restored = capture(
        &normal_target,
        Some(&BenchService {
            image: normal_shared.clone(),
        }),
        Some("bench.service"),
    )? == normal.old;

    let foreign_root = root.join("foreign-guard");
    fs::create_dir_all(&foreign_root).map_err(|e| e.to_string())?;
    let foreign_target = foreign_root.join("fixture.txt");
    fs::write(&foreign_target, b"before").map_err(|e| e.to_string())?;
    let (foreign_service, _) = BenchService::new("bench.service");
    let mut foreign = Transaction::admit(ctx.clone(), &foreign_root, Box::new(foreign_service))?;
    let desired = RestorationImage {
        bytes: b"after".to_vec(),
        ..foreign.old.clone()
    };
    foreign.apply(
        foreign
            .compare(ctx.key, &foreign.old.clone(), &desired)
            .ok_or("no diff")?,
    )?;
    fs::write(&foreign_target, b"foreign").map_err(|e| e.to_string())?;
    let foreign_err = foreign.rollback().unwrap_err();
    let journal = fs::read_to_string(&foreign.journal).map_err(|e| e.to_string())?;
    let foreign_guard = foreign_err == "foreign"
        && fs::read(&foreign_target).map_err(|e| e.to_string())? == b"foreign"
        && journal.contains("failed-rollback-incomplete");

    let crash_root = root.join("crash-recovery");
    fs::create_dir_all(&crash_root).map_err(|e| e.to_string())?;
    let crash_target = crash_root.join("fixture.txt");
    fs::write(&crash_target, b"before").map_err(|e| e.to_string())?;
    let (crash_service, crash_shared) = BenchService::new("bench.service");
    let mut crash = Transaction::admit(ctx.clone(), &crash_root, Box::new(crash_service))?;
    let desired = RestorationImage {
        bytes: b"after".to_vec(),
        ..crash.old.clone()
    };
    crash.apply(
        crash
            .compare(ctx.key, &crash.old.clone(), &desired)
            .ok_or("no diff")?,
    )?;
    *crash_shared.borrow_mut() = ServiceImage {
        name: "bench.service".into(),
        enabled: false,
        active: false,
    };
    drop(crash);
    let recovered_service = BenchService {
        image: crash_shared.clone(),
    };
    let _ = Transaction::admit(ctx, &crash_root, Box::new(recovered_service))?;
    let crash_recovery = fs::read(&crash_target).map_err(|e| e.to_string())? == b"before"
        && crash_shared.borrow().enabled
        && crash_shared.borrow().active;

    let strict_validation = json!({"weak": Atom::leaf("weak", Reversibility::Weak).validate_strict().is_err(), "forward_only": Atom::leaf("forward", Reversibility::ForwardOnly).validate_strict().is_err()});
    let out = json!({"cases":[committed,{"status":"rollback","restored":restored,"service_restored":normal_shared.borrow().enabled && normal_shared.borrow().active,"xattr_supported":xattr_supported,"rollback":rollback},{"status":"crash_recovery","ok":crash_recovery},{"status":"foreign_guard","ok":foreign_guard},{"status":"terminal_commit_readmission","ok":terminal_commit_readmission}],"forced_failure":{"mode":640,"uid":normal.old.uid,"gid":normal.old.gid,"xattr_supported":xattr_supported,"service_after_apply":{"enabled":normal_after_service.enabled,"active":normal_after_service.active},"rollback_restored":restored},"crash_recovery":crash_recovery,"foreign_guard":foreign_guard,"terminal_commit_readmission":terminal_commit_readmission,"strict_validation":strict_validation,"paths":{"journal":t.journal,"capsule":t.capsule}});
    println!(
        "{}",
        serde_json::to_string(&out).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn set_bench_xattr(p: &Path, value: &[u8]) -> bool {
    let Ok(c) = cp(p) else { return false };
    let k = CString::new("user.harmonia-before").unwrap();
    unsafe {
        libc::lsetxattr(
            c.as_ptr(),
            k.as_ptr(),
            value.as_ptr() as *const _,
            value.len(),
            0,
        ) == 0
    }
}
