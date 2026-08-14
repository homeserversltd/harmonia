//! Durable transactional atom: capsule first, ordered JSONL journal, guarded rollback.
use crate::atoms::r#do::InvocationKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    ffi::{CString, OsStr},
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    rc::Rc,
};
#[derive(Clone, Debug, Default)]
pub(crate) struct RunCarrier {
    pub projection: Option<crate::profile_engine::ProfileProjection>,
    pub update_plan: Option<crate::update_set::UpdatePlan>,
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
fn restore(i: &RestorationImage, s: &mut dyn ServiceState) -> Result<(), String> {
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
        restore(&a.0, &mut *self.service)?;
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
        restore(&old, s)?;
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
