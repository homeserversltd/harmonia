//! One-owner durable transactional ritual: observe, compare, act, attest, seal, recover.
use super::transaction::{Target, UpdatePlan};
use crate::atoms::r#do::InvocationKey;
use crate::atoms::ask::change_unit::ServiceStateSnapshot;
use crate::*;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::{ffi::OsStrExt, fs::{MetadataExt, OpenOptionsExt}},
    path::{Path, PathBuf},
};

thread_local! {
    static SHADOW: std::cell::RefCell<ShadowState> = const { std::cell::RefCell::new(ShadowState::Idle) };
}

#[derive(Clone)]
enum ShadowState {
    Idle,
    Armed(Snapshot, Vec<ServiceStateSnapshot>),
    Building,
    Built(Snapshot, bool), // owed until commit, skipped rollback, or clean rollback
    Refused(String),
    Restoring,
}

fn shadow_name(root: &Path, building: bool) -> Result<PathBuf, String> {
    let name = root.file_name().ok_or_else(|| format!("rollback-shadow-invalid {}", root.display()))?;
    let mut sibling = std::ffi::OsString::from(".");
    sibling.push(name);
    sibling.push(if building { ".harmonia-shadow.building" } else { ".harmonia-shadow" });
    Ok(root.parent().ok_or_else(|| format!("rollback-shadow-invalid {}", root.display()))?.join(sibling))
}

pub(crate) fn arm_shadow(snapshot: &Snapshot, services: &[ServiceStateSnapshot]) {
    if !snapshot.roots.is_empty() {
        SHADOW.with(|state| *state.borrow_mut() = ShadowState::Armed(snapshot.clone(), services.to_vec()));
    }
}

pub(crate) fn refuse_shadow(signal: String) {
    SHADOW.with(|state| *state.borrow_mut() = ShadowState::Refused(signal));
}

fn hard_link_nofollow(root: &Path, source: &Path, destination: &Path) -> Result<(), String> {
    let src_parent = open_dir_nofollow(root, source.parent().ok_or_else(|| "source parent missing".to_string())?)?;
    let dst_parent = open_dir_nofollow(root, destination.parent().ok_or_else(|| "destination parent missing".to_string())?)?;
    let src_name = std::ffi::CString::new(source.file_name().ok_or_else(|| "source name missing".to_string())?.as_bytes()).map_err(|e| e.to_string())?;

    let st = stat_at(&src_parent, &src_name).map_err(|e| e.to_string())?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG { return Err("source is not a regular file".into()); }
    let witness = crate::atoms::projectio::engine_state_witness();
    let src_file = fs::File::from(src_parent);
    let dst_file = fs::File::from(dst_parent);
    crate::atoms::projectio::act_at_link(&witness, &src_file, source.file_name().unwrap(), &dst_file, destination.file_name().unwrap(), None).map_err(|e| e.to_string())?;
    Ok(())
}

fn check_shadows(snapshot: &Snapshot) -> Result<(), String> {
    for root in &snapshot.roots {
        if snapshot.roots.iter().any(|other| other.path != root.path && root.path.starts_with(&other.path)) {
            return Err(format!("rollback-shadow-nested-root {}", root.path.display()));
        }
        for building in [false, true] {
            let path = shadow_name(&root.path, building)?;
            match fs::symlink_metadata(&path) {
                Ok(_) => return Err(format!("rollback-shadow-left-standing {}", path.display())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                Err(e) => return Err(format!("rollback-shadow-left-standing {}: {e}", path.display())),
            }
        }
    }
    Ok(())
}

fn build_shadows(snapshot: &Snapshot) -> Result<(), (String, bool)> {
    let witness = crate::atoms::projectio::engine_state_witness();
    let mut made = Vec::new();
    let result = (|| {
        for root in &snapshot.roots {
            let building = shadow_name(&root.path, true)?;
            let final_path = shadow_name(&root.path, false)?;
            let mut nodes = snapshot.nodes.iter().filter(|n| n.path == root.path || n.path.starts_with(&root.path)).collect::<Vec<_>>();
            nodes.sort_by_key(|n| n.path.components().count());
            let mut directories = Vec::new();
            for node in nodes {
                if matches!(node.kind, Kind::Missing) { continue; }
                let relative = node.path.strip_prefix(&root.path).map_err(|e| e.to_string())?;
                let destination = if relative.as_os_str().is_empty() { building.clone() } else { building.join(relative) };
                match &node.kind {
                    Kind::Dir => {
                        crate::atoms::projectio::act_scratch_make_dir_new_mode(&witness, &destination, 0o700).map_err(|e| format!("rollback-shadow-build-failed {}: {e}", destination.display()))?;
                        if node.path == root.path { made.push((root.path.clone(), building.clone())); }
                        let directory = open_dir_nofollow(&root.path, &destination).map_err(|e| format!("rollback-shadow-build-failed {}: {e}", destination.display()))?;
                        directories.push((directory, node, destination));
                    },
                    Kind::Symlink(target) => {
                        crate::atoms::projectio::act_scratch_symlink(&witness, target, &destination).map_err(|e| e.to_string())?;
                        if node.path == root.path { made.push((root.path.clone(), building.clone())); }
                        crate::atoms::projectio::act_scratch_link_owner(&witness, &destination, node.uid, node.gid).map_err(|e| format!("rollback-shadow-build-failed {}: {e}", destination.display()))?;
                    },
                    Kind::File(hash) => {
                        hard_link_nofollow(&root.path, &node.path, &destination).map_err(|e| format!("rollback-shadow-link-failed {}: {e}", node.path.display()))?;
                        if node.path == root.path { made.push((root.path.clone(), building.clone())); }
                        if hash_regular_nofollow(&destination).map_err(|e| format!("rollback-shadow-seal-mismatch {}: {e}", node.path.display()))? != *hash {
                            return Err(format!("rollback-shadow-seal-mismatch {}", node.path.display()));
                        }
                    },
                    Kind::Special => return Err(format!("rollback-shadow-special-file {}", node.path.display())),
                    Kind::Missing => {},
                }
            }
            for (directory, node, destination) in directories.into_iter().rev() {
                let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
                if unsafe { libc::fstat(directory.as_raw_fd(), stat.as_mut_ptr()) } != 0 { return Err(std::io::Error::last_os_error().to_string()); }
                let stat = unsafe { stat.assume_init() };
                let directory = fs::File::from(directory);
                if stat.st_uid != node.uid || stat.st_gid != node.gid {
                    crate::atoms::projectio::act_fd_owner(&witness, &directory, node.uid, node.gid, None).map_err(|e| format!("rollback-shadow-build-failed {}: {e}", destination.display()))?;
                }
                crate::atoms::projectio::act_fd_mode(&witness, &directory, node.mode & 0o7777, None).map_err(|e| format!("rollback-shadow-build-failed {}: {e}", destination.display()))?;
            }
            if made.last().is_some_and(|(_, path)| path == &building) {
                if let Err(error) = crate::atoms::projectio::act_scratch_rename_new(&witness, &building, &final_path) {
                    if error.kind() == std::io::ErrorKind::AlreadyExists {
                        return Err(format!("rollback-shadow-left-standing {}", final_path.display()));
                    }
                    return Err(format!("rollback-shadow-build-failed {}: {error}", final_path.display()));
                }
                made.last_mut().unwrap().1 = final_path;
            }
        }
        Ok(())
    })();
    if let Err(mut error) = result {
        let mut survives = false;
        for (root, path) in made.iter().rev() {
            if let Err(cleanup) = rm(root, path, (&witness).into(), true) {
                survives = true;
                error.push_str(&format!("; rollback-shadow-cleanup-failed {}: {cleanup}", path.display()));
            }
        }
        Err((error, survives))
    } else {
        Ok(())
    }
}

pub(crate) fn authorize_shadow() -> Result<(), String> {
    let snapshot = SHADOW.with(|state| {
        let mut state = state.borrow_mut();
        match &*state {
            ShadowState::Refused(signal) => Err(signal.clone()),
            ShadowState::Armed(_, _) => match std::mem::replace(&mut *state, ShadowState::Building) {
                ShadowState::Armed(snapshot, services) => Ok(Some((snapshot, services))),
                _ => unreachable!(),
            },
            _ => Ok(None),
        }
    })?;
    if let Some((snapshot, services)) = snapshot {
        let result = (|| {
            let run_id = crate::receipts::active_run_id().ok_or_else(|| "rollback-shadow-record-failed: run id absent".to_string())?;
            let roots = snapshot.roots.iter().map(|root| root.path.clone()).collect::<Vec<_>>();
            if crate::ledger::rollback_read()?.is_some() { return Err("rollback-shadow-record-present".into()); }
            if let Err(error) = check_shadows(&snapshot) {
                if crate::ledger::rollback_read()?.is_some() { return Err("rollback-shadow-record-present".into()); }
                return Err(error);
            }
            let rows = snapshot_rows(&snapshot)?;
            crate::ledger::rollback_begin(&run_id, &rows, &services)?;
            if let Err((mut error, survives)) = build_shadows(&snapshot) {
                if !survives {
                    if let Err(cleanup) = crate::ledger::rollback_delete(&run_id) {
                        error.push_str(&format!("; rollback-shadow-cleanup-failed run_id={run_id}: {cleanup}"));
                    }
                }
                return Err(error);
            }
            if let Err(mut error) = crate::ledger::rollback_mark(&run_id, "held") {
                match remove_shadow_roots(&roots) {
                    Err(cleanup) => error.push_str(&format!("; {cleanup}")),
                    Ok(()) => if let Err(cleanup) = crate::ledger::rollback_delete(&run_id) {
                        error.push_str(&format!("; rollback-shadow-cleanup-failed run_id={run_id}: {cleanup}"));
                    },
                }
                return Err(error);
            }
            Ok(())
        })();
        match result {
            Ok(()) => SHADOW.with(|state| *state.borrow_mut() = ShadowState::Built(snapshot, true)),
            Err(error) => {
                SHADOW.with(|state| *state.borrow_mut() = ShadowState::Refused(error.clone()));
                return Err(error);
            }
        }
    }
    Ok(())
}

pub(crate) fn shadow_not_owed() {
    SHADOW.with(|state| if let ShadowState::Built(_, owed) = &mut *state.borrow_mut() {
        *owed = false;
        let result = crate::receipts::active_run_id().ok_or_else(|| "rollback-shadow-record-failed: run id absent".to_string())
            .and_then(|id| crate::ledger::rollback_mark(&id, "closing"));
        if let Err(error) = result { eprintln!("rollback-shadow-mark-failed: {error}"); }
    });
}

pub(crate) fn remove_shadow_roots(roots: &[PathBuf]) -> Result<(), String> {
    let witness = crate::atoms::projectio::engine_state_witness();
    let mut errors = Vec::new();
    for root in roots {
        for building in [false, true] {
            match shadow_name(root, building) {
                Ok(path) => if let Err(error) = rm(root, &path, (&witness).into(), true) {
                    errors.push(format!("rollback-shadow-cleanup-failed {}: {error}", path.display()));
                },
                Err(error) => errors.push(format!("rollback-shadow-cleanup-failed {}: {error}", root.display())),
            }
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}

pub(crate) fn recover_dead_shadow(key: Option<&InvocationKey>, profile_id: &str) -> Result<(), String> {
    for _ in 0..8 {
        let Some(press) = crate::ledger::rollback_read()? else { return Ok(()); };
        let live = super::convergence_lock::engine_run_lock_pid_is_live(press.pid)
            .map_err(|error| format!("rollback-shadow-cleanup-failed pid={}: {error}", press.pid))?;
        let ticks = crate::atoms::attest::convergence_receipts::process_start_ticks(press.pid);
        if live && (press.start_ticks.is_none() || ticks.is_none() || press.start_ticks == ticks) { return Ok(()); }
        return match press.state.as_str() {
            "held" => {
                let owed = || format!("rollback-recovery-owed run_id={}", press.run_id);
                let key = key.ok_or_else(owed)?;
                match crate::ledger::rollback_takeover(&press)? {
                    None => continue,
                    Some(false) => return Err(owed()),
                    Some(true) => {},
                }
                let incomplete = |error: String| format!("rollback-recovery-incomplete run_id={}: {error}", press.run_id);
                let (snapshot, services) = snapshot_from_rows(&press.run_id).map_err(&incomplete)?;
                let mut restored = Vec::new();
                let mut errors = Vec::new();
                SHADOW.with(|state| *state.borrow_mut() = ShadowState::Restoring);
                if let Err(error) = restore(&snapshot, key, &mut restored) { errors.push(error); }
                if let Err(error) = restore_services(&services, key) { errors.push(format!("rollback-service-restore-failed: {error}")); }
                SHADOW.with(|state| *state.borrow_mut() = ShadowState::Idle);
                if !errors.is_empty() { return Err(incomplete(errors.join("; "))); }
                remove_shadow_roots(&press.roots)?;
                crate::ledger::rollback_delete(&press.run_id).map_err(&incomplete)?;
                let _ = crate::deeds::record("transaction", profile_id, false, !restored.is_empty(), None, Some(&press.run_id), None, Some("transaction-killed-rolled-back"), Some(restored.len() as u64));
                Ok(())
            },
            "building" | "closing" => {
                crate::ledger::rollback_clear_dead(&press, remove_shadow_roots)
                    .map_err(|error| if error.starts_with("rollback-shadow-cleanup-failed") { error }
                        else { format!("rollback-shadow-cleanup-failed run_id={}: {error}", press.run_id) })
            },
            other => Err(format!("rollback-shadow-cleanup-failed run_id={}: invalid state {other}", press.run_id)),
        };
    }
    Err("rollback-recovery-contended".into())
}

pub(crate) fn close_shadow() -> Result<(), String> {
    let old = SHADOW.with(|state| std::mem::replace(&mut *state.borrow_mut(), ShadowState::Idle));
    if let ShadowState::Built(snapshot, false) = old {
        let run_id = crate::receipts::active_run_id().ok_or_else(|| "rollback-shadow-record-failed: run id absent".to_string())?;
        crate::ledger::rollback_mark(&run_id, "closing")?;
        let roots = snapshot.roots.into_iter().map(|root| root.path).collect::<Vec<_>>();
        remove_shadow_roots(&roots)?;
        crate::ledger::rollback_delete(&run_id)?;
    }
    Ok(())
}

// Exact target custody is owned by the admitted atom.
#[derive(Clone, Debug)]
enum Kind {
    Missing,
    File([u8; 32]),
    Special,
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
    pub(crate) roots: Vec<Target>,
    nodes: Vec<Node>,
}
fn snapshot_rows(snapshot: &Snapshot) -> Result<crate::ledger::RollbackRows, String> {
    let roots = snapshot.roots.iter().map(|root| (root.path.as_os_str().as_bytes().to_vec(), root.member.clone())).collect();
    let nodes = snapshot.nodes.iter().map(|node| {
        let (kind, sha256, link) = match &node.kind {
            Kind::Missing => ("missing", None, None),
            Kind::Dir => ("dir", None, None),
            Kind::File(hash) => ("file", Some(hash.to_vec()), None),
            Kind::Symlink(text) => ("link", None, Some(text.as_os_str().as_bytes().to_vec())),
            Kind::Special => return Err(format!("rollback-shadow-special-file {}", node.path.display())),
        };
        Ok(crate::ledger::RollbackNodeRow { path: node.path.as_os_str().as_bytes().to_vec(), kind: kind.into(), mode: node.mode, uid: node.uid, gid: node.gid, sha256, link })
    }).collect::<Result<Vec<_>, String>>()?;
    Ok(crate::ledger::RollbackRows { roots, nodes })
}

fn snapshot_from_rows(run_id: &str) -> Result<(Snapshot, Vec<ServiceStateSnapshot>), String> {
    use std::os::unix::ffi::OsStringExt;
    let (rows, services) = crate::ledger::rollback_rows(run_id)?;
    let roots = rows.roots.into_iter().map(|(path, member)| Target { path: PathBuf::from(std::ffi::OsString::from_vec(path)), member, module: String::new() }).collect();
    let nodes = rows.nodes.into_iter().map(|row| {
        let kind = match row.kind.as_str() {
            "missing" => Kind::Missing,
            "dir" => Kind::Dir,
            "file" => Kind::File(row.sha256.ok_or_else(|| "rollback file hash absent".to_string())?.try_into().map_err(|_| "rollback file hash invalid".to_string())?),
            "link" => Kind::Symlink(PathBuf::from(std::ffi::OsString::from_vec(row.link.ok_or_else(|| "rollback link absent".to_string())?))),
            _ => return Err(format!("rollback node kind invalid: {}", row.kind)),
        };
        Ok(Node { path: PathBuf::from(std::ffi::OsString::from_vec(row.path)), kind, mode: row.mode, uid: row.uid, gid: row.gid })
    }).collect::<Result<Vec<_>, String>>()?;
    Ok((Snapshot { roots, nodes }, services))
}

pub(crate) fn validate_member_scoped_target(path: &Path, member: &str) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!("update-set-target-invalid {}", path.display()));
    }
    if member == "sudoers" {
        let text = path
            .to_str()
            .ok_or_else(|| format!("update-set-target-invalid {}", path.display()))?;
        let segments = text.split('/').collect::<Vec<_>>();
        let valid = segments.len() == 4
            && segments[0].is_empty()
            && segments[1] == "etc"
            && segments[2] == "sudoers.d"
            && !segments[3].is_empty()
            && segments[3] != "."
            && segments[3] != ".."
            && path.file_name().and_then(|name| name.to_str()) == Some(segments[3]);
        if !valid {
            return Err(format!("update-set-sudoers-target-invalid {}", path.display()));
        }
        return crate::atoms::files::ensure_resolved_containment(Path::new("/etc/sudoers.d"), path);
    }
    if member == "sbin" && path == Path::new("/usr/local/sbin") {
        return Ok(());
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
    } else if m.file_type().is_file() {
        Kind::File(hash_regular_nofollow(p).map_err(|e| format!("rollback-shadow-read-failed {}: {e}", p.display()))?)
    } else {
        return Err(format!("rollback-shadow-special-file {}", p.display()));
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
    let mut roots = Vec::new();
    for t in ts {
        validate_member_scoped_target(&t.path, &t.member)?;
        if let Some(root) = roots.iter().find(|root: &&Target| root.path == t.path) {
            if root.member != t.member {
                return Err(format!(
                    "update-set-target-member-ambiguous {}",
                    t.path.display()
                ));
            }
        } else {
            roots.push(t.clone());
        }
    }
    let mut nodes = Vec::new();
    for r in &roots {
        capture_tree(&r.path, &mut nodes)?;
    }
    Ok(Snapshot {
        roots,
        nodes,
    })
}
fn snapshot_with_sudoers_preimages(
    targets: &[Target],
    preimages: &[crate::tools::files::SudoersSnapshotPreimage],
) -> Result<Snapshot, String> {
    let mut snapshot = snapshot(targets)?;
    for preimage in preimages {
        let target = Target {
            path: preimage.path.clone(),
            member: "sudoers".into(),
            module: "sudoers".into(),
        };
        validate_member_scoped_target(&target.path, &target.member)?;
        if snapshot.roots.iter().any(|root| root.path == target.path) {
            return Err(format!(
                "update-set-target-duplicate {}",
                target.path.display()
            ));
        }
        snapshot.roots.push(target.clone());
        snapshot.nodes.push(Node {
            path: target.path,
            kind: Kind::File(Sha256::digest(&preimage.bytes).into()),
            mode: preimage.mode,
            uid: preimage.uid,
            gid: preimage.gid,
        });
    }
    Ok(snapshot)
}
// Resolve the held root's parent by name, then never follow a link below it.
fn open_dir_nofollow(root: &Path, path: &Path) -> Result<OwnedFd, String> {
    let parent = root.parent().ok_or_else(|| "root parent missing".to_string())?;
    let relative = path.strip_prefix(parent).map_err(|e| e.to_string())?;
    let parent = std::ffi::CString::new(parent.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let fd = unsafe { libc::open(parent.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 { return Err(std::io::Error::last_os_error().to_string()); }
    let mut dir = unsafe { OwnedFd::from_raw_fd(fd) };
    for component in relative.components() {
        match component {
            std::path::Component::Normal(name) => {
                let name = std::ffi::CString::new(name.as_bytes()).map_err(|e| e.to_string())?;
                let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
                if fd < 0 { return Err(std::io::Error::last_os_error().to_string()); }
                dir = unsafe { OwnedFd::from_raw_fd(fd) };
            },
            _ => return Err("invalid directory component".into()),
        }
    }
    Ok(dir)
}

fn stat_at(dir: &OwnedFd, name: &std::ffi::CStr) -> Result<libc::stat, std::io::Error> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe { libc::fstatat(dir.as_raw_fd(), name.as_ptr(), st.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
    if rc != 0 { return Err(std::io::Error::last_os_error()); }
    Ok(unsafe { st.assume_init() })
}

// Walk only through the held, no-follow directories; never re-resolve the root.
fn remove_held_tree(dir: &fs::File, name: &std::ffi::OsStr, path: &Path, witness: crate::atoms::projectio::PenWitness<'_>, scratch: bool) -> Result<(), String> {
    let cname = std::ffi::CString::new(name.as_bytes()).map_err(|e| e.to_string())?;
    let fd = unsafe { libc::openat(dir.as_raw_fd(), cname.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 { return Err(std::io::Error::last_os_error().to_string()); }
    let child = unsafe { fs::File::from_raw_fd(fd) };
    for entry in fs::read_dir(format!("/proc/self/fd/{}", child.as_raw_fd())).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let child_name = entry.file_name();
        let child_path = path.join(&child_name);
        let meta = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
        if meta.file_type().is_dir() {
            remove_held_tree(&child, &child_name, &child_path, witness, scratch)?;
        } else {
            crate::atoms::projectio::act_at_unlink(witness, &child, &child_name, false, if scratch { None } else { Some(&child_path) }).map_err(|e| e.to_string())?;
        }
    }
    crate::atoms::projectio::act_at_unlink(witness, dir, name, true, if scratch { None } else { Some(path) }).map_err(|e| e.to_string())
}

fn rm(root: &Path, p: &Path, witness: crate::atoms::projectio::PenWitness<'_>, scratch: bool) -> Result<(), String> {
    let parent = p.parent().ok_or_else(|| "parent missing".to_string())?;
    let dir = match open_dir_nofollow(root, parent) {
        Ok(dir) => dir,
        Err(error) => return Err(error),
    };
    let name = std::ffi::CString::new(p.file_name().ok_or_else(|| "name missing".to_string())?.as_bytes()).map_err(|e| e.to_string())?;
    let st = match stat_at(&dir, &name) {
        Ok(st) => st,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
    };
    if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
        let dir = fs::File::from(dir);
        remove_held_tree(&dir, p.file_name().unwrap(), p, witness, scratch)
    } else {
        let dir = fs::File::from(dir);
        crate::atoms::projectio::act_at_unlink(witness, &dir, p.file_name().unwrap(), false, if scratch { None } else { Some(p) }).map_err(|e| e.to_string())
    }
}
fn restore_owner(witness: &crate::atoms::projectio::RollbackWitness, path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if m.uid() == uid && m.gid() == gid {
        return Ok(());
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("ownership-restore-open-failed {}: {e}", path.display()))?;
    crate::atoms::projectio::act_fd_owner(witness, &file, uid, gid, Some(path)).map_err(|e| format!("ownership-restore-failed {}: {e}", path.display()))?;
    Ok(())
}
fn root_matches_snapshot(root: &Path, expected: &[Node]) -> Result<bool, String> {
    let mut current = Vec::new();
    let mut capture_errors = Vec::new();
    capture_tree_for_verify(root, &mut current, &mut capture_errors);
    if !capture_errors.is_empty() { return Err(capture_errors.join("; ")); }
    let mut wanted = expected
        .iter()
        .filter(|node| node.path == root || node.path.starts_with(root.join("")))
        .cloned()
        .collect::<Vec<_>>();
    current.sort_by(|a, b| a.path.cmp(&b.path));
    wanted.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(current.len() == wanted.len()
        && current.iter().zip(&wanted).all(|(a, b)| {
            a.path == b.path
                && a.mode == b.mode
                && a.uid == b.uid
                && a.gid == b.gid
                && std::mem::discriminant(&a.kind) == std::mem::discriminant(&b.kind)
                && match (&a.kind, &b.kind) {
                    (Kind::File(x), Kind::File(y)) => x == y,
                    (Kind::Symlink(x), Kind::Symlink(y)) => x == y,
                    _ => true,
                }
        }))
}

struct SnapshotVerification {
    errors: Vec<String>,
    verified_roots: BTreeSet<PathBuf>,
}

// O_PATH pins a non-followed inode without opening a device or FIFO for reading.
fn hash_regular_nofollow(path: &Path) -> Result<[u8; 32], String> {
    use std::io::Read;
    let pinned = fs::OpenOptions::new().read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path).map_err(|e| e.to_string())?;
    if !pinned.metadata().map_err(|e| e.to_string())?.file_type().is_file() {
        return Err(format!("not a regular file: {}", path.display()));
    }
    let mut file = fs::File::open(format!("/proc/self/fd/{}", pinned.as_raw_fd())).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

fn capture_tree_for_verify(p: &Path, nodes: &mut Vec<Node>, errors: &mut Vec<String>) {
    let m = match fs::symlink_metadata(p) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            nodes.push(Node {
                path: p.into(),
                kind: Kind::Missing,
                mode: 0,
                uid: 0,
                gid: 0,
            });
            return;
        }
        Err(error) => {
            errors.push(format!(
                "rollback-capture-failed {}: {error}",
                p.display()
            ));
            return;
        }
    };
    let kind = if m.file_type().is_symlink() {
        match fs::read_link(p) {
            Ok(target) => Kind::Symlink(target),
            Err(error) => {
                errors.push(format!(
                    "rollback-capture-failed {}: {error}",
                    p.display()
                ));
                return;
            }
        }
    } else if m.is_dir() {
        Kind::Dir
    } else if m.file_type().is_file() {
        match hash_regular_nofollow(p) {
            Ok(hash) => Kind::File(hash),
            Err(error) => {
                errors.push(format!("rollback-capture-failed {}: {error}", p.display()));
                return;
            }
        }
    } else {
        // The full mode records the special kind without opening it.
        Kind::Special
    };
    let is_dir = matches!(kind, Kind::Dir);
    nodes.push(Node {
        path: p.into(),
        kind,
        mode: m.mode(),
        uid: m.uid(),
        gid: m.gid(),
    });
    if is_dir {
        let entries = match fs::read_dir(p) {
            Ok(entries) => entries,
            Err(error) => {
                errors.push(format!(
                    "rollback-capture-failed {}: {error}",
                    p.display()
                ));
                return;
            }
        };
        for entry in entries {
            match entry {
                Ok(entry) => capture_tree_for_verify(&entry.path(), nodes, errors),
                Err(error) => errors.push(format!(
                    "rollback-capture-failed {} (directory entry): {error}",
                    p.display()
                )),
            }
        }
    }
}

fn kind_name(kind: &Kind) -> &'static str {
    match kind {
        Kind::Missing => "missing",
        Kind::File(_) => "file",
        Kind::Special => "special",
        Kind::Symlink(_) => "symlink",
        Kind::Dir => "directory",
    }
}

fn verify(s: &Snapshot) -> SnapshotVerification {
    let mut actual = Vec::new();
    let mut errors = Vec::new();
    let mut verified_roots = s
        .roots
        .iter()
        .map(|root| root.path.clone())
        .collect::<BTreeSet<_>>();
    for (root_index, root) in s.roots.iter().enumerate() {
        let mut root_nodes = Vec::new();
        let mut capture_errors = Vec::new();
        capture_tree_for_verify(&root.path, &mut root_nodes, &mut capture_errors);
        for error in capture_errors {
            errors.push(format!("{error} (root {})", root.path.display()));
            verified_roots.remove(&root.path);
        }
        actual.extend(root_nodes.into_iter().map(|node| (root_index, node)));
    }

    // Preserve flattened snapshot order for overlapping roots and appended sudoers preimages.
    actual.sort_by(|(_, left), (_, right)| left.path.cmp(&right.path));
    let mut expected = s.nodes.clone();
    expected.sort_by(|left, right| left.path.cmp(&right.path));
    if actual.len() != expected.len() {
        errors.push(format!(
            "rollback-snapshot-count-mismatch expected={} actual={}",
            expected.len(),
            actual.len()
        ));
    }

    let roots_for_path = |path: &Path| {
        s.roots
            .iter()
            .filter(|root| path == root.path.as_path() || path.starts_with(root.path.as_path()))
            .collect::<Vec<_>>()
    };
    let (mut expected_index, mut actual_index) = (0, 0);
    while expected_index < expected.len() || actual_index < actual.len() {
        match (expected.get(expected_index), actual.get(actual_index)) {
            (Some(sealed), Some((root_index, observed))) if sealed.path == observed.path => {
                let root = &s.roots[*root_index];
                let mut metadata_differences = Vec::new();
                if observed.mode != sealed.mode {
                    metadata_differences.push(format!(
                        "mode expected={:#o} actual={:#o}",
                        sealed.mode, observed.mode
                    ));
                }
                if observed.uid != sealed.uid {
                    metadata_differences.push(format!(
                        "uid expected={} actual={}",
                        sealed.uid, observed.uid
                    ));
                }
                if observed.gid != sealed.gid {
                    metadata_differences.push(format!(
                        "gid expected={} actual={}",
                        sealed.gid, observed.gid
                    ));
                }
                if !metadata_differences.is_empty() {
                    errors.push(format!(
                        "rollback-metadata-mismatch {} (root {}): {}",
                        observed.path.display(),
                        root.path.display(),
                        metadata_differences.join(", ")
                    ));
                    verified_roots.remove(&root.path);
                }
                match (&observed.kind, &sealed.kind) {
                    (Kind::File(actual_bytes), Kind::File(expected_bytes))
                        if actual_bytes != expected_bytes =>
                    {
                        errors.push(format!(
                            "rollback-bytes-mismatch {} (root {})",
                            observed.path.display(),
                            root.path.display()
                        ));
                        verified_roots.remove(&root.path);
                    }
                    (Kind::Symlink(actual_target), Kind::Symlink(expected_target))
                        if actual_target != expected_target =>
                    {
                        errors.push(format!(
                            "rollback-symlink-target-mismatch {} (root {}): expected {}, actual {}",
                            observed.path.display(),
                            root.path.display(),
                            expected_target.display(),
                            actual_target.display()
                        ));
                        verified_roots.remove(&root.path);
                    }
                    _ if std::mem::discriminant(&observed.kind)
                        != std::mem::discriminant(&sealed.kind) =>
                    {
                        errors.push(format!(
                            "rollback-kind-mismatch {} (root {}): expected {}, actual {}",
                            observed.path.display(),
                            root.path.display(),
                            kind_name(&sealed.kind),
                            kind_name(&observed.kind)
                        ));
                        verified_roots.remove(&root.path);
                    }
                    _ => {}
                }
                expected_index += 1;
                actual_index += 1;
            }
            (Some(sealed), Some((_, observed))) if sealed.path < observed.path => {
                let affected_roots = roots_for_path(&sealed.path);
                if affected_roots.is_empty() {
                    errors.push(format!(
                        "rollback-snapshot-path-unassigned {}",
                        sealed.path.display()
                    ));
                    verified_roots.clear();
                } else {
                    for root in affected_roots {
                        errors.push(format!(
                            "rollback-path-missing {} (root {})",
                            sealed.path.display(),
                            root.path.display()
                        ));
                        verified_roots.remove(&root.path);
                    }
                }
                expected_index += 1;
            }
            (Some(_), Some((root_index, observed))) => {
                let root = &s.roots[*root_index];
                errors.push(format!(
                    "rollback-path-unexpected {} (root {})",
                    observed.path.display(),
                    root.path.display()
                ));
                verified_roots.remove(&root.path);
                actual_index += 1;
            }
            (Some(sealed), None) => {
                let affected_roots = roots_for_path(&sealed.path);
                if affected_roots.is_empty() {
                    errors.push(format!(
                        "rollback-snapshot-path-unassigned {}",
                        sealed.path.display()
                    ));
                    verified_roots.clear();
                } else {
                    for root in affected_roots {
                        errors.push(format!(
                            "rollback-path-missing {} (root {})",
                            sealed.path.display(),
                            root.path.display()
                        ));
                        verified_roots.remove(&root.path);
                    }
                }
                expected_index += 1;
            }
            (None, Some((root_index, observed))) => {
                let root = &s.roots[*root_index];
                errors.push(format!(
                    "rollback-path-unexpected {} (root {})",
                    observed.path.display(),
                    root.path.display()
                ));
                verified_roots.remove(&root.path);
                actual_index += 1;
            }
            (None, None) => break,
        }
    }
    SnapshotVerification {
        errors,
        verified_roots,
    }
}

#[cfg(feature = "test-facade")]
fn mutate_rollback_verification_root(s: &Snapshot) -> Result<(), String> {
    use std::io::Write as _;

    let Some(requested) = std::env::var_os("HARMONIA_TEST_ROLLBACK_VERIFY_MUTATE_ROOT") else {
        return Ok(());
    };
    let requested = PathBuf::from(requested);
    let Some(root) = s.roots.iter().find(|root| root.path == requested) else {
        return Err(format!(
            "rollback-test-mutation-root-not-sealed {}",
            requested.display()
        ));
    };
    if root.member == "sudoers" {
        return Err(format!(
            "rollback-test-mutation-root-is-sudoers {}",
            requested.display()
        ));
    }
    let Some(sealed) = s.nodes.iter().find(|node| node.path == requested) else {
        return Err(format!(
            "rollback-test-mutation-root-snapshot-missing {}",
            requested.display()
        ));
    };
    if !matches!(&sealed.kind, Kind::File(_)) {
        return Err(format!(
            "rollback-test-mutation-root-not-file {}",
            requested.display()
        ));
    }
    let metadata = fs::symlink_metadata(&requested).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "rollback-test-mutation-root-not-regular-file {}",
            requested.display()
        ));
    }
    let mut file = fs::OpenOptions::new()
        .append(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&requested)
        .map_err(|error| error.to_string())?;
    file.write_all(b"\nHARMONIA_TEST_ROLLBACK_VERIFY_MUTATION\n")
        .map_err(|error| error.to_string())
}

fn comparison_authorized_write(node: &Node, root: &Path, hash: &[u8; 32], witness: &crate::atoms::projectio::RollbackWitness) -> Result<(), String> {
    let shadow_root = shadow_name(root, false)?;
    let relative = node.path.strip_prefix(root).map_err(|e| e.to_string())?;
    let shadow = if relative.as_os_str().is_empty() { shadow_root } else { shadow_root.join(relative) };
    crate::atoms::comparison::execute_once(
        "ritual-restore-write",
        || {
            let metadata = match fs::symlink_metadata(&node.path) {
                Ok(metadata) if metadata.file_type().is_file() => metadata,
                _ => return Ok::<_, String>(false),
            };
            Ok(metadata.mode() == node.mode && metadata.uid() == node.uid && metadata.gid() == node.gid
                && hash_regular_nofollow(&node.path).ok().as_ref() == Some(hash))
        },
        |current| if *current { crate::atoms::comparison::DiffDecision::Empty } else { crate::atoms::comparison::DiffDecision::Different },
        |authorization, _| {
            let pinned = fs::OpenOptions::new().read(true)
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&shadow).map_err(|e| format!("rollback-shadow-missing {}: {e}", node.path.display()))?;
            let pinned_meta = pinned.metadata().map_err(|e| format!("rollback-shadow-missing {}: {e}", node.path.display()))?;
            if !pinned_meta.file_type().is_file() { return Err(format!("rollback-shadow-missing {}", node.path.display())); }
            let mut shadow_file = fs::File::open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
                .map_err(|e| format!("rollback-shadow-missing {}: {e}", node.path.display()))?;
            let shadow_meta = shadow_file.metadata().map_err(|e| format!("rollback-shadow-missing {}: {e}", node.path.display()))?;
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 65536];
            loop {
                use std::io::Read;
                let count = shadow_file.read(&mut buffer).map_err(|e| format!("rollback-shadow-missing {}: {e}", node.path.display()))?;
                if count == 0 { break; }
                hasher.update(&buffer[..count]);
            }
            let got: [u8; 32] = hasher.finalize().into();
            if got != *hash { return Err(format!("rollback-shadow-altered {}", node.path.display())); }
            let same = fs::symlink_metadata(&node.path).ok().is_some_and(|m| m.file_type().is_file() && m.dev() == shadow_meta.dev() && m.ino() == shadow_meta.ino());
            if !same {
                if fs::symlink_metadata(&node.path).ok().is_some_and(|m| m.file_type().is_dir()) {
                    remove_changed_kind(root, &node.path, witness).map_err(|e| format!("rollback-remove-failed {}: {e}", node.path.display()))?;
                }
                let parent = node.path.parent().ok_or_else(|| "parent missing".to_string())?;
                let name = node.path.file_name().ok_or_else(|| "name missing".to_string())?.to_string_lossy();
                let temp = parent.join(format!(".{name}.harmonia-restore-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos()));
                let destination = open_dir_nofollow(root, parent)?;
                let destination = fs::File::from(destination);
                crate::atoms::projectio::act_fd_link(&authorization, &shadow_file, &destination, temp.file_name().ok_or_else(|| "name missing".to_string())?, None).map_err(|e| e.to_string())?;
                if let Err(error) = crate::atoms::projectio::act_rename(&authorization, &temp, &node.path, true, false) {
                    let _ = crate::atoms::projectio::act_scratch_remove(&authorization, &temp);
                    return Err(error.to_string());
                }
            }
            restore_owner(witness, &node.path, node.uid, node.gid)?;
            let m = fs::symlink_metadata(&node.path).map_err(|e| e.to_string())?;
            if m.mode() & 0o7777 != node.mode & 0o7777 {
                crate::atoms::projectio::act_mode(&authorization, &node.path, node.mode & 0o7777).map_err(|e| e.to_string())?;
            }
            Ok(())
        },
    ).map(|_| ())
}

// Reject a failed or replaced ancestor before any operation can follow it.
fn restore_parent_is_safe(root: &Path, path: &Path) -> Result<(), String> {
    if path == root { return Ok(()); }
    let parent = path.parent().ok_or_else(|| "parent missing".to_string())?;
    let relative = parent.strip_prefix(root).map_err(|e| e.to_string())?;
    let mut current = root.to_path_buf();
    for part in std::iter::once(None).chain(relative.components().map(Some)) {
        if let Some(part) = part { current.push(part.as_os_str()); }
        let m = fs::symlink_metadata(&current).map_err(|e| format!("{}: {e}", current.display()))?;
        if !m.file_type().is_dir() { return Err(format!("{}: not a directory", current.display())); }
    }
    Ok(())
}

// A missing nested root is already restored if a non-link ancestor is absent.
fn restore_missing(root: &Path, path: &Path, witness: &crate::atoms::projectio::RollbackWitness) -> Result<(), String> {
    if root != path {
        let parent = path.parent().ok_or_else(|| "parent missing".to_string())?;
        let relative = parent.strip_prefix(root).map_err(|e| e.to_string())?;
        let mut current = root.to_path_buf();
        for part in std::iter::once(None).chain(relative.components().map(Some)) {
            if let Some(part) = part { current.push(part.as_os_str()); }
            match fs::symlink_metadata(&current) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(format!("{}: {e}", current.display())),
                Ok(m) if m.file_type().is_symlink() => return Err(format!("{}: symlink ancestor", current.display())),
                Ok(m) if !m.file_type().is_dir() => return Ok(()),
                Ok(_) => {},
            }
        }
    }
    rm(root, path, witness.into(), false)
}

// Changed-kind removals use the same anchored descriptor path as missing roots.
fn remove_changed_kind(root: &Path, path: &Path, witness: &crate::atoms::projectio::RollbackWitness) -> Result<(), String> {
    rm(root, path, witness.into(), false)
}

fn restore_link(node: &Node, target: &Path, witness: &crate::atoms::projectio::RollbackWitness) -> Result<(), String> {
    if let Ok(m) = fs::symlink_metadata(&node.path) {
        if m.file_type().is_symlink() && m.uid() == node.uid && m.gid() == node.gid
            && fs::read_link(&node.path).map_err(|e| e.to_string())? == target { return Ok(()); }
    }
    crate::atoms::projectio::rollback_symlink(witness, target, &node.path, node.uid, node.gid).map_err(|e| e.to_string())
}

fn collect_extra_dir(dir: &OwnedFd, path: &Path, named: &BTreeSet<PathBuf>, extras: &mut Vec<PathBuf>, failures: &mut BTreeMap<PathBuf, String>) {
    // The proc fd refers to this pinned directory, not to a re-resolved tree path.
    let entries = match fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd())) {
        Ok(entries) => entries,
        Err(e) => { failures.insert(path.to_path_buf(), e.to_string()); return; }
    };
    for entry in entries {
        let entry = match entry { Ok(e) => e, Err(e) => { failures.insert(path.to_path_buf(), e.to_string()); continue; } };
        let name_os = entry.file_name();
        let child = path.join(&name_os);
        let name = match std::ffi::CString::new(name_os.as_bytes()) { Ok(n) => n, Err(e) => { failures.insert(child, e.to_string()); continue; } };
        let st = match stat_at(dir, &name) { Ok(st) => st, Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue, Err(e) => { failures.insert(child, e.to_string()); continue; } };
        if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
            let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
            if fd < 0 { failures.insert(child.clone(), std::io::Error::last_os_error().to_string()); }
            else {
                let child_dir = unsafe { OwnedFd::from_raw_fd(fd) };
                collect_extra_dir(&child_dir, &child, named, extras, failures);
            }
        }
        if !named.contains(&child) { extras.push(child); }
    }
}

fn collect_extras(path: &Path, named: &BTreeSet<PathBuf>, extras: &mut Vec<PathBuf>, failures: &mut BTreeMap<PathBuf, String>) {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_dir() => match open_dir_nofollow(path, path) {
            Ok(dir) => collect_extra_dir(&dir, path, named, extras, failures),
            Err(e) => { failures.insert(path.to_path_buf(), e); },
        },
        Ok(_) => {},
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
        Err(e) => { failures.insert(path.to_path_buf(), e.to_string()); },
    }
}

fn remove_extra(root: &Path, path: &Path, witness: &crate::atoms::projectio::RollbackWitness) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| "parent missing".to_string())?;
    let dir = open_dir_nofollow(root, parent)?;
    let name = std::ffi::CString::new(path.file_name().ok_or_else(|| "name missing".to_string())?.as_bytes()).map_err(|e| e.to_string())?;
    let st = match stat_at(&dir, &name) {
        Ok(st) => st,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
    };
    let directory = st.st_mode & libc::S_IFMT == libc::S_IFDIR;
    let dir = fs::File::from(dir);
    crate::atoms::projectio::act_at_unlink(witness, &dir, path.file_name().unwrap(), directory, Some(path)).map_err(|e| e.to_string())
}

pub(crate) fn restore(
    s: &Snapshot,
    key: &InvocationKey,
    restored_paths: &mut Vec<String>,
) -> Result<(), String> {
    let witness = crate::atoms::projectio::rollback_witness(s, key);
    let mut changed = Vec::new();
    let mut errors = Vec::new();
    let mut observations = Vec::new();
    let mut restored_roots = BTreeSet::new();
    for root in &s.roots {
        if let Err(error) = validate_member_scoped_target(&root.path, &root.member) {
            errors.push(format!(
                "rollback-target-invalid {}: {error}",
                root.path.display()
            ));
            continue;
        }
        match root_matches_snapshot(&root.path, &s.nodes) {
            Ok(true) => {}
            Ok(false) => changed.push(root.path.clone()),
            Err(error) => {
                observations.push((root.path.clone(), format!("rollback-observe-failed {}: {error}", root.path.display())));
                changed.push(root.path.clone());
            },
        }
    }
    let changed_roots = changed.clone();
    changed.retain(|root| {
        !changed_roots
            .iter()
            .any(|parent| parent != root && root.starts_with(parent))
    });
    for root in changed.iter().rev() {
        let mut root_failed = false;
        if let Some(parent) = root.parent() {
            if let Err(error) = crate::atoms::projectio::rollback_make_dir(&witness, parent) {
                root_failed = true;
                errors.push(format!("rollback-restore-failed {}: {error}", parent.display()));
            }
        }
        let mut nodes = s.nodes.iter().filter(|n| n.path == *root || n.path.starts_with(root)).collect::<Vec<_>>();
        nodes.sort_by_key(|n| n.path.components().count());
        let named = nodes.iter().filter(|n| !matches!(n.kind, Kind::Missing)).map(|n| n.path.clone()).collect::<BTreeSet<_>>();
        for n in &nodes {
            let result = (|| -> Result<(), String> {
                if matches!(n.kind, Kind::Missing) {
                    return restore_missing(root, &n.path, &witness).map_err(|e| format!("rollback-remove-failed {}: {e}", n.path.display()));
                }
                restore_parent_is_safe(root, &n.path)?;
                let existing = match fs::symlink_metadata(&n.path) {
                    Ok(m) => Some(m),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) => return Err(e.to_string()),
                };
                if let Some(m) = &existing {
                    let same = match &n.kind {
                        Kind::Dir => m.file_type().is_dir(),
                        Kind::File(_) => m.file_type().is_file(),
                        Kind::Special => false,
                        Kind::Symlink(_) => m.file_type().is_symlink(),
                        Kind::Missing => false,
                    };
                    if !same && !matches!(n.kind, Kind::File(_)) {
                        remove_changed_kind(root, &n.path, &witness).map_err(|e| format!("rollback-remove-failed {}: {e}", n.path.display()))?;
                    }
                }
                match &n.kind {
                    Kind::Missing => {},
                    Kind::Dir => {
                        if fs::symlink_metadata(&n.path).is_err() { crate::atoms::projectio::rollback_make_dir(&witness, &n.path).map_err(|e| e.to_string())?; }
                        let m = fs::symlink_metadata(&n.path).map_err(|e| e.to_string())?;
                        if m.mode() & 0o700 != 0o700 {
                            crate::atoms::projectio::rollback_mode(&witness, &n.path, (m.mode() & 0o7777) | 0o700).map_err(|e| e.to_string())?;
                        }
                    },
                    Kind::File(hash) => comparison_authorized_write(n, root, hash, &witness)?,
                    Kind::Special => return Err(format!("rollback-shadow-special-file {}", n.path.display())),
                    Kind::Symlink(target) => restore_link(n, target, &witness)?,
                }
                Ok(())
            })();
            if let Err(error) = result {
                root_failed = true;
                if error.starts_with("rollback-remove-failed ") { errors.push(error); }
                else { errors.push(format!("rollback-restore-failed {}: {error}", n.path.display())); }
            }
        }
        // Unnamed entries are visited only after every sealed node was attempted.
        for pass in 0..2 {
            let mut extras = Vec::new();
            let mut failures = BTreeMap::new();
            if named.contains(root) { collect_extras(root, &named, &mut extras, &mut failures); }
            extras.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
            for path in extras {
                if let Err(error) = remove_extra(root, &path, &witness) { failures.insert(path, error); }
            }
            if pass == 1 {
                for (path, error) in failures {
                    root_failed = true;
                    errors.push(format!("rollback-extra-remove-failed {}: {error}", path.display()));
                }
            }
        }
        for n in nodes.iter().rev().filter(|n| matches!(n.kind, Kind::Dir)) {
            let result = restore_parent_is_safe(root, &n.path).and_then(|_| {
                let m = fs::symlink_metadata(&n.path).map_err(|e| e.to_string())?;
                if !m.file_type().is_dir() { return Err("not a directory".into()); }
                restore_owner(&witness, &n.path, n.uid, n.gid)?;
                if m.mode() & 0o7777 != n.mode & 0o7777 {
                    crate::atoms::projectio::rollback_mode(&witness, &n.path, n.mode & 0o7777).map_err(|e| e.to_string())?;
                }
                Ok(())
            });
            if let Err(error) = result {
                root_failed = true;
                errors.push(format!("rollback-restore-failed {}: {error}", n.path.display()));
            }
        }
        if !root_failed { restored_roots.insert(root.clone()); }
    }
    #[cfg(feature = "test-facade")]
    if let Err(error) = mutate_rollback_verification_root(s) {
        errors.push(format!("rollback-test-mutation-failed: {error}"));
    }
    let verification = verify(s);
    for (root, error) in observations {
        if !verification.verified_roots.contains(&root) { errors.push(error); }
    }
    errors.extend(
        verification
            .errors
            .into_iter()
            .map(|error| format!("rollback-final-verify-failed: {error}")),
    );
    restored_paths.retain(|restored_path| {
        verification
            .verified_roots
            .iter()
            .any(|root| root.display().to_string() == *restored_path)
    });
    for root in restored_roots {
        if verification.verified_roots.contains(&root) {
            let restored_path = root.display().to_string();
            if !restored_paths.contains(&restored_path) {
                restored_paths.push(restored_path);
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

pub(crate) fn snapshot_services(plan: &UpdatePlan) -> Result<Vec<ServiceStateSnapshot>, String> {
    plan.services
        .iter()
        .map(|s| {
            crate::atoms::ask::change_unit::snapshot_service_state(&s.name, s.user, s.target_user.as_deref())
        })
        .collect()
}
pub(crate) fn restore_services(states: &[ServiceStateSnapshot], key: &InvocationKey) -> Result<(), String> {
    let mut errors = Vec::new();
    for sealed in states {
        let result = (|| {
            let observed = crate::atoms::ask::change_unit::snapshot_service_state(
                &sealed.name,
                sealed.user,
                sealed.target_user.as_deref(),
            )?;
            if observed.enabled != sealed.enabled || observed.active != sealed.active {
                crate::atoms::r#do::change_unit::restore_service_state(key, sealed)?;
            }
            Ok::<(), String>(())
        })();
        if let Err(error) = result { errors.push(format!("{}: {error}", sealed.name)); }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum TransactionState {
    Open,
    Applied,
    Committed,
    RolledBack,
    RollbackIncomplete,
    RefusedForeignPostImage,
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ProjectionChild {
    pub ordinal: usize,
    pub member: String,
    pub target_indices: Vec<usize>,
    pub service_indices: Vec<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_sha: Option<String>,
}
#[derive(Clone, Debug)]
pub(crate) struct SealedProjection {
    pub profile_id: String,
    pub profile_identity: String,
    pub source_head: String,
    pub children: Vec<ProjectionChild>,
    pub snapshot: Snapshot,
    pub services: Vec<ServiceStateSnapshot>,
    pub gui_face: Option<String>,
    pub gui_member: Option<String>,
    pub caduceus_count: usize,
    pub member_modules: BTreeMap<String, Vec<String>>,
    pub sudoers_fragments: BTreeMap<String, Vec<String>>,
}
#[derive(Clone, Debug)]
pub(crate) struct ProjectionTransaction {
    pub sealed: SealedProjection,
    pub state: TransactionState,
    applied_children: BTreeSet<usize>,
    pub restored_paths: Vec<String>,
    pub rollback_errors: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct TransactionReceipt {
    pub schema: &'static str,
    pub state: TransactionState,
    pub profile_id: String,
    pub profile_identity: String,
    pub source_head: String,
    pub gui: Option<String>,
    #[serde(skip)]
    pub(crate) gui_member: Option<String>,
    #[serde(skip)]
    pub(crate) syzygy_sha: Option<String>,
    #[serde(skip)]
    pub(crate) syzygy_signal: String,
    #[serde(skip)]
    pub(crate) member_modules: BTreeMap<String, Vec<String>>,
    #[serde(skip)]
    pub(crate) held_root_members: BTreeSet<String>,
    #[serde(skip)]
    pub(crate) rollback_ran: bool,
    pub children: Vec<ProjectionChild>,
    pub target_count: usize,
    pub service_count: usize,
    pub caduceus_count: usize,
}
pub(crate) fn validate_exact_root(path: &Path, member: &str) -> Result<(), String> {
    validate_exact_root_at(path, member, Path::new("/"))
}
pub(crate) fn validate_exact_root_at(path: &Path, member: &str, root: &Path) -> Result<(), String> {
    validate_member_scoped_target(path, member)?;
    let containment_root = if member == "sudoers" {
        Path::new("/etc/sudoers.d")
    } else {
        root
    };
    crate::atoms::files::ensure_resolved_containment(containment_root, path)
}
pub(crate) fn seal_projection(
    plan: &UpdatePlan,
    profile_id: &str,
    profile_identity: &str,
    source_head: &str,
    safe_modules: &BTreeSet<String>,
) -> Result<ProjectionTransaction, String> {
    if plan.gui_member.is_none() && plan.gui_face.is_some() {
        return Err("sealed-projection-gui-missing".into());
    }
    for t in &plan.targets {
        validate_exact_root(&t.path, &t.member)?;
    }
    let mut rollback_plan = plan.clone();
    rollback_plan.targets.retain(|target| safe_modules.contains(&target.module));
    rollback_plan.services.retain(|service| safe_modules.contains(&service.module));
    // All planned sudoers names are excluded from supplemental preimages,
    // including names owned by developer-mode modules.
    let sudoers_targets = plan
        .targets
        .iter()
        .filter(|target| target.member == "sudoers")
        .collect::<Vec<_>>();
    let sudoers_step_will_run = safe_modules.contains("sudoers")
        && (plan.member_modules.get("sudoers").is_some_and(|modules| modules.iter().any(|module| module == "sudoers"))
            || sudoers_targets.iter().any(|target| target.module == "sudoers"));
    // Sudoers fragment targets enter this one filesystem snapshot;
    // supplemental sudoers preimages extend it for common rollback.
    let snapshot = if sudoers_step_will_run {
        let selected_names = sudoers_targets
            .iter()
            .map(|target| {
                if target.path.parent() != Some(Path::new("/etc/sudoers.d")) {
                    return Err(format!(
                        "update-set-sudoers-target-invalid {}",
                        target.path.display()
                    ));
                }
                target
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        format!(
                            "update-set-sudoers-target-invalid {}",
                            target.path.display()
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let preimages = crate::tools::files::snapshot_unselected_sudoers_preimages(
            Path::new("/etc/sudoers.d"),
            &selected_names,
        )?;
        snapshot_with_sudoers_preimages(&rollback_plan.targets, &preimages)?
    } else {
        snapshot(&rollback_plan.targets)?
    };
    let services = snapshot_services(&rollback_plan)?;
    let members = if let Some(members) = &plan.pinned_members {
        members.clone()
    } else {
        let mut members = Vec::new();
        for t in &plan.targets {
            if !members.contains(&t.member) {
                members.push(t.member.clone());
            }
        }
        for m in [
            (plan.caduceus_count > 0).then_some("caduceus"),
            Some("sbin"),
            plan.gui_member.as_deref(),
        ] {
            if let Some(m) = m {
                if !members.iter().any(|x| x == m) {
                    members.push(m.to_string());
                }
            }
        }
        members
    };
    let children = members
        .into_iter()
        .enumerate()
        .map(|(ordinal, member)| ProjectionChild {
            ordinal,
            target_indices: plan
                .targets
                .iter()
                .enumerate()
                .filter_map(|(i, t)| (t.member == member).then_some(i))
                .collect(),
            service_indices: plan
                .services
                .iter()
                .enumerate()
                .filter_map(|(i, s)| (s.name == member).then_some(i))
                .collect(),
            source_sha: None,
            member,
        })
        .collect();
    Ok(ProjectionTransaction {
        sealed: SealedProjection {
            profile_id: profile_id.into(),
            profile_identity: profile_identity.into(),
            source_head: source_head.into(),
            children,
            snapshot,
            services,
            gui_face: plan.gui_face.clone(),
            gui_member: plan.gui_member.clone(),
            caduceus_count: plan.caduceus_count,
            member_modules: plan.member_modules.clone(),
            sudoers_fragments: BTreeMap::from([(
                "sudoers".to_owned(),
                plan.targets
                    .iter()
                    .filter(|target| target.member == "sudoers")
                    .filter_map(|target| target.path.file_name()?.to_str().map(str::to_owned))
                    .collect(),
            )]),
        },
        state: TransactionState::Open,
        applied_children: BTreeSet::new(),
        restored_paths: Vec::new(),
        rollback_errors: Vec::new(),
    })
}
impl ProjectionTransaction {
    pub(crate) fn authorize_caduceus_source(
        &mut self,
        authorization: &crate::atoms::ask::beam::BeamConvergenceAuthorization,
    ) -> Result<(), String> {
        let mut children = self
            .sealed
            .children
            .iter_mut()
            .filter(|child| child.member == "caduceus")
            .collect::<Vec<_>>();
        if children.len() != 1 {
            return Err(format!(
                "sealed-caduceus-child-cardinality-{}",
                children.len()
            ));
        }
        children[0].source_sha = Some(authorization.caduceus_sha().to_owned());
        Ok(())
    }
}

pub(crate) fn apply_projection(
    txn: &mut ProjectionTransaction,
    child: usize,
    _key: &InvocationKey,
) -> Result<(), String> {
    if !matches!(txn.state, TransactionState::Open | TransactionState::Applied) {
        return Err("transaction-not-open".into());
    }
    if child >= txn.sealed.children.len() {
        return Err("sealed-child-out-of-range".into());
    }
    if !txn.applied_children.insert(child) {
        return Err("sealed-child-already-applied".into());
    }
    txn.state = TransactionState::Applied;
    Ok(())
}
fn receipt_for(t: &ProjectionTransaction) -> TransactionReceipt {
    TransactionReceipt {
        schema: "harmonia.transaction.v1",
        state: t.state.clone(),
        profile_id: t.sealed.profile_id.clone(),
        profile_identity: t.sealed.profile_identity.clone(),
        source_head: t.sealed.source_head.clone(),
        gui: t.sealed.gui_face.clone(),
        gui_member: t.sealed.gui_member.clone(),
        syzygy_sha: None,
        syzygy_signal: "none".into(),
        member_modules: t.sealed.member_modules.clone(),
        held_root_members: t.sealed.snapshot.roots.iter().map(|root| root.member.clone()).collect(),
        rollback_ran: matches!(t.state, TransactionState::RolledBack | TransactionState::RollbackIncomplete),
        children: t.sealed.children.clone(),
        target_count: t.sealed.snapshot.roots.len(),
        service_count: t.sealed.services.len(),
        caduceus_count: t.sealed.caduceus_count,
    }
}
pub(crate) fn transaction_receipt(t: &ProjectionTransaction) -> TransactionReceipt {
    receipt_for(t)
}
pub(crate) fn commit_projection(
    t: &mut ProjectionTransaction,
) -> Result<TransactionReceipt, String> {
    if t.state == TransactionState::Committed {
        return Ok(receipt_for(t));
    }
    if t.state != TransactionState::Applied
        || t.applied_children.len() != t.sealed.children.len()
    {
        return Err("transaction-not-applied".into());
    }
    t.state = TransactionState::Committed;
    Ok(receipt_for(t))
}
pub(crate) fn rollback_projection(
    t: &mut ProjectionTransaction,
    key: &InvocationKey,
) -> Result<TransactionReceipt, String> {
    if t.state == TransactionState::RolledBack {
        return Ok(receipt_for(t));
    }
    if t.state == TransactionState::Committed {
        return Err("committed-transaction-not-rollbackable".into());
    }
    t.restored_paths.clear();
    t.rollback_errors.clear();
    let prior_shadow = SHADOW.with(|state| std::mem::replace(&mut *state.borrow_mut(), ShadowState::Restoring));
    if let Err(error) = restore(&t.sealed.snapshot, key, &mut t.restored_paths) {
        t.rollback_errors.push(error);
    }
    if let Err(error) = restore_services(&t.sealed.services, key) {
        t.rollback_errors
            .push(format!("rollback-service-restore-failed: {error}"));
    }
    SHADOW.with(|state| *state.borrow_mut() = prior_shadow);
    if t.rollback_errors.is_empty() {
        shadow_not_owed();
        t.state = TransactionState::RolledBack;
        Ok(receipt_for(t))
    } else {
        t.state = TransactionState::RollbackIncomplete;
        Err(format!(
            "rollback-incomplete: {}",
            t.rollback_errors.join("; ")
        ))
    }
}
pub(crate) fn compute_syzygy_sha(
    caduceus: &str,
    sbin: &str,
    gui: Option<&str>,
    keyman: Option<&str>,
) -> Result<String, String> {
    for (member, sha) in [("caduceus", caduceus), ("sbin", sbin)]
        .into_iter()
        .chain(keyman.into_iter().map(|sha| ("keyman", sha)))
        .chain(gui.into_iter().map(|sha| ("gui", sha)))
    {
        if sha.len() != 40
            || !sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(format!("syzygy-source-sha-invalid {member}"));
        }
    }
    let mut bytes = String::with_capacity(160);
    if let Some(gui) = gui {
        bytes.push_str(gui);
    }
    bytes.push_str(caduceus);
    bytes.push_str(sbin);
    if let Some(keyman) = keyman {
        bytes.push_str(keyman);
    }
    Ok(format!("{:x}", Sha256::digest(bytes.as_bytes())))
}

pub(crate) fn project_update_set_v1(r: &TransactionReceipt) -> Value {
    let verdict = match r.state {
        TransactionState::Committed => "ok",
        TransactionState::RolledBack if r.target_count > 0 || r.service_count > 0 => "failed-rolled-back",
        TransactionState::RollbackIncomplete => "failed-rollback-incomplete",
        _ => "failed",
    };
    json!({"schema":"harmonia.update-set.v1","set_name":"appliance-syzygy","profile_id":r.profile_id,"profile_identity":r.profile_identity,"source_head":r.source_head,"gui":r.gui,"gui_member":r.gui_member,"syzygy_sha":r.syzygy_sha,"syzygy_signal":r.syzygy_signal,"set_verdict":verdict,"members":r.children.iter().map(|c| {
        let status = if r.state == TransactionState::Committed {
            "standing"
        } else if !r.held_root_members.contains(&c.member) || !r.rollback_ran {
            "not-restored"
        } else if r.state == TransactionState::RollbackIncomplete {
            "rollback-incomplete"
        } else if r.state == TransactionState::RolledBack {
            "rolled-back"
        } else {
            "not-restored"
        };
        json!({"ordinal":c.ordinal,"member":c.member,"status":status})
    }).collect::<Vec<_>>(),"targets":r.target_count,"services":r.service_count,"caduceus_count":r.caduceus_count})
}

#[cfg(test)]
mod update_set_root_containment_tests {
    use super::validate_exact_root_at;
    use std::{fs, os::unix::fs::symlink, path::Path};

    #[test]
    fn fake_root_target_resolves_and_escaping_parent_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let outside = dir.path().join("outside");
        fs::create_dir_all(root.join("usr/local/bin")).unwrap();
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink("bin", root.join("usr/local/alias")).unwrap();
        assert!(
            validate_exact_root_at(&root.join("usr/local/alias/target"), "caduceus", &root).is_ok()
        );
        symlink(&outside, root.join("usr/local/sbin")).unwrap();
        assert!(validate_exact_root_at(
            &root.join("usr/local/sbin/target"),
            "sbin",
            &root
        ).is_err());
    }
}

#[cfg(test)]
mod syzygy_sha_tests {
    use super::compute_syzygy_sha;
    #[test]
    fn fixed_member_order_changes_digest() {
        let a =
            compute_syzygy_sha(&"0".repeat(40), &"1".repeat(40), Some(&"2".repeat(40)), None).unwrap();
        let b =
            compute_syzygy_sha(&"1".repeat(40), &"0".repeat(40), Some(&"2".repeat(40)), None).unwrap();
        assert_ne!(a, b);
    }
    #[test]
    fn empty_gui_contributes_no_bytes() {
        assert_eq!(
            compute_syzygy_sha(
                "0000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000001",
                None,
                None
            )
            .unwrap(),
            "4db7b49a94a77aa7f21dfab94156b5f6934670f0b801ee2a9784e4171b91660c"
        );
    }
    #[test]
    fn source_shas_require_lowercase_hex() {
        assert!(compute_syzygy_sha(&"A".repeat(40), &"1".repeat(40), None, None).is_err());
        let d = compute_syzygy_sha(&"a".repeat(40), &"f".repeat(40), None, None).unwrap();
        assert!(d
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
    #[test]
    fn known_answer_vector() {
        assert_eq!(
            compute_syzygy_sha(
                "0123456789abcdef0123456789abcdef01234567",
                &"a".repeat(40),
                Some(&"f".repeat(40)),
                None
            )
            .unwrap(),
            "9061b13dce037de65c9940e0c7777b923bc4444c0ecbf765c6d19c1d8308972d"
        );
    }
}

#[cfg(test)]
mod update_set_receipt_tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn committed_unresolvable_sbin_still_writes_update_set() {
        let dir = tempfile::tempdir().expect("receipt directory");
        // Exercise receipt persistence with an unresolved resolver result,
        // independent of the machine's schema door, forge, or credentials.
        let caduceus_sha = "a".repeat(40);
        let signal = "syzygy-flag-unresolvable sbin";
        let mut member_modules = BTreeMap::new();
        member_modules.insert("caduceus".into(), vec!["caduceus".into()]);
        member_modules.insert("sbin".into(), vec!["sbin".into()]);
        let receipt = TransactionReceipt {
            schema: "harmonia.transaction.v1",
            state: TransactionState::Committed,
            profile_id: "test".into(),
            profile_identity: "test".into(),
            source_head: "unresolved".into(),
            gui: None,
            gui_member: None,
            syzygy_sha: None,
            syzygy_signal: "none".into(),
            member_modules,
            held_root_members: Default::default(),
            rollback_ran: false,
            children: vec![
                ProjectionChild {
                    ordinal: 0,
                    member: "caduceus".into(),
                    target_indices: vec![],
                    service_indices: vec![],
                    source_sha: None,
                },
                ProjectionChild {
                    ordinal: 1,
                    member: "sbin".into(),
                    target_indices: vec![],
                    service_indices: vec![],
                    source_sha: None,
                },
            ],
            target_count: 0,
            service_count: 0,
            caduceus_count: 1,
        };
        let mint = crate::atoms::attest::SyzygyEvidence {
            mint: crate::atoms::attest::SyzygyMint {
                caduceus_sha: caduceus_sha.clone(),
                partner_sha: String::new(),
                keyman_sha: None,
                gui_sha: None,
                syzygy_sha: None,
                env_sha: "e".repeat(64),
                signal: signal.into(),
            },
            member_flags: serde_json::json!({
                "caduceus": {
                    "source_sha": caduceus_sha,
                    "flagged_at": "2026-09-08T00:00:00Z",
                    "malformed_flags": 0
                },
                "sbin": signal
            }),
            observations: serde_json::json!({"signals": [signal]}),
        };
        crate::atoms::attest::write_transaction_receipt(dir.path(), &receipt, &mint, None)
            .expect("update-set receipt");
        let value: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("update-set.json")).expect("update-set.json"),
        )
        .expect("valid update-set.json");
        assert_eq!(value["syzygy_sha"], serde_json::Value::Null);
        assert_eq!(value["syzygy_signal"], signal);
        assert_eq!(value["schema"], "harmonia.update-set.v1");
        assert_eq!(value["set_verdict"], "ok");
        assert_eq!(value["member_flags"], mint.member_flags);
        assert_eq!(value["member_flag_observations"], mint.observations);
        let members = value["members"].as_array().expect("member receipts");
        assert_eq!(members.len(), 2);
        for (member, source_sha) in [
            ("caduceus", serde_json::json!(caduceus_sha)),
            ("sbin", serde_json::Value::Null),
        ] {
            let child = members.iter().find(|child| child["member"] == member)
                .expect("declared member");
            assert_eq!(child["source_sha"], source_sha);
            assert_eq!(child["status"], "standing");
        }
    }
}
