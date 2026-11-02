//! One-owner durable transactional ritual: observe, compare, act, attest, seal, recover.
use super::transaction::{Target, UpdatePlan};
use crate::atoms::r#do::InvocationKey;
use crate::atoms::ask::change_unit::ServiceStateSnapshot;
use crate::*;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::fd::{AsRawFd, FromRawFd},
    os::unix::{ffi::OsStrExt, fs::{MetadataExt, OpenOptionsExt, PermissionsExt}},
    path::{Path, PathBuf},
    rc::Rc,
};

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
    pub(crate) roots: Vec<Target>,
    nodes: Vec<Node>,
}

// These preimages belong to this press, not the installed product. The owner
// removes only the files it created, both on an explicit close and on unwind.
#[derive(Debug)]
struct PressBackup {
    path: PathBuf,
    directory: Rc<fs::File>,
    files: BTreeMap<PathBuf, (u64, u64)>,
    roots: Vec<PathBuf>,
    closed: Cell<bool>,
}

#[derive(Debug)]
struct PromotionBackup { path: PathBuf, directory: Rc<fs::File> }
type PromotionFiles = BTreeMap<PathBuf, Vec<PromotionBackup>>;

fn open_child(parent: &fs::File, name: &std::ffi::OsStr, directory: bool) -> std::io::Result<fs::File> {
    let name = CString::new(name.as_bytes()).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 { return Err(std::io::Error::last_os_error()); }
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

fn open_absolute_directory(path: &Path) -> std::io::Result<fs::File> {
    if !path.is_absolute() { return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput)); }
    let mut current = fs::OpenOptions::new().read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC).open("/")?;
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {},
            std::path::Component::Normal(name) => current = open_child(&current, name, true)?,
            _ => return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput)),
        }
    }
    Ok(current)
}

// Walk from an opened receipt directory and retain each opened backup parent;
// no pathname component supplied by a receipt is followed as a symlink.
// A failed branch does not discard the backups found in other branches.
fn promotion_backups(backup: &PressBackup) -> (PromotionFiles, Vec<String>) {
    let mut result = PromotionFiles::new();
    let mut errors = Vec::new();
    let Some(receipt_dir) = backup.path.parent() else { return (result, vec!["rollback-backup-parent-missing".into()]); };
    let modules = match open_child(&backup.directory, std::ffi::OsStr::new("modules"), true) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (result, errors),
        Err(e) => return (result, vec![format!("rollback-backup-modules-open-failed: {e}")]),
    };
    let mut pending = vec![(Rc::new(modules), receipt_dir.join("modules"))];
    while let Some((directory, path)) = pending.pop() {
        let entries = match fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd())) {
            Ok(entries) => entries,
            Err(e) => { errors.push(format!("rollback-backup-receipt-walk-failed {}: {e}", path.display())); continue; }
        };
        for entry in entries {
            let entry = match entry { Ok(entry) => entry, Err(e) => { errors.push(format!("rollback-backup-receipt-walk-failed: {e}")); continue; } };
            let kind = match entry.file_type() { Ok(kind) => kind, Err(e) => { errors.push(format!("rollback-backup-receipt-observe-failed: {e}")); continue; } };
            let name = entry.file_name();
            if kind.is_symlink() {
                errors.push(format!("rollback-backup-receipt-symlink {}", path.join(&name).display()));
                continue;
            }
            if kind.is_dir() {
                match open_child(&directory, &name, true) {
                    Ok(child) => pending.push((Rc::new(child), path.join(&name))),
                    Err(e) => errors.push(format!("rollback-backup-directory-open-failed {}: {e}", path.join(&name).display())),
                }
                continue;
            }
            if !kind.is_file() || name != "routine-child.json" { continue; }
            let receipt = (|| -> Result<Value, String> {
                let mut file = open_child(&directory, &name, false).map_err(|e| format!("rollback-backup-receipt-open-failed: {e}"))?;
                if !file.metadata().map_err(|e| format!("rollback-backup-receipt-stat-failed: {e}"))?.is_file() { return Err("rollback-backup-receipt-not-regular".into()); }
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes).map_err(|e| format!("rollback-backup-receipt-read-failed: {e}"))?;
                serde_json::from_slice(&bytes).map_err(|e| format!("rollback-backup-receipt-invalid: {e}"))
            })();
            let receipt = match receipt { Ok(receipt) => receipt, Err(e) => { errors.push(e); continue; } };
            if !crate::receipts::is_current_run_receipt(&receipt) || receipt.get("tool").and_then(Value::as_str) != Some("place-file") { continue; }
            let Some(target) = receipt.pointer("/outputs/path").and_then(Value::as_str).map(PathBuf::from) else { continue; };
            if !backup.files.contains_key(&target) { continue; }
            let expected = path.join("backups/prior-binary");
            for child in receipt.get("receipts").and_then(Value::as_array).into_iter().flatten() {
                let Some(recorded) = child.pointer("/movement/backed_up").and_then(Value::as_str).map(PathBuf::from) else { continue; };
                let recorded = if recorded.is_absolute() { recorded } else {
                    match std::env::current_dir() { Ok(cwd) => cwd.join(recorded), Err(e) => { errors.push(format!("rollback-backup-current-dir-failed: {e}")); continue; } }
                };
                if recorded != expected {
                    errors.push(format!("rollback-promotion-backup-outside-default {}", recorded.display()));
                    continue;
                }
                let parent = match open_child(&directory, std::ffi::OsStr::new("backups"), true) {
                    Ok(parent) => Rc::new(parent),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => { errors.push(format!("rollback-promotion-backup-parent-unsafe {}: {e}", expected.display())); continue; }
                };
                match open_child(&parent, std::ffi::OsStr::new("prior-binary"), false).and_then(|f| f.metadata()) {
                    Ok(metadata) if metadata.is_file() => result.entry(target.clone()).or_default().push(PromotionBackup { path: expected.clone(), directory: parent }),
                    Ok(_) => errors.push(format!("rollback-promotion-backup-not-regular {}", expected.display())),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                    Err(e) => errors.push(format!("rollback-promotion-backup-observe-failed {}: {e}", expected.display())),
                }
            }
        }
    }
    (result, errors)
}

fn remove_promotion_backups(backups: &PromotionFiles) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    let mut errors = Vec::new();
    for backup in backups.values().flatten() {
        if !seen.insert(&backup.path) { continue; }
        let name = CString::new("prior-binary").expect("literal contains no NUL");
        if unsafe { libc::unlinkat(backup.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            errors.push(format!("rollback-promotion-backup-cleanup-failed {}: {}", backup.path.display(), std::io::Error::last_os_error()));
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}
impl PressBackup {
    fn create(snapshot: &Snapshot, receipt_dir: &Path) -> Result<Option<Rc<Self>>, String> {
        let receipt_dir = if receipt_dir.is_absolute() {
            receipt_dir.to_path_buf()
        } else {
            std::env::current_dir().map_err(|error| format!("rollback-backup-current-dir-failed: {error}"))?.join(receipt_dir)
        };
        let mut candidates = BTreeMap::new();
        let mut roots = Vec::new();
        for root in &snapshot.roots {
            if root.member == "sudoers" { continue; }
            roots.push(root.path.clone());
            for node in &snapshot.nodes {
                if node.path == root.path || node.path.starts_with(&root.path) {
                    if let Kind::File(bytes) = &node.kind {
                        candidates.insert(node.path.clone(), bytes);
                    }
                }
            }
        }
        if candidates.is_empty() { return Ok(None); }
        // One file makes green cleanup one unlink: a cleanup failure cannot
        // remove only some preimages before the caller attempts rollback.
        let path = receipt_dir.join(".harmonia-press-preimages");
        let directory = Rc::new(open_absolute_directory(&receipt_dir)
            .map_err(|error| format!("rollback-backup-root-open-failed: {error}"))?);
        let name = CString::new(".harmonia-press-preimages").expect("literal contains no NUL");
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600) };
        if fd < 0 { return Err(format!("rollback-backup-create-failed: {}", std::io::Error::last_os_error())); }
        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        let mut guard = Self { path, directory, files: BTreeMap::new(), roots, closed: Cell::new(false) };
        let mut offset = 0u64;
        for (target, bytes) in candidates {
            let length = u64::try_from(bytes.len()).map_err(|_| "rollback-backup-length-invalid")?;
            guard.files.insert(target, (offset, length));
            file.write_all(bytes).map_err(|error| format!("rollback-backup-write-failed: {error}"))?;
            offset = offset.checked_add(length).ok_or("rollback-backup-length-invalid")?;
        }
        Ok(Some(Rc::new(guard)))
    }
    fn bytes(&self, path: &Path, expected: &[u8], promotions: &PromotionFiles) -> Result<Option<Vec<u8>>, String> {
        if let Some(paths) = promotions.get(path) {
            for promotion in paths {
                let Ok(file) = open_child(&promotion.directory, std::ffi::OsStr::new("prior-binary"), false) else { continue; };
                let mut bytes = Vec::new();
                if file.take(expected.len() as u64 + 1).read_to_end(&mut bytes).is_ok()
                    && Sha256::digest(&bytes) == Sha256::digest(expected) { return Ok(Some(bytes)); }
            }
            // A damaged producer backup must not prevent restoration from the
            // independently sealed and identity-checked press preimage below.
        }
        let Some((offset, length)) = self.files.get(path) else {
            if self.roots.iter().any(|root| path == root || path.starts_with(root)) {
                return Err(format!("rollback-backup-entry-missing {}", path.display()));
            }
            return Ok(None);
        };
        let length = usize::try_from(*length).map_err(|_| "rollback-backup-length-invalid")?;
        let mut file = open_child(&self.directory, std::ffi::OsStr::new(".harmonia-press-preimages"), false)
            .map_err(|error| format!("rollback-backup-read-failed: {error}"))?;
        file.seek(SeekFrom::Start(*offset)).map_err(|error| format!("rollback-backup-read-failed: {error}"))?;
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes).map_err(|error| format!("rollback-backup-read-failed: {error}"))?;
        if Sha256::digest(&bytes) != Sha256::digest(expected) {
            return Err(format!("rollback-backup-identity-mismatch {}", path.display()));
        }
        Ok(Some(bytes))
    }
    fn close(&self) -> Result<(), String> {
        if self.closed.get() { return Ok(()); }
        let name = CString::new(".harmonia-press-preimages").expect("literal contains no NUL");
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(format!("rollback-backup-cleanup-failed: {}", std::io::Error::last_os_error()));
        }
        self.closed.set(true);
        Ok(())
    }
}
impl Drop for PressBackup {
    fn drop(&mut self) { let _ = self.close(); }
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
            kind: Kind::File(preimage.bytes.clone()),
            mode: preimage.mode,
            uid: preimage.uid,
            gid: preimage.gid,
        });
    }
    Ok(snapshot)
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
    } else {
        match fs::read(p) {
            Ok(bytes) => Kind::File(bytes),
            Err(error) => {
                errors.push(format!(
                    "rollback-capture-failed {}: {error}",
                    p.display()
                ));
                return;
            }
        }
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

fn comparison_authorized_write(path: &Path, bytes: &[u8], mode: Option<u32>, key: &InvocationKey) -> Result<(), String> {
    let desired = bytes.to_vec();
    let path = path.to_path_buf();
    crate::atoms::comparison::execute_once(
        "ritual-restore-write",
        || Ok::<_, String>(fs::read(&path).ok()),
        |observed| if observed.as_deref() == Some(desired.as_slice()) { crate::atoms::comparison::DiffDecision::Empty } else { crate::atoms::comparison::DiffDecision::Different },
        |authorization, _| crate::atoms::r#do::write_file::atomic_write_bytes_with_ownership(&authorization, key, &path, &desired, mode, None, None),
    ).map(|_| ())
}

pub(crate) fn restore(
    s: &Snapshot,
    key: &InvocationKey,
    restored_paths: &mut Vec<String>,
) -> Result<(), String> {
    restore_with_backup(s, key, restored_paths, None, &BTreeMap::new())
}
fn restore_with_backup(
    s: &Snapshot,
    key: &InvocationKey,
    restored_paths: &mut Vec<String>,
    backup: Option<&PressBackup>,
    promotions: &PromotionFiles,
) -> Result<(), String> {
    // Refuse before removing any promoted path if a press preimage is gone
    // or has changed. Restore will read the same owned preimages below.
    if let Some(backup) = backup {
        for node in &s.nodes {
            if let Kind::File(bytes) = &node.kind { backup.bytes(&node.path, bytes, promotions)?; }
        }
    }
    let mut changed = Vec::new();
    let mut errors = Vec::new();
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
            Err(error) => errors.push(format!(
                "rollback-observe-failed {}: {error}",
                root.path.display()
            )),
        }
    }
    let changed_roots = changed.clone();
    changed.retain(|root| {
        !changed_roots
            .iter()
            .any(|parent| parent != root && root.starts_with(parent))
    });
    for root in changed.iter().rev() {
        if let Err(error) = rm(root) {
            errors.push(format!(
                "rollback-remove-failed {}: {error}",
                root.display()
            ));
            continue;
        }
        let mut root_failed = false;
        for n in &s.nodes {
            if !(n.path == *root || n.path.starts_with(root.join(""))) {
                continue;
            }
            let result = (|| -> Result<(), String> {
                match &n.kind {
                    Kind::Missing => return Ok(()),
                    Kind::Dir => fs::create_dir_all(&n.path).map_err(|e| e.to_string())?,
                    Kind::File(b) => {
                        if let Some(p) = n.path.parent() {
                            fs::create_dir_all(p).map_err(|e| e.to_string())?;
                        }
                        let saved = match backup { Some(backup) => backup.bytes(&n.path, b, promotions)?, None => None };
                        comparison_authorized_write(&n.path, saved.as_deref().unwrap_or(b), Some(n.mode & 0o7777), key)?;
                    }
                    Kind::Symlink(t) => {
                        if let Some(p) = n.path.parent() {
                            fs::create_dir_all(p).map_err(|e| e.to_string())?;
                        }
                        std::os::unix::fs::symlink(t, &n.path).map_err(|e| e.to_string())?;
                    }
                }
                if !matches!(n.kind, Kind::Missing | Kind::Symlink(_)) {
                    restore_owner(&n.path, n.uid, n.gid)?;
                    fs::set_permissions(&n.path, fs::Permissions::from_mode(n.mode & 0o7777))
                        .map_err(|e| e.to_string())?;
                }
                Ok(())
            })();
            if let Err(error) = result {
                root_failed = true;
                errors.push(format!(
                    "rollback-restore-failed {}: {error}",
                    n.path.display()
                ));
                break;
            }
        }
        if !root_failed {
            restored_roots.insert(root.clone());
        }
    }
    #[cfg(feature = "test-facade")]
    if let Err(error) = mutate_rollback_verification_root(s) {
        errors.push(format!("rollback-test-mutation-failed: {error}"));
    }
    let verification = verify(s);
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
    for sealed in states {
        let observed = crate::atoms::ask::change_unit::snapshot_service_state(
            &sealed.name,
            sealed.user,
            sealed.target_user.as_deref(),
        )?;
        if observed.enabled != sealed.enabled || observed.active != sealed.active {
            crate::atoms::r#do::change_unit::restore_service_state(key, sealed)?;
        }
    }
    Ok(())
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
    backup: Option<Rc<PressBackup>>,
    pub services: Vec<ServiceStateSnapshot>,
    pub service_members: Vec<String>,
    pub prior_caduceus_identity: Result<String, String>,
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
    producer_rollback_members: BTreeSet<String>,
    pub restored_paths: Vec<String>,
    pub restored_members: Vec<RestoredMember>,
    pub rollback_errors: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct RestoredMember {
    pub member: String,
    pub prior_identity: Option<String>,
    pub attempted_identity: Option<String>,
    pub running_identity: Option<String>,
    pub ok: bool,
    pub signal: Option<String>,
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
) -> Result<ProjectionTransaction, String> {
    seal_projection_inner(plan, profile_id, profile_identity, source_head, None)
}
pub(crate) fn seal_projection_at_receipt(
    plan: &UpdatePlan,
    profile_id: &str,
    profile_identity: &str,
    source_head: &str,
    receipt_dir: &Path,
) -> Result<ProjectionTransaction, String> {
    seal_projection_inner(plan, profile_id, profile_identity, source_head, Some(receipt_dir))
}
fn seal_projection_inner(
    plan: &UpdatePlan,
    profile_id: &str,
    profile_identity: &str,
    source_head: &str,
    receipt_dir: Option<&Path>,
) -> Result<ProjectionTransaction, String> {
    if plan.gui_member.is_none() && plan.gui_face.is_some() {
        return Err("sealed-projection-gui-missing".into());
    }
    for t in &plan.targets {
        validate_exact_root(&t.path, &t.member)?;
    }
    let sudoers_targets = plan
        .targets
        .iter()
        .filter(|target| target.member == "sudoers")
        .collect::<Vec<_>>();
    let sudoers_step_will_run = plan.member_modules.contains_key("sudoers");
    // Sudoers fragment targets enter this one filesystem snapshot;
    // supplemental sudoers preimages extend it for common rollback.
    let snapshot = if sudoers_step_will_run || !sudoers_targets.is_empty() {
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
        snapshot_with_sudoers_preimages(&plan.targets, &preimages)?
    } else {
        snapshot(&plan.targets)?
    };
    let services = snapshot_services(plan)?;
    let prior_caduceus_identity = if plan.caduceus_count > 0 || plan.targets.iter().any(|target| target.member == "caduceus") {
        crate::atoms::ask::beam::door_url().map_err(str::to_owned)
            .and_then(|url| crate::atoms::ask::beam::fetch_door(&url))
            .map(|door| door.caduceus_sha)
    } else {
        Err("rollback-caduceus-not-present".into())
    };
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
                .filter_map(|(i, s)| (s.member == member).then_some(i))
                .collect(),
            source_sha: None,
            member,
        })
        .collect();
    let backup = match receipt_dir { Some(dir) => PressBackup::create(&snapshot, dir)?, None => None };
    Ok(ProjectionTransaction {
        sealed: SealedProjection {
            profile_id: profile_id.into(),
            profile_identity: profile_identity.into(),
            source_head: source_head.into(),
            children,
            snapshot,
            backup,
            services,
            service_members: plan.services.iter().map(|service| service.member.clone()).collect(),
            prior_caduceus_identity,
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
        producer_rollback_members: BTreeSet::new(),
        restored_paths: Vec::new(),
        restored_members: Vec::new(),
        rollback_errors: Vec::new(),
    })
}
impl ProjectionTransaction {
    // A producer may restore itself before the outer snapshot comparison.
    // Preserve its member as a potential promotion; missing attempted identity
    // must then be an explicit incomplete signal, not an omitted row.
    pub(crate) fn note_producer_rollbacks(&mut self, steps: &[Value]) {
        for step in steps {
            let Some(signal) = step.pointer("/outcome/first_missing_signal").and_then(Value::as_str) else { continue; };
            if !signal.contains("rollback_process_verified=") { continue; }
            let Some(module) = step.get("module").and_then(Value::as_str) else { continue; };
            for (member, modules) in &self.sealed.member_modules {
                if modules.iter().any(|value| value == module) {
                    self.producer_rollback_members.insert(member.clone());
                }
            }
        }
    }
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
    if let Some(backup) = &t.sealed.backup {
        let (promotions, errors) = promotion_backups(backup);
        if !errors.is_empty() { return Err(errors.join("; ")); }
        remove_promotion_backups(&promotions)?;
        backup.close()?;
    }
    t.state = TransactionState::Committed;
    Ok(receipt_for(t))
}

fn member_identity_path(snapshot: &Snapshot, member: &str) -> Option<PathBuf> {
    let roots = snapshot.roots.iter().filter(|root| root.member == member);
    if member == "sbin" {
        return roots.map(|root| if root.path.file_name() == Some(std::ffi::OsStr::new("cli.py")) { root.path.clone() } else { root.path.join("cli.py") })
            .find(|path| snapshot.nodes.iter().any(|node| node.path == *path && matches!(node.kind, Kind::File(_))));
    }
    roots.map(|root| root.path.clone())
        .find(|path| snapshot.nodes.iter().any(|node| node.path == *path && matches!(node.kind, Kind::File(_))))
}

fn before_digest(snapshot: &Snapshot, path: &Path) -> Option<String> {
    snapshot.nodes.iter().find_map(|node| {
        if node.path != path { return None; }
        match &node.kind {
            Kind::File(bytes) => Some(format!("{:x}", Sha256::digest(bytes))),
            _ => None,
        }
    })
}

fn current_digest(path: &Path) -> Option<String> {
    fs::read(path).ok().map(|bytes| format!("{:x}", Sha256::digest(bytes)))
}

fn current_caduceus_identity() -> Result<String, String> {
    let url = crate::atoms::ask::beam::door_url().map_err(str::to_owned)?;
    crate::atoms::ask::beam::fetch_door(&url).map(|door| door.caduceus_sha)
}

fn restart_restored_service(state: &ServiceStateSnapshot, key: &InvocationKey) -> Result<(), String> {
    use crate::atoms::comparison::DiffDecision;
    use crate::atoms::r#do::change_unit::{unit_change_scoped, UnitVerb};
    crate::atoms::comparison::execute_once(
        "rollback-restart-restored-service",
        || Ok::<_, String>(()),
        |_| DiffDecision::Different,
        |authorization, _| {
            let result = unit_change_scoped(&authorization, key, &state.name, UnitVerb::Restart,
                state.user, state.target_user.as_deref(), 30)?;
            if result.ok { Ok(()) } else { Err(format!("rollback-restart-failed {}", state.name)) }
        },
    ).map(|_| ())
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
    t.restored_members.clear();
    t.rollback_errors.clear();
    let mut changed_members = t.producer_rollback_members.clone();
    let mut observed_changed_members = BTreeSet::new();
    let mut unobserved_members = BTreeSet::new();
    for root in &t.sealed.snapshot.roots {
        match root_matches_snapshot(&root.path, &t.sealed.snapshot.nodes) {
            Ok(false) => { changed_members.insert(root.member.clone()); observed_changed_members.insert(root.member.clone()); }
            Ok(true) => {}
            Err(error) => {
                changed_members.insert(root.member.clone());
                unobserved_members.insert(root.member.clone());
                t.rollback_errors.push(format!("rollback-member-observation-failed member={} path={}: {error}", root.member, root.path.display()));
            }
        }
    }
    // A producer can restore its own bytes before the outer rollback runs.
    // The still-running process is a separate witness of a promoted member.
    if let (Ok(prior), Ok(running)) = (&t.sealed.prior_caduceus_identity, current_caduceus_identity()) {
        if prior != &running { changed_members.insert("caduceus".to_owned()); }
    }
    for member in &changed_members {
        let identity_path = member_identity_path(&t.sealed.snapshot, member);
        let (prior, attempted) = if member == "caduceus" {
            let prior = t.sealed.prior_caduceus_identity.clone().ok();
            let attempted = t.sealed.children.iter()
                .find(|child| child.member == *member).and_then(|child| child.source_sha.clone())
                .or_else(|| current_caduceus_identity().ok().filter(|running| Some(running) != prior.as_ref()));
            (prior, attempted)
        } else {
            let prior = identity_path.as_deref().and_then(|path| before_digest(&t.sealed.snapshot, path));
            let attempted = if t.producer_rollback_members.contains(member) && !observed_changed_members.contains(member) {
                None
            } else { identity_path.as_deref().and_then(current_digest) };
            (prior, attempted)
        };
        t.restored_members.push(RestoredMember {
            member: member.clone(), prior_identity: prior, attempted_identity: attempted,
            running_identity: None, ok: false, signal: None,
        });
    }
    let promotions = if let Some(backup) = t.sealed.backup.as_deref() {
        let (promotions, errors) = promotion_backups(backup);
        t.rollback_errors.extend(errors);
        promotions
    } else { BTreeMap::new() };
    if let Err(error) = restore_with_backup(&t.sealed.snapshot, key, &mut t.restored_paths, t.sealed.backup.as_deref(), &promotions) {
        t.rollback_errors.push(error);
    }
    let mut unrestored_members = BTreeSet::new();
    for root in &t.sealed.snapshot.roots {
        match root_matches_snapshot(&root.path, &t.sealed.snapshot.nodes) {
            Ok(true) => {}
            Ok(false) => { unrestored_members.insert(root.member.clone()); }
            Err(error) => {
                unrestored_members.insert(root.member.clone());
                t.rollback_errors.push(format!("rollback-member-readback-failed member={} path={}: {error}", root.member, root.path.display()));
            }
        }
    }
    let mut failed_service_members = BTreeSet::new();
    for (state, member) in t.sealed.services.iter().zip(&t.sealed.service_members) {
        if unrestored_members.contains(member) {
            failed_service_members.insert(member.clone());
            t.rollback_errors.push(format!("rollback-service-restore-skipped-unrestored member={member} service={}", state.name));
            continue;
        }
        if let Err(error) = crate::atoms::r#do::change_unit::restore_service_state(key, state) {
            failed_service_members.insert(member.clone());
            t.rollback_errors.push(format!("rollback-service-restore-failed member={member}: {error}"));
            continue;
        }
        if state.active && changed_members.contains(member) {
            if let Err(error) = restart_restored_service(state, key) {
                failed_service_members.insert(member.clone());
                t.rollback_errors.push(format!("rollback-service-restart-failed member={member}: {error}"));
            }
        }
    }
    for row in &mut t.restored_members {
        let path = member_identity_path(&t.sealed.snapshot, &row.member);
        // A file digest is a CLI identity, not proof of an active service's
        // process image. Only Caduceus has a running-identity observation.
        let active_service = t.sealed.services.iter().zip(&t.sealed.service_members)
            .any(|(state, member)| state.active && member == &row.member);
        row.running_identity = if row.member == "caduceus" {
            current_caduceus_identity().ok()
        } else if row.member == "sbin" && !active_service {
            path.as_deref().and_then(current_digest)
        } else {
            None
        };
        let identity_unprovable = row.member != "caduceus" && (row.member != "sbin" || active_service);
        let matches = row.prior_identity.is_some() && row.attempted_identity.is_some()
            && row.running_identity == row.prior_identity;
        row.ok = !unrestored_members.contains(&row.member) && !unobserved_members.contains(&row.member)
            && !failed_service_members.contains(&row.member)
            && !identity_unprovable && matches;
        if !row.ok {
            let signal = if unobserved_members.contains(&row.member) { "rollback-member-pre-restore-observation-failed" }
                else if unrestored_members.contains(&row.member) { "rollback-member-files-unrestored" }
                else if failed_service_members.contains(&row.member) { "rollback-member-service-restore-failed" }
                else if identity_unprovable { "rollback-running-identity-unavailable" }
                else if row.prior_identity.is_none() { "rollback-prior-identity-unavailable" }
                else if row.attempted_identity.is_none() { "rollback-attempted-identity-unavailable" }
                else if row.running_identity.is_none() { "rollback-running-identity-unavailable" }
                else { "rollback-running-identity-mismatch" };
            row.signal = Some(signal.into());
            t.rollback_errors.push(format!("{signal} member={}", row.member));
        }
    }
    if let Some(backup) = &t.sealed.backup {
        if let Err(error) = remove_promotion_backups(&promotions) { t.rollback_errors.push(error); }
        if let Err(error) = backup.close() { t.rollback_errors.push(error); }
    }
    if t.rollback_errors.is_empty() {
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
        TransactionState::RolledBack => "failed-rolled-back",
        TransactionState::RollbackIncomplete => "failed-rollback-incomplete",
        TransactionState::RefusedForeignPostImage => "refused-foreign-post-image",
        _ => "failed",
    };
    let member_status = if r.state == TransactionState::Committed {
        "standing"
    } else if r.state == TransactionState::RollbackIncomplete {
        "rollback-incomplete"
    } else {
        "rolled-back"
    };
    json!({"schema":"harmonia.update-set.v1","set_name":"appliance-syzygy","profile_id":r.profile_id,"profile_identity":r.profile_identity,"source_head":r.source_head,"gui":r.gui,"gui_member":r.gui_member,"syzygy_sha":r.syzygy_sha,"syzygy_signal":r.syzygy_signal,"set_verdict":verdict,"members":r.children.iter().map(|c|json!({"ordinal":c.ordinal,"member":c.member,"status":member_status})).collect::<Vec<_>>(),"targets":r.target_count,"services":r.service_count,"caduceus_count":r.caduceus_count})
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
