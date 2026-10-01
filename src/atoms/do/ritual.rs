//! One-owner durable transactional ritual: observe, compare, act, attest, seal, recover.
use super::transaction::{Target, UpdatePlan, PAM_SUDO_MEMBER, PAM_SUDO_TARGET};
use crate::atoms::r#do::InvocationKey;
use crate::atoms::ask::change_unit::ServiceStateSnapshot;
use crate::*;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
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
    if member == PAM_SUDO_MEMBER {
        if path.to_str() != Some(PAM_SUDO_TARGET) {
            return Err(format!(
                "update-set-pam-sudo-target-invalid {}",
                path.display()
            ));
        }
        return crate::atoms::files::ensure_resolved_containment(Path::new("/etc/pam.d"), path);
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
                        comparison_authorized_write(&n.path, b, Some(n.mode & 0o7777), key)?;
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
    pub children: Vec<ProjectionChild>,
    pub target_count: usize,
    pub service_count: usize,
    pub caduceus_count: usize,
}
pub(crate) fn validate_exact_root(path: &Path, member: &str) -> Result<(), String> {
    validate_exact_root_at(path, member, Path::new("/"))
}
pub(crate) fn validate_exact_root_at(path: &Path, member: &str, root: &Path) -> Result<(), String> {
    if member == PAM_SUDO_MEMBER && root != Path::new("/") {
        let expected = root.join(PAM_SUDO_TARGET.trim_start_matches('/'));
        if path != expected {
            return Err(format!(
                "update-set-pam-sudo-target-invalid {}",
                path.display()
            ));
        }
        // Validate the exact logical target under the supplied test/alternate
        // root; do not resolve the host's live /etc/pam.d while proving a
        // scratch-root transaction.
        return crate::atoms::files::ensure_resolved_containment(root, path);
    }
    validate_member_scoped_target(path, member)?;
    let containment_root = if member == "sudoers" {
        Path::new("/etc/sudoers.d")
    } else if member == PAM_SUDO_MEMBER {
        Path::new("/etc/pam.d")
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
    if plan.gui_member.is_none() && plan.gui_face.is_some() {
        return Err("sealed-projection-gui-missing".into());
    }
    let pam_sudo_targets = plan
        .targets
        .iter()
        .filter(|target| target.member == PAM_SUDO_MEMBER)
        .collect::<Vec<_>>();
    if (plan.member_modules.contains_key(PAM_SUDO_MEMBER) || !pam_sudo_targets.is_empty())
        && pam_sudo_targets.len() != 1
    {
        return Err(format!(
            "update-set-pam-sudo-target-cardinality-{}",
            pam_sudo_targets.len()
        ));
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
    // Both the PAM-Sudo target and sudoers fragment targets enter this one
    // filesystem snapshot; supplemental sudoers preimages extend it, so the
    // transaction's common rollback restores every member together.
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
    let mut members = if let Some(members) = &plan.pinned_members {
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
    if pam_sudo_targets.len() == 1 && !members.iter().any(|member| member == PAM_SUDO_MEMBER) {
        members.push(PAM_SUDO_MEMBER.to_owned());
    }
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
    if let Err(error) = restore(&t.sealed.snapshot, key, &mut t.restored_paths) {
        t.rollback_errors.push(error);
    }
    if let Err(error) = restore_services(&t.sealed.services, key) {
        t.rollback_errors
            .push(format!("rollback-service-restore-failed: {error}"));
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
) -> Result<String, String> {
    for (member, sha) in [("caduceus", caduceus), ("sbin", sbin)]
        .into_iter()
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
    let mut bytes = String::with_capacity(120);
    if let Some(gui) = gui {
        bytes.push_str(gui);
    }
    bytes.push_str(caduceus);
    bytes.push_str(sbin);
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
            compute_syzygy_sha(&"0".repeat(40), &"1".repeat(40), Some(&"2".repeat(40))).unwrap();
        let b =
            compute_syzygy_sha(&"1".repeat(40), &"0".repeat(40), Some(&"2".repeat(40))).unwrap();
        assert_ne!(a, b);
    }
    #[test]
    fn empty_gui_contributes_no_bytes() {
        assert_eq!(
            compute_syzygy_sha(
                "0000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000001",
                None
            )
            .unwrap(),
            "4db7b49a94a77aa7f21dfab94156b5f6934670f0b801ee2a9784e4171b91660c"
        );
    }
    #[test]
    fn source_shas_require_lowercase_hex() {
        assert!(compute_syzygy_sha(&"A".repeat(40), &"1".repeat(40), None).is_err());
        let d = compute_syzygy_sha(&"a".repeat(40), &"f".repeat(40), None).unwrap();
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
                Some(&"f".repeat(40))
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
