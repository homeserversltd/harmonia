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
    roots: Vec<Target>,
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

pub(crate) fn restore(s: &Snapshot, key: &InvocationKey) -> Result<(), String> {
    let mut changed = Vec::new();
    for root in &s.roots {
        validate_member_scoped_target(&root.path, &root.member)?;
        if !root_matches_snapshot(&root.path, &s.nodes)? {
            changed.push(root.path.clone());
        }
    }
    let changed_roots = changed.clone();
    changed.retain(|root| {
        !changed_roots
            .iter()
            .any(|parent| parent != root && root.starts_with(parent))
    });
    for root in changed.iter().rev() {
        rm(root)?;
    }
    for n in &s.nodes {
        if !changed
            .iter()
            .any(|root| n.path == *root || n.path.starts_with(root.join("")))
        {
            continue;
        }
        match &n.kind {
            Kind::Missing => continue,
            Kind::Dir => fs::create_dir_all(&n.path).map_err(|e| e.to_string())?,
            Kind::File(b) => {
                if let Some(p) = n.path.parent() {
                    fs::create_dir_all(p).map_err(|e| e.to_string())?;
                }
                comparison_authorized_write(&n.path, b, Some(n.mode & 0o7777), key)?
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
        capture_tree(&r.path, &mut got)?;
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
}
#[derive(Clone, Debug)]
pub(crate) struct ProjectionTransaction {
    pub sealed: SealedProjection,
    pub state: TransactionState,
    applied_children: BTreeSet<usize>,
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
    if !root.is_absolute() || !path.starts_with(root) {
        return Err(format!("update-set-root-outside {}", path.display()));
    }
    let mut cur = root.to_path_buf();
    let relative = path.strip_prefix(root).map_err(|_| "update-set-root-outside")?;
    for component in relative.components() {
        cur.push(component.as_os_str());
        if let Ok(metadata) = fs::symlink_metadata(&cur) {
            if metadata.file_type().is_symlink() {
                return Err(format!("update-set-root-symlink {}", cur.display()));
            }
        }
    }
    Ok(())
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
    for t in &plan.targets {
        validate_exact_root(&t.path, &t.member)?;
    }
    let snapshot = snapshot(&plan.targets)?;
    let services = snapshot_services(plan)?;
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
            Some("agathodaimon"),
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
        },
        state: TransactionState::Open,
        applied_children: BTreeSet::new(),
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
    let a = restore(&t.sealed.snapshot, key);
    let b = restore_services(&t.sealed.services, key);
    if a.is_ok() && b.is_ok() {
        t.state = TransactionState::RolledBack;
        Ok(receipt_for(t))
    } else {
        t.state = TransactionState::RollbackIncomplete;
        Err("rollback-incomplete".into())
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
    bytes.push_str(caduceus);
    bytes.push_str(sbin);
    if let Some(gui) = gui {
        bytes.push_str(gui);
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
    json!({"schema":"harmonia.update-set.v1","set_name":"appliance-syzygy","profile_id":r.profile_id,"profile_identity":r.profile_identity,"source_head":r.source_head,"gui":r.gui,"gui_member":r.gui_member,"syzygy_sha":r.syzygy_sha,"syzygy_signal":r.syzygy_signal,"set_verdict":verdict,"members":r.children.iter().map(|c|json!({"ordinal":c.ordinal,"member":c.member,"status":if r.state==TransactionState::Committed {"standing"} else {"rolled-back"}})).collect::<Vec<_>>(),"targets":r.target_count,"services":r.service_count,"caduceus_count":r.caduceus_count})
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
            "f1820713847173c6f662ec7a077824eb6a5ca884f32724d58535b24479aa0ee5"
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
