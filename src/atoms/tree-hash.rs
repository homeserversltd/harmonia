//! Shared Harmonia module-tree identity primitives.
use crate::atoms::r#do::remove_dir::{self, Kind, Node};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

/// Identity for cross-boundary source/installed/materialized comparisons.
pub(crate) fn content_tree_sha256(path: &Path) -> Result<String, String> {
    hash_captured(path, false, None)
}
/// Full-fidelity identity for capsule sealed-payload pack/verify semantics.
pub(crate) fn full_tree_sha256(path: &Path) -> Result<String, String> {
    hash_captured(path, true, None)
}
/// Deterministic ownership fixture over a real captured filesystem tree.
pub(crate) fn full_tree_sha256_with_ownership_fixture(
    path: &Path,
    uid: u32,
    gid: u32,
) -> Result<String, String> {
    hash_captured(path, true, Some((uid, gid)))
}

fn hash_captured(
    path: &Path,
    full_fidelity: bool,
    ownership: Option<(u32, u32)>,
) -> Result<String, String> {
    let image = remove_dir::capture(path)?;
    let mut active = HashSet::new();
    let root = dereference(image.root, path, &mut active)?;
    let root = match ownership {
        Some((uid, gid)) => override_ownership(root, uid, gid),
        None => root,
    };
    let mut chain = Sha256::new();
    hash_node(&mut chain, &root, full_fidelity);
    Ok(format!("{:x}", chain.finalize()))
}

fn dereference(
    node: Node,
    physical_path: &Path,
    active: &mut HashSet<PathBuf>,
) -> Result<Node, String> {
    match node.kind {
        Kind::Symlink => {
            let target = fs::canonicalize(physical_path).map_err(|e| {
                format!(
                    "module-tree-hash-broken-link {}: {e}",
                    physical_path.display()
                )
            })?;
            let image = remove_dir::capture(&target)?;
            dereference_at(image.root, &target, node.relative, active)
        }
        Kind::Directory => {
            let identity = fs::canonicalize(physical_path).map_err(|e| {
                format!(
                    "module-tree-hash-directory-resolve {}: {e}",
                    physical_path.display()
                )
            })?;
            if !active.insert(identity.clone()) {
                return Err(format!(
                    "module-tree-hash-cycle {}",
                    physical_path.display()
                ));
            }
            let mut children = Vec::with_capacity(node.children.len());
            for child in node.children {
                let name = child
                    .relative
                    .rsplit(|b| *b == b'/')
                    .next()
                    .unwrap_or(&[])
                    .to_vec();
                children.push(dereference(
                    child,
                    &physical_path.join(std::ffi::OsString::from_vec(name)),
                    active,
                )?);
            }
            active.remove(&identity);
            Ok(Node { children, ..node })
        }
        Kind::File => Ok(node),
    }
}

fn dereference_at(
    mut node: Node,
    physical_path: &Path,
    relative: Vec<u8>,
    active: &mut HashSet<PathBuf>,
) -> Result<Node, String> {
    node.relative = relative.clone();
    match node.kind {
        Kind::Directory => {
            let identity = fs::canonicalize(physical_path).map_err(|e| {
                format!(
                    "module-tree-hash-directory-resolve {}: {e}",
                    physical_path.display()
                )
            })?;
            if !active.insert(identity.clone()) {
                return Err(format!(
                    "module-tree-hash-cycle {}",
                    physical_path.display()
                ));
            }
            let mut children = Vec::with_capacity(node.children.len());
            for child in node.children {
                let name = child
                    .relative
                    .rsplit(|b| *b == b'/')
                    .next()
                    .unwrap_or(&[])
                    .to_vec();
                let child_path = physical_path.join(std::ffi::OsString::from_vec(name.clone()));
                let child_relative = if relative.is_empty() {
                    name
                } else {
                    [relative.as_slice(), b"/", name.as_slice()].concat()
                };
                children.push(dereference_at(child, &child_path, child_relative, active)?);
            }
            active.remove(&identity);
            Ok(Node { children, ..node })
        }
        Kind::File => Ok(node),
        Kind::Symlink => {
            let target = fs::canonicalize(physical_path).map_err(|e| {
                format!(
                    "module-tree-hash-broken-link {}: {e}",
                    physical_path.display()
                )
            })?;
            let image = remove_dir::capture(&target)?;
            dereference_at(image.root, &target, node.relative, active)
        }
    }
}

fn override_ownership(mut node: Node, uid: u32, gid: u32) -> Node {
    node.uid = uid;
    node.gid = gid;
    node.children = node
        .children
        .into_iter()
        .map(|child| override_ownership(child, uid, gid))
        .collect();
    node
}

fn hash_node(chain: &mut Sha256, node: &Node, full_fidelity: bool) {
    hash_bytes(chain, &node.relative);
    chain.update([match node.kind {
        Kind::Directory => 0,
        Kind::File => 1,
        Kind::Symlink => 2,
    }]);
    hash_bytes(chain, &node.bytes);
    hash_bytes(chain, &node.link);
    chain.update(node.mode.to_le_bytes());
    if full_fidelity {
        chain.update(node.uid.to_le_bytes());
        chain.update(node.gid.to_le_bytes());
        chain.update([u8::from(node.xattrs.supported)]);
        let mut xattrs = node.xattrs.values.iter().collect::<Vec<_>>();
        xattrs.sort_by(|a, b| a.name.cmp(&b.name));
        chain.update((xattrs.len() as u64).to_le_bytes());
        for xattr in xattrs {
            hash_bytes(chain, &xattr.name);
            hash_bytes(chain, &xattr.value);
        }
    }
    chain.update((node.children.len() as u64).to_le_bytes());
    for child in &node.children {
        hash_node(chain, child, full_fidelity);
    }
}
fn hash_bytes(chain: &mut Sha256, bytes: &[u8]) {
    chain.update((bytes.len() as u64).to_le_bytes());
    chain.update(bytes);
}
