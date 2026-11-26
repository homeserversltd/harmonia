//! Exact directory image capture/removal/restoration; symlink-safe and byte-preserving.
use crate::atoms::r#do::InvocationKey;
use crate::atoms::{Drift, Receipt};
use crate::atoms::comparison::ActionAuthorization;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static RESTORE_LINK_NONCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Xattr {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Xattrs {
    pub supported: bool,
    pub values: Vec<Xattr>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Kind {
    Directory,
    File,
    Symlink,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Node {
    pub relative: Vec<u8>,
    pub kind: Kind,
    pub bytes: Vec<u8>,
    pub link: Vec<u8>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub xattrs: Xattrs,
    pub children: Vec<Node>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Image {
    pub root: Node,
}
fn cpath(p: &Path) -> Result<std::ffi::CString, String> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(|_| "remove-dir-path-nul".into())
}
fn attrs(p: &Path) -> Result<Xattrs, String> {
    let c = cpath(p)?;
    let n = unsafe { libc::llistxattr(c.as_ptr(), std::ptr::null_mut(), 0) };
    if n < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOTSUP) || e.raw_os_error() == Some(libc::EOPNOTSUPP) {
            return Ok(Xattrs {
                supported: false,
                values: vec![],
            });
        }
        return Err(format!("remove-dir-llistxattr: {e}"));
    };
    if n == 0 {
        return Ok(Xattrs {
            supported: true,
            values: vec![],
        });
    };
    let mut b = vec![0u8; n as usize];
    let n = unsafe { libc::llistxattr(c.as_ptr(), b.as_mut_ptr() as *mut _, b.len()) };
    if n < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOTSUP) || e.raw_os_error() == Some(libc::EOPNOTSUPP) {
            return Ok(Xattrs {
                supported: false,
                values: vec![],
            });
        }
        return Err(format!("remove-dir-llistxattr: {e}"));
    };
    let mut out = Vec::new();
    for name in b[..n as usize].split(|v| *v == 0).filter(|v| !v.is_empty()) {
        let nc = std::ffi::CString::new(name).map_err(|_| "remove-dir-xattr-name-nul")?;
        let z = unsafe { libc::lgetxattr(c.as_ptr(), nc.as_ptr(), std::ptr::null_mut(), 0) };
        if z < 0 {
            return Err(format!(
                "remove-dir-lgetxattr: {}",
                std::io::Error::last_os_error()
            ));
        };
        let mut v = vec![0u8; z as usize];
        if z > 0
            && unsafe {
                libc::lgetxattr(c.as_ptr(), nc.as_ptr(), v.as_mut_ptr() as *mut _, v.len())
            } < 0
        {
            return Err(format!(
                "remove-dir-lgetxattr: {}",
                std::io::Error::last_os_error()
            ));
        };
        out.push(Xattr {
            name: name.to_vec(),
            value: v,
        })
    }
    Ok(Xattrs {
        supported: true,
        values: out,
    })
}
fn node(root: &Path, rel: Vec<u8>) -> Result<Node, String> {
    let p = if rel.is_empty() {
        root.to_path_buf()
    } else {
        root.join(std::ffi::OsString::from(std::ffi::OsString::from_vec(
            rel.clone(),
        )))
    };
    let m =
        fs::symlink_metadata(&p).map_err(|e| format!("remove-dir-stat {}: {e}", p.display()))?;
    let mode = m.mode() & 0o7777;
    let x = attrs(&p)?;
    if m.file_type().is_symlink() {
        return Ok(Node {
            relative: rel,
            kind: Kind::Symlink,
            bytes: vec![],
            link: fs::read_link(&p)
                .map_err(|e| e.to_string())?
                .into_os_string()
                .into_encoded_bytes(),
            mode,
            uid: m.uid(),
            gid: m.gid(),
            xattrs: x,
            children: vec![],
        });
    }
    if m.is_dir() {
        let mut ch = Vec::new();
        for e in fs::read_dir(&p).map_err(|e| e.to_string())? {
            let e = e.map_err(|e| e.to_string())?;
            use std::os::unix::ffi::OsStrExt;
            let mut child = rel.clone();
            if !child.is_empty() {
                child.push(b'/');
            }
            child.extend_from_slice(e.file_name().as_bytes());
            ch.push(node(root, child)?)
        }
        ch.sort_by(|a, b| a.relative.cmp(&b.relative));
        Ok(Node {
            relative: rel,
            kind: Kind::Directory,
            bytes: vec![],
            link: vec![],
            mode,
            uid: m.uid(),
            gid: m.gid(),
            xattrs: x,
            children: ch,
        })
    } else if m.is_file() {
        Ok(Node {
            relative: rel,
            kind: Kind::File,
            bytes: fs::read(&p).map_err(|e| e.to_string())?,
            link: vec![],
            mode,
            uid: m.uid(),
            gid: m.gid(),
            xattrs: x,
            children: vec![],
        })
    } else {
        Err("remove-dir-unsupported-node".into())
    }
}
pub(crate) fn capture(root: &Path) -> Result<Image, String> {
    Ok(Image {
        root: node(root, vec![])?,
    })
}
pub(crate) fn remove_authorized(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    root: &Path,
) -> Result<(), String> {
    remove(authorization, root)?;
    let _ = (authorization, invocation);
    Ok(())
}

pub(crate) fn remove(authorization: &ActionAuthorization, root: &Path) -> Result<(), String> {
    crate::atoms::projectio::act_remove_tree(authorization, root, crate::atoms::projectio::RemoveTree::Tree, false)
        .map_err(|e| e.to_string())
}
fn cleanup_link_stage(
    authorization: &ActionAuthorization,
    candidate: &Path,
    link: &Path,
) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(candidate) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
        Ok(metadata) => metadata,
    };
    if !metadata.file_type().is_symlink()
        || fs::read_link(candidate).map_err(|e| e.to_string())? != link
    {
        return Err("remove-dir-link-stage-changed".into());
    }
    crate::atoms::projectio::act_remove(authorization, candidate, true)
        .map_err(|e| e.to_string())
}

fn restore_node(
    authorization: &ActionAuthorization,
    base: &Path,
    n: &Node,
) -> Result<(), String> {
    let p = if n.relative.is_empty() {
        base.to_path_buf()
    } else {
        base.join(std::ffi::OsString::from_vec(n.relative.clone()))
    };
    match n.kind {
        Kind::Directory => {
            crate::atoms::projectio::act_make_dir(authorization, &p)
                .map_err(|e| e.to_string())?;
            for c in &n.children {
                restore_node(authorization, base, c)?
            }
        }
        Kind::File => {
            if let Some(d) = p.parent() {
                crate::atoms::projectio::act_make_dir(authorization, d)
                    .map_err(|e| e.to_string())?
            };
            crate::atoms::projectio::act_put(
                authorization,
                &p,
                &n.bytes,
                Some(n.mode),
                Some(n.uid),
                Some(n.gid),
            )
            .map_err(|e| e.to_string())?;
        }
        Kind::Symlink => {
            if let Some(d) = p.parent() {
                crate::atoms::projectio::act_make_dir(authorization, d)
                    .map_err(|e| e.to_string())?
            };
            let link = std::path::PathBuf::from(std::ffi::OsString::from_vec(n.link.clone()));
            let parent = p.parent().unwrap_or_else(|| Path::new("."));
            let candidate = loop {
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                let nonce = RESTORE_LINK_NONCE.fetch_add(1, Ordering::Relaxed);
                let candidate = parent.join(format!(
                    ".remove-dir-restore-{}-{timestamp}-{nonce}",
                    std::process::id()
                ));
                match fs::symlink_metadata(&candidate) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Ok(_) => continue,
                    Err(e) => return Err(e.to_string()),
                }
                match crate::atoms::projectio::act_link_stage(
                    authorization,
                    &link,
                    &candidate,
                ) {
                    Ok(()) => break candidate,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        return match cleanup_link_stage(authorization, &candidate, &link) {
                            Ok(()) => Err(error.to_string()),
                            Err(cleanup) => Err(format!(
                                "{error}; remove-dir-link-stage-cleanup-failed: {cleanup}"
                            )),
                        };
                    }
                }
            };
            if let Err(error) = crate::atoms::projectio::act_link_promote(
                authorization,
                &link,
                &candidate,
                &p,
                crate::atoms::projectio::LinkPromotion::NoReplace,
                false,
            ) {
                return match cleanup_link_stage(authorization, &candidate, &link) {
                    Ok(()) => Err(error.to_string()),
                    Err(cleanup) => Err(format!(
                        "{error}; remove-dir-link-stage-cleanup-failed: {cleanup}"
                    )),
                };
            }
        }
    };
    Ok(())
}
fn restore_attrs(
    authorization: &ActionAuthorization,
    p: &Path,
    n: &Node,
) -> Result<(), String> {
    let current = attrs(p)?;
    if !n.xattrs.supported {
        return Ok(());
    }
    if n.xattrs.supported && !current.supported {
        return Err("remove-dir-xattr-unsupported".into());
    }
    for old in current.values {
        if !n.xattrs.values.iter().any(|x| x.name == old.name) {
            let name = std::ffi::OsString::from_vec(old.name);
            crate::atoms::projectio::act_xattr_remove(authorization, p, &name)
                .map_err(|e| e.to_string())?;
        }
    }
    for x in &n.xattrs.values {
        let name = std::ffi::OsString::from_vec(x.name.clone());
        crate::atoms::projectio::act_xattr_set(authorization, p, &name, &x.value)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub(crate) fn restore(
    authorization: &ActionAuthorization,
    base: &Path,
    image: &Image,
) -> Result<(), String> {
    restore_node(authorization, base, &image.root)?;
    fn walk(authorization: &ActionAuthorization, base: &Path, n: &Node) -> Result<(), String> {
        for c in &n.children {
            walk(authorization, base, c)?
        }
        let p = if n.relative.is_empty() {
            base.to_path_buf()
        } else {
            base.join(std::ffi::OsString::from_vec(n.relative.clone()))
        };
        crate::atoms::projectio::act_owner(authorization, &p, n.uid, n.gid)
            .map_err(|e| e.to_string())?;
        restore_attrs(authorization, &p, n)?;
        if !matches!(n.kind, Kind::Symlink) {
            crate::atoms::projectio::act_mode(authorization, &p, n.mode)
                .map_err(|e| e.to_string())?
        }
        if matches!(n.kind, Kind::File | Kind::Directory) {
            crate::atoms::projectio::act_sync(authorization, &p)
                .map_err(|e| e.to_string())?
        }
        Ok(())
    }
    walk(authorization, base, &image.root)?;
    Ok(())
}

pub(crate) fn exact(a: &Image, b: &Image) -> bool {
    a == b
}

/// Replace a path with an exact image, including an absent destination.
///
/// The old image is captured before any mutation. If removal or restoration of
/// the replacement fails, the partial destination is removed and the captured
/// image is restored before returning the original error. Any rollback failure
/// is appended without hiding the original failure.
pub(crate) fn replace_authorized(
    a: &ActionAuthorization,
    i: &InvocationKey,
    root: &Path,
    replacement: &Image,
) -> Result<(), String> {
    let old = if fs::symlink_metadata(root).is_ok() {
        Some(capture(root)?)
    } else {
        None
    };
    let result = (|| {
        if old.is_some() {
            remove(a, root)?;
        }
        restore(a, root, replacement)
    })();
    if let Err(original) = result {
        let rollback = (|| {
            if fs::symlink_metadata(root).is_ok() {
                remove(a, root)?;
            }
            if let Some(image) = old.as_ref() {
                restore(a, root, image)?;
            }
            Ok::<(), String>(())
        })();
        return match rollback {
            Ok(()) => Err(original),
            Err(rollback) => Err(format!("{original}; rollback failed: {rollback}")),
        };
    }
    let _ = (a, i);
    Ok(())
}

pub(crate) fn operate(
    a: &ActionAuthorization,
    i: &InvocationKey,
    root: &Path,
    restore_image: Option<&Image>,
) -> Result<Image, String> {
    let observation = crate::atoms::ask::remove_dir::probe(root, "recursive-exact")?;
    if !observation.root.present {
        return Err("remove-dir-path-absent".into());
    }
    let image = capture(root)?;
    remove(a, root)?;
    if let Some(x) = restore_image {
        restore(a, root, x)?
    };
    let _ = (a, i);
    Ok(image)
}
