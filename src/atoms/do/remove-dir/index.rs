//! Exact directory image capture/removal/restoration; symlink-safe and byte-preserving.
use crate::atoms::r#do::{apply, InvocationKey};
use crate::atoms::{Drift, Receipt};
use crate::tools::comparison::ActionAuthorization;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
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
pub(crate) fn remove(root: &Path) -> Result<(), String> {
    let m = fs::symlink_metadata(root).map_err(|e| e.to_string())?;
    if m.is_dir() && !m.file_type().is_symlink() {
        fs::remove_dir_all(root).map_err(|e| e.to_string())
    } else {
        fs::remove_file(root).map_err(|e| e.to_string())
    }
}
fn restore_node(base: &Path, n: &Node) -> Result<(), String> {
    use std::os::unix::ffi::OsStringExt;
    let p = if n.relative.is_empty() {
        base.to_path_buf()
    } else {
        base.join(std::ffi::OsString::from_vec(n.relative.clone()))
    };
    match n.kind {
        Kind::Directory => {
            fs::create_dir_all(&p).map_err(|e| e.to_string())?;
            for c in &n.children {
                restore_node(base, c)?
            }
        }
        Kind::File => {
            if let Some(d) = p.parent() {
                fs::create_dir_all(d).map_err(|e| e.to_string())?
            };
            let mut f = fs::File::create(&p).map_err(|e| e.to_string())?;
            std::io::Write::write_all(&mut f, &n.bytes).map_err(|e| e.to_string())?
        }
        Kind::Symlink => {
            if let Some(d) = p.parent() {
                fs::create_dir_all(d).map_err(|e| e.to_string())?
            };
            std::os::unix::fs::symlink(std::ffi::OsString::from_vec(n.link.clone()), &p)
                .map_err(|e| e.to_string())?
        }
    };
    Ok(())
}
fn restore_attrs(p: &Path, n: &Node) -> Result<(), String> {
    let current = attrs(p)?;
    if !n.xattrs.supported {
        return Ok(());
    }
    if n.xattrs.supported && !current.supported {
        return Err("remove-dir-xattr-unsupported".into());
    }
    let c = cpath(p)?;
    for old in current.values {
        if !n.xattrs.values.iter().any(|x| x.name == old.name) {
            let nc = std::ffi::CString::new(old.name).map_err(|_| "remove-dir-xattr-name-nul")?;
            if unsafe { libc::lremovexattr(c.as_ptr(), nc.as_ptr()) } < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
    }
    for x in &n.xattrs.values {
        let nc = std::ffi::CString::new(x.name.clone()).map_err(|_| "remove-dir-xattr-name-nul")?;
        if unsafe {
            libc::lsetxattr(
                c.as_ptr(),
                nc.as_ptr(),
                x.value.as_ptr() as *const _,
                x.value.len(),
                0,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    Ok(())
}

pub(crate) fn restore(base: &Path, image: &Image) -> Result<(), String> {
    restore_node(base, &image.root)?;
    fn walk(base: &Path, n: &Node) -> Result<(), String> {
        for c in &n.children {
            walk(base, c)?
        }
        let p = if n.relative.is_empty() {
            base.to_path_buf()
        } else {
            base.join(std::ffi::OsString::from_vec(n.relative.clone()))
        };
        let c = cpath(&p)?;
        if unsafe { libc::lchown(c.as_ptr(), n.uid, n.gid) } < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        restore_attrs(&p, n)?;
        if !matches!(n.kind, Kind::Symlink) {
            fs::set_permissions(&p, fs::Permissions::from_mode(n.mode))
                .map_err(|e| e.to_string())?
        }
        if matches!(n.kind, Kind::File | Kind::Directory) {
            fs::File::open(&p)
                .map_err(|e| e.to_string())?
                .sync_all()
                .map_err(|e| e.to_string())?
        }
        Ok(())
    }
    walk(base, &image.root)
}

pub(crate) fn exact(a: &Image, b: &Image) -> bool {
    a == b
}
pub(crate) fn operate(
    a: ActionAuthorization,
    i: InvocationKey,
    root: &Path,
    restore_image: Option<&Image>,
) -> Result<Image, String> {
    let image = capture(root)?;
    remove(root)?;
    if let Some(x) = restore_image {
        restore(root, x)?
    };
    apply(
        a,
        i,
        Receipt {
            atom: "do".into(),
            ok: true,
            drift: Drift::Current,
            message: "exact directory operation".into(),
        },
    )?;
    Ok(image)
}
