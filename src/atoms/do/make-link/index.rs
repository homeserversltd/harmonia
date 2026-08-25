use crate::atoms::r#do::InvocationKey;
use crate::atoms::comparison::ActionAuthorization;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CollisionPolicy {
    Refuse,
    ReplaceRegularFile,
    ReplaceEmptyDirectory,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub changed: bool,
    pub message: String,
}

#[cfg(unix)]
fn exchange(left: &Path, right: &Path) -> Result<(), String> {
    use std::ffi::CString;
    let l = CString::new(left.as_os_str().as_encoded_bytes())
        .map_err(|_| "make-link-invalid-path".to_string())?;
    let r = CString::new(right.as_os_str().as_encoded_bytes())
        .map_err(|_| "make-link-invalid-path".to_string())?;
    #[cfg(target_os = "linux")]
    {
        let rc = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                l.as_ptr(),
                libc::AT_FDCWD,
                r.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().to_string())
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (l, r);
        Err("make-link-exchange-unsupported".into())
    }
}
#[cfg(unix)]
fn path_kind(p: &Path) -> Result<&'static str, String> {
    match fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_symlink() => Ok("symlink"),
        Ok(m) if m.file_type().is_file() => Ok("regular-file"),
        Ok(m) if m.file_type().is_dir() => Ok("directory"),
        Ok(_) => Ok("other"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok("absent"),
        Err(e) => Err(format!("make-link-observe-failed: {e}")),
    }
}

#[cfg(unix)]
pub(crate) fn converge(
    source: &Path,
    link: &Path,
    policy: CollisionPolicy,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<Outcome, String> {
    let parent = link
        .parent()
        .ok_or_else(|| "make-link-parent-missing".to_string())?;
    if !parent.is_dir() {
        return Err("make-link-parent-missing".into());
    };
    let before = path_kind(link)?;
    if before == "symlink" && fs::read_link(link).map_err(|e| e.to_string())? == source {
        return Ok(Outcome {
            changed: false,
            message: "make-link unchanged".into(),
        });
    };
    match (before, policy) {
        ("regular-file", CollisionPolicy::Refuse) => {
            return Err("make-link-target-collision-regular-file".into());
        }
        ("directory", CollisionPolicy::Refuse) => {
            return Err("make-link-target-collision-directory".into());
        }
        ("other", _) => return Err("make-link-target-collision-other".into()),
        ("directory", CollisionPolicy::ReplaceEmptyDirectory)
            if fs::read_dir(link)
                .map_err(|e| e.to_string())?
                .next()
                .is_some() =>
        {
            return Err("make-link-target-directory-not-empty".into());
        }
        ("directory", CollisionPolicy::ReplaceRegularFile) => {
            return Err("make-link-target-collision-directory".into());
        }
        _ => {}
    }
    let n = link.file_name().and_then(|v| v.to_str()).unwrap_or("link");
    let c = parent.join(format!(".{n}.make-link-{}", std::process::id()));
    let _ = fs::remove_file(&c);
    std::os::unix::fs::symlink(source, &c).map_err(|e| format!("make-link-stage-failed: {e}"))?;
    if let (Some(u), Some(g)) = (uid, gid) {
        use std::ffi::CString;
        let cc = CString::new(c.as_os_str().as_encoded_bytes())
            .map_err(|_| "make-link-invalid-path".to_string())?;
        if unsafe { libc::lchown(cc.as_ptr(), u, g) } != 0 {
            let _ = fs::remove_file(&c);
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    let promoted = if before == "absent" {
        if fs::symlink_metadata(link).is_ok() {
            let _ = fs::remove_file(&c);
            return Err("make-link-target-raced".into());
        }
        fs::rename(&c, link).map_err(|e| e.to_string())
    } else {
        exchange(&c, link)
    };
    if let Err(e) = promoted {
        let _ = fs::remove_file(&c);
        return Err(format!("make-link-promote-failed: {e}"));
    }
    if std::env::var_os("HARMONIA_MAKE_LINK_FAIL_AFTER_ACTION").is_some() {
        let rb = if before == "absent" {
            fs::remove_file(link).map_err(|e| e.to_string())
        } else {
            exchange(&c, link)
        };
        if rb.is_ok() {
            let cleanup = if before == "directory" {
                fs::remove_dir(&c)
            } else {
                fs::remove_file(&c)
            };
            let _ = cleanup;
        }
        let status = if rb.is_ok() { "ok" } else { "failed" };
        return Err(format!(
            "make-link-injected-post-action-failure exact-rollback={status}"
        ));
    }
    if before != "absent" {
        (if before == "directory" {
            fs::remove_dir(&c)
        } else {
            fs::remove_file(&c)
        })
        .map_err(|e| format!("make-link-cleanup-failed: {e}"))?;
    }
    Ok(Outcome {
        changed: true,
        message: "make-link converged".into(),
    })
}
#[cfg(not(unix))]
pub(crate) fn converge(
    _: &Path,
    _: &Path,
    _: CollisionPolicy,
    _: Option<u32>,
    _: Option<u32>,
) -> Result<Outcome, String> {
    Err("make-link-unsupported".into())
}

#[cfg(unix)]
pub(crate) fn symlink(
    _authorization: &ActionAuthorization,
    _invocation: &InvocationKey,
    target: &Path,
    link: &Path,
) -> Result<(), String> {
    converge(target, link, CollisionPolicy::Refuse, None, None).map(|_| ())
}
#[cfg(not(unix))]
pub(crate) fn symlink(
    _: &ActionAuthorization,
    _: &InvocationKey,
    _: &Path,
    _: &Path,
) -> Result<(), String> {
    Err("make-link-unsupported".into())
}
