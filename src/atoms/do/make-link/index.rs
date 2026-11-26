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
fn checked_exchange_paths(left: &Path, right: &Path) -> Result<(), String> {
    use std::ffi::CString;
    let l = CString::new(left.as_os_str().as_encoded_bytes())
        .map_err(|_| "make-link-invalid-path".to_string())?;
    let r = CString::new(right.as_os_str().as_encoded_bytes())
        .map_err(|_| "make-link-invalid-path".to_string())?;
    #[cfg(target_os = "linux")]
    { let _ = (l, r); Ok(()) }
    #[cfg(not(target_os = "linux"))]
    { let _ = (l, r); Err("make-link-exchange-unsupported".into()) }
}
#[cfg(unix)]
pub(crate) fn converge(
    authorization: &ActionAuthorization,
    source: &Path,
    link: &Path,
    policy: CollisionPolicy,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<Outcome, String> {
    converge_with_scratch(authorization, source, link, policy, uid, gid, false)
}

#[cfg(unix)]
fn converge_with_scratch(
    authorization: &ActionAuthorization,
    source: &Path,
    link: &Path,
    policy: CollisionPolicy,
    uid: Option<u32>,
    gid: Option<u32>,
    scratch: bool,
) -> Result<Outcome, String> {
    let parent = link
        .parent()
        .ok_or_else(|| "make-link-parent-missing".to_string())?;
    if !parent.is_dir() {
        return Err("make-link-parent-missing".into());
    };
    let observation = crate::atoms::ask::make_link::probe(source, link)?;
    let before = match observation.preimage.kind {
        None => "absent",
        Some(crate::atoms::ask::FsKind::File) => "regular-file",
        Some(crate::atoms::ask::FsKind::Directory) => "directory",
        Some(crate::atoms::ask::FsKind::Symlink) => "symlink",
        Some(crate::atoms::ask::FsKind::Other) => "other",
    };
    if before == "symlink" && observation.preimage.link_target.as_deref() == Some(source) {
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
    use crate::atoms::projectio::{self, LinkPromotion, RemoveTree};
    let _ = projectio::act_remove(authorization, &c, true);
    projectio::act_link_stage(authorization, source, &c).map_err(|e| format!("make-link-stage-failed: {e}"))?;
    if let (Some(u), Some(g)) = (uid, gid) {
        use std::ffi::CString;
        let _cc = CString::new(c.as_os_str().as_encoded_bytes())
            .map_err(|_| "make-link-invalid-path".to_string())?;
        if let Err(error) = projectio::act_scratch_owner(authorization, &c, u, g) {
            let _ = projectio::act_remove(authorization, &c, true);
            return Err(error.to_string());
        }
    }
    let promoted = if before == "absent" {
        if fs::symlink_metadata(link).is_ok() {
            let _ = projectio::act_remove(authorization, &c, true);
            return Err("make-link-target-raced".into());
        }
        projectio::act_link_promote(authorization, source, &c, link, LinkPromotion::Rename, scratch).map_err(|e| e.to_string())
    } else {
        checked_exchange_paths(&c, link).and_then(|_| projectio::act_link_promote(authorization, source, &c, link, LinkPromotion::Exchange, scratch).map_err(|e| e.to_string()))
    };
    if let Err(e) = promoted {
        let _ = projectio::act_remove(authorization, &c, true);
        return Err(format!("make-link-promote-failed: {e}"));
    }
    if std::env::var_os("HARMONIA_MAKE_LINK_FAIL_AFTER_ACTION").is_some() {
        let rb = if before == "absent" {
            projectio::act_remove(authorization, link, scratch).map_err(|e| e.to_string())
        } else {
            checked_exchange_paths(&c, link).and_then(|_| projectio::act_exchange_back(authorization, &c, link, scratch).map_err(|e| e.to_string()))
        };
        if rb.is_ok() {
            let cleanup = if before == "directory" {
                projectio::act_remove_tree(authorization, &c, RemoveTree::Empty, true)
            } else {
                projectio::act_remove(authorization, &c, true)
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
            projectio::act_remove_tree(authorization, &c, RemoveTree::Empty, true)
        } else {
            projectio::act_remove(authorization, &c, true)
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
    _: &ActionAuthorization,
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
    authorization: &ActionAuthorization,
    _invocation: &InvocationKey,
    target: &Path,
    link: &Path,
) -> Result<(), String> {
    converge(authorization, target, link, CollisionPolicy::Refuse, None, None).map(|_| ())
}
#[cfg(unix)]
pub(crate) fn symlink_scratch(
    authorization: &ActionAuthorization,
    _invocation: &InvocationKey,
    target: &Path,
    link: &Path,
) -> Result<(), String> {
    converge_with_scratch(authorization, target, link, CollisionPolicy::Refuse, None, None, true).map(|_| ())
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
