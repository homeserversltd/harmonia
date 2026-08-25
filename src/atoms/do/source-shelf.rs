//! Typed filesystem mutations owned by the source-shelf transaction.
use crate::atoms::comparison::ActionAuthorization;
use crate::atoms::r#do::InvocationKey;
use crate::atoms::{Drift, Receipt};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn receipt(message: String) -> Receipt {
    Receipt {
        atom: "do".into(),
        ok: true,
        drift: Drift::Current,
        message,
    }
}

pub(crate) fn mkdir_all(
    a: ActionAuthorization,
    i: InvocationKey,
    path: &Path,
) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| e.to_string())?;
    {
        let _ = (a, i, path);
        Ok(())
    }
}

pub(crate) fn copy(
    a: ActionAuthorization,
    i: InvocationKey,
    source: &Path,
    target: &Path,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), String> {
    let bytes = fs::read(source)
        .map_err(|e| format!("files-source-read-failed {}: {e}", source.display()))?;
    atomic_write(a, i, target, &bytes, mode, uid, gid)
}

pub(crate) fn rename(
    a: ActionAuthorization,
    i: InvocationKey,
    from: &Path,
    to: &Path,
) -> Result<(), String> {
    crate::atoms::r#do::rename::rename(a, i, from, to)
}

pub(crate) fn copy_raw(
    a: ActionAuthorization,
    i: InvocationKey,
    source: &Path,
    target: &Path,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), String> {
    copy(a, i, source, target, mode, uid, gid)
}

fn atomic_write(
    a: ActionAuthorization,
    i: InvocationKey,
    target: &Path,
    bytes: &[u8],
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), String> {
    let parent = target
        .parent()
        .ok_or_else(|| format!("files-target-parent-missing {}", target.display()))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temp = parent.join(format!(
        ".{}.harmonia-tmp-{}",
        target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file"),
        nonce
    ));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)
            .map_err(|e| format!("files-temp-create-failed {}: {e}", temp.display()))?;
        file.write_all(bytes)
            .map_err(|e| format!("files-temp-write-failed {}: {e}", temp.display()))?;
        file.sync_all()
            .map_err(|e| format!("files-temp-sync-failed {}: {e}", temp.display()))?;
        drop(file);
        if let Some(mode) = mode {
            set_mode(&temp, mode)?;
        }
        set_ownership(&temp, uid, gid)?;
        fs::rename(&temp, target).map_err(|e| {
            format!(
                "files-atomic-promote-failed {} -> {}: {e}",
                temp.display(),
                target.display()
            )
        })?;
        sync_directory(parent)?;
        let _ = (a, i, target);
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
        let _ = sync_directory(parent);
    }
    result
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)
        .map_err(|e| format!("files-mode-metadata-failed {}: {e}", path.display()))?
        .permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions)
        .map_err(|e| format!("files-mode-set-failed {}: {e}", path.display()))
}
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn set_ownership(path: &Path, uid: Option<u32>, gid: Option<u32>) -> Result<(), String> {
    if uid.is_none() && gid.is_none() {
        return Ok(());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("managed-file-owner-open-failed {}: {e}", path.display()))?;
    let uid = uid.map_or(!0 as libc::uid_t, |value| value as libc::uid_t);
    let gid = gid.map_or(!0 as libc::gid_t, |value| value as libc::gid_t);
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(format!(
            "managed-file-owner-set-failed {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}
#[cfg(not(unix))]
fn set_ownership(_path: &Path, _uid: Option<u32>, _gid: Option<u32>) -> Result<(), String> {
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            format!(
                "source-shelf-sweep-directory-sync-failed {}: {error}",
                path.display()
            )
        })
}

pub(crate) fn remove_file(
    a: ActionAuthorization,
    i: InvocationKey,
    path: &Path,
) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
        Ok(m) if m.file_type().is_dir() => {
            return Err(format!(
                "source-shelf-remove-file-directory {}",
                path.display()
            ))
        }
        Ok(_) => {}
    }
    crate::atoms::r#do::remove_file::remove_file_with_policy(
        a,
        i,
        path,
        crate::atoms::r#do::remove_file::RemovePolicy {
            no_follow: true,
            collision_refuse: true,
            rollback_exact: true,
        },
    )
}

pub(crate) fn remove_tree(
    a: ActionAuthorization,
    i: InvocationKey,
    path: &Path,
) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
        Ok(m) if !m.file_type().is_dir() => return remove_file(a, i, path),
        Ok(_) => {}
    }
    fs::remove_dir_all(path).map_err(|e| e.to_string())?;
    {
        let _ = (a, i, path);
        Ok(())
    }
}

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use similar::TextDiff;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, PathBuf};

use crate::atoms::files::{
    file_mode, reject_ssh_path, resolve_gid, resolve_uid, validate_receipt_name,
    validate_relative_path, validate_source_shelf_relative_path, PYTHON_RUNTIME_DEBRIS_EXCLUDE,
};

#[derive(Debug, Clone)]
pub struct SourceShelfSweepRequest {
    pub source_root: PathBuf,
    pub shelf_source: PathBuf,
    pub target_shelf: PathBuf,
    pub launcher_source_root: PathBuf,
    pub launcher_target_root: PathBuf,
    pub launcher_pattern: String,
    pub shelf_owner: String,
    pub shelf_group: String,
    pub shelf_directory_mode: u32,
    pub shelf_file_mode: u32,
    pub launcher_mode: u32,
    pub prune: bool,
    /// Additive shared-root guard.  When absent, preserve the established sweep.
    pub launcher_exclude: Vec<String>,
    /// Additive ownership ledger.  Only paths recorded here may be replaced/pruned.
    pub provenance_state: Option<PathBuf>,
    /// Shared-root mode: carry source inventory per owned path without replacing
    /// cohabiting material outside the provenance ledger.
    pub owned_recursive: bool,
    pub receipt_name: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct SourceShelfSweepProvenance {
    #[serde(default)]
    paths: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceShelfSweepOrphanRemoval {
    pub target: PathBuf,
    pub path: String,
    pub pre_removal_size_hint: u64,
    pub pre_removal_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceShelfSweepEntry {
    pub kind: String,
    pub relative_path: String,
    pub source: Option<PathBuf>,
    pub target: PathBuf,
    pub source_digest: Option<String>,
    pub before_digest: Option<String>,
    pub after_digest: Option<String>,
    pub desired_mode: u32,
    pub before_mode: Option<u32>,
    pub after_mode: Option<u32>,
    pub desired_uid: u32,
    pub desired_gid: u32,
    pub before_uid: Option<u32>,
    pub before_gid: Option<u32>,
    pub after_uid: Option<u32>,
    pub after_gid: Option<u32>,
    pub action: String,
    pub changed: bool,
    pub readback_ok: bool,
    pub rollback_action: String,
    pub rollback_readback_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orphan_removal: Option<SourceShelfSweepOrphanRemoval>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceShelfSweepOutcome {
    pub ok: bool,
    pub changed: bool,
    pub current: bool,
    pub source_inventory_count: usize,
    pub target_inventory_count_before: usize,
    pub target_inventory_count_after: usize,
    pub promoted_count: usize,
    pub removed_count: usize,
    pub transaction_state: String,
    pub rollback_state: String,
    pub first_blocker: String,
    pub entries: Vec<SourceShelfSweepEntry>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Default)]
struct SourceShelfSweepFault {
    fail_setup_after_stage: bool,
    fail_after_promotions: Option<usize>,
    fail_cleanup: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SweepTreeEntry {
    relative_path: PathBuf,
    is_dir: bool,
}

fn sweep_nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{}-{nanos}", std::process::id())
}

fn validate_mode(label: &str, mode: u32) -> Result<(), String> {
    if mode & !0o777 != 0 {
        return Err(format!("source-shelf-sweep-{label}-mode-rejected {mode:o}"));
    }
    Ok(())
}

fn validate_launcher_pattern(pattern: &str) -> Result<(), String> {
    if pattern.is_empty()
        || pattern.contains('/')
        || pattern.contains('\\')
        || pattern == "."
        || pattern == ".."
    {
        return Err(format!(
            "source-shelf-sweep-launcher-pattern-rejected {pattern:?}"
        ));
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<(), String> {
    let mut cursor = PathBuf::new();
    for component in path.components() {
        cursor.push(component.as_os_str());
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "source-shelf-sweep-target-symlink-component-rejected {}",
                    cursor.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(format!(
                    "source-shelf-sweep-target-component-metadata-failed {}: {error}",
                    cursor.display()
                ));
            }
        }
    }
    Ok(())
}

fn basename_pattern_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut previous = vec![false; value.len() + 1];
    previous[0] = true;
    for token in pattern {
        let mut current = vec![false; value.len() + 1];
        match token {
            b'*' => {
                current[0] = previous[0];
                for index in 1..=value.len() {
                    current[index] = previous[index] || current[index - 1];
                }
            }
            b'?' => {
                for index in 1..=value.len() {
                    current[index] = previous[index - 1];
                }
            }
            literal => {
                for index in 1..=value.len() {
                    current[index] = previous[index - 1] && *literal == value[index - 1];
                }
            }
        }
        previous = current;
    }
    previous[value.len()]
}

fn source_shelf_excluded(patterns: &[String], relative: &Path) -> bool {
    let relative = relative.to_string_lossy();
    patterns.iter().any(|pattern| {
        basename_pattern_matches(pattern, &relative)
            || relative
                .split('/')
                .any(|part| basename_pattern_matches(pattern, part))
    })
}

fn source_shelf_sweep_exclude(configured: &[String]) -> Vec<String> {
    let mut exclude = configured.to_vec();
    // Ignore Python bytecode runtime debris without treating it as owned content.
    exclude.extend(
        PYTHON_RUNTIME_DEBRIS_EXCLUDE
            .iter()
            .copied()
            .map(String::from),
    );
    exclude
}

fn carry_excluded_shelf_entries(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: crate::atoms::r#do::InvocationKey,
    shelf_backup: &Path,
    promoted_shelf: &Path,
    exclude: &[String],
) -> Result<Vec<(PathBuf, PathBuf)>, String> {
    fn carry(
        authorization: crate::atoms::comparison::ActionAuthorization,
        invocation: crate::atoms::r#do::InvocationKey,
        shelf_backup: &Path,
        promoted_shelf: &Path,
        path: &Path,
        exclude: &[String],
        carried: &mut Vec<(PathBuf, PathBuf)>,
    ) -> Result<(), String> {
        let mut children = fs::read_dir(path)
            .map_err(|error| {
                format!(
                    "source-shelf-sweep-excluded-backup-read-failed {}: {error}",
                    path.display()
                )
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            let backup_path = child.path();
            let relative_path = backup_path
                .strip_prefix(shelf_backup)
                .map_err(|error| error.to_string())?
                .to_path_buf();
            validate_relative_path(&relative_path)?;
            let promoted_path = promoted_shelf.join(&relative_path);
            if source_shelf_excluded(exclude, &relative_path) {
                match fs::symlink_metadata(&promoted_path) {
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        crate::atoms::r#do::source_shelf::rename(
                            authorization,
                            invocation,
                            &backup_path,
                            &promoted_path,
                        )
                        .map_err(|error| {
                            format!(
                                "source-shelf-sweep-excluded-carry-failed {} -> {}: {error}",
                                backup_path.display(),
                                promoted_path.display()
                            )
                        })?;
                        carried.push((backup_path, promoted_path));
                    }
                    Err(error) => {
                        return Err(format!(
                            "source-shelf-sweep-excluded-stage-metadata-failed {}: {error}",
                            promoted_path.display()
                        ))
                    }
                }
                continue;
            }
            if child
                .file_type()
                .map_err(|error| format!("source-shelf-sweep-excluded-entry-type-failed: {error}"))?
                .is_dir()
            {
                carry(
                    authorization,
                    invocation,
                    shelf_backup,
                    promoted_shelf,
                    &backup_path,
                    exclude,
                    carried,
                )?;
            }
        }
        Ok(())
    }
    let mut carried = Vec::new();
    carry(
        authorization,
        invocation,
        shelf_backup,
        promoted_shelf,
        shelf_backup,
        exclude,
        &mut carried,
    )?;
    Ok(carried)
}

fn load_sweep_provenance(path: &Path) -> Result<SourceShelfSweepProvenance, String> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
            format!(
                "source-shelf-sweep-provenance-parse-failed {}: {error}",
                path.display()
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
        Err(error) => Err(format!(
            "source-shelf-sweep-provenance-read-failed {}: {error}",
            path.display()
        )),
    }
}

fn write_sweep_provenance(
    path: &Path,
    provenance: &SourceShelfSweepProvenance,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "source-shelf-sweep-provenance-parent-missing".to_string())?;
    crate::atoms::attest::prepare_receipt_parent(parent).map_err(|error| {
        format!(
            "source-shelf-sweep-provenance-parent-create-failed {}: {error}",
            parent.display()
        )
    })?;
    crate::atoms::attest::write_json_atomic(
        path,
        &json!({
            "schema":"harmonia.files.source_shelf_sweep.provenance.v1",
            "paths": provenance.paths,
        }),
    )
}

fn inventory_sweep_tree(root: &Path, exclude: &[String]) -> Result<Vec<SweepTreeEntry>, String> {
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        format!(
            "source-shelf-sweep-tree-metadata-failed {}: {error}",
            root.display()
        )
    })?;
    if !metadata.file_type().is_dir() {
        return Err(format!(
            "source-shelf-sweep-tree-not-directory {}",
            root.display()
        ));
    }
    let mut entries = vec![SweepTreeEntry {
        relative_path: PathBuf::from("."),
        is_dir: true,
    }];
    fn walk(
        root: &Path,
        path: &Path,
        exclude: &[String],
        entries: &mut Vec<SweepTreeEntry>,
    ) -> Result<(), String> {
        let mut children = fs::read_dir(path)
            .map_err(|error| {
                format!(
                    "source-shelf-sweep-tree-read-failed {}: {error}",
                    path.display()
                )
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            let child_path = child.path();
            let relative_path = child_path
                .strip_prefix(root)
                .map_err(|error| error.to_string())?
                .to_path_buf();
            validate_relative_path(&relative_path)?;
            if source_shelf_excluded(exclude, &relative_path) {
                continue;
            }
            let kind = child
                .file_type()
                .map_err(|error| format!("source-shelf-sweep-entry-type-failed: {error}"))?;
            if kind.is_symlink() || (!kind.is_dir() && !kind.is_file()) {
                return Err(format!(
                    "source-shelf-sweep-entry-kind-rejected {}",
                    child_path.display()
                ));
            }
            entries.push(SweepTreeEntry {
                relative_path: relative_path.clone(),
                is_dir: kind.is_dir(),
            });
            if kind.is_dir() {
                walk(root, &child_path, exclude, entries)?;
            }
        }
        Ok(())
    }
    walk(root, root, exclude, &mut entries)?;
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(entries)
}

fn sweep_internal_quarantine_path(target_root: &Path, relative: &Path) -> bool {
    let Some(Component::Normal(component)) = relative.components().next() else {
        return false;
    };
    let Some(name) = component.to_str() else {
        return false;
    };
    let Some(suffix) = name.strip_prefix(".harmonia-source-shelf-sweep-") else {
        return false;
    };
    let Some((pid, nanos)) = suffix.split_once('-') else {
        return false;
    };
    if pid.is_empty()
        || nanos.is_empty()
        || !pid.bytes().all(|byte| byte.is_ascii_digit())
        || !nanos.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    fs::symlink_metadata(target_root.join(component))
        .is_ok_and(|metadata| metadata.file_type().is_dir())
}

fn inventory_sweep_tree_if_present(
    root: &Path,
    exclude: &[String],
) -> Result<Vec<SweepTreeEntry>, String> {
    match fs::symlink_metadata(root) {
        Ok(_) => inventory_sweep_tree(root, exclude),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(format!(
            "source-shelf-sweep-target-metadata-failed {}: {error}",
            root.display()
        )),
    }
}

fn orphan_removal_state(
    target: &Path,
    relative: &Path,
) -> Result<SourceShelfSweepOrphanRemoval, String> {
    let metadata = fs::symlink_metadata(target).map_err(|error| {
        format!(
            "source-shelf-sweep-orphan-metadata-failed {}: {error}",
            target.display()
        )
    })?;
    let file_type = metadata.file_type();
    if !file_type.is_file() && !file_type.is_dir() {
        return Err(format!(
            "source-shelf-sweep-orphan-entry-kind-rejected {}",
            target.display()
        ));
    }
    Ok(SourceShelfSweepOrphanRemoval {
        target: target.to_path_buf(),
        path: relative.display().to_string(),
        pre_removal_size_hint: metadata.len(),
        pre_removal_sha256: if file_type.is_file() {
            Some(digest_file(target)?)
        } else {
            None
        },
    })
}

fn digest_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "source-shelf-sweep-file-read-failed {}: {error}",
            path.display()
        )
    })?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn sync_authorized_parent(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: crate::atoms::r#do::InvocationKey,
    launcher_root: &Path,
    path: &Path,
    newly_created: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("source-shelf-sweep-parent-missing {}", path.display()))?;
    if !parent.starts_with(launcher_root) {
        return Err(format!(
            "source-shelf-sweep-parent-outside-launcher-root {}",
            parent.display()
        ));
    }
    let mut missing = Vec::new();
    let mut cursor = parent;
    while cursor != launcher_root {
        if cursor.exists() {
            break;
        }
        missing.push(cursor.to_path_buf());
        cursor = cursor
            .parent()
            .ok_or_else(|| format!("source-shelf-sweep-parent-missing {}", cursor.display()))?;
    }
    crate::atoms::r#do::source_shelf::mkdir_all(authorization, invocation, parent)?;
    newly_created.extend(missing);
    sync_sweep_directory(parent)
}

fn remove_new_launcher_dirs(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: crate::atoms::r#do::InvocationKey,
    launcher_root: &Path,
    newly_created: &mut Vec<PathBuf>,
) -> Result<(), String> {
    newly_created.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    newly_created.dedup();
    let mut errors = Vec::new();
    for path in newly_created.iter() {
        if !path.starts_with(launcher_root) || path == launcher_root {
            continue;
        }
        match crate::atoms::r#do::symlink_converge::remove_dir(authorization, invocation, path) {
            Ok(()) => {
                if let Some(parent) = path.parent() {
                    if let Err(error) = sync_sweep_directory(parent) {
                        errors.push(format!(
                            "sync removed-directory parent {}: {error}",
                            parent.display()
                        ));
                    }
                }
            }
            Err(error) if error.contains("No such file") => {}
            Err(error) => errors.push(format!(
                "remove created directory {}: {error}",
                path.display()
            )),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn sync_sweep_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            format!(
                "source-shelf-sweep-directory-sync-failed {}: {error}",
                path.display()
            )
        })
}

fn stage_sweep_tree(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: crate::atoms::r#do::InvocationKey,
    source: &Path,
    stage: &Path,
    entries: &[SweepTreeEntry],
    directory_mode: u32,
    file_mode: u32,
    uid: u32,
    gid: u32,
) -> Result<(), String> {
    crate::atoms::r#do::make_dir::create_dir_all(authorization, invocation, stage).map_err(
        |error| {
            format!(
                "source-shelf-sweep-stage-create-failed {}: {error}",
                stage.display()
            )
        },
    )?;
    crate::atoms::r#do::change_mode::change(
        authorization,
        invocation,
        &crate::atoms::r#do::change_mode::Plan {
            path: stage.to_path_buf(),
            mode: Some(directory_mode),
            no_follow: true,
        },
    )?;
    crate::atoms::r#do::change_owner::change(
        authorization,
        invocation,
        &crate::atoms::r#do::change_owner::Plan {
            path: stage.to_path_buf(),
            uid: Some(uid),
            gid: Some(gid),
            no_follow: true,
        },
    )?;
    for entry in entries
        .iter()
        .filter(|entry| entry.relative_path != Path::new("."))
    {
        let source_path = source.join(&entry.relative_path);
        let target_path = stage.join(&entry.relative_path);
        if entry.is_dir {
            crate::atoms::r#do::make_dir::create_dir_all(authorization, invocation, &target_path)
                .map_err(|error| {
                format!(
                    "source-shelf-sweep-stage-directory-failed {}: {error}",
                    target_path.display()
                )
            })?;
            crate::atoms::r#do::change_mode::change(
                authorization,
                invocation,
                &crate::atoms::r#do::change_mode::Plan {
                    path: target_path.clone(),
                    mode: Some(directory_mode),
                    no_follow: true,
                },
            )?;
            crate::atoms::r#do::change_owner::change(
                authorization,
                invocation,
                &crate::atoms::r#do::change_owner::Plan {
                    path: target_path.clone(),
                    uid: Some(uid),
                    gid: Some(gid),
                    no_follow: true,
                },
            )?;
        } else {
            let parent = target_path.parent().ok_or_else(|| {
                format!(
                    "source-shelf-sweep-stage-parent-missing {}",
                    target_path.display()
                )
            })?;
            crate::atoms::r#do::copy_file::copy(
                authorization,
                invocation,
                &crate::atoms::r#do::copy_file::Plan {
                    source: source_path,
                    target: target_path.clone(),
                    mode: Some(file_mode),
                    uid: Some(uid),
                    gid: Some(gid),
                    no_follow: true,
                    restore: None,
                },
            )?;
            sync_sweep_directory(parent)?;
        }
    }
    let mut directories: Vec<_> = entries
        .iter()
        .filter(|entry| entry.is_dir)
        .map(|entry| {
            if entry.relative_path == Path::new(".") {
                stage.to_path_buf()
            } else {
                stage.join(&entry.relative_path)
            }
        })
        .collect();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        sync_sweep_directory(&directory)?;
    }
    Ok(())
}

fn sweep_path_state(
    path: &Path,
    is_dir: bool,
) -> Result<(Option<String>, Option<u32>, Option<u32>, Option<u32>), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || (is_dir && !metadata.file_type().is_dir())
                || (!is_dir && !metadata.file_type().is_file())
            {
                return Ok((None, None, None, None));
            }
            let digest = if is_dir {
                None
            } else {
                Some(digest_file(path)?)
            };
            #[cfg(unix)]
            let ownership = (Some(metadata.uid()), Some(metadata.gid()));
            #[cfg(not(unix))]
            let ownership = (None, None);
            Ok((digest, Some(file_mode(path)?), ownership.0, ownership.1))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((None, None, None, None)),
        Err(error) => Err(format!(
            "source-shelf-sweep-path-metadata-failed {}: {error}",
            path.display()
        )),
    }
}

fn shelf_is_current(
    source: &Path,
    target: &Path,
    source_entries: &[SweepTreeEntry],
    directory_mode: u32,
    file_mode: u32,
    uid: u32,
    gid: u32,
    exclude: &[String],
) -> Result<bool, String> {
    let target_entries = inventory_sweep_tree_if_present(target, exclude)?;
    if source_entries != target_entries {
        return Ok(false);
    }
    for entry in source_entries {
        let source_path = if entry.relative_path == Path::new(".") {
            source.to_path_buf()
        } else {
            source.join(&entry.relative_path)
        };
        let target_path = if entry.relative_path == Path::new(".") {
            target.to_path_buf()
        } else {
            target.join(&entry.relative_path)
        };
        let (target_digest, target_mode, target_uid, target_gid) =
            sweep_path_state(&target_path, entry.is_dir)?;
        let desired_mode = if entry.is_dir {
            directory_mode
        } else {
            file_mode
        };
        if target_mode != Some(desired_mode)
            || target_uid != Some(uid)
            || target_gid != Some(gid)
            || (!entry.is_dir && target_digest != Some(digest_file(&source_path)?))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn source_launchers(
    source_root: &Path,
    pattern: &str,
    exclude: &[String],
) -> Result<BTreeMap<String, PathBuf>, String> {
    fn walk(
        root: &Path,
        dir: &Path,
        pattern: &str,
        exclude: &[String],
        out: &mut BTreeMap<String, PathBuf>,
    ) -> Result<(), String> {
        for entry in fs::read_dir(dir).map_err(|error| {
            format!(
                "source-shelf-sweep-launcher-source-read-failed {}: {error}",
                dir.display()
            )
        })? {
            let entry = entry.map_err(|error| error.to_string())?;
            let path = entry.path();
            let relative = path.strip_prefix(root).map_err(|error| error.to_string())?;
            // An excluded entry owns no recursive walk: do this before kind
            // checks so excluded symlinks (for example venv/lib64) are inert.
            if source_shelf_excluded(exclude, relative) {
                continue;
            }
            let kind = entry.file_type().map_err(|error| error.to_string())?;
            if kind.is_symlink() {
                return Err(format!(
                    "source-shelf-sweep-launcher-source-kind-rejected {}",
                    path.display()
                ));
            }
            if kind.is_dir() {
                walk(root, &path, pattern, exclude, out)?;
                continue;
            }
            let name = relative.to_string_lossy().replace('\\', "/");
            let basename = relative
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("");
            if basename_pattern_matches(pattern, basename)
                && !source_shelf_excluded(exclude, relative)
            {
                out.insert(name, path);
            }
        }
        Ok(())
    }
    let mut launchers = BTreeMap::new();
    walk(source_root, source_root, pattern, exclude, &mut launchers)?;
    if launchers.is_empty() {
        return Err(format!(
            "source-shelf-sweep-launcher-pattern-empty {pattern:?}"
        ));
    }
    Ok(launchers)
}

fn target_pattern_files(
    target_root: &Path,
    pattern: &str,
    exclude: &[String],
) -> Result<BTreeSet<String>, String> {
    fn walk(
        root: &Path,
        dir: &Path,
        pattern: &str,
        exclude: &[String],
        out: &mut BTreeSet<String>,
    ) -> Result<(), String> {
        if !dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(dir).map_err(|error| {
            format!(
                "source-shelf-sweep-launcher-target-read-failed {}: {error}",
                dir.display()
            )
        })? {
            let entry = entry.map_err(|error| error.to_string())?;
            let path = entry.path();
            let relative = path.strip_prefix(root).map_err(|error| error.to_string())?;
            // Match the source walk: an excluded subtree is not inspected,
            // classified, or treated as an orphan candidate.
            if source_shelf_excluded(exclude, relative) {
                continue;
            }
            let kind = entry.file_type().map_err(|error| error.to_string())?;
            if kind.is_dir() {
                walk(root, &path, pattern, exclude, out)?;
                continue;
            }
            if kind.is_symlink() {
                return Err(format!(
                    "source-shelf-sweep-launcher-target-kind-rejected {}",
                    path.display()
                ));
            }
            let name = relative.to_string_lossy().replace('\\', "/");
            let basename = relative
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("");
            if basename_pattern_matches(pattern, basename)
                && !source_shelf_excluded(exclude, relative)
                && !basename.starts_with(".harmonia-source-shelf-sweep-")
            {
                out.insert(name);
            }
        }
        Ok(())
    }
    let mut names = BTreeSet::new();
    walk(target_root, target_root, pattern, exclude, &mut names)?;
    Ok(names)
}

fn launcher_is_current(
    source: &Path,
    target: &Path,
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<bool, String> {
    let (digest, target_mode, target_uid, target_gid) = sweep_path_state(target, false)?;
    Ok(digest == Some(digest_file(source)?)
        && target_mode == Some(mode)
        && target_uid == Some(uid)
        && target_gid == Some(gid))
}

fn build_sweep_entries(
    request: &SourceShelfSweepRequest,
    shelf_source: &Path,
    source_entries: &[SweepTreeEntry],
    launchers: &BTreeMap<String, PathBuf>,
    stale: &BTreeSet<String>,
    uid: u32,
    gid: u32,
    after: bool,
) -> Result<Vec<SourceShelfSweepEntry>, String> {
    let mut entries = Vec::new();
    for entry in source_entries {
        let source = if entry.relative_path == Path::new(".") {
            shelf_source.to_path_buf()
        } else {
            shelf_source.join(&entry.relative_path)
        };
        let target = if entry.relative_path == Path::new(".") {
            request.target_shelf.clone()
        } else {
            request.target_shelf.join(&entry.relative_path)
        };
        let (before_digest, before_mode, before_uid, before_gid) =
            sweep_path_state(&target, entry.is_dir)?;
        let source_digest = if entry.is_dir {
            None
        } else {
            Some(digest_file(&source)?)
        };
        let desired_mode = if entry.is_dir {
            request.shelf_directory_mode
        } else {
            request.shelf_file_mode
        };
        let current = before_mode == Some(desired_mode)
            && before_uid == Some(uid)
            && before_gid == Some(gid)
            && (entry.is_dir || before_digest == source_digest);
        entries.push(SourceShelfSweepEntry {
            kind: if entry.is_dir {
                "shelf-directory"
            } else {
                "shelf-file"
            }
            .into(),
            relative_path: entry.relative_path.to_string_lossy().into_owned(),
            source: Some(source),
            target,
            source_digest: source_digest.clone(),
            before_digest: if after {
                source_digest.clone()
            } else {
                before_digest.clone()
            },
            after_digest: if after { source_digest } else { before_digest },
            desired_mode,
            before_mode: if after {
                Some(desired_mode)
            } else {
                before_mode
            },
            after_mode: if after {
                Some(desired_mode)
            } else {
                before_mode
            },
            desired_uid: uid,
            desired_gid: gid,
            before_uid: if after { Some(uid) } else { before_uid },
            before_gid: if after { Some(gid) } else { before_gid },
            after_uid: if after { Some(uid) } else { before_uid },
            after_gid: if after { Some(gid) } else { before_gid },
            action: if current {
                "unchanged"
            } else if after {
                "promoted"
            } else {
                "planned"
            }
            .into(),
            changed: !current,
            readback_ok: after || current,
            rollback_action: "not-needed".into(),
            rollback_readback_ok: None,
            orphan_removal: None,
        });
    }
    for (name, source) in launchers {
        let target = request.launcher_target_root.join(name);
        let (before_digest, before_mode, before_uid, before_gid) =
            sweep_path_state(&target, false)?;
        let source_digest = Some(digest_file(source)?);
        let current = before_digest == source_digest
            && before_mode == Some(request.launcher_mode)
            && before_uid == Some(uid)
            && before_gid == Some(gid);
        entries.push(SourceShelfSweepEntry {
            kind: "launcher".into(),
            relative_path: name.clone(),
            source: Some(source.clone()),
            target,
            source_digest: source_digest.clone(),
            before_digest: if after {
                source_digest.clone()
            } else {
                before_digest.clone()
            },
            after_digest: if after { source_digest } else { before_digest },
            desired_mode: request.launcher_mode,
            before_mode: if after {
                Some(request.launcher_mode)
            } else {
                before_mode
            },
            after_mode: if after {
                Some(request.launcher_mode)
            } else {
                before_mode
            },
            desired_uid: uid,
            desired_gid: gid,
            before_uid: if after { Some(uid) } else { before_uid },
            before_gid: if after { Some(gid) } else { before_gid },
            after_uid: if after { Some(uid) } else { before_uid },
            after_gid: if after { Some(gid) } else { before_gid },
            action: if current {
                "unchanged"
            } else if after {
                "promoted"
            } else {
                "planned"
            }
            .into(),
            changed: !current,
            readback_ok: after || current,
            rollback_action: "not-needed".into(),
            rollback_readback_ok: None,
            orphan_removal: None,
        });
    }
    for name in stale {
        let target = request.launcher_target_root.join(name);
        let (digest, mode, observed_uid, observed_gid) = sweep_path_state(&target, false)?;
        entries.push(SourceShelfSweepEntry {
            kind: "stale-launcher".into(),
            relative_path: name.clone(),
            source: None,
            target,
            source_digest: None,
            before_digest: if after { None } else { digest.clone() },
            after_digest: if after { None } else { digest },
            desired_mode: request.launcher_mode,
            before_mode: if after { None } else { mode },
            after_mode: if after { None } else { mode },
            desired_uid: uid,
            desired_gid: gid,
            before_uid: if after { None } else { observed_uid },
            before_gid: if after { None } else { observed_gid },
            after_uid: if after { None } else { observed_uid },
            after_gid: if after { None } else { observed_gid },
            action: if request.prune {
                if after {
                    "removed"
                } else {
                    "planned-removal"
                }
            } else {
                "preserved"
            }
            .into(),
            changed: request.prune,
            readback_ok: after || !request.prune,
            rollback_action: "not-needed".into(),
            rollback_readback_ok: None,
            orphan_removal: None,
        });
    }
    Ok(entries)
}

fn readback_sweep_entries(
    mut entries: Vec<SourceShelfSweepEntry>,
) -> Result<Vec<SourceShelfSweepEntry>, String> {
    for entry in &mut entries {
        let stale = entry.kind == "stale-launcher";
        let is_dir = entry.kind == "shelf-directory";
        let (digest, mode, uid, gid) = sweep_path_state(&entry.target, is_dir)?;
        entry.after_digest = digest.clone();
        entry.after_mode = mode;
        entry.after_uid = uid;
        entry.after_gid = gid;
        if stale {
            entry.readback_ok =
                digest.is_none() && mode.is_none() && uid.is_none() && gid.is_none();
            entry.action = if entry.readback_ok {
                "removed"
            } else {
                "remove-failed"
            }
            .into();
        } else {
            entry.readback_ok = mode == Some(entry.desired_mode)
                && uid == Some(entry.desired_uid)
                && gid == Some(entry.desired_gid)
                && (is_dir || digest == entry.source_digest);
            entry.action = if !entry.changed {
                "unchanged"
            } else if entry.readback_ok {
                "promoted"
            } else {
                "readback-failed"
            }
            .into();
        }
    }
    Ok(entries)
}

fn readback_rollback_entries(
    mut entries: Vec<SourceShelfSweepEntry>,
) -> Result<Vec<SourceShelfSweepEntry>, String> {
    for entry in &mut entries {
        let is_dir = entry.kind == "shelf-directory";
        let (digest, mode, uid, gid) = sweep_path_state(&entry.target, is_dir)?;
        entry.after_digest = digest.clone();
        entry.after_mode = mode;
        entry.after_uid = uid;
        entry.after_gid = gid;
        let restored = digest == entry.before_digest
            && mode == entry.before_mode
            && uid == entry.before_uid
            && gid == entry.before_gid;
        entry.rollback_action = if entry.changed {
            "restored"
        } else {
            "preserved"
        }
        .into();
        entry.rollback_readback_ok = Some(restored);
        entry.readback_ok = restored;
        entry.action = "rolled-back".into();
    }
    Ok(entries)
}

fn write_sweep_receipts(
    receipt_dir: &Path,
    request: &SourceShelfSweepRequest,
    outcome: &SourceShelfSweepOutcome,
    apply: bool,
) -> Result<(), String> {
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
    let base = request.receipt_name.trim_end_matches(".json");
    for (index, entry) in outcome.entries.iter().enumerate() {
        // Unchanged observations belong in the closing run receipt only.
        if !entry.changed {
            continue;
        }
        let safe = entry
            .relative_path
            .replace(['/', '\\'], "_")
            .trim_matches('_')
            .to_string();
        let lane = if matches!(entry.kind.as_str(), "launcher" | "stale-launcher") {
            "launcher"
        } else {
            "file"
        };
        crate::atoms::attest::write_json_atomic(
            &receipt_dir.join(format!("{base}-{lane}-{index:04}-{safe}.json")),
            &json!({
                "schema": "harmonia.files.source_shelf_sweep.file.v1",
                "ok": outcome.ok && entry.readback_ok,
                "apply": apply,
                "atomicity": "per-path atomic",
                "transaction": "all-or-restored",
                "receipt_write_contract": "same-directory temp write, file fsync, atomic rename, parent-directory fsync",
                "entry": entry,
                "observed_state": {"before_digest": entry.before_digest, "before_mode": entry.before_mode, "before_uid": entry.before_uid, "before_gid": entry.before_gid},
                "desired_state": {"source_digest": entry.source_digest, "mode": entry.desired_mode, "uid": entry.desired_uid, "gid": entry.desired_gid},
                "diff_decision": if entry.changed { "different" } else { "empty" },
                "movement": entry.action,
                "truthful_changed": entry.changed && outcome.changed,
                "first_blocker": if entry.readback_ok { "none" } else { outcome.first_blocker.as_str() },
            }),
        )?;
    }
    let receipt_name = if request.receipt_name.ends_with(".json") {
        request.receipt_name.clone()
    } else {
        format!("{}.json", request.receipt_name)
    };
    crate::atoms::attest::write_json_atomic(
        &receipt_dir.join(receipt_name),
        &json!({
            "schema": "harmonia.files.source_shelf_sweep.transaction.v1",
            "ok": outcome.ok,
            "apply": apply,
            "changed": outcome.changed,
            "observed_state": {"source_inventory_count": outcome.source_inventory_count, "target_inventory_count_before": outcome.target_inventory_count_before, "current": outcome.current},
            "desired_state": {"shelf_source": request.shelf_source, "target_shelf": request.target_shelf, "prune": request.prune},
            "diff_decision": if outcome.current && !outcome.changed { "empty" } else { "different" },
            "movement": if outcome.changed { "shelf-promote-or-bounded-removal" } else if outcome.current { "none" } else { "report-only" },
            "truthful_changed": outcome.changed,
            "current": outcome.current,
            "atomicity": "per-path atomic",
            "transaction_contract": "all-or-restored",
            "whole_set_atomic": false,
            "receipt_write_contract": "same-directory temp write, file fsync, atomic rename, parent-directory fsync",
            "source_root": request.source_root,
            "shelf_source": request.shelf_source,
            "target_shelf": request.target_shelf,
            "launcher_source_root": request.launcher_source_root,
            "launcher_target_root": request.launcher_target_root,
            "launcher_pattern": request.launcher_pattern,
            "shelf_owner": request.shelf_owner,
            "shelf_group": request.shelf_group,
            "shelf_directory_mode": request.shelf_directory_mode,
            "shelf_file_mode": request.shelf_file_mode,
            "launcher_mode": request.launcher_mode,
            "prune": request.prune,
            "source_inventory_count": outcome.source_inventory_count,
            "target_inventory_count_before": outcome.target_inventory_count_before,
            "target_inventory_count_after": outcome.target_inventory_count_after,
            "promoted_count": outcome.promoted_count,
            "removed_count": outcome.removed_count,
            "transaction_state": outcome.transaction_state,
            "rollback_state": outcome.rollback_state,
            "first_blocker": outcome.first_blocker,
            "entries": outcome.entries,
        }),
    )
}

pub fn source_shelf_sweep(
    request: &SourceShelfSweepRequest,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<SourceShelfSweepOutcome, String> {
    if apply && invocation.is_none() {
        return Err("source-shelf-sweep-invocation-key-missing".into());
    }
    if request.owned_recursive {
        let shelf_outcome =
            source_shelf_owned_recursive_sweep(request, receipt_dir, apply, invocation)?;
        if request.launcher_pattern == ".harmonia-no-flat-launchers" {
            return Ok(shelf_outcome);
        }

        // Recursive shelf entries and flat launchers have different ownership
        // shapes. Preserve the shelf pass, then run the declared launcher lane
        // through the established launcher-only transaction.
        let mut launcher_request = request.clone();
        launcher_request.source_root = request.launcher_source_root.clone();
        launcher_request.shelf_source = PathBuf::from(".");
        launcher_request.target_shelf = request.launcher_target_root.clone();
        launcher_request.owned_recursive = false;
        launcher_request.receipt_name = format!("{}-launcher-pass", request.receipt_name);
        let launcher_outcome = source_shelf_sweep_with_fault(
            &launcher_request,
            receipt_dir,
            apply,
            SourceShelfSweepFault::default(),
            invocation,
        )?;
        let mut outcome = SourceShelfSweepOutcome {
            ok: shelf_outcome.ok && launcher_outcome.ok,
            changed: shelf_outcome.changed || launcher_outcome.changed,
            current: shelf_outcome.current && launcher_outcome.current,
            source_inventory_count: shelf_outcome.source_inventory_count
                + launcher_outcome.source_inventory_count,
            target_inventory_count_before: shelf_outcome.target_inventory_count_before
                + launcher_outcome.target_inventory_count_before,
            target_inventory_count_after: shelf_outcome.target_inventory_count_after
                + launcher_outcome.target_inventory_count_after,
            promoted_count: shelf_outcome.promoted_count + launcher_outcome.promoted_count,
            removed_count: shelf_outcome.removed_count + launcher_outcome.removed_count,
            transaction_state: if shelf_outcome.changed || launcher_outcome.changed {
                "committed"
            } else if shelf_outcome.current && launcher_outcome.current {
                "unchanged"
            } else {
                "planned"
            }
            .into(),
            rollback_state: if shelf_outcome.rollback_state == "not-needed"
                && launcher_outcome.rollback_state == "not-needed"
            {
                "not-needed".into()
            } else {
                format!(
                    "shelf={};launchers={}",
                    shelf_outcome.rollback_state, launcher_outcome.rollback_state
                )
            },
            first_blocker: if shelf_outcome.first_blocker != "none" {
                shelf_outcome.first_blocker.clone()
            } else {
                launcher_outcome.first_blocker.clone()
            },
            entries: shelf_outcome.entries,
            message: "owned recursive source shelf and flat launchers observed".into(),
        };
        outcome.entries.extend(launcher_outcome.entries);
        write_sweep_receipts(receipt_dir, request, &outcome, apply)?;
        let launcher_pass_prefix = format!(
            "{}-launcher-pass",
            request.receipt_name.trim_end_matches(".json")
        );
        for entry in fs::read_dir(receipt_dir).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(&launcher_pass_prefix) && name.ends_with(".json") {
                crate::atoms::attest::remove_artifact(&entry.path()).map_err(|error| {
                    format!(
                        "source-shelf-sweep-launcher-pass-receipt-cleanup-failed {}: {error}",
                        entry.path().display()
                    )
                })?;
            }
        }
        sync_sweep_directory(receipt_dir)?;
        return Ok(outcome);
    }
    match source_shelf_sweep_with_fault(
        request,
        receipt_dir,
        apply,
        SourceShelfSweepFault::default(),
        invocation,
    ) {
        Ok(outcome) => Ok(outcome),
        Err(blocker) => {
            if validate_receipt_name(&request.receipt_name).is_ok() {
                let receipt_name = if request.receipt_name.ends_with(".json") {
                    request.receipt_name.clone()
                } else {
                    format!("{}.json", request.receipt_name)
                };
                let receipt_path = receipt_dir.join(receipt_name);
                let stale = fs::read(&receipt_path)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                    .and_then(|receipt| {
                        receipt
                            .get("first_blocker")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_string)
                    })
                    .is_none_or(|first_blocker| first_blocker != blocker);
                if !receipt_path.exists() || stale {
                    let outcome = SourceShelfSweepOutcome {
                        ok: false,
                        changed: false,
                        current: false,
                        source_inventory_count: 0,
                        target_inventory_count_before: 0,
                        target_inventory_count_after: 0,
                        promoted_count: 0,
                        removed_count: 0,
                        transaction_state: "refused".into(),
                        rollback_state: "not-needed".into(),
                        first_blocker: blocker.clone(),
                        entries: Vec::new(),
                        message: blocker.clone(),
                    };
                    if let Err(receipt_error) =
                        write_sweep_receipts(receipt_dir, request, &outcome, apply)
                    {
                        return Err(format!("{blocker}; receipt-write-failed: {receipt_error}"));
                    }
                }
            }
            Err(blocker)
        }
    }
}

fn source_shelf_owned_recursive_sweep(
    request: &SourceShelfSweepRequest,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<SourceShelfSweepOutcome, String> {
    if apply && invocation.is_none() {
        return Err("source-shelf-sweep-invocation-key-missing".into());
    }
    validate_receipt_name(&request.receipt_name)?;
    validate_source_shelf_relative_path(&request.shelf_source)?;
    let sweep_exclude = source_shelf_sweep_exclude(&request.launcher_exclude);
    let provenance_path = request
        .provenance_state
        .as_ref()
        .ok_or_else(|| "source-shelf-sweep-owned-recursive-provenance-required".to_string())?;
    if !request.target_shelf.is_absolute() || !request.target_shelf.is_dir() {
        return Err("source-shelf-sweep-owned-recursive-target-root-invalid".into());
    }
    validate_mode("shelf-directory", request.shelf_directory_mode)?;
    validate_mode("shelf-file", request.shelf_file_mode)?;
    reject_ssh_path(&request.target_shelf)?;
    reject_symlink_components(&request.target_shelf)?;
    let source_root = request.source_root.canonicalize().map_err(|error| {
        format!(
            "source-shelf-sweep-source-root-invalid {}: {error}",
            request.source_root.display()
        )
    })?;
    let shelf_source = source_root
        .join(&request.shelf_source)
        .canonicalize()
        .map_err(|error| {
            format!(
                "source-shelf-sweep-shelf-source-invalid {}: {error}",
                request.shelf_source.display()
            )
        })?;
    shelf_source.strip_prefix(&source_root).map_err(|_| {
        format!(
            "source-shelf-sweep-shelf-source-outside-root {}",
            shelf_source.display()
        )
    })?;
    let uid = resolve_uid(&request.shelf_owner)
        .map_err(|error| format!("source-shelf-sweep-owner-resolution-failed: {error}"))?;
    let gid = resolve_gid(&request.shelf_group)
        .map_err(|error| format!("source-shelf-sweep-group-resolution-failed: {error}"))?;
    // Keep the source root in the inventory: it is an owned directory whose
    // declared mode must converge just like every child directory.
    let desired: Vec<SweepTreeEntry> = inventory_sweep_tree(&shelf_source, &sweep_exclude)?;
    let desired_paths: BTreeSet<String> = desired
        .iter()
        .map(|entry| {
            let target = if entry.relative_path == Path::new(".") {
                request.target_shelf.clone()
            } else {
                request.target_shelf.join(&entry.relative_path)
            };
            target.display().to_string()
        })
        .collect();
    let mut provenance = load_sweep_provenance(provenance_path)?;
    provenance.paths.retain(|path| {
        Path::new(path)
            .strip_prefix(&request.target_shelf)
            .ok()
            .is_none_or(|relative| !source_shelf_excluded(&sweep_exclude, relative))
    });
    let target_inventory = inventory_sweep_tree_if_present(&request.target_shelf, &sweep_exclude)?;
    let mut orphan_stale = BTreeSet::new();
    for target_entry in target_inventory
        .iter()
        .filter(|entry| entry.relative_path != Path::new("."))
    {
        // A committed sweep intentionally retains its rollback quarantine under
        // the target root. It is internal sweep state, not foreign material;
        // absent-source, unledgered paths are removable only in prune mode.
        if sweep_internal_quarantine_path(&request.target_shelf, &target_entry.relative_path) {
            continue;
        }
        let target_path = request.target_shelf.join(&target_entry.relative_path);
        let target_path_string = target_path.display().to_string();
        if !desired_paths.contains(&target_path_string)
            && !provenance.paths.contains(&target_path_string)
        {
            if request.prune {
                orphan_stale.insert(target_entry.relative_path.clone());
                continue;
            }
            let blocker = format!(
                "source-shelf-sweep-provenance-refused-unowned-target {}",
                target_path.display()
            );
            let outcome = SourceShelfSweepOutcome {
                ok: false,
                changed: false,
                current: false,
                source_inventory_count: desired.len(),
                target_inventory_count_before: target_inventory.len(),
                target_inventory_count_after: target_inventory.len(),
                promoted_count: 0,
                removed_count: 0,
                transaction_state: "refused".into(),
                rollback_state: "not-needed".into(),
                first_blocker: blocker.clone(),
                entries: Vec::new(),
                message: blocker.clone(),
            };
            write_sweep_receipts(receipt_dir, request, &outcome, apply)?;
            return Err(blocker);
        }
    }
    let mut stale: Vec<PathBuf> = provenance
        .paths
        .iter()
        .filter_map(|path| {
            let absolute = PathBuf::from(path);
            absolute
                .strip_prefix(&request.target_shelf)
                .ok()
                .and_then(|relative| {
                    (!relative.as_os_str().is_empty()
                        && !source_shelf_excluded(&sweep_exclude, relative)
                        && !desired_paths.contains(path))
                    .then(|| relative.to_path_buf())
                })
        })
        .collect();
    stale.extend(orphan_stale.iter().cloned());
    stale.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    stale.dedup();
    let mut entries = Vec::new();
    let mut drift = !stale.is_empty();
    for entry in &desired {
        let source = if entry.relative_path == Path::new(".") {
            shelf_source.to_path_buf()
        } else {
            shelf_source.join(&entry.relative_path)
        };
        let target = if entry.relative_path == Path::new(".") {
            request.target_shelf.clone()
        } else {
            request.target_shelf.join(&entry.relative_path)
        };
        // Source presence is explicit ownership for this sweep; the ledger
        // remains authoritative only for paths absent from the source.
        let source_owned = desired_paths.contains(&target.display().to_string());
        let ledger_owned = provenance.paths.contains(&target.display().to_string());
        let owned = source_owned || ledger_owned;
        let current = if entry.is_dir && target.exists() && !owned {
            true
        } else {
            let (digest, mode, observed_uid, observed_gid) =
                sweep_path_state(&target, entry.is_dir)?;
            if !owned && target.exists() && !entry.is_dir {
                digest == Some(digest_file(&source)?)
            } else {
                mode == Some(if entry.is_dir {
                    request.shelf_directory_mode
                } else {
                    request.shelf_file_mode
                }) && observed_uid == Some(uid)
                    && observed_gid == Some(gid)
                    && (entry.is_dir || digest == Some(digest_file(&source)?))
            }
        };
        drift |= !current;
        let (before_digest, before_mode, before_uid, before_gid) =
            sweep_path_state(&target, entry.is_dir)?;
        let source_digest = if entry.is_dir {
            None
        } else {
            Some(digest_file(&source)?)
        };
        let desired_mode = if entry.is_dir {
            request.shelf_directory_mode
        } else {
            request.shelf_file_mode
        };
        entries.push(SourceShelfSweepEntry {
            kind: if entry.is_dir {
                "owned-recursive-directory"
            } else {
                "owned-recursive-file"
            }
            .into(),
            relative_path: entry.relative_path.display().to_string(),
            source: Some(source),
            target,
            source_digest: source_digest.clone(),
            before_digest: before_digest.clone(),
            after_digest: before_digest,
            desired_mode,
            before_mode,
            after_mode: before_mode,
            desired_uid: uid,
            desired_gid: gid,
            before_uid,
            before_gid,
            after_uid: before_uid,
            after_gid: before_gid,
            action: if current { "unchanged" } else { "planned" }.into(),
            changed: !current,
            readback_ok: current,
            rollback_action: "not-needed".into(),
            rollback_readback_ok: None,
            orphan_removal: None,
        });
    }
    for relative in &stale {
        entries.push(SourceShelfSweepEntry {
            kind: "stale-owned-recursive-path".into(),
            relative_path: relative.display().to_string(),
            source: None,
            target: request.target_shelf.join(relative),
            source_digest: None,
            before_digest: None,
            after_digest: None,
            desired_mode: request.shelf_file_mode,
            before_mode: None,
            after_mode: None,
            desired_uid: uid,
            desired_gid: gid,
            before_uid: None,
            before_gid: None,
            after_uid: None,
            after_gid: None,
            action: "quarantined".into(),
            changed: true,
            readback_ok: false,
            rollback_action: "quarantine-preserved".into(),
            rollback_readback_ok: None,
            orphan_removal: if orphan_stale.contains(relative) {
                Some(orphan_removal_state(
                    &request.target_shelf.join(relative),
                    relative,
                )?)
            } else {
                None
            },
        });
    }
    if !apply {
        let outcome = SourceShelfSweepOutcome {
            ok: !drift,
            changed: false,
            current: !drift,
            source_inventory_count: desired.len(),
            target_inventory_count_before: 0,
            target_inventory_count_after: 0,
            promoted_count: 0,
            removed_count: 0,
            transaction_state: if drift { "planned" } else { "unchanged" }.into(),
            rollback_state: "not-needed".into(),
            first_blocker: if drift {
                "source-shelf-sweep-not-converged".into()
            } else {
                "none".into()
            },
            entries,
            message: "owned recursive source shelf sweep planned".into(),
        };
        write_sweep_receipts(receipt_dir, request, &outcome, apply)?;
        return Ok(outcome);
    }
    let quarantine = request
        .target_shelf
        .join(format!(".harmonia-source-shelf-sweep-{}", sweep_nonce()));
    let mut promoted_count = 0usize;
    let mut removed_count = 0usize;
    let movement = crate::atoms::comparison::execute_once(
        "source-shelf-owned-recursive",
        || Ok::<_, String>(true),
        |_| {
            if drift {
                crate::atoms::comparison::DiffDecision::Different
            } else {
                crate::atoms::comparison::DiffDecision::Empty
            }
        },
        |authorization, _| {
            (|| -> Result<(), String> {
                let invocation = invocation.ok_or("source-shelf-sweep-invocation-key-missing")?;
                crate::atoms::r#do::source_shelf::mkdir_all(
                    authorization,
                    invocation,
                    &quarantine,
                )?;
                for entry in &desired {
                    let source = if entry.relative_path == Path::new(".") {
                        shelf_source.to_path_buf()
                    } else {
                        shelf_source.join(&entry.relative_path)
                    };
                    let target = if entry.relative_path == Path::new(".") {
                        request.target_shelf.clone()
                    } else {
                        request.target_shelf.join(&entry.relative_path)
                    };
                    let target_path = target.display().to_string();
                    let source_owned = desired_paths.contains(&target_path);
                    let ledger_owned = provenance.paths.contains(&target_path);
                    let owned = source_owned || ledger_owned;
                    if source_owned {
                        provenance.paths.insert(target_path);
                    }
                    if entry.is_dir {
                        if !target.exists() {
                            crate::atoms::r#do::source_shelf::mkdir_all(
                                authorization,
                                invocation,
                                &target,
                            )
                            .map_err(|error| {
                                format!(
                                    "source-shelf-sweep-owned-directory-create-failed {}: {error}",
                                    target.display()
                                )
                            })?;
                            crate::atoms::r#do::change_mode::change(
                                authorization,
                                invocation,
                                &crate::atoms::r#do::change_mode::Plan {
                                    path: target.clone(),
                                    mode: Some(request.shelf_directory_mode),
                                    no_follow: true,
                                },
                            )?;
                            crate::atoms::r#do::change_owner::change(
                                authorization,
                                invocation,
                                &crate::atoms::r#do::change_owner::Plan {
                                    path: target.clone(),
                                    uid: Some(uid),
                                    gid: Some(gid),
                                    no_follow: true,
                                },
                            )?;
                            provenance.paths.insert(target.display().to_string());
                            promoted_count += 1;
                        } else {
                            let (_, observed_mode, observed_uid, observed_gid) =
                                sweep_path_state(&target, true)?;
                            let directory_changed = observed_mode
                                != Some(request.shelf_directory_mode)
                                || observed_uid != Some(uid)
                                || observed_gid != Some(gid);
                            if observed_mode != Some(request.shelf_directory_mode) {
                                crate::atoms::r#do::change_mode::change(
                                    authorization,
                                    invocation,
                                    &crate::atoms::r#do::change_mode::Plan {
                                        path: target.clone(),
                                        mode: Some(request.shelf_directory_mode),
                                        no_follow: true,
                                    },
                                )?;
                            }
                            if observed_uid != Some(uid) || observed_gid != Some(gid) {
                                crate::atoms::r#do::change_owner::change(
                                    authorization,
                                    invocation,
                                    &crate::atoms::r#do::change_owner::Plan {
                                        path: target.clone(),
                                        uid: Some(uid),
                                        gid: Some(gid),
                                        no_follow: true,
                                    },
                                )?;
                            }
                            if directory_changed {
                                promoted_count += 1;
                            }
                            provenance.paths.insert(target.display().to_string());
                        }
                    } else {
                        let (digest, mode, observed_uid, observed_gid) =
                            sweep_path_state(&target, false)?;
                        let current = if !owned && target.exists() {
                            digest == Some(digest_file(&source)?)
                        } else {
                            digest == Some(digest_file(&source)?)
                                && mode == Some(request.shelf_file_mode)
                                && observed_uid == Some(uid)
                                && observed_gid == Some(gid)
                        };
                        if current {
                            if !owned {
                                provenance.paths.insert(target.display().to_string());
                            }
                            continue;
                        }
                        if target.exists() {
                            let backup = quarantine.join(&entry.relative_path);
                            if let Some(parent) = backup.parent() {
                                crate::atoms::r#do::source_shelf::mkdir_all(
                                    authorization,
                                    invocation,
                                    parent,
                                )?;
                            }
                            crate::atoms::r#do::source_shelf::rename(
                                authorization,
                                invocation,
                                &target,
                                &backup,
                            )
                            .map_err(|error| {
                                format!(
                                    "source-shelf-sweep-owned-quarantine-failed {}: {error}",
                                    target.display()
                                )
                            })?;
                        }
                        crate::atoms::r#do::source_shelf::copy(
                            authorization,
                            invocation,
                            &source,
                            &target,
                            Some(request.shelf_file_mode),
                            Some(uid),
                            Some(gid),
                        )?;
                        provenance.paths.insert(target.display().to_string());
                        promoted_count += 1;
                    }
                }
                for relative in &stale {
                    let target = request.target_shelf.join(relative);
                    if !target.exists() {
                        provenance.paths.remove(&target.display().to_string());
                        continue;
                    }
                    if fs::symlink_metadata(&target)
                        .map_err(|error| error.to_string())?
                        .file_type()
                        .is_dir()
                        && fs::read_dir(&target)
                            .map_err(|error| error.to_string())?
                            .next()
                            .is_some()
                    {
                        return Err(format!(
                            "source-shelf-sweep-owned-directory-not-empty {}",
                            target.display()
                        ));
                    }
                    let backup = quarantine.join(relative);
                    if let Some(parent) = backup.parent() {
                        crate::atoms::r#do::source_shelf::mkdir_all(
                            authorization,
                            invocation,
                            parent,
                        )?;
                    }
                    crate::atoms::r#do::source_shelf::rename(
                        authorization,
                        invocation,
                        &target,
                        &backup,
                    )
                    .map_err(|error| {
                        format!(
                            "source-shelf-sweep-owned-quarantine-failed {}: {error}",
                            target.display()
                        )
                    })?;
                    provenance.paths.remove(&target.display().to_string());
                    removed_count += 1;
                }
                write_sweep_provenance(provenance_path, &provenance)
            })()
        },
    )
    .map(|_| ());
    if let Err(blocker) = movement {
        let outcome = SourceShelfSweepOutcome {
            ok: false,
            changed: promoted_count > 0 || removed_count > 0,
            current: false,
            source_inventory_count: desired.len(),
            target_inventory_count_before: 0,
            target_inventory_count_after: 0,
            promoted_count,
            removed_count,
            transaction_state: "incomplete".into(),
            rollback_state: "quarantine-preserved".into(),
            first_blocker: blocker.clone(),
            entries,
            message: blocker.clone(),
        };
        write_sweep_receipts(receipt_dir, request, &outcome, apply)?;
        return Err(blocker);
    }
    for entry in &mut entries {
        entry.readback_ok = if entry.action == "quarantined" {
            !entry.target.exists()
        } else if let Ok((digest, mode, observed_uid, observed_gid)) =
            sweep_path_state(&entry.target, entry.kind.contains("directory"))
        {
            entry.after_digest = digest;
            entry.after_mode = mode;
            entry.after_uid = observed_uid;
            entry.after_gid = observed_gid;
            mode == Some(entry.desired_mode)
                && observed_uid == Some(entry.desired_uid)
                && observed_gid == Some(entry.desired_gid)
                && (entry.source_digest.is_none() || entry.after_digest == entry.source_digest)
        } else {
            false
        };
        entry.action = if entry.action == "unchanged" {
            "unchanged".into()
        } else if entry.action == "quarantined" {
            "quarantined".into()
        } else {
            "promoted".into()
        };
    }
    let outcome = SourceShelfSweepOutcome {
        ok: true,
        changed: promoted_count > 0 || removed_count > 0,
        current: true,
        source_inventory_count: desired.len(),
        target_inventory_count_before: 0,
        target_inventory_count_after: inventory_sweep_tree_if_present(
            &request.target_shelf,
            &sweep_exclude,
        )?
        .len(),
        promoted_count,
        removed_count,
        transaction_state: "committed".into(),
        rollback_state: "quarantine-preserved".into(),
        first_blocker: "none".into(),
        entries,
        message: "owned recursive source shelf converged".into(),
    };
    write_sweep_receipts(receipt_dir, request, &outcome, apply)?;
    Ok(outcome)
}

fn source_shelf_sweep_with_fault(
    request: &SourceShelfSweepRequest,
    receipt_dir: &Path,
    apply: bool,
    fault: SourceShelfSweepFault,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<SourceShelfSweepOutcome, String> {
    validate_receipt_name(&request.receipt_name)?;
    validate_source_shelf_relative_path(&request.shelf_source)?;
    let sweep_exclude = source_shelf_sweep_exclude(&request.launcher_exclude);
    validate_launcher_pattern(&request.launcher_pattern)?;
    validate_mode("shelf-directory", request.shelf_directory_mode)?;
    validate_mode("shelf-file", request.shelf_file_mode)?;
    validate_mode("launcher", request.launcher_mode)?;
    reject_ssh_path(&request.target_shelf)?;
    reject_ssh_path(&request.launcher_target_root)?;
    if !request.target_shelf.is_absolute() || !request.launcher_target_root.is_absolute() {
        return Err("source-shelf-sweep-target-path-must-be-absolute".into());
    }
    let declared_shelf_parent = request
        .target_shelf
        .parent()
        .ok_or_else(|| "source-shelf-sweep-target-shelf-parent-missing".to_string())?;
    if !declared_shelf_parent.is_dir() {
        return Err(format!(
            "source-shelf-sweep-target-shelf-parent-missing {}",
            declared_shelf_parent.display()
        ));
    }
    if !request.launcher_target_root.is_dir() {
        return Err(format!(
            "source-shelf-sweep-launcher-target-root-missing {}",
            request.launcher_target_root.display()
        ));
    }
    reject_symlink_components(declared_shelf_parent)?;
    reject_symlink_components(&request.launcher_target_root)?;
    let source_root = request.source_root.canonicalize().map_err(|error| {
        format!(
            "source-shelf-sweep-source-root-invalid {}: {error}",
            request.source_root.display()
        )
    })?;
    if !source_root.is_dir() {
        return Err(format!(
            "source-shelf-sweep-source-root-not-directory {}",
            source_root.display()
        ));
    }
    let shelf_source = source_root
        .join(&request.shelf_source)
        .canonicalize()
        .map_err(|error| {
            format!(
                "source-shelf-sweep-shelf-source-invalid {}: {error}",
                request.shelf_source.display()
            )
        })?;
    shelf_source.strip_prefix(&source_root).map_err(|_| {
        format!(
            "source-shelf-sweep-shelf-source-outside-root {}",
            shelf_source.display()
        )
    })?;
    let launcher_source_root = request
        .launcher_source_root
        .canonicalize()
        .map_err(|error| {
            format!(
                "source-shelf-sweep-launcher-source-root-invalid {}: {error}",
                request.launcher_source_root.display()
            )
        })?;
    launcher_source_root
        .strip_prefix(&source_root)
        .map_err(|_| {
            format!(
                "source-shelf-sweep-launcher-source-root-outside-root {}",
                launcher_source_root.display()
            )
        })?;
    let uid = resolve_uid(&request.shelf_owner)
        .map_err(|error| format!("source-shelf-sweep-owner-resolution-failed: {error}"))?;
    let gid = resolve_gid(&request.shelf_group)
        .map_err(|error| format!("source-shelf-sweep-group-resolution-failed: {error}"))?;
    let launcher_only = request.provenance_state.is_some()
        && request.shelf_source == Path::new(".")
        && request.target_shelf == request.launcher_target_root;
    let source_entries = if launcher_only {
        Vec::new()
    } else {
        inventory_sweep_tree(&shelf_source, &sweep_exclude)?
    };
    let target_before = inventory_sweep_tree_if_present(&request.target_shelf, &sweep_exclude)?;
    let launchers = source_launchers(
        &launcher_source_root,
        &request.launcher_pattern,
        &sweep_exclude,
    )?;
    let target_launchers = target_pattern_files(
        &request.launcher_target_root,
        &request.launcher_pattern,
        &sweep_exclude,
    )?;
    let stale: BTreeSet<_> = target_launchers
        .difference(&launchers.keys().cloned().collect())
        .cloned()
        .collect();
    let shelf_current = launcher_only
        || shelf_is_current(
            &shelf_source,
            &request.target_shelf,
            &source_entries,
            request.shelf_directory_mode,
            request.shelf_file_mode,
            uid,
            gid,
            &sweep_exclude,
        )?;
    let mut launcher_drift = BTreeSet::new();
    for (name, source) in &launchers {
        if !launcher_is_current(
            source,
            &request.launcher_target_root.join(name),
            request.launcher_mode,
            uid,
            gid,
        )? {
            launcher_drift.insert(name.clone());
        }
    }
    let mut provenance = request
        .provenance_state
        .as_ref()
        .map(|path| load_sweep_provenance(path))
        .transpose()?
        .unwrap_or_default();
    let drift =
        !shelf_current || !launcher_drift.is_empty() || (request.prune && !stale.is_empty());
    let planned_entries = build_sweep_entries(
        request,
        &shelf_source,
        &source_entries,
        &launchers,
        &stale,
        uid,
        gid,
        false,
    )?;
    if !apply {
        let outcome = SourceShelfSweepOutcome {
            ok: !drift,
            changed: false,
            current: !drift,
            source_inventory_count: source_entries.len() + launchers.len(),
            target_inventory_count_before: target_before.len() + target_launchers.len(),
            target_inventory_count_after: target_before.len() + target_launchers.len(),
            promoted_count: 0,
            removed_count: 0,
            transaction_state: if drift { "planned" } else { "unchanged" }.into(),
            rollback_state: "not-needed".into(),
            first_blocker: if drift {
                "source-shelf-sweep-not-converged".into()
            } else {
                "none".into()
            },
            entries: planned_entries,
            message: if drift {
                "source-shelf-sweep-not-converged".into()
            } else {
                "source shelf and launchers current".into()
            },
        };
        write_sweep_receipts(receipt_dir, request, &outcome, apply)?;
        return Ok(outcome);
    }

    let run = crate::atoms::comparison::execute(
        "files",
        || {
            let shelf_current_now = launcher_only
                || shelf_is_current(
                    &shelf_source,
                    &request.target_shelf,
                    &source_entries,
                    request.shelf_directory_mode,
                    request.shelf_file_mode,
                    uid,
                    gid,
                    &sweep_exclude,
                )?;
            let target_launchers_now = target_pattern_files(
                &request.launcher_target_root,
                &request.launcher_pattern,
                &sweep_exclude,
            )?;
            let mut launcher_drift_now = false;
            for name in launchers.keys() {
                if !launcher_is_current(
                    launchers
                        .get(name)
                        .expect("launcher name comes from inventory"),
                    &request.launcher_target_root.join(name),
                    request.launcher_mode,
                    uid,
                    gid,
                )? {
                    launcher_drift_now = true;
                    break;
                }
            }
            let stale_now = target_launchers_now
                .difference(&launchers.keys().cloned().collect())
                .next()
                .is_some();
            Ok::<_, String>(
                (!launcher_only && !shelf_current_now)
                    || launcher_drift_now
                    || (request.prune && stale_now),
            )
        },
        |different| {
            if *different {
                crate::atoms::comparison::DiffDecision::Different
            } else {
                crate::atoms::comparison::DiffDecision::Empty
            }
        },
        |authorization, _| {
            let invocation = invocation.ok_or("source-shelf-sweep-invocation-key-missing")?;
            let shelf_parent = request.target_shelf.parent().ok_or_else(|| {
                format!(
                    "source-shelf-sweep-target-shelf-parent-missing {}",
                    request.target_shelf.display()
                )
            })?;
            let nonce = sweep_nonce();
            let shelf_name = request
                .target_shelf
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| "source-shelf-sweep-target-shelf-name-invalid".to_string())?;
            let stage = shelf_parent.join(format!(".{shelf_name}.harmonia-stage-{nonce}"));
            let shelf_backup = shelf_parent.join(format!(".{shelf_name}.harmonia-prior-{nonce}"));
            let quarantine = request
                .launcher_target_root
                .join(format!(".harmonia-source-shelf-sweep-{nonce}"));
            let stage_existed_before = stage.exists();
            let quarantine_existed_before = quarantine.exists();
            let setup = (|| -> Result<(), String> {
                stage_sweep_tree(
                    authorization,
                    invocation,
                    &shelf_source,
                    &stage,
                    &source_entries,
                    request.shelf_directory_mode,
                    request.shelf_file_mode,
                    uid,
                    gid,
                )?;
                if fault.fail_setup_after_stage {
                    return Err("source-shelf-sweep-injected-setup-failure".into());
                }
                crate::atoms::r#do::source_shelf::mkdir_all(authorization, invocation, &quarantine)
                    .map_err(|error| {
                        format!(
                            "source-shelf-sweep-quarantine-create-failed {}: {error}",
                            quarantine.display()
                        )
                    })?;
                sync_sweep_directory(&request.launcher_target_root)?;
                Ok(())
            })();
            if let Err(blocker) = setup {
                let mut cleanup_errors = Vec::new();
                for (path, existed_before) in [
                    (&stage, stage_existed_before),
                    (&quarantine, quarantine_existed_before),
                ] {
                    if existed_before {
                        continue;
                    }
                    if let Err(error) = crate::atoms::r#do::source_shelf::remove_tree(
                        authorization,
                        invocation,
                        path,
                    ) {
                        if !error.contains("No such file") {
                            cleanup_errors
                                .push(format!("remove setup path {}: {error}", path.display()));
                        }
                    }
                }
                for parent in [shelf_parent, request.launcher_target_root.as_path()] {
                    if let Err(error) = crate::atoms::r#do::symlink_converge::sync_parent(
                        authorization,
                        invocation,
                        parent,
                    ) {
                        cleanup_errors.push(error);
                    }
                }
                let cleanup_complete = cleanup_errors.is_empty();
                let outcome = SourceShelfSweepOutcome {
                    ok: false,
                    changed: !cleanup_complete,
                    current: false,
                    source_inventory_count: source_entries.len() + launchers.len(),
                    target_inventory_count_before: target_before.len() + target_launchers.len(),
                    target_inventory_count_after: target_before.len() + target_launchers.len(),
                    promoted_count: 0,
                    removed_count: 0,
                    transaction_state: if cleanup_complete {
                        "setup-failed-cleaned"
                    } else {
                        "setup-cleanup-incomplete"
                    }
                    .into(),
                    rollback_state: if cleanup_complete {
                        "restored"
                    } else {
                        "incomplete"
                    }
                    .into(),
                    first_blocker: blocker.clone(),
                    entries: planned_entries.clone(),
                    message: if cleanup_complete {
                        format!("{blocker}; staging and quarantine setup residue removed")
                    } else {
                        format!(
                            "{blocker}; setup cleanup errors: {}",
                            cleanup_errors.join("; ")
                        )
                    },
                };
                write_sweep_receipts(receipt_dir, request, &outcome, apply)?;
                return Err(outcome.message);
            }

            let shelf_had_prior = request.target_shelf.exists();
            let mut shelf_promoted = false;
            let mut carried_excluded: Vec<(PathBuf, PathBuf)> = Vec::new();
            let mut launcher_backups: Vec<(PathBuf, PathBuf)> = Vec::new();
            let mut new_launchers: Vec<PathBuf> = Vec::new();
            let mut newly_created_launcher_dirs: Vec<PathBuf> = Vec::new();
            let mut promoted_count = 0usize;
            let mut removed_count = 0usize;
            let transaction = (|| -> Result<(), String> {
                if !shelf_current {
                    if shelf_had_prior {
                        crate::atoms::r#do::source_shelf::rename(
                            authorization,
                            invocation,
                            &request.target_shelf,
                            &shelf_backup,
                        )
                        .map_err(|error| {
                            format!("source-shelf-sweep-shelf-quarantine-failed: {error}")
                        })?;
                    }
                    crate::atoms::r#do::source_shelf::rename(
                        authorization,
                        invocation,
                        &stage,
                        &request.target_shelf,
                    )
                    .map_err(|error| format!("source-shelf-sweep-shelf-promote-failed: {error}"))?;
                    if shelf_had_prior {
                        carried_excluded = carry_excluded_shelf_entries(
                            authorization,
                            invocation,
                            &shelf_backup,
                            &request.target_shelf,
                            &sweep_exclude,
                        )?;
                    }
                    sync_sweep_directory(shelf_parent)?;
                    shelf_promoted = true;
                    promoted_count += 1;
                    if fault
                        .fail_after_promotions
                        .is_some_and(|limit| promoted_count >= limit)
                    {
                        return Err("source-shelf-sweep-injected-promotion-failure".into());
                    }
                }
                for name in &launcher_drift {
                    let source = launchers
                        .get(name)
                        .expect("launcher drift names come from inventory");
                    let target = request.launcher_target_root.join(name);
                    sync_authorized_parent(
                        authorization,
                        invocation,
                        &request.launcher_target_root,
                        &target,
                        &mut newly_created_launcher_dirs,
                    )?;
                    if target.exists() {
                        let backup = receipt_dir.join("backups").join(name);
                        if let Some(parent) = backup.parent() {
                            crate::atoms::r#do::source_shelf::mkdir_all(
                                authorization,
                                invocation,
                                parent,
                            )
                            .map_err(|error| {
                                format!(
                                    "source-shelf-sweep-launcher-backup-parent-failed {}: {error}",
                                    parent.display()
                                )
                            })?;
                        }
                        crate::atoms::r#do::source_shelf::copy_raw(
                            authorization,
                            invocation,
                            &target,
                            &backup,
                            None,
                            None,
                            None,
                        )
                        .map_err(|error| {
                            format!(
                                "source-shelf-sweep-launcher-backup-failed {} -> {}: {error}",
                                target.display(),
                                backup.display()
                            )
                        })?;
                        sync_sweep_directory(backup.parent().expect("launcher backup has parent"))?;
                        crate::atoms::r#do::source_shelf::mkdir_all(
                            authorization,
                            invocation,
                            &quarantine,
                        )
                        .map_err(|error| {
                            format!(
                                "source-shelf-sweep-quarantine-create-failed {}: {error}",
                                quarantine.display()
                            )
                        })?;
                        let backup = quarantine.join(name);
                        sync_authorized_parent(
                            authorization,
                            invocation,
                            &request.launcher_target_root,
                            &backup,
                            &mut newly_created_launcher_dirs,
                        )?;
                        crate::atoms::r#do::source_shelf::rename(
                            authorization,
                            invocation,
                            &target,
                            &backup,
                        )
                        .map_err(|error| {
                            format!(
                                "source-shelf-sweep-launcher-quarantine-failed {}: {error}",
                                target.display()
                            )
                        })?;
                        sync_sweep_directory(target.parent().expect("launcher target has parent"))?;
                        sync_sweep_directory(backup.parent().expect("launcher backup has parent"))?;
                        launcher_backups.push((target.clone(), backup));
                    } else {
                        new_launchers.push(target.clone());
                    }
                    crate::atoms::r#do::source_shelf::copy_raw(
                        authorization,
                        invocation,
                        source,
                        &target,
                        Some(request.launcher_mode),
                        Some(uid),
                        Some(gid),
                    )?;
                    sync_sweep_directory(target.parent().expect("launcher target has parent"))?;
                    promoted_count += 1;
                    if fault
                        .fail_after_promotions
                        .is_some_and(|limit| promoted_count >= limit)
                    {
                        return Err("source-shelf-sweep-injected-promotion-failure".into());
                    }
                }
                if request.prune {
                    for name in &stale {
                        let target = request.launcher_target_root.join(name);
                        crate::atoms::r#do::source_shelf::mkdir_all(
                            authorization,
                            invocation,
                            &quarantine,
                        )
                        .map_err(|error| {
                            format!(
                                "source-shelf-sweep-quarantine-create-failed {}: {error}",
                                quarantine.display()
                            )
                        })?;
                        let backup = quarantine.join(name);
                        sync_authorized_parent(
                            authorization,
                            invocation,
                            &request.launcher_target_root,
                            &backup,
                            &mut newly_created_launcher_dirs,
                        )?;
                        crate::atoms::r#do::source_shelf::rename(
                            authorization,
                            invocation,
                            &target,
                            &backup,
                        )
                        .map_err(|error| {
                            format!(
                                "source-shelf-sweep-stale-launcher-quarantine-failed {}: {error}",
                                target.display()
                            )
                        })?;
                        sync_sweep_directory(
                            target.parent().expect("stale launcher target has parent"),
                        )?;
                        sync_sweep_directory(
                            backup.parent().expect("stale launcher backup has parent"),
                        )?;
                        launcher_backups.push((target, backup));
                        removed_count += 1;
                    }
                    sync_sweep_directory(&request.launcher_target_root)?;
                }
                let mut readback_exclude = sweep_exclude.clone();
                if let Ok(relative) = quarantine.strip_prefix(&request.target_shelf) {
                    readback_exclude.push(relative.to_string_lossy().into_owned());
                }
                if !launcher_only
                    && !shelf_is_current(
                        &shelf_source,
                        &request.target_shelf,
                        &source_entries,
                        request.shelf_directory_mode,
                        request.shelf_file_mode,
                        uid,
                        gid,
                        &readback_exclude,
                    )?
                {
                    return Err("source-shelf-sweep-shelf-readback-failed".into());
                }
                for (name, source) in &launchers {
                    if !launcher_is_current(
                        source,
                        &request.launcher_target_root.join(name),
                        request.launcher_mode,
                        uid,
                        gid,
                    )? {
                        return Err(format!(
                            "source-shelf-sweep-launcher-readback-failed {name}"
                        ));
                    }
                }
                if request.prune {
                    for name in &stale {
                        if request.launcher_target_root.join(name).exists() {
                            return Err(format!(
                                "source-shelf-sweep-stale-launcher-readback-failed {name}"
                            ));
                        }
                    }
                }
                Ok(())
            })();

            let mut committed_outcome = None;
            let transaction = transaction.and_then(|_| {
                let target_after =
                    inventory_sweep_tree_if_present(&request.target_shelf, &sweep_exclude)?;
                let target_launchers_after = target_pattern_files(
                    &request.launcher_target_root,
                    &request.launcher_pattern,
                    &sweep_exclude,
                )?;
                let entries = readback_sweep_entries(planned_entries.clone())?;
                if entries.iter().any(|entry| !entry.readback_ok) {
                    return Err("source-shelf-sweep-entry-readback-failed".into());
                }
                let outcome = SourceShelfSweepOutcome {
                    ok: true,
                    changed: true,
                    current: true,
                    source_inventory_count: source_entries.len() + launchers.len(),
                    target_inventory_count_before: target_before.len() + target_launchers.len(),
                    target_inventory_count_after: target_after.len() + target_launchers_after.len(),
                    promoted_count,
                    removed_count,
                    transaction_state: "committed".into(),
                    rollback_state: "not-needed".into(),
                    first_blocker: "none".into(),
                    entries,
                    message: "source shelf and launchers converged".into(),
                };
                committed_outcome = Some(outcome);
                Ok(())
            });

            if let Err(blocker) = transaction {
                let mut rollback_errors = Vec::new();
                for target in new_launchers.iter().rev() {
                    if let Err(error) = crate::atoms::r#do::source_shelf::remove_file(
                        authorization,
                        invocation,
                        target,
                    ) {
                        if !error.contains("No such file") {
                            rollback_errors.push(format!("remove {}: {error}", target.display()));
                        }
                    }
                    if let Some(parent) = target.parent() {
                        if let Err(error) = sync_sweep_directory(parent) {
                            rollback_errors.push(format!(
                                "sync removed launcher parent {}: {error}",
                                parent.display()
                            ));
                        }
                    }
                }
                for (target, backup) in launcher_backups.iter().rev() {
                    let _ = crate::atoms::r#do::source_shelf::remove_file(
                        authorization,
                        invocation,
                        target,
                    );
                    if let Some(parent) = target.parent() {
                        if let Err(error) = sync_sweep_directory(parent) {
                            rollback_errors.push(format!(
                                "sync replaced launcher parent {}: {error}",
                                parent.display()
                            ));
                        }
                    }
                    if let Err(error) = crate::atoms::r#do::source_shelf::rename(
                        authorization,
                        invocation,
                        backup,
                        target,
                    ) {
                        rollback_errors.push(format!(
                            "restore {} -> {}: {error}",
                            backup.display(),
                            target.display()
                        ));
                    } else {
                        if let Some(parent) = target.parent() {
                            if let Err(error) = sync_sweep_directory(parent) {
                                rollback_errors.push(format!(
                                    "sync restored launcher parent {}: {error}",
                                    parent.display()
                                ));
                            }
                        }
                        if let Some(parent) = backup.parent() {
                            if let Err(error) = sync_sweep_directory(parent) {
                                rollback_errors.push(format!(
                                    "sync launcher backup parent {}: {error}",
                                    parent.display()
                                ));
                            }
                        }
                    }
                }
                if shelf_promoted {
                    for (backup, promoted) in carried_excluded.iter().rev() {
                        if let Err(error) = crate::atoms::r#do::source_shelf::rename(
                            authorization,
                            invocation,
                            promoted,
                            backup,
                        ) {
                            rollback_errors.push(format!(
                                "restore excluded {} -> {}: {error}",
                                promoted.display(),
                                backup.display()
                            ));
                        }
                    }
                    if let Err(error) = crate::atoms::r#do::source_shelf::remove_tree(
                        authorization,
                        invocation,
                        &request.target_shelf,
                    ) {
                        rollback_errors.push(format!(
                            "remove promoted shelf {}: {error}",
                            request.target_shelf.display()
                        ));
                    }
                    if shelf_had_prior {
                        if let Err(error) = crate::atoms::r#do::source_shelf::rename(
                            authorization,
                            invocation,
                            &shelf_backup,
                            &request.target_shelf,
                        ) {
                            rollback_errors.push(format!(
                                "restore shelf {} -> {}: {error}",
                                shelf_backup.display(),
                                request.target_shelf.display()
                            ));
                        }
                    }
                }
                let _ = crate::atoms::r#do::source_shelf::remove_tree(
                    authorization,
                    invocation,
                    &stage,
                );
                let _ = crate::atoms::r#do::source_shelf::remove_tree(
                    authorization,
                    invocation,
                    &quarantine,
                );
                if let Err(error) = sync_sweep_directory(&request.launcher_target_root) {
                    rollback_errors
                        .push(format!("sync launcher quarantine rollback parent: {error}"));
                }
                if let Err(error) = remove_new_launcher_dirs(
                    authorization,
                    invocation,
                    &request.launcher_target_root,
                    &mut newly_created_launcher_dirs,
                ) {
                    rollback_errors.push(error);
                }
                let rollback_entries = match readback_rollback_entries(planned_entries.clone()) {
                    Ok(entries) => {
                        if entries
                            .iter()
                            .any(|entry| entry.rollback_readback_ok != Some(true))
                        {
                            rollback_errors.push("rollback-readback-mismatch".into());
                        }
                        entries
                    }
                    Err(error) => {
                        rollback_errors.push(format!("rollback-readback-failed: {error}"));
                        Vec::new()
                    }
                };
                let rollback_state = if rollback_errors.is_empty() {
                    "restored"
                } else {
                    "incomplete"
                };
                let outcome = SourceShelfSweepOutcome {
                    ok: false,
                    changed: !rollback_errors.is_empty(),
                    current: false,
                    source_inventory_count: source_entries.len() + launchers.len(),
                    target_inventory_count_before: target_before.len() + target_launchers.len(),
                    target_inventory_count_after: inventory_sweep_tree_if_present(
                        &request.target_shelf,
                        &sweep_exclude,
                    )
                    .map(|entries| entries.len())
                    .unwrap_or_default()
                        + target_pattern_files(
                            &request.launcher_target_root,
                            &request.launcher_pattern,
                            &sweep_exclude,
                        )
                        .map(|entries| entries.len())
                        .unwrap_or_default(),
                    promoted_count,
                    removed_count,
                    transaction_state: if rollback_errors.is_empty() {
                        "rolled-back"
                    } else {
                        "rollback-incomplete"
                    }
                    .into(),
                    rollback_state: rollback_state.into(),
                    first_blocker: blocker.clone(),
                    entries: rollback_entries,
                    message: if rollback_errors.is_empty() {
                        format!("{blocker}; prior state restored")
                    } else {
                        format!("{blocker}; rollback errors: {}", rollback_errors.join("; "))
                    },
                };
                write_sweep_receipts(receipt_dir, request, &outcome, apply)?;
                return Err(outcome.message);
            }

            let mut outcome = committed_outcome
                .ok_or_else(|| "source-shelf-sweep-committed-outcome-missing".to_string())?;
            let cleanup = (|| -> Result<(), String> {
                if fault.fail_cleanup {
                    return Err("source-shelf-sweep-injected-cleanup-failure".into());
                }
                let remove_dir_all_if_present = |path: &Path, label: &str| -> Result<(), String> {
                    if let Err(error) = crate::atoms::r#do::source_shelf::remove_tree(
                        authorization,
                        invocation,
                        path,
                    ) {
                        if !error.contains("No such file") {
                            return Err(format!("{label} {}: {error}", path.display()));
                        }
                    }
                    Ok(())
                };
                remove_dir_all_if_present(
                    &quarantine,
                    "source-shelf-sweep-quarantine-remove-failed",
                )?;
                if shelf_had_prior && shelf_promoted {
                    if let Ok(relative) = quarantine.strip_prefix(&request.target_shelf) {
                        remove_dir_all_if_present(
                            &shelf_backup.join(relative),
                            "source-shelf-sweep-quarantine-backup-remove-failed",
                        )?;
                    }
                    remove_dir_all_if_present(
                        &shelf_backup,
                        "source-shelf-sweep-prior-shelf-remove-failed",
                    )?;
                }
                let _ = crate::atoms::r#do::source_shelf::remove_tree(
                    authorization,
                    invocation,
                    &stage,
                );
                sync_sweep_directory(shelf_parent)?;
                sync_sweep_directory(&request.launcher_target_root)?;
                Ok(())
            })();
            if let Err(blocker) = cleanup {
                outcome.ok = false;
                outcome.transaction_state = "committed-cleanup-debt".into();
                outcome.first_blocker = blocker.clone();
                outcome.message =
                    format!("source shelf and launchers converged; cleanup debt: {blocker}");
                write_sweep_receipts(receipt_dir, request, &outcome, apply).map_err(
                    |receipt_error| {
                        format!("{}; receipt-write-failed: {receipt_error}", outcome.message)
                    },
                )?;
                return Err(outcome.message);
            }
            if let Some(path) = request.provenance_state.as_ref() {
                for name in launchers.keys() {
                    provenance.paths.insert(
                        request
                            .launcher_target_root
                            .join(name)
                            .display()
                            .to_string(),
                    );
                }
                for name in &stale {
                    provenance.paths.remove(
                        &request
                            .launcher_target_root
                            .join(name)
                            .display()
                            .to_string(),
                    );
                }
                write_sweep_provenance(path, &provenance)?;
            }
            write_sweep_receipts(receipt_dir, request, &outcome, apply)?;
            Ok(outcome)
        },
    )?;
    match run {
        crate::atoms::comparison::ComparisonRun::Moved { movement, .. } => Ok(movement),
        crate::atoms::comparison::ComparisonRun::Current { .. } => {
            let outcome = SourceShelfSweepOutcome {
                ok: true,
                changed: false,
                current: true,
                source_inventory_count: source_entries.len() + launchers.len(),
                target_inventory_count_before: target_before.len() + target_launchers.len(),
                target_inventory_count_after: target_before.len() + target_launchers.len(),
                promoted_count: 0,
                removed_count: 0,
                transaction_state: "unchanged".into(),
                rollback_state: "not-needed".into(),
                first_blocker: "none".into(),
                entries: planned_entries,
                message: "source shelf and launchers current".into(),
            };
            write_sweep_receipts(receipt_dir, request, &outcome, apply)?;
            Ok(outcome)
        }
    }
}
