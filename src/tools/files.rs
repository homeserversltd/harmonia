use super::{ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};

pub const NAME: &str = "files";
pub const DESCRIPTION: &str =
    "Staged file/template/directory/symlink primitive with atomic promotion.";
pub const PERMUTATIONS: &[ToolPermutation] = &[
    ToolPermutation::new(
        "managed-files",
        "converge managed file declarations from typed JSON",
        &[
            ToolArg::optional("files", ToolArgKind::Json),
            ToolArg::optional("owner", ToolArgKind::String),
            ToolArg::optional("group", ToolArgKind::String),
        ],
    ),
    ToolPermutation::new(
        "managed-directories",
        "converge managed directory declarations with mode and ownership readback",
        &[ToolArg::required("directories", ToolArgKind::Json)],
    ),
    ToolPermutation::new(
        "converge",
        "converge a source file tree into a target root",
        &[
            ToolArg::required("source_root", ToolArgKind::String),
            ToolArg::required("target_root", ToolArgKind::String),
            ToolArg::required("files", ToolArgKind::StringArray),
            ToolArg::optional("backup_existing", ToolArgKind::Bool),
            ToolArg::optional("receipt_name", ToolArgKind::String),
            ToolArg::optional("summary_receipt", ToolArgKind::Json),
            ToolArg::optional("owner", ToolArgKind::String),
            ToolArg::optional("group", ToolArgKind::String),
        ],
    ),
    ToolPermutation::new(
        "remove",
        "remove only declared regular files beneath a target root and receipt their prior and final state",
        &[
            ToolArg::required("target_root", ToolArgKind::String),
            ToolArg::required("paths", ToolArgKind::StringArray),
        ],
    ),
    ToolPermutation::new(
        "directory-sync",
        "verify or copy a source directory tree into a target directory",
        &[
            ToolArg::required("source_root", ToolArgKind::String),
            ToolArg::required("target_root", ToolArgKind::String),
            ToolArg::optional("files", ToolArgKind::StringArray),
            ToolArg::optional("backup_existing", ToolArgKind::Bool),
            ToolArg::optional("receipt_name", ToolArgKind::String),
            ToolArg::optional("allow_same_root", ToolArgKind::Bool),
            ToolArg::optional("owner", ToolArgKind::String),
            ToolArg::optional("group", ToolArgKind::String),
        ],
    ),
    ToolPermutation::new(
        "source-shelf-sweep",
        "converge one source shelf plus pattern-selected flat launchers with per-path atomic, all-or-restored semantics",
        &[
            ToolArg::required("source_root", ToolArgKind::String),
            ToolArg::required("shelf_source", ToolArgKind::String),
            ToolArg::required("target_shelf", ToolArgKind::String),
            ToolArg::required("launcher_source_root", ToolArgKind::String),
            ToolArg::required("launcher_target_root", ToolArgKind::String),
            ToolArg::required("launcher_pattern", ToolArgKind::String),
            ToolArg::required("shelf_owner", ToolArgKind::String),
            ToolArg::required("shelf_group", ToolArgKind::String),
            ToolArg::required("shelf_directory_mode", ToolArgKind::Integer),
            ToolArg::required("shelf_file_mode", ToolArgKind::Integer),
            ToolArg::required("launcher_mode", ToolArgKind::Integer),
            ToolArg::required("prune", ToolArgKind::Bool),
        ],
    ),
    ToolPermutation::new(
        "validated-symlink",
        "validate a candidate symlink before atomically promoting declared link ownership",
        &[
            ToolArg::required("source", ToolArgKind::String),
            ToolArg::required("target", ToolArgKind::String),
            ToolArg::required("validator_program", ToolArgKind::String),
            ToolArg::optional("validator_args", ToolArgKind::StringArray),
            ToolArg::optional("reload_program", ToolArgKind::String),
            ToolArg::optional("reload_args", ToolArgKind::StringArray),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ),
    ToolPermutation::new(
        "validated-file-symlink",
        "validate staged file and include-visible link candidates before reversible promotion",
        &[
            ToolArg::required("desired_source", ToolArgKind::String),
            ToolArg::required("source", ToolArgKind::String),
            ToolArg::required("target", ToolArgKind::String),
            ToolArg::required("validator_program", ToolArgKind::String),
            ToolArg::optional("validator_args", ToolArgKind::StringArray),
            ToolArg::optional("reload_program", ToolArgKind::String),
            ToolArg::optional("reload_args", ToolArgKind::StringArray),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ),
];
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION, PERMUTATIONS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub action: String,
    pub target: String,
    pub args: Vec<String>,
}

impl Request {
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            target: NAME.to_string(),
            args: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub ok: bool,
    pub changed: bool,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSpec {
    pub relative_path: PathBuf,
    pub mode: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileConvergenceRequest {
    pub source_root: PathBuf,
    pub target_root: PathBuf,
    pub files: Vec<FileSpec>,
    pub backup_existing: bool,
    pub receipt_name: String,
    pub owner: Option<String>,
    pub group: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileConvergenceEntry {
    pub relative_path: String,
    pub source: PathBuf,
    pub target: PathBuf,
    pub source_exists: bool,
    pub target_exists_before: bool,
    pub content_equal_before: bool,
    pub mode_equal_before: bool,
    pub target_exists_after: bool,
    pub content_equal_after: bool,
    pub mode_equal_after: bool,
    pub changed: bool,
    pub backed_up_to: Option<PathBuf>,
    pub final_mode: Option<u32>,
    pub ownership_source: String,
    pub observed_uid_before: Option<u32>,
    pub observed_gid_before: Option<u32>,
    pub observed_uid_after: Option<u32>,
    pub observed_gid_after: Option<u32>,
    pub ownership_changed: bool,
    pub observed_uid: Option<u32>,
    pub observed_gid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileConvergenceOutcome {
    pub ok: bool,
    pub changed: bool,
    pub ownership_changed: bool,
    pub checked: usize,
    pub written: usize,
    pub backed_up: usize,
    pub missing: Vec<String>,
    pub entries: Vec<FileConvergenceEntry>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileRemovalEntry {
    pub relative_path: String,
    pub target: PathBuf,
    pub found_before: String,
    pub exists_after: bool,
    pub result: String,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileRemovalOutcome {
    pub ok: bool,
    pub changed: bool,
    pub checked: usize,
    pub removed: usize,
    pub entries: Vec<FileRemovalEntry>,
    pub message: String,
}

pub fn files_request(action: impl Into<String>) -> Request {
    Request::new(action)
}

pub fn atomic_promote(target: impl Into<String>) -> Request {
    Request {
        action: "atomic-promote".to_string(),
        target: target.into(),
        args: Vec::new(),
    }
}

pub fn plan(request: &Request) -> Outcome {
    Outcome {
        ok: true,
        changed: false,
        message: format!("{} {} planned for {}", NAME, request.action, request.target),
    }
}

pub(crate) struct ManagedFilesRequest<'a> {
    pub module_id: &'a str,
    pub files: &'a [crate::ManagedFileManifest],
    pub owner: Option<&'a str>,
    pub group: Option<&'a str>,
    pub receipt_name: &'a str,
    pub schema: &'a str,
    pub first_missing_signal: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedDirectorySpec {
    pub path: String,
    pub mode: u32,
    pub owner: String,
    pub group: String,
}

pub(crate) fn converge_managed_directories(
    directories: &[ManagedDirectorySpec],
    receipt_dir: &Path,
    receipt_name: &str,
    apply: bool,
) -> Result<crate::OperationOutcome, String> {
    validate_receipt_name(receipt_name)?;
    if directories.is_empty() {
        return Err("managed-directories-empty-request".to_string());
    }
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let mut changed = false;
    let mut entries = Vec::new();
    for directory in directories {
        let path = PathBuf::from(&directory.path);
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir))
            || directory.mode > 0o777
        {
            return Err(format!(
                "managed-directory-declaration-invalid {}",
                directory.path
            ));
        }
        reject_ssh_path(&path)?;
        let desired_uid = resolve_uid(&directory.owner)?;
        let desired_gid = resolve_gid(&directory.group)?;
        let metadata = fs::symlink_metadata(&path).ok();
        if metadata
            .as_ref()
            .is_some_and(|value| !value.file_type().is_dir())
        {
            return Err(format!(
                "managed-directory-not-directory {}",
                path.display()
            ));
        }
        let existed_before = metadata.is_some();
        let mode_equal_before = existed_before && target_mode(&path)? == Some(directory.mode);
        let (owner_equal_before, group_equal_before) =
            ownership_equal(&path, Some(desired_uid), Some(desired_gid))?;
        let entry_changed =
            !existed_before || !mode_equal_before || !owner_equal_before || !group_equal_before;
        if apply && entry_changed {
            fs::create_dir_all(&path)
                .map_err(|e| format!("managed-directory-create-failed {}: {e}", path.display()))?;
            fs::set_permissions(&path, fs::Permissions::from_mode(directory.mode)).map_err(
                |e| format!("managed-directory-mode-set-failed {}: {e}", path.display()),
            )?;
            set_ownership(&path, Some(desired_uid), Some(desired_gid))?;
            if target_mode(&path)? != Some(directory.mode) {
                return Err(format!(
                    "managed-directory-mode-readback-failed {}",
                    path.display()
                ));
            }
            let (owner_equal_after, group_equal_after) =
                ownership_equal(&path, Some(desired_uid), Some(desired_gid))?;
            if !owner_equal_after || !group_equal_after {
                return Err(format!(
                    "managed-directory-owner-readback-failed {}",
                    path.display()
                ));
            }
            changed = true;
        }
        entries.push(json!({
            "path": directory.path,
            "mode": directory.mode,
            "owner": directory.owner,
            "group": directory.group,
            "existed_before": existed_before,
            "mode_equal_before": mode_equal_before,
            "owner_equal_before": owner_equal_before,
            "group_equal_before": group_equal_before,
            "changed": entry_changed,
            "applied": apply && entry_changed,
        }));
    }
    crate::write_json(
        &receipt_dir.join(format!("{receipt_name}.json")),
        &json!({
            "schema": "harmonia.files.managed_directories.v1",
            "ok": true,
            "apply": apply,
            "changed": changed,
            "entries": entries,
            "first_missing_signal": "none",
        }),
    )?;
    Ok(crate::OperationOutcome {
        ok: true,
        changed,
        skipped: !apply,
        message: format!("{} managed directories checked", directories.len()),
        command: None,
    })
}

pub(crate) fn converge_managed_files(
    request: &ManagedFilesRequest<'_>,
    receipt_dir: &Path,
    apply: bool,
) -> Result<crate::OperationOutcome, String> {
    validate_receipt_name(request.receipt_name)?;
    for file in request.files {
        reject_ssh_path(Path::new(&file.path))?;
    }
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let mut missing = Vec::new();
    let mut written = Vec::new();
    let mut changed = false;
    let mut entries = Vec::new();
    let desired_uid = request.owner.map(resolve_uid).transpose()?;
    let desired_gid = request.group.map(resolve_gid).transpose()?;
    for file in request.files {
        let path = PathBuf::from(&file.path);
        let target_regular = fs::symlink_metadata(&path)
            .map(|metadata| metadata.file_type().is_file())
            .unwrap_or(false);
        let existing = fs::read(&path).ok();
        let desired = file.content.as_bytes();
        let content_equal = target_regular && existing.as_deref() == Some(desired);
        let mode = file.mode.unwrap_or(0o644);
        let mode_equal = target_regular && target_mode(&path)? == Some(mode);
        let (owner_equal, group_equal) = ownership_equal(&path, desired_uid, desired_gid)?;
        let ownership_matches = owner_equal && group_equal;
        let file_changed = !content_equal || !mode_equal || !ownership_matches;
        if file_changed {
            if apply {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(|e| {
                        format!("managed-file-parent-failed {}: {e}", parent.display())
                    })?;
                }
                if !content_equal || !mode_equal {
                    atomic_write_bytes(&path, desired, Some(mode))?;
                }
                set_ownership(&path, desired_uid, desired_gid)?;
                let (owner_equal_after, group_equal_after) =
                    ownership_equal(&path, desired_uid, desired_gid)?;
                if !owner_equal_after || !group_equal_after {
                    return Err(format!(
                        "managed-file-owner-readback-failed {}",
                        path.display()
                    ));
                }
                written.push(file.path.clone());
                changed = true;
            } else {
                missing.push(file.path.clone());
            }
        }
        entries.push(json!({
            "path": file.path,
            "mode": mode,
            "content_equal_before": content_equal,
            "mode_equal_before": mode_equal,
            "owner": request.owner,
            "group": request.group,
            "owner_equal_before": owner_equal,
            "group_equal_before": group_equal,
            "changed": file_changed,
            "written": apply && file_changed,
        }));
        let safe_name = file
            .path
            .replace('/', "_")
            .trim_start_matches('_')
            .to_string();
        let per_file = receipt_dir.join(format!(
            "{}-{}.json",
            request.receipt_name.trim_end_matches(".json"),
            safe_name
        ));
        crate::write_json(
            &per_file,
            &json!({
                "schema": "harmonia.files.managed_file.v1",
                "ok": !file_changed || apply,
                "module": request.module_id,
                "path": file.path,
                "mode": mode,
                "owner": request.owner,
                "group": request.group,
                "owner_equal_before": owner_equal,
                "group_equal_before": group_equal,
                "apply": apply,
                "changed": file_changed,
                "written": apply && file_changed,
                "first_missing_signal": if !file_changed || apply { "none" } else { request.first_missing_signal },
            }),
        )?;
    }
    let ok = missing.is_empty() || !apply;
    let receipt = receipt_dir.join(if request.receipt_name.ends_with(".json") {
        request.receipt_name.to_string()
    } else {
        format!("{}.json", request.receipt_name)
    });
    crate::write_json(
        &receipt,
        &json!({
            "schema": request.schema,
            "ok": ok,
            "module": request.module_id,
            "missing": missing,
            "written": written,
            "owner": request.owner,
            "group": request.group,
            "apply": apply,
            "changed": changed,
            "entries": entries,
            "first_missing_signal": if ok { "none" } else { request.first_missing_signal },
        }),
    )?;
    Ok(crate::OperationOutcome {
        ok,
        changed,
        skipped: !apply && !request.files.is_empty(),
        message: format!("{} managed files checked", request.files.len()),
        command: None,
    })
}

#[cfg(unix)]
fn resolve_uid(value: &str) -> Result<u32, String> {
    if let Ok(uid) = value.parse::<u32>() {
        return Ok(uid);
    }
    let name = CString::new(value).map_err(|_| format!("managed-file-owner-invalid {value:?}"))?;
    let entry = unsafe { libc::getpwnam(name.as_ptr()) };
    if entry.is_null() {
        return Err(format!("managed-file-owner-unknown {value}"));
    }
    Ok(unsafe { (*entry).pw_uid })
}

#[cfg(not(unix))]
fn resolve_uid(value: &str) -> Result<u32, String> {
    Err(format!("managed-file-owner-unsupported {value}"))
}

#[cfg(unix)]
fn resolve_gid(value: &str) -> Result<u32, String> {
    if let Ok(gid) = value.parse::<u32>() {
        return Ok(gid);
    }
    let name = CString::new(value).map_err(|_| format!("managed-file-group-invalid {value:?}"))?;
    let entry = unsafe { libc::getgrnam(name.as_ptr()) };
    if entry.is_null() {
        return Err(format!("managed-file-group-unknown {value}"));
    }
    Ok(unsafe { (*entry).gr_gid })
}

#[cfg(not(unix))]
fn resolve_gid(value: &str) -> Result<u32, String> {
    Err(format!("managed-file-group-unsupported {value}"))
}

#[cfg(unix)]
fn ownership_equal(
    path: &Path,
    desired_uid: Option<u32>,
    desired_gid: Option<u32>,
) -> Result<(bool, bool), String> {
    if !path.exists() {
        return Ok((desired_uid.is_none(), desired_gid.is_none()));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| format!("managed-file-owner-metadata-failed {}: {e}", path.display()))?;
    Ok((
        desired_uid.map_or(true, |uid| metadata.uid() == uid),
        desired_gid.map_or(true, |gid| metadata.gid() == gid),
    ))
}

#[cfg(not(unix))]
fn ownership_equal(
    _path: &Path,
    _desired_uid: Option<u32>,
    _desired_gid: Option<u32>,
) -> Result<(bool, bool), String> {
    Ok((true, true))
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

pub fn converge_files(
    request: &FileConvergenceRequest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<FileConvergenceOutcome, String> {
    if request.files.is_empty() {
        return Err("files-converge-empty-request".to_string());
    }
    validate_receipt_name(&request.receipt_name)?;
    validate_specs(&request.files)?;
    for spec in &request.files {
        reject_ssh_path(&request.target_root.join(&spec.relative_path))?;
    }
    let desired_uid = request
        .owner
        .as_deref()
        .map(resolve_uid)
        .transpose()
        .map_err(|error| format!("files-converge-owner-resolution-failed: {error}"))?;
    let desired_gid = request
        .group
        .as_deref()
        .map(resolve_gid)
        .transpose()
        .map_err(|error| format!("files-converge-group-resolution-failed: {error}"))?;
    let ownership_source = if desired_uid.is_some() || desired_gid.is_some() {
        "declared"
    } else {
        "ambient"
    };

    let mut entries = Vec::new();
    let mut missing = Vec::new();
    let mut written = 0usize;
    let mut backed_up = 0usize;

    for spec in &request.files {
        let source = request.source_root.join(&spec.relative_path);
        let target = request.target_root.join(&spec.relative_path);
        let relative_path = spec.relative_path.to_string_lossy().to_string();
        let source_exists = source.is_file();
        let target_exists_before = target.exists();
        if !source_exists {
            missing.push(relative_path.clone());
            entries.push(FileConvergenceEntry {
                relative_path,
                source,
                target,
                source_exists,
                target_exists_before,
                content_equal_before: false,
                mode_equal_before: false,
                target_exists_after: target_exists_before,
                content_equal_after: false,
                mode_equal_after: false,
                changed: false,
                backed_up_to: None,
                final_mode: spec.mode,
                ownership_source: ownership_source.to_string(),
                observed_uid_before: None,
                observed_gid_before: None,
                observed_uid_after: None,
                observed_gid_after: None,
                ownership_changed: false,
                observed_uid: None,
                observed_gid: None,
            });
            continue;
        }

        if target_exists_before && !target.is_file() {
            let signal = format!("files-converge-target-not-file {}", target.display());
            write_partial_failure_receipt(
                receipt_dir,
                request,
                apply,
                request.files.len(),
                written,
                backed_up,
                &missing,
                &entries,
                &signal,
            )?;
            return Err(signal);
        }
        let content_equal_before = if target_exists_before {
            match same_file_bytes(&source, &target) {
                Ok(equal) => equal,
                Err(signal) => {
                    write_partial_failure_receipt(
                        receipt_dir,
                        request,
                        apply,
                        request.files.len(),
                        written,
                        backed_up,
                        &missing,
                        &entries,
                        &signal,
                    )?;
                    return Err(signal);
                }
            }
        } else {
            false
        };
        let final_mode = spec.mode.or_else(|| source_mode(&source).ok());
        let mode_equal_before = if target_exists_before {
            target_mode(&target)? == final_mode
        } else {
            false
        };
        let (observed_uid_before, observed_gid_before) = observed_ownership(&target)?;
        let ownership_changed = desired_uid
            .map(|uid| observed_uid_before != Some(uid))
            .unwrap_or(false)
            || desired_gid
                .map(|gid| observed_gid_before != Some(gid))
                .unwrap_or(false);
        let content_changed = !target_exists_before || !content_equal_before || !mode_equal_before;
        let entry_changed = content_changed || ownership_changed;
        let mut backed_up_to = None;

        if apply && entry_changed {
            if let Some(parent) = target.parent() {
                create_parent_dirs(parent, desired_uid, desired_gid)?;
            }
            if target_exists_before && content_changed && request.backup_existing {
                let backup = backup_target(&target, receipt_dir, &spec.relative_path)?;
                backed_up_to = Some(backup);
                backed_up += 1;
            }
            if let Err(signal) = if content_changed {
                atomic_copy(&source, &target, final_mode, desired_uid, desired_gid)
            } else {
                set_ownership(&target, desired_uid, desired_gid)
            } {
                write_partial_failure_receipt(
                    receipt_dir,
                    request,
                    apply,
                    request.files.len(),
                    written,
                    backed_up,
                    &missing,
                    &entries,
                    &signal,
                )?;
                return Err(signal);
            }
            if content_changed {
                written += 1;
            }
        }

        let target_exists_after = target.exists();
        let content_equal_after = if target_exists_after {
            same_file_bytes(&source, &target)?
        } else {
            false
        };
        let mode_equal_after = if target_exists_after {
            target_mode(&target)? == final_mode
        } else {
            false
        };
        let (observed_uid_after, observed_gid_after) = observed_ownership(&target)?;
        let ownership_equal_after = desired_uid
            .map(|uid| observed_uid_after == Some(uid))
            .unwrap_or(true)
            && desired_gid
                .map(|gid| observed_gid_after == Some(gid))
                .unwrap_or(true);
        if apply
            && (!target_exists_after
                || !content_equal_after
                || !mode_equal_after
                || !ownership_equal_after)
        {
            let signal = format!(
                "files-converge-post-write-readback-failed {}",
                target.display()
            );
            let mut failure_entries = entries.clone();
            failure_entries.push(FileConvergenceEntry {
                relative_path: relative_path.clone(),
                source: source.clone(),
                target: target.clone(),
                source_exists,
                target_exists_before,
                content_equal_before,
                mode_equal_before,
                target_exists_after,
                content_equal_after,
                mode_equal_after,
                changed: entry_changed,
                backed_up_to: backed_up_to.clone(),
                final_mode,
                ownership_source: ownership_source.to_string(),
                observed_uid_before,
                observed_gid_before,
                observed_uid_after,
                observed_gid_after,
                ownership_changed,
                observed_uid: observed_uid_after,
                observed_gid: observed_gid_after,
            });
            write_partial_failure_receipt(
                receipt_dir,
                request,
                apply,
                request.files.len(),
                written,
                backed_up,
                &missing,
                &failure_entries,
                &signal,
            )?;
            return Err(signal);
        }

        entries.push(FileConvergenceEntry {
            relative_path,
            source,
            target,
            source_exists,
            target_exists_before,
            content_equal_before,
            mode_equal_before,
            target_exists_after,
            content_equal_after,
            mode_equal_after,
            changed: entry_changed,
            backed_up_to,
            final_mode,
            ownership_source: ownership_source.to_string(),
            observed_uid_before,
            observed_gid_before,
            observed_uid_after,
            observed_gid_after,
            ownership_changed,
            observed_uid: observed_uid_after,
            observed_gid: observed_gid_after,
        });
    }

    let ok = missing.is_empty();
    let changed = entries.iter().any(|entry| entry.changed);
    let ownership_changed = entries.iter().any(|entry| entry.ownership_changed);
    let outcome = FileConvergenceOutcome {
        ok,
        changed,
        ownership_changed,
        checked: request.files.len(),
        written,
        backed_up,
        missing,
        entries,
        message: if ok {
            format!(
                "{} files {} from {} to {}",
                request.files.len(),
                if apply { "converged" } else { "planned" },
                request.source_root.display(),
                request.target_root.display()
            )
        } else {
            "files convergence source incomplete".to_string()
        },
    };
    write_convergence_receipt(receipt_dir, request, &outcome, apply)?;
    Ok(outcome)
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub receipt_name: String,
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

fn inventory_sweep_tree(root: &Path) -> Result<Vec<SweepTreeEntry>, String> {
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
    fn walk(root: &Path, path: &Path, entries: &mut Vec<SweepTreeEntry>) -> Result<(), String> {
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
                walk(root, &child_path, entries)?;
            }
        }
        Ok(())
    }
    walk(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(entries)
}

fn inventory_sweep_tree_if_present(root: &Path) -> Result<Vec<SweepTreeEntry>, String> {
    match fs::symlink_metadata(root) {
        Ok(_) => inventory_sweep_tree(root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(format!(
            "source-shelf-sweep-target-metadata-failed {}: {error}",
            root.display()
        )),
    }
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

fn sync_directory(path: &Path) -> Result<(), String> {
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
    source: &Path,
    stage: &Path,
    entries: &[SweepTreeEntry],
    directory_mode: u32,
    file_mode: u32,
    uid: u32,
    gid: u32,
) -> Result<(), String> {
    fs::create_dir(stage).map_err(|error| {
        format!(
            "source-shelf-sweep-stage-create-failed {}: {error}",
            stage.display()
        )
    })?;
    set_mode(stage, directory_mode)?;
    set_ownership(stage, Some(uid), Some(gid))?;
    for entry in entries
        .iter()
        .filter(|entry| entry.relative_path != Path::new("."))
    {
        let source_path = source.join(&entry.relative_path);
        let target_path = stage.join(&entry.relative_path);
        if entry.is_dir {
            fs::create_dir(&target_path).map_err(|error| {
                format!(
                    "source-shelf-sweep-stage-directory-failed {}: {error}",
                    target_path.display()
                )
            })?;
            set_mode(&target_path, directory_mode)?;
            set_ownership(&target_path, Some(uid), Some(gid))?;
        } else {
            let parent = target_path.parent().ok_or_else(|| {
                format!(
                    "source-shelf-sweep-stage-parent-missing {}",
                    target_path.display()
                )
            })?;
            atomic_copy(
                &source_path,
                &target_path,
                Some(file_mode),
                Some(uid),
                Some(gid),
            )?;
            sync_directory(parent)?;
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
        sync_directory(&directory)?;
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
) -> Result<bool, String> {
    let target_entries = inventory_sweep_tree_if_present(target)?;
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
) -> Result<BTreeMap<String, PathBuf>, String> {
    let mut launchers = BTreeMap::new();
    for entry in fs::read_dir(source_root).map_err(|error| {
        format!(
            "source-shelf-sweep-launcher-source-read-failed {}: {error}",
            source_root.display()
        )
    })? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !basename_pattern_matches(pattern, &name) {
            continue;
        }
        let path = entry.path();
        let kind = entry.file_type().map_err(|error| error.to_string())?;
        if !kind.is_file() || kind.is_symlink() {
            return Err(format!(
                "source-shelf-sweep-launcher-source-kind-rejected {}",
                path.display()
            ));
        }
        if path.parent() != Some(source_root) {
            return Err(format!(
                "source-shelf-sweep-launcher-match-outside-root {}",
                path.display()
            ));
        }
        launchers.insert(name, path);
    }
    if launchers.is_empty() {
        return Err(format!(
            "source-shelf-sweep-launcher-pattern-empty {pattern:?}"
        ));
    }
    Ok(launchers)
}

fn target_pattern_files(target_root: &Path, pattern: &str) -> Result<BTreeSet<String>, String> {
    if !target_root.exists() {
        return Ok(BTreeSet::new());
    }
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(target_root).map_err(|error| {
        format!(
            "source-shelf-sweep-launcher-target-read-failed {}: {error}",
            target_root.display()
        )
    })? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !basename_pattern_matches(pattern, &name) {
            continue;
        }
        let kind = entry.file_type().map_err(|error| error.to_string())?;
        if !kind.is_file() || kind.is_symlink() {
            return Err(format!(
                "source-shelf-sweep-launcher-target-kind-rejected {}",
                entry.path().display()
            ));
        }
        names.insert(name);
    }
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
    fs::create_dir_all(receipt_dir).map_err(|error| error.to_string())?;
    let base = request.receipt_name.trim_end_matches(".json");
    for (index, entry) in outcome.entries.iter().enumerate() {
        let safe = entry
            .relative_path
            .replace(['/', '\\'], "_")
            .trim_matches('_')
            .to_string();
        crate::write_json(
            &receipt_dir.join(format!("{base}-file-{index:04}-{safe}.json")),
            &json!({
                "schema": "harmonia.files.source_shelf_sweep.file.v1",
                "ok": outcome.ok && entry.readback_ok,
                "apply": apply,
                "atomicity": "per-path atomic",
                "transaction": "all-or-restored",
                "receipt_write_contract": "same-directory temp write, file fsync, atomic rename, parent-directory fsync",
                "entry": entry,
                "first_blocker": if entry.readback_ok { "none" } else { outcome.first_blocker.as_str() },
            }),
        )?;
    }
    let receipt_name = if request.receipt_name.ends_with(".json") {
        request.receipt_name.clone()
    } else {
        format!("{}.json", request.receipt_name)
    };
    crate::write_json(
        &receipt_dir.join(receipt_name),
        &json!({
            "schema": "harmonia.files.source_shelf_sweep.transaction.v1",
            "ok": outcome.ok,
            "apply": apply,
            "changed": outcome.changed,
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
) -> Result<SourceShelfSweepOutcome, String> {
    match source_shelf_sweep_with_fault(
        request,
        receipt_dir,
        apply,
        SourceShelfSweepFault::default(),
    ) {
        Ok(outcome) => Ok(outcome),
        Err(blocker) => {
            if validate_receipt_name(&request.receipt_name).is_ok() {
                let receipt_name = if request.receipt_name.ends_with(".json") {
                    request.receipt_name.clone()
                } else {
                    format!("{}.json", request.receipt_name)
                };
                if !receipt_dir.join(receipt_name).exists() {
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

fn source_shelf_sweep_with_fault(
    request: &SourceShelfSweepRequest,
    receipt_dir: &Path,
    apply: bool,
    fault: SourceShelfSweepFault,
) -> Result<SourceShelfSweepOutcome, String> {
    validate_receipt_name(&request.receipt_name)?;
    validate_relative_path(&request.shelf_source)?;
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
    let source_entries = inventory_sweep_tree(&shelf_source)?;
    let target_before = inventory_sweep_tree_if_present(&request.target_shelf)?;
    let launchers = source_launchers(&launcher_source_root, &request.launcher_pattern)?;
    let target_launchers =
        target_pattern_files(&request.launcher_target_root, &request.launcher_pattern)?;
    let stale: BTreeSet<_> = target_launchers
        .difference(&launchers.keys().cloned().collect())
        .cloned()
        .collect();
    let shelf_current = shelf_is_current(
        &shelf_source,
        &request.target_shelf,
        &source_entries,
        request.shelf_directory_mode,
        request.shelf_file_mode,
        uid,
        gid,
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
    if !drift || !apply {
        let outcome = SourceShelfSweepOutcome {
            ok: true,
            changed: false,
            current: !drift,
            source_inventory_count: source_entries.len() + launchers.len(),
            target_inventory_count_before: target_before.len() + target_launchers.len(),
            target_inventory_count_after: target_before.len() + target_launchers.len(),
            promoted_count: 0,
            removed_count: 0,
            transaction_state: if drift { "planned" } else { "unchanged" }.into(),
            rollback_state: "not-needed".into(),
            first_blocker: "none".into(),
            entries: planned_entries,
            message: if drift {
                "source shelf sweep planned".into()
            } else {
                "source shelf and launchers current".into()
            },
        };
        write_sweep_receipts(receipt_dir, request, &outcome, apply)?;
        return Ok(outcome);
    }

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
        fs::create_dir(&quarantine).map_err(|error| {
            format!(
                "source-shelf-sweep-quarantine-create-failed {}: {error}",
                quarantine.display()
            )
        })?;
        sync_directory(&request.launcher_target_root)?;
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
            if let Err(error) = fs::remove_dir_all(path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    cleanup_errors.push(format!("remove setup path {}: {error}", path.display()));
                }
            }
        }
        for parent in [shelf_parent, request.launcher_target_root.as_path()] {
            if let Err(error) = sync_directory(parent) {
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
    let mut launcher_backups: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut new_launchers: Vec<PathBuf> = Vec::new();
    let mut promoted_count = 0usize;
    let mut removed_count = 0usize;
    let transaction = (|| -> Result<(), String> {
        if !shelf_current {
            if shelf_had_prior {
                fs::rename(&request.target_shelf, &shelf_backup).map_err(|error| {
                    format!("source-shelf-sweep-shelf-quarantine-failed: {error}")
                })?;
            }
            fs::rename(&stage, &request.target_shelf)
                .map_err(|error| format!("source-shelf-sweep-shelf-promote-failed: {error}"))?;
            sync_directory(shelf_parent)?;
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
            if target.exists() {
                let backup = quarantine.join(name);
                fs::rename(&target, &backup).map_err(|error| {
                    format!(
                        "source-shelf-sweep-launcher-quarantine-failed {}: {error}",
                        target.display()
                    )
                })?;
                launcher_backups.push((target.clone(), backup));
            } else {
                new_launchers.push(target.clone());
            }
            atomic_copy(
                source,
                &target,
                Some(request.launcher_mode),
                Some(uid),
                Some(gid),
            )?;
            sync_directory(&request.launcher_target_root)?;
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
                let backup = quarantine.join(name);
                fs::rename(&target, &backup).map_err(|error| {
                    format!(
                        "source-shelf-sweep-stale-launcher-quarantine-failed {}: {error}",
                        target.display()
                    )
                })?;
                launcher_backups.push((target, backup));
                removed_count += 1;
            }
            sync_directory(&request.launcher_target_root)?;
        }
        if !shelf_is_current(
            &shelf_source,
            &request.target_shelf,
            &source_entries,
            request.shelf_directory_mode,
            request.shelf_file_mode,
            uid,
            gid,
        )? {
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
        let target_after = inventory_sweep_tree_if_present(&request.target_shelf)?;
        let target_launchers_after =
            target_pattern_files(&request.launcher_target_root, &request.launcher_pattern)?;
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
            if let Err(error) = fs::remove_file(target) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    rollback_errors.push(format!("remove {}: {error}", target.display()));
                }
            }
        }
        for (target, backup) in launcher_backups.iter().rev() {
            let _ = fs::remove_file(target);
            if let Err(error) = fs::rename(backup, target) {
                rollback_errors.push(format!(
                    "restore {} -> {}: {error}",
                    backup.display(),
                    target.display()
                ));
            }
        }
        if shelf_promoted {
            if let Err(error) = fs::remove_dir_all(&request.target_shelf) {
                rollback_errors.push(format!(
                    "remove promoted shelf {}: {error}",
                    request.target_shelf.display()
                ));
            }
            if shelf_had_prior {
                if let Err(error) = fs::rename(&shelf_backup, &request.target_shelf) {
                    rollback_errors.push(format!(
                        "restore shelf {} -> {}: {error}",
                        shelf_backup.display(),
                        request.target_shelf.display()
                    ));
                }
            }
        }
        let _ = fs::remove_dir_all(&stage);
        let _ = fs::remove_dir_all(&quarantine);
        let rollback_entries = match readback_rollback_entries(planned_entries) {
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
            target_inventory_count_after: inventory_sweep_tree_if_present(&request.target_shelf)
                .map(|entries| entries.len())
                .unwrap_or_default()
                + target_pattern_files(&request.launcher_target_root, &request.launcher_pattern)
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
        fs::remove_dir_all(&quarantine).map_err(|error| {
            format!(
                "source-shelf-sweep-quarantine-remove-failed {}: {error}",
                quarantine.display()
            )
        })?;
        if shelf_had_prior && shelf_promoted {
            fs::remove_dir_all(&shelf_backup).map_err(|error| {
                format!(
                    "source-shelf-sweep-prior-shelf-remove-failed {}: {error}",
                    shelf_backup.display()
                )
            })?;
        }
        let _ = fs::remove_dir_all(&stage);
        sync_directory(shelf_parent)?;
        sync_directory(&request.launcher_target_root)?;
        Ok(())
    })();
    if let Err(blocker) = cleanup {
        outcome.ok = false;
        outcome.transaction_state = "committed-cleanup-debt".into();
        outcome.first_blocker = blocker.clone();
        outcome.message = format!("source shelf and launchers converged; cleanup debt: {blocker}");
        write_sweep_receipts(receipt_dir, request, &outcome, apply).map_err(|receipt_error| {
            format!("{}; receipt-write-failed: {receipt_error}", outcome.message)
        })?;
        return Err(outcome.message);
    }
    write_sweep_receipts(receipt_dir, request, &outcome, apply)?;
    Ok(outcome)
}

pub fn remove_declared_files(
    target_root: &Path,
    paths: &[String],
    receipt_dir: &Path,
    receipt_name: &str,
    apply: bool,
) -> Result<FileRemovalOutcome, String> {
    if paths.is_empty() {
        return Err("files-remove-empty-request".to_string());
    }
    validate_receipt_name(receipt_name)?;
    let specs: Vec<FileSpec> = paths
        .iter()
        .map(|path| FileSpec {
            relative_path: PathBuf::from(path),
            mode: None,
        })
        .collect();
    validate_specs(&specs)?;

    let mut entries = Vec::new();
    let mut removed = 0usize;
    let mut changed = false;
    let mut failure = None;
    for spec in specs {
        let target = target_root.join(&spec.relative_path);
        let metadata = match fs::symlink_metadata(&target) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                failure = Some(format!(
                    "files-remove-metadata-failed {}: {error}",
                    target.display()
                ));
                entries.push(FileRemovalEntry {
                    relative_path: spec.relative_path.to_string_lossy().into_owned(),
                    target,
                    found_before: "unreadable".into(),
                    exists_after: true,
                    result: "unreadable".into(),
                    changed: false,
                });
                break;
            }
        };
        let relative_path = spec.relative_path.to_string_lossy().into_owned();
        match metadata {
            None => entries.push(FileRemovalEntry {
                relative_path,
                target,
                found_before: "absent".into(),
                exists_after: false,
                result: "absent".into(),
                changed: false,
            }),
            Some(metadata) if !metadata.file_type().is_file() => {
                failure = Some(format!(
                    "files-remove-target-not-regular-file {}",
                    target.display()
                ));
                entries.push(FileRemovalEntry {
                    relative_path,
                    target,
                    found_before: if metadata.file_type().is_symlink() {
                        "symlink".into()
                    } else {
                        "non-regular".into()
                    },
                    exists_after: true,
                    result: "refused-non-regular".into(),
                    changed: false,
                });
                break;
            }
            Some(_) if apply => {
                match fs::remove_file(&target) {
                    Ok(()) => {
                        let exists_after = fs::symlink_metadata(&target).is_ok();
                        if exists_after {
                            failure = Some(format!(
                                "files-remove-post-remove-readback-failed {}",
                                target.display()
                            ));
                        }
                        removed += 1;
                        changed = true;
                        entries.push(FileRemovalEntry {
                            relative_path,
                            target,
                            found_before: "regular-file".into(),
                            exists_after,
                            result: if exists_after {
                                "remove-readback-failed".into()
                            } else {
                                "removed".into()
                            },
                            changed: true,
                        });
                    }
                    Err(error) => {
                        failure =
                            Some(format!("files-remove-failed {}: {error}", target.display()));
                        entries.push(FileRemovalEntry {
                            relative_path,
                            target,
                            found_before: "regular-file".into(),
                            exists_after: true,
                            result: "remove-failed".into(),
                            changed: false,
                        });
                    }
                }
                if failure.is_some() {
                    break;
                }
            }
            Some(_) => entries.push(FileRemovalEntry {
                relative_path,
                target,
                found_before: "regular-file".into(),
                exists_after: true,
                result: "planned-removal".into(),
                changed: true,
            }),
        }
    }
    let ok = failure.is_none();
    let outcome = FileRemovalOutcome {
        ok,
        changed,
        checked: paths.len(),
        removed,
        entries,
        message: failure
            .unwrap_or_else(|| format!("{} declared files removed or absent", paths.len())),
    };
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let receipt = receipt_dir.join(if receipt_name.ends_with(".json") {
        receipt_name.to_string()
    } else {
        format!("{receipt_name}.json")
    });
    crate::write_json(
        &receipt,
        &json!({
            "schema": "harmonia.files.remove.v1",
            "ok": outcome.ok,
            "apply": apply,
            "target_root": target_root,
            "checked": outcome.checked,
            "removed": outcome.removed,
            "changed": outcome.changed,
            "entries": outcome.entries,
            "first_missing_signal": if outcome.ok { "none" } else { outcome.message.as_str() },
        }),
    )?;
    Ok(outcome)
}

pub(crate) fn validate_relative_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(format!("files-relative-path-rejected {}", path.display()));
    }
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            _ => return Err(format!("files-relative-path-rejected {}", path.display())),
        }
    }
    Ok(())
}

fn reject_ssh_path(path: &Path) -> Result<(), String> {
    if path
        .components()
        .any(|component| matches!(component, Component::Normal(value) if value == ".ssh"))
    {
        return Err(format!(
            "credential-boundary-refused: {} is under .ssh, Harmonia never writes SSH/credential material",
            path.display()
        ));
    }
    Ok(())
}

fn validate_specs(specs: &[FileSpec]) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for spec in specs {
        validate_relative_path(&spec.relative_path)?;
        if !seen.insert(spec.relative_path.clone()) {
            return Err(format!(
                "files-duplicate-relative-path-rejected {}",
                spec.relative_path.display()
            ));
        }
        if let Some(mode) = spec.mode {
            if mode & !0o777 != 0 {
                return Err(format!("files-mode-rejected {:o}", mode));
            }
        }
    }
    Ok(())
}

fn validate_receipt_name(receipt_name: &str) -> Result<(), String> {
    if receipt_name.is_empty() {
        return Ok(());
    }
    let path = Path::new(receipt_name);
    if path.is_absolute() || path.components().count() != 1 {
        return Err(format!("files-receipt-name-rejected {receipt_name}"));
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(format!("files-receipt-name-rejected {receipt_name}"));
    };
    if name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return Err(format!("files-receipt-name-rejected {receipt_name}"));
    }
    Ok(())
}

fn source_mode(path: &Path) -> Result<u32, String> {
    file_mode(path)
}

fn target_mode(path: &Path) -> Result<Option<u32>, String> {
    if path.exists() {
        Ok(Some(file_mode(path)?))
    } else {
        Ok(None)
    }
}

#[cfg(unix)]
fn observed_ownership(path: &Path) -> Result<(Option<u32>, Option<u32>), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok((Some(metadata.uid()), Some(metadata.gid()))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((None, None)),
        Err(error) => Err(format!(
            "files-owner-metadata-failed {}: {error}",
            path.display()
        )),
    }
}

#[cfg(not(unix))]
fn observed_ownership(_path: &Path) -> Result<(Option<u32>, Option<u32>), String> {
    Ok((None, None))
}

fn create_parent_dirs(
    parent: &Path,
    desired_uid: Option<u32>,
    desired_gid: Option<u32>,
) -> Result<(), String> {
    if desired_uid.is_none() && desired_gid.is_none() {
        return fs::create_dir_all(parent).map_err(|error| {
            format!(
                "files-converge-target-parent-create-failed {}: {error}",
                parent.display()
            )
        });
    }

    let mut missing = Vec::new();
    let mut cursor = parent;
    while !cursor.exists() {
        missing.push(cursor.to_path_buf());
        cursor = cursor.parent().ok_or_else(|| {
            format!(
                "files-converge-target-parent-create-failed {}",
                parent.display()
            )
        })?;
    }
    for directory in missing.iter().rev() {
        match fs::create_dir(directory) {
            Ok(()) => set_ownership(directory, desired_uid, desired_gid)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "files-converge-target-parent-create-failed {}: {error}",
                    directory.display()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn file_mode(path: &Path) -> Result<u32, String> {
    Ok(fs::metadata(path)
        .map_err(|e| format!("files-metadata-failed {}: {e}", path.display()))?
        .permissions()
        .mode()
        & 0o777)
}

#[cfg(not(unix))]
pub(crate) fn file_mode(_path: &Path) -> Result<u32, String> {
    Ok(0o644)
}

fn same_file_bytes(source: &Path, target: &Path) -> Result<bool, String> {
    let source_bytes = fs::read(source)
        .map_err(|e| format!("files-source-read-failed {}: {e}", source.display()))?;
    let target_bytes = fs::read(target)
        .map_err(|e| format!("files-target-read-failed {}: {e}", target.display()))?;
    Ok(source_bytes == target_bytes)
}

fn backup_target(target: &Path, receipt_dir: &Path, rel: &Path) -> Result<PathBuf, String> {
    let backup = receipt_dir.join("backups").join(rel);
    if let Some(parent) = backup.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "files-backup-parent-create-failed {}: {e}",
                parent.display()
            )
        })?;
    }
    fs::copy(target, &backup).map_err(|e| {
        format!(
            "files-backup-failed {} -> {}: {e}",
            target.display(),
            backup.display()
        )
    })?;
    Ok(backup)
}

pub(crate) fn atomic_write_bytes(
    target: &Path,
    bytes: &[u8],
    mode: Option<u32>,
) -> Result<(), String> {
    atomic_write_bytes_with_ownership(target, bytes, mode, None, None)
}

fn atomic_write_bytes_with_ownership(
    target: &Path,
    bytes: &[u8],
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), String> {
    let parent = target
        .parent()
        .ok_or_else(|| format!("files-target-parent-missing {}", target.display()))?;
    let temp = parent.join(format!(
        ".{}.harmonia-tmp-{}",
        target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file"),
        sweep_nonce()
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
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
        let _ = sync_directory(parent);
    }
    result
}

fn atomic_copy(
    source: &Path,
    target: &Path,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), String> {
    let bytes = fs::read(source)
        .map_err(|e| format!("files-source-read-failed {}: {e}", source.display()))?;
    atomic_write_bytes_with_ownership(target, &bytes, mode, uid, gid)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
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

fn write_partial_failure_receipt(
    receipt_dir: &Path,
    request: &FileConvergenceRequest,
    apply: bool,
    checked: usize,
    written: usize,
    backed_up: usize,
    missing: &[String],
    entries: &[FileConvergenceEntry],
    signal: &str,
) -> Result<(), String> {
    let outcome = FileConvergenceOutcome {
        ok: false,
        changed: entries.iter().any(|entry| entry.changed) || written > 0 || backed_up > 0,
        ownership_changed: entries.iter().any(|entry| entry.ownership_changed),
        checked,
        written,
        backed_up,
        missing: missing.to_vec(),
        entries: entries.to_vec(),
        message: signal.to_string(),
    };
    write_convergence_receipt(receipt_dir, request, &outcome, apply)
}

fn write_convergence_receipt(
    receipt_dir: &Path,
    request: &FileConvergenceRequest,
    outcome: &FileConvergenceOutcome,
    apply: bool,
) -> Result<(), String> {
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let receipt = json!({
        "schema": "harmonia.files.converge.v1",
        "ok": outcome.ok,
        "apply": apply,
        "source_root": request.source_root,
        "target_root": request.target_root,
        "backup_existing": request.backup_existing,
        "owner": request.owner,
        "group": request.group,
        "checked": outcome.checked,
        "written": outcome.written,
        "backed_up": outcome.backed_up,
        "changed": outcome.changed,
        "ownership_changed": outcome.ownership_changed,
        "missing": outcome.missing,
        "entries": outcome.entries,
        "first_missing_signal": if outcome.ok { "none" } else if outcome.missing.is_empty() { outcome.message.as_str() } else { "files-convergence-source-incomplete" },
    });
    let mut receipt_name = request.receipt_name.clone();
    if receipt_name.is_empty() {
        receipt_name = "files-converge".to_string();
    }
    if !receipt_name.ends_with(".json") {
        receipt_name.push_str(".json");
    }
    let path = receipt_dir.join(receipt_name);
    let mut file = File::create(&path)
        .map_err(|e| format!("files-receipt-create-failed {}: {e}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, &receipt).map_err(|e| e.to_string())?;
    writeln!(file).map_err(|e| e.to_string())?;
    Ok(())
}

pub(crate) fn validated_symlink(
    receipt_dir: &Path,
    name: &str,
    source: &Path,
    target: &Path,
    validator_program: &str,
    validator_args: &[String],
    reload_program: Option<&str>,
    reload_args: &[String],
    timeout_secs: u64,
    apply: bool,
) -> Result<crate::OperationOutcome, String> {
    let source_ok = source.is_file();
    let prior = fs::read_link(target).ok();
    let current = prior.as_deref() == Some(source);
    let mut validator = crate::CmdResult {
        ok: true,
        code: 0,
        stdout: "not-run".into(),
        stderr: String::new(),
    };
    let mut reload = None;
    let mut promoted = false;
    let mut signal = "none".to_string();
    if !source_ok {
        signal = "validated-symlink-source-missing".into();
    } else if !current && apply {
        let parent = target
            .parent()
            .ok_or_else(|| "validated-symlink-target-parent-missing".to_string())?;
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        if target.exists() && !target.is_symlink() {
            signal = "validated-symlink-target-not-link".into();
        } else {
            let candidate = parent.join(format!(
                ".{}.harmonia-candidate-{}",
                target
                    .file_name()
                    .and_then(|v| v.to_str())
                    .unwrap_or("link"),
                std::process::id()
            ));
            let _ = fs::remove_file(&candidate);
            #[cfg(unix)]
            std::os::unix::fs::symlink(source, &candidate).map_err(|e| e.to_string())?;
            #[cfg(not(unix))]
            return Err("validated-symlink-unsupported".into());
            let refs: Vec<&str> = validator_args.iter().map(String::as_str).collect();
            validator =
                crate::tools::command::capture_with_timeout(validator_program, &refs, timeout_secs);
            if validator.ok {
                fs::rename(&candidate, target).map_err(|e| e.to_string())?;
                promoted = true;
                if let Some(program) = reload_program.filter(|value| !value.is_empty()) {
                    let refs: Vec<&str> = reload_args.iter().map(String::as_str).collect();
                    let result =
                        crate::tools::command::capture_with_timeout(program, &refs, timeout_secs);
                    if !result.ok {
                        if let Some(old) = prior {
                            let _ = fs::remove_file(target);
                            #[cfg(unix)]
                            let _ = std::os::unix::fs::symlink(old, target);
                        }
                        signal = "validated-symlink-reload-failed-restored".into();
                    }
                    reload = Some(result);
                }
            } else {
                signal = "validated-symlink-validator-failed".into();
                let _ = fs::remove_file(candidate);
            }
        }
    }
    let ok = source_ok
        && signal == "none"
        && validator.ok
        && reload.as_ref().map(|v| v.ok).unwrap_or(true);
    crate::write_json(
        &receipt_dir.join(format!("{name}.json")),
        &json!({"schema":"harmonia.files.validated_symlink.v1","source":source,"target":target,"apply":apply,"changed":promoted,"source_exists":source_ok,"link_current_before":current,"validator":validator,"reload":reload,"first_missing_signal":signal,"ok":ok}),
    )?;
    Ok(crate::OperationOutcome {
        ok,
        changed: promoted,
        skipped: !apply,
        message: "validated symlink".into(),
        command: None,
    })
}

#[cfg(test)]
mod managed_ownership_tests {
    use super::*;

    #[test]
    fn managed_files_refuse_ssh_paths_in_plan_and_apply_without_writing() {
        assert!(reject_ssh_path(Path::new(".ssh/config")).is_err());
        assert!(reject_ssh_path(Path::new("myssh-notes/config")).is_ok());
        for apply in [false, true] {
            let scratch = std::env::temp_dir().join(format!(
                "harmonia-managed-ssh-refusal-{}-{apply}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&scratch);
            let target = scratch.join(".ssh/known_hosts");
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(&target, b"preserved\n").unwrap();
            let files = vec![crate::ManagedFileManifest {
                path: target.to_string_lossy().into_owned(),
                content: "replacement\n".to_string(),
                mode: Some(0o600),
            }];

            let error = converge_managed_files(
                &ManagedFilesRequest {
                    module_id: "test",
                    files: &files,
                    owner: None,
                    group: None,
                    receipt_name: "ssh-refusal",
                    schema: "harmonia.test.ssh.v1",
                    first_missing_signal: "credential-boundary-refused",
                },
                &scratch.join("receipts"),
                apply,
            )
            .unwrap_err();

            assert!(error.contains("credential-boundary-refused"));
            assert!(error.contains(&target.display().to_string()));
            assert_eq!(fs::read(&target).unwrap(), b"preserved\n");
            let _ = fs::remove_dir_all(&scratch);
        }
    }

    #[cfg(unix)]
    #[test]
    fn managed_files_reports_declared_owner_drift_even_when_bytes_and_mode_match() {
        let scratch = std::env::temp_dir().join(format!(
            "harmonia-managed-owner-drift-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(&scratch).unwrap();
        let target = scratch.join("payload");
        fs::write(&target, b"desired\n").unwrap();
        set_mode(&target, 0o644).unwrap();
        let metadata = fs::metadata(&target).unwrap();
        let desired_uid = metadata.uid().wrapping_add(1).to_string();
        let actual_gid = metadata.gid().to_string();
        let files = vec![crate::ManagedFileManifest {
            path: target.to_string_lossy().into_owned(),
            content: "desired\n".to_string(),
            mode: Some(0o644),
        }];

        let outcome = converge_managed_files(
            &ManagedFilesRequest {
                module_id: "test",
                files: &files,
                owner: Some(&desired_uid),
                group: Some(&actual_gid),
                receipt_name: "owner-drift",
                schema: "harmonia.test.owner.v1",
                first_missing_signal: "managed-files-drift",
            },
            &scratch,
            false,
        )
        .unwrap();

        assert!(outcome.ok);
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(scratch.join("owner-drift.json")).unwrap()).unwrap();
        assert_eq!(receipt["entries"][0]["content_equal_before"], true);
        assert_eq!(receipt["entries"][0]["mode_equal_before"], true);
        assert_eq!(receipt["entries"][0]["owner_equal_before"], false);
        assert_eq!(receipt["entries"][0]["group_equal_before"], true);
        assert_eq!(receipt["entries"][0]["changed"], true);
        let _ = fs::remove_dir_all(&scratch);
    }

    #[cfg(unix)]
    #[test]
    fn managed_files_apply_chowns_when_running_with_root_authority() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let scratch = std::env::temp_dir().join(format!(
            "harmonia-managed-owner-apply-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(&scratch).unwrap();
        let target = scratch.join("payload");
        fs::write(&target, b"desired\n").unwrap();
        set_mode(&target, 0o755).unwrap();
        let files = vec![crate::ManagedFileManifest {
            path: target.to_string_lossy().into_owned(),
            content: "desired\n".to_string(),
            mode: Some(0o755),
        }];

        let outcome = converge_managed_files(
            &ManagedFilesRequest {
                module_id: "test",
                files: &files,
                owner: Some("65534"),
                group: Some("65534"),
                receipt_name: "owner-apply",
                schema: "harmonia.test.owner.v1",
                first_missing_signal: "managed-files-drift",
            },
            &scratch,
            true,
        )
        .unwrap();

        assert!(outcome.ok);
        assert!(outcome.changed);
        let metadata = fs::metadata(&target).unwrap();
        assert_eq!(metadata.uid(), 65534);
        assert_eq!(metadata.gid(), 65534);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o755);
        let _ = fs::remove_dir_all(&scratch);
    }

    #[cfg(unix)]
    #[test]
    fn managed_files_replaces_symlink_before_privileged_owner_change() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let scratch = std::env::temp_dir().join(format!(
            "harmonia-managed-owner-symlink-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(&scratch).unwrap();
        let victim = scratch.join("victim");
        let target = scratch.join("payload");
        fs::write(&victim, b"desired\n").unwrap();
        set_mode(&victim, 0o755).unwrap();
        std::os::unix::fs::symlink(&victim, &target).unwrap();
        let files = vec![crate::ManagedFileManifest {
            path: target.to_string_lossy().into_owned(),
            content: "desired\n".to_string(),
            mode: Some(0o755),
        }];

        converge_managed_files(
            &ManagedFilesRequest {
                module_id: "test",
                files: &files,
                owner: Some("65534"),
                group: Some("65534"),
                receipt_name: "owner-symlink",
                schema: "harmonia.test.owner.v1",
                first_missing_signal: "managed-files-drift",
            },
            &scratch,
            true,
        )
        .unwrap();

        let target_metadata = fs::symlink_metadata(&target).unwrap();
        assert!(target_metadata.file_type().is_file());
        assert_eq!(target_metadata.uid(), 65534);
        assert_eq!(target_metadata.gid(), 65534);
        let victim_metadata = fs::metadata(&victim).unwrap();
        assert_eq!(victim_metadata.uid(), 0);
        assert_eq!(victim_metadata.gid(), 0);
        let _ = fs::remove_dir_all(&scratch);
    }

    #[cfg(unix)]
    #[test]
    fn converge_applies_declared_ownership_and_receipts_observed_metadata() {
        let scratch = std::env::temp_dir().join(format!(
            "harmonia-files-declared-owner-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&scratch);
        let source = scratch.join("source");
        let target = scratch.join("target");
        let receipts = scratch.join("receipts");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::write(source.join("nested/payload"), "desired\n").unwrap();
        let owner = unsafe { libc::geteuid() }.to_string();
        let group = unsafe { libc::getegid() }.to_string();
        let request = FileConvergenceRequest {
            source_root: source,
            target_root: target.clone(),
            files: vec![FileSpec {
                relative_path: PathBuf::from("nested/payload"),
                mode: Some(0o640),
            }],
            backup_existing: false,
            receipt_name: "declared-owner".to_string(),
            owner: Some(owner.clone()),
            group: Some(group.clone()),
        };

        let outcome = converge_files(&request, &receipts, true).unwrap();
        assert!(outcome.ok);
        assert_eq!(outcome.written, 1);
        let payload = target.join("nested/payload");
        let metadata = fs::metadata(&payload).unwrap();
        let parent_metadata = fs::metadata(target.join("nested")).unwrap();
        assert_eq!(metadata.uid().to_string(), owner);
        assert_eq!(metadata.gid().to_string(), group);
        assert_eq!(parent_metadata.uid(), metadata.uid());
        assert_eq!(parent_metadata.gid(), metadata.gid());
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(receipts.join("declared-owner.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["entries"][0]["ownership_source"], "declared");
        assert_eq!(receipt["entries"][0]["observed_uid"], metadata.uid());
        assert_eq!(receipt["entries"][0]["observed_gid"], metadata.gid());
        let _ = fs::remove_dir_all(&scratch);
    }

    #[cfg(unix)]
    fn sweep_test_request(scratch: &Path) -> SourceShelfSweepRequest {
        SourceShelfSweepRequest {
            source_root: scratch.join("source"),
            shelf_source: PathBuf::from("caduceus_staff"),
            target_shelf: scratch.join("target/caduceus_staff"),
            launcher_source_root: scratch.join("source"),
            launcher_target_root: scratch.join("target"),
            launcher_pattern: "caduceus-*".into(),
            shelf_owner: unsafe { libc::geteuid() }.to_string(),
            shelf_group: unsafe { libc::getegid() }.to_string(),
            shelf_directory_mode: 0o755,
            shelf_file_mode: 0o644,
            launcher_mode: 0o755,
            prune: true,
            receipt_name: "source-shelf-sweep".into(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn source_shelf_sweep_converges_prunes_receipts_and_then_returns_unchanged() {
        let scratch = std::env::temp_dir().join(format!(
            "harmonia-source-shelf-sweep-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(scratch.join("source/caduceus_staff/nested")).unwrap();
        fs::create_dir_all(scratch.join("target/caduceus_staff")).unwrap();
        fs::write(
            scratch.join("source/caduceus_staff/nested/module.py"),
            b"desired\n",
        )
        .unwrap();
        fs::write(scratch.join("source/caduceus-current"), b"new launcher\n").unwrap();
        fs::write(scratch.join("target/caduceus_staff/old.py"), b"old shelf\n").unwrap();
        fs::write(scratch.join("target/caduceus-current"), b"old launcher\n").unwrap();
        fs::write(scratch.join("target/caduceus-stale"), b"stale launcher\n").unwrap();
        fs::write(scratch.join("target/not-owned"), b"preserve\n").unwrap();
        let request = sweep_test_request(&scratch);
        let receipts = scratch.join("receipts");

        let applied = source_shelf_sweep(&request, &receipts, true).unwrap();
        assert!(applied.ok);
        assert!(applied.changed);
        assert_eq!(applied.transaction_state, "committed");
        assert_eq!(applied.rollback_state, "not-needed");
        assert_eq!(applied.first_blocker, "none");
        assert_eq!(applied.removed_count, 1);
        assert_eq!(
            fs::read(scratch.join("target/caduceus_staff/nested/module.py")).unwrap(),
            b"desired\n"
        );
        assert_eq!(
            fs::read(scratch.join("target/caduceus-current")).unwrap(),
            b"new launcher\n"
        );
        assert!(!scratch.join("target/caduceus-stale").exists());
        assert_eq!(
            fs::read(scratch.join("target/not-owned")).unwrap(),
            b"preserve\n"
        );
        assert_eq!(
            file_mode(&scratch.join("target/caduceus-current")).unwrap(),
            0o755
        );
        assert_eq!(
            file_mode(&scratch.join("target/caduceus_staff/nested/module.py")).unwrap(),
            0o644
        );
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(receipts.join("source-shelf-sweep.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["atomicity"], "per-path atomic");
        assert_eq!(receipt["transaction_contract"], "all-or-restored");
        assert_eq!(receipt["whole_set_atomic"], false);
        assert_eq!(
            receipt["receipt_write_contract"],
            "same-directory temp write, file fsync, atomic rename, parent-directory fsync"
        );
        assert!(receipt["entries"].as_array().unwrap().len() >= 4);

        let unchanged = source_shelf_sweep(&request, &receipts, true).unwrap();
        assert!(unchanged.ok);
        assert!(!unchanged.changed);
        assert_eq!(unchanged.transaction_state, "unchanged");
        assert_eq!(unchanged.promoted_count, 0);
        assert_eq!(unchanged.removed_count, 0);
        let _ = fs::remove_dir_all(&scratch);
    }

    #[cfg(unix)]
    #[test]
    fn source_shelf_sweep_rejects_traversal_and_out_of_root_launcher_source() {
        let scratch = std::env::temp_dir().join(format!(
            "harmonia-source-shelf-sweep-reject-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(scratch.join("source/caduceus_staff")).unwrap();
        fs::create_dir_all(scratch.join("outside")).unwrap();
        fs::create_dir_all(scratch.join("target")).unwrap();
        fs::write(scratch.join("source/caduceus-one"), b"one\n").unwrap();
        let mut request = sweep_test_request(&scratch);
        request.shelf_source = PathBuf::from("../outside");
        assert!(
            source_shelf_sweep(&request, &scratch.join("receipts"), false)
                .unwrap_err()
                .contains("relative-path-rejected")
        );
        request = sweep_test_request(&scratch);
        request.launcher_source_root = scratch.join("outside");
        assert!(
            source_shelf_sweep(&request, &scratch.join("receipts"), false)
                .unwrap_err()
                .contains("launcher-source-root-outside-root")
        );
        request = sweep_test_request(&scratch);
        request.launcher_pattern = "../caduceus-*".into();
        assert!(
            source_shelf_sweep(&request, &scratch.join("receipts"), false)
                .unwrap_err()
                .contains("launcher-pattern-rejected")
        );
        let _ = fs::remove_dir_all(&scratch);
    }

    #[cfg(unix)]
    #[test]
    fn source_shelf_sweep_restores_prior_state_after_promotion_failure() {
        let scratch = std::env::temp_dir().join(format!(
            "harmonia-source-shelf-sweep-rollback-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(scratch.join("source/caduceus_staff")).unwrap();
        fs::create_dir_all(scratch.join("target/caduceus_staff")).unwrap();
        fs::write(
            scratch.join("source/caduceus_staff/module.py"),
            b"new shelf\n",
        )
        .unwrap();
        fs::write(scratch.join("source/caduceus-current"), b"new launcher\n").unwrap();
        fs::write(
            scratch.join("target/caduceus_staff/module.py"),
            b"old shelf\n",
        )
        .unwrap();
        fs::write(scratch.join("target/caduceus-current"), b"old launcher\n").unwrap();
        fs::write(scratch.join("target/caduceus-stale"), b"stale launcher\n").unwrap();
        let request = sweep_test_request(&scratch);
        let receipts = scratch.join("receipts");

        let setup_error = source_shelf_sweep_with_fault(
            &request,
            &receipts,
            true,
            SourceShelfSweepFault {
                fail_setup_after_stage: true,
                ..SourceShelfSweepFault::default()
            },
        )
        .unwrap_err();
        assert!(setup_error.contains("injected-setup-failure"));
        assert!(setup_error.contains("setup residue removed"));
        let setup_receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(receipts.join("source-shelf-sweep.json")).unwrap())
                .unwrap();
        assert_eq!(setup_receipt["transaction_state"], "setup-failed-cleaned");
        assert_eq!(setup_receipt["rollback_state"], "restored");
        assert!(fs::read_dir(scratch.join("target")).unwrap().all(|entry| {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            !name.contains("harmonia-stage") && !name.starts_with(".harmonia-source-shelf-sweep-")
        }));

        let error = source_shelf_sweep_with_fault(
            &request,
            &receipts,
            true,
            SourceShelfSweepFault {
                fail_after_promotions: Some(1),
                ..SourceShelfSweepFault::default()
            },
        )
        .unwrap_err();
        assert!(error.contains("injected-promotion-failure"));
        assert!(error.contains("prior state restored"));
        assert_eq!(
            fs::read(scratch.join("target/caduceus_staff/module.py")).unwrap(),
            b"old shelf\n"
        );
        assert_eq!(
            fs::read(scratch.join("target/caduceus-current")).unwrap(),
            b"old launcher\n"
        );
        assert_eq!(
            fs::read(scratch.join("target/caduceus-stale")).unwrap(),
            b"stale launcher\n"
        );
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(receipts.join("source-shelf-sweep.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["transaction_state"], "rolled-back");
        assert_eq!(receipt["rollback_state"], "restored");
        assert_eq!(
            receipt["first_blocker"],
            "source-shelf-sweep-injected-promotion-failure"
        );

        let cleanup_error = source_shelf_sweep_with_fault(
            &request,
            &receipts,
            true,
            SourceShelfSweepFault {
                fail_cleanup: true,
                ..SourceShelfSweepFault::default()
            },
        )
        .unwrap_err();
        assert!(cleanup_error.contains("cleanup debt"));
        let cleanup_receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(receipts.join("source-shelf-sweep.json")).unwrap())
                .unwrap();
        assert_eq!(cleanup_receipt["ok"], false);
        assert_eq!(cleanup_receipt["current"], true);
        assert_eq!(
            cleanup_receipt["transaction_state"],
            "committed-cleanup-debt"
        );
        assert_eq!(
            cleanup_receipt["first_blocker"],
            "source-shelf-sweep-injected-cleanup-failure"
        );
        assert_eq!(
            cleanup_receipt["receipt_write_contract"],
            "same-directory temp write, file fsync, atomic rename, parent-directory fsync"
        );
        assert_eq!(
            fs::read(scratch.join("target/caduceus_staff/module.py")).unwrap(),
            b"new shelf\n"
        );
        let _ = fs::remove_dir_all(&scratch);
    }
}
