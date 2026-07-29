use super::{ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeSet;
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
        std::process::id()
    ));
    {
        let mut file = File::create(&temp)
            .map_err(|e| format!("files-temp-create-failed {}: {e}", temp.display()))?;
        file.write_all(bytes)
            .map_err(|e| format!("files-temp-write-failed {}: {e}", temp.display()))?;
        file.sync_all()
            .map_err(|e| format!("files-temp-sync-failed {}: {e}", temp.display()))?;
    }
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
    Ok(())
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
}
