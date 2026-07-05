use super::{ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

pub const NAME: &str = "files";
pub const DESCRIPTION: &str =
    "Staged file/template/directory/symlink primitive with atomic promotion.";
pub const PERMUTATIONS: &[ToolPermutation] = &[
    ToolPermutation::new(
        "managed-files",
        "converge managed file declarations from typed JSON",
        &[ToolArg::optional("files", ToolArgKind::Json)],
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileConvergenceOutcome {
    pub ok: bool,
    pub changed: bool,
    pub checked: usize,
    pub written: usize,
    pub backed_up: usize,
    pub missing: Vec<String>,
    pub entries: Vec<FileConvergenceEntry>,
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
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let mut missing = Vec::new();
    let mut written = Vec::new();
    let mut changed = false;
    let mut entries = Vec::new();
    for file in request.files {
        let path = PathBuf::from(&file.path);
        let existing = fs::read(&path).ok();
        let desired = file.content.as_bytes();
        let content_equal = existing.as_deref() == Some(desired);
        let mode = file.mode.unwrap_or(0o644);
        let mode_equal = path.exists() && target_mode(&path)? == Some(mode);
        let file_changed = !content_equal || !mode_equal;
        if file_changed {
            if apply {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(|e| {
                        format!("managed-file-parent-failed {}: {e}", parent.display())
                    })?;
                }
                atomic_write_bytes(&path, desired, Some(mode))?;
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
        let entry_changed = !target_exists_before || !content_equal_before || !mode_equal_before;
        let mut backed_up_to = None;

        if apply && entry_changed {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    format!(
                        "files-converge-target-parent-create-failed {}: {e}",
                        parent.display()
                    )
                })?;
            }
            if target_exists_before && request.backup_existing {
                let backup = backup_target(&target, receipt_dir, &spec.relative_path)?;
                backed_up_to = Some(backup);
                backed_up += 1;
            }
            if let Err(signal) = atomic_copy(&source, &target, final_mode) {
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
            written += 1;
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
        if apply && (!target_exists_after || !content_equal_after || !mode_equal_after) {
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
        });
    }

    let ok = missing.is_empty();
    let changed = entries.iter().any(|entry| entry.changed);
    let outcome = FileConvergenceOutcome {
        ok,
        changed,
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
fn file_mode(path: &Path) -> Result<u32, String> {
    Ok(fs::metadata(path)
        .map_err(|e| format!("files-metadata-failed {}: {e}", path.display()))?
        .permissions()
        .mode()
        & 0o777)
}

#[cfg(not(unix))]
fn file_mode(_path: &Path) -> Result<u32, String> {
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

fn atomic_write_bytes(target: &Path, bytes: &[u8], mode: Option<u32>) -> Result<(), String> {
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
    fs::rename(&temp, target).map_err(|e| {
        format!(
            "files-atomic-promote-failed {} -> {}: {e}",
            temp.display(),
            target.display()
        )
    })?;
    Ok(())
}

fn atomic_copy(source: &Path, target: &Path, mode: Option<u32>) -> Result<(), String> {
    let bytes = fs::read(source)
        .map_err(|e| format!("files-source-read-failed {}: {e}", source.display()))?;
    atomic_write_bytes(target, &bytes, mode)
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
        "checked": outcome.checked,
        "written": outcome.written,
        "backed_up": outcome.backed_up,
        "changed": outcome.changed,
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
