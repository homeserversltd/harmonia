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
    let mut validator = crate::CmdResult { ok: true, code: 0, stdout: "not-run".into(), stderr: String::new() };
    let mut reload = None;
    let mut promoted = false;
    let mut signal = "none".to_string();
    if !source_ok { signal = "validated-symlink-source-missing".into(); }
    else if !current && apply {
        let parent = target.parent().ok_or_else(|| "validated-symlink-target-parent-missing".to_string())?;
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        if target.exists() && !target.is_symlink() { signal = "validated-symlink-target-not-link".into(); }
        else {
            let candidate = parent.join(format!(".{}.harmonia-candidate-{}", target.file_name().and_then(|v| v.to_str()).unwrap_or("link"), std::process::id()));
            let _ = fs::remove_file(&candidate);
            #[cfg(unix)] std::os::unix::fs::symlink(source, &candidate).map_err(|e| e.to_string())?;
            #[cfg(not(unix))] return Err("validated-symlink-unsupported".into());
            let refs: Vec<&str> = validator_args.iter().map(String::as_str).collect();
            validator = crate::tools::command::capture_with_timeout(validator_program, &refs, timeout_secs);
            if validator.ok {
                fs::rename(&candidate, target).map_err(|e| e.to_string())?;
                promoted = true;
                if let Some(program) = reload_program.filter(|value| !value.is_empty()) {
                    let refs: Vec<&str> = reload_args.iter().map(String::as_str).collect();
                    let result = crate::tools::command::capture_with_timeout(program, &refs, timeout_secs);
                    if !result.ok {
                        if let Some(old) = prior { let _ = fs::remove_file(target); #[cfg(unix)] let _ = std::os::unix::fs::symlink(old, target); }
                        signal = "validated-symlink-reload-failed-restored".into();
                    }
                    reload = Some(result);
                }
            } else { signal = "validated-symlink-validator-failed".into(); let _ = fs::remove_file(candidate); }
        }
    }
    let ok = source_ok && signal == "none" && validator.ok && reload.as_ref().map(|v| v.ok).unwrap_or(true);
    crate::write_json(&receipt_dir.join(format!("{name}.json")), &json!({"schema":"harmonia.files.validated_symlink.v1","source":source,"target":target,"apply":apply,"changed":promoted,"source_exists":source_ok,"link_current_before":current,"validator":validator,"reload":reload,"first_missing_signal":signal,"ok":ok}))?;
    Ok(crate::OperationOutcome { ok, changed: promoted, skipped: !apply, message: "validated symlink".into(), command: None })
}

#[derive(Clone)]
struct SavedFile {
    bytes: Option<Vec<u8>>,
    mode: Option<u32>,
}

fn save_file(path: &Path) -> Result<SavedFile, String> {
    if path.exists() {
        if !path.is_file() {
            return Err(format!("validated-file-symlink-source-not-file {}", path.display()));
        }
        Ok(SavedFile {
            bytes: Some(fs::read(path).map_err(|e| e.to_string())?),
            mode: Some(file_mode(path)?),
        })
    } else {
        Ok(SavedFile { bytes: None, mode: None })
    }
}

fn restore_file(path: &Path, saved: &SavedFile) -> Result<(), String> {
    match &saved.bytes {
        Some(bytes) => atomic_write_bytes(path, bytes, saved.mode),
        None => {
            if path.exists() || path.is_symlink() {
                fs::remove_file(path).map_err(|e| format!("validated-file-symlink-restore-source-remove-failed {}: {e}", path.display()))?;
            }
            Ok(())
        }
    }
}

fn restore_link(path: &Path, saved: &Option<PathBuf>) -> Result<(), String> {
    if path.exists() || path.is_symlink() {
        fs::remove_file(path).map_err(|e| format!("validated-file-symlink-restore-link-remove-failed {}: {e}", path.display()))?;
    }
    if let Some(link) = saved {
        #[cfg(unix)]
        std::os::unix::fs::symlink(link, path)
            .map_err(|e| format!("validated-file-symlink-restore-link-create-failed {}: {e}", path.display()))?;
        #[cfg(not(unix))]
        return Err("validated-file-symlink-unsupported".into());
    }
    Ok(())
}

/// Validates desired bytes through a hidden source candidate and a non-hidden sibling
/// link candidate, so Nginx's `sites-enabled/*` include observes the exact candidate.
pub(crate) fn validated_file_symlink(
    receipt_dir: &Path,
    name: &str,
    desired_source: &Path,
    source: &Path,
    target: &Path,
    validator_program: &str,
    validator_args: &[String],
    reload_program: Option<&str>,
    reload_args: &[String],
    timeout_secs: u64,
    apply: bool,
) -> Result<crate::OperationOutcome, String> {
    let desired = match fs::read(desired_source) {
        Ok(value) => value,
        Err(_) => return write_validated_file_symlink_receipt(receipt_dir, name, apply, false, false, false, false, false, None, None, None, "validated-file-symlink-desired-source-missing"),
    };
    let desired_mode = file_mode(desired_source)?;
    let source_before = save_file(source)?;
    let link_before = fs::read_link(target).ok();
    if (target.exists() || target.is_symlink()) && link_before.is_none() {
        return write_validated_file_symlink_receipt(receipt_dir, name, apply, false, false, false, false, false, None, None, None, "validated-file-symlink-target-not-link");
    }
    let source_current = source_before.bytes.as_deref() == Some(desired.as_slice()) && source_before.mode == Some(desired_mode);
    let link_current = link_before.as_deref() == Some(source);
    if (source_current && link_current) || !apply {
        return write_validated_file_symlink_receipt(receipt_dir, name, apply, true, false, false, false, false, None, None, None, "none");
    }

    let source_parent = source.parent().ok_or_else(|| "validated-file-symlink-source-parent-missing".to_string())?;
    let target_parent = target.parent().ok_or_else(|| "validated-file-symlink-target-parent-missing".to_string())?;
    fs::create_dir_all(source_parent).map_err(|e| e.to_string())?;
    fs::create_dir_all(target_parent).map_err(|e| e.to_string())?;
    let pid = std::process::id();
    let source_candidate = source_parent.join(format!(".{}.harmonia-source-candidate-{pid}", source.file_name().and_then(|v| v.to_str()).unwrap_or("source")));
    let link_candidate = target_parent.join(format!("{}.harmonia-link-candidate-{pid}", target.file_name().and_then(|v| v.to_str()).unwrap_or("link")));
    let clean_candidates = || {
        let _ = fs::remove_file(&source_candidate);
        let _ = fs::remove_file(&link_candidate);
    };
    clean_candidates();
    if let Err(error) = atomic_write_bytes(&source_candidate, &desired, Some(desired_mode)) {
        clean_candidates();
        return write_validated_file_symlink_receipt(receipt_dir, name, apply, false, false, false, false, false, None, None, None, &format!("validated-file-symlink-stage-source-failed: {error}"));
    }
    #[cfg(unix)]
    if let Err(error) = std::os::unix::fs::symlink(&source_candidate, &link_candidate) {
        clean_candidates();
        return write_validated_file_symlink_receipt(receipt_dir, name, apply, false, false, false, false, false, None, None, None, &format!("validated-file-symlink-stage-link-failed: {error}"));
    }
    #[cfg(not(unix))]
    return Err("validated-file-symlink-unsupported".into());

    let validator_refs: Vec<&str> = validator_args.iter().map(String::as_str).collect();
    let validator = crate::tools::command::capture_with_timeout(validator_program, &validator_refs, timeout_secs);
    if !validator.ok {
        clean_candidates();
        return write_validated_file_symlink_receipt(receipt_dir, name, apply, false, true, false, false, false, Some(validator), None, None, "validated-file-symlink-validator-failed");
    }

    let mut source_promoted = false;
    let mut link_promoted = false;
    let mut promotion_error = None;
    if !source_current {
        if let Err(error) = fs::rename(&source_candidate, source) {
            promotion_error = Some(format!("validated-file-symlink-promote-source-failed: {error}"));
        } else {
            source_promoted = true;
        }
    }
    if promotion_error.is_none() && !link_current {
        let _ = fs::remove_file(&link_candidate);
        #[cfg(unix)]
        if let Err(error) = std::os::unix::fs::symlink(source, &link_candidate) {
            promotion_error = Some(format!("validated-file-symlink-restage-live-link-failed: {error}"));
        }
        if promotion_error.is_none() {
            if let Err(error) = fs::rename(&link_candidate, target) {
                promotion_error = Some(format!("validated-file-symlink-promote-link-failed: {error}"));
            } else {
                link_promoted = true;
            }
        }
    }
    if let Some(error) = promotion_error {
        let source_restore = restore_file(source, &source_before);
        let link_restore = restore_link(target, &link_before);
        let restored = source_restore.is_ok() && link_restore.is_ok();
        clean_candidates();
        let signal = if restored { error } else { "validated-file-symlink-restoration-failed".to_string() };
        return write_validated_file_symlink_receipt(receipt_dir, name, apply, false, true, source_promoted, link_promoted, true, Some(validator), None, Some(restored), &signal);
    }
    clean_candidates();

    let mut reconcile = None;
    let mut restored = None;
    let mut ok = true;
    let mut signal = "none";
    if let Some(program) = reload_program.filter(|value| !value.is_empty()) {
        let refs: Vec<&str> = reload_args.iter().map(String::as_str).collect();
        let result = crate::tools::command::capture_with_timeout(program, &refs, timeout_secs);
        if !result.ok {
            let source_restore = restore_file(source, &source_before);
            let link_restore = restore_link(target, &link_before);
            let restoration_ok = source_restore.is_ok() && link_restore.is_ok();
            restored = Some(restoration_ok);
            ok = false;
            signal = if restoration_ok { "validated-file-symlink-reconcile-failed-restored" } else { "validated-file-symlink-restoration-failed" };
        }
        reconcile = Some(result);
    }
    write_validated_file_symlink_receipt(receipt_dir, name, apply, ok, true, source_promoted, link_promoted, restored.is_some(), Some(validator), reconcile, restored, signal)
}

#[allow(clippy::too_many_arguments)]
fn write_validated_file_symlink_receipt(
    receipt_dir: &Path,
    name: &str,
    apply: bool,
    ok: bool,
    validation_ran: bool,
    source_promoted: bool,
    link_promoted: bool,
    restoration_attempted: bool,
    validator: Option<crate::CmdResult>,
    reconcile: Option<crate::CmdResult>,
    restoration_ok: Option<bool>,
    signal: &str,
) -> Result<crate::OperationOutcome, String> {
    let changed = ok && (source_promoted || link_promoted);
    crate::write_json(
        &receipt_dir.join(format!("{name}.json")),
        &json!({
            "schema":"harmonia.files.validated_file_symlink.v1",
            "ok":ok,
            "apply":apply,
            "changed":changed,
            "validation":{"ran":validation_ran,"result":validator},
            "promotion":{"source":source_promoted,"link":link_promoted},
            "reconcile":reconcile,
            "restoration":{"attempted":restoration_attempted,"ok":restoration_ok},
            "first_missing_signal":signal,
        }),
    )?;
    Ok(crate::OperationOutcome { ok, changed, skipped: !apply, message: "validated file symlink".into(), command: None })
}
