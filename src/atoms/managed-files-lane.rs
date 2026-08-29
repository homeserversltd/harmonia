// Compatibility names remain seated at their owning primitive do atoms.
pub(crate) type InvocationKey = crate::atoms::r#do::InvocationKey;
pub(crate) type ActionAuthorization = crate::atoms::comparison::ActionAuthorization;
pub(crate) type ChangeModePlan = crate::atoms::r#do::change_mode::Plan;
pub(crate) type ChangeOwnerPlan = crate::atoms::r#do::change_owner::Plan;
pub(crate) type CopyFilePlan = crate::atoms::r#do::copy_file::Plan;
pub(crate) type FileWriteOptions<'a> = crate::atoms::r#do::write_file::FileWriteOptions<'a>;
pub(crate) const PYTHON_RUNTIME_DEBRIS_EXCLUDE: &[&str] = &["__pycache__", "*.pyc", "*.pyo"];
pub(crate) use crate::atoms::r#do::change_mode::change as change_mode;
pub(crate) use crate::atoms::r#do::change_owner::change as change_owner;
pub(crate) use crate::atoms::r#do::copy_file::copy as copy_file;
pub(crate) use crate::atoms::r#do::make_dir::create_dir_all as make_dir;
pub(crate) use crate::atoms::r#do::remove_dir::capture as remove_dir_capture;
pub(crate) fn remove_dir(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    path: &Path,
) -> Result<RemoveDirImage, String> {
    crate::atoms::r#do::remove_dir::operate(authorization, invocation, path, None)
}
pub(crate) use crate::atoms::r#do::backfill_file::{
    converge_managed_directories,
};
pub(crate) use crate::atoms::r#do::remove_dir::remove_authorized as remove_dir_authorized;
pub(crate) use crate::atoms::r#do::remove_dir::replace_authorized as remove_dir_replace;
pub(crate) use crate::atoms::r#do::remove_file::remove_file;
pub(crate) use crate::atoms::r#do::write_file::file_write;

pub(crate) type RemoveDirImage = crate::atoms::r#do::remove_dir::Image;
pub(crate) type RemoveDirKind = crate::atoms::r#do::remove_dir::Kind;

pub(crate) fn remove_dir_exact(left: &RemoveDirImage, right: &RemoveDirImage) -> bool {
    crate::atoms::r#do::remove_dir::exact(left, right)
}

use serde::{Deserialize, Serialize};
use serde_json::json;
use similar::TextDiff;
use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::ffi::CString;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::path::{Component, Path, PathBuf};

const NAME: &str = "files";

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

/// Classification is performed at the shared file membrane, before any
/// observation is promoted to an actuator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TargetClass {
    Software,
    Config,
    Refused(String),
}

pub(crate) fn is_protected_path(path: &Path) -> bool {
    let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("");
    name.starts_with("id_")
        || name.ends_with(".pem")
        || name.ends_with(".key")
        || name.ends_with(".p12")
        || name.ends_with(".pfx")
        || path.components().any(|component| {
            matches!(component,
            Component::Normal(value) if matches!(value.to_str(), Some(".ssh") | Some("key") |
            Some("keys") | Some("private") | Some("credentials") | Some("secrets")))
        })
}

/// Classify a routine file target at the final membrane immediately before
/// dispatching a file actuator.
pub(crate) fn authorize_routine_target(path: &Path, apply: bool) -> Result<TargetClass, String> {
    let class = classify_target(path);
    match (&class, apply) {
        (TargetClass::Refused(reason), _) => Err(reason.clone()),
        (TargetClass::Config, true) => Err(format!(
            "configuration-actuator-authority-refused {}",
            path.display()
        )),
        _ => Ok(class),
    }
}

pub(crate) fn classify_target(path: &Path) -> TargetClass {
    if is_protected_path(path) {
        return TargetClass::Refused(format!("credential-boundary-refused {}", path.display()));
    }
    let text = path.to_string_lossy();
    if text == "/etc"
        || text.starts_with("/etc/")
        || text == "/home"
        || text.starts_with("/home/")
        || text == "/root"
        || text.starts_with("/root/")
        || text == "$HOME"
        || text.starts_with("$HOME/")
        || text.contains("config_deploy:interactable")
    {
        TargetClass::Config
    } else {
        TargetClass::Software
    }
}

pub(crate) fn classify_request(
    request: &FileConvergenceRequest,
) -> Result<Vec<TargetClass>, String> {
    request
        .files
        .iter()
        .map(
            |file| match classify_target(&request.target_root.join(&file.relative_path)) {
                TargetClass::Refused(reason) => Err(reason),
                class => Ok(class),
            },
        )
        .collect()
}

fn validate_hotfix_target(target: &Path) -> Result<(), String> {
    let home_dotfile = target.starts_with("/home")
        && target.components().any(|part| {
            matches!(part, Component::Normal(value) if value.to_string_lossy().starts_with('.'))
        });
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let key_material = file_name.starts_with("id_")
        || file_name.ends_with(".key")
        || file_name.ends_with(".pem")
        || file_name.ends_with(".p12")
        || file_name.ends_with(".pfx")
        || target.components().any(|part| {
            matches!(part, Component::Normal(value) if matches!(value.to_str(), Some("key") | Some("keys") | Some("private") | Some("credentials") | Some("secrets")))
        });
    let account_or_operator_setting = matches!(
        target.to_str(),
        Some("/etc/passwd" | "/etc/shadow" | "/etc/group" | "/etc/gshadow" | "/etc/sudoers")
    );
    let homeserver_configuration = matches!(
        target.to_str(),
        Some("/etc/homeserver/config.json" | "/etc/homeserver.json")
    ) || target.starts_with("/var/www/homeserver");
    if !target.is_absolute()
        || target
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        || target.starts_with("/root")
        || home_dotfile
        || file_name == "authorized_keys"
        || key_material
        || account_or_operator_setting
        || homeserver_configuration
    {
        return Err(format!(
            "hotfix-target-identity-or-config-wall {}",
            target.display()
        ));
    }
    reject_ssh_path(target)
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_omitted: Option<String>,
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
    pub missing_target_birth_debts: Vec<String>,
    pub entries: Vec<FileConvergenceEntry>,
    pub message: String,
}

const UNIFIED_DIFF_BYTE_LIMIT: usize = 256 * 1024;

#[derive(Debug, Clone, Default)]
pub(crate) struct UnifiedFileDiff {
    pub(crate) text: Option<String>,
    pub(crate) omitted: Option<String>,
}

pub(crate) fn unified_file_diff(source: &Path, target: &Path) -> Result<UnifiedFileDiff, String> {
    let declared = fs::read(source)
        .map_err(|error| format!("files-source-read-failed {}: {error}", source.display()))?;
    let current = match fs::read(target) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => {
            return Err(format!(
                "files-target-read-failed {}: {error}",
                target.display()
            ));
        }
    };
    if current.len() > UNIFIED_DIFF_BYTE_LIMIT || declared.len() > UNIFIED_DIFF_BYTE_LIMIT {
        return Ok(UnifiedFileDiff {
            text: None,
            omitted: Some(format!(
                "too-large: {} -> {}",
                human_byte_size(current.len()),
                human_byte_size(declared.len())
            )),
        });
    }
    let Ok(current) = String::from_utf8(current) else {
        return Ok(UnifiedFileDiff {
            text: None,
            omitted: Some("binary".to_string()),
        });
    };
    let Ok(declared) = String::from_utf8(declared) else {
        return Ok(UnifiedFileDiff {
            text: None,
            omitted: Some("binary".to_string()),
        });
    };
    Ok(UnifiedFileDiff {
        text: Some(
            TextDiff::from_lines(&current, &declared)
                .unified_diff()
                .context_radius(3)
                .header("current", "declared")
                .to_string(),
        ),
        omitted: None,
    })
}

fn human_byte_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else {
        format!("{:.1}KiB", bytes as f64 / 1024.0)
    }
}

pub(crate) fn write_unified_diff_receipt(
    receipt_dir: &Path,
    receipt_name: &str,
    relative_path: &str,
    diff: &str,
) -> Result<(), String> {
    let safe_path = relative_path.replace('/', "_").replace('\\', "_");
    let stem = receipt_name.trim_end_matches(".json");
    crate::atoms::attest::prepare_receipt_parent(receipt_dir).map_err(|error| {
        format!(
            "files-diff-receipt-directory-create-failed {}: {error}",
            receipt_dir.display()
        )
    })?;
    let path = receipt_dir.join(format!("{stem}-{safe_path}.diff"));
    crate::atoms::attest::write_bytes_atomic(&path, diff.as_bytes()).map_err(|error| {
        format!(
            "files-diff-receipt-write-failed {}: {error}",
            path.display()
        )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymlinkSourceKind {
    RegularExecutable,
}

impl SymlinkSourceKind {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "regular-executable" => Ok(Self::RegularExecutable),
            other => Err(format!("symlink-converge-source-kind-unsupported {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymlinkConflictPolicy {
    RefuseNonSymlink,
    ReplaceRegularFile,
    ReplaceEmptyDirectory,
}

impl SymlinkConflictPolicy {
    fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.unwrap_or("refuse-non-symlink") {
            "refuse-non-symlink" => Ok(Self::RefuseNonSymlink),
            "replace-regular-file" => Ok(Self::ReplaceRegularFile),
            "replace-empty-directory" => Ok(Self::ReplaceEmptyDirectory),
            other => Err(format!(
                "symlink-converge-conflict-policy-unsupported {other}"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymlinkConvergeRequest {
    pub source: PathBuf,
    pub target: PathBuf,
    pub required_source_kind: SymlinkSourceKind,
    pub conflict_policy: SymlinkConflictPolicy,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub receipt_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SymlinkPathIdentity {
    pub kind: String,
    pub link_target: Option<PathBuf>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub device: Option<u64>,
    pub inode: Option<u64>,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SymlinkSourceIdentity {
    pub kind: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub change_seconds: i64,
    pub change_nanoseconds: i64,
}

pub(crate) fn validate_symlink_converge_args(
    args: &BTreeMap<String, serde_json::Value>,
) -> Result<(), String> {
    let source = Path::new(
        args.get("source")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
    );
    let target = Path::new(
        args.get("target")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
    );
    for (label, path) in [("source", source), ("target", target)] {
        if !path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(format!("symlink-converge-{label}-path-invalid"));
        }
    }
    if source == target {
        return Err("symlink-converge-source-target-identical".to_string());
    }
    for field in ["owner", "group"] {
        if args
            .get(field)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(format!("symlink-converge-{field}-empty"));
        }
    }
    reject_ssh_path(target)?;
    SymlinkSourceKind::parse(
        args.get("required_source_kind")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
    )?;
    SymlinkConflictPolicy::parse(
        args.get("conflict_policy")
            .and_then(serde_json::Value::as_str),
    )?;
    Ok(())
}

pub const SYSTEM_EXECUTABLE_PATHS: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    // Debian places systemd's service binaries outside PATH; they remain a
    // kernel-owned system executable surface and must be discoverable here.
    "/usr/lib/systemd",
    "/lib/systemd",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutableSearchScope {
    System,
}

impl ExecutableSearchScope {
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.unwrap_or("system") {
            "system" => Ok(Self::System),
            other => Err(format!("executable-search-scope-unsupported {other}")),
        }
    }

    fn paths(self) -> Vec<PathBuf> {
        match self {
            Self::System => SYSTEM_EXECUTABLE_PATHS.iter().map(PathBuf::from).collect(),
        }
    }
}

pub(crate) fn validate_executable_present_args(
    args: &BTreeMap<String, serde_json::Value>,
) -> Result<(), String> {
    let executable = args
        .get("executable")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    validate_executable_name(executable)?;
    ExecutableSearchScope::parse(args.get("search_scope").and_then(serde_json::Value::as_str))?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutablePresentRequest {
    pub executable: String,
    pub search_scope: ExecutableSearchScope,
    pub receipt_name: String,
    pub receipt_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecutableMetadata {
    pub candidate_path: PathBuf,
    pub resolved_path: Option<PathBuf>,
    pub path_kind: String,
    pub target_kind: String,
    pub symlink_target: Option<PathBuf>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub executable_for_effective_context: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecutablePresentOutcome {
    pub ok: bool,
    pub changed: bool,
    pub executable: String,
    pub search_scope: ExecutableSearchScope,
    pub search_order: Vec<PathBuf>,
    pub resolved_path: Option<PathBuf>,
    pub metadata: Option<ExecutableMetadata>,
    pub inspected: Vec<ExecutableMetadata>,
    pub first_blocker: String,
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
pub(crate) struct ManagedDirectorySpec {
    pub path: String,
    pub mode: u32,
    pub owner: String,
    pub group: String,
}

pub(crate) fn resolve_uid(value: &str) -> Result<u32, String> {
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
pub(crate) fn resolve_uid(value: &str) -> Result<u32, String> {
    Err(format!("managed-file-owner-unsupported {value}"))
}

#[cfg(unix)]
pub(crate) fn resolve_gid(value: &str) -> Result<u32, String> {
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
pub(crate) fn resolve_gid(value: &str) -> Result<u32, String> {
    Err(format!("managed-file-group-unsupported {value}"))
}

#[cfg(unix)]
pub(crate) fn ownership_equal(
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
pub(crate) fn ownership_equal(
    _path: &Path,
    _desired_uid: Option<u32>,
    _desired_gid: Option<u32>,
) -> Result<(bool, bool), String> {
    Ok((true, true))
}

pub(crate) use crate::atoms::r#do::backfill_file::ensure_files_present_with_invocation;
pub(crate) use crate::atoms::r#do::place_file::{
    converge_files_authorized, converge_files_authorized_with_config_policy,
};

fn validate_executable_name(executable: &str) -> Result<(), String> {
    let path = Path::new(executable);
    let is_bare_name = !executable.contains('/')
        && !executable.contains('\\')
        && path.components().count() == 1
        && !matches!(executable, "." | "..");
    let is_absolute_path = path.is_absolute()
        && !executable.contains('\\')
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir));
    if executable.is_empty() || !(is_bare_name || is_absolute_path) {
        return Err(format!("executable-name-rejected {executable:?}"));
    }
    Ok(())
}

#[cfg(unix)]
fn executable_for_effective_context(path: &Path) -> Result<bool, String> {
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("executable-path-invalid {}", path.display()))?;
    let result = unsafe {
        libc::faccessat(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            libc::X_OK,
            libc::AT_EACCESS,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(libc::EACCES) | Some(libc::ENOENT) | Some(libc::ENOTDIR)
    ) {
        Ok(false)
    } else {
        Err(format!(
            "executable-access-check-failed {}: {error}",
            path.display()
        ))
    }
}

#[cfg(not(unix))]
fn executable_for_effective_context(_path: &Path) -> Result<bool, String> {
    Err("executable-effective-context-check-unsupported".into())
}

fn executable_metadata(candidate: &Path) -> Result<ExecutableMetadata, String> {
    let link_metadata = fs::symlink_metadata(candidate).map_err(|error| {
        format!(
            "executable-candidate-metadata-failed {}: {error}",
            candidate.display()
        )
    })?;
    let is_symlink = link_metadata.file_type().is_symlink();
    let symlink_target = if is_symlink {
        Some(fs::read_link(candidate).map_err(|error| {
            format!(
                "executable-symlink-read-failed {}: {error}",
                candidate.display()
            )
        })?)
    } else {
        None
    };
    let resolved_path = candidate.canonicalize().ok();
    let target_metadata = resolved_path
        .as_deref()
        .and_then(|path| fs::metadata(path).ok());
    let target_regular = target_metadata
        .as_ref()
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false);
    let executable = if target_regular {
        executable_for_effective_context(candidate)?
    } else {
        false
    };
    #[cfg(unix)]
    let (mode, uid, gid) = target_metadata
        .as_ref()
        .map(|metadata| {
            (
                Some(metadata.permissions().mode() & 0o777),
                Some(metadata.uid()),
                Some(metadata.gid()),
            )
        })
        .unwrap_or((None, None, None));
    #[cfg(not(unix))]
    let (mode, uid, gid) = (None, None, None);
    Ok(ExecutableMetadata {
        candidate_path: candidate.to_path_buf(),
        resolved_path,
        path_kind: if is_symlink {
            "symlink"
        } else if link_metadata.file_type().is_file() {
            "regular-file"
        } else {
            "non-regular"
        }
        .into(),
        target_kind: if target_regular {
            "regular-file"
        } else if target_metadata.is_some() {
            "non-regular"
        } else {
            "unresolved"
        }
        .into(),
        symlink_target,
        mode,
        uid,
        gid,
        size: target_metadata.as_ref().map(|metadata| metadata.len()),
        executable_for_effective_context: executable,
    })
}

fn executable_present_in_paths(
    request: &ExecutablePresentRequest,
    search_order: Vec<PathBuf>,
    receipt_dir: &Path,
) -> Result<ExecutablePresentOutcome, String> {
    validate_executable_name(&request.executable)?;
    validate_receipt_name(&request.receipt_name)?;
    let mut inspected = Vec::new();
    let mut selected = None;
    for root in &search_order {
        if !root.is_absolute() {
            return Err(format!(
                "executable-search-root-not-absolute {}",
                root.display()
            ));
        }
        let candidate = root.join(&request.executable);
        match fs::symlink_metadata(&candidate) {
            Ok(_) => {
                let metadata = executable_metadata(&candidate)?;
                if metadata.target_kind == "regular-file"
                    && metadata.executable_for_effective_context
                {
                    selected = Some(metadata.clone());
                    inspected.push(metadata);
                    break;
                }
                inspected.push(metadata);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "executable-candidate-metadata-failed {}: {error}",
                    candidate.display()
                ));
            }
        }
    }
    let first_blocker = if selected.is_some() {
        "none"
    } else if inspected.is_empty() {
        "executable-not-found"
    } else {
        "executable-not-runnable"
    }
    .to_string();
    let outcome = ExecutablePresentOutcome {
        ok: selected.is_some(),
        changed: false,
        executable: request.executable.clone(),
        search_scope: request.search_scope,
        search_order,
        resolved_path: selected
            .as_ref()
            .and_then(|metadata| metadata.resolved_path.clone()),
        metadata: selected,
        inspected,
        first_blocker: first_blocker.clone(),
        message: if first_blocker == "none" {
            format!("executable {} is runnable", request.executable)
        } else {
            format!("{first_blocker} {}", request.executable)
        },
    };
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
    let receipt_name = if request.receipt_name.ends_with(".json") {
        request.receipt_name.clone()
    } else {
        format!("{}.json", request.receipt_name)
    };
    crate::atoms::attest::write_json_atomic(
        &receipt_dir.join(receipt_name),
        &json!({
            "schema": "harmonia.files.executable_present.v1",
            "ok": outcome.ok,
            "changed": false,
            "evidence_only": true,
            "executable": outcome.executable,
            "search_scope": outcome.search_scope,
            "search_order": outcome.search_order,
            "receipt_label": request.receipt_label,
            "resolved_path": outcome.resolved_path,
            "metadata": outcome.metadata,
            "inspected": outcome.inspected,
            "first_missing_signal": outcome.first_blocker,
        }),
    )?;
    Ok(outcome)
}

pub fn executable_present(
    request: &ExecutablePresentRequest,
    receipt_dir: &Path,
) -> Result<ExecutablePresentOutcome, String> {
    executable_present_in_paths(request, request.search_scope.paths(), receipt_dir)
}

pub(crate) use crate::atoms::r#do::remove_file_organ::remove_declared_files;

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

pub(crate) fn validate_source_shelf_relative_path(path: &Path) -> Result<(), String> {
    if path == Path::new(".") {
        return Ok(());
    }
    validate_relative_path(path)?;
    if path
        .to_string_lossy()
        .split(std::path::MAIN_SEPARATOR)
        .any(|component| component == ".")
    {
        return Err(format!("files-relative-path-rejected {}", path.display()));
    }
    Ok(())
}

pub(crate) fn reject_ssh_path(path: &Path) -> Result<(), String> {
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

pub(crate) fn validate_interactable_target(path: &Path) -> Result<(), String> {
    if is_protected_path(path) {
        return Err(format!(
            "credential-boundary-refused: {} is key-shaped, Harmonia never hard-stamps credential material",
            path.display()
        ));
    }
    Ok(())
}

pub(crate) use crate::atoms::r#do::place_file::hard_stamp_interactable;

pub(crate) fn validate_specs(specs: &[FileSpec]) -> Result<(), String> {
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

pub(crate) fn validate_receipt_name(receipt_name: &str) -> Result<(), String> {
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

pub(crate) fn source_mode(path: &Path) -> Result<u32, String> {
    file_mode(path)
}

pub(crate) fn target_mode(path: &Path) -> Result<Option<u32>, String> {
    if path.exists() {
        Ok(Some(file_mode(path)?))
    } else {
        Ok(None)
    }
}

#[cfg(unix)]
pub(crate) fn observed_ownership(path: &Path) -> Result<(Option<u32>, Option<u32>), String> {
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
pub(crate) fn observed_ownership(_path: &Path) -> Result<(Option<u32>, Option<u32>), String> {
    Ok((None, None))
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

pub(crate) fn same_file_bytes(source: &Path, target: &Path) -> Result<bool, String> {
    let source_bytes = fs::read(source)
        .map_err(|e| format!("files-source-read-failed {}: {e}", source.display()))?;
    let target_bytes = fs::read(target)
        .map_err(|e| format!("files-target-read-failed {}: {e}", target.display()))?;
    Ok(source_bytes == target_bytes)
}

pub(crate) fn write_partial_failure_receipt(
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
        missing_target_birth_debts: Vec::new(),
        entries: entries.to_vec(),
        message: signal.to_string(),
    };
    write_convergence_receipt(receipt_dir, request, &outcome, apply, false)
}

fn convergence_entry_receipt(
    entry: &FileConvergenceEntry,
    apply: bool,
    held: bool,
) -> serde_json::Value {
    let mut receipt = serde_json::to_value(entry).expect("file convergence entry serializes");
    let object = receipt
        .as_object_mut()
        .expect("file convergence entry serializes to an object");
    let exact_before = entry.source_exists
        && entry.target_exists_before
        && entry.content_equal_before
        && entry.mode_equal_before
        && !entry.ownership_changed;
    let diff_decision = if exact_before { "empty" } else { "different" };
    let movement = if !apply {
        "none"
    } else if entry.changed {
        if entry.backed_up_to.is_some() || !entry.content_equal_before || !entry.mode_equal_before {
            "backup-and-atomic-copy"
        } else {
            "chown"
        }
    } else if diff_decision == "different" {
        "report-only"
    } else {
        "none"
    };
    object.insert(
        "observed_state".into(),
        json!({
            "source_exists": entry.source_exists,
            "target_exists": entry.target_exists_before,
            "content_equal": entry.content_equal_before,
            "mode_equal": entry.mode_equal_before,
            "uid": entry.observed_uid_before,
            "gid": entry.observed_gid_before,
        }),
    );
    object.insert(
        "desired_state".into(),
        json!({"mode": entry.final_mode, "ownership_source": entry.ownership_source}),
    );
    object.insert("diff_decision".into(), json!(diff_decision));
    object.insert("movement".into(), json!(movement));
    object.insert("truthful_changed".into(), json!(apply && entry.changed));
    object.insert(
        "ok".into(),
        json!(
            held || (entry.source_exists
                && if apply {
                    entry.target_exists_after && entry.content_equal_after && entry.mode_equal_after
                } else {
                    entry.target_exists_before
                })
        ),
    );
    if held {
        object.insert("state".into(), json!("held/authority-refused"));
    }
    receipt
}

pub(crate) fn write_convergence_receipt(
    receipt_dir: &Path,
    request: &FileConvergenceRequest,
    outcome: &FileConvergenceOutcome,
    apply: bool,
    held: bool,
) -> Result<(), String> {
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
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
        "changed": apply && outcome.changed,
        "ownership_changed": apply && outcome.ownership_changed,
        "missing": outcome.missing,
        "missing_target_birth_debts": outcome.missing_target_birth_debts,
        "state": if held { "held/authority-refused" } else if outcome.ok { "converged" } else { "incomplete" },
        "entries": outcome.entries.iter().map(|entry| convergence_entry_receipt(entry, apply, held)).collect::<Vec<_>>(),
        "first_missing_signal": if held { "authority-refused" } else if outcome.ok { "none" } else if !outcome.missing_target_birth_debts.is_empty() { "missing-target-birth-debt" } else if outcome.missing.is_empty() { outcome.message.as_str() } else { "files-convergence-source-incomplete" },
    });
    let mut receipt_name = request.receipt_name.clone();
    if receipt_name.is_empty() {
        receipt_name = "files-converge".to_string();
    }
    if !receipt_name.ends_with(".json") {
        receipt_name.push_str(".json");
    }
    let path = receipt_dir.join(receipt_name);
    crate::atoms::attest::write_json_atomic(&path, &receipt)
        .map_err(|e| format!("files-receipt-write-failed {}: {e}", path.display()))
}

#[cfg(test)]
mod source_shelf_sweep_tests {
    use super::*;
    use crate::atoms::r#do::source_shelf::{SourceShelfSweepRequest, source_shelf_sweep};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_sweep_nonce() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        format!("{}-{nanos}", std::process::id())
    }

    fn request(
        source_root: &Path,
        target_shelf: &Path,
        mode: u32,
        provenance_state: &Path,
    ) -> SourceShelfSweepRequest {
        let metadata = fs::symlink_metadata(target_shelf).unwrap();
        let owner = metadata.uid().to_string();
        let group = metadata.gid().to_string();
        SourceShelfSweepRequest {
            source_root: source_root.to_path_buf(),
            shelf_source: PathBuf::from("agathodaimon"),
            target_shelf: target_shelf.to_path_buf(),
            launcher_source_root: source_root.to_path_buf(),
            launcher_target_root: target_shelf.parent().unwrap().to_path_buf(),
            launcher_pattern: ".harmonia-no-flat-launchers".into(),
            shelf_owner: owner,
            shelf_group: group,
            shelf_directory_mode: mode,
            shelf_file_mode: 0o644,
            launcher_mode: 0o755,
            prune: false,
            launcher_exclude: Vec::new(),
            provenance_state: Some(provenance_state.to_path_buf()),
            owned_recursive: true,
            receipt_name: "test".into(),
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn owned_recursive_apply_converges_root_and_reads_receipts() {
        let root =
            std::env::temp_dir().join(format!("harmonia-shelf-root-apply-{}", test_sweep_nonce()));
        let source_root = root.join("source");
        let source = source_root.join("agathodaimon");
        let target = root.join("target/agathodaimon");
        let receipts = root.join("receipts");
        let provenance = root.join("state/provenance.json");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let request = request(&source_root, &target, 0o755, &provenance);
        let outcome = source_shelf_sweep(
            &request,
            &receipts,
            true,
            Some(&crate::atoms::r#do::InvocationKey::for_apply()),
        )
        .unwrap();
        assert_eq!(mode(&target), 0o755);
        assert!(outcome.ok);
        assert!(outcome.changed);
        assert_eq!(outcome.promoted_count, 1);
        let root_entry = outcome
            .entries
            .iter()
            .find(|entry| entry.relative_path == ".")
            .unwrap();
        assert_eq!(root_entry.before_mode, Some(0o700));
        assert_eq!(root_entry.after_mode, Some(0o755));
        assert_eq!(root_entry.action, "promoted");
        assert!(root_entry.changed);
        assert!(root_entry.readback_ok);

        let transaction: serde_json::Value =
            serde_json::from_slice(&fs::read(receipts.join("test.json")).unwrap()).unwrap();
        assert_eq!(transaction["changed"], true);
        assert_eq!(transaction["promoted_count"], 1);
        assert_eq!(transaction["entries"][0]["relative_path"], ".");
        assert_eq!(transaction["entries"][0]["before_mode"], 0o700);
        assert_eq!(transaction["entries"][0]["after_mode"], 0o755);
        assert_eq!(transaction["entries"][0]["action"], "promoted");
        assert_eq!(transaction["entries"][0]["readback_ok"], true);

        let entry_receipt = fs::read_dir(&receipts)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.file_name().unwrap() != "test.json")
            .unwrap();
        let entry_receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(entry_receipt).unwrap()).unwrap();
        assert_eq!(entry_receipt["entry"]["relative_path"], ".");
        assert_eq!(entry_receipt["entry"]["before_mode"], 0o700);
        assert_eq!(entry_receipt["entry"]["after_mode"], 0o755);
        assert_eq!(entry_receipt["movement"], "promoted");
        assert_eq!(entry_receipt["truthful_changed"], true);
        assert_eq!(entry_receipt["entry"]["readback_ok"], true);
        assert!(provenance.exists());
        let provenance_json: serde_json::Value =
            serde_json::from_slice(&fs::read(&provenance).unwrap()).unwrap();
        let provenance_paths = provenance_json["paths"].as_array().unwrap();
        let target_string = target.display().to_string();
        let dot_target_string = target.join(".").display().to_string();
        assert!(provenance_paths.iter().any(|path| path == &target_string));
        assert!(!provenance_paths
            .iter()
            .any(|path| path == &dot_target_string));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn owned_recursive_apply_empty_diff_does_not_mutate_target_or_provenance() {
        let root =
            std::env::temp_dir().join(format!("harmonia-shelf-root-empty-{}", test_sweep_nonce()));
        let source_root = root.join("source");
        let source = source_root.join("agathodaimon");
        let target = root.join("target/agathodaimon");
        let receipts = root.join("receipts");
        let provenance = root.join("state/provenance.json");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        let request = request(&source_root, &target, 0o755, &provenance);
        let before_meta = fs::symlink_metadata(&target).unwrap();
        let before_children: Vec<_> = fs::read_dir(&target)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        let outcome = source_shelf_sweep(
            &request,
            &receipts,
            true,
            Some(&crate::atoms::r#do::InvocationKey::for_apply()),
        )
        .unwrap();
        assert!(outcome.ok);
        assert!(!outcome.changed);
        assert_eq!(outcome.promoted_count, 0);
        let root_entry = outcome
            .entries
            .iter()
            .find(|entry| entry.relative_path == ".")
            .unwrap();
        assert_eq!(root_entry.before_mode, Some(0o755));
        assert_eq!(root_entry.after_mode, Some(0o755));
        assert_eq!(root_entry.action, "unchanged");
        assert!(!root_entry.changed);
        assert!(root_entry.readback_ok);
        let after_meta = fs::symlink_metadata(&target).unwrap();
        let after_children: Vec<_> = fs::read_dir(&target)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(before_meta.mode(), after_meta.mode());
        assert_eq!(before_meta.uid(), after_meta.uid());
        assert_eq!(before_meta.gid(), after_meta.gid());
        assert_eq!(before_children, after_children);
        assert!(!provenance.exists());
        let transaction: serde_json::Value =
            serde_json::from_slice(&fs::read(receipts.join("test.json")).unwrap()).unwrap();
        assert_eq!(transaction["changed"], false);
        assert_eq!(transaction["promoted_count"], 0);
        assert_eq!(transaction["entries"][0]["relative_path"], ".");
        assert_eq!(transaction["entries"][0]["action"], "unchanged");
        assert_eq!(transaction["entries"][0]["changed"], false);
        fs::remove_dir_all(root).unwrap();
    }
}
