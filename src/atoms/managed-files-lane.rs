// Operation-semantic actuator seats owned by the files tool. These delegations
// preserve the atom APIs without coupling callers to a specific band.
pub(crate) type InvocationKey = crate::atoms::r#do::InvocationKey;
pub(crate) type ActionAuthorization = crate::atoms::comparison::ActionAuthorization;
pub(crate) type ChangeModePlan = crate::atoms::r#do::change_mode::Plan;
pub(crate) type ChangeOwnerPlan = crate::atoms::r#do::change_owner::Plan;
pub(crate) type CopyFilePlan = crate::atoms::r#do::copy_file::Plan;
pub(crate) type FileWriteOptions<'a> = crate::atoms::r#do::write_file::FileWriteOptions<'a>;

const PYTHON_RUNTIME_DEBRIS_EXCLUDE: &[&str] = &["__pycache__", "*.pyc", "*.pyo"];

pub(crate) type RemoveDirImage = crate::atoms::r#do::remove_dir::Image;
pub(crate) type RemoveDirNode = crate::atoms::r#do::remove_dir::Node;
pub(crate) type RemoveDirKind = crate::atoms::r#do::remove_dir::Kind;

pub(crate) fn remove_dir_capture(
    path: &Path,
) -> Result<crate::atoms::r#do::remove_dir::Image, String> {
    crate::atoms::r#do::remove_dir::capture(path)
}

pub(crate) fn remove_dir(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    path: &Path,
) -> Result<crate::atoms::r#do::remove_dir::Image, String> {
    crate::atoms::r#do::remove_dir::operate(authorization, invocation, path, None)
}

pub(crate) fn remove_dir_authorized(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    path: &Path,
) -> Result<(), String> {
    crate::atoms::r#do::remove_dir::remove_authorized(authorization, invocation, path)
}

pub(crate) fn rename(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    from: &Path,
    to: &Path,
) -> Result<(), String> {
    crate::atoms::r#do::rename::rename(authorization, invocation, from, to)
}

pub(crate) fn remove_dir_replace(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    path: &Path,
    image: &RemoveDirImage,
) -> Result<(), String> {
    crate::atoms::r#do::remove_dir::replace_authorized(authorization, invocation, path, image)
}

pub(crate) fn remove_dir_exact(left: &RemoveDirImage, right: &RemoveDirImage) -> bool {
    crate::atoms::r#do::remove_dir::exact(left, right)
}

pub(crate) fn remove_dir_is_directory(image: &RemoveDirImage) -> bool {
    matches!(image.root.kind, RemoveDirKind::Directory)
}

pub(crate) fn change_mode(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    plan: &ChangeModePlan,
) -> Result<(), String> {
    crate::atoms::r#do::change_mode::change(authorization, invocation, plan)
}

pub(crate) fn change_owner(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    plan: &ChangeOwnerPlan,
) -> Result<(), String> {
    crate::atoms::r#do::change_owner::change(authorization, invocation, plan)
}

pub(crate) fn copy_file(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    plan: &CopyFilePlan,
) -> Result<(), String> {
    crate::atoms::r#do::copy_file::copy(authorization, invocation, plan)
}

pub(crate) fn file_write(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    path: &Path,
    bytes: &[u8],
    options: FileWriteOptions<'_>,
) -> Result<crate::atoms::r#do::write_file::FileWriteResult, String> {
    crate::atoms::r#do::write_file::file_write(authorization, invocation, path, bytes, options)
}

pub(crate) fn remove_file(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    path: &Path,
) -> Result<(), String> {
    crate::atoms::r#do::remove_file::remove_file(authorization, invocation, path)
}

pub(crate) fn make_dir(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    path: &Path,
) -> Result<(), String> {
    crate::atoms::r#do::make_dir::create_dir_all(authorization, invocation, path)
}

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use similar::TextDiff;
use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::ffi::CString;
use std::fs::{self, File};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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

fn classify_request(request: &FileConvergenceRequest) -> Result<Vec<TargetClass>, String> {
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
struct UnifiedFileDiff {
    text: Option<String>,
    omitted: Option<String>,
}

fn unified_file_diff(source: &Path, target: &Path) -> Result<UnifiedFileDiff, String> {
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

fn write_unified_diff_receipt(
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

pub(crate) use crate::remove_file::{FileRemovalEntry, FileRemovalOutcome};

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

pub(crate) fn converge_managed_directories(
    directories: &[ManagedDirectorySpec],
    receipt_dir: &Path,
    receipt_name: &str,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<crate::OperationOutcome, String> {
    validate_receipt_name(receipt_name)?;
    if directories.is_empty() {
        return Err("managed-directories-empty-request".to_string());
    }
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
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
        let run = crate::atoms::comparison::execute(
            "files",
            || {
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
                let mode_equal_before =
                    existed_before && target_mode(&path)? == Some(directory.mode);
                let (owner_equal_before, group_equal_before) =
                    ownership_equal(&path, Some(desired_uid), Some(desired_gid))?;
                Ok::<_, String>((
                    existed_before,
                    mode_equal_before,
                    owner_equal_before,
                    group_equal_before,
                ))
            },
            |observation| {
                if observation.0 && observation.1 && observation.2 && observation.3 {
                    crate::atoms::comparison::DiffDecision::Empty
                } else {
                    crate::atoms::comparison::DiffDecision::Different
                }
            },
            |authorization, _| {
                if !apply {
                    return Ok(false);
                }
                let key = invocation.ok_or("managed-directory-invocation-missing")?;
                crate::atoms::r#do::make_dir::create_dir_all(authorization, key, &path).map_err(
                    |e| format!("managed-directory-create-failed {}: {e}", path.display()),
                )?;
                crate::atoms::r#do::change_mode::change(
                    authorization,
                    key,
                    &crate::atoms::r#do::change_mode::Plan {
                        path: path.clone(),
                        mode: Some(directory.mode),
                        no_follow: true,
                    },
                )
                .map_err(|e| {
                    format!("managed-directory-mode-set-failed {}: {e}", path.display())
                })?;
                crate::atoms::r#do::change_owner::change(
                    authorization,
                    key,
                    &crate::atoms::r#do::change_owner::Plan {
                        path: path.clone(),
                        uid: Some(desired_uid),
                        gid: Some(desired_gid),
                        no_follow: true,
                    },
                )
                .map_err(|e| {
                    format!("managed-directory-owner-set-failed {}: {e}", path.display())
                })?;
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
                Ok(true)
            },
        )?;
        let observation = run.observation();
        let diff_decision = match run.decision() {
            crate::atoms::comparison::DiffDecision::Empty => "empty",
            crate::atoms::comparison::DiffDecision::Different => "different",
        };
        let (movement, truthful_changed) = match &run {
            crate::atoms::comparison::ComparisonRun::Current { .. } => ("none", false),
            crate::atoms::comparison::ComparisonRun::Moved { movement, .. } if *movement => {
                ("mkdir-chmod-chown", true)
            }
            crate::atoms::comparison::ComparisonRun::Moved { .. } => ("report-only", false),
        };
        changed |= truthful_changed;
        entries.push(json!({
            "path": directory.path,
            "mode": directory.mode,
            "owner": directory.owner,
            "group": directory.group,
            "existed_before": observation.0,
            "mode_equal_before": observation.1,
            "owner_equal_before": observation.2,
            "group_equal_before": observation.3,
            "changed": truthful_changed,
            "applied": truthful_changed,
            "observed_state": {"exists": observation.0, "mode_equal": observation.1, "owner_equal": observation.2, "group_equal": observation.3},
            "desired_state": {"mode": directory.mode, "uid": desired_uid, "gid": desired_gid},
            "diff_decision": diff_decision,
            "movement": movement,
            "truthful_changed": truthful_changed,
        }));
    }
    crate::atoms::attest::write_json_atomic(
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

#[derive(Debug, Clone)]
struct ManagedFileObservation {
    path: PathBuf,
    target_exists_before: bool,
    missing_target_debt: bool,
    mode: u32,
    content_equal: bool,
    mode_equal: bool,
    owner_equal: bool,
    group_equal: bool,
}

impl ManagedFileObservation {
    fn file_changed(&self) -> bool {
        !self.content_equal || !self.mode_equal || !self.owner_equal || !self.group_equal
    }

    fn observed_state(&self) -> serde_json::Value {
        json!({
            "target_exists": self.target_exists_before,
            "state": if self.missing_target_debt { "missing-target-birth-debt" } else { "observed" },
            "content_equal": self.content_equal,
            "mode_equal": self.mode_equal,
            "owner_equal": self.owner_equal,
            "group_equal": self.group_equal,
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum ManagedFileMovement {
    ReportOnly,
    ContentModeAndOwnership,
    Ownership,
}

impl ManagedFileMovement {
    fn as_str(self) -> &'static str {
        match self {
            Self::ReportOnly => "report-only",
            Self::ContentModeAndOwnership => "atomic-write-chmod-chown",
            Self::Ownership => "chown",
        }
    }
}

pub(crate) fn converge_managed_files(
    request: &ManagedFilesRequest<'_>,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<crate::OperationOutcome, String> {
    validate_receipt_name(request.receipt_name)?;
    let classes = request
        .files
        .iter()
        .map(|file| classify_target(Path::new(&file.path)))
        .collect::<Vec<_>>();
    if let Some(reason) = classes.iter().find_map(|class| match class {
        TargetClass::Refused(reason) => Some(reason.clone()),
        _ => None,
    }) {
        return Err(reason);
    }
    let apply = apply
        && classes
            .iter()
            .all(|class| matches!(class, TargetClass::Software));
    for file in request.files {
        reject_ssh_path(Path::new(&file.path))?;
    }
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
    let mut drift = Vec::new();
    let mut missing_target_birth_debts = Vec::new();
    let mut written = Vec::new();
    let mut changed = false;
    let mut entries = Vec::new();
    let desired_uid = request.owner.map(resolve_uid).transpose()?;
    let desired_gid = request.group.map(resolve_gid).transpose()?;
    for file in request.files {
        let desired = file.content.as_bytes();
        let run = match crate::atoms::comparison::execute_mode(
            "files",
            || {
                let path = PathBuf::from(&file.path);
                let target_exists_before = fs::symlink_metadata(&path).is_ok();
                let target_regular = fs::symlink_metadata(&path)
                    .map(|metadata| metadata.file_type().is_file())
                    .unwrap_or(false);
                let existing = fs::read(&path).ok();
                let mode = file.mode.unwrap_or(0o644);
                let content_equal = target_regular && existing.as_deref() == Some(desired);
                let mode_equal = target_regular && target_mode(&path)? == Some(mode);
                let (owner_equal, group_equal) = ownership_equal(&path, desired_uid, desired_gid)?;
                Ok::<_, String>(ManagedFileObservation {
                    path,
                    target_exists_before,
                    missing_target_debt: !target_exists_before,
                    mode,
                    content_equal,
                    mode_equal,
                    owner_equal,
                    group_equal,
                })
            },
            |observation| {
                if observation.file_changed() {
                    crate::atoms::comparison::DiffDecision::Different
                } else {
                    crate::atoms::comparison::DiffDecision::Empty
                }
            },
            |authorization, observation| {
                if !apply {
                    return Ok(ManagedFileMovement::ReportOnly);
                }
                let key = invocation.ok_or("managed-file-invocation-missing")?;
                if let Some(parent) = observation.path.parent() {
                    if !parent.is_dir() {
                        make_dir(authorization, key, parent)?;
                    }
                }
                if !observation.content_equal || !observation.mode_equal {
                    crate::atoms::r#do::write_file::atomic_write_bytes_with_ownership(
                        authorization,
                        key,
                        &observation.path,
                        desired,
                        Some(observation.mode),
                        desired_uid,
                        desired_gid,
                    )?;
                } else if !observation.owner_equal || !observation.group_equal {
                    crate::atoms::r#do::change_owner::change(
                        authorization,
                        key,
                        &crate::atoms::r#do::change_owner::Plan {
                            path: observation.path.clone(),
                            uid: desired_uid,
                            gid: desired_gid,
                            no_follow: true,
                        },
                    )?;
                }
                let (owner_equal_after, group_equal_after) =
                    ownership_equal(&observation.path, desired_uid, desired_gid)?;
                if !owner_equal_after || !group_equal_after {
                    return Err(format!(
                        "managed-file-owner-readback-failed {}",
                        observation.path.display()
                    ));
                }
                Ok(if !observation.content_equal || !observation.mode_equal {
                    ManagedFileMovement::ContentModeAndOwnership
                } else {
                    ManagedFileMovement::Ownership
                })
            },
            apply,
        ) {
            Ok(run) => run,
            Err(error) => {
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
                crate::atoms::attest::write_json_atomic(
                    &per_file,
                    &json!({
                        "schema": "harmonia.files.managed_file.v1",
                        "ok": false,
                        "module": request.module_id,
                        "path": file.path,
                        "apply": apply,
                        "state": "act-error",
                        "error": error,
                        "first_missing_signal": "managed-file-act-error",
                    }),
                )?;
                return Err(error);
            }
        };
        let observation = run.observation();
        let file_changed = observation.file_changed();
        let missing_target_debt = observation.missing_target_debt;
        let target_exists_before = observation.target_exists_before;
        let mode = observation.mode;
        let content_equal = observation.content_equal;
        let mode_equal = observation.mode_equal;
        let owner_equal = observation.owner_equal;
        let group_equal = observation.group_equal;
        let diff_decision = match run.decision() {
            crate::atoms::comparison::DiffDecision::Empty => "empty",
            crate::atoms::comparison::DiffDecision::Different => "different",
        };
        let movement = match &run {
            crate::atoms::comparison::ComparisonRun::Current { .. } => "none",
            crate::atoms::comparison::ComparisonRun::Moved { movement, .. } => movement.as_str(),
        };
        let report_only_drift = file_changed && !missing_target_debt && !apply;
        let truthful_changed = matches!(
            &run,
            crate::atoms::comparison::ComparisonRun::Moved {
                movement: ManagedFileMovement::ContentModeAndOwnership
                    | ManagedFileMovement::Ownership,
                ..
            }
        );
        if missing_target_debt {
            missing_target_birth_debts.push(file.path.clone());
        } else if file_changed && truthful_changed {
            written.push(file.path.clone());
            changed = true;
        } else if file_changed {
            drift.push(file.path.clone());
        }
        entries.push(json!({
            "path": file.path,
            "target_exists_before": target_exists_before,
            "state": if missing_target_debt { "missing-target-birth-debt" } else { "observed" },
            "mode": mode,
            "content_equal_before": content_equal,
            "mode_equal_before": mode_equal,
            "owner": request.owner,
            "group": request.group,
            "owner_equal_before": owner_equal,
            "group_equal_before": group_equal,
            "changed": truthful_changed,
            "drift_detected": file_changed && !missing_target_debt,
            "written": truthful_changed,
            "observed_state": observation.observed_state(),
            "desired_state": {"content_sha256": format!("{:x}", Sha256::digest(desired)), "mode": mode, "uid": desired_uid, "gid": desired_gid},
            "diff_decision": diff_decision,
            "movement": movement,
            "truthful_changed": truthful_changed,
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
        crate::atoms::attest::write_json_atomic(
            &per_file,
            &json!({
                "schema": "harmonia.files.managed_file.v1",
                "ok": !missing_target_debt,
                "module": request.module_id,
                "path": file.path,
                "mode": mode,
                "owner": request.owner,
                "group": request.group,
                "owner_equal_before": owner_equal,
                "group_equal_before": group_equal,
                "apply": apply,
                "target_exists_before": target_exists_before,
                "state": if missing_target_debt { "missing-target-birth-debt" } else if report_only_drift { "drift-reported" } else { "observed" },
                "changed": truthful_changed,
                "drift_detected": file_changed && !missing_target_debt,
                "written": truthful_changed,
                "observed_state": observation.observed_state(),
                "desired_state": {"content_sha256": format!("{:x}", Sha256::digest(desired)), "mode": mode, "uid": desired_uid, "gid": desired_gid},
                "diff_decision": diff_decision,
                "movement": movement,
                "truthful_changed": truthful_changed,
                "first_missing_signal": if missing_target_debt { "missing-target-birth-debt" } else if report_only_drift { request.first_missing_signal } else { "none" },
            }),
        )?;
    }
    let ok = missing_target_birth_debts.is_empty() || !apply;
    let receipt = receipt_dir.join(if request.receipt_name.ends_with(".json") {
        request.receipt_name.to_string()
    } else {
        format!("{}.json", request.receipt_name)
    });
    crate::atoms::attest::write_json_atomic(
        &receipt,
        &json!({
            "schema": request.schema,
            "ok": ok,
            "module": request.module_id,
            "drift": drift,
            "missing_target_birth_debts": missing_target_birth_debts,
            "written": written,
            "owner": request.owner,
            "group": request.group,
            "apply": apply,
            "changed": changed,
            "entries": entries,
            "first_missing_signal": if !missing_target_birth_debts.is_empty() { "missing-target-birth-debt" } else if !drift.is_empty() { request.first_missing_signal } else { "none" },
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

pub fn converge_files(
    request: &FileConvergenceRequest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<FileConvergenceOutcome, String> {
    if apply {
        return Err("software-authorization-required".into());
    }
    converge_files_authorized(request, receipt_dir, None, None)
}

pub(crate) fn converge_files_with_invocation(
    request: &FileConvergenceRequest,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<FileConvergenceOutcome, String> {
    if apply {
        return Err("software-authorization-required".into());
    }
    converge_files_authorized(request, receipt_dir, None, invocation)
}

pub(crate) fn converge_files_authorized(
    request: &FileConvergenceRequest,
    receipt_dir: &Path,
    authorization: Option<&crate::SoftwareApplyAuthorization>,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<FileConvergenceOutcome, String> {
    converge_files_authorized_with_config_policy(
        request,
        receipt_dir,
        authorization,
        invocation,
        false,
    )
}

pub(crate) fn converge_files_authorized_with_config_policy(
    request: &FileConvergenceRequest,
    receipt_dir: &Path,
    authorization: Option<&crate::SoftwareApplyAuthorization>,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
    allow_config_proposal: bool,
) -> Result<FileConvergenceOutcome, String> {
    if request.files.is_empty() {
        return Err("files-converge-empty-request".to_string());
    }
    validate_receipt_name(&request.receipt_name)?;
    validate_specs(&request.files)?;
    let classes = classify_request(request)?;
    let held = !allow_config_proposal
        && classes
            .iter()
            .any(|class| matches!(class, TargetClass::Config));
    let apply = authorization.is_some()
        && !held
        && classes
            .iter()
            .all(|class| matches!(class, TargetClass::Software));
    // InvocationKey is an actuator bearer, never an observation/proposal bearer.
    let actuation_invocation = apply.then_some(invocation).flatten();
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
    let mut missing_target_birth_debts = Vec::new();
    let mut written = 0usize;
    let mut backed_up = 0usize;

    for spec in &request.files {
        let source = request.source_root.join(&spec.relative_path);
        let target = request.target_root.join(&spec.relative_path);
        let relative_path = spec.relative_path.to_string_lossy().to_string();
        let source_exists = source.is_file();
        let target_exists_before = fs::symlink_metadata(&target).is_ok();
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
                diff: None,
                diff_omitted: None,
            });
            continue;
        }

        if !target_exists_before {
            missing_target_birth_debts.push(relative_path.clone());
            let file_diff = unified_file_diff(&source, &target)?;
            if let Some(diff) = file_diff.text.as_deref() {
                write_unified_diff_receipt(
                    receipt_dir,
                    &request.receipt_name,
                    &relative_path,
                    diff,
                )?;
            }
            entries.push(FileConvergenceEntry {
                relative_path,
                source,
                target,
                source_exists,
                target_exists_before: false,
                content_equal_before: false,
                mode_equal_before: false,
                target_exists_after: false,
                content_equal_after: false,
                mode_equal_after: false,
                changed: false,
                backed_up_to: None,
                final_mode: spec
                    .mode
                    .or_else(|| source_mode(&request.source_root.join(&spec.relative_path)).ok()),
                ownership_source: ownership_source.to_string(),
                observed_uid_before: None,
                observed_gid_before: None,
                observed_uid_after: None,
                observed_gid_after: None,
                ownership_changed: false,
                observed_uid: None,
                observed_gid: None,
                diff: file_diff.text,
                diff_omitted: file_diff.omitted,
            });
            continue;
        }

        let content_equal_before = if target.is_file() {
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
        let content_changed = !content_equal_before || !mode_equal_before;
        let entry_changed = content_changed || ownership_changed;
        let file_diff = if !content_equal_before {
            unified_file_diff(&source, &target)?
        } else {
            UnifiedFileDiff::default()
        };
        if let Some(diff) = file_diff.text.as_deref() {
            write_unified_diff_receipt(receipt_dir, &request.receipt_name, &relative_path, diff)?;
        }
        let desired_bytes = fs::read(&source)
            .map_err(|error| format!("files-source-read-failed {}: {error}", source.display()))?;
        let backup_path = receipt_dir.join("backups").join(&spec.relative_path);
        if !apply {
            // Observe/compare/propose is a terminal lane: no actuator call and no
            // InvocationKey may cross into a mutation-capable descendant.
            entries.push(FileConvergenceEntry {
                relative_path,
                source,
                target,
                source_exists,
                target_exists_before,
                content_equal_before,
                mode_equal_before,
                target_exists_after: target_exists_before,
                content_equal_after: content_equal_before,
                mode_equal_after: mode_equal_before,
                changed: entry_changed,
                backed_up_to: None,
                final_mode,
                ownership_source: ownership_source.to_string(),
                observed_uid_before,
                observed_gid_before,
                observed_uid_after: observed_uid_before,
                observed_gid_after: observed_gid_before,
                ownership_changed,
                observed_uid: observed_uid_before,
                observed_gid: observed_gid_before,
                diff: file_diff.text,
                diff_omitted: file_diff.omitted,
            });
            continue;
        }
        let place = crate::place_file::execute(crate::place_file::PlaceFileRequest {
            path: &target,
            declared_bytes: &desired_bytes,
            mode: final_mode,
            ownership: crate::place_file::DeclaredOwnership {
                uid: desired_uid,
                gid: desired_gid,
            },
            backup: if request.backup_existing && content_changed {
                crate::place_file::BackupPolicy::To(&backup_path)
            } else {
                crate::place_file::BackupPolicy::None
            },
            invocation: actuation_invocation,
        });
        let (backed_up_to, wrote_content, truthful_changed) = match place {
            Ok(outcome) => {
                let _typed_receipt = outcome.receipt;
                let changed = outcome.movement.changed();
                (
                    outcome.movement.backed_up,
                    outcome.movement.bytes || outcome.movement.mode,
                    changed,
                )
            }
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
        };
        if backed_up_to.is_some() {
            backed_up += 1;
        }
        if wrote_content {
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
                changed: truthful_changed,
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
                diff: file_diff.text.clone(),
                diff_omitted: file_diff.omitted.clone(),
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
            diff: file_diff.text,
            diff_omitted: file_diff.omitted,
        });
    }

    let ok = held || (missing.is_empty() && missing_target_birth_debts.is_empty());
    let changed = !held && entries.iter().any(|entry| entry.changed);
    let ownership_changed = !held && entries.iter().any(|entry| entry.ownership_changed);
    let outcome = FileConvergenceOutcome {
        ok,
        changed,
        ownership_changed,
        checked: request.files.len(),
        written,
        backed_up,
        missing,
        missing_target_birth_debts,
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
            "files convergence incomplete".to_string()
        },
    };
    write_convergence_receipt(receipt_dir, request, &outcome, apply, held)?;
    Ok(outcome)
}

/// Seed files are a one-way ownership boundary: the declared source is used
/// only to create an absent regular file. Later bytes, mode, and ownership
/// belong to the external writer and are deliberately not reconverged.
#[cfg(not(test))]
pub fn ensure_files_present(
    request: &FileConvergenceRequest,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<FileConvergenceOutcome, String> {
    ensure_files_present_with_invocation(request, receipt_dir, apply, invocation)
}

pub(crate) fn ensure_files_present_with_invocation(
    request: &FileConvergenceRequest,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<FileConvergenceOutcome, String> {
    if request.files.is_empty() {
        return Err("files-ensure-present-empty-request".to_string());
    }
    validate_receipt_name(&request.receipt_name)?;
    validate_specs(&request.files)?;
    let desired_uid = request.owner.as_deref().map(resolve_uid).transpose()?;
    let desired_gid = request.group.as_deref().map(resolve_gid).transpose()?;
    let mut comparisons = Vec::new();
    let mut written = 0usize;
    for spec in &request.files {
        let source = request.source_root.join(&spec.relative_path);
        if !source.is_file() {
            return Err(format!(
                "files-ensure-present-source-missing {}",
                source.display()
            ));
        }
        let target = request.target_root.join(&spec.relative_path);
        reject_ssh_path(&target)?;
        let run = crate::atoms::comparison::execute(
            "files",
            || match fs::symlink_metadata(&target) {
                Ok(metadata) if metadata.file_type().is_file() => Ok(true),
                Ok(_) => Err(format!(
                    "files-ensure-present-target-not-regular-file {}",
                    target.display()
                )),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(format!(
                    "files-ensure-present-target-metadata-failed {}: {error}",
                    target.display()
                )),
            },
            |present| {
                if *present {
                    crate::atoms::comparison::DiffDecision::Empty
                } else {
                    crate::atoms::comparison::DiffDecision::Different
                }
            },
            |authorization, _| {
                if !apply {
                    return Ok(false);
                }
                let parent = target
                    .parent()
                    .ok_or_else(|| format!("files-target-parent-missing {}", target.display()))?;
                let key = invocation.ok_or("files-ensure-present-invocation-missing")?;
                crate::atoms::r#do::make_dir::create_dir_all(authorization, key, parent).map_err(
                    |e| {
                        format!(
                            "files-ensure-present-parent-create-failed {}: {e}",
                            parent.display()
                        )
                    },
                )?;
                let bytes = fs::read(&source)
                    .map_err(|e| format!("files-source-read-failed {}: {e}", source.display()))?;
                crate::atoms::r#do::write_file::atomic_write_bytes_with_ownership(
                    authorization,
                    key,
                    &target,
                    &bytes,
                    spec.mode.or_else(|| source_mode(&source).ok()),
                    desired_uid,
                    desired_gid,
                )?;
                if !fs::symlink_metadata(&target)
                    .map(|m| m.file_type().is_file())
                    .unwrap_or(false)
                {
                    return Err(format!(
                        "files-ensure-present-readback-failed {}",
                        target.display()
                    ));
                }
                Ok(true)
            },
        )?;
        let present = *run.observation();
        let decision = match run.decision() {
            crate::atoms::comparison::DiffDecision::Empty => "empty",
            crate::atoms::comparison::DiffDecision::Different => "different",
        };
        let changed = matches!(
            &run,
            crate::atoms::comparison::ComparisonRun::Moved { movement: true, .. }
        );
        written += usize::from(changed);
        comparisons.push(json!({
            "relative_path": spec.relative_path,
            "source": source, "target": target,
            "observed_state": {"target_kind": if present { "regular-file" } else { "absent" }},
            "desired_state": {"target_kind": "regular-file", "mode": spec.mode, "uid": desired_uid, "gid": desired_gid},
            "diff_decision": decision,
            "movement": if changed { "create-seed" } else if decision == "different" { "report-only" } else { "none" },
            "truthful_changed": changed,
        }));
    }
    let changed = written > 0;
    let outcome = FileConvergenceOutcome {
        ok: true,
        changed,
        ownership_changed: false,
        checked: request.files.len(),
        written,
        backed_up: 0,
        missing: Vec::new(),
        missing_target_birth_debts: Vec::new(),
        entries: Vec::new(),
        message: format!(
            "{} seed files {}",
            request.files.len(),
            if changed {
                "created"
            } else {
                "already present or planned"
            }
        ),
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
            "schema": "harmonia.files.ensure_present.v1", "ok": true, "apply": apply,
            "source_root": request.source_root, "target_root": request.target_root,
            "checked": outcome.checked, "written": outcome.written, "changed": outcome.changed,
            "entries": comparisons, "first_missing_signal": "none",
        }),
    )?;
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
    sync_directory(parent)
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
                    if let Err(error) = sync_directory(parent) {
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
            crate::atoms::r#do::source_shelf::copy(
                authorization,
                invocation,
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
            first_blocker: "none".into(),
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
        sync_directory(receipt_dir)?;
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
    let desired: Vec<SweepTreeEntry> = inventory_sweep_tree(&shelf_source, &sweep_exclude)?
        .into_iter()
        .filter(|entry| entry.relative_path != Path::new("."))
        .collect();
    let desired_paths: BTreeSet<String> = desired
        .iter()
        .map(|entry| {
            request
                .target_shelf
                .join(&entry.relative_path)
                .display()
                .to_string()
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
        let source = shelf_source.join(&entry.relative_path);
        let target = request.target_shelf.join(&entry.relative_path);
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
            source_digest: None,
            before_digest: None,
            after_digest: None,
            desired_mode: if entry.is_dir {
                request.shelf_directory_mode
            } else {
                request.shelf_file_mode
            },
            before_mode: None,
            after_mode: None,
            desired_uid: uid,
            desired_gid: gid,
            before_uid: None,
            before_gid: None,
            after_uid: None,
            after_gid: None,
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
            ok: true,
            changed: false,
            current: !drift,
            source_inventory_count: desired.len(),
            target_inventory_count_before: 0,
            target_inventory_count_after: 0,
            promoted_count: 0,
            removed_count: 0,
            transaction_state: if drift { "planned" } else { "unchanged" }.into(),
            rollback_state: "not-needed".into(),
            first_blocker: "none".into(),
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
        |_| crate::atoms::comparison::DiffDecision::Different,
        |authorization, _| {
            (|| -> Result<(), String> {
                let invocation = invocation.ok_or("source-shelf-sweep-invocation-key-missing")?;
                crate::atoms::r#do::source_shelf::mkdir_all(
                    authorization,
                    invocation,
                    &quarantine,
                )?;
                for entry in &desired {
                    let source = shelf_source.join(&entry.relative_path);
                    let target = request.target_shelf.join(&entry.relative_path);
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
        } else {
            entry.target.exists()
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
                        sync_directory(backup.parent().expect("launcher backup has parent"))?;
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
                        sync_directory(target.parent().expect("launcher target has parent"))?;
                        sync_directory(backup.parent().expect("launcher backup has parent"))?;
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
                    sync_directory(target.parent().expect("launcher target has parent"))?;
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
                        sync_directory(target.parent().expect("stale launcher target has parent"))?;
                        sync_directory(backup.parent().expect("stale launcher backup has parent"))?;
                        launcher_backups.push((target, backup));
                        removed_count += 1;
                    }
                    sync_directory(&request.launcher_target_root)?;
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
                        if let Err(error) = sync_directory(parent) {
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
                        if let Err(error) = sync_directory(parent) {
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
                            if let Err(error) = sync_directory(parent) {
                                rollback_errors.push(format!(
                                    "sync restored launcher parent {}: {error}",
                                    parent.display()
                                ));
                            }
                        }
                        if let Some(parent) = backup.parent() {
                            if let Err(error) = sync_directory(parent) {
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
                if let Err(error) = sync_directory(&request.launcher_target_root) {
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
                sync_directory(shelf_parent)?;
                sync_directory(&request.launcher_target_root)?;
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

pub fn remove_declared_files(
    target_root: &Path,
    paths: &[String],
    receipt_dir: &Path,
    receipt_name: &str,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<FileRemovalOutcome, String> {
    crate::remove_file::execute(
        target_root,
        paths,
        receipt_dir,
        receipt_name,
        apply,
        invocation,
        true,
        "refuse",
        "exact",
    )
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

fn validate_source_shelf_relative_path(path: &Path) -> Result<(), String> {
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

pub(crate) fn validate_interactable_target(path: &Path) -> Result<(), String> {
    if is_protected_path(path) {
        return Err(format!(
            "credential-boundary-refused: {} is key-shaped, Harmonia never hard-stamps credential material",
            path.display()
        ));
    }
    Ok(())
}

pub(crate) fn hard_stamp_interactable(
    id: &str,
    source: &Path,
    target: &Path,
    mode: Option<u32>,
    owner: Option<&str>,
    group: Option<&str>,
    backup_root: &Path,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<serde_json::Value, String> {
    validate_interactable_target(target)?;
    if !source.is_file() {
        return Err(format!(
            "interactable-reference-source-missing {}",
            source.display()
        ));
    }
    let metadata = fs::symlink_metadata(target).map_err(|error| {
        format!(
            "interactable-target-birth-debt {}: {error}",
            target.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "interactable-target-not-regular-file {}",
            target.display()
        ));
    }
    let desired_uid = owner.map(resolve_uid).transpose()?;
    let desired_gid = group.map(resolve_gid).transpose()?;
    let desired_bytes = fs::read(source).map_err(|error| {
        format!(
            "interactable-reference-source-read-failed {}: {error}",
            source.display()
        )
    })?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().to_string())
        .unwrap_or_else(|_| "0".to_string());
    let backup = backup_root.join(id).join(format!(
        "{}-{}",
        stamp,
        target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("target")
    ));
    let place = crate::place_file::execute(crate::place_file::PlaceFileRequest {
        path: target,
        declared_bytes: &desired_bytes,
        mode: mode.or_else(|| source_mode(source).ok()),
        ownership: crate::place_file::DeclaredOwnership {
            uid: desired_uid,
            gid: desired_gid,
        },
        backup: crate::place_file::BackupPolicy::To(&backup),
        invocation,
    })?;
    let changed = place.movement.changed();
    let backed_up_to = place.movement.backed_up;
    let before_sha256 = backed_up_to
        .as_ref()
        .map(|path| {
            fs::read(path)
                .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
                .map_err(|error| error.to_string())
        })
        .transpose()?;
    let reference_sha256 = format!("{:x}", Sha256::digest(&desired_bytes));
    let target_sha256 = format!(
        "{:x}",
        Sha256::digest(fs::read(target).map_err(|error| error.to_string())?)
    );
    if target_sha256 != reference_sha256 {
        return Err(format!(
            "interactable-hard-stamp-readback-failed {}",
            target.display()
        ));
    }
    Ok(json!({
        "schema": "harmonia.interactables.hard_stamp.receipt.v1",
        "ok": true,
        "id": id,
        "kind": "hard-stamp",
        "backup_path": backed_up_to,
        "backed_up_to": backed_up_to,
        "before_sha256": before_sha256,
        "reference_sha256": reference_sha256,
        "target_sha256": target_sha256,
        "target": target,
        "reference_source": source,
        "changed": changed,
    }))
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

pub(crate) fn target_mode(path: &Path) -> Result<Option<u32>, String> {
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

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    crate::atoms::attest::set_mode(path, mode)
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
        json!(held || (entry.source_exists
            && if apply {
                entry.target_exists_after && entry.content_equal_after && entry.mode_equal_after
            } else {
                entry.target_exists_before
            })),
    );
    if held {
        object.insert("state".into(), json!("held/authority-refused"));
    }
    receipt
}

fn write_convergence_receipt(
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

#[cfg(unix)]
fn observe_symlink_path(path: &Path) -> Result<SymlinkPathIdentity, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            let kind = if file_type.is_symlink() {
                "symlink"
            } else if file_type.is_file() {
                "regular-file"
            } else if file_type.is_dir() {
                "directory"
            } else {
                "other"
            };
            let link_target = if file_type.is_symlink() {
                Some(fs::read_link(path).map_err(|error| {
                    format!(
                        "symlink-converge-readlink-failed {}: {error}",
                        path.display()
                    )
                })?)
            } else {
                None
            };
            Ok(SymlinkPathIdentity {
                kind: kind.to_string(),
                link_target,
                mode: Some(metadata.permissions().mode() & 0o7777),
                uid: Some(metadata.uid()),
                gid: Some(metadata.gid()),
                device: Some(metadata.dev()),
                inode: Some(metadata.ino()),
                size: Some(metadata.size()),
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(SymlinkPathIdentity {
            kind: "absent".to_string(),
            link_target: None,
            mode: None,
            uid: None,
            gid: None,
            device: None,
            inode: None,
            size: None,
        }),
        Err(error) => Err(format!(
            "symlink-converge-target-observation-failed {}: {error}",
            path.display()
        )),
    }
}

#[cfg(not(unix))]
fn observe_symlink_path(_path: &Path) -> Result<SymlinkPathIdentity, String> {
    Err("symlink-converge-unsupported".to_string())
}

#[cfg(unix)]
fn read_symlink_source(
    path: &Path,
    required_kind: SymlinkSourceKind,
) -> Result<SymlinkSourceIdentity, String> {
    let file = crate::atoms::attest::open_nofollow_read(path).map_err(|error| {
        format!(
            "symlink-converge-source-open-failed {}: {error}",
            path.display()
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        format!(
            "symlink-converge-source-readback-failed {}: {error}",
            path.display()
        )
    })?;
    match required_kind {
        SymlinkSourceKind::RegularExecutable => {
            if !metadata.file_type().is_file() {
                return Err(format!(
                    "symlink-converge-source-kind-mismatch {} expected=regular-executable",
                    path.display()
                ));
            }
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(format!(
                    "symlink-converge-source-not-executable {}",
                    path.display()
                ));
            }
        }
    }
    Ok(SymlinkSourceIdentity {
        kind: "regular-executable".to_string(),
        mode: metadata.permissions().mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        change_seconds: metadata.ctime(),
        change_nanoseconds: metadata.ctime_nsec(),
    })
}

#[cfg(not(unix))]
fn read_symlink_source(
    _path: &Path,
    _required_kind: SymlinkSourceKind,
) -> Result<SymlinkSourceIdentity, String> {
    Err("symlink-converge-unsupported".to_string())
}

#[cfg(unix)]
fn stage_symlink(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: crate::atoms::r#do::InvocationKey,
    source: &Path,
    target: &Path,
    _uid: Option<u32>,
    _gid: Option<u32>,
) -> Result<PathBuf, String> {
    crate::atoms::r#do::symlink_converge::stage(
        authorization,
        invocation,
        source,
        target,
        _uid,
        _gid,
    )
}

#[cfg(not(unix))]
fn stage_symlink(
    _authorization: crate::atoms::comparison::ActionAuthorization,
    _invocation: crate::atoms::r#do::InvocationKey,
    _source: &Path,
    _target: &Path,
    _uid: Option<u32>,
    _gid: Option<u32>,
) -> Result<PathBuf, String> {
    Err("symlink-converge-unsupported".to_string())
}

#[cfg(target_os = "linux")]
fn exchange_paths(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: crate::atoms::r#do::InvocationKey,
    left: &Path,
    right: &Path,
) -> Result<(), String> {
    crate::atoms::r#do::symlink_converge::exchange(authorization, invocation, left, right).map_err(
        |error| {
            format!(
                "symlink-converge-exchange-failed {}: {error}",
                right.display()
            )
        },
    )
}
#[cfg(target_os = "linux")]
fn rename_noreplace(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: crate::atoms::r#do::InvocationKey,
    left: &Path,
    right: &Path,
) -> Result<(), String> {
    crate::atoms::r#do::symlink_converge::rename_noreplace(authorization, invocation, left, right)
        .map_err(|error| format!("symlink-converge-create-raced {}: {error}", right.display()))
}

#[cfg(not(target_os = "linux"))]
fn exchange_paths(
    _authorization: crate::atoms::comparison::ActionAuthorization,
    _invocation: crate::atoms::r#do::InvocationKey,
    _left: &Path,
    _right: &Path,
) -> Result<(), String> {
    Err("symlink-converge-exchange-unsupported".to_string())
}

#[cfg(not(target_os = "linux"))]
fn rename_noreplace(
    _authorization: crate::atoms::comparison::ActionAuthorization,
    _invocation: crate::atoms::r#do::InvocationKey,
    _left: &Path,
    _right: &Path,
) -> Result<(), String> {
    Err("symlink-converge-noreplace-unsupported".to_string())
}

fn promote_staged_symlink(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: crate::atoms::r#do::InvocationKey,
    candidate: &Path,
    target: &Path,
    before: &SymlinkPathIdentity,
) -> Result<(), String> {
    if before.kind == "absent" {
        if let Err(error) = rename_noreplace(authorization, invocation, candidate, target) {
            let _ = crate::atoms::r#do::symlink_converge::remove_file(
                authorization,
                invocation,
                candidate,
            );
            return Err(error);
        }
        return Ok(());
    }

    if let Err(error) = exchange_paths(authorization, invocation, candidate, target) {
        let _ =
            crate::atoms::r#do::symlink_converge::remove_file(authorization, invocation, candidate);
        return Err(error);
    }
    let exchanged = observe_symlink_path(candidate);
    let prior_matches = exchanged.as_ref().is_ok_and(|identity| identity == before);
    let directory_still_empty = before.kind != "directory"
        || fs::read_dir(candidate)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(false);
    if !prior_matches || !directory_still_empty {
        let rollback = exchange_paths(authorization, invocation, candidate, target);
        if rollback.is_ok() {
            let _ = crate::atoms::r#do::symlink_converge::remove_file(
                authorization,
                invocation,
                candidate,
            );
        }
        return Err(format!(
            "symlink-converge-target-raced prior_matches={prior_matches} directory_still_empty={directory_still_empty} rollback={}",
            if rollback.is_ok() { "ok" } else { "failed" }
        ));
    }

    let cleanup = if before.kind == "directory" {
        crate::atoms::r#do::symlink_converge::remove_dir(authorization, invocation, candidate)
    } else {
        crate::atoms::r#do::symlink_converge::remove_file(authorization, invocation, candidate)
    };
    cleanup.map_err(|error| {
        format!(
            "symlink-converge-prior-cleanup-failed {}: {error}",
            candidate.display()
        )
    })
}

#[derive(Debug, Clone)]
struct SymlinkComparisonObservation {
    before: SymlinkPathIdentity,
    source: Result<SymlinkSourceIdentity, String>,
    desired_uid: Option<u32>,
    desired_gid: Option<u32>,
}

fn symlink_diff_decision(
    observation: &SymlinkComparisonObservation,
    request: &SymlinkConvergeRequest,
) -> crate::atoms::comparison::DiffDecision {
    let ownership_current = observation
        .desired_uid
        .map_or(true, |uid| observation.before.uid == Some(uid))
        && observation
            .desired_gid
            .map_or(true, |gid| observation.before.gid == Some(gid));
    let exact = observation.before.kind == "symlink"
        && observation.before.link_target.as_deref() == Some(request.source.as_path())
        && ownership_current
        && observation.source.is_ok();
    if exact {
        crate::atoms::comparison::DiffDecision::Empty
    } else {
        crate::atoms::comparison::DiffDecision::Different
    }
}

pub(crate) fn symlink_converge(
    request: &SymlinkConvergeRequest,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<crate::OperationOutcome, String> {
    validate_receipt_name(&request.receipt_name)?;
    let desired_uid = request
        .owner
        .as_deref()
        .map(resolve_uid)
        .transpose()
        .map_err(|error| format!("symlink-converge-owner-resolution-failed: {error}"))?;
    let desired_gid = request
        .group
        .as_deref()
        .map(resolve_gid)
        .transpose()
        .map_err(|error| format!("symlink-converge-group-resolution-failed: {error}"))?;
    let observation = crate::atoms::comparison::execute(
        "files",
        || {
            Ok::<_, String>(SymlinkComparisonObservation {
                before: observe_symlink_path(&request.target)?,
                source: read_symlink_source(&request.source, request.required_source_kind),
                desired_uid,
                desired_gid,
            })
        },
        |observation| symlink_diff_decision(observation, request),
        |authorization, _| {
            symlink_converge_action(authorization, invocation, request, receipt_dir, apply)
        },
    )?;
    let decision = match observation.decision() {
        crate::atoms::comparison::DiffDecision::Empty => "empty",
        crate::atoms::comparison::DiffDecision::Different => "different",
    };
    let movement = match &observation {
        crate::atoms::comparison::ComparisonRun::Current { .. } => None,
        crate::atoms::comparison::ComparisonRun::Moved { movement, .. } => Some(movement),
    };
    let outcome = match &observation {
        crate::atoms::comparison::ComparisonRun::Current { .. } => crate::OperationOutcome {
            ok: true,
            changed: false,
            skipped: !apply,
            message: "symlink converge unchanged".into(),
            command: None,
        },
        crate::atoms::comparison::ComparisonRun::Moved { movement, .. } => movement.clone(),
    };
    let path = receipt_dir.join(format!("{}.json", request.receipt_name));
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
    let mut receipt = if path.exists() {
        serde_json::from_str(&fs::read_to_string(&path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?
    } else {
        json!({
            "schema": "harmonia.files.symlink_converge.v1",
            "ok": outcome.ok, "apply": apply, "changed": outcome.changed,
            "would_change": false, "source": request.source, "target": request.target,
            "required_source_kind": request.required_source_kind,
            "conflict_policy": request.conflict_policy,
            "owner": request.owner, "group": request.group,
            "desired_uid": desired_uid, "desired_gid": desired_gid,
            "before": observation.observation().before, "after": observation.observation().before,
            "final_readlink": observation.observation().before.link_target,
            "first_missing_signal": "none",
        })
    };
    let object = receipt
        .as_object_mut()
        .ok_or_else(|| "symlink-converge-receipt-not-object".to_string())?;
    object.insert(
        "observed_state".into(),
        serde_json::to_value(&observation.observation().before).map_err(|e| e.to_string())?,
    );
    object.insert(
        "desired_state".into(),
        json!({"kind":"symlink","link_target":request.source,"uid":desired_uid,"gid":desired_gid}),
    );
    object.insert("diff_decision".into(), json!(decision));
    object.insert(
        "movement".into(),
        movement
            .map(|m| json!({"ok":m.ok,"changed":m.changed,"skipped":m.skipped,"message":m.message}))
            .unwrap_or_else(|| json!("none")),
    );
    object.insert("truthful_changed".into(), json!(outcome.changed));
    crate::atoms::attest::write_json_atomic(&path, &receipt)?;
    Ok(outcome)
}

fn symlink_converge_action(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
    request: &SymlinkConvergeRequest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<crate::OperationOutcome, String> {
    validate_receipt_name(&request.receipt_name)?;
    let mut declared_args = BTreeMap::new();
    declared_args.insert("source".to_string(), json!(request.source));
    declared_args.insert("target".to_string(), json!(request.target));
    declared_args.insert(
        "required_source_kind".to_string(),
        json!(request.required_source_kind),
    );
    declared_args.insert(
        "conflict_policy".to_string(),
        json!(request.conflict_policy),
    );
    if let Some(owner) = &request.owner {
        declared_args.insert("owner".to_string(), json!(owner));
    }
    if let Some(group) = &request.group {
        declared_args.insert("group".to_string(), json!(group));
    }
    validate_symlink_converge_args(&declared_args)?;

    let before = observe_symlink_path(&request.target)?;
    let source_before = read_symlink_source(&request.source, request.required_source_kind);
    let source_before_receipt = source_before.as_ref().ok().cloned();
    let desired_uid = request
        .owner
        .as_deref()
        .map(resolve_uid)
        .transpose()
        .map_err(|error| format!("symlink-converge-owner-resolution-failed: {error}"))?;
    let desired_gid = request
        .group
        .as_deref()
        .map(resolve_gid)
        .transpose()
        .map_err(|error| format!("symlink-converge-group-resolution-failed: {error}"))?;

    let finish = |ok: bool,
                  changed: bool,
                  would_change: bool,
                  blocker: &str,
                  after: &SymlinkPathIdentity,
                  source_after: Option<&SymlinkSourceIdentity>|
     -> Result<crate::OperationOutcome, String> {
        crate::atoms::attest::prepare_receipt_parent(receipt_dir).map_err(|error| {
            format!(
                "symlink-converge-receipt-dir-failed {}: {error}",
                receipt_dir.display()
            )
        })?;
        crate::atoms::attest::write_json_atomic(
            &receipt_dir.join(format!("{}.json", request.receipt_name)),
            &json!({
                "schema": "harmonia.files.symlink_converge.v1",
                "ok": ok,
                "apply": apply,
                "changed": changed,
                "would_change": would_change,
                "source": request.source,
                "target": request.target,
                "required_source_kind": request.required_source_kind,
                "conflict_policy": request.conflict_policy,
                "owner": request.owner,
                "group": request.group,
                "desired_uid": desired_uid,
                "desired_gid": desired_gid,
                "source_before": source_before_receipt.as_ref(),
                "source_after": source_after,
                "source_identity_stable": source_before_receipt.as_ref().zip(source_after).map(|(a, b)| a == b).unwrap_or(false),
                "before": before,
                "after": after,
                "final_readlink": after.link_target,
                "first_missing_signal": blocker,
            }),
        )?;
        Ok(crate::OperationOutcome {
            ok,
            changed,
            skipped: !apply,
            message: format!(
                "{blocker} source={} target={}",
                request.source.display(),
                request.target.display()
            ),
            command: None,
        })
    };

    let source_before = match source_before {
        Ok(identity) => identity,
        Err(blocker) => {
            let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
            return finish(false, false, false, &blocker, &after, None);
        }
    };
    let ownership_current = desired_uid.map_or(true, |uid| before.uid == Some(uid))
        && desired_gid.map_or(true, |gid| before.gid == Some(gid));
    let exact_link = before.kind == "symlink"
        && before.link_target.as_deref() == Some(request.source.as_path())
        && ownership_current;
    if exact_link {
        let source_after = match read_symlink_source(&request.source, request.required_source_kind)
        {
            Ok(identity) => identity,
            Err(blocker) => {
                let after =
                    observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
                return finish(false, false, false, &blocker, &after, None);
            }
        };
        let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
        let target_stable = after.kind == "symlink"
            && after.link_target.as_deref() == Some(request.source.as_path())
            && desired_uid.map_or(true, |uid| after.uid == Some(uid))
            && desired_gid.map_or(true, |gid| after.gid == Some(gid));
        let source_stable = source_before == source_after;
        let stable = target_stable && source_stable;
        return finish(
            stable,
            false,
            false,
            if stable {
                "none"
            } else if !source_stable {
                "symlink-converge-source-changed-during-readback"
            } else {
                "symlink-converge-target-changed-during-readback"
            },
            &after,
            Some(&source_after),
        );
    }

    let conflict_blocker = match before.kind.as_str() {
        "regular-file" if request.conflict_policy != SymlinkConflictPolicy::ReplaceRegularFile => {
            Some("symlink-converge-target-regular-file-refused")
        }
        "directory" if request.conflict_policy != SymlinkConflictPolicy::ReplaceEmptyDirectory => {
            Some("symlink-converge-target-directory-refused")
        }
        "other" => Some("symlink-converge-target-kind-refused"),
        _ => None,
    };
    if let Some(blocker) = conflict_blocker {
        let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
        let source_after = read_symlink_source(&request.source, request.required_source_kind).ok();
        return finish(false, false, true, blocker, &after, source_after.as_ref());
    }
    if before.kind == "directory"
        && fs::read_dir(&request.target)
            .map_err(|error| {
                format!(
                    "symlink-converge-target-directory-read-failed {}: {error}",
                    request.target.display()
                )
            })?
            .next()
            .is_some()
    {
        let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
        let source_after = read_symlink_source(&request.source, request.required_source_kind).ok();
        return finish(
            false,
            false,
            true,
            "symlink-converge-target-directory-not-empty-refused",
            &after,
            source_after.as_ref(),
        );
    }
    if !apply {
        let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
        let source_after = read_symlink_source(&request.source, request.required_source_kind)?;
        let stable = source_before == source_after;
        return finish(
            stable,
            false,
            true,
            if stable {
                "none"
            } else {
                "symlink-converge-source-changed-during-readback"
            },
            &after,
            Some(&source_after),
        );
    }

    let invocation = invocation.ok_or("symlink-converge-invocation-missing")?;

    let parent = request.target.parent().ok_or_else(|| {
        format!(
            "symlink-converge-target-parent-missing {}",
            request.target.display()
        )
    })?;
    if !parent.is_dir() {
        return finish(
            false,
            false,
            true,
            "symlink-converge-target-parent-missing",
            &before,
            Some(&source_before),
        );
    }
    let source_pre_stage = match read_symlink_source(&request.source, request.required_source_kind)
    {
        Ok(identity) => identity,
        Err(blocker) => {
            let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
            return finish(false, false, true, &blocker, &after, None);
        }
    };
    if source_pre_stage != source_before {
        let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
        return finish(
            false,
            false,
            true,
            "symlink-converge-source-changed-before-stage",
            &after,
            Some(&source_pre_stage),
        );
    }
    let candidate = match stage_symlink(
        authorization,
        invocation,
        &request.source,
        &request.target,
        desired_uid,
        desired_gid,
    ) {
        Ok(candidate) => candidate,
        Err(blocker) => return finish(false, false, true, &blocker, &before, Some(&source_before)),
    };
    let source_pre_promote =
        match read_symlink_source(&request.source, request.required_source_kind) {
            Ok(identity) => identity,
            Err(blocker) => {
                let _ = crate::atoms::r#do::symlink_converge::remove_file(
                    authorization,
                    invocation,
                    &candidate,
                );
                let after =
                    observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
                return finish(false, false, true, &blocker, &after, None);
            }
        };
    if source_pre_promote != source_before {
        let _ = crate::atoms::r#do::symlink_converge::remove_file(
            authorization,
            invocation,
            &candidate,
        );
        let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
        return finish(
            false,
            false,
            true,
            "symlink-converge-source-changed-before-promote",
            &after,
            Some(&source_pre_promote),
        );
    }
    if let Err(blocker) = promote_staged_symlink(
        authorization,
        invocation,
        &candidate,
        &request.target,
        &before,
    ) {
        let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
        return finish(
            false,
            after != before,
            true,
            &blocker,
            &after,
            Some(&source_before),
        );
    }
    if let Err(error) =
        crate::atoms::r#do::symlink_converge::sync_parent(authorization, invocation, parent)
    {
        let after = observe_symlink_path(&request.target).unwrap_or_else(|_| before.clone());
        return finish(
            false,
            true,
            true,
            &format!("symlink-converge-parent-sync-failed: {error}"),
            &after,
            Some(&source_before),
        );
    }
    let after = match observe_symlink_path(&request.target) {
        Ok(identity) => identity,
        Err(blocker) => return finish(false, true, true, &blocker, &before, Some(&source_before)),
    };
    let source_after = match read_symlink_source(&request.source, request.required_source_kind) {
        Ok(identity) => identity,
        Err(blocker) => return finish(false, true, true, &blocker, &after, None),
    };
    let final_ok = after.kind == "symlink"
        && after.link_target.as_deref() == Some(request.source.as_path())
        && desired_uid.map_or(true, |uid| after.uid == Some(uid))
        && desired_gid.map_or(true, |gid| after.gid == Some(gid))
        && source_before == source_after;
    finish(
        final_ok,
        true,
        true,
        if final_ok {
            "none"
        } else {
            "symlink-converge-final-readback-failed"
        },
        &after,
        Some(&source_after),
    )
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
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<crate::OperationOutcome, String> {
    crate::atoms::r#do::make_symlink::execute(
        crate::atoms::r#do::make_symlink::ValidatedFileSymlinkRequest {
            receipt_dir,
            name,
            desired_source: source,
            source,
            target,
            validator_program,
            validator_args,
            reload_program,
            reload_args,
            timeout_secs,
            apply,
        },
        invocation,
    )
}

pub(crate) fn files_bench(
    root: &Path,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<serde_json::Value, String> {
    let source = root.join("source");
    let target = root.join("target");
    let receipts = root.join("receipts");
    fs::create_dir_all(&source).map_err(|e| e.to_string())?;
    fs::create_dir_all(&target).map_err(|e| e.to_string())?;
    fs::create_dir_all(&receipts).map_err(|e| e.to_string())?;
    fs::write(source.join("a"), b"new\n").map_err(|e| e.to_string())?;
    fs::write(target.join("a"), b"old\n").map_err(|e| e.to_string())?;
    let request = crate::atoms::files::FileConvergenceRequest {
        source_root: source.clone(),
        target_root: target.clone(),
        files: vec![crate::atoms::files::FileSpec {
            relative_path: "a".into(),
            mode: Some(0o644),
        }],
        backup_existing: true,
        receipt_name: "bench".into(),
        owner: None,
        group: None,
    };
    let mode = crate::UpdateMode::from_apply_flag_with_invocation(true, invocation);
    let first = crate::atoms::files::converge_files_authorized(
        &request,
        &receipts,
        mode.software_authorization(),
        mode.invocation(),
    )?;
    let bytes_changed = fs::read(target.join("a")).map_err(|e| e.to_string())? == b"new\n";
    use std::os::unix::fs::PermissionsExt;
    let mode_ok = fs::metadata(target.join("a"))
        .map_err(|e| e.to_string())?
        .permissions()
        .mode()
        & 0o777
        == 0o644;
    let backup_ok = fs::read_dir(&receipts)
        .map_err(|e| e.to_string())?
        .any(|e| {
            e.ok()
                .map(|e| e.file_name().to_string_lossy().contains("backup"))
                .unwrap_or(false)
        });
    let second = crate::atoms::files::converge_files_authorized(
        &request,
        &receipts,
        mode.software_authorization(),
        mode.invocation(),
    )?;
    let quiet = !second.changed;
    let bad_target = target.join("bad");
    fs::create_dir(&bad_target).map_err(|e| e.to_string())?;
    let bad = crate::atoms::files::converge_files_authorized(
        &crate::atoms::files::FileConvergenceRequest {
            files: vec![crate::atoms::files::FileSpec {
                relative_path: "bad".into(),
                mode: Some(0o644),
            }],
            receipt_name: "bad".into(),
            ..request.clone()
        },
        &receipts,
        None,
        None,
    );
    let controlled_error = bad.map(|outcome| !outcome.ok).unwrap_or(true);
    Ok(
        serde_json::json!({"first_ok":first.ok,"bytes_changed":bytes_changed,"declared_mode":mode_ok,"backup_old_bytes":backup_ok,"second_quiet":quiet,"controlled_target_not_file":controlled_error,"ok":first.ok && first.changed && bytes_changed && mode_ok && backup_ok && quiet && controlled_error}),
    )
}
