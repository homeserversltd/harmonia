//! Native Hermes source/dependency maintenance. Generations are built in their
//! final paths, pinned to one observed upstream commit, and selected only by an
//! atomic replacement of the declared, owner-controlled launcher.
use crate::atoms::comparison::{ActionAuthorization, DiffDecision};
use crate::atoms::r#do::InvocationKey;
use crate::{OperationOutcome, SoftwareApplyAuthorization};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::{Arc, Condvar, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const OFFICIAL_URL: &str = "https://github.com/NousResearch/hermes-agent.git";
const MANAGED_MARKER: &str = "# harmonia-hermes-maintenance-v1";

#[derive(Clone)]
struct OwnerContext {
    name: String,
    uid: u32,
    gid: u32,
    home: PathBuf,
    hermes_home: PathBuf,
    command_bearer: crate::atoms::command::CommandBearer,
}

thread_local! {
    static OWNER_CONTEXT: RefCell<Option<OwnerContext>> = const { RefCell::new(None) };
}

struct OwnerContextScope(Option<OwnerContext>);

impl OwnerContextScope {
    fn install(owner: OwnerContext) -> Self {
        let previous = OWNER_CONTEXT.with(|slot| slot.replace(Some(owner)));
        Self(previous)
    }
}

impl Drop for OwnerContextScope {
    fn drop(&mut self) {
        let previous = self.0.take();
        OWNER_CONTEXT.with(|slot| {
            slot.replace(previous);
        });
    }
}

fn current_owner_context() -> Result<OwnerContext, String> {
    OWNER_CONTEXT
        .with(|slot| slot.borrow().clone())
        .ok_or_else(|| "maintenance-owner-context-unavailable".to_string())
}

fn resolve_owner_context(name: &str) -> Result<OwnerContext, String> {
    let c_name = CString::new(name).map_err(|_| "owner-account-name-invalid")?;
    let (uid, gid, home) = unsafe {
        let entry = libc::getpwnam(c_name.as_ptr());
        if entry.is_null() {
            return Err(format!("owner-account-unknown-{name}"));
        }
        let entry = &*entry;
        if entry.pw_dir.is_null() {
            return Err("owner-account-home-invalid".into());
        }
        let home = std::ffi::CStr::from_ptr(entry.pw_dir)
            .to_str()
            .map_err(|_| "owner-account-home-invalid")?;
        (entry.pw_uid, entry.pw_gid, PathBuf::from(home))
    };
    if uid == 0 {
        return Err("maintenance-custody-declared-owner-must-be-non-root".into());
    }
    if !home.is_absolute() {
        return Err("owner-account-home-invalid".into());
    }
    let effective_uid = unsafe { libc::geteuid() };
    if effective_uid != 0 && effective_uid != uid {
        return Err("maintenance-custody-euid-does-not-match-declared-owner".into());
    }
    let home = home
        .canonicalize()
        .map_err(|error| format!("owner-account-home-unavailable: {error}"))?;
    let home_metadata = fs::symlink_metadata(&home)
        .map_err(|error| format!("owner-account-home-unavailable: {error}"))?;
    if home_metadata.file_type().is_symlink() || !home_metadata.is_dir() || home_metadata.uid() != uid {
        return Err("owner-account-home-not-owner-controlled".into());
    }
    let configured_hermes_home = std::env::var_os("HERMES_HOME").map(PathBuf::from);
    let hermes_home = match configured_hermes_home {
        Some(path) if path.is_absolute() => match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() && metadata.uid() == uid => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && path.starts_with(&home) => path,
            Ok(_) => return Err("maintenance-owner-hermes-home-not-owner-controlled".into()),
            Err(error) => return Err(format!("maintenance-owner-hermes-home-observe: {error}")),
        },
        Some(_) => return Err("maintenance-owner-hermes-home-not-absolute".into()),
        None => home.join(".hermes"),
    };
    let command_bearer = crate::atoms::command::resolve_command_bearer(Some(name));
    if !command_bearer.is_explicit() || command_bearer.actual() != name {
        return Err("maintenance-custody-command-bearer-resolution-failed".into());
    }
    Ok(OwnerContext {
        name: name.to_owned(),
        uid,
        gid,
        home,
        hermes_home,
        command_bearer,
    })
}

fn validate_caller_identity(owner: &OwnerContext) -> Result<(), String> {
    let effective_uid = unsafe { libc::geteuid() };
    if effective_uid == 0 || effective_uid == owner.uid {
        Ok(())
    } else {
        Err("maintenance-custody-euid-does-not-match-declared-owner".into())
    }
}

struct CapturedStatus {
    success: bool,
    code: Option<i32>,
}

impl CapturedStatus {
    fn success(&self) -> bool {
        self.success
    }

    fn code(&self) -> Option<i32> {
        self.code
    }
}

struct CapturedOutput {
    status: CapturedStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn owner_environment(owner: &OwnerContext) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("HOME".into(), owner.home.to_string_lossy().into_owned()),
        ("USER".into(), owner.name.clone()),
        ("LOGNAME".into(), owner.name.clone()),
        (
            "XDG_CONFIG_HOME".into(),
            owner.home.join(".config").to_string_lossy().into_owned(),
        ),
        ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
    ])
}

fn run_owner_command(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    mut env: BTreeMap<String, String>,
    timeout_secs: u64,
) -> Result<CapturedOutput, String> {
    let owner = current_owner_context()?;
    let mut clean_env = owner_environment(&owner);
    clean_env.append(&mut env);
    if !clean_env.contains_key("PATH") {
        clean_env.insert("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into());
    }
    let mut argv = vec!["-i".to_owned(), "--".to_owned()];
    argv.extend(clean_env.into_iter().map(|(key, value)| format!("{key}={value}")));
    argv.push(program.to_owned());
    argv.extend(args.iter().map(|arg| (*arg).to_owned()));
    let argv = argv.iter().map(String::as_str).collect::<Vec<_>>();
    let cwd = cwd
        .map(|path| path.to_str().ok_or_else(|| "maintenance-command-cwd-not-utf8".to_string()))
        .transpose()?;
    let result = crate::atoms::command::capture_with_command_bearer_and_limit(
        "/usr/bin/env",
        &argv,
        cwd,
        timeout_secs,
        &owner.command_bearer,
        None,
    );
    Ok(CapturedOutput {
        status: CapturedStatus {
            success: result.ok,
            code: (result.code >= 0).then_some(result.code),
        },
        stdout: result.stdout.into_bytes(),
        stderr: result.stderr.into_bytes(),
    })
}

#[derive(Debug, Clone)]
pub(crate) struct Request {
    owner: String,
    source_root: PathBuf,
    launcher: PathBuf,
    upstream_url: String,
    branch: String,
    requested_extras: Option<Vec<String>>,
    receipt_dir: PathBuf,
    receipt_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Selection {
    owner: String,
    launcher: String,
    anchor_root: String,
    generation: String,
    source_sha: String,
    lock_sha256: String,
    manifest_sha256: String,
    extras: Vec<String>,
    inventory_sha256: String,
    predecessor_launcher_sha256: String,
    predecessor_launcher_mode: u32,
    predecessor_launcher_uid: u32,
    predecessor_launcher_gid: u32,
}

#[derive(Debug, Deserialize)]
struct PredecessorLauncherMetadata {
    sha256: String,
    mode: u32,
    uid: u32,
    gid: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct Observation {
    pub(crate) owner: String,
    pub(crate) owner_uid: u32,
    pub(crate) source_root: PathBuf,
    pub(crate) launcher: PathBuf,
    pub(crate) anchor_sha: String,
    pub(crate) target_sha: String,
    pub(crate) active_source_sha: String,
    pub(crate) active_root: PathBuf,
    pub(crate) active_generation: Option<PathBuf>,
    pub(crate) extras: Vec<String>,
    pub(crate) lock_sha256: String,
    pub(crate) manifest_sha256: String,
    pub(crate) inventory_sha256: String,
    pub(crate) launcher_sha256: String,
    pub(crate) launcher_mode: u32,
    pub(crate) launcher_uid: u32,
    pub(crate) launcher_gid: u32,
    pub(crate) changed: bool,
    pub(crate) reasons: Vec<String>,
    update_lock: UpdateLock,
}

#[derive(Debug, Clone)]
struct UpdateLock {
    file: Arc<File>,
    common_dir: PathBuf,
    path: PathBuf,
    device: u64,
    inode: u64,
    owner_uid: u32,
    owner_gid: u32,
}

/// Invocation-local custody carried across the framework's post-action observe.
#[derive(Debug, Clone)]
pub(crate) struct ObservationBinding {
    owner: String,
    declared_source_root: PathBuf,
    declared_launcher: PathBuf,
    source_root: PathBuf,
    launcher: PathBuf,
    owner_uid: u32,
    anchor_sha: String,
    target_sha: String,
    update_lock: UpdateLock,
}

impl Request {
    fn from_args(args: &BTreeMap<String, Value>, receipt_dir: &Path, receipt_name: &str) -> Result<Self, String> {
        let mut receipt_components = Path::new(receipt_name).components();
        if receipt_name.is_empty()
            || receipt_name.contains('/')
            || Path::new(receipt_name).is_absolute()
            || !matches!(
                receipt_components.next(),
                Some(std::path::Component::Normal(component)) if !component.is_empty()
            )
            || receipt_components.next().is_some()
            || receipt_name == "routine-child"
        {
            return Err("hermes-maintenance-receipt-name-invalid".into());
        }
        let text = |name: &str| -> Result<String, String> {
            args.get(name).and_then(Value::as_str).map(str::to_owned)
                .ok_or_else(|| format!("hermes-maintenance-argument-{name}-missing"))
        };
        let owner = text("owner")?;
        let source_root = PathBuf::from(text("source_root")?);
        let launcher = PathBuf::from(text("launcher")?);
        let upstream_url = args.get("upstream_url").map(|value| value.as_str()
            .ok_or_else(|| "upstream-url-must-be-string".to_string()))
            .transpose()?.unwrap_or(OFFICIAL_URL).to_owned();
        let branch = args.get("branch").map(|value| value.as_str()
            .ok_or_else(|| "branch-must-be-string".to_string()))
            .transpose()?.unwrap_or("main").to_owned();
        let requested_extras = args.get("extras").map(|value| {
            value.as_array().ok_or_else(|| "hermes-maintenance-extras-not-array".to_string())?
                .iter().map(|entry| entry.as_str().map(str::to_owned)
                    .ok_or_else(|| "hermes-maintenance-extra-not-string".to_string()))
                .collect::<Result<Vec<_>, _>>()
        }).transpose()?;
        Ok(Self { owner, source_root, launcher, upstream_url, branch, requested_extras,
            receipt_dir: receipt_dir.to_path_buf(), receipt_name: receipt_name.to_owned() })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Inventory {
    sha256: String,
    distributions: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub(crate) struct Movement {
    pub(crate) generation: String,
    pub(crate) selected_source_sha: String,
    candidate_launcher: Vec<u8>,
    lock_sha256: String,
    manifest_sha256: String,
    inventory_sha256: String,
    extras: Vec<String>,
    dependency_readiness: String,
    frontdoor: String,
}

#[derive(Debug, Clone, Serialize)]
struct MovementReceipt {
    source: String,
    dependencies: String,
    launcher: String,
    service: String,
}

#[derive(Debug, Clone, Serialize)]
struct RunReceipt {
    ok: bool,
    apply: bool,
    changed: bool,
    status: String,
    source_root: String,
    launcher: String,
    before: Option<String>,
    target: Option<String>,
    after: Option<String>,
    generation: Option<String>,
    source_sha: Option<String>,
    dependency_readiness: Option<String>,
    frontdoor: Option<String>,
    lock_sha256: Option<String>,
    manifest_sha256: Option<String>,
    inventory_sha256: Option<String>,
    extras: Vec<String>,
    reasons: Vec<String>,
    failed_stage: Option<String>,
    predecessor: String,
    movement: MovementReceipt,
    error: Option<String>,
}

pub(crate) fn execute_step(
    step: &crate::tools::routine::ValidatedStep,
    receipt_dir: &Path,
    software: Option<&SoftwareApplyAuthorization>,
    invocation: Option<&InvocationKey>,
) -> Result<OperationOutcome, String> {
    validate_args(&step.args)?;
    let request = Request::from_args(&step.args, receipt_dir, &step.step_id)?;
    let owner = resolve_owner_context(&request.owner)?;
    validate_caller_identity(&owner)?;
    let _owner_scope = OwnerContextScope::install(owner);
    preflight_receipt_shapes(&request, &current_owner_context()?)?;
    let apply = software.is_some();
    let binding_slot = std::cell::RefCell::new(None::<ObservationBinding>);
    let initial_observation_slot = std::cell::RefCell::new(None::<Observation>);
    let movement_slot = std::cell::RefCell::new(None::<Movement>);
    let run = crate::atoms::declaration::execute(
        "hermes-maintenance",
        "converge",
        || {
            let observation = {
                let mut binding = binding_slot.borrow_mut();
                crate::atoms::ask::hermes_maintenance::observe(&request, &mut binding)?
            };
            let mut initial = initial_observation_slot.borrow_mut();
            if initial.is_none() {
                *initial = Some(observation.clone());
            }
            Ok(observation)
        },
        |observation| {
            if apply && observation.changed { DiffDecision::Different } else { DiffDecision::Empty }
        },
        |action_authorization, observation| {
            let software = software.ok_or_else(|| "hermes-maintenance-software-authorization-missing".to_string())?;
            let key = invocation.ok_or_else(|| "hermes-maintenance-invocation-key-missing".to_string())?;
            let movement = crate::atoms::r#do::hermes_maintenance::converge(
                &action_authorization, key, software, &request, observation)
                ?;
            *movement_slot.borrow_mut() = Some(movement.clone());
            Ok(movement)
        },
    );
    match run {
        Ok(crate::atoms::comparison::ComparisonRun::Current { observation, .. }) => {
            if observation.changed && !apply {
                crate::atoms::attest::hermes_maintenance::receipt(
                    &request,
                    &observation,
                    false,
                    None,
                )?;
                return Ok(OperationOutcome { ok: true, changed: false, skipped: true,
                    message: "hermes-maintenance-drift-observed-no-write".into(), command: None });
            }
            if observation.changed { return Err("hermes-maintenance-diff-lost-before-action".into()); }
            Ok(OperationOutcome { ok: true, changed: false, skipped: !apply,
                message: "hermes-maintenance-current".into(), command: None })
        }
        Ok(crate::atoms::comparison::ComparisonRun::Moved {
            observation: _,
            movement,
            ..
        }) => {
            let initial = match initial_observation_slot.borrow().clone() {
                Some(initial) => initial,
                None => {
                    let error = "failed-stage=post-promotion-settlement rollback-refused-debt=initial-observation-missing";
                    if let Err(receipt_error) = crate::atoms::attest::hermes_maintenance::failure(
                        &request,
                        None,
                        apply,
                        "post-promotion-settlement",
                        error,
                    ) {
                        return Err(format!(
                            "{error}; failure-receipt-write-failed: {receipt_error}"
                        ));
                    }
                    return Err(error.into());
                }
            };
            if let Err(receipt_error) = crate::atoms::attest::hermes_maintenance::receipt(
                &request,
                &initial,
                apply,
                Some(&movement),
            ) {
                let error = match restore_predecessor_if_candidate(
                    &request,
                    Path::new(&movement.generation),
                    &movement.candidate_launcher,
                    &initial,
                ) {
                    Ok(state) => format!(
                        "failed-stage=success-receipt-write rollback={state}: {receipt_error}"
                    ),
                    Err(rollback_error) => format!(
                        "failed-stage=success-receipt-write rollback-refused-debt={rollback_error}: {receipt_error}"
                    ),
                };
                if let Err(failure_error) = crate::atoms::attest::hermes_maintenance::failure(
                    &request,
                    Some(&initial),
                    apply,
                    "success-receipt-write",
                    &error,
                ) {
                    return Err(format!(
                        "{error}; failure-receipt-write-failed: {failure_error}"
                    ));
                }
                return Err(error);
            }
            Ok(OperationOutcome { ok: true, changed: true, skipped: false,
                message: "hermes-maintenance-generation-selected".into(), command: None })
        }
        Err(error) => {
            let observed = initial_observation_slot.borrow().clone();
            let error = match (observed.as_ref(), movement_slot.borrow().as_ref()) {
                (Some(initial), Some(movement)) => {
                    match restore_predecessor_if_candidate(
                        &request,
                        Path::new(&movement.generation),
                        &movement.candidate_launcher,
                        initial,
                    ) {
                        Ok(state) => format!(
                            "failed-stage=post-promotion-settlement original-error={error} rollback={state}"
                        ),
                        Err(rollback_error) => format!(
                            "failed-stage=post-promotion-settlement original-error={error} rollback-refused-debt={rollback_error}"
                        ),
                    }
                }
                (None, Some(_)) => format!(
                    "failed-stage=post-promotion-settlement original-error={error} rollback-refused-debt=initial-observation-missing"
                ),
                _ => error,
            };
            if let Err(receipt_error) = crate::atoms::attest::hermes_maintenance::failure(
                &request,
                observed.as_ref(),
                apply,
                "observe-or-act",
                &error,
            ) {
                return Err(format!("{error}; failure-receipt-write-failed: {receipt_error}"));
            }
            Err(error)
        }
    }
}

pub(crate) fn validate_args(args: &BTreeMap<String, Value>) -> Result<(), String> {
    let owner = args.get("owner").and_then(Value::as_str).ok_or("owner-name-required")?;
    if owner.is_empty() || owner.len() > 64 || !owner.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
        return Err("owner-must-be-account-name-not-path".into());
    }
    for name in ["source_root", "launcher"] {
        let value = args.get(name).and_then(Value::as_str).ok_or_else(|| format!("{name}-required"))?;
        if !Path::new(value).is_absolute() || value.contains('\0') {
            return Err(format!("{name}-must-be-absolute-path"));
        }
    }
    if args.get("upstream_url").is_some_and(|v| !v.is_string()) {
        return Err("upstream-url-must-be-string".into());
    }
    if args.get("upstream_url").and_then(Value::as_str).is_some_and(|v| v != OFFICIAL_URL) {
        return Err("upstream-url-must-be-official-hermes-agent".into());
    }
    if args.get("branch").is_some_and(|v| !v.is_string()) {
        return Err("branch-must-be-string".into());
    }
    if args.get("branch").and_then(Value::as_str).is_some_and(|v| v != "main") {
        return Err("upstream-branch-must-be-main".into());
    }
    if let Some(extras) = args.get("extras") {
        let list = extras.as_array().ok_or("extras-must-be-string-array")?;
        let mut seen = BTreeSet::new();
        for extra in list {
            let value = extra.as_str().ok_or("extra-must-be-string")?;
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.') {
                return Err("extra-name-invalid".into());
            }
            if !seen.insert(value) { return Err(format!("duplicate-extra-{value}")); }
        }
    }
    Ok(())
}

/// Read-only observation resolves remote main once, holds the common-dir flock
/// through an eventual action, conservatively observes legacy recovery markers,
/// and compares active bytes against their persisted stamp. The flock does not
/// fence historical marker-only native updaters.
pub(crate) fn observe(
    request: &Request,
    retained: &mut Option<ObservationBinding>,
) -> Result<Observation, String> {
    validate_request(request)?;
    let owner = current_owner_context()?;
    if owner.name != request.owner {
        return Err("maintenance-observation-custody-binding-changed".into());
    }
    validate_caller_identity(&owner)?;
    let first_observation = retained.is_none();
    let (root, launcher, owner_uid, anchor_sha, target_sha, update_lock) =
        if let Some(binding) = retained.as_ref() {
            if request.owner != binding.owner
                || request.source_root != binding.declared_source_root
                || request.launcher != binding.declared_launcher
            {
                return Err("maintenance-observation-custody-binding-changed".into());
            }
            let root = canonical_directory(&request.source_root, "source-root")?;
            if root != binding.source_root {
                return Err("maintenance-observation-source-root-binding-changed".into());
            }
            guard_incomplete_recovery(&root, &request.owner)?;
            let launcher = canonical_parent_file(&request.launcher)?;
            if launcher != binding.launcher {
                return Err("maintenance-observation-launcher-binding-changed".into());
            }
            let owner_uid = owner.uid;
            if owner_uid != binding.owner_uid {
                return Err("maintenance-custody-owner-binding-changed".into());
            }
            let anchor_sha = validate_source_anchor(
                &root,
                owner_uid,
                &binding.update_lock,
                Some(&binding.anchor_sha),
            )?;
            (
                root,
                launcher,
                owner_uid,
                anchor_sha,
                binding.target_sha.clone(),
                binding.update_lock.clone(),
            )
        } else {
            let root = canonical_directory(&request.source_root, "source-root")?;
            guard_incomplete_recovery(&root, &request.owner)?;
            let launcher = canonical_parent_file(&request.launcher)?;
            let owner_uid = owner.uid;
            let update_lock = acquire_update_lock(&root)?;
            let anchor_sha = validate_source_anchor(&root, owner_uid, &update_lock, None)?;
            let target_sha = resolve_remote_once(&request.upstream_url, &request.branch)?;
            (root, launcher, owner_uid, anchor_sha, target_sha, update_lock)
        };

    let launcher_meta = fs::symlink_metadata(&launcher)
        .map_err(|e| format!("launcher-observe-failed: {e}"))?;
    if !launcher_meta.file_type().is_file()
        || launcher_meta.uid() != owner_uid
        || launcher_meta.permissions().mode() & 0o111 == 0
    {
        return Err("launcher-not-owner-controlled-executable-regular-file".into());
    }
    let launcher_bytes = fs::read(&launcher).map_err(|e| format!("launcher-read-failed: {e}"))?;
    let launcher_sha = digest(&launcher_bytes);
    let launcher_text = std::str::from_utf8(&launcher_bytes)
        .map_err(|_| "launcher-not-utf8-recognized-script")?;
    let managed = parse_managed_launcher(launcher_text, &launcher, &request.owner, &root)?;
    let is_legacy = managed.is_none();
    let mut reasons = Vec::new();
    // Prove an old main-era source is on the official path before consulting
    // any PM code from a pinned upstream snapshot for legacy extra selection.
    if is_legacy {
        prove_official_ancestry(&root, &root, &anchor_sha, &anchor_sha, &target_sha)?;
    }

    let (active_root, active_generation, active_source_sha, extras, lock_sha, manifest_sha, inventory_sha) =
        if let Some((generation, selection)) = managed {
            validate_generation_path(&root, &generation, owner_uid)?;
            let source = generation.join("source");
            let venv = generation.join("venv");
            validate_owned_tree(&source, owner_uid, TreeKind::Source)?;
            validate_owned_tree(&venv, owner_uid, TreeKind::Venv(root.clone()))?;
            ensure_clean(&source)?;
            if git_text(&source, &["rev-parse", "--abbrev-ref", "HEAD"])? != "HEAD" {
                return Err("selected-generation-source-not-detached".into());
            }
            let source_sha = git_text(&source, &["rev-parse", "HEAD"])?;
            if source_sha != selection.source_sha {
                reasons.push("selection-source-stamp-drift".into());
            }
            let selected_origin = git_text(&source, &["remote", "get-url", "origin"])?;
            if canonical_url(&selected_origin) != OFFICIAL_URL {
                return Err("selected-generation-origin-mismatch".into());
            }
            let selected_common = source_common_dir(&source)?;
            if selected_common != update_lock.common_dir {
                reasons.push("selected-generation-lock-domain-drift".into());
            } else {
                validate_shared_worktree_git_file(&source, &update_lock.common_dir, owner.uid)?;
            }
            let actual_lock = dependency_lock_digest(&source)?;
            let actual_manifest = dependency_manifest_digest(&source)?;
            let actual_inventory = inventory(&venv)?.sha256;
            if actual_lock != selection.lock_sha256 {
                reasons.push("dependency-lock-drift".into());
            }
            if actual_manifest != selection.manifest_sha256 {
                reasons.push("dependency-manifest-drift".into());
            }
            if actual_inventory != selection.inventory_sha256 {
                reasons.push("installed-inventory-drift".into());
            }
            if request.requested_extras.as_ref().is_some_and(|wanted| {
                normalize_extras(wanted) != selection.extras
            }) {
                reasons.push("explicit-extra-selection-drift".into());
            }
            let builder = find_builder_python(&root)?;
            validate_extras_against_project(&source, &selection.extras, &builder)?;
            if verify_installed_identity(&venv, &source, &builder).is_err() {
                reasons.push("installed-source-identity-unproven".into());
            }
            if front_door_ready(
                &launcher,
                &venv,
                &source,
                Some(&generation),
                &builder,
                &selection.extras,
                &source_sha,
                &root,
                &request.owner,
                false,
            ).is_err() {
                reasons.push("active-launcher-readiness-unproven".into());
            }
            (
                source,
                Some(generation),
                source_sha,
                selection.extras,
                actual_lock,
                actual_manifest,
                actual_inventory,
            )
        } else {
            if !legacy_launcher_matches(launcher_text, &root) {
                return Err("unrecognized-foreign-launcher-preserved".into());
            }
            let venv = find_venv(&root)?;
            validate_owned_tree(&venv, owner_uid, TreeKind::Venv(root.clone()))?;
            let builder = find_builder_python(&root)?;
            verify_installed_identity(&venv, &root, &builder)
                .map_err(|error| format!("legacy-installed-source-identity-unproven: {error}"))?;
            front_door_ready(
                &launcher,
                &venv,
                &root,
                None,
                &builder,
                &[],
                &anchor_sha,
                &root,
                &request.owner,
                false,
            )
            .map_err(|error| format!("legacy-predecessor-not-runnable: {error}"))?;
            let extras = match request.requested_extras.as_ref() {
                Some(values) => normalize_extras(values),
                None => legacy_extras(&root, &venv, &target_sha)?,
            };
            let (legacy_lock, lock_present) = observed_dependency_lock_digest(&root)?;
            if !lock_present {
                reasons.push("dependency-lock-absent".into());
            }
            let current = legacy_pm_current(&root, &venv, &extras)?;
            if !current {
                reasons.push("legacy-dependency-currentness-unproven".into());
            }
            if !legacy_native_update_lock_compatible(&root, &venv, &update_lock.path)? {
                reasons.push("legacy-native-update-lock-compatibility-unproven".into());
            }
            (
                root.clone(),
                None,
                anchor_sha.clone(),
                extras,
                legacy_lock,
                dependency_manifest_digest(&root)?,
                inventory(&venv)?.sha256,
            )
        };

    if active_source_sha != target_sha {
        reasons.push("source-behind-upstream-main".into());
    }
    if request.requested_extras.as_ref().is_some_and(|wanted| {
        normalize_extras(wanted) != extras
    }) && !reasons.iter().any(|reason| reason == "explicit-extra-selection-drift") {
        reasons.push("explicit-extra-selection-drift".into());
    }
    if !is_legacy {
        prove_official_ancestry(&root, &active_root, &anchor_sha, &active_source_sha, &target_sha)?;
    }
    let observation = Observation {
        owner: request.owner.clone(),
        owner_uid,
        source_root: root.clone(),
        launcher: launcher.clone(),
        anchor_sha: anchor_sha.clone(),
        target_sha: target_sha.clone(),
        active_source_sha,
        active_root,
        active_generation,
        extras,
        lock_sha256: lock_sha,
        manifest_sha256: manifest_sha,
        inventory_sha256: inventory_sha,
        launcher_sha256: launcher_sha,
        launcher_mode: launcher_meta.permissions().mode() & 0o7777,
        launcher_uid: launcher_meta.uid(),
        launcher_gid: launcher_meta.gid(),
        changed: !reasons.is_empty(),
        reasons,
        update_lock: update_lock.clone(),
    };
    if first_observation {
        *retained = Some(ObservationBinding {
            owner: request.owner.clone(),
            declared_source_root: request.source_root.clone(),
            declared_launcher: request.launcher.clone(),
            source_root: root,
            launcher,
            owner_uid,
            anchor_sha,
            target_sha,
            update_lock,
        });
    }
    Ok(observation)
}

/// Act only after the declaration minted ActionAuthorization for a non-empty
/// diff and the caller supplied both software apply and invocation custody.
pub(crate) fn apply(
    _authorization: &ActionAuthorization,
    _invocation: &InvocationKey,
    _software: &SoftwareApplyAuthorization,
    request: &Request,
    observed: &Observation,
) -> Result<Movement, String> {
    let owner = current_owner_context()?;
    if owner.name != observed.owner || owner.uid != observed.owner_uid {
        return Err("failed-stage=custody-owner-binding predecessor=preserved".into());
    }
    validate_caller_identity(&owner)
        .map_err(|_| "failed-stage=custody-euid predecessor=preserved".to_string())?;
    if observed
        .reasons
        .iter()
        .any(|reason| reason == "legacy-native-update-lock-compatibility-unproven")
    {
        return Err(
            "failed-stage=legacy-native-update-lock-incompatible predecessor=preserved".into(),
        );
    }
    guard_incomplete_recovery(&observed.source_root, &observed.owner)
        .map_err(|error| format!("failed-stage=native-recovery-debt predecessor=preserved: {error}"))?;
    let _held_update_lock = &observed.update_lock;
    verify_predecessor(request, observed)?;
    let gen_root = observed
        .source_root
        .parent()
        .ok_or("source-root-parent-missing")?
        .join(".hermes-maintenance")
        .join("generations");
    create_owned_directory_tree(&gen_root, observed.owner_uid, owner.gid)?;
    reject_symlink_components(&gen_root)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let prefix = format!(
        "{}-{}",
        &observed.target_sha[..12],
        &observed.manifest_sha256[..12]
    );
    let generation = gen_root.join(format!("{prefix}-{}-{nonce}", std::process::id()));
    create_owned_directory(&generation, owner.uid, owner.gid, 0o700)
        .map_err(|e| format!("failed-stage=generation-create predecessor=preserved: {e}"))?;
    let source = generation.join("source");
    let venv = generation.join("venv");
    let build = generation.join("build");
    prepare_build_dirs(&build)?;
    stage_source(
        &observed.source_root,
        &source,
        &observed.target_sha,
        &observed.anchor_sha,
        &observed.update_lock,
    )?;
    let lock_sha = dependency_lock_digest(&source)?;
    let manifest_sha = dependency_manifest_digest(&source)?;
    let extras = choose_extras(request, observed, &source)?;
    let builder = find_builder_python(&observed.source_root)?;
    validate_extras_against_project(&source, &extras, &builder)?;
    let old_venv = match &observed.active_generation {
        Some(path) => path.join("venv"),
        None => find_venv(&observed.active_root)?,
    };
    build_environment(&source, &venv, &builder, &build, &extras)
        .map_err(|e| format!("failed-stage=dependency-build target={} predecessor=preserved: {e}", observed.target_sha))?;
    ensure_clean(&source).map_err(|e| format!("failed-stage=post-build-source-cleanliness predecessor=preserved: {e}"))?;
    if git_text(&source, &["rev-parse", "HEAD"])? != observed.target_sha {
        return Err("failed-stage=post-build-source-pin predecessor=preserved".into());
    }
    validate_owned_tree(&source, observed.owner_uid, TreeKind::Source)?;
    validate_owned_tree(&venv, observed.owner_uid, TreeKind::Venv(observed.source_root.clone()))?;
    let candidate_launcher = venv.join("bin/hermes");
    front_door_ready(
        &candidate_launcher,
        &venv,
        &source,
        Some(&generation),
        &builder,
        &extras,
        &observed.target_sha,
        &observed.source_root,
        &observed.owner,
        true,
    )
    .map_err(|e| format!("failed-stage=candidate-readiness predecessor=preserved: {e}"))?;
    let new_inventory = inventory(&venv)?;
    let old_inventory = inventory(&old_venv)?;
    let dropped = missing_runtime_distributions(&old_inventory.distributions, &new_inventory.distributions);
    if !dropped.is_empty() {
        return Err(format!("failed-stage=unknown-dependency-custody predecessor=preserved unrepresented-runtime-distributions={}", dropped.join(",")));
    }
    make_tree_readonly(&source)?;
    make_tree_readonly(&venv)?;
    ensure_clean(&source).map_err(|e| format!("failed-stage=sealed-source-cleanliness predecessor=preserved: {e}"))?;
    validate_owned_tree(&source, observed.owner_uid, TreeKind::Source)?;
    validate_owned_tree(&venv, observed.owner_uid, TreeKind::Venv(observed.source_root.clone()))?;
    let final_inventory = inventory(&venv)?;
    let final_lock = dependency_lock_digest(&source)?;
    let final_manifest = dependency_manifest_digest(&source)?;
    let final_source_sha = git_text(&source, &["rev-parse", "HEAD"])?;
    if final_source_sha != observed.target_sha
        || final_lock != lock_sha
        || final_manifest != manifest_sha
    {
        return Err("failed-stage=final-candidate-identity predecessor=preserved".into());
    }
    let current_launcher = fs::read(&observed.launcher)
        .map_err(|e| format!("failed-stage=launcher-reobserve predecessor=preserved: {e}"))?;
    if digest(&current_launcher) != observed.launcher_sha256 {
        return Err("failed-stage=launcher-custody-changed predecessor=preserved".into());
    }
    let backup = generation.join("predecessor-launcher.bin");
    write_new_file(&backup, &current_launcher, 0o600, observed.launcher_uid, observed.launcher_gid)?;
    let selection = Selection {
        owner: observed.owner.clone(),
        launcher: observed.launcher.to_string_lossy().into_owned(),
        anchor_root: observed.source_root.to_string_lossy().into_owned(),
        generation: generation.to_string_lossy().into_owned(),
        source_sha: final_source_sha.clone(),
        lock_sha256: final_lock,
        manifest_sha256: final_manifest,
        extras: extras.clone(),
        inventory_sha256: final_inventory.sha256.clone(),
        predecessor_launcher_sha256: observed.launcher_sha256.clone(),
        predecessor_launcher_mode: observed.launcher_mode,
        predecessor_launcher_uid: observed.launcher_uid,
        predecessor_launcher_gid: observed.launcher_gid,
    };
    let selection_bytes = serde_json::to_vec_pretty(&selection).map_err(|e| e.to_string())?;
    let selection_hash = digest(&selection_bytes);
    write_new_file(
        &generation.join("selection.json"),
        &selection_bytes,
        0o444,
        observed.owner_uid,
        observed.launcher_gid,
    )?;
    write_new_file(
        &generation.join("predecessor-launcher.json"),
        serde_json::to_vec_pretty(&json!({"sha256":observed.launcher_sha256,"mode":observed.launcher_mode,"uid":observed.launcher_uid,"gid":observed.launcher_gid})).map_err(|e|e.to_string())?.as_slice(),
        0o444,
        observed.owner_uid,
        observed.launcher_gid,
    )?;
    sync_directory(&generation)?;
    sync_directory(&gen_root)?;
    let wrapper = launcher_bytes(&generation, &selection_hash);
    let mut replacement = tempfile_launcher(&observed.launcher, &wrapper, observed)?;
    verify_pre_promotion(request, observed)
        .map_err(|e| format!("failed-stage=pre-promotion-revalidation predecessor=preserved: {e}"))?;
    if let Err(error) = promote_launcher(
        &observed.launcher,
        &mut replacement,
        &observed.launcher_sha256,
    ) {
        let rollback = restore_predecessor_if_candidate(request, &generation, &wrapper, observed);
        return Err(format!(
            "failed-stage=atomic-launcher-selection target={} {}: {error}",
            observed.target_sha,
            rollback_description(rollback)
        ));
    }
    let selected_result = (|| -> Result<(PathBuf, Selection), String> {
        let actual = fs::read(&observed.launcher)
            .map_err(|e| format!("launcher-readback-failed: {e}"))?;
        if actual != wrapper {
            return Err("launcher-selection-conflict-foreign-intervention-preserved".into());
        }
        let (selected_generation, selected_stamp) = parse_managed_launcher(
            std::str::from_utf8(&actual).map_err(|_| "selected-launcher-not-utf8")?,
            &observed.launcher,
            &observed.owner,
            &observed.source_root,
        )?
        .ok_or("selection-readback-not-managed")?;
        let selected_source = selected_generation.join("source");
        let selected_venv = selected_generation.join("venv");
        let actual_source_sha = git_text(&selected_source, &["rev-parse", "HEAD"])?;
        let actual_lock = dependency_lock_digest(&selected_source)?;
        let actual_manifest = dependency_manifest_digest(&selected_source)?;
        let actual_inventory = inventory(&selected_venv)?.sha256;
        if selected_generation != generation
            || selected_stamp.source_sha != actual_source_sha
            || selected_stamp.source_sha != observed.target_sha
            || selected_stamp.inventory_sha256 != actual_inventory
            || selected_stamp.lock_sha256 != actual_lock
            || selected_stamp.manifest_sha256 != actual_manifest
        {
            return Err("selection-identity-readback-mismatch".into());
        }
        front_door_ready(
            &observed.launcher,
            &selected_venv,
            &selected_source,
            Some(&selected_generation),
            &builder,
            &selected_stamp.extras,
            &selected_stamp.source_sha,
            &observed.source_root,
            &observed.owner,
            false,
        )?;
        Ok((selected_generation, selected_stamp))
    })();
    let (selected_generation, selected_stamp) = match selected_result {
        Ok(selection) => selection,
        Err(error) => {
            let rollback = restore_predecessor_if_candidate(
                request,
                &generation,
                &wrapper,
                observed,
            );
            return Err(format!(
                "failed-stage=selected-candidate-verification {}: {error}",
                rollback_description(rollback)
            ));
        }
    };
    Ok(Movement {
        generation: selected_generation.to_string_lossy().into_owned(),
        selected_source_sha: selected_stamp.source_sha.clone(),
        candidate_launcher: wrapper,
        lock_sha256: selected_stamp.lock_sha256,
        manifest_sha256: selected_stamp.manifest_sha256,
        inventory_sha256: selected_stamp.inventory_sha256,
        extras: selected_stamp.extras,
        dependency_readiness: "build-environment+native-lock-consistency+installed-inventory".into(),
        frontdoor: "help+installed-identity+pinned-source".into(),
    })
}

pub(crate) fn receipt(
    request: &Request,
    observation: &Observation,
    apply: bool,
    movement: Option<&Movement>,
) -> Result<(), String> {
    let receipt = RunReceipt {
        ok: true,
        apply,
        changed: apply,
        status: if apply { "selected" } else { "proposal" }.into(),
        source_root: observation.source_root.to_string_lossy().into_owned(),
        launcher: observation.launcher.to_string_lossy().into_owned(),
        before: Some(observation.active_source_sha.clone()),
        target: Some(observation.target_sha.clone()),
        after: movement
            .map(|m| m.selected_source_sha.clone())
            .or_else(|| Some(observation.active_source_sha.clone())),
        generation: movement.map(|m| m.generation.clone()),
        source_sha: Some(movement.map(|m| m.selected_source_sha.clone()).unwrap_or_else(|| observation.active_source_sha.clone())),
        dependency_readiness: movement.map(|m| m.dependency_readiness.clone()),
        frontdoor: movement.map(|m| m.frontdoor.clone()),
        lock_sha256: Some(movement.map(|m| m.lock_sha256.clone()).unwrap_or_else(|| observation.lock_sha256.clone())),
        manifest_sha256: Some(movement.map(|m| m.manifest_sha256.clone()).unwrap_or_else(|| observation.manifest_sha256.clone())),
        inventory_sha256: Some(movement.map(|m| m.inventory_sha256.clone()).unwrap_or_else(|| observation.inventory_sha256.clone())),
        extras: movement.map(|m| m.extras.clone()).unwrap_or_else(|| observation.extras.clone()),
        reasons: observation.reasons.clone(),
        failed_stage: None,
        predecessor: if apply { "retained-runnable" } else { "untouched" }.into(),
        movement: MovementReceipt {
            source: if apply { "pinned-source-selected" } else { "none" }.into(),
            dependencies: if apply { "build-environment+native-lock-consistency+installed-inventory" } else { "none" }.into(),
            launcher: if apply { "atomic-replacement-readback" } else { "none" }.into(),
            service: "none".into(),
        },
        error: None,
    };
    write_receipt(request, &receipt)
}

pub(crate) fn failure(
    request: &Request,
    observation: Option<&Observation>,
    apply: bool,
    stage: &str,
    error: &str,
) -> Result<(), String> {
    let parsed = error
        .split_whitespace()
        .find_map(|part| part.strip_prefix("failed-stage="));
    let after = observation.and_then(|o| actual_selected_source_sha(o).ok());
    let before = observation.map(|o| o.active_source_sha.clone());
    let changed = before.as_ref().zip(after.as_ref()).is_some_and(|(a, b)| a != b);
    let predecessor = if error.contains("rollback-refused-debt") {
        "rollback-refused-debt"
    } else if error.contains("rollback=predecessor-restored-runnable-readback") {
        "predecessor-restored-runnable-readback"
    } else if error.contains("rollback=predecessor-retained-runnable-readback") {
        "predecessor-retained-runnable-readback"
    } else if changed {
        "candidate-selected-readback"
    } else {
        "selection-not-confirmed"
    };
    let receipt = RunReceipt {
        ok: false,
        apply,
        changed,
        status: "failed".into(),
        source_root: request.source_root.to_string_lossy().into_owned(),
        launcher: request.launcher.to_string_lossy().into_owned(),
        before,
        target: observation.map(|o| o.target_sha.clone()),
        after,
        generation: None,
        source_sha: observation.map(|o| o.active_source_sha.clone()),
        dependency_readiness: None,
        frontdoor: None,
        lock_sha256: observation.map(|o| o.lock_sha256.clone()),
        manifest_sha256: observation.map(|o| o.manifest_sha256.clone()),
        inventory_sha256: observation.map(|o| o.inventory_sha256.clone()),
        extras: observation.map(|o| o.extras.clone()).unwrap_or_default(),
        reasons: observation.map(|o| o.reasons.clone()).unwrap_or_default(),
        failed_stage: Some(parsed.unwrap_or(stage).to_owned()),
        predecessor: predecessor.into(),
        movement: MovementReceipt {
            source: "not-asserted".into(),
            dependencies: "not-asserted".into(),
            launcher: "not-asserted".into(),
            service: "none".into(),
        },
        error: Some(error.to_owned()),
    };
    write_receipt(request, &receipt)
}
fn write_receipt(request: &Request, receipt: &RunReceipt) -> Result<(), String> {
    let owner = current_owner_context()?;
    preflight_receipt_shapes(request, &owner)?;
    let path = request.receipt_dir.join(format!("{}.json", request.receipt_name));
    let value = serde_json::to_value(receipt).map_err(|error| error.to_string())?;
    write_owned_json_atomic(&path, &value, &owner)?;
    let log = request.receipt_dir.join("harmonia-atoms.log");
    ensure_owned_append_file(&log, &owner)?;
    crate::atoms::attest::attest(
        &log,
        &crate::atoms::Receipt {
            atom: "hermes-maintenance".into(),
            ok: receipt.ok,
            drift: if receipt.changed {
                crate::atoms::Drift::File {
                    expected_sha256: receipt.target.clone().unwrap_or_default(),
                    actual_sha256: receipt.after.clone(),
                }
            } else {
                crate::atoms::Drift::Current
            },
            message: format!(
                "status={} apply={} predecessor={} stage={}",
                receipt.status,
                receipt.apply,
                receipt.predecessor,
                receipt.failed_stage.as_deref().unwrap_or("none")
            ),
        },
        &[],
    )?;
    Ok(())
}

fn preflight_receipt_shapes(request: &Request, owner: &OwnerContext) -> Result<(), String> {
    prepare_receipt_directory(&request.receipt_dir, owner)
        .map_err(|error| format!("hermes-maintenance-receipt-dir: {error}"))?;
    let receipt = request
        .receipt_dir
        .join(format!("{}.json", request.receipt_name));
    validate_receipt_file_shape(&receipt, owner)?;
    let log = request.receipt_dir.join("harmonia-atoms.log");
    validate_attest_log_shape(&log, owner)?;
    check_effective_access(&request.receipt_dir, libc::W_OK | libc::X_OK, "receipt-dir")?;
    if fs::symlink_metadata(&log).is_ok() {
        check_effective_access(&log, libc::W_OK, "attest-log")?;
    }
    Ok(())
}

fn prepare_receipt_directory(path: &Path, owner: &OwnerContext) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("managed-directory-must-be-absolute".into());
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_dir() => {}
            Ok(_) => {
                return Err(format!(
                    "managed-directory-path-not-real-directory-{}",
                    current.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_owned_directory(&current, owner.uid, owner.gid, 0o700)?;
            }
            Err(error) => {
                return Err(format!(
                    "managed-directory-inspect-{}: {error}",
                    current.display()
                ));
            }
        }
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("managed-directory-inspect-{}: {error}", path.display()))?;
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || (metadata.uid() != owner.uid && !(effective_uid == 0 && metadata.uid() == 0))
    {
        return Err(format!("managed-path-owner-mismatch-{}", path.display()));
    }
    Ok(())
}

fn check_effective_access(path: &Path, mode: libc::c_int, label: &str) -> Result<(), String> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("{label}-path-invalid"))?;
    if unsafe { libc::faccessat(libc::AT_FDCWD, path.as_ptr(), mode, libc::AT_EACCESS) } != 0 {
        return Err(format!(
            "{label}-not-writable: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn validate_receipt_file_shape(path: &Path, owner: &OwnerContext) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == owner.uid
                && metadata.gid() == owner.gid
                && metadata.nlink() == 1
                && metadata.permissions().mode() & 0o7777 == 0o644 =>
        {
            Ok(())
        }
        Ok(_) => Err(format!(
            "native-receipt-file-not-owner-controlled-{}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "receipt-observe-failed {}: {error}",
            path.display()
        )),
    }
}

fn validate_attest_log_shape(path: &Path, owner: &OwnerContext) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let effective_uid = unsafe { libc::geteuid() };
            let owner_match = (metadata.uid(), metadata.gid()) == (owner.uid, owner.gid)
                || (effective_uid == 0 && metadata.uid() == 0);
            if metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && owner_match
                && metadata.nlink() == 1
                && metadata.permissions().mode() & 0o7777 == 0o644
            {
                Ok(())
            } else {
                Err(format!(
                    "native-receipt-file-not-owner-controlled-{}",
                    path.display()
                ))
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "native-receipt-file-observe-{}: {error}",
            path.display()
        )),
    }
}

fn ensure_owned_append_file(path: &Path, owner: &OwnerContext) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_attest_log_shape(path, owner),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)
                .map_err(|error| format!("native-receipt-file-create-{}: {error}", path.display()))?;
            let result = (|| -> Result<(), String> {
                let before = file.metadata().map_err(|error| error.to_string())?;
                if (before.uid(), before.gid()) != (owner.uid, owner.gid)
                    && unsafe { libc::fchown(file.as_raw_fd(), owner.uid, owner.gid) } != 0
                {
                    return Err("native-receipt-file-owner-assignment-failed".into());
                }
                file.set_permissions(fs::Permissions::from_mode(0o644))
                    .map_err(|error| format!("native-receipt-file-mode: {error}"))?;
                file.sync_all()
                    .map_err(|error| format!("native-receipt-file-sync: {error}"))?;
                let metadata = file.metadata().map_err(|error| error.to_string())?;
                if (metadata.uid(), metadata.gid(), metadata.nlink()) != (owner.uid, owner.gid, 1) {
                    return Err("native-receipt-file-owner-mismatch".into());
                }
                Ok(())
            })();
            if result.is_err() {
                drop(file);
                let _ = fs::remove_file(path);
            }
            result
        }
        Err(error) => Err(format!("native-receipt-file-observe-{}: {error}", path.display())),
    }
}
fn write_owned_json_atomic(
    path: &Path,
    value: &serde_json::Value,
    owner: &OwnerContext,
) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("receipt-serialize-failed {}: {error}", path.display()))?;
    bytes.push(b'\n');
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.uid() == owner.uid
                && metadata.gid() == owner.gid
                && metadata.nlink() == 1
                && metadata.permissions().mode() & 0o7777 == 0o644 =>
        {
            if fs::read(path)
                .map_err(|error| format!("receipt-read-failed {}: {error}", path.display()))?
                == bytes
            {
                return Ok(());
            }
        }
        Ok(_) => return Err(format!("native-receipt-file-not-owner-controlled-{}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("receipt-observe-failed {}: {error}", path.display())),
    }
    let parent = path.parent().ok_or("native-receipt-parent-missing")?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or("native-receipt-name-invalid")?;
    let temp = parent.join(format!(
        ".{name}.hermes-maintenance-{}-{}.tmp",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)
            .map_err(|error| format!("native-receipt-temp-create: {error}"))?;
        file.write_all(&bytes)
            .map_err(|error| format!("native-receipt-temp-write: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("native-receipt-temp-sync: {error}"))?;
        let before = file.metadata().map_err(|error| error.to_string())?;
        if (before.uid(), before.gid()) != (owner.uid, owner.gid)
            && unsafe { libc::fchown(file.as_raw_fd(), owner.uid, owner.gid) } != 0
        {
            return Err("native-receipt-temp-owner-assignment-failed".into());
        }
        file.set_permissions(fs::Permissions::from_mode(0o644))
            .map_err(|error| format!("native-receipt-temp-mode: {error}"))?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if metadata.uid() != owner.uid || metadata.gid() != owner.gid {
            return Err("native-receipt-temp-owner-mismatch".into());
        }
        drop(file);
        fs::rename(&temp, path).map_err(|error| format!("native-receipt-atomic-promote: {error}"))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("native-receipt-parent-sync: {error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn validate_request(r: &Request) -> Result<(), String> {
    if r.owner.is_empty() || !r.owner.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') { return Err("owner-must-be-account-name-not-path".into()); }
    if r.upstream_url != OFFICIAL_URL { return Err("upstream-url-must-be-official-hermes-agent".into()); }
    if r.branch != "main" { return Err("upstream-branch-must-be-main".into()); }
    Ok(())
}
fn canonical_url(value: &str) -> &str { value.strip_suffix("/").unwrap_or(value) }
fn canonical_directory(path: &Path, name: &str) -> Result<PathBuf,String> {
    let canonical = path.canonicalize().map_err(|e| format!("{name}-unavailable: {e}"))?;
    if !canonical.is_dir() { return Err(format!("{name}-not-directory")); }
    Ok(canonical)
}
fn canonical_parent_file(path: &Path) -> Result<PathBuf,String> {
    if !path.is_absolute() { return Err("launcher-must-be-absolute".into()); }
    let parent = path.parent().ok_or("launcher-parent-missing")?.canonicalize().map_err(|e| format!("launcher-parent-unavailable: {e}"))?;
    if path.file_name().and_then(OsStr::to_str) != Some("hermes") { return Err("launcher-basename-must-be-hermes".into()); }
    let full = parent.join(path.file_name().unwrap());
    let metadata = fs::symlink_metadata(&full).map_err(|e| format!("launcher-unavailable: {e}"))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() { return Err("launcher-must-be-regular-nonsymlink".into()); }
    Ok(full)
}
fn account_uid(name: &str) -> Result<u32, String> {
    let owner = current_owner_context()?;
    if owner.name != name {
        return Err("maintenance-custody-owner-binding-changed".into());
    }
    Ok(owner.uid)
}
fn resolve_remote_once(url: &str, branch: &str) -> Result<String, String> {
    let output = run_owner_command(
        "git",
        &["ls-remote", url, &format!("refs/heads/{branch}")],
        None,
        BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("GIT_OPTIONAL_LOCKS".into(), "0".into()),
            ("GIT_TERMINAL_PROMPT".into(), "0".into()),
        ]),
        900,
    )
    .map_err(|error| format!("upstream-main-resolution-failed: {error}"))?;
    if !output.status.success() {
        return Err(format!("upstream-main-resolution-failed exit={:?}", output.status.code()));
    }
    let text = String::from_utf8(output.stdout).map_err(|_| "upstream-main-response-not-utf8")?;
    let mut fields = text.split_whitespace();
    let sha = fields.next().ok_or("upstream-main-absent")?;
    let reference = fields.next().ok_or("upstream-main-ref-absent")?;
    if reference != format!("refs/heads/{branch}")
        || !matches!(sha.len(), 40 | 64)
        || !sha.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("upstream-main-resolution-malformed".into());
    }
    Ok(sha.to_ascii_lowercase())
}
fn git_text(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = git_output(root, args)?;
    if !output.status.success() {
        return Err(format!(
            "git-{} failed exit={:?}: {}",
            args.join("-"),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
fn git_output(root: &Path, args: &[&str]) -> Result<CapturedOutput, String> {
    let root = root
        .to_str()
        .ok_or_else(|| "maintenance-git-path-not-utf8".to_string())?;
    let mut argv = vec!["-C", root];
    argv.extend_from_slice(args);
    run_owner_command(
        "git",
        &argv,
        None,
        BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("GIT_OPTIONAL_LOCKS".into(), "0".into()),
            ("GIT_TERMINAL_PROMPT".into(), "0".into()),
        ]),
        900,
    )
}
fn git_output_raw(root: &Path, args: &[&str]) -> Result<Output, String> {
    let owner = current_owner_context()?;
    let root = root
        .to_str()
        .ok_or_else(|| "maintenance-git-path-not-utf8".to_string())?;
    let mut argv = vec!["-C", root];
    argv.extend_from_slice(args);
    let mut env = owner_environment(&owner);
    env.insert("PATH".into(), "/usr/bin:/bin".into());
    env.insert("GIT_OPTIONAL_LOCKS".into(), "0".into());
    env.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
    crate::atoms::command::capture_bytes_with_command_bearer_and_env(
        "git",
        &argv,
        None,
        &owner.command_bearer,
        env,
    )
}
fn stage_pinned_snapshot(dest: &Path, target: &str) -> Result<(), String> {
    let dest_arg = dest
        .to_str()
        .ok_or("pinned-pm-snapshot-path-not-utf8")?;
    let git_env = BTreeMap::from([
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("GIT_OPTIONAL_LOCKS".into(), "0".into()),
        ("GIT_TERMINAL_PROMPT".into(), "0".into()),
    ]);
    let init = run_owner_command("git", &["init", "--quiet", dest_arg], None, git_env.clone(), 900)?;
    if !init.status.success() {
        return Err(format!(
            "pinned-pm-snapshot-init-failed: {}",
            String::from_utf8_lossy(&init.stderr).trim()
        ));
    }
    let remote = git_output(dest, &["remote", "add", "origin", OFFICIAL_URL])?;
    if !remote.status.success() {
        return Err(format!(
            "pinned-pm-snapshot-origin-failed: {}",
            String::from_utf8_lossy(&remote.stderr).trim()
        ));
    }
    let fetch = git_output(dest, &["fetch", "--no-tags", "origin", target])?;
    if !fetch.status.success() {
        return Err(format!(
            "pinned-pm-snapshot-fetch-failed: {}",
            String::from_utf8_lossy(&fetch.stderr).trim()
        ));
    }
    let checkout = git_output(dest, &["checkout", "--quiet", "--detach", target])?;
    if !checkout.status.success() {
        return Err(format!(
            "pinned-pm-snapshot-checkout-failed: {}",
            String::from_utf8_lossy(&checkout.stderr).trim()
        ));
    }
    if git_text(dest, &["rev-parse", "HEAD"])? != target {
        return Err("pinned-pm-snapshot-target-mismatch".into());
    }
    if canonical_url(&git_text(dest, &["remote", "get-url", "origin"])?) != OFFICIAL_URL {
        return Err("pinned-pm-snapshot-origin-mismatch".into());
    }
    ensure_clean(dest)
}
fn ensure_clean(root: &Path) -> Result<(),String> {
    let status=git_output(root,&["status","--porcelain=v1","--untracked-files=all"])?;
    if !status.status.success() { return Err("git-status-failed".into()); }
    if !status.stdout.is_empty() { return Err(format!("dirty-source-preserved: {}",String::from_utf8_lossy(&status.stdout).trim())); }
    Ok(())
}
enum TreeKind {
    Source,
    Venv(PathBuf),
}
fn require_owned(path: &Path, uid: u32) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| format!("owned-path-unavailable-{}: {e}", path.display()))?;
    if metadata.uid() != uid {
        return Err(format!("managed-path-owner-mismatch-{}", path.display()));
    }
    Ok(())
}
fn validate_owned_tree(root: &Path, uid: u32, kind: TreeKind) -> Result<(), String> {
    reject_symlink_components(root)?;
    let canonical = root.canonicalize().map_err(|e| format!("owned-tree-unavailable-{}: {e}", root.display()))?;
    if canonical != root {
        return Err(format!("owned-tree-not-canonical-{}", root.display()));
    }
    require_owned_directory(root, uid)?;
    match kind {
        TreeKind::Source => validate_tracked_source(root, uid),
        TreeKind::Venv(source_root) => {
            for path in walkdir(root)? {
                validate_venv_entry(root, &path, uid, &source_root)?;
            }
            Ok(())
        }
    }
}
fn validate_tracked_source(root: &Path, uid: u32) -> Result<(), String> {
    let git_dir = absolute_from(root, &git_text(root, &["rev-parse", "--git-dir"])?)?
        .canonicalize().map_err(|e| format!("source-git-dir-unavailable: {e}"))?;
    let common_dir = absolute_from(root, &git_text(root, &["rev-parse", "--git-common-dir"])?)?
        .canonicalize().map_err(|e| format!("source-git-common-dir-unavailable: {e}"))?;
    for metadata_path in [root.join(".git"), git_dir.clone(), common_dir.clone()] {
        let metadata = fs::symlink_metadata(&metadata_path)
            .map_err(|e| format!("source-git-identity-unavailable-{}: {e}", metadata_path.display()))?;
        if metadata.file_type().is_symlink() || metadata.uid() != uid
            || !(metadata.is_dir() || metadata.is_file())
        {
            return Err(format!("source-git-identity-not-owner-controlled-{}", metadata_path.display()));
        }
    }
    if fs::symlink_metadata(root.join(".git"))
        .map_err(|error| format!("source-git-identity-unavailable: {error}"))?
        .is_file()
    {
        validate_gitdir_file(root, uid, &git_dir, &common_dir)?;
    }
    let listing = git_output_raw(root, &["ls-files", "--cached", "-z"])?;
    if !listing.status.success() {
        return Err(format!("source-tracked-file-list-failed: {}", String::from_utf8_lossy(&listing.stderr).trim()));
    }
    for relative in listing.stdout.split(|byte| *byte == 0).filter(|entry| !entry.is_empty()) {
        validate_tracked_entry(root, Path::new(std::ffi::OsStr::from_bytes(relative)), uid)?;
    }
    Ok(())
}
fn source_common_dir(root: &Path) -> Result<PathBuf, String> {
    absolute_from(root, &git_text(root, &["rev-parse", "--git-common-dir"])?)?
        .canonicalize()
        .map_err(|error| format!("source-git-common-dir-unavailable: {error}"))
}
fn validate_gitdir_file(
    root: &Path,
    uid: u32,
    git_dir: &Path,
    common_dir: &Path,
) -> Result<(), String> {
    let dot_git = root.join(".git");
    let metadata = fs::symlink_metadata(&dot_git)
        .map_err(|error| format!("source-git-file-observe: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.uid() != uid {
        return Err("source-git-file-not-owner-controlled-regular-file".into());
    }
    let text = fs::read_to_string(&dot_git)
        .map_err(|error| format!("source-git-file-read: {error}"))?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() != 1 {
        return Err("source-git-file-format-invalid".into());
    }
    let target = lines[0]
        .strip_prefix("gitdir:")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or("source-git-file-format-invalid")?;
    let pointed = absolute_from(root, target)?
        .canonicalize()
        .map_err(|error| format!("source-git-file-target-unavailable: {error}"))?;
    if pointed != git_dir || !git_dir.starts_with(common_dir.join("worktrees")) {
        return Err("source-git-file-target-mismatch".into());
    }
    let commondir_file = git_dir.join("commondir");
    let commondir_meta = fs::symlink_metadata(&commondir_file)
        .map_err(|error| format!("source-git-commondir-observe: {error}"))?;
    if commondir_meta.file_type().is_symlink() || !commondir_meta.is_file() || commondir_meta.uid() != uid {
        return Err("source-git-commondir-not-owner-controlled-regular-file".into());
    }
    let commondir_text = fs::read_to_string(&commondir_file)
        .map_err(|error| format!("source-git-commondir-read: {error}"))?;
    let common_target = absolute_from(git_dir, commondir_text.trim())?
        .canonicalize()
        .map_err(|error| format!("source-git-commondir-target-unavailable: {error}"))?;
    if common_target != common_dir {
        return Err("source-git-commondir-target-mismatch".into());
    }
    let worktrees = common_dir.join("worktrees");
    let mut current = git_dir;
    loop {
        require_owned_directory(current, uid)?;
        if current == common_dir {
            break;
        }
        current = current
            .parent()
            .filter(|parent| parent.starts_with(common_dir))
            .ok_or("source-git-admin-dir-outside-common-dir")?;
    }
    require_owned_directory(&worktrees, uid)
}
fn validate_shared_worktree_git_file(
    root: &Path,
    expected_common: &Path,
    uid: u32,
) -> Result<(), String> {
    let common = source_common_dir(root)?;
    if common != expected_common {
        return Err("source-worktree-common-dir-mismatch".into());
    }
    let git_dir = absolute_from(root, &git_text(root, &["rev-parse", "--git-dir"])?)?
        .canonicalize()
        .map_err(|error| format!("source-git-dir-unavailable: {error}"))?;
    validate_gitdir_file(root, uid, &git_dir, &common)
}
fn validate_tracked_entry(root: &Path, relative: &Path, uid: u32) -> Result<(), String> {
    let path = root.join(relative);
    let mut parent = root.to_path_buf();
    for component in relative.parent().into_iter().flat_map(Path::components) {
        parent.push(component);
        require_owned_directory(&parent, uid)?;
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|e| format!("tracked-source-entry-unavailable-{}: {e}", path.display()))?;
    if metadata.uid() != uid {
        return Err(format!("tracked-source-owner-mismatch-{}", path.display()));
    }
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(&path).map_err(|e| format!("tracked-source-symlink-read-{}: {e}", path.display()))?;
        if target.is_absolute() {
            return Err(format!("tracked-source-absolute-symlink-refused-{}", path.display()));
        }
        let resolved = path.parent().ok_or("tracked-source-symlink-parent-missing")?.join(target)
            .canonicalize().map_err(|e| format!("tracked-source-symlink-target-unavailable-{}: {e}", path.display()))?;
        if !resolved.starts_with(root) {
            return Err(format!("tracked-source-symlink-escapes-root-{}", path.display()));
        }
    } else if !metadata.is_file() && !metadata.is_dir() {
        return Err(format!("tracked-source-special-file-refused-{}", path.display()));
    }
    Ok(())
}
fn require_owned_directory(path: &Path, uid: u32) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| format!("managed-directory-unavailable-{}: {e}", path.display()))?;
    if metadata.uid() != uid || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("managed-directory-not-owner-controlled-{}", path.display()));
    }
    Ok(())
}
fn validate_venv_entry(root: &Path, path: &Path, uid: u32, source_root: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| format!("owned-tree-entry-unavailable-{}: {e}", path.display()))?;
    if metadata.uid() != uid {
        return Err(format!("owned-tree-owner-mismatch-{}", path.display()));
    }
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        let target = fs::read_link(path).map_err(|e| format!("owned-tree-symlink-read-{}: {e}", path.display()))?;
        if target.is_absolute() {
            validate_interpreter_symlink(root, path, &target, source_root, uid)?;
        } else {
            let resolved = path.parent().ok_or("owned-tree-symlink-parent-missing")?.join(target)
                .canonicalize().map_err(|e| format!("owned-tree-symlink-target-unavailable-{}: {e}", path.display()))?;
            if !resolved.starts_with(root) {
                validate_interpreter_symlink(root, path, &resolved, source_root, uid)?;
            }
        }
    } else if !file_type.is_file() && !file_type.is_dir() {
        return Err(format!("owned-tree-special-file-refused-{}", path.display()));
    }
    Ok(())
}
fn python_executable_name(path: &Path) -> bool {
    path.file_name().and_then(OsStr::to_str).is_some_and(|name| {
        name == "python" || name == "python3" || name.strip_prefix("python3.")
            .is_some_and(|version| !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.'))
    })
}
fn validate_interpreter_symlink(root: &Path, link: &Path, target: &Path, source_root: &Path, uid: u32) -> Result<(), String> {
    let expected_bin = root.join("bin");
    if link.parent() != Some(expected_bin.as_path()) || !python_executable_name(link) {
        return Err(format!("owned-tree-absolute-symlink-refused-{}", link.display()));
    }
    let resolved = target.canonicalize()
        .map_err(|e| format!("owned-python-interpreter-unavailable-{}: {e}", link.display()))?;
    let metadata = fs::metadata(&resolved)
        .map_err(|e| format!("owned-python-interpreter-stat-{}: {e}", resolved.display()))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 || !python_executable_name(&resolved) {
        return Err(format!("owned-python-interpreter-not-executable-{}", resolved.display()));
    }
    let generation_runtime = resolved.ancestors().find(|candidate| {
        candidate.file_name().and_then(OsStr::to_str) == Some("runtime")
            && candidate
                .parent()
                .and_then(Path::file_name)
                .and_then(OsStr::to_str)
                == Some("build")
    });
    if let Some(runtime_root) = generation_runtime {
        let generation = runtime_root
            .parent()
            .and_then(Path::parent)
            .ok_or("managed-generation-runtime-parent-missing")?;
        let approved = generation_runtime_directory(source_root, generation, uid)?;
        if approved.as_path() != runtime_root {
            return Err("managed-generation-runtime-path-mismatch".into());
        }
        let mut current = resolved.as_path();
        loop {
            let entry = fs::symlink_metadata(current)
                .map_err(|e| format!("managed-generation-python-owner-check-{}: {e}", current.display()))?;
            if entry.uid() != uid || entry.file_type().is_symlink() {
                return Err(format!("managed-generation-python-not-owner-controlled-{}", current.display()));
            }
            if current == approved.as_path() {
                return Ok(());
            }
            current = current.parent().ok_or("managed-generation-runtime-not-ancestor")?;
            if !current.starts_with(&approved) {
                return Err("managed-generation-runtime-not-ancestor".into());
            }
        }
    }
    let managed_root = source_root.join(".hermes-runtime/python");
    let managed = managed_root.canonicalize().ok().is_some_and(|base| resolved.starts_with(base));
    if managed {
        let base = managed_root.canonicalize().map_err(|e| format!("managed-python-root-unavailable: {e}"))?;
        let mut current = resolved.as_path();
        loop {
            let entry = fs::symlink_metadata(current)
                .map_err(|e| format!("managed-python-owner-check-{}: {e}", current.display()))?;
            if entry.uid() != uid || entry.file_type().is_symlink() {
                return Err(format!("managed-python-not-source-owned-{}", current.display()));
            }
            if current == base { break; }
            current = current.parent().ok_or("managed-python-root-not-ancestor")?;
            if !current.starts_with(&base) {
                return Err("managed-python-root-not-ancestor".into());
            }
        }
        return Ok(());
    }
    for base in [Path::new("/usr/bin"), Path::new("/usr/local/bin"), Path::new("/bin")] {
        if base.canonicalize().ok().is_some_and(|base| resolved.starts_with(base)) {
            return Ok(());
        }
    }
    Err(format!("owned-python-interpreter-outside-approved-root-{}", resolved.display()))
}
fn generation_runtime_directory(
    anchor_root: &Path,
    generation: &Path,
    owner_uid: u32,
) -> Result<PathBuf, String> {
    reject_symlink_components(generation)?;
    let canonical_generation = generation
        .canonicalize()
        .map_err(|e| format!("generation-unavailable: {e}"))?;
    if canonical_generation.as_path() != generation {
        return Err("generation-path-not-canonical".into());
    }
    let expected_root = anchor_root
        .parent()
        .ok_or("source-root-parent-missing")?
        .join(".hermes-maintenance/generations")
        .canonicalize()
        .map_err(|e| format!("generation-root-unavailable: {e}"))?;
    reject_symlink_components(&expected_root)?;
    require_owned_directory(&expected_root, owner_uid)?;
    if canonical_generation.parent() != Some(expected_root.as_path()) {
        return Err("generation-path-outside-owned-generation-root".into());
    }
    validate_generation_path(anchor_root, &canonical_generation, owner_uid)?;
    let build = canonical_generation.join("build");
    let runtime = build.join("runtime");
    reject_symlink_components(&build)?;
    require_owned_directory(&build, owner_uid)?;
    reject_symlink_components(&runtime)?;
    let canonical_runtime = runtime
        .canonicalize()
        .map_err(|e| format!("generation-runtime-unavailable: {e}"))?;
    if canonical_runtime.as_path() != runtime.as_path() {
        return Err("generation-runtime-path-not-canonical".into());
    }
    require_owned_directory(&canonical_runtime, owner_uid)?;
    Ok(canonical_runtime)
}
fn own_created_directory(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<(), String> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("managed-directory-open-{}: {error}", path.display()))?;
    if unsafe { libc::fchown(directory.as_raw_fd(), uid, gid) } != 0 {
        return Err(format!("managed-directory-owner-{}", path.display()));
    }
    directory
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|error| format!("managed-directory-mode-{}: {error}", path.display()))?;
    let metadata = directory
        .metadata()
        .map_err(|error| format!("managed-directory-stat-{}: {error}", path.display()))?;
    if metadata.uid() != uid {
        return Err(format!("managed-directory-owner-mismatch-{}", path.display()));
    }
    Ok(())
}
fn create_owned_directory(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), String> {
    fs::create_dir(path)
        .map_err(|error| format!("managed-directory-create-{}: {error}", path.display()))?;
    if let Err(error) = own_created_directory(path, uid, gid, mode) {
        let _ = fs::remove_dir(path);
        return Err(error);
    }
    Ok(())
}
fn create_owned_directory_tree(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("managed-directory-must-be-absolute".into());
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(format!(
                        "managed-directory-path-not-real-directory-{}",
                        current.display()
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_owned_directory(&current, uid, gid, 0o700)?;
            }
            Err(error) => {
                return Err(format!(
                    "managed-directory-inspect-{}: {error}",
                    current.display()
                ));
            }
        }
    }
    require_owned(path, uid)
}
struct ScopedTempDir {
    path: PathBuf,
}
impl ScopedTempDir {
    fn path(&self) -> &Path {
        &self.path
    }
}
impl Drop for ScopedTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
fn isolated_tempdir() -> Result<ScopedTempDir, String> {
    let owner = current_owner_context()?;
    let base = owner.home.join(".cache/hermes-maintenance/tmp");
    create_owned_directory_tree(&base, owner.uid, owner.gid)?;
    for _ in 0..128 {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("isolated-temporary-directory-clock: {error}"))?
            .as_nanos();
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!(
            "hermes-maintenance-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                if let Err(error) = own_created_directory(&path, owner.uid, owner.gid, 0o700) {
                    let _ = fs::remove_dir(&path);
                    return Err(error);
                }
                return Ok(ScopedTempDir { path });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("isolated-temporary-directory-failed: {error}")),
        }
    }
    Err("isolated-temporary-directory-name-collision-limit".into())
}
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|e| format!("directory-sync-{}: {e}", path.display()))
}
fn front_door_ready(
    launcher: &Path,
    venv: &Path,
    source: &Path,
    generation: Option<&Path>,
    builder: &Path,
    extras: &[String],
    expected_sha: &str,
    recovery_root: &Path,
    owner: &str,
    native_lock_proof: bool,
) -> Result<(), String> {
    guard_incomplete_recovery(recovery_root, owner)?;
    let runtime = if let Some(generation) = generation {
        if source.parent() != Some(generation)
            || source.file_name().and_then(OsStr::to_str) != Some("source")
        {
            return Err("generation-source-runtime-binding-mismatch".into());
        }
        Some(generation_runtime_directory(recovery_root, generation, account_uid(owner)?)?)
    } else {
        None
    };
    let home = isolated_tempdir()?;
    let hermes_home = home.path().join("hermes");
    let owner_context = current_owner_context()?;
    create_owned_directory_tree(&hermes_home, owner_context.uid, owner_context.gid)
        .map_err(|error| format!("readiness-home-create: {error}"))?;
    let cache_home = home.path().join("cache");
    create_owned_directory_tree(&cache_home, owner_context.uid, owner_context.gid)
        .map_err(|error| format!("readiness-cache-create: {error}"))?;
    let launcher = launcher
        .to_str()
        .ok_or("front-door-launcher-path-not-utf8")?;
    let mut environment = BTreeMap::from([
        ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
        ("HOME".into(), home.path().to_string_lossy().into_owned()),
        ("HERMES_HOME".into(), hermes_home.to_string_lossy().into_owned()),
        ("TMPDIR".into(), home.path().to_string_lossy().into_owned()),
        ("XDG_CACHE_HOME".into(), cache_home.to_string_lossy().into_owned()),
        ("HERMES_DISABLE_LAZY_INSTALLS".into(), "1".into()),
        ("PYTHONDONTWRITEBYTECODE".into(), "1".into()),
    ]);
    if let Some(runtime) = &runtime {
        environment.insert("HERMES_RUNTIME_DIR".into(), runtime.to_string_lossy().into_owned());
    }
    let output = run_owner_command(launcher, &["--help"], None, environment, 900)
        .map_err(|error| format!("front-door-readiness-spawn-failed: {error}"))?;
    if !output.status.success() || output.stdout.is_empty() && output.stderr.is_empty() {
        return Err("front-door-help-not-ready".into());
    }
    verify_installed_identity(venv, source, builder)?;
    // Quiet/current observations compare the persisted lock digest and inventory;
    // run the native PM check only while proving a freshly built candidate.
    if native_lock_proof {
        native_pm_dependency_proof(source, venv, builder, runtime.as_deref())?;
    }
    validate_extras_against_project(source, extras, builder)?;
    ensure_clean(source)?;
    if git_text(source, &["rev-parse", "HEAD"])? != expected_sha {
        return Err("front-door-source-pin-not-ready".into());
    }
    Ok(())
}
fn native_pm_dependency_proof(
    source: &Path,
    venv: &Path,
    builder: &Path,
    runtime: Option<&Path>,
) -> Result<(), String> {
    let home = isolated_tempdir()?;
    let cache = home.path().join("cache");
    let hermes_home = home.path().join("hermes");
    let owner = current_owner_context()?;
    create_owned_directory_tree(&cache, owner.uid, owner.gid)
        .map_err(|error| format!("native-pm-cache-create: {error}"))?;
    create_owned_directory_tree(&hermes_home, owner.uid, owner.gid)
        .map_err(|error| format!("native-pm-home-create: {error}"))?;
    let mut environment = json!({
        "HOME": home.path().to_string_lossy(),
        "HERMES_HOME": hermes_home.to_string_lossy(),
        "TMPDIR": home.path().to_string_lossy(),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HERMES_DISABLE_LAZY_INSTALLS": "1",
        "PYTHONDONTWRITEBYTECODE": "1"
    });
    if let Some(runtime) = runtime {
        environment["HERMES_RUNTIME_DIR"] = json!(
            runtime.to_str().ok_or("generation-runtime-path-not-utf8")?
        );
    }
    let script = r#"import sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from pm.client import check_project_lock
check_project_lock(Path(sys.argv[1]),python=Path(sys.argv[2]),cache=Path(sys.argv[3]),env=json.loads(sys.argv[4]),explicit=True,quiet=True)"#;
    let source_arg = source.to_str().ok_or("source-path-not-utf8")?;
    let python_path = venv.join("bin/python");
    let python_arg = python_path.to_str().ok_or("venv-python-not-utf8")?;
    let cache_arg = cache.to_str().ok_or("native-pm-cache-not-utf8")?;
    let environment_json = environment.to_string();
    let args = [
        "-I", "-B", "-c", script,
        source_arg, python_arg, cache_arg, environment_json.as_str(),
    ];
    let builder = builder
        .to_str()
        .ok_or("native-pm-builder-path-not-utf8")?;
    let mut command_env = BTreeMap::from([
        ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
        ("HOME".into(), home.path().to_string_lossy().into_owned()),
        ("HERMES_HOME".into(), hermes_home.to_string_lossy().into_owned()),
        ("TMPDIR".into(), home.path().to_string_lossy().into_owned()),
        ("HERMES_DISABLE_LAZY_INSTALLS".into(), "1".into()),
        ("PYTHONDONTWRITEBYTECODE".into(), "1".into()),
    ]);
    if let Some(runtime) = runtime {
        command_env.insert("HERMES_RUNTIME_DIR".into(), runtime.to_string_lossy().into_owned());
    }
    let output = run_owner_command(builder, &args, Some(source), command_env, 900)
        .map_err(|error| format!("native-pm-dependency-proof-spawn-failed: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "native-pm-dependency-proof-failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}
fn guard_incomplete_recovery(source_root: &Path, owner: &str) -> Result<(), String> {
    for marker in [
        source_root.join(".update-incomplete"),
        source_root.join(".lazy-refresh-incomplete"),
        source_root.join(".hermes-update-zip-swap"),
        source_root.join(".hermes-update-old"),
        source_root.join("hermes_cli.hermes-update-old"),
    ] {
        match fs::symlink_metadata(&marker) {
            Ok(_) => return Err(format!("incomplete-native-recovery-refused-{}", marker.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("native-recovery-marker-observe-{}: {error}", marker.display())),
        }
    }
    let owner_context = current_owner_context()?;
    if owner_context.name != owner {
        return Err("maintenance-recovery-owner-binding-changed".into());
    }
    let home = owner_context.hermes_home;
    if !home.is_absolute() {
        return Err("pm-install-state-home-not-absolute".into());
    }
    let legacy_native_marker = home.join(".hermes-update-in-progress");
    match fs::symlink_metadata(&legacy_native_marker) {
        Ok(_) => return Err(format!("legacy-native-update-in-progress-refused-{}", legacy_native_marker.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("legacy-native-update-marker-observe-{}: {error}", legacy_native_marker.display())),
    }
    let key = &digest(source_root.to_string_lossy().as_bytes())[..16];
    let pending = home.join("installs").join(key).join("source-completion-pending");
    match fs::symlink_metadata(&pending) {
        Ok(_) => Err(format!("incomplete-native-recovery-refused-{}", pending.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("native-recovery-marker-observe-{}: {error}", pending.display())),
    }
}
fn verify_installed_identity(venv: &Path, source: &Path, _builder: &Path) -> Result<(), String> {
    let script = r#"import sys,tomllib,importlib.metadata as md,importlib.util,json
from pathlib import Path
from urllib.parse import unquote,urlparse
source=Path(sys.argv[1]).resolve(); project=tomllib.loads((source/'pyproject.toml').read_text())['project']
dist=md.distribution(project['name'])
if dist.version != project['version']: raise SystemExit('distribution-version-does-not-match-pinned-source')
entry=project['scripts']['hermes']; module,function=entry.split(':',1)
launcher=Path(sys.prefix,'bin','hermes').read_text()
if f'from {module} import {function}' not in launcher: raise SystemExit('installed-launcher-entrypoint-mismatch')
editable=False
try:
    direct=json.loads(dist.read_text('direct_url.json') or '{}')
except (ValueError,TypeError): raise SystemExit('installed-direct-url-invalid')
if direct.get('dir_info',{}).get('editable') is True:
    parsed=urlparse(direct.get('url',''))
    if parsed.scheme!='file' or parsed.netloc not in ('','localhost'): raise SystemExit('editable-source-url-not-local-file')
    if Path(unquote(parsed.path)).resolve()!=source: raise SystemExit('editable-source-maps-foreign-tree')
    editable=True
roots=('agent','tools','hermes_cli','gateway','tui_gateway','cron','acp_adapter','plugins','providers','hermes_platform','pm')
count=0
for root in roots:
    package=source/root
    if not package.exists(): continue
    if editable:
        spec=importlib.util.find_spec(root)
        if spec is None: raise SystemExit('editable-import-missing:'+root)
        if package.is_dir():
            locations=[Path(p).resolve() for p in (spec.submodule_search_locations or ())]
            if package.resolve() not in locations: raise SystemExit('editable-import-maps-foreign-tree:'+root)
        elif package.with_suffix('.py').is_file():
            if spec.origin is None or Path(spec.origin).resolve()!=package.with_suffix('.py').resolve():
                raise SystemExit('editable-import-maps-foreign-tree:'+root)
        else: continue
    for path in package.rglob('*.py'):
        if not editable:
            installed=Path(dist.locate_file(path.relative_to(source)))
            if not installed.is_file() or installed.read_bytes() != path.read_bytes():
                raise SystemExit('installed-python-source-mismatch:'+path.relative_to(source).as_posix())
        count += 1
if count == 0: raise SystemExit('installed-python-source-inventory-empty')
print(str(count))"#;
    let home = isolated_tempdir()?;
    let owner = current_owner_context()?;
    let hermes_home = home.path().join("hermes");
    create_owned_directory_tree(&hermes_home, owner.uid, owner.gid)?;
    let python_path = venv.join("bin/python");
    let python = python_path
        .to_str()
        .ok_or("installed-identity-python-path-not-utf8")?;
    let output = run_owner_command(
        python,
        &[
            "-I",
            "-B",
            "-c",
            script,
            source.to_str().ok_or("source-path-not-utf8")?,
        ],
        None,
        BTreeMap::from([
            ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
            ("HOME".into(), home.path().to_string_lossy().into_owned()),
            ("HERMES_HOME".into(), hermes_home.to_string_lossy().into_owned()),
            ("TMPDIR".into(), home.path().to_string_lossy().into_owned()),
            ("HERMES_DISABLE_LAZY_INSTALLS".into(), "1".into()),
            ("PYTHONDONTWRITEBYTECODE".into(), "1".into()),
        ]),
        900,
    )
    .map_err(|error| format!("installed-identity-spawn-failed: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "installed-identity-unproven: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}
fn actual_selected_source_sha(observation: &Observation) -> Result<String, String> {
    let bytes = fs::read(&observation.launcher).map_err(|e| format!("launcher-readback-failed: {e}"))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "launcher-readback-not-utf8")?;
    match parse_managed_launcher(text, &observation.launcher, &observation.owner, &observation.source_root)? {
        Some((generation, selection)) => {
            let source = generation.join("source");
            let actual = git_text(&source, &["rev-parse", "HEAD"])?;
            if actual != selection.source_sha {
                return Err("selected-source-readback-stamp-mismatch".into());
            }
            Ok(actual)
        }
        None if digest(&bytes) == observation.launcher_sha256 => Ok(observation.active_source_sha.clone()),
        None => Err("launcher-selection-conflict-readback-unmanaged".into()),
    }
}
fn prove_official_ancestry(
    anchor_root: &Path,
    active_root: &Path,
    anchor_sha: &str,
    active_sha: &str,
    target_sha: &str,
) -> Result<(), String> {
    if ![anchor_sha, active_sha, target_sha].iter().all(|sha| {
        matches!(sha.len(), 40 | 64) && sha.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Err("official-ancestry-invalid-commit-identity".into());
    }
    if anchor_sha == active_sha && active_sha == target_sha {
        return Ok(());
    }
    let target = format!("{target_sha}^{{commit}}");
    for root in [active_root, anchor_root] {
        let target_exists = git_output(root, &["cat-file", "-e", &target])?;
        if !target_exists.status.success() {
            continue;
        }
        let anchor_exists = git_output(root, &["cat-file", "-e", &format!("{anchor_sha}^{{commit}}")])?;
        let active_exists = git_output(root, &["cat-file", "-e", &format!("{active_sha}^{{commit}}")])?;
        if !anchor_exists.status.success() || !active_exists.status.success() {
            continue;
        }
        for older in [anchor_sha, active_sha] {
            if !is_ancestor(root, older, target_sha)? {
                return Err(format!("official-source-diverged-not-ancestor-{older}"));
            }
        }
        return Ok(());
    }
    let scratch = isolated_tempdir()?;
    let repository = scratch.path().join("ancestry.git");
    let repository_arg = repository
        .to_str()
        .ok_or("isolated-ancestry-path-not-utf8")?;
    let git_env = BTreeMap::from([
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("GIT_OPTIONAL_LOCKS".into(), "0".into()),
        ("GIT_TERMINAL_PROMPT".into(), "0".into()),
    ]);
    let init = run_owner_command(
        "git",
        &["init", "--bare", "--quiet", repository_arg],
        None,
        git_env.clone(),
        900,
    )
    .map_err(|error| format!("isolated-ancestry-init-failed: {error}"))?;
    if !init.status.success() {
        return Err(format!(
            "isolated-ancestry-init-failed: {}",
            String::from_utf8_lossy(&init.stderr).trim()
        ));
    }
    let repository_root = repository_arg;
    let fetch = run_owner_command(
        "git",
        &["-C", repository_root, "fetch", "--no-tags", OFFICIAL_URL, target_sha],
        None,
        git_env,
        900,
    )
    .map_err(|error| format!("isolated-ancestry-fetch-failed: {error}"))?;
    if !fetch.status.success() {
        return Err(format!(
            "isolated-ancestry-fetch-failed: {}",
            String::from_utf8_lossy(&fetch.stderr).trim()
        ));
    }
    let resolved_target = git_text(&repository, &["rev-parse", &target])?;
    if resolved_target != target_sha {
        return Err("isolated-ancestry-fetch-target-mismatch".into());
    }
    for older in [anchor_sha, active_sha] {
        let exists = git_output(&repository, &["cat-file", "-e", &format!("{older}^{{commit}}")])?;
        if !exists.status.success() {
            return Err(format!("official-ancestry-object-unavailable-{older}"));
        }
        if !is_ancestor(&repository, older, target_sha)? {
            return Err(format!("official-source-diverged-not-ancestor-{older}"));
        }
    }
    Ok(())
}
fn missing_runtime_distributions(old: &[(String, String)], new: &[(String, String)]) -> Vec<String> {
    const TOOL_DISTRIBUTIONS: &[&str] = &["pip", "setuptools", "wheel", "uv"];
    missing_inventory_names(old, new)
        .into_iter()
        .filter(|entry| {
            let name = entry.split_once("==").map(|(name, _)| name).unwrap_or(entry);
            !TOOL_DISTRIBUTIONS.contains(&name)
        })
        .collect()
}
fn absolute_from(root:&Path,value:&str)->Result<PathBuf,String>{
    let p=PathBuf::from(value); Ok(if p.is_absolute(){p}else{root.join(p)})
}
fn is_ancestor(root:&Path,older:&str,newer:&str)->Result<bool,String>{
    let output=git_output(root,&["merge-base","--is-ancestor",older,newer])?;
    match output.status.code(){Some(0)=>Ok(true),Some(1)=>Ok(false),code=>Err(format!("git-ancestry-check-failed exit={code:?}: {}",String::from_utf8_lossy(&output.stderr).trim()))}
}
fn parse_managed_launcher(
    text: &str,
    launcher: &Path,
    owner: &str,
    anchor_root: &Path,
) -> Result<Option<(PathBuf, Selection)>, String> {
    if !text.lines().any(|line| line == MANAGED_MARKER) {
        return Ok(None);
    }
    let generation = text
        .lines()
        .find_map(|line| line.strip_prefix("# generation="))
        .ok_or("managed-launcher-generation-missing")?;
    let selection_hash = text
        .lines()
        .find_map(|line| line.strip_prefix("# selection-sha256="))
        .ok_or("managed-launcher-selection-hash-missing")?;
    let generation = PathBuf::from(generation);
    validate_generation_path(anchor_root, &generation, account_uid(owner)?)?;
    let bytes = fs::read(generation.join("selection.json"))
        .map_err(|e| format!("selected-generation-stamp-unreadable: {e}"))?;
    if digest(&bytes) != selection_hash {
        return Err("selected-generation-stamp-digest-mismatch".into());
    }
    let selection: Selection = serde_json::from_slice(&bytes)
        .map_err(|e| format!("selected-generation-stamp-invalid: {e}"))?;
    if selection.owner != owner
        || selection.launcher != launcher.to_string_lossy()
        || selection.anchor_root != anchor_root.to_string_lossy()
        || selection.generation != generation.to_string_lossy()
        || text.as_bytes() != launcher_bytes(&generation, selection_hash)
    {
        return Err("selected-generation-ownership-or-wrapper-mismatch".into());
    }
    Ok(Some((generation, selection)))
}
fn legacy_launcher_matches(text: &str, root: &Path) -> bool {
    let executable = root.join("venv/bin/hermes");
    let expected = format!(
        "#!/usr/bin/env bash\nunset PYTHONPATH\nunset PYTHONHOME\nexec \"{}\" \"$@\"\n",
        executable.display()
    );
    text == expected
}
fn validate_generation_path(root: &Path, generation: &Path, owner_uid: u32) -> Result<(), String> {
    let parent = root.parent().ok_or("source-root-parent-missing")?;
    let expected = parent.join(".hermes-maintenance/generations");
    let expected = expected.canonicalize().map_err(|e| format!("generation-root-unavailable: {e}"))?;
    reject_symlink_components(&expected)?;
    let canonical = generation.canonicalize().map_err(|e| format!("generation-unavailable: {e}"))?;
    if canonical == expected || !canonical.starts_with(&expected) {
        return Err("generation-path-outside-owned-generation-root".into());
    }
    reject_symlink_components(&canonical)?;
    require_owned(&canonical, owner_uid)
}
fn find_venv(root:&Path)->Result<PathBuf,String>{
    for p in [root.join("venv"),root.join(".venv")] { if p.join("bin/python").is_file()&&p.join("bin/hermes").is_file(){return Ok(p)} }
    Err("installed-hermes-venv-absent-or-unknown".into())
}
fn find_builder_python(root:&Path)->Result<PathBuf,String>{
    for p in [root.join("venv/bin/python"),root.join(".venv/bin/python")] { if p.is_file(){return p.canonicalize().map_err(|e|e.to_string())} }
    Err("source-root-manager-python-unavailable".into())
}
fn normalize_extras(input:&[String])->Vec<String>{
    let mut values=input.iter().map(|s|s.to_ascii_lowercase()).collect::<Vec<_>>();
    values.retain(|s|s!="all"); values.sort(); values.dedup(); values
}
fn legacy_extras(root:&Path,venv:&Path,target_sha:&str)->Result<Vec<String>,String>{
    // Upstream's own selection reads site-packages without imports. Replace its
    // support probe with a non-spawning marker evaluator; absent packaging on a
    // gated installed extra is a refusal, never a guessed selection.
    // Pre-PM anchors use the exact upstream snapshot already resolved by this
    // observation; the temporary checkout exists only to import pm.extras.
    let snapshot = if root.join("pm/extras.py").is_file() {
        None
    } else {
        Some(isolated_tempdir()?)
    };
    let snapshot_root = snapshot.as_ref().map(|directory| directory.path().join("source"));
    if let Some(path) = snapshot_root.as_deref() {
        stage_pinned_snapshot(path, target_sha)?;
    }
    let module_root = snapshot_root.as_deref().unwrap_or(root);
    let python_path=venv.join("bin/python");
    let script=r#"import sys,json,os,platform
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import pm.extras as e

def safe_supported(extra, environment=None, importable=None):
    marker=e._platform_gates().get(extra)
    if marker is None: return True
    try:
        from packaging.markers import Marker
    except ImportError:
        raise RuntimeError('unsupported-platform-gate-unverifiable:'+extra)
    env=environment or {'sys_platform':sys.platform,'platform_system':platform.system(),'platform_machine':platform.machine(),'os_name':os.name}
    return bool(Marker(marker).evaluate(environment=env))
e.extra_supported=safe_supported
print(json.dumps(e.legacy_selection(Path(sys.argv[2]))))"#;
    let python = python_path
        .to_str()
        .ok_or("legacy-extra-python-path-not-utf8")?;
    let out = run_owner_command(
        python,
        &[
            "-I",
            "-B",
            "-c",
            script,
            module_root.to_str().ok_or("source-root-not-utf8")?,
            root.to_str().ok_or("source-root-not-utf8")?,
        ],
        None,
        BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("PYTHONDONTWRITEBYTECODE".into(), "1".into()),
        ]),
        900,
    )
    .map_err(|error| format!("legacy-extra-observation-failed: {error}"))?;
    if !out.status.success() {
        return Err(format!(
            "legacy-extra-selection-unknown: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let values: Vec<String> = serde_json::from_slice(&out.stdout)
        .map_err(|_| "legacy-extra-selection-invalid")?;
    if values.first().map(String::as_str)!=Some("all"){return Err("legacy-extra-selection-missing-core".into())}
    let extras = normalize_extras(&values[1..].to_vec());
    validate_extras_against_project(module_root, &extras, &python_path)?;
    Ok(extras)
}
fn legacy_native_update_lock_compatible(
    root: &Path,
    venv: &Path,
    lock_path: &Path,
) -> Result<bool, String> {
    let root_arg = root
        .to_str()
        .ok_or("legacy-lock-source-root-not-utf8")?;
    let lock_arg = lock_path
        .to_str()
        .ok_or("legacy-lock-anchor-path-not-utf8")?;
    let code = r#"import importlib
from pathlib import Path
import sys
try:
    update_lock = importlib.import_module('hermes_cli.update_lock')
except Exception:
    print('unproven')
else:
    checkout_lock_path = getattr(update_lock, 'checkout_lock_path', None)
    acquire_checkout = getattr(update_lock, '_acquire_checkout', None)
    if not callable(checkout_lock_path) or not callable(acquire_checkout):
        print('unproven')
    else:
        try:
            source_lock = Path(checkout_lock_path(Path(sys.argv[1]))).resolve()
            held_lock = Path(sys.argv[2]).resolve()
        except Exception:
            print('unproven')
        else:
            print('compatible' if source_lock == held_lock else 'unproven')"#;
    let output = run_python(venv, root, code, &[root_arg, lock_arg])?;
    match output.as_str() {
        "compatible" => Ok(true),
        "unproven" => Ok(false),
        _ => Err("legacy-native-update-lock-observation-invalid".into()),
    }
}
fn legacy_pm_current(root:&Path,venv:&Path,extras:&[String])->Result<bool,String>{
    if !root.join("pm/client.py").is_file() {
        return Ok(false);
    }
    let python_path = venv.join("bin/python");
    let python = python_path
        .to_str()
        .ok_or("legacy-current-python-path-not-utf8")?;
    let script = r#"import sys
sys.path.insert(0,sys.argv[1])
import pm
from pm.client import venv_is_current
print('yes' if venv_is_current(extras=['all',*__import__('json').loads(sys.argv[3])],project_root=__import__('pathlib').Path(sys.argv[2])) else 'no')"#;
    let home = isolated_tempdir()?;
    let owner = current_owner_context()?;
    let hermes_home = home.path().join("hermes");
    create_owned_directory_tree(&hermes_home, owner.uid, owner.gid)?;
    let output = run_owner_command(
        python,
        &[
            "-I",
            "-B",
            "-c",
            script,
            root.to_str().ok_or("source-root-not-utf8")?,
            root.to_str().ok_or("source-root-not-utf8")?,
            &serde_json::to_string(extras).map_err(|error| error.to_string())?,
        ],
        None,
        BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), home.path().to_string_lossy().into_owned()),
            ("HERMES_HOME".into(), hermes_home.to_string_lossy().into_owned()),
            ("HERMES_DISABLE_LAZY_INSTALLS".into(), "1".into()),
            ("PYTHONDONTWRITEBYTECODE".into(), "1".into()),
        ]),
        900,
    )
    .map_err(|error| format!("installed-currentness-observation-failed: {error}"))?;
    if !output.status.success() {
        return Ok(false);
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim() == "yes")
}
fn dependency_manifest_paths(root:&Path)->Result<Vec<PathBuf>,String>{
    let mut out=Vec::new();
    for name in ["pyproject.toml","uv.lock","poetry.lock","Pipfile.lock","setup.cfg","setup.py"] { let p=root.join(name); if p.is_file(){out.push(p)} }
    for prefix in ["requirements","constraints"] { for entry in fs::read_dir(root).map_err(|e|e.to_string())? {let p=entry.map_err(|e|e.to_string())?.path(); if let Some(n)=p.file_name().and_then(OsStr::to_str){if n.starts_with(prefix)&&n.ends_with(".txt")&&p.is_file(){out.push(p)}}} }
    out.sort(); if !out.iter().any(|p|p.file_name().and_then(OsStr::to_str)==Some("pyproject.toml")){return Err("dependency-manifest-pyproject-missing".into())}
    Ok(out)
}
fn dependency_manifest_digest(root:&Path)->Result<String,String>{
    let mut hasher=Sha256::new();
    for path in dependency_manifest_paths(root)? {let name=path.file_name().and_then(OsStr::to_str).ok_or("manifest-name-not-utf8")?;let data=fs::read(&path).map_err(|e|format!("manifest-read-{}: {e}",path.display()))?;hasher.update((name.len() as u64).to_be_bytes());hasher.update(name.as_bytes());hasher.update((data.len() as u64).to_be_bytes());hasher.update(data);}
    Ok(hex(&hasher.finalize()))
}
fn dependency_lock_digest(root:&Path)->Result<String,String>{
    let lock=root.join("uv.lock"); if !lock.is_file(){return Err("dependency-lock-uv-lock-missing".into())}
    let bytes=fs::read(&lock).map_err(|e|format!("dependency-lock-read: {e}"))?; Ok(digest(&bytes))
}
fn observed_dependency_lock_digest(root: &Path) -> Result<(String, bool), String> {
    let lock = root.join("uv.lock");
    match fs::metadata(&lock) {
        Ok(metadata) if metadata.is_file() => Ok((dependency_lock_digest(root)?, true)),
        Ok(_) => Err("dependency-lock-uv-lock-not-regular-file".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(("absent:uv.lock".into(), false))
        }
        Err(error) => Err(format!("dependency-lock-observe: {error}")),
    }
}
fn inventory(venv:&Path)->Result<Inventory,String>{
    let python=venv.join("bin/python"); if !python.is_file(){return Err(format!("venv-python-missing-{}",python.display()))}
    let script=r#"import sys,json,hashlib,os,stat,importlib.metadata as md
from pathlib import Path
roots=sorted(Path(sys.prefix,'lib').glob('python*/site-packages'))
if not roots: raise SystemExit('site-packages-missing')
root=roots[-1]; h=hashlib.sha256(); rows=[]
for d in md.distributions(path=[str(root)]):
    n=d.metadata.get('Name','').strip(); v=d.version
    if not n: raise SystemExit('distribution-name-missing')
    rows.append((n.lower().replace('_','-'),v))
rows.sort()
for base,dirs,files in os.walk(root,followlinks=False):
    dirs.sort(); files.sort()
    for name in dirs[:]:
        if name=='__pycache__': dirs.remove(name); continue
        p=Path(base,name)
        if p.is_symlink():
            rel=p.relative_to(root).as_posix(); h.update(b'L'+rel.encode()+b'\0'+os.readlink(p).encode()+b'\0'); dirs.remove(name)
    for name in files:
        if name.endswith(('.pyc','.pyo')): continue
        p=Path(base,name); rel=p.relative_to(root).as_posix(); st=p.lstat(); h.update(b'F'+rel.encode()+b'\0'+str(stat.S_IMODE(st.st_mode)).encode()+b'\0')
        if stat.S_ISLNK(st.st_mode): h.update(os.readlink(p).encode()+b'\0')
        elif stat.S_ISREG(st.st_mode):
            with p.open('rb') as f:
                while True:
                    b=f.read(1024*1024)
                    if not b: break
                    h.update(b)
        else: raise SystemExit('non-regular-site-package-entry:'+rel)
print(json.dumps({'sha256':h.hexdigest(),'distributions':rows},separators=(',',':')))"#;
    let python = python
        .to_str()
        .ok_or("inventory-python-path-not-utf8")?;
    let output = run_owner_command(
        python,
        &["-I", "-c", script],
        None,
        BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
        900,
    )
    .map_err(|error| format!("inventory-python-failed: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "installed-inventory-failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| format!("installed-inventory-invalid: {error}"))
}
fn validate_extras_against_project(
    source: &Path,
    extras: &[String],
    interpreter: &Path,
) -> Result<(), String> {
    let script = r#"import sys,tomllib
from pathlib import Path
p=Path(sys.argv[1]); d=tomllib.loads((p/'pyproject.toml').read_text()); known=set(d.get('project',{}).get('optional-dependencies',{}))
unknown=sorted(set(sys.argv[2:])-known)
if unknown: raise SystemExit('unknown-extras:'+','.join(unknown))"#;
    let home = isolated_tempdir()?;
    let interpreter = interpreter
        .to_str()
        .ok_or("extra-validation-python-path-not-utf8")?;
    let mut args = vec!["-I", "-B", "-c", script, source.to_str().ok_or("source-path-not-utf8")?];
    args.extend(extras.iter().map(String::as_str));
    let output = run_owner_command(
        interpreter,
        &args,
        None,
        BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), home.path().to_string_lossy().into_owned()),
            ("PYTHONDONTWRITEBYTECODE".into(), "1".into()),
        ]),
        900,
    )
    .map_err(|error| format!("extra-validation-python-failed: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "extra-selection-not-supported: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}
fn build_environment(source:&Path,out:&Path,builder:&Path,build:&Path,extras:&[String])->Result<(),String>{
    let mut selected=vec!["all".to_owned()];selected.extend(extras.iter().cloned());
    let script=r#"import sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from pm.client import build_environment
root,out,cache=map(Path,sys.argv[2:5]); extras=json.loads(sys.argv[5]); env=json.loads(sys.argv[6])
build_environment(source=root,out=out,python=None,cache=cache,env=env,extras=extras,groups=[],all_extras=False,no_install_project=False,frozen=True,explicit=True,timeout=3600)"#;
    let env=json!({"HOME":build.join("home").to_string_lossy(),"HERMES_HOME":build.join("home/hermes").to_string_lossy(),"HERMES_RUNTIME_DIR":build.join("runtime").to_string_lossy(),"TMPDIR":build.join("tmp").to_string_lossy(),"XDG_CACHE_HOME":build.join("cache/xdg").to_string_lossy(),"UV_CACHE_DIR":build.join("cache/uv").to_string_lossy(),"PIP_CACHE_DIR":build.join("cache/pip").to_string_lossy(),"PATH":"/usr/local/bin:/usr/bin:/bin","HERMES_DISABLE_LAZY_INSTALLS":"1","PYTHONDONTWRITEBYTECODE":"1"});
    let cache_path = build.join("cache");
    let selected_json = serde_json::to_string(&selected).map_err(|e| e.to_string())?;
    let env_json = env.to_string();
    let args = [
        "-I",
        "-B",
        "-c",
        script,
        source.to_str().ok_or("source-path-not-utf8")?,
        source.to_str().ok_or("source-path-not-utf8")?,
        out.to_str().ok_or("venv-path-not-utf8")?,
        cache_path.to_str().ok_or("cache-path-not-utf8")?,
        selected_json.as_str(),
        env_json.as_str(),
    ];
    let builder = builder
        .to_str()
        .ok_or("dependency-builder-path-not-utf8")?;
    let output = run_owner_command(
        builder,
        &args,
        Some(source),
        BTreeMap::from([
            ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
            ("HOME".into(), build.join("home").to_string_lossy().into_owned()),
            ("HERMES_HOME".into(), build.join("home/hermes").to_string_lossy().into_owned()),
            ("HERMES_RUNTIME_DIR".into(), build.join("runtime").to_string_lossy().into_owned()),
            ("TMPDIR".into(), build.join("tmp").to_string_lossy().into_owned()),
            ("XDG_CACHE_HOME".into(), build.join("cache/xdg").to_string_lossy().into_owned()),
            ("UV_CACHE_DIR".into(), build.join("cache/uv").to_string_lossy().into_owned()),
            ("PIP_CACHE_DIR".into(), build.join("cache/pip").to_string_lossy().into_owned()),
            ("HERMES_DISABLE_LAZY_INSTALLS".into(), "1".into()),
            ("PYTHONDONTWRITEBYTECODE".into(), "1".into()),
        ]),
        3600,
    )
    .map_err(|error| format!("dependency-builder-spawn-failed: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "dependency-builder-exit={:?} {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}
fn run_python(venv: &Path, source: &Path, code: &str, args: &[&str]) -> Result<String, String> {
    let python_path = venv.join("bin/python");
    let python = python_path
        .to_str()
        .ok_or("candidate-python-path-not-utf8")?;
    let script = format!("import sys;sys.path.insert(0,{:?});{}", source.to_string_lossy(), code);
    let mut argv = vec!["-I", "-B", "-c", script.as_str()];
    argv.extend_from_slice(args);
    let output = run_owner_command(
        python,
        &argv,
        None,
        BTreeMap::from([
            ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
            ("HERMES_DISABLE_LAZY_INSTALLS".into(), "1".into()),
            ("PYTHONDONTWRITEBYTECODE".into(), "1".into()),
        ]),
        900,
    )?;
    if !output.status.success() {
        return Err(format!(
            "candidate-python-exit={:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
fn missing_inventory_names(old:&[(String,String)],new:&[(String,String)])->Vec<String>{
    let have=new.iter().map(|(n,_)|n.as_str()).collect::<BTreeSet<_>>();
    old.iter().filter(|(n,_)|!have.contains(n.as_str())).map(|(n,v)|format!("{n}=={v}")).collect()
}
fn prepare_build_dirs(build: &Path) -> Result<(), String> {
    let owner = current_owner_context()?;
    for path in [
        build.join("home"),
        build.join("home/hermes"),
        build.join("runtime"),
        build.join("tmp"),
        build.join("cache"),
        build.join("cache/xdg"),
        build.join("cache/uv"),
        build.join("cache/pip"),
    ] {
        create_owned_directory_tree(&path, owner.uid, owner.gid)
            .map_err(|error| format!("build-scratch-create: {error}"))?;
    }
    Ok(())
}
fn stage_source(
    anchor_root: &Path,
    dest: &Path,
    target: &str,
    anchor: &str,
    update_lock: &UpdateLock,
) -> Result<(), String> {
    let owner = current_owner_context()?;
    let parent = dest.parent().ok_or("candidate-source-parent-missing")?;
    require_owned_directory(parent, owner.uid)?;
    match fs::symlink_metadata(dest) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return Err("failed-stage=source-worktree-path-already-exists predecessor=preserved".into()),
        Err(error) => return Err(format!("failed-stage=source-worktree-path-observe: {error}")),
    }
    verify_update_lock_binding(anchor_root, update_lock)?;
    let fetch = git_output(anchor_root, &["fetch", "--no-tags", "origin", target])?;
    if !fetch.status.success() {
        return Err(format!(
            "failed-stage=pinned-candidate-fetch target={target} predecessor=preserved exit={:?}: {}",
            fetch.status.code(),
            String::from_utf8_lossy(&fetch.stderr).trim()
        ));
    }
    verify_update_lock_binding(anchor_root, update_lock)?;
    let target_commit = format!("{target}^{{commit}}");
    if git_text(anchor_root, &["rev-parse", "--verify", &target_commit])? != target {
        return Err("failed-stage=pinned-candidate-commit-verification predecessor=preserved".into());
    }
    if !is_ancestor(anchor_root, anchor, target)? {
        return Err("failed-stage=official-ancestry target-not-descendant predecessor=preserved".into());
    }
    let dest_arg = dest
        .to_str()
        .ok_or("candidate-source-path-not-utf8")?;
    let worktree = git_output(
        anchor_root,
        &["worktree", "add", "--detach", dest_arg, target],
    )?;
    if !worktree.status.success() {
        return Err(format!(
            "failed-stage=source-worktree-add target={target} predecessor=preserved exit={:?}: {}",
            worktree.status.code(),
            String::from_utf8_lossy(&worktree.stderr).trim()
        ));
    }
    verify_update_lock_binding(anchor_root, update_lock)?;
    if git_text(dest, &["rev-parse", "HEAD"])? != target {
        return Err("failed-stage=source-pin-verification predecessor=preserved".into());
    }
    if git_text(dest, &["rev-parse", "--abbrev-ref", "HEAD"])? != "HEAD" {
        return Err("failed-stage=source-not-detached predecessor=preserved".into());
    }
    if canonical_url(&git_text(dest, &["remote", "get-url", "origin"])?) != OFFICIAL_URL {
        return Err("failed-stage=source-origin-verification predecessor=preserved".into());
    }
    validate_shared_worktree_git_file(dest, &update_lock.common_dir, owner.uid)?;
    if source_common_dir(dest)? != update_lock.common_dir {
        return Err("failed-stage=source-common-dir-verification predecessor=preserved".into());
    }
    ensure_clean(dest)?;
    if git_text(anchor_root, &["rev-parse", "HEAD"])? != anchor
        || git_text(anchor_root, &["symbolic-ref", "--quiet", "--short", "HEAD"])? != "main"
    {
        return Err("failed-stage=anchor-checkout-changed predecessor=preserved".into());
    }
    Ok(())
}
fn acquire_update_lock(root: &Path) -> Result<UpdateLock, String> {
    let owner = current_owner_context()?;
    let common = source_common_dir(root)?;
    require_owned_directory(&common, owner.uid)?;
    let path = common.join("hermes-update.lock");
    let created = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => Some(file),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
        Err(error) => {
            return Err(format!("upstream-update-lock-open-failed {}: {error}", path.display()));
        }
    };
    let file = if let Some(file) = created {
        let ownership = if unsafe { libc::geteuid() } == 0 {
            unsafe { libc::fchown(file.as_raw_fd(), owner.uid, owner.gid) }
        } else {
            0
        };
        if ownership != 0 {
            let _ = fs::remove_file(&path);
            return Err("upstream-update-lock-owner-assignment-failed".into());
        }
        file.set_permissions(fs::Permissions::from_mode(0o644))
            .map_err(|error| format!("upstream-update-lock-mode-failed: {error}"))?;
        file
    } else {
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|error| format!("upstream-update-lock-open-failed {}: {error}", path.display()))?
    };
    let meta = file.metadata().map_err(|error| error.to_string())?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != owner.uid
        || meta.gid() != owner.gid
        || meta.permissions().mode() & 0o200 == 0
    {
        return Err(format!("upstream-update-lock-not-owner-controlled-single-link {}", path.display()));
    }
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err("upstream-update-lock-held-or-unavailable".into());
    }
    let binding = UpdateLock {
        file: Arc::new(file),
        common_dir: common,
        path,
        device: meta.dev(),
        inode: meta.ino(),
        owner_uid: owner.uid,
        owner_gid: owner.gid,
    };
    verify_update_lock_binding(root, &binding)?;
    Ok(binding)
}
fn verify_update_lock_binding(root: &Path, lock: &UpdateLock) -> Result<(), String> {
    let common = source_common_dir(root)
        .map_err(|_| "upstream-update-lock-binding-changed")?;
    let path = common.join("hermes-update.lock");
    if common != lock.common_dir || path != lock.path {
        return Err("upstream-update-lock-binding-changed".into());
    }
    let held = lock
        .file
        .metadata()
        .map_err(|_| "upstream-update-lock-binding-changed")?;
    let opened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|_| "upstream-update-lock-binding-changed")?;
    let current = opened
        .metadata()
        .map_err(|_| "upstream-update-lock-binding-changed")?;
    let named = fs::symlink_metadata(&path)
        .map_err(|_| "upstream-update-lock-binding-changed")?;
    if named.file_type().is_symlink()
        || !held.is_file()
        || held.nlink() != 1
        || held.dev() != lock.device
        || held.ino() != lock.inode
        || held.uid() != lock.owner_uid
        || held.gid() != lock.owner_gid
        || !current.is_file()
        || current.nlink() != 1
        || current.dev() != lock.device
        || current.ino() != lock.inode
        || current.uid() != lock.owner_uid
        || current.gid() != lock.owner_gid
        || !named.is_file()
        || named.nlink() != 1
        || named.dev() != lock.device
        || named.ino() != lock.inode
        || named.uid() != lock.owner_uid
        || named.gid() != lock.owner_gid
    {
        return Err("upstream-update-lock-binding-changed".into());
    }
    let named_again = fs::symlink_metadata(&path)
        .map_err(|_| "upstream-update-lock-binding-changed")?;
    if named_again.file_type().is_symlink()
        || !named_again.is_file()
        || named_again.nlink() != 1
        || named_again.dev() != lock.device
        || named_again.ino() != lock.inode
        || named_again.uid() != lock.owner_uid
        || named_again.gid() != lock.owner_gid
    {
        return Err("upstream-update-lock-binding-changed".into());
    }
    Ok(())
}
fn validate_source_anchor(
    root:&Path,
    owner_uid:u32,
    update_lock:&UpdateLock,
    expected_anchor:Option<&str>,
)->Result<String,String>{
    verify_update_lock_binding(root,update_lock)?;
    validate_owned_tree(root,owner_uid,TreeKind::Source)?;
    let branch=git_text(root,&["symbolic-ref","--quiet","--short","HEAD"])?;
    if branch!="main"{return Err(format!("source-anchor-branch-must-be-main-actual-{branch}"))}
    let anchor=git_text(root,&["rev-parse","HEAD"])?;
    if expected_anchor.is_some_and(|expected|expected!=anchor.as_str()){return Err("maintenance-observation-anchor-binding-changed".into())}
    ensure_clean(root)?;
    let origin=git_text(root,&["remote","get-url","origin"])?;
    if canonical_url(&origin)!=OFFICIAL_URL{return Err("foreign-origin-preserved".into())}
    Ok(anchor)
}
fn verify_predecessor(r:&Request,o:&Observation)->Result<(),String>{
    verify_update_lock_binding(&o.source_root,&o.update_lock)?;
    if r.owner!=o.owner
        ||canonical_directory(&r.source_root,"source-root")?!=o.source_root
        ||canonical_parent_file(&r.launcher)?!=o.launcher
    {return Err("failed-stage=predecessor-custody-binding-changed predecessor=untouched".into())}
    let bytes=fs::read(&o.launcher).map_err(|e|e.to_string())?;
    if digest(&bytes)!=o.launcher_sha256{return Err("failed-stage=predecessor-launcher-changed predecessor=untouched".into())}
    if git_text(&o.source_root,&["rev-parse","HEAD"])?!=o.anchor_sha{return Err("failed-stage=predecessor-source-changed predecessor=untouched".into())}
    ensure_clean(&o.source_root)?;
    if canonical_url(&git_text(&o.source_root,&["remote","get-url","origin"])? )!=OFFICIAL_URL{return Err("failed-stage=predecessor-origin-changed predecessor=untouched".into())}
    let uid=account_uid(&r.owner)?;
    if uid!=o.owner_uid{return Err("failed-stage=predecessor-custody-binding-changed predecessor=untouched".into())}
    let meta=fs::symlink_metadata(&o.launcher).map_err(|e|e.to_string())?;
    if meta.uid() != uid
        || meta.gid() != o.launcher_gid
        || meta.permissions().mode() & 0o7777 != o.launcher_mode
        || meta.nlink() != 1
        || !meta.file_type().is_file()
        || meta.file_type().is_symlink()
    {
        return Err("failed-stage=predecessor-launcher-ownership predecessor=untouched".into());
    }
    verify_predecessor_runnable(o, true)
        .map_err(|error| format!("failed-stage=predecessor-runnable-evidence predecessor=untouched: {error}"))?;
    Ok(())
}

fn verify_predecessor_runnable(
    observation: &Observation,
    through_launcher: bool,
) -> Result<(), String> {
    let generation = observation.active_generation.as_deref();
    let venv = match generation {
        Some(generation) => generation.join("venv"),
        None => find_venv(&observation.active_root)?,
    };
    let launcher = if through_launcher {
        observation.launcher.clone()
    } else {
        venv.join("bin/hermes")
    };
    let builder = find_builder_python(&observation.source_root)?;
    front_door_ready(
        &launcher,
        &venv,
        &observation.active_root,
        generation,
        &builder,
        &observation.extras,
        &observation.active_source_sha,
        &observation.source_root,
        &observation.owner,
        false,
    )
}

fn verify_pre_promotion(request: &Request, observation: &Observation) -> Result<(), String> {
    let owner = current_owner_context()?;
    if owner.uid != observation.owner_uid
        || request.owner != observation.owner
        || owner.name != request.owner
    {
        return Err("pre-promotion-custody-changed".into());
    }
    validate_caller_identity(&owner)
        .map_err(|_| "pre-promotion-custody-changed".to_string())?;
    verify_update_lock_binding(&observation.source_root, &observation.update_lock)?;
    if canonical_directory(&request.source_root,"source-root")?!=observation.source_root
        ||canonical_parent_file(&request.launcher)?!=observation.launcher
    {
        return Err("pre-promotion-custody-binding-changed".into());
    }
    guard_incomplete_recovery(&observation.source_root, &observation.owner)?;
    let branch = git_text(
        &observation.source_root,
        &["symbolic-ref", "--quiet", "--short", "HEAD"],
    )?;
    if branch != "main" {
        return Err("pre-promotion-anchor-branch-changed".into());
    }
    if git_text(&observation.source_root, &["rev-parse", "HEAD"])? != observation.anchor_sha {
        return Err("pre-promotion-anchor-sha-changed".into());
    }
    ensure_clean(&observation.source_root)
        .map_err(|error| format!("pre-promotion-anchor-not-clean: {error}"))?;
    let origin = git_text(&observation.source_root, &["remote", "get-url", "origin"])?;
    if canonical_url(&origin) != OFFICIAL_URL {
        return Err("pre-promotion-anchor-origin-changed".into());
    }
    let metadata = fs::symlink_metadata(&observation.launcher)
        .map_err(|error| format!("pre-promotion-launcher-observe: {error}"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != observation.launcher_uid
        || metadata.gid() != observation.launcher_gid
        || (metadata.permissions().mode() & 0o7777) != observation.launcher_mode
    {
        return Err("pre-promotion-launcher-metadata-changed".into());
    }
    let bytes = fs::read(&observation.launcher)
        .map_err(|error| format!("pre-promotion-launcher-read: {error}"))?;
    if digest(&bytes) != observation.launcher_sha256 {
        return Err("pre-promotion-launcher-bytes-changed".into());
    }
    Ok(())
}
fn choose_extras(r:&Request,o:&Observation,source:&Path)->Result<Vec<String>,String>{
    let values=if let Some(values)=&r.requested_extras{normalize_extras(values)}else{o.extras.clone()};
    let interpreter = find_builder_python(&o.source_root)?;
    validate_extras_against_project(source, &values, &interpreter)?;
    Ok(values)
}
fn shell_quote(path:&str)->String{format!("'{}'",path.replace('\'', "'\\''"))}
fn launcher_bytes(generation:&Path,selection_hash:&str)->Vec<u8>{
    let executable=shell_quote(&generation.join("venv/bin/hermes").to_string_lossy());
    let runtime = shell_quote(&generation.join("build/runtime").to_string_lossy());
    format!("#!/bin/sh\n{MANAGED_MARKER}\n# generation={}\n# selection-sha256={}\nunset PYTHONHOME PYTHONPATH VIRTUAL_ENV HERMES_RUNTIME_DIR\nexport HERMES_RUNTIME_DIR={runtime}\nexport HERMES_DISABLE_LAZY_INSTALLS=1\nexport PYTHONDONTWRITEBYTECODE=1\nexec {executable} \"$@\"\n",generation.display(),selection_hash).into_bytes()
}
struct TempLauncher{path:PathBuf,file:Option<File>}
impl Drop for TempLauncher {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
fn tempfile_launcher(path: &Path, bytes: &[u8], o: &Observation) -> Result<TempLauncher, String> {
    let parent = path.parent().ok_or("launcher-parent-missing")?;
    let temp = parent.join(format!(
        ".hermes-maintenance-{}-{}.tmp",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(o.launcher_mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)
        .map_err(|error| format!("failed-stage=launcher-temp-create predecessor=preserved: {error}"))?;
    let result = (|| -> Result<(), String> {
        file.write_all(bytes)
            .map_err(|error| format!("launcher-temp-write: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("launcher-temp-sync: {error}"))?;
        if unsafe { libc::fchown(file.as_raw_fd(), o.launcher_uid, o.launcher_gid) } != 0 {
            return Err("launcher-temp-owner-preservation-failed".into());
        }
        file.set_permissions(fs::Permissions::from_mode(o.launcher_mode))
            .map_err(|error| format!("launcher-temp-mode: {error}"))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("launcher-temp-stat: {error}"))?;
        if metadata.uid() != o.launcher_uid || metadata.gid() != o.launcher_gid {
            return Err("launcher-temp-owner-preservation-mismatch".into());
        }
        Ok(())
    })();
    if let Err(error) = result {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    Ok(TempLauncher {
        path: temp,
        file: Some(file),
    })
}
fn promote_launcher(path:&Path,temp:&mut TempLauncher,expected_sha:&str)->Result<(),String>{
    let now=fs::read(path).map_err(|e|e.to_string())?;
    if digest(&now)!=expected_sha{return Err("launcher-changed-before-atomic-rename".into())}
    let _file=temp.file.take().ok_or("launcher-temp-file-missing")?;
    drop(_file);
    fs::rename(&temp.path,path).map_err(|e|format!("atomic-launcher-rename: {e}"))?;
    File::open(path.parent().ok_or("launcher-parent-missing")?).and_then(|f|f.sync_all()).map_err(|e|format!("launcher-parent-sync: {e}"))?;
    Ok(())
}
fn rollback_description(result: Result<&'static str, String>) -> String {
    match result {
        Ok(state) => format!("rollback={state}"),
        Err(error) => format!("rollback-refused-debt={error}"),
    }
}

fn restore_predecessor_if_candidate(
    request: &Request,
    generation_path: &Path,
    candidate: &[u8],
    observation: &Observation,
) -> Result<&'static str, String> {
    let owner = current_owner_context()?;
    if owner.name != observation.owner || owner.uid != observation.owner_uid {
        return Err("rollback-owner-binding-changed".into());
    }
    validate_caller_identity(&owner)
        .map_err(|_| "rollback-caller-identity-changed".to_string())?;
    verify_update_lock_binding(&observation.source_root, &observation.update_lock)?;
    if request.owner != observation.owner
        || canonical_directory(&request.source_root, "source-root")? != observation.source_root
        || canonical_parent_file(&request.launcher)? != observation.launcher
    {
        return Err("rollback-request-binding-changed".into());
    }
    guard_incomplete_recovery(&observation.source_root, &observation.owner)?;
    if git_text(&observation.source_root, &["symbolic-ref", "--quiet", "--short", "HEAD"])?
        != "main"
        || git_text(&observation.source_root, &["rev-parse", "HEAD"])? != observation.anchor_sha
    {
        return Err("rollback-anchor-binding-changed".into());
    }
    ensure_clean(&observation.source_root)
        .map_err(|error| format!("rollback-anchor-not-clean: {error}"))?;
    if canonical_url(&git_text(&observation.source_root, &["remote", "get-url", "origin"])?)
        != OFFICIAL_URL
    {
        return Err("rollback-anchor-origin-changed".into());
    }

    let generation = generation_path
        .canonicalize()
        .map_err(|error| format!("rollback-generation-unavailable: {error}"))?;
    if generation.as_path() != generation_path {
        return Err("rollback-generation-path-not-canonical".into());
    }
    validate_generation_path(&observation.source_root, &generation, observation.owner_uid)?;

    let selection_path = generation.join("selection.json");
    let selection_meta = fs::symlink_metadata(&selection_path)
        .map_err(|error| format!("rollback-selection-observe: {error}"))?;
    if !selection_meta.file_type().is_file()
        || selection_meta.file_type().is_symlink()
        || selection_meta.uid() != observation.owner_uid
        || selection_meta.gid() != observation.launcher_gid
        || selection_meta.nlink() != 1
        || selection_meta.permissions().mode() & 0o7777 != 0o444
    {
        return Err("rollback-selection-not-owner-controlled".into());
    }
    let selection_bytes = fs::read(&selection_path)
        .map_err(|error| format!("rollback-selection-read: {error}"))?;
    let selection_hash = digest(&selection_bytes);
    let selection: Selection = serde_json::from_slice(&selection_bytes)
        .map_err(|error| format!("rollback-selection-invalid: {error}"))?;
    if selection.owner != observation.owner
        || selection.launcher != observation.launcher.to_string_lossy()
        || selection.anchor_root != observation.source_root.to_string_lossy()
        || selection.generation != generation.to_string_lossy()
        || selection.source_sha != observation.target_sha
        || selection.predecessor_launcher_sha256 != observation.launcher_sha256
        || selection.predecessor_launcher_mode != observation.launcher_mode
        || selection.predecessor_launcher_uid != observation.launcher_uid
        || selection.predecessor_launcher_gid != observation.launcher_gid
    {
        return Err("rollback-selection-target-anchor-owner-binding-mismatch".into());
    }
    if candidate != launcher_bytes(&generation, &selection_hash).as_slice() {
        return Err("rollback-candidate-wrapper-bytes-mismatch".into());
    }
    let candidate_text = std::str::from_utf8(candidate)
        .map_err(|_| "rollback-candidate-wrapper-not-utf8")?;
    match parse_managed_launcher(
        candidate_text,
        &observation.launcher,
        &observation.owner,
        &observation.source_root,
    )? {
        Some((selected_generation, selected))
            if selected_generation == generation && selected.source_sha == observation.target_sha =>
        {
        }
        _ => return Err("rollback-candidate-wrapper-binding-mismatch".into()),
    }

    let backup = generation.join("predecessor-launcher.bin");
    let backup_meta = fs::symlink_metadata(&backup)
        .map_err(|error| format!("rollback-predecessor-backup-observe: {error}"))?;
    if !backup_meta.file_type().is_file()
        || backup_meta.file_type().is_symlink()
        || backup_meta.uid() != observation.launcher_uid
        || backup_meta.gid() != observation.launcher_gid
        || backup_meta.nlink() != 1
        || backup_meta.permissions().mode() & 0o7777 != 0o600
    {
        return Err("rollback-predecessor-backup-not-owner-controlled".into());
    }
    let predecessor = fs::read(&backup)
        .map_err(|error| format!("rollback-predecessor-backup-read: {error}"))?;
    if digest(&predecessor) != observation.launcher_sha256 {
        return Err("rollback-predecessor-backup-hash-mismatch".into());
    }
    let metadata_path = generation.join("predecessor-launcher.json");
    let metadata = fs::symlink_metadata(&metadata_path)
        .map_err(|error| format!("rollback-predecessor-metadata-observe: {error}"))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != observation.owner_uid
        || metadata.gid() != observation.launcher_gid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o444
    {
        return Err("rollback-predecessor-metadata-not-owner-controlled".into());
    }
    let predecessor_metadata: PredecessorLauncherMetadata = serde_json::from_slice(
        &fs::read(&metadata_path)
            .map_err(|error| format!("rollback-predecessor-metadata-read: {error}"))?,
    )
    .map_err(|error| format!("rollback-predecessor-metadata-invalid: {error}"))?;
    if predecessor_metadata.sha256 != observation.launcher_sha256
        || predecessor_metadata.mode != observation.launcher_mode
        || predecessor_metadata.uid != observation.launcher_uid
        || predecessor_metadata.gid != observation.launcher_gid
    {
        return Err("rollback-predecessor-metadata-observation-mismatch".into());
    }

    let current_meta = fs::symlink_metadata(&observation.launcher)
        .map_err(|error| format!("launcher-rollback-stat: {error}"))?;
    if !current_meta.file_type().is_file()
        || current_meta.file_type().is_symlink()
        || current_meta.uid() != observation.launcher_uid
        || current_meta.gid() != observation.launcher_gid
        || current_meta.permissions().mode() & 0o7777 != observation.launcher_mode
        || current_meta.nlink() != 1
    {
        return Err("launcher-rollback-metadata-cas-refused".into());
    }
    let current = fs::read(&observation.launcher)
        .map_err(|error| format!("launcher-rollback-readback: {error}"))?;
    if current == predecessor {
        verify_predecessor_runnable(observation, true)
            .map_err(|error| format!("rollback-predecessor-runnable-unproven: {error}"))?;
        return Ok("predecessor-retained-runnable-readback");
    }
    if current != candidate {
        return Err("launcher-rollback-cas-refused-foreign-intervention-preserved".into());
    }
    verify_predecessor_runnable(observation, false)
        .map_err(|error| format!("rollback-predecessor-runnable-unproven: {error}"))?;

    let mut replacement = tempfile_launcher(&observation.launcher, &predecessor, observation)?;
    let reobserved_meta = fs::symlink_metadata(&observation.launcher)
        .map_err(|error| format!("launcher-rollback-reobserve-stat: {error}"))?;
    let reobserved = fs::read(&observation.launcher)
        .map_err(|error| format!("launcher-rollback-reobserve: {error}"))?;
    if reobserved != candidate
        || reobserved_meta.uid() != observation.launcher_uid
        || reobserved_meta.gid() != observation.launcher_gid
        || reobserved_meta.permissions().mode() & 0o7777 != observation.launcher_mode
        || reobserved_meta.nlink() != 1
        || !reobserved_meta.file_type().is_file()
        || reobserved_meta.file_type().is_symlink()
    {
        return Err("launcher-rollback-cas-lost-foreign-intervention-preserved".into());
    }
    let _file = replacement
        .file
        .take()
        .ok_or("launcher-rollback-temp-file-missing")?;
    drop(_file);
    fs::rename(&replacement.path, &observation.launcher)
        .map_err(|error| format!("launcher-rollback-rename: {error}"))?;
    File::open(
        observation
            .launcher
            .parent()
            .ok_or("launcher-parent-missing")?,
    )
    .and_then(|file| file.sync_all())
    .map_err(|error| format!("launcher-rollback-parent-sync: {error}"))?;
    let readback_meta = fs::symlink_metadata(&observation.launcher)
        .map_err(|error| format!("launcher-rollback-readback-stat: {error}"))?;
    let readback = fs::read(&observation.launcher)
        .map_err(|error| format!("launcher-rollback-readback: {error}"))?;
    if readback != predecessor
        || readback_meta.uid() != observation.launcher_uid
        || readback_meta.gid() != observation.launcher_gid
        || readback_meta.permissions().mode() & 0o7777 != observation.launcher_mode
        || readback_meta.nlink() != 1
        || !readback_meta.file_type().is_file()
        || readback_meta.file_type().is_symlink()
    {
        return Err("launcher-rollback-predecessor-readback-mismatch".into());
    }
    verify_predecessor_runnable(observation, true)
        .map_err(|error| format!("rollback-restored-predecessor-runnable-unproven: {error}"))?;
    Ok("predecessor-restored-runnable-readback")
}
fn write_new_file(path: &Path, bytes: &[u8], mode: u32, uid: u32, gid: u32) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .map_err(|error| format!("generation-file-create-{}: {error}", path.display()))?;
    let result = (|| -> Result<(), String> {
        file.write_all(bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
            return Err(format!("generation-file-owner-{}", path.display()));
        }
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|error| error.to_string())?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if metadata.uid() != uid || metadata.gid() != gid {
            return Err(format!("generation-file-owner-mismatch-{}", path.display()));
        }
        Ok(())
    })();
    if result.is_err() {
        drop(file);
        let _ = fs::remove_file(path);
    }
    result
}
fn make_tree_readonly(root:&Path)->Result<(),String>{
    for entry in walkdir(root)? {
        let metadata=fs::symlink_metadata(&entry).map_err(|e|e.to_string())?;
        if metadata.file_type().is_symlink(){continue}
        let mode=metadata.permissions().mode();
        if metadata.is_dir(){fs::set_permissions(&entry,fs::Permissions::from_mode((mode&0o555)|0o500)).map_err(|e|e.to_string())?}
        else if metadata.is_file(){fs::set_permissions(&entry,fs::Permissions::from_mode(mode&!0o222)).map_err(|e|e.to_string())?}
    }
    Ok(())
}
fn walkdir(root:&Path)->Result<Vec<PathBuf>,String>{
    let mut out=vec![root.to_path_buf()];let mut i=0;
    while i<out.len(){let p=out[i].clone();i+=1;if fs::symlink_metadata(&p).map_err(|e|e.to_string())?.is_dir(){for e in fs::read_dir(&p).map_err(|e|e.to_string())?{out.push(e.map_err(|e|e.to_string())?.path())}}}
    out.sort_by_key(|p|std::cmp::Reverse(p.components().count()));Ok(out)
}
fn reject_symlink_components(path:&Path)->Result<(),String>{
    let mut current=PathBuf::new();for c in path.components(){current.push(c);if let Ok(m)=fs::symlink_metadata(&current){if m.file_type().is_symlink(){return Err(format!("managed-generation-path-has-symlink-{}",current.display()))}}}
    Ok(())
}
fn digest(bytes:&[u8])->String{let hash=Sha256::digest(bytes);hex(&hash)}
fn hex(bytes:&[u8])->String{const H:&[u8]=b"0123456789abcdef";let mut s=String::with_capacity(bytes.len()*2);for b in bytes{s.push(H[(b>>4)as usize]as char);s.push(H[(b&15)as usize]as char)}s}
