//! Observe and repair the declared Hermes installation through its native updater.
use crate::atoms::comparison::{ActionAuthorization, DiffDecision};
use crate::atoms::r#do::InvocationKey;
use crate::{OperationOutcome, SoftwareApplyAuthorization};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{CString, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const OFFICIAL_URL: &str = "https://github.com/NousResearch/hermes-agent.git";
const OFFICIAL_URL_NO_GIT: &str = "https://github.com/NousResearch/hermes-agent";
const OFFICIAL_SSH_SCP: &str = "git@github.com:NousResearch/hermes-agent.git";
const OFFICIAL_SSH_SCP_NO_GIT: &str = "git@github.com:NousResearch/hermes-agent";
const OFFICIAL_SSH: &str = "ssh://git@github.com/NousResearch/hermes-agent.git";
const OFFICIAL_SSH_NO_GIT: &str = "ssh://git@github.com/NousResearch/hermes-agent";
const OWNER_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
const UPDATER_TIMEOUT_SECS: u64 = 3600;
const COMMAND_OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
const UPDATER_OUTPUT_TAIL_BYTES: usize = 4096;
const UPDATE_MARKER_MAX_AGE_SECS: f64 = 20.0 * 60.0;
const UPDATE_MARKER_FUTURE_SKEW_SECS: f64 = 5.0;
const UPDATE_MARKER_CREATE_TIME_TOLERANCE_SECS: f64 = 2.0;
const UPDATE_MARKER_MAX_BYTES: u64 = 8192;
const LAUNCHER_MAX_BYTES: u64 = 1024 * 1024;

#[derive(Clone)]
struct OwnerContext {
    name: String,
    uid: u32,
    gid: u32,
    home: PathBuf,
    hermes_home: PathBuf,
    command_bearer: crate::atoms::command::CommandBearer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReceiptCustody {
    uid: u32,
    gid: u32,
}

impl ReceiptCustody {
    fn current() -> Self {
        Self {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        }
    }

    fn validate_current(self) -> Result<(), String> {
        if self == Self::current() {
            Ok(())
        } else {
            Err("native-receipt-engine-custody-changed".into())
        }
    }
}

thread_local! {
    static OWNER_CONTEXT: std::cell::RefCell<Option<OwnerContext>> = const { std::cell::RefCell::new(None) };
}

struct OwnerContextScope(Option<OwnerContext>);
impl OwnerContextScope {
    fn install(owner: OwnerContext) -> Self {
        Self(OWNER_CONTEXT.with(|slot| slot.replace(Some(owner))))
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
    if home_metadata.file_type().is_symlink()
        || !home_metadata.is_dir()
        || home_metadata.uid() != uid
    {
        return Err("owner-account-home-not-owner-controlled".into());
    }
    let hermes_home = home.join(".hermes");
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

struct CapturedOutput {
    status: CapturedStatus,
    stdout: Vec<u8>,
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

fn owner_environment(owner: &OwnerContext) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("HOME".into(), owner.home.to_string_lossy().into_owned()),
        ("USER".into(), owner.name.clone()),
        ("LOGNAME".into(), owner.name.clone()),
        (
            "XDG_CONFIG_HOME".into(),
            owner.home.join(".config").to_string_lossy().into_owned(),
        ),
        ("PATH".into(), OWNER_PATH.into()),
        (
            "HERMES_HOME".into(),
            owner.hermes_home.to_string_lossy().into_owned(),
        ),
        (
            "TMPDIR".into(),
            owner
                .home
                .join(".cache/hermes-maintenance/tmp")
                .to_string_lossy()
                .into_owned(),
        ),
    ])
}

fn run_owner_command(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    extra_env: BTreeMap<String, String>,
    timeout_secs: u64,
) -> Result<CapturedOutput, String> {
    let owner = current_owner_context()?;
    let mut env = owner_environment(&owner);
    env.extend(extra_env);
    let cwd = cwd
        .map(|path| {
            path.to_str()
                .ok_or_else(|| "maintenance-command-cwd-not-utf8".to_string())
        })
        .transpose()?;
    let output = crate::atoms::command::capture_bytes_with_command_bearer_and_env(
        program,
        args,
        cwd,
        &owner.command_bearer,
        env,
        timeout_secs,
        COMMAND_OUTPUT_LIMIT,
    )?;
    Ok(CapturedOutput {
        status: CapturedStatus {
            success: output.status.success(),
            code: output.status.code(),
        },
        stdout: output.stdout,
    })
}

struct UpdaterOutput {
    status: CapturedStatus,
    stdout_tail: String,
    stderr_tail: String,
    error: Option<String>,
}

fn run_owner_updater(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    extra_env: BTreeMap<String, String>,
    timeout_secs: u64,
) -> Result<UpdaterOutput, String> {
    let owner = current_owner_context()?;
    let mut env = owner_environment(&owner);
    env.extend(extra_env);
    let cwd = cwd
        .map(|path| {
            path.to_str()
                .ok_or_else(|| "maintenance-command-cwd-not-utf8".to_string())
        })
        .transpose()?;
    let output = crate::atoms::command::capture_bytes_with_command_bearer_and_env_tail(
        program,
        args,
        cwd,
        &owner.command_bearer,
        env,
        timeout_secs,
        COMMAND_OUTPUT_LIMIT,
        UPDATER_OUTPUT_TAIL_BYTES,
    )?;
    Ok(UpdaterOutput {
        status: CapturedStatus {
            success: output
                .status
                .as_ref()
                .is_some_and(std::process::ExitStatus::success),
            code: output.status.as_ref().and_then(std::process::ExitStatus::code),
        },
        stdout_tail: bounded_utf8_tail(&output.stdout_tail, UPDATER_OUTPUT_TAIL_BYTES),
        stderr_tail: bounded_utf8_tail(&output.stderr_tail, UPDATER_OUTPUT_TAIL_BYTES),
        error: output.error,
    })
}

fn bounded_utf8_tail(bytes: &[u8], limit: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut start = text.len();
    for (index, _) in text.char_indices().rev() {
        if text.len() - index > limit {
            break;
        }
        start = index;
    }
    text[start..].to_owned()
}

#[derive(Debug, Clone)]
pub(crate) struct Request {
    owner: String,
    source_root: PathBuf,
    launcher: PathBuf,
    upstream_url: String,
    branch: String,
    receipt_dir: PathBuf,
    receipt_name: String,
    receipt_custody: ReceiptCustody,
}

#[derive(Debug, Clone)]
pub(crate) struct Observation {
    pub(crate) owner: String,
    pub(crate) owner_uid: u32,
    pub(crate) source_root: PathBuf,
    pub(crate) launcher: PathBuf,
    pub(crate) anchor_sha: String,
    pub(crate) target_sha: String,
    pub(crate) launcher_sha256: String,
    pub(crate) branch: Option<String>,
    native_stamp_fields: Option<InstallStampFields>,
    pub(crate) changed: bool,
    pub(crate) reasons: Vec<String>,
}

/// Invocation-local identity binding; the installed HEAD is expected to move
/// between the first and post-action observations.
#[derive(Debug, Clone)]
pub(crate) struct ObservationBinding {
    owner: String,
    declared_source_root: PathBuf,
    declared_launcher: PathBuf,
    source_root: PathBuf,
    launcher: PathBuf,
    owner_uid: u32,
    target_sha: String,
}

#[derive(Debug, Clone)]
struct RollbackSnapshot {
    source_root: PathBuf,
    launcher: PathBuf,
    launcher_directory: PathBuf,
    launcher_directory_mode: u32,
    launcher_directory_uid: u32,
    launcher_directory_gid: u32,
    launcher_directory_dev: u64,
    launcher_directory_ino: u64,
    pre_sha: String,
    branch: Option<String>,
    launchers: Vec<LauncherSnapshot>,
    owner_uid: u32,
}

#[derive(Debug, Clone)]
struct LauncherSnapshot {
    path: PathBuf,
    bytes: Vec<u8>,
    mode: u32,
    uid: u32,
    gid: u32,
}

#[derive(Debug, Clone)]
struct LauncherDirectorySnapshot {
    path: PathBuf,
    mode: u32,
    uid: u32,
    gid: u32,
    dev: u64,
    ino: u64,
}

#[derive(Debug, Clone, Serialize)]
struct RestoredLauncher {
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UntrackedWorkSnapshot {
    path: Vec<u8>,
    mode: u32,
    uid: u32,
    gid: u32,
    symlink: bool,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalWorkSnapshot {
    status: Vec<u8>,
    staged_diff: Vec<u8>,
    worktree_diff: Vec<u8>,
    untracked: Vec<UntrackedWorkSnapshot>,
}

#[derive(Debug, Clone)]
pub(crate) struct Movement {
    pub(crate) pre_sha: String,
    pub(crate) target_sha: String,
    pub(crate) post_sha: Option<String>,
    pub(crate) movement: String,
    pub(crate) stage: String,
    pub(crate) updater_exit_code: Option<i32>,
    pub(crate) updater_stdout_tail: String,
    pub(crate) updater_stderr_tail: String,
    restored_launchers: Vec<RestoredLauncher>,
    pub(crate) stash_names_created: Vec<String>,
    pub(crate) stash_restore_sha: Option<String>,
    pub(crate) stash_restore_outcome: Option<String>,
    pub(crate) preserved_refs_created: Vec<String>,
    pub(crate) config_sha256_before: Option<String>,
    pub(crate) config_sha256_after: Option<String>,
    pub(crate) env_sha256_before: Option<String>,
    pub(crate) env_sha256_after: Option<String>,
    pub(crate) duration_ms: u128,
    pub(crate) native_update_receipt_path: Option<String>,
    pub(crate) changed: bool,
    pub(crate) ok: bool,
    pub(crate) error: Option<String>,
    snapshot: Option<RollbackSnapshot>,
}

#[derive(Debug, Serialize)]
struct RunReceipt {
    ok: bool,
    apply: bool,
    changed: bool,
    status: String,
    owner: String,
    uid: u32,
    home: String,
    timeout_secs: u64,
    source_root: String,
    launcher: String,
    pre_sha: Option<String>,
    target_sha: Option<String>,
    post_sha: Option<String>,
    movement: String,
    stage: String,
    updater_exit_code: Option<i32>,
    updater_stdout_tail: String,
    updater_stderr_tail: String,
    restored_launchers: Vec<RestoredLauncher>,
    stash_names_created: Vec<String>,
    stash_restore_sha: Option<String>,
    stash_restore_outcome: Option<String>,
    preserved_refs_created: Vec<String>,
    config_sha256_before: Option<String>,
    config_sha256_after: Option<String>,
    env_sha256_before: Option<String>,
    env_sha256_after: Option<String>,
    duration_ms: u128,
    native_update_receipt_path: Option<String>,
    launcher_sha256_before: Option<String>,
    launcher_sha256_after: Option<String>,
    branch_before: Option<String>,
    reasons: Vec<String>,
    error: Option<String>,
}

impl Request {
    fn from_args(
        args: &BTreeMap<String, Value>,
        receipt_dir: &Path,
        receipt_name: &str,
        receipt_custody: ReceiptCustody,
    ) -> Result<Self, String> {
        let mut components = Path::new(receipt_name).components();
        if receipt_name.is_empty()
            || receipt_name.contains('/')
            || Path::new(receipt_name).is_absolute()
            || !matches!(components.next(), Some(std::path::Component::Normal(c)) if !c.is_empty())
            || components.next().is_some()
            || receipt_name == "routine-child"
        {
            return Err("hermes-maintenance-receipt-name-invalid".into());
        }
        let text = |key: &str| {
            args.get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("hermes-maintenance-argument-{key}-missing"))
        };
        Ok(Self {
            owner: text("owner")?,
            source_root: PathBuf::from(text("source_root")?),
            launcher: PathBuf::from(text("launcher")?),
            upstream_url: args
                .get("upstream_url")
                .and_then(Value::as_str)
                .unwrap_or(OFFICIAL_URL)
                .to_owned(),
            branch: args
                .get("branch")
                .and_then(Value::as_str)
                .unwrap_or("main")
                .to_owned(),
            receipt_dir: receipt_dir.to_path_buf(),
            receipt_name: receipt_name.to_owned(),
            receipt_custody,
        })
    }
}

pub(crate) fn execute_step(
    step: &crate::tools::routine::ValidatedStep,
    receipt_dir: &Path,
    software: Option<&SoftwareApplyAuthorization>,
    invocation: Option<&InvocationKey>,
) -> Result<OperationOutcome, String> {
    validate_args(&step.args)?;
    let request = Request::from_args(
        &step.args,
        receipt_dir,
        &step.step_id,
        ReceiptCustody::current(),
    )?;
    let owner = resolve_owner_context(&request.owner)?;
    validate_caller_identity(&owner)?;
    let _owner_scope = OwnerContextScope::install(owner);
    validate_receipt_shapes_readonly(&request)?;
    let apply = software.is_some();
    let binding_slot = std::cell::RefCell::new(None::<ObservationBinding>);
    let initial_slot = std::cell::RefCell::new(None::<Observation>);
    let movement_slot = std::cell::RefCell::new(None::<Movement>);
    let run = crate::atoms::declaration::execute(
        "hermes-maintenance",
        "converge",
        || {
            let observation = {
                let mut binding = binding_slot.borrow_mut();
                crate::atoms::ask::hermes_maintenance::observe(&request, &mut binding)?
            };
            if initial_slot.borrow().is_none() {
                *initial_slot.borrow_mut() = Some(observation.clone());
            }
            Ok(observation)
        },
        |observation| {
            if apply && observation.changed {
                DiffDecision::Different
            } else {
                DiffDecision::Empty
            }
        },
        |authorization, observation| {
            let software = software
                .ok_or_else(|| "hermes-maintenance-software-authorization-missing".to_string())?;
            let key = invocation
                .ok_or_else(|| "hermes-maintenance-invocation-key-missing".to_string())?;
            let movement = crate::atoms::r#do::hermes_maintenance::converge(
                &authorization,
                key,
                software,
                &request,
                observation,
            )?;
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
                return Ok(OperationOutcome {
                    ok: true,
                    changed: false,
                    skipped: true,
                    message: "hermes-maintenance-drift-observed-no-write".into(),
                    command: None,
                });
            }
            if observation.changed {
                return Err("hermes-maintenance-diff-lost-before-action".into());
            }
            Ok(OperationOutcome {
                ok: true,
                changed: false,
                skipped: !apply,
                message: "hermes-maintenance-current".into(),
                command: None,
            })
        }
        Ok(crate::atoms::comparison::ComparisonRun::Moved { movement, .. }) => {
            let initial = initial_slot
                .borrow()
                .clone()
                .ok_or("hermes-maintenance-initial-observation-missing")?;
            crate::atoms::attest::hermes_maintenance::receipt(
                &request,
                &initial,
                apply,
                Some(&movement),
            )?;
            Ok(OperationOutcome {
                ok: movement.ok,
                changed: movement.changed,
                skipped: false,
                message: movement
                    .error
                    .clone()
                    .unwrap_or_else(|| "hermes-maintenance-native-update-proved".into()),
                command: None,
            })
        }
        Err(original_error) => {
            let initial = initial_slot.borrow().clone();
            let mut movement = movement_slot.borrow().clone();
            let mut error = original_error;
            if let (Some(initial), Some(movement)) = (initial.as_ref(), movement.as_mut()) {
                if movement.ok {
                    let rollback = movement
                        .snapshot
                        .clone()
                        .ok_or_else(|| "rollback-snapshot-missing".to_string())
                        .and_then(|snapshot| restore_snapshot(&snapshot, movement));
                    match rollback {
                        Ok(()) => {
                            movement.ok = false;
                            movement.changed = false;
                            movement.stage = "rolled-back".into();
                            movement.error = Some("post-update-observation-failed; rollback=pre-sha-and-launcher-restored-runnable".into());
                            movement.post_sha =
                                git_text(&initial.source_root, &["rev-parse", "HEAD"]).ok();
                            error = format!("failed-stage=post-update-observation rollback=pre-sha-and-launcher-restored-runnable; original={error}");
                        }
                        Err(debt) => {
                            movement.ok = false;
                            movement.changed = false;
                            movement.stage = "rollback-refused-debt".into();
                            movement.error = Some(format!("rollback-refused-debt={debt}"));
                            error = format!("failed-stage=post-update-observation rollback-refused-debt={debt}; original={error}");
                        }
                    }
                }
                crate::atoms::attest::hermes_maintenance::receipt(
                    &request,
                    initial,
                    apply,
                    Some(movement),
                )?;
            } else {
                crate::atoms::attest::hermes_maintenance::failure(
                    &request,
                    initial.as_ref(),
                    apply,
                    "observe-or-act",
                    &error,
                )?;
            }
            Err(error)
        }
    }
}

pub(crate) fn validate_args(args: &BTreeMap<String, Value>) -> Result<(), String> {
    let owner = args
        .get("owner")
        .and_then(Value::as_str)
        .ok_or("owner-name-required")?;
    if owner.is_empty()
        || owner.len() > 64
        || !owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("owner-must-be-account-name-not-path".into());
    }
    for name in ["source_root", "launcher"] {
        let value = args
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{name}-required"))?;
        if !Path::new(value).is_absolute() || value.contains('\0') {
            return Err(format!("{name}-must-be-absolute-path"));
        }
    }
    let source_root = Path::new(
        args.get("source_root")
            .and_then(Value::as_str)
            .ok_or("source_root-required")?,
    );
    let launcher = Path::new(
        args.get("launcher")
            .and_then(Value::as_str)
            .ok_or("launcher-required")?,
    );
    validate_launcher_declaration(owner, source_root, launcher)?;
    if args
        .get("upstream_url")
        .is_some_and(|value| value.as_str().is_none())
    {
        return Err("upstream-url-must-be-string".into());
    }
    if args
        .get("upstream_url")
        .and_then(Value::as_str)
        .is_some_and(|url| !official_url(url))
    {
        return Err("upstream-url-must-be-official-hermes-agent".into());
    }
    if args
        .get("branch")
        .is_some_and(|value| value.as_str().is_none())
    {
        return Err("branch-must-be-string".into());
    }
    if args
        .get("branch")
        .and_then(Value::as_str)
        .is_some_and(|branch| branch != "main")
    {
        return Err("upstream-branch-must-be-main".into());
    }
    Ok(())
}

fn validate_launcher_declaration(
    owner: &str,
    source_root: &Path,
    launcher: &Path,
) -> Result<(), String> {
    // Declaration validation is lexical and host-free. Account resolution and
    // filesystem custody checks belong to observe/launcher binding.
    let rejected = launcher.display();
    let allowed_external = PathBuf::from(format!("/home/{owner}/.local/bin/hermes"));
    let allowed_internal = source_root.join(".hermes/bin/hermes");
    if launcher.as_os_str() == allowed_external.as_os_str()
        || launcher.as_os_str() == allowed_internal.as_os_str()
    {
        Ok(())
    } else {
        Err(format!(
            "hermes-maintenance-launcher-declaration-not-converging: {rejected}"
        ))
    }
}

fn official_url(url: &str) -> bool {
    matches!(
        url.trim_end_matches('/'),
        OFFICIAL_URL
            | OFFICIAL_URL_NO_GIT
            | OFFICIAL_SSH_SCP
            | OFFICIAL_SSH_SCP_NO_GIT
            | OFFICIAL_SSH
            | OFFICIAL_SSH_NO_GIT
    )
}

/// Observation performs no filesystem writes: no lock-file creation, receipt
/// directory creation, updater invocation, or temporary profile allocation.
/// Currentness uses read-only Git HEAD, install-stamp, runtime-facts, and
/// launcher checks. It avoids bare `--version`: upstream's fast-version path
/// reaches `_startup_fast` and `source_check`, which perform update/cache work;
/// `hermes_bootstrap` may also repair the install first. The launcher's runtime
/// command performs interrupted-pull recovery, so it is not an observation
/// probe. Version probes belong only in isolated act/post-update/rollback proof.
pub(crate) fn observe(
    request: &Request,
    retained: &mut Option<ObservationBinding>,
) -> Result<Observation, String> {
    if !official_url(&request.upstream_url) {
        return Err("upstream-url-must-be-official-hermes-agent".into());
    }
    if request.branch != "main" {
        return Err("upstream-branch-must-be-main".into());
    }
    let owner = current_owner_context()?;
    if owner.name != request.owner {
        return Err("maintenance-observation-custody-binding-changed".into());
    }
    validate_caller_identity(&owner)?;
    let first = retained.is_none();
    let root = canonical_install_root(&request.source_root, owner.uid)?;
    let launcher = canonical_parent_file(&request.launcher)?;
    validate_origin(&root)?;
    if updater_is_live(&root, &owner)? {
        return Err("native-updater-live-retry".into());
    }
    let target_sha = if let Some(binding) = retained.as_ref() {
        if binding.owner != request.owner
            || binding.declared_source_root != request.source_root
            || binding.declared_launcher != request.launcher
            || binding.source_root != root
            || binding.launcher != launcher
            || binding.owner_uid != owner.uid
        {
            return Err("maintenance-observation-custody-binding-changed".into());
        }
        binding.target_sha.clone()
    } else {
        resolve_remote_main(&request.upstream_url)?
    };
    validate_origin(&root)?;
    let pre_sha = git_text(&root, &["rev-parse", "HEAD"])?;
    validate_sha(&pre_sha, "installed-head")?;
    let branch = git_optional_text(&root, &["symbolic-ref", "--quiet", "--short", "HEAD"])?;
    let status = git_output_raw(
        &root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    if !status.status.success() {
        return Err("installed-source-status-failed".into());
    }
    let launcher_meta = fs::symlink_metadata(&launcher)
        .map_err(|error| format!("launcher-observe-failed: {error}"))?;
    if !launcher_meta.is_file()
        || launcher_meta.file_type().is_symlink()
        || launcher_meta.uid() != owner.uid
        || launcher_meta.nlink() != 1
        || launcher_meta.permissions().mode() & 0o111 == 0
    {
        return Err("launcher-not-owner-controlled-executable-regular-file".into());
    }
    let launcher_bytes =
        fs::read(&launcher).map_err(|error| format!("launcher-read-failed: {error}"))?;
    if launcher_bytes.len() > 1024 * 1024 {
        return Err("launcher-size-exceeds-bound".into());
    }
    validate_launcher_binding(&root, &launcher, &owner, &launcher_bytes)?;
    static_runnable_probe(&launcher, &launcher_bytes)?;
    let native_state = inspect_native_install_state(&root, &launcher, &owner, &pre_sha)?;
    let dirty = !source_status_is_clean(&status.stdout, native_state.stamp_coherent);
    let mut reasons = native_state.reasons.clone();
    let target_or_retained_descendant =
        pre_sha == target_sha || (!first && is_ancestor(&root, &target_sha, &pre_sha)?);
    if !target_or_retained_descendant {
        reasons.push("installed-head-differs-from-official-main".into());
    }
    if branch.as_deref() != Some("main") {
        reasons.push("installed-checkout-not-main".into());
    }
    if dirty {
        reasons.push("installed-worktree-dirty".into());
    }
    if update_marker_present(&root, &owner)? {
        reasons.push("native-update-marker-present".into());
    }
    let observation = Observation {
        owner: request.owner.clone(),
        owner_uid: owner.uid,
        source_root: root.clone(),
        launcher: launcher.clone(),
        anchor_sha: pre_sha,
        target_sha: target_sha.clone(),
        launcher_sha256: digest(&launcher_bytes),
        branch,
        native_stamp_fields: native_state.stamp_fields.clone(),
        changed: !reasons.is_empty(),
        reasons,
    };
    if first {
        *retained = Some(ObservationBinding {
            owner: request.owner.clone(),
            declared_source_root: request.source_root.clone(),
            declared_launcher: request.launcher.clone(),
            source_root: root,
            launcher,
            owner_uid: owner.uid,
            target_sha,
        });
    }
    Ok(observation)
}

pub(crate) fn apply(
    _authorization: &ActionAuthorization,
    _invocation: &InvocationKey,
    _software: &SoftwareApplyAuthorization,
    request: &Request,
    observed: &Observation,
) -> Result<Movement, String> {
    let started = Instant::now();
    let owner = current_owner_context()?;
    if owner.name != observed.owner || owner.uid != observed.owner_uid {
        return Err("failed-stage=custody-owner-binding predecessor=preserved".into());
    }
    validate_caller_identity(&owner)
        .map_err(|_| "failed-stage=custody-euid predecessor=preserved".to_string())?;
    prepare_receipt_directory(&request.receipt_dir, request.receipt_custody)?;
    validate_receipt_output_custody(request)?;
    validate_origin(&observed.source_root)
        .map_err(|error| format!("failed-stage=foreign-origin predecessor=preserved: {error}"))?;
    if updater_is_live(&observed.source_root, &owner)? {
        return Err("failed-stage=native-updater-live-retry predecessor=preserved".into());
    }
    if canonical_install_root(&request.source_root, owner.uid)? != observed.source_root
        || canonical_parent_file(&request.launcher)? != observed.launcher
    {
        return Err("failed-stage=pre-action-custody-binding predecessor=preserved".into());
    }
    let pre_sha = git_text(&observed.source_root, &["rev-parse", "HEAD"])?;
    if pre_sha != observed.anchor_sha {
        return Err("failed-stage=pre-action-source-changed predecessor=preserved".into());
    }
    let launcher_bytes = fs::read(&observed.launcher).map_err(|error| {
        format!("failed-stage=pre-action-launcher-read predecessor=preserved: {error}")
    })?;
    if digest(&launcher_bytes) != observed.launcher_sha256 {
        return Err("failed-stage=pre-action-launcher-changed predecessor=preserved".into());
    }
    static_runnable_probe(&observed.launcher, &launcher_bytes)?;
    let (launcher_directory, launchers) = snapshot_launchers(
        &observed.launcher,
        &observed.source_root,
        &owner,
        &launcher_bytes,
    )?;
    let snapshot = RollbackSnapshot {
        source_root: observed.source_root.clone(),
        launcher: observed.launcher.clone(),
        launcher_directory: launcher_directory.path,
        launcher_directory_mode: launcher_directory.mode,
        launcher_directory_uid: launcher_directory.uid,
        launcher_directory_gid: launcher_directory.gid,
        launcher_directory_dev: launcher_directory.dev,
        launcher_directory_ino: launcher_directory.ino,
        pre_sha: pre_sha.clone(),
        branch: observed.branch.clone(),
        launchers,
        owner_uid: owner.uid,
    };
    let mut movement = Movement {
        pre_sha: pre_sha.clone(),
        target_sha: observed.target_sha.clone(),
        post_sha: None,
        movement: "not-started".into(),
        stage: "pre-action".into(),
        updater_exit_code: None,
        updater_stdout_tail: String::new(),
        updater_stderr_tail: String::new(),
        restored_launchers: Vec::new(),
        stash_names_created: Vec::new(),
        stash_restore_sha: None,
        stash_restore_outcome: None,
        preserved_refs_created: Vec::new(),
        config_sha256_before: hash_optional_file(&owner.hermes_home.join("config.yaml"))?,
        config_sha256_after: None,
        env_sha256_before: hash_optional_file(&owner.hermes_home.join(".env"))?,
        env_sha256_after: None,
        duration_ms: 0,
        native_update_receipt_path: None,
        changed: false,
        ok: false,
        error: None,
        snapshot: Some(snapshot.clone()),
    };
    let previous_native_receipt =
        latest_native_receipt(&owner.hermes_home.join("logs/update_receipts"));
    let action_scratch = isolated_tempdir()?;
    let mut pre_update_stash_sha = None;
    let mut pre_update_work_snapshot = None;
    let mut pre_update_work_snapshot_error = None;
    let mut live_after_stash = false;
    let action_result = (|| -> Result<(), String> {
        if updater_is_live(&observed.source_root, &owner)? {
            return Err("native-updater-live-retry".into());
        }
        movement.stage = "preserve-head-ref".into();
        let ref_name = preserve_head_ref(&observed.source_root, &pre_sha)?;
        movement.preserved_refs_created.push(ref_name);
        movement.stage = "preserve-local-worktree".into();
        let status = git_output_raw(
            &observed.source_root,
            &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        )?;
        if !status.status.success() {
            return Err("source-status-before-stash-failed".into());
        }
        if !status.stdout.is_empty() {
            match snapshot_local_worktree(&observed.source_root) {
                Ok(snapshot) => pre_update_work_snapshot = Some(snapshot),
                Err(error) => pre_update_work_snapshot_error = Some(error),
            }
            let stash_message = unique_name("hermes-maintenance-preserved");
            if updater_is_live(&observed.source_root, &owner)? {
                return Err("native-updater-live-retry".into());
            }
            let stash = git_output(
                &observed.source_root,
                &[
                    "stash",
                    "push",
                    "--include-untracked",
                    "--message",
                    &stash_message,
                ],
            )?;
            if !stash.status.success() {
                return Err("local-work-stash-failed".into());
            }
            let stash_subject = git_text(
                &observed.source_root,
                &["stash", "list", "--format=%gs", "-n", "1"],
            )?;
            if !stash_subject.contains(&stash_message) {
                return Err("local-work-stash-readback-missing".into());
            }
            let stash_sha = git_text(
                &observed.source_root,
                &["rev-parse", "--verify", "refs/stash"],
            )?;
            validate_sha(&stash_sha, "stash")?;
            let after_stash = git_output_raw(
                &observed.source_root,
                &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
            )?;
            if !after_stash.status.success() || !after_stash.stdout.is_empty() {
                return Err("local-work-stash-incomplete".into());
            }
            pre_update_stash_sha = Some(stash_sha.clone());
            movement
                .stash_names_created
                .push(format!("stash@{{0}}:{stash_message}:{stash_sha}"));
        }
        match updater_is_live(&observed.source_root, &owner) {
            Ok(false) => {}
            Ok(true) => {
                live_after_stash = true;
                return Err("native-updater-live-retry".into());
            }
            Err(error) => {
                live_after_stash = true;
                return Err(format!(
                    "native-updater-live-check-after-stash-failed: {error}"
                ));
            }
        }
        movement.stage = "native-update".into();
        let args = [
            "update",
            "--yes",
            "--no-gateway-restart",
            "--branch",
            "main",
        ];
        let result = run_owner_updater(
            &observed.launcher.to_string_lossy(),
            &args,
            Some(&observed.source_root),
            BTreeMap::from([
                ("GIT_TERMINAL_PROMPT".into(), "0".into()),
                (
                    "TMPDIR".into(),
                    action_scratch.path.to_string_lossy().into_owned(),
                ),
            ]),
            UPDATER_TIMEOUT_SECS,
        );
        match result {
            Ok(output) => {
                movement.updater_exit_code = output.status.code();
                movement.updater_stdout_tail = output.stdout_tail;
                movement.updater_stderr_tail = output.stderr_tail;
                if let Some(error) = output.error {
                    return Err(format!("native-updater-capture-failed: {error}"));
                }
                if !output.status.success() {
                    return Err("native-updater-returned-nonzero".into());
                }
            }
            Err(error) => return Err(format!("native-updater-start-failed: {error}")),
        }
        movement.stage = "post-update-proof".into();
        let post_sha = git_text(&observed.source_root, &["rev-parse", "HEAD"])?;
        validate_sha(&post_sha, "post-update-head")?;
        if !is_ancestor(&observed.source_root, &observed.target_sha, &post_sha)? {
            return Err("post-update-head-is-not-target-or-descendant".into());
        }
        validate_origin(&observed.source_root)?;
        let post_branch = git_optional_text(
            &observed.source_root,
            &["symbolic-ref", "--quiet", "--short", "HEAD"],
        )?;
        if post_branch.as_deref() != Some("main") {
            return Err("post-update-branch-is-not-main".into());
        }
        let source_status = git_output_raw(
            &observed.source_root,
            &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        )?;
        if !source_status.status.success() {
            return Err("post-update-source-not-clean".into());
        }
        let launcher_after = fs::read(&observed.launcher)
            .map_err(|error| format!("post-update-launcher-read-failed: {error}"))?;
        validate_launcher_binding(
            &observed.source_root,
            &observed.launcher,
            &owner,
            &launcher_after,
        )?;
        static_runnable_probe(&observed.launcher, &launcher_after)?;
        let native_state =
            inspect_native_install_state(&observed.source_root, &observed.launcher, &owner, &post_sha)?;
        if !native_state.reasons.is_empty() || update_marker_present(&observed.source_root, &owner)? {
            return Err(format!(
                "post-update-native-install-not-current reasons={}",
                native_state.reasons.join(",")
            ));
        }
        if !source_status_is_clean(&source_status.stdout, native_state.stamp_coherent) {
            return Err("post-update-source-not-clean".into());
        }
        prove_launch_isolated(&observed.launcher, &observed.source_root)?;
        movement.post_sha = Some(post_sha.clone());
        movement.config_sha256_after = hash_optional_file(&owner.hermes_home.join("config.yaml"))?;
        movement.env_sha256_after = hash_optional_file(&owner.hermes_home.join(".env"))?;
        let current_native_receipt =
            latest_native_receipt(&owner.hermes_home.join("logs/update_receipts"));
        movement.native_update_receipt_path =
            current_native_receipt.filter(|path| Some(path) != previous_native_receipt.as_ref());
        movement.changed = post_sha != pre_sha
            || post_branch != observed.branch
            || digest(&launcher_after) != observed.launcher_sha256
            || native_state.stamp_fields != observed.native_stamp_fields;
        movement.movement = if !movement.changed {
            "native-update-completed-without-installation-movement"
        } else if post_sha != pre_sha {
            "official-main-advanced"
        } else {
            "native-installation-layout-advanced"
        }
        .into();
        movement.ok = true;
        movement.stage = "complete".into();
        Ok(())
    })();
    if let Err(action_error) = action_result {
        movement.stage = stage_from_error(&action_error, &movement.stage);
        let failed_stage = movement.stage.clone();
        movement.error = Some(format!("failed-stage={failed_stage}; {action_error}"));
        if live_after_stash {
            movement.movement = "retry-live-native-updater".into();
            movement.stage = "live-updater-retry".into();
            movement.post_sha = git_text(&observed.source_root, &["rev-parse", "HEAD"]).ok();
            movement.config_sha256_after =
                hash_optional_file(&owner.hermes_home.join("config.yaml"))
                    .ok()
                    .flatten();
            movement.env_sha256_after = hash_optional_file(&owner.hermes_home.join(".env"))
                .ok()
                .flatten();
            if let Some(stash_sha) = pre_update_stash_sha.as_deref() {
                movement.stash_restore_sha = Some(stash_sha.to_owned());
                match restore_created_stash(
                    &observed.source_root,
                    stash_sha,
                    pre_update_work_snapshot.as_ref(),
                    pre_update_work_snapshot_error.as_deref(),
                ) {
                    Ok(()) => {
                        movement.stash_restore_outcome = Some("restored-and-verified".into());
                    }
                    Err(error) => {
                        movement.stash_restore_outcome =
                            Some(format!("restore-refused-debt={error}"));
                        movement.error = Some(format!(
                            "{}; stash-restore-refused-debt={error}",
                            movement
                                .error
                                .as_deref()
                                .unwrap_or("native-updater-live-retry")
                        ));
                    }
                }
            } else {
                movement.stash_restore_outcome = Some("not-needed-no-stash".into());
            }
            movement.duration_ms = started.elapsed().as_millis();
            return Ok(movement);
        }
        if action_error.contains("native-updater-live-retry") {
            movement.movement = "retry-live-native-updater".into();
            movement.stage = "live-updater-retry".into();
            movement.post_sha = git_text(&observed.source_root, &["rev-parse", "HEAD"]).ok();
            movement.config_sha256_after =
                hash_optional_file(&owner.hermes_home.join("config.yaml"))
                    .ok()
                    .flatten();
            movement.env_sha256_after = hash_optional_file(&owner.hermes_home.join(".env"))
                .ok()
                .flatten();
            movement.duration_ms = started.elapsed().as_millis();
            return Ok(movement);
        }
        movement.movement = "rolled-back-after-native-update-failure".into();
        let rollback_result = restore_snapshot(&snapshot, &mut movement);
        movement.post_sha = git_text(&observed.source_root, &["rev-parse", "HEAD"]).ok();
        movement.config_sha256_after = hash_optional_file(&owner.hermes_home.join("config.yaml"))
            .ok()
            .flatten();
        movement.env_sha256_after = hash_optional_file(&owner.hermes_home.join(".env"))
            .ok()
            .flatten();
        movement.native_update_receipt_path =
            latest_native_receipt(&owner.hermes_home.join("logs/update_receipts"))
                .filter(|path| Some(path) != previous_native_receipt.as_ref());
        if let Err(rollback_error) = rollback_result {
            movement.changed = false;
            movement.ok = false;
            movement.error = Some(format!(
                "{}; rollback-refused-debt={rollback_error}",
                movement.error.as_deref().unwrap_or("update-failed")
            ));
        } else {
            movement.stage = "rolled-back".into();
            movement.changed = false;
            movement.ok = false;
            movement.error = Some(format!(
                "{}; rollback=pre-sha-and-launcher-restored-runnable",
                movement.error.as_deref().unwrap_or("update-failed")
            ));
        }
    }
    movement.duration_ms = started.elapsed().as_millis();
    Ok(movement)
}

fn stage_from_error(error: &str, current: &str) -> String {
    if error.contains("native-updater") || error.contains("live-retry") {
        "native-update".into()
    } else if error.contains("post-update")
        || error.contains("target-or-descendant")
        || error.contains("launch")
    {
        "post-update-proof".into()
    } else {
        current.to_owned()
    }
}

fn snapshot_launchers(
    launcher: &Path,
    source_root: &Path,
    owner: &OwnerContext,
    expected_main_bytes: &[u8],
) -> Result<(LauncherDirectorySnapshot, Vec<LauncherSnapshot>), String> {
    let directory_path = launcher
        .parent()
        .ok_or("launcher-parent-missing")?
        .to_path_buf();
    let directory = launcher_directory_snapshot(&directory_path, owner.uid)?;
    let source_bytes = source_root.as_os_str().as_bytes().to_vec();
    let mut launchers = Vec::new();
    let mut main_included = false;
    let entries = fs::read_dir(&directory_path)
        .map_err(|error| format!("launcher-directory-census-failed: {error}"))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("launcher-directory-entry-read-failed: {error}"))?;
        let path = entry.path();
        if path == launcher {
            let (bytes, metadata) = read_owner_executable_launcher(&path, owner.uid)?;
            if bytes != expected_main_bytes {
                return Err("pre-action-launcher-changed-during-snapshot".into());
            }
            launchers.push(LauncherSnapshot {
                path,
                bytes,
                mode: metadata.permissions().mode() & 0o7777,
                uid: metadata.uid(),
                gid: metadata.gid(),
            });
            main_included = true;
            continue;
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("launcher-sibling-observe-failed: {error}")),
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != owner.uid
            || metadata.permissions().mode() & 0o111 == 0
        {
            continue;
        }
        if !file_contains_bytes(&path, &source_bytes, owner.uid)? {
            continue;
        }
        let (bytes, metadata) = read_owner_executable_launcher(&path, owner.uid)?;
        if source_bytes.is_empty()
            || !bytes
                .windows(source_bytes.len())
                .any(|window| window == source_bytes)
        {
            return Err("launcher-source-binding-changed-during-snapshot".into());
        }
        launchers.push(LauncherSnapshot {
            path,
            bytes,
            mode: metadata.permissions().mode() & 0o7777,
            uid: metadata.uid(),
            gid: metadata.gid(),
        });
    }
    if !main_included {
        return Err("declared-launcher-not-in-launcher-directory-census".into());
    }
    verify_launcher_directory(&directory, owner.uid)?;
    Ok((directory, launchers))
}

fn file_contains_bytes(path: &Path, needle: &[u8], owner_uid: u32) -> Result<bool, String> {
    if needle.is_empty() {
        return Ok(false);
    }
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("launcher-census-stat-failed: {error}")),
    };
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.uid() != owner_uid
        || before.permissions().mode() & 0o111 == 0
    {
        return Ok(false);
    }
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("launcher-census-open-failed: {error}")),
    };
    let opened = file
        .metadata()
        .map_err(|error| format!("launcher-census-fstat-failed: {error}"))?;
    if !opened.is_file()
        || opened.uid() != owner_uid
        || opened.dev() != before.dev()
        || opened.ino() != before.ino()
    {
        return Ok(false);
    }
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut carry = Vec::with_capacity(needle.len().saturating_sub(1));
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("launcher-census-read-failed: {error}"))?;
        if count == 0 {
            return Ok(false);
        }
        let mut window = Vec::with_capacity(carry.len() + count);
        window.extend_from_slice(&carry);
        window.extend_from_slice(&buffer[..count]);
        if window
            .windows(needle.len())
            .any(|candidate| candidate == needle)
        {
            return Ok(true);
        }
        let keep = needle.len().saturating_sub(1).min(window.len());
        carry.clear();
        carry.extend_from_slice(&window[window.len() - keep..]);
    }
}

fn launcher_directory_snapshot(
    path: &Path,
    owner_uid: u32,
) -> Result<LauncherDirectorySnapshot, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("launcher-directory-observe-failed: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != owner_uid {
        return Err("launcher-directory-not-owner-controlled-real-directory".into());
    }
    Ok(LauncherDirectorySnapshot {
        path: path.to_path_buf(),
        mode: metadata.permissions().mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}

fn verify_launcher_directory(
    expected: &LauncherDirectorySnapshot,
    owner_uid: u32,
) -> Result<(), String> {
    let current = launcher_directory_snapshot(&expected.path, owner_uid)?;
    if current.mode != expected.mode
        || current.uid != expected.uid
        || current.gid != expected.gid
        || current.dev != expected.dev
        || current.ino != expected.ino
    {
        return Err("rollback-launcher-directory-custody-changed".into());
    }
    Ok(())
}

fn read_owner_executable_launcher(
    path: &Path,
    owner_uid: u32,
) -> Result<(Vec<u8>, fs::Metadata), String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("launcher-snapshot-stat-failed: {error}"))?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.uid() != owner_uid
        || before.nlink() != 1
        || before.permissions().mode() & 0o111 == 0
        || before.len() > LAUNCHER_MAX_BYTES
    {
        return Err("launcher-snapshot-file-not-owner-controlled-executable".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("launcher-snapshot-open-failed: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("launcher-snapshot-fstat-failed: {error}"))?;
    if !opened.is_file()
        || opened.uid() != owner_uid
        || opened.nlink() != 1
        || opened.len() > LAUNCHER_MAX_BYTES
        || opened.dev() != before.dev()
        || opened.ino() != before.ino()
    {
        return Err("launcher-snapshot-file-custody-changed".into());
    }
    let mut bytes = Vec::with_capacity(opened.len().min(LAUNCHER_MAX_BYTES) as usize);
    Read::take(file, LAUNCHER_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("launcher-snapshot-read-failed: {error}"))?;
    if bytes.len() as u64 > LAUNCHER_MAX_BYTES {
        return Err("launcher-size-exceeds-bound".into());
    }
    let after = fs::symlink_metadata(path)
        .map_err(|error| format!("launcher-snapshot-readback-stat-failed: {error}"))?;
    if !after.is_file()
        || after.file_type().is_symlink()
        || after.uid() != owner_uid
        || after.nlink() != 1
        || after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.len() != bytes.len() as u64
    {
        return Err("launcher-snapshot-file-changed-during-read".into());
    }
    Ok((bytes, opened))
}

fn preserve_head_ref(root: &Path, sha: &str) -> Result<String, String> {
    let ref_name = format!(
        "refs/hermes-maintenance/preserved/{}-{}",
        std::process::id(),
        now_nanos()?
    );
    let output = git_output(root, &["update-ref", &ref_name, sha])?;
    if !output.status.success() {
        return Err("pre-update-head-preservation-ref-failed".into());
    }
    if git_text(root, &["rev-parse", "--verify", &ref_name])? != sha {
        return Err("pre-update-head-preservation-ref-readback-mismatch".into());
    }
    Ok(ref_name)
}

fn snapshot_local_worktree(root: &Path) -> Result<LocalWorkSnapshot, String> {
    let status = git_output_raw(
        root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    if !status.status.success() {
        return Err("stash-restore-status-snapshot-failed".into());
    }
    let staged = git_output_raw(
        root,
        &[
            "diff",
            "--cached",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
        ],
    )?;
    if !staged.status.success() {
        return Err("stash-restore-index-snapshot-failed".into());
    }
    let worktree = git_output_raw(
        root,
        &["diff", "--binary", "--no-ext-diff", "--no-textconv"],
    )?;
    if !worktree.status.success() {
        return Err("stash-restore-worktree-snapshot-failed".into());
    }
    let untracked_output = git_output_raw(
        root,
        &[
            "ls-files",
            "--others",
            "--exclude-standard",
            "--full-name",
            "-z",
        ],
    )?;
    if !untracked_output.status.success() {
        return Err("stash-restore-untracked-list-snapshot-failed".into());
    }
    let mut untracked = Vec::new();
    for raw_path in untracked_output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let relative = Path::new(OsStr::from_bytes(raw_path));
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err("stash-restore-untracked-path-invalid".into());
        }
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("stash-restore-untracked-stat-failed: {error}"))?;
        let symlink = metadata.file_type().is_symlink();
        let bytes = if symlink {
            fs::read_link(&path)
                .map_err(|error| format!("stash-restore-untracked-symlink-read-failed: {error}"))?
                .as_os_str()
                .as_bytes()
                .to_vec()
        } else if metadata.is_file() {
            fs::read(&path)
                .map_err(|error| format!("stash-restore-untracked-file-read-failed: {error}"))?
        } else {
            return Err("stash-restore-untracked-entry-not-file-or-symlink".into());
        };
        untracked.push(UntrackedWorkSnapshot {
            path: raw_path.to_vec(),
            mode: metadata.permissions().mode() & 0o7777,
            uid: metadata.uid(),
            gid: metadata.gid(),
            symlink,
            sha256: digest(&bytes),
        });
    }
    let status_readback = git_output_raw(
        root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    if !status_readback.status.success() || status_readback.stdout != status.stdout {
        return Err("stash-restore-worktree-changed-during-snapshot".into());
    }
    Ok(LocalWorkSnapshot {
        status: status.stdout,
        staged_diff: staged.stdout,
        worktree_diff: worktree.stdout,
        untracked,
    })
}

fn restore_created_stash(
    root: &Path,
    stash_sha: &str,
    expected: Option<&LocalWorkSnapshot>,
    snapshot_error: Option<&str>,
) -> Result<(), String> {
    validate_sha(stash_sha, "stash")?;
    let applied = git_output(root, &["stash", "apply", "--index", stash_sha])?;
    if !applied.status.success() {
        return Err(format!(
            "stash-apply-index-failed-exit-{:?}",
            applied.status.code()
        ));
    }
    if let Some(error) = snapshot_error {
        return Err(format!("stash-restore-preimage-unavailable: {error}"));
    }
    let expected = expected.ok_or("stash-restore-preimage-unavailable")?;
    let actual = snapshot_local_worktree(root)?;
    if &actual != expected {
        return Err("stash-restore-index-worktree-untracked-readback-mismatch".into());
    }
    Ok(())
}

fn preserve_post_update_worktree(
    root: &Path,
    movement: &mut Movement,
    owner: &OwnerContext,
) -> Result<(), String> {
    let status = git_output_raw(
        root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    if !status.status.success() {
        return Err("rollback-post-update-status-failed".into());
    }
    if status.stdout.is_empty() {
        return Ok(());
    }
    let stash_message = unique_name("hermes-maintenance-post-update-preserved");
    if updater_is_live(root, owner)? {
        return Err("native-updater-live-retry".into());
    }
    let stash = git_output(
        root,
        &[
            "stash",
            "push",
            "--include-untracked",
            "--message",
            &stash_message,
        ],
    )?;
    if !stash.status.success() {
        return Err("rollback-post-update-work-stash-failed".into());
    }
    let stash_subject = git_text(root, &["stash", "list", "--format=%gs", "-n", "1"])?;
    if !stash_subject.contains(&stash_message) {
        return Err("rollback-post-update-work-stash-readback-missing".into());
    }
    let stash_sha = git_text(root, &["rev-parse", "--verify", "refs/stash"])?;
    validate_sha(&stash_sha, "rollback-stash")?;
    let after_stash = git_output_raw(
        root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    if !after_stash.status.success() || !after_stash.stdout.is_empty() {
        return Err("rollback-post-update-work-stash-incomplete".into());
    }
    movement
        .stash_names_created
        .push(format!("stash@{{0}}:{stash_message}:{stash_sha}"));
    Ok(())
}

fn restore_snapshot(
    snapshot: &RollbackSnapshot,
    movement: &mut Movement,
) -> Result<(), String> {
    let owner = current_owner_context()?;
    if owner.uid != snapshot.owner_uid {
        return Err("rollback-owner-binding-changed".into());
    }
    if updater_is_live(&snapshot.source_root, &owner)? {
        return Err("rollback-refused-while-native-updater-live".into());
    }
    if git_text(
        &snapshot.source_root,
        &[
            "cat-file",
            "-e",
            &format!("{}^{{commit}}", snapshot.pre_sha),
        ],
    )
    .is_err()
    {
        return Err("rollback-pre-sha-object-unavailable".into());
    }
    let current_sha = git_text(&snapshot.source_root, &["rev-parse", "HEAD"])?;
    let current_branch = git_optional_text(
        &snapshot.source_root,
        &["symbolic-ref", "--quiet", "--short", "HEAD"],
    )?;
    if current_sha != snapshot.pre_sha || current_branch != snapshot.branch {
        preserve_post_update_worktree(&snapshot.source_root, movement, &owner)?;
        if let Some(branch) = snapshot.branch.as_deref() {
            let exists = git_output(
                &snapshot.source_root,
                &[
                    "show-ref",
                    "--verify",
                    "--quiet",
                    &format!("refs/heads/{branch}"),
                ],
            )?;
            if exists.status.code() == Some(0) {
                if updater_is_live(&snapshot.source_root, &owner)? {
                    return Err("native-updater-live-retry".into());
                }
                let switched = git_output(
                    &snapshot.source_root,
                    &["switch", "--quiet", "--force", "--", branch],
                )?;
                if !switched.status.success() {
                    return Err("rollback-original-branch-switch-failed".into());
                }
                if updater_is_live(&snapshot.source_root, &owner)? {
                    return Err("native-updater-live-retry".into());
                }
                let reset = git_output(
                    &snapshot.source_root,
                    &["reset", "--hard", &snapshot.pre_sha],
                )?;
                if !reset.status.success() {
                    return Err("rollback-source-reset-failed".into());
                }
            } else {
                if updater_is_live(&snapshot.source_root, &owner)? {
                    return Err("native-updater-live-retry".into());
                }
                let create = git_output(
                    &snapshot.source_root,
                    &[
                        "switch",
                        "--quiet",
                        "--force",
                        "-c",
                        branch,
                        &snapshot.pre_sha,
                    ],
                )?;
                if !create.status.success() {
                    return Err("rollback-original-branch-recreate-failed".into());
                }
            }
        } else {
            if updater_is_live(&snapshot.source_root, &owner)? {
                return Err("native-updater-live-retry".into());
            }
            let switched = git_output(
                &snapshot.source_root,
                &[
                    "switch",
                    "--quiet",
                    "--force",
                    "--detach",
                    &snapshot.pre_sha,
                ],
            )?;
            if !switched.status.success() {
                return Err("rollback-detached-head-restore-failed".into());
            }
        }
    }
    if git_text(&snapshot.source_root, &["rev-parse", "HEAD"])? != snapshot.pre_sha
        || git_optional_text(
            &snapshot.source_root,
            &["symbolic-ref", "--quiet", "--short", "HEAD"],
        )? != snapshot.branch
    {
        return Err("rollback-source-sha-or-branch-readback-mismatch".into());
    }
    let directory = LauncherDirectorySnapshot {
        path: snapshot.launcher_directory.clone(),
        mode: snapshot.launcher_directory_mode,
        uid: snapshot.launcher_directory_uid,
        gid: snapshot.launcher_directory_gid,
        dev: snapshot.launcher_directory_dev,
        ino: snapshot.launcher_directory_ino,
    };
    let mut main_bytes = None;
    for launcher in &snapshot.launchers {
        if updater_is_live(&snapshot.source_root, &owner)? {
            return Err("native-updater-live-retry".into());
        }
        let restored = restore_launcher(launcher, &directory, owner.uid)?;
        if restored != launcher.bytes {
            return Err(format!(
                "rollback-launcher-byte-readback-mismatch-{}",
                launcher.path.display()
            ));
        }
        movement.restored_launchers.push(RestoredLauncher {
            path: launcher.path.to_string_lossy().into_owned(),
            sha256: digest(&restored),
        });
        if launcher.path == snapshot.launcher {
            main_bytes = Some(restored);
        }
    }
    let main_bytes = main_bytes.ok_or("rollback-main-launcher-snapshot-missing")?;
    static_runnable_probe(&snapshot.launcher, &main_bytes)?;
    prove_launch_isolated(&snapshot.launcher, &snapshot.source_root)?;
    Ok(())
}

fn restore_launcher(
    snapshot: &LauncherSnapshot,
    directory: &LauncherDirectorySnapshot,
    owner_uid: u32,
) -> Result<Vec<u8>, String> {
    verify_launcher_directory(directory, owner_uid)?;
    let original_target = restorable_launcher_identity(&snapshot.path, owner_uid)?;
    let basename = snapshot
        .path
        .file_name()
        .ok_or("rollback-launcher-basename-missing")?;
    let temp = directory.path.join(format!(
        ".hermes-maintenance-rollback-{}-{}-{}.tmp",
        std::process::id(),
        now_nanos()?,
        basename.to_string_lossy()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(snapshot.mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)
        .map_err(|error| format!("rollback-launcher-temp-create-failed: {error}"))?;
    let write_result = (|| -> Result<(), String> {
        file.write_all(&snapshot.bytes)
            .map_err(|error| error.to_string())?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if (metadata.uid(), metadata.gid()) != (snapshot.uid, snapshot.gid)
            && unsafe {
                libc::fchown(file.as_raw_fd(), snapshot.uid, snapshot.gid)
            } != 0
        {
            return Err("rollback-launcher-owner-restore-failed".into());
        }
        file.set_permissions(fs::Permissions::from_mode(snapshot.mode))
            .map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        Ok(())
    })();
    if let Err(error) = write_result {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    drop(file);
    verify_launcher_directory(directory, owner_uid)?;
    if restorable_launcher_identity(&snapshot.path, owner_uid)? != original_target {
        let _ = fs::remove_file(&temp);
        return Err("rollback-launcher-target-changed-before-promote".into());
    }
    fs::rename(&temp, &snapshot.path).map_err(|error| {
        let _ = fs::remove_file(&temp);
        format!("rollback-launcher-atomic-rename-failed: {error}")
    })?;
    verify_launcher_directory(directory, owner_uid)?;
    File::open(&directory.path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("rollback-launcher-parent-sync-failed: {error}"))?;
    let (restored, metadata) = read_owner_executable_launcher(&snapshot.path, owner_uid)?;
    if restored != snapshot.bytes
        || metadata.permissions().mode() & 0o7777 != snapshot.mode
        || metadata.uid() != snapshot.uid
        || metadata.gid() != snapshot.gid
    {
        return Err("rollback-launcher-readback-mismatch".into());
    }
    Ok(restored)
}

fn restorable_launcher_identity(
    path: &Path,
    owner_uid: u32,
) -> Result<Option<(u64, u64)>, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == owner_uid
                && metadata.nlink() == 1 =>
        {
            Ok(Some((metadata.dev(), metadata.ino())))
        }
        Ok(_) => Err("rollback-launcher-target-custody-changed".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("rollback-launcher-stat-failed: {error}")),
    }
}

pub(crate) fn receipt(
    request: &Request,
    observation: &Observation,
    apply: bool,
    movement: Option<&Movement>,
) -> Result<(), String> {
    let owner = current_owner_context()?;
    let receipt = match movement {
        Some(movement) => RunReceipt {
            ok: movement.ok,
            apply,
            changed: movement.changed,
            status: if movement.ok {
                "updated"
            } else if movement.stage == "rolled-back" {
                "rolled-back"
            } else {
                "failed"
            }
            .into(),
            owner: owner.name,
            uid: owner.uid,
            home: owner.home.to_string_lossy().into_owned(),
            timeout_secs: UPDATER_TIMEOUT_SECS,
            source_root: observation.source_root.to_string_lossy().into_owned(),
            launcher: observation.launcher.to_string_lossy().into_owned(),
            pre_sha: Some(movement.pre_sha.clone()),
            target_sha: Some(movement.target_sha.clone()),
            post_sha: movement.post_sha.clone(),
            movement: movement.movement.clone(),
            stage: movement.stage.clone(),
            updater_exit_code: movement.updater_exit_code,
            updater_stdout_tail: movement.updater_stdout_tail.clone(),
            updater_stderr_tail: movement.updater_stderr_tail.clone(),
            restored_launchers: movement.restored_launchers.clone(),
            stash_names_created: movement.stash_names_created.clone(),
            stash_restore_sha: movement.stash_restore_sha.clone(),
            stash_restore_outcome: movement.stash_restore_outcome.clone(),
            preserved_refs_created: movement.preserved_refs_created.clone(),
            config_sha256_before: movement.config_sha256_before.clone(),
            config_sha256_after: movement.config_sha256_after.clone(),
            env_sha256_before: movement.env_sha256_before.clone(),
            env_sha256_after: movement.env_sha256_after.clone(),
            duration_ms: movement.duration_ms,
            native_update_receipt_path: movement.native_update_receipt_path.clone(),
            launcher_sha256_before: Some(observation.launcher_sha256.clone()),
            launcher_sha256_after: fs::read(&observation.launcher)
                .ok()
                .map(|bytes| digest(&bytes)),
            branch_before: observation.branch.clone(),
            reasons: observation.reasons.clone(),
            error: movement.error.clone(),
        },
        None => RunReceipt {
            ok: true,
            apply,
            changed: false,
            status: if apply { "current" } else { "proposal" }.into(),
            owner: owner.name,
            uid: owner.uid,
            home: owner.home.to_string_lossy().into_owned(),
            timeout_secs: UPDATER_TIMEOUT_SECS,
            source_root: observation.source_root.to_string_lossy().into_owned(),
            launcher: observation.launcher.to_string_lossy().into_owned(),
            pre_sha: Some(observation.anchor_sha.clone()),
            target_sha: Some(observation.target_sha.clone()),
            post_sha: Some(observation.anchor_sha.clone()),
            movement: "none".into(),
            stage: "observe".into(),
            updater_exit_code: None,
            updater_stdout_tail: String::new(),
            updater_stderr_tail: String::new(),
            restored_launchers: Vec::new(),
            stash_names_created: Vec::new(),
            stash_restore_sha: None,
            stash_restore_outcome: None,
            preserved_refs_created: Vec::new(),
            config_sha256_before: None,
            config_sha256_after: None,
            env_sha256_before: None,
            env_sha256_after: None,
            duration_ms: 0,
            native_update_receipt_path: None,
            launcher_sha256_before: Some(observation.launcher_sha256.clone()),
            launcher_sha256_after: Some(observation.launcher_sha256.clone()),
            branch_before: observation.branch.clone(),
            reasons: observation.reasons.clone(),
            error: None,
        },
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
    let owner = current_owner_context()?;
    let receipt = RunReceipt {
        ok: false,
        apply,
        changed: false,
        status: "failed".into(),
        owner: owner.name,
        uid: owner.uid,
        home: owner.home.to_string_lossy().into_owned(),
        timeout_secs: UPDATER_TIMEOUT_SECS,
        source_root: request.source_root.to_string_lossy().into_owned(),
        launcher: request.launcher.to_string_lossy().into_owned(),
        pre_sha: observation.map(|value| value.anchor_sha.clone()),
        target_sha: observation.map(|value| value.target_sha.clone()),
        post_sha: observation.map(|value| value.anchor_sha.clone()),
        movement: "none".into(),
        stage: stage.into(),
        updater_exit_code: None,
        updater_stdout_tail: String::new(),
        updater_stderr_tail: String::new(),
        restored_launchers: Vec::new(),
        stash_names_created: Vec::new(),
        stash_restore_sha: None,
        stash_restore_outcome: None,
        preserved_refs_created: Vec::new(),
        config_sha256_before: None,
        config_sha256_after: None,
        env_sha256_before: None,
        env_sha256_after: None,
        duration_ms: 0,
        native_update_receipt_path: None,
        launcher_sha256_before: observation.map(|value| value.launcher_sha256.clone()),
        launcher_sha256_after: observation.map(|value| value.launcher_sha256.clone()),
        branch_before: observation.and_then(|value| value.branch.clone()),
        reasons: observation
            .map(|value| value.reasons.clone())
            .unwrap_or_default(),
        error: Some(error.to_owned()),
    };
    write_receipt(request, &receipt)
}

fn write_receipt(request: &Request, receipt: &RunReceipt) -> Result<(), String> {
    let _owner = current_owner_context()?;
    prepare_receipt_directory(&request.receipt_dir, request.receipt_custody)?;
    validate_receipt_output_custody(request)?;
    let receipt_path = request
        .receipt_dir
        .join(format!("{}.json", request.receipt_name));
    let mut bytes = serde_json::to_vec_pretty(receipt).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    atomic_write_owned(
        &receipt_path,
        &bytes,
        request.receipt_custody.uid,
        request.receipt_custody.gid,
        0o644,
    )?;
    let log = request.receipt_dir.join("harmonia-atoms.log");
    match fs::symlink_metadata(&log) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == request.receipt_custody.uid
                && metadata.gid() == request.receipt_custody.gid
                && metadata.nlink() == 1 => {}
        Ok(_) => return Err("native-receipt-log-not-engine-controlled".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&log)
                .map_err(|error| format!("native-receipt-log-create-failed: {error}"))?;
            if unsafe {
                libc::fchown(
                    file.as_raw_fd(),
                    request.receipt_custody.uid,
                    request.receipt_custody.gid,
                )
            } != 0
            {
                drop(file);
                let _ = fs::remove_file(&log);
                return Err("native-receipt-log-owner-assignment-failed".into());
            }
        }
        Err(error) => return Err(format!("native-receipt-log-observe-failed: {error}")),
    }
    let mut file = OpenOptions::new()
        .append(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&log)
        .map_err(|error| format!("native-receipt-log-open-failed: {error}"))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if metadata.uid() != request.receipt_custody.uid
        || metadata.gid() != request.receipt_custody.gid
        || metadata.nlink() != 1
    {
        return Err("native-receipt-log-not-engine-controlled".into());
    }
    crate::atoms::attest::attest(
        &log,
        &crate::atoms::Receipt {
            atom: "hermes-maintenance".into(),
            ok: receipt.ok,
            drift: if receipt.changed {
                crate::atoms::Drift::File {
                    expected_sha256: receipt.target_sha.clone().unwrap_or_default(),
                    actual_sha256: receipt.post_sha.clone(),
                }
            } else {
                crate::atoms::Drift::Current
            },
            message: format!(
                "status={} changed={} stage={}",
                receipt.status, receipt.changed, receipt.stage
            ),
        },
        &[],
    )?;
    file.flush()
        .map_err(|error| format!("native-receipt-log-flush-failed: {error}"))?;
    Ok(())
}

fn validate_receipt_shapes_readonly(request: &Request) -> Result<(), String> {
    if !request.receipt_dir.is_absolute() {
        return Err("managed-directory-must-be-absolute".into());
    }
    let mut current = PathBuf::new();
    for component in request.receipt_dir.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(format!(
                    "managed-directory-path-not-real-directory-{}",
                    current.display()
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(format!("receipt-directory-observe-failed: {error}")),
        }
    }
    Ok(())
}

fn validate_receipt_output_custody(request: &Request) -> Result<(), String> {
    request.receipt_custody.validate_current()?;
    validate_receipt_shapes_readonly(request)?;
    match fs::symlink_metadata(&request.receipt_dir) {
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == request.receipt_custody.uid
                && metadata.gid() == request.receipt_custody.gid =>
        {
            validate_receipt_file_shape(
                &request
                    .receipt_dir
                    .join(format!("{}.json", request.receipt_name)),
                request.receipt_custody,
                "native-receipt-file",
            )?;
            validate_receipt_file_shape(
                &request.receipt_dir.join("harmonia-atoms.log"),
                request.receipt_custody,
                "native-receipt-log",
            )?;
        }
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            return Err("receipt-directory-not-engine-controlled".into());
        }
        Ok(_) => return Err("managed-directory-path-not-real-directory".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err("receipt-directory-unavailable".into());
        }
        Err(error) => return Err(format!("receipt-directory-observe-failed: {error}")),
    }
    Ok(())
}

fn validate_receipt_file_shape(
    path: &Path,
    custody: ReceiptCustody,
    label: &str,
) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == custody.uid
                && metadata.gid() == custody.gid
                && metadata.nlink() == 1 =>
        {
            Ok(())
        }
        Ok(_) => Err(format!("{label}-not-engine-controlled")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("{label}-observe-failed: {error}")),
    }
}

fn prepare_receipt_directory(path: &Path, custody: ReceiptCustody) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("managed-directory-must-be-absolute".into());
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(format!(
                    "managed-directory-path-not-real-directory-{}",
                    current.display()
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)
                    .map_err(|error| format!("receipt-directory-create-failed: {error}"))?;
                own_path(&current, custody.uid, custody.gid, 0o700)?;
            }
            Err(error) => return Err(format!("receipt-directory-observe-failed: {error}")),
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != custody.uid
        || metadata.gid() != custody.gid
    {
        return Err("receipt-directory-not-engine-controlled".into());
    }
    Ok(())
}

fn own_path(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<(), String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| error.to_string())?;
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err("managed-path-owner-assignment-failed".into());
    }
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|error| error.to_string())
}

fn atomic_write_owned(
    path: &Path,
    bytes: &[u8],
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == uid
                && metadata.gid() == gid
                && metadata.nlink() == 1 => {}
        Ok(_) => return Err("native-receipt-file-not-engine-controlled".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("receipt-file-observe-failed: {error}")),
    }
    let parent = path.parent().ok_or("native-receipt-parent-missing")?;
    let temp = parent.join(format!(
        ".hermes-maintenance-receipt-{}-{}.tmp",
        std::process::id(),
        now_nanos()?
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)
        .map_err(|error| format!("native-receipt-temp-create-failed: {error}"))?;
    let result = (|| -> Result<(), String> {
        file.write_all(bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if (metadata.uid(), metadata.gid()) != (uid, gid)
            && unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0
        {
            return Err("native-receipt-temp-owner-assignment-failed".into());
        }
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|error| error.to_string())?;
        Ok(())
    })();
    if let Err(error) = result {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    drop(file);
    fs::rename(&temp, path).map_err(|error| {
        let _ = fs::remove_file(&temp);
        format!("native-receipt-atomic-promote-failed: {error}")
    })?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("native-receipt-parent-sync-failed: {error}"))
}

fn canonical_install_root(path: &Path, owner_uid: u32) -> Result<PathBuf, String> {
    let canonical = path.canonicalize().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            "hermes-install-not-installed".to_string()
        } else {
            format!("hermes-install-root-unavailable: {error}")
        }
    })?;
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|error| format!("hermes-install-root-stat-failed: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != owner_uid {
        return Err("hermes-install-root-not-owner-controlled".into());
    }
    if !canonical.join(".git").exists() {
        return Err("hermes-install-not-installed".into());
    }
    Ok(canonical)
}

fn canonical_parent_file(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("launcher-must-be-absolute".into());
    }
    if path.file_name().and_then(OsStr::to_str) != Some("hermes") {
        return Err("launcher-basename-must-be-hermes".into());
    }
    let parent = path
        .parent()
        .ok_or("launcher-parent-missing")?
        .canonicalize()
        .map_err(|error| format!("launcher-parent-unavailable: {error}"))?;
    let full = parent.join(path.file_name().ok_or("launcher-basename-missing")?);
    let metadata = fs::symlink_metadata(&full).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            "hermes-install-not-installed".to_string()
        } else {
            format!("launcher-unavailable: {error}")
        }
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("launcher-must-be-regular-nonsymlink".into());
    }
    Ok(full)
}

fn validate_launcher_binding(
    root: &Path,
    launcher: &Path,
    owner: &OwnerContext,
    bytes: &[u8],
) -> Result<(), String> {
    let internal = root.join(".hermes/bin/hermes");
    let external = owner.home.join(".local/bin/hermes");
    if launcher == internal {
        return Ok(());
    }
    if launcher != external {
        return Err(format!(
            "hermes-maintenance-launcher-declaration-not-converging: {}",
            launcher.display()
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "launcher-not-recognized-text")?;
    let root_text = root.to_string_lossy();
    let internal_text = internal.to_string_lossy();
    let bound_to_root = text.contains(internal_text.as_ref())
        || (text.contains(root_text.as_ref())
            && (text.contains("venv/bin/hermes")
                || text.contains("hermes_cli.main")
                || text.contains("cd ")
                || text.contains("cd\\t")));
    if !bound_to_root {
        return Err("external-launcher-does-not-bind-declared-install".into());
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct NativeInstallState {
    stamp_fields: Option<InstallStampFields>,
    stamp_coherent: bool,
    reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InstallStampFields {
    commit: Option<Value>,
    branch: Option<Value>,
    dirty: Option<Value>,
    schema_version: Option<Value>,
    update_mechanism: Option<Value>,
}

impl InstallStampFields {
    fn from_stamp(stamp: &Value) -> Self {
        let mut commit = stamp.get("commit").cloned();
        if let Some(Value::String(value)) = &mut commit {
            *value = value.to_ascii_lowercase();
        }
        Self {
            commit,
            branch: stamp.get("branch").cloned(),
            dirty: stamp.get("dirty").cloned(),
            schema_version: stamp.get("schemaVersion").cloned(),
            update_mechanism: stamp.get("updateMechanism").cloned(),
        }
    }
}

/// Read the native source-install identity and managed runtime without
/// executing Hermes or creating an observation profile. Upstream's plain
/// `--version` path is not an observation: its update check writes a cache.
fn inspect_native_install_state(
    root: &Path,
    launcher: &Path,
    owner: &OwnerContext,
    head: &str,
) -> Result<NativeInstallState, String> {
    let internal_launcher = root.join(".hermes/bin/hermes");
    let external_launcher = owner.home.join(".local/bin/hermes");
    let layout = if launcher == internal_launcher {
        "native-internal".to_owned()
    } else if launcher == external_launcher {
        "native-external".to_owned()
    } else {
        "legacy".to_owned()
    };
    let mut reasons = Vec::new();
    if layout == "legacy" {
        reasons.push("legacy-install-layout".into());
    }

    // Upstream may ignore this generated stamp in Git; validate its bytes independently.
    let stamp_path = root.join("install-stamp.json");
    let stamp_bytes = read_owner_file(&stamp_path, owner, 1024 * 1024, "native-install-stamp")?;
    let mut stamp_fields = None;
    let mut stamp_coherent = false;
    // Native bootstrap installs may omit runtimeDir; their managed tools live outside source_root.
    let mut runtime_root = owner.hermes_home.join("tools");
    match stamp_bytes {
        Some(bytes) => {
            match serde_json::from_slice::<Value>(&bytes) {
                Ok(stamp) if stamp.is_object() => {
                    stamp_fields = Some(InstallStampFields::from_stamp(&stamp));
                    let commit = stamp.get("commit").and_then(Value::as_str);
                    stamp_coherent = stamp.get("schemaVersion").and_then(Value::as_u64) == Some(2)
                        && commit.is_some_and(|value| value.eq_ignore_ascii_case(head))
                        && stamp.get("updateMechanism").and_then(Value::as_str) == Some("self")
                        && stamp.get("dirty").and_then(Value::as_bool) == Some(false)
                        && stamp.get("branch").and_then(Value::as_str) == Some("main");
                    if !stamp_coherent {
                        reasons.push("native-install-stamp-not-coherent".into());
                    }
                    match stamp.get("runtimeDir") {
                        None | Some(Value::Null) => {}
                        Some(Value::String(value)) if !value.is_empty() => {
                            let declared = PathBuf::from(value);
                            runtime_root = if declared.is_absolute() {
                                declared
                            } else {
                                root.join(declared)
                            };
                        }
                        Some(_) => reasons.push("native-runtime-directory-invalid".into()),
                    }
                }
                _ => reasons.push("native-install-stamp-invalid".into()),
            }
        }
        None => reasons.push("native-install-stamp-missing".into()),
    }

    let facts_path = runtime_root.join("facts.json");
    if reject_symlink_components(&runtime_root).is_err() {
        reasons.push("native-runtime-path-not-real".into());
    } else {
        match read_owner_file(&facts_path, owner, 4 * 1024 * 1024, "native-runtime-facts")? {
            Some(bytes) => {
                let entry = serde_json::from_slice::<Value>(&bytes)
                    .ok()
                    .and_then(|facts| {
                        facts
                            .get("packages")?
                            .get("python")?
                            .get("entry")?
                            .as_str()
                            .map(str::to_owned)
                    });
                let Some(entry) = entry else {
                    reasons.push("native-runtime-python-entry-missing".into());
                    return Ok(NativeInstallState {
                        stamp_fields,
                        stamp_coherent,
                        reasons,
                    });
                };
                let entry_path = Path::new(&entry);
                if entry_path.is_absolute()
                    || entry_path.components().any(|component| {
                        !matches!(component, std::path::Component::Normal(_))
                    })
                {
                    reasons.push("native-runtime-python-entry-invalid".into());
                } else {
                    let python = runtime_root.join(entry_path).join("bin/python3");
                    if canonical_runtime_executable(&python, owner).is_err() {
                        reasons.push("native-runtime-python-not-runnable".into());
                    }
                }
            }
            None => reasons.push("native-runtime-facts-missing".into()),
        }
    }

    Ok(NativeInstallState {
        stamp_fields,
        stamp_coherent,
        reasons,
    })
}

/// `--porcelain=v1 -z` may expose this generated untracked stamp when upstream
/// does not ignore it. Only its exact path with a coherent stamp is tolerated;
/// tracked modifications and all other worktree entries remain dirty.
fn source_status_is_clean(status: &[u8], stamp_coherent: bool) -> bool {
    status.is_empty() || (stamp_coherent && status == b"?? install-stamp.json\0")
}

fn canonical_runtime_executable(path: &Path, owner: &OwnerContext) -> Result<PathBuf, String> {
    let parent = path
        .parent()
        .ok_or("native-runtime-python-parent-missing")?;
    reject_symlink_components(parent).map_err(|_| "native-runtime-python-parent-not-real")?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|error| format!("native-runtime-python-parent-unavailable: {error}"))?;
    let resolved = path
        .canonicalize()
        .map_err(|error| format!("native-runtime-python-unavailable: {error}"))?;
    if !resolved.starts_with(&canonical_parent) {
        return Err("native-runtime-python-target-outside-runtime-bin".into());
    }
    let metadata = fs::symlink_metadata(&resolved)
        .map_err(|error| format!("native-runtime-python-stat-failed: {error}"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner.uid
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err("native-runtime-python-not-owner-controlled-executable".into());
    }
    Ok(resolved)
}

fn read_owner_file(
    path: &Path,
    owner: &OwnerContext,
    limit: u64,
    label: &str,
) -> Result<Option<Vec<u8>>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{label}-observe-failed: {error}")),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner.uid
        || metadata.gid() != owner.gid
        || metadata.nlink() != 1
        || metadata.len() > limit
    {
        return Err(format!("{label}-not-owner-controlled-regular-file"));
    }
    fs::read(path)
        .map(Some)
        .map_err(|error| format!("{label}-read-failed: {error}"))
}

fn reject_symlink_components(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("managed-runtime-path-not-absolute".into());
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("managed-runtime-path-has-symlink-{}", current.display()))
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(format!("managed-runtime-path-observe-failed: {error}")),
        }
    }
    Ok(())
}

fn static_runnable_probe(launcher: &Path, bytes: &[u8]) -> Result<(), String> {
    let metadata = fs::symlink_metadata(launcher)
        .map_err(|error| format!("launcher-runnable-stat-failed: {error}"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err("launcher-not-runnable-executable-file".into());
    }
    if bytes.starts_with(b"\x7fELF") {
        return Ok(());
    }
    let line = bytes
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let shebang = line.strip_prefix(b"#!").ok_or("launcher-shebang-missing")?;
    let text = std::str::from_utf8(shebang)
        .map_err(|_| "launcher-shebang-not-utf8")?
        .trim();
    let mut words = text.split_whitespace();
    let interpreter = words.next().ok_or("launcher-interpreter-missing")?;
    let executable = if interpreter == "/usr/bin/env" {
        let command = words
            .find(|word| !word.starts_with('-'))
            .ok_or("launcher-env-interpreter-missing")?;
        find_on_fixed_path(command).ok_or("launcher-env-interpreter-unavailable")?
    } else {
        PathBuf::from(interpreter)
    };
    let interpreter_meta = fs::metadata(&executable)
        .map_err(|error| format!("launcher-interpreter-unavailable: {error}"))?;
    if !interpreter_meta.is_file() || interpreter_meta.permissions().mode() & 0o111 == 0 {
        return Err("launcher-interpreter-not-executable".into());
    }
    Ok(())
}

fn find_on_fixed_path(command: &str) -> Option<PathBuf> {
    if command.contains('/') {
        let path = PathBuf::from(command);
        return path.is_file().then_some(path);
    }
    OWNER_PATH
        .split(':')
        .map(|directory| Path::new(directory).join(command))
        .find(|path| path.is_file())
}

fn resolve_remote_main(url: &str) -> Result<String, String> {
    let output = run_owner_command(
        "git",
        &["ls-remote", url, "refs/heads/main"],
        None,
        BTreeMap::from([
            ("GIT_OPTIONAL_LOCKS".into(), "0".into()),
            ("GIT_TERMINAL_PROMPT".into(), "0".into()),
        ]),
        900,
    )
    .map_err(|error| format!("upstream-main-resolution-failed: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "upstream-main-resolution-failed-exit-{:?}",
            output.status.code()
        ));
    }
    let text =
        std::str::from_utf8(&output.stdout).map_err(|_| "upstream-main-response-not-utf8")?;
    let mut fields = text.split_whitespace();
    let sha = fields.next().ok_or("upstream-main-absent")?;
    let reference = fields.next().ok_or("upstream-main-ref-absent")?;
    if reference != "refs/heads/main" {
        return Err("upstream-main-resolution-malformed".into());
    }
    validate_sha(sha, "upstream-main")?;
    Ok(sha.to_ascii_lowercase())
}

fn validate_origin(root: &Path) -> Result<(), String> {
    let origin = git_text(root, &["remote", "get-url", "origin"])?;
    if !official_url(&origin) {
        return Err("foreign-origin-preserved".into());
    }
    Ok(())
}

fn update_marker_present(root: &Path, owner: &OwnerContext) -> Result<bool, String> {
    for marker in [
        root.join(".hermes-update-in-progress"),
        owner.hermes_home.join(".hermes-update-in-progress"),
    ] {
        match fs::symlink_metadata(&marker) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("native-update-marker-observe-failed: {error}")),
        }
    }
    Ok(false)
}

fn updater_is_live(root: &Path, owner: &OwnerContext) -> Result<bool, String> {
    let common = PathBuf::from(git_text(root, &["rev-parse", "--git-common-dir"])?);
    let common = if common.is_absolute() {
        common
    } else {
        root.join(common)
    };
    let common = common
        .canonicalize()
        .map_err(|error| format!("git-common-dir-unavailable: {error}"))?;
    let lock = common.join("hermes-update.lock");
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock)
    {
        Ok(file) => {
            let metadata = file.metadata().map_err(|error| error.to_string())?;
            if !metadata.is_file() || metadata.nlink() != 1 || metadata.uid() != owner.uid {
                return Err("upstream-update-lock-not-owner-controlled".into());
            }
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(true);
                }
                return Err(format!("upstream-update-lock-probe-failed: {error}"));
            }
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) } != 0 {
                return Err(format!(
                    "upstream-update-lock-probe-release-failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("upstream-update-lock-probe-failed: {error}")),
    }
    for marker in [
        root.join(".hermes-update-in-progress"),
        owner.hermes_home.join(".hermes-update-in-progress"),
    ] {
        if marker_pid_live(&marker, owner.uid)? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Clone)]
struct UpdateMarkerSnapshot {
    bytes: Vec<u8>,
    metadata: fs::Metadata,
}

#[derive(Clone)]
struct MarkerClaim {
    pid: Option<i32>,
    started_at: Option<String>,
    creation_time: Option<String>,
}

struct LinuxProcessIdentity {
    start_epoch: Option<f64>,
}

fn marker_pid_live(path: &Path, owner_uid: u32) -> Result<bool, String> {
    let Some(snapshot) = read_update_marker_snapshot(path, owner_uid)? else {
        return Ok(false);
    };
    Ok(marker_snapshot_has_live_claim(&snapshot))
}

fn read_update_marker_snapshot(
    path: &Path,
    owner_uid: u32,
) -> Result<Option<UpdateMarkerSnapshot>, String> {
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("native-update-marker-observe-failed: {error}")),
    };
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.uid() != owner_uid
        || before.nlink() != 1
        || before.len() > UPDATE_MARKER_MAX_BYTES
    {
        return Err("native-update-marker-shape-invalid".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("native-update-marker-open-failed: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("native-update-marker-fstat-failed: {error}"))?;
    if !opened.is_file()
        || opened.uid() != owner_uid
        || opened.nlink() != 1
        || opened.len() > UPDATE_MARKER_MAX_BYTES
        || opened.dev() != before.dev()
        || opened.ino() != before.ino()
    {
        return Err("native-update-marker-custody-changed".into());
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    Read::take(file, UPDATE_MARKER_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("native-update-marker-read-failed: {error}"))?;
    if bytes.len() as u64 > UPDATE_MARKER_MAX_BYTES {
        return Err("native-update-marker-size-exceeds-bound".into());
    }
    let after = fs::symlink_metadata(path)
        .map_err(|error| format!("native-update-marker-readback-stat-failed: {error}"))?;
    if !after.is_file()
        || after.file_type().is_symlink()
        || after.uid() != owner_uid
        || after.nlink() != 1
        || after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.len() != bytes.len() as u64
        || marker_metadata_mtime(&after) != marker_metadata_mtime(&opened)
    {
        return Err("native-update-marker-changed-during-read".into());
    }
    Ok(Some(UpdateMarkerSnapshot {
        bytes,
        metadata: opened,
    }))
}

fn marker_metadata_mtime(metadata: &fs::Metadata) -> f64 {
    metadata.mtime() as f64 + metadata.mtime_nsec() as f64 / 1_000_000_000.0
}

fn marker_snapshot_has_live_claim(snapshot: &UpdateMarkerSnapshot) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(f64::NAN);
    marker_claims(&snapshot.bytes)
        .iter()
        .any(|claim| marker_claim_is_live(claim, marker_metadata_mtime(&snapshot.metadata), now))
}

fn marker_claim_is_live(claim: &MarkerClaim, mtime: f64, now: f64) -> bool {
    let Some(pid) = claim.pid.filter(|pid| *pid > 1) else {
        return false;
    };
    let Some(identity) = linux_process_identity(pid) else {
        return false;
    };
    if let Some(raw_creation_time) = claim.creation_time.as_deref() {
        let Ok(expected) = raw_creation_time.parse::<f64>() else {
            return false;
        };
        if !expected.is_finite() || expected <= 0.0 {
            return false;
        }
        return identity.start_epoch.is_some_and(|observed| {
            observed.is_finite()
                && (observed - expected).abs() <= UPDATE_MARKER_CREATE_TIME_TOLERANCE_SECS
        });
    }
    let timestamp = match claim.started_at.as_deref() {
        Some(raw) => match raw.parse::<f64>() {
            Ok(timestamp) if timestamp.is_finite() && timestamp > 0.0 => timestamp,
            _ => return false,
        },
        None => mtime,
    };
    timestamp.is_finite()
        && timestamp <= now + UPDATE_MARKER_FUTURE_SKEW_SECS
        && now - timestamp <= UPDATE_MARKER_MAX_AGE_SECS
}

fn linux_process_identity(pid: i32) -> Option<LinuxProcessIdentity> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.rfind(')')?;
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    let state = *fields.first()?;
    if matches!(state, "Z" | "X") {
        return None;
    }
    let start_ticks = fields.get(19)?.parse::<u64>().ok()?;
    let boot_epoch = fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("btime "))?
        .parse::<u64>()
        .ok()? as f64;
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let start_epoch = (ticks_per_second > 0)
        .then(|| boot_epoch + start_ticks as f64 / ticks_per_second as f64);
    Some(LinuxProcessIdentity { start_epoch })
}

fn marker_claims(bytes: &[u8]) -> Vec<MarkerClaim> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let text = text.trim_start_matches(|character: char| {
        character.is_whitespace() || character == '\u{feff}'
    });
    if let Ok(value) = serde_json::from_str::<Value>(text.trim()) {
        if value.is_object() {
            return json_marker_claims(&value);
        }
    }
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let Some(first) = lines.first() else {
        return Vec::new();
    };
    let mut claims = vec![MarkerClaim {
        pid: parse_pid(first),
        started_at: lines.get(1).map(|line| line.to_string()),
        creation_time: None,
    }];
    for line in lines.iter().skip(2) {
        if let Some(raw) = line.strip_prefix("ct:") {
            claims[0].creation_time = Some(if claims[0].creation_time.is_some() {
                String::new()
            } else {
                raw.trim().to_string()
            });
        } else if let Some(claim) = parse_delegate_claim(line, claims[0].started_at.clone()) {
            claims.push(claim);
        }
    }
    claims
}

fn json_marker_claims(value: &Value) -> Vec<MarkerClaim> {
    let mut claims = Vec::new();
    let pid = value.get("pid").or_else(|| value.get("process_id"));
    if pid.is_some() {
        claims.push(MarkerClaim {
            pid: pid.and_then(json_pid),
            started_at: json_raw_field(value, &["started_at", "startedAt"]),
            creation_time: json_raw_field(value, &["ct", "creation_time"]),
        });
    }
    if let Some(delegate) = value.get("delegate") {
        if delegate.is_object() {
            let pid = delegate
                .get("pid")
                .or_else(|| delegate.get("process_id"));
            if pid.is_some() {
                claims.push(MarkerClaim {
                    pid: pid.and_then(json_pid),
                    started_at: json_raw_field(delegate, &["started_at", "startedAt"]),
                    creation_time: json_raw_field(delegate, &["ct", "creation_time"]),
                });
            }
        }
    }
    if value.get("delegate_pid").is_some() {
        claims.push(MarkerClaim {
            pid: value.get("delegate_pid").and_then(json_pid),
            started_at: json_raw_field(value, &["started_at", "startedAt"]),
            creation_time: json_raw_field(value, &["delegate_ct", "delegate_creation_time"]),
        });
    }
    claims
}

fn json_raw_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value.get(*key).map(|value| match value {
            Value::String(text) => text.trim().to_string(),
            Value::Number(number) => number.to_string(),
            _ => String::new(),
        })
    })
}

fn json_pid(value: &Value) -> Option<i32> {
    value
        .as_i64()
        .and_then(|pid| i32::try_from(pid).ok())
        .or_else(|| value.as_str().and_then(parse_pid))
}

fn parse_pid(value: &str) -> Option<i32> {
    value.trim().parse::<i32>().ok().filter(|pid| *pid > 1)
}

fn parse_delegate_claim(line: &str, started_at: Option<String>) -> Option<MarkerClaim> {
    let rest = line.strip_prefix("delegate:")?.trim();
    let mut words = rest.split_whitespace();
    let pid = words.next().and_then(parse_pid);
    let creation_time = words.find_map(|word| {
        word.strip_prefix("ct:")
            .map(|value| value.trim().to_string())
    });
    Some(MarkerClaim {
        pid,
        started_at,
        creation_time,
    })
}

fn git_text(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = git_output(root, args)?;
    if !output.status.success() {
        return Err(format!(
            "git-command-failed-{}-exit-{:?}",
            args.join("-"),
            output.status.code()
        ));
    }
    String::from_utf8(output.stdout)
        .map(|text| text.trim().to_owned())
        .map_err(|_| "git-command-output-not-utf8".into())
}
fn git_optional_text(root: &Path, args: &[&str]) -> Result<Option<String>, String> {
    let output = git_output(root, args)?;
    match output.status.code() {
        Some(0) => String::from_utf8(output.stdout)
            .map(|text| Some(text.trim().to_owned()))
            .map_err(|_| "git-command-output-not-utf8".into()),
        Some(1) => Ok(None),
        code => Err(format!(
            "git-command-failed-{}-exit-{code:?}",
            args.join("-")
        )),
    }
}
fn git_output(root: &Path, args: &[&str]) -> Result<CapturedOutput, String> {
    let root = root.to_str().ok_or("maintenance-git-path-not-utf8")?;
    let mut argv = vec!["-C", root];
    argv.extend_from_slice(args);
    run_owner_command(
        "git",
        &argv,
        None,
        BTreeMap::from([
            ("GIT_OPTIONAL_LOCKS".into(), "0".into()),
            ("GIT_TERMINAL_PROMPT".into(), "0".into()),
        ]),
        UPDATER_TIMEOUT_SECS,
    )
}
fn git_output_raw(root: &Path, args: &[&str]) -> Result<Output, String> {
    let root = root.to_str().ok_or("maintenance-git-path-not-utf8")?;
    let mut argv = vec!["-C", root];
    argv.extend_from_slice(args);
    let owner = current_owner_context()?;
    let mut env = owner_environment(&owner);
    env.insert("GIT_OPTIONAL_LOCKS".into(), "0".into());
    env.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
    crate::atoms::command::capture_bytes_with_command_bearer_and_env(
        "git",
        &argv,
        None,
        &owner.command_bearer,
        env,
        UPDATER_TIMEOUT_SECS,
        COMMAND_OUTPUT_LIMIT,
    )
}
fn is_ancestor(root: &Path, older: &str, newer: &str) -> Result<bool, String> {
    let output = git_output(root, &["merge-base", "--is-ancestor", older, newer])?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        code => Err(format!("git-ancestry-check-failed-exit-{code:?}")),
    }
}
fn validate_sha(value: &str, label: &str) -> Result<(), String> {
    if matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!("{label}-sha-invalid"))
    }
}

fn prove_launch_isolated(launcher: &Path, source_root: &Path) -> Result<(), String> {
    let temp = isolated_tempdir()?;
    let hermes_home = temp.path.join("hermes-home");
    let config_home = temp.path.join("config");
    let data_home = temp.path.join("data");
    let state_home = temp.path.join("state");
    let cache_home = temp.path.join("cache");
    let tmp_dir = temp.path.join("tmp");
    for path in [
        &hermes_home,
        &config_home,
        &data_home,
        &state_home,
        &cache_home,
        &tmp_dir,
    ] {
        fs::create_dir(path)
            .map_err(|error| format!("isolated-profile-directory-create-failed: {error}"))?;
        own_path(
            path,
            current_owner_context()?.uid,
            current_owner_context()?.gid,
            0o700,
        )?;
    }
    let owner = current_owner_context()?;
    let internal_launcher = source_root.join(".hermes/bin/hermes");
    let external_native_binding = if launcher == owner.home.join(".local/bin/hermes") {
        let launcher_text = read_owner_file(launcher, &owner, 1024 * 1024, "isolated-launcher")
            .ok()
            .flatten()
            .and_then(|bytes| String::from_utf8(bytes).ok());
        launcher_text
            .as_deref()
            .zip(internal_launcher.to_str())
            .is_some_and(|(text, internal_path)| {
                text.lines().any(|line| {
                    let mut words = line.split_whitespace();
                    words.next() == Some("exec") && words.next() == Some(internal_path)
                })
            })
    } else {
        false
    };
    if launcher == internal_launcher || external_native_binding {
        stage_isolated_native_dependency_selection(source_root, &hermes_home, &owner)?;
    }
    let output = run_owner_command(
        &launcher.to_string_lossy(),
        &["--version"],
        Some(source_root),
        BTreeMap::from([
            (
                "HERMES_HOME".into(),
                hermes_home.to_string_lossy().into_owned(),
            ),
            (
                "XDG_CONFIG_HOME".into(),
                config_home.to_string_lossy().into_owned(),
            ),
            (
                "XDG_DATA_HOME".into(),
                data_home.to_string_lossy().into_owned(),
            ),
            (
                "XDG_STATE_HOME".into(),
                state_home.to_string_lossy().into_owned(),
            ),
            (
                "XDG_CACHE_HOME".into(),
                cache_home.to_string_lossy().into_owned(),
            ),
            ("TMPDIR".into(), tmp_dir.to_string_lossy().into_owned()),
            ("HERMES_DISABLE_LAZY_INSTALLS".into(), "1".into()),
            ("PYTHONDONTWRITEBYTECODE".into(), "1".into()),
        ]),
        120,
    )?;
    if output.status.success() {
        Ok(())
    } else {
        Err("isolated-launch-version-probe-failed".into())
    }
}

fn stage_isolated_native_dependency_selection(
    source_root: &Path,
    isolated_hermes_home: &Path,
    owner: &OwnerContext,
) -> Result<(), String> {
    let canonical_root = source_root
        .canonicalize()
        .map_err(|error| format!("isolated-native-source-root-unavailable: {error}"))?;
    let canonical_text = canonical_root
        .to_str()
        .ok_or("isolated-native-source-root-not-utf8")?;
    let install_digest = digest(canonical_text.as_bytes());
    let install_key = &install_digest[..16];
    let source_install = owner.hermes_home.join("installs").join(install_key);
    reject_symlink_components(&source_install)
        .map_err(|_| "isolated-native-install-state-not-real")?;
    let source_facts = source_install.join("facts.json");
    let facts = read_owner_file(
        &source_facts,
        owner,
        4 * 1024 * 1024,
        "isolated-native-runtime-facts",
    )?
    .ok_or("isolated-native-runtime-facts-missing")?;
    let parsed = serde_json::from_slice::<Value>(&facts)
        .map_err(|_| "isolated-native-runtime-facts-invalid")?;
    let environment = parsed
        .get("packages")
        .and_then(|packages| packages.get("venv"))
        .and_then(|venv| venv.get("environment"))
        .and_then(Value::as_str)
        .ok_or("isolated-native-dependency-selection-missing")?;
    let environment = Path::new(environment);
    if !environment.is_absolute() {
        return Err("isolated-native-dependency-environment-not-absolute".into());
    }

    let source_generations = source_install.join("environments");
    reject_symlink_components(&source_generations)
        .map_err(|_| "isolated-native-environments-path-not-real")?;
    let canonical_generations = source_generations
        .canonicalize()
        .map_err(|error| format!("isolated-native-environments-unavailable: {error}"))?;
    let canonical_environment = environment
        .canonicalize()
        .map_err(|error| format!("isolated-native-dependency-environment-unavailable: {error}"))?;
    let environment_metadata = fs::symlink_metadata(&canonical_environment)
        .map_err(|error| format!("isolated-native-dependency-environment-stat-failed: {error}"))?;
    if !canonical_environment.starts_with(&canonical_generations)
        || !environment_metadata.is_dir()
        || environment_metadata.file_type().is_symlink()
        || environment_metadata.uid() != owner.uid
        || !canonical_environment.join("pyvenv.cfg").is_file()
    {
        return Err("isolated-native-dependency-environment-not-owner-controlled".into());
    }

    let isolated_installs = isolated_hermes_home.join("installs");
    fs::create_dir(&isolated_installs)
        .map_err(|error| format!("isolated-native-installs-create-failed: {error}"))?;
    own_path(&isolated_installs, owner.uid, owner.gid, 0o700)?;
    let isolated_install = isolated_installs.join(install_key);
    fs::create_dir(&isolated_install)
        .map_err(|error| format!("isolated-native-install-create-failed: {error}"))?;
    own_path(&isolated_install, owner.uid, owner.gid, 0o700)?;
    // Upstream resolves the selected venv and requires it below the active install state's
    // environments directory. Keep its facts bytes unchanged and expose only that path in the
    // temporary home; the dependency generation itself remains in the owner's store.
    symlink(
        &canonical_generations,
        isolated_install.join("environments"),
    )
    .map_err(|error| format!("isolated-native-environments-link-failed: {error}"))?;
    write_isolated_owner_file(&isolated_install.join("facts.json"), &facts, owner)
}

fn write_isolated_owner_file(
    path: &Path,
    bytes: &[u8],
    owner: &OwnerContext,
) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("isolated-native-facts-create-failed: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("isolated-native-facts-write-failed: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("isolated-native-facts-sync-failed: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("isolated-native-facts-stat-failed: {error}"))?;
    if (metadata.uid(), metadata.gid()) != (owner.uid, owner.gid)
        && unsafe { libc::fchown(file.as_raw_fd(), owner.uid, owner.gid) } != 0
    {
        return Err("isolated-native-facts-owner-assignment-failed".into());
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("isolated-native-facts-mode-set-failed: {error}"))
}

struct ScopedTempDir {
    path: PathBuf,
    created_parents: Vec<PathBuf>,
}
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
impl Drop for ScopedTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
        for parent in self.created_parents.iter().rev() {
            let _ = fs::remove_dir(parent);
        }
    }
}
fn isolated_tempdir() -> Result<ScopedTempDir, String> {
    let owner = current_owner_context()?;
    let base = owner.home.join(".cache/hermes-maintenance/tmp");
    let created_parents =
        create_owned_directory_tree_track(&base, &owner.home, owner.uid, owner.gid)?;
    for _ in 0..128 {
        let path = base.join(format!(
            "hermes-maintenance-{}-{}-{}",
            std::process::id(),
            now_nanos()?,
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                own_path(&path, owner.uid, owner.gid, 0o700)?;
                return Ok(ScopedTempDir {
                    path,
                    created_parents,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("isolated-temporary-directory-failed: {error}")),
        }
    }
    Err("isolated-temporary-directory-name-collision-limit".into())
}
fn create_owned_directory_tree_track(
    path: &Path,
    owner_home: &Path,
    uid: u32,
    gid: u32,
) -> Result<Vec<PathBuf>, String> {
    if !path.is_absolute() || !owner_home.is_absolute() || !path.starts_with(owner_home) {
        return Err("temporary-parent-outside-owner-home".into());
    }
    let mut current = PathBuf::new();
    let mut created = Vec::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || (current.starts_with(owner_home) && metadata.uid() != uid)
                {
                    return Err(format!(
                        "temporary-parent-not-owner-controlled-{}",
                        current.display()
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)
                    .map_err(|error| format!("temporary-parent-create-failed: {error}"))?;
                own_path(&current, uid, gid, 0o700)?;
                created.push(current.clone());
            }
            Err(error) => return Err(format!("temporary-parent-observe-failed: {error}")),
        }
    }
    Ok(created)
}

fn hash_optional_file(path: &Path) -> Result<Option<String>, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            let bytes =
                fs::read(path).map_err(|error| format!("config-hash-read-failed: {error}"))?;
            Ok(Some(digest(&bytes)))
        }
        Ok(_) => Err("config-hash-path-not-regular-file".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("config-hash-observe-failed: {error}")),
    }
}

fn latest_native_receipt(directory: &Path) -> Option<String> {
    let entries = fs::read_dir(directory).ok()?;
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            let unique_name = name.strip_prefix("update_")?.strip_suffix(".json")?;
            if unique_name.is_empty() {
                return None;
            }
            let metadata = fs::symlink_metadata(entry.path()).ok()?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return None;
            }
            Some((metadata.modified().ok()?, entry.path()))
        })
        .max_by(|(left_modified, left_path), (right_modified, right_path)| {
            left_modified
                .cmp(right_modified)
                .then_with(|| left_path.cmp(right_path))
        })
        .map(|(_, path)| path.to_string_lossy().into_owned())
}

fn unique_name(prefix: &str) -> String {
    format!(
        "{prefix}-{}-{}",
        std::process::id(),
        now_nanos().unwrap_or_default()
    )
}
fn now_nanos() -> Result<u128, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos())
}
fn digest(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    hex(&hash)
}
fn hex(bytes: &[u8]) -> String {
    const H: &[u8] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(H[(byte >> 4) as usize] as char);
        output.push(H[(byte & 0x0f) as usize] as char);
    }
    output
}
