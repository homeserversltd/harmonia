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
use std::io::Write;
use std::os::fd::AsRawFd;
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
    stderr: Vec<u8>,
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
        stderr: output.stderr,
    })
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
    pub(crate) native_state_sha256: String,
    pub(crate) launcher_mode: u32,
    pub(crate) launcher_uid: u32,
    pub(crate) launcher_gid: u32,
    pub(crate) branch: Option<String>,
    pub(crate) dirty: bool,
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
    pre_sha: String,
    branch: Option<String>,
    launcher_bytes: Vec<u8>,
    launcher_mode: u32,
    launcher_uid: u32,
    launcher_gid: u32,
    owner_uid: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct Movement {
    pub(crate) pre_sha: String,
    pub(crate) target_sha: String,
    pub(crate) post_sha: Option<String>,
    pub(crate) movement: String,
    pub(crate) stage: String,
    pub(crate) updater_exit_code: Option<i32>,
    pub(crate) stash_names_created: Vec<String>,
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
    stash_names_created: Vec<String>,
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
        native_state_sha256: native_state.fingerprint(),
        launcher_mode: launcher_meta.permissions().mode() & 0o7777,
        launcher_uid: launcher_meta.uid(),
        launcher_gid: launcher_meta.gid(),
        branch,
        dirty,
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
    let snapshot = RollbackSnapshot {
        source_root: observed.source_root.clone(),
        launcher: observed.launcher.clone(),
        pre_sha: pre_sha.clone(),
        branch: observed.branch.clone(),
        launcher_bytes,
        launcher_mode: observed.launcher_mode,
        launcher_uid: observed.launcher_uid,
        launcher_gid: observed.launcher_gid,
        owner_uid: owner.uid,
    };
    let mut movement = Movement {
        pre_sha: pre_sha.clone(),
        target_sha: observed.target_sha.clone(),
        post_sha: None,
        movement: "not-started".into(),
        stage: "pre-action".into(),
        updater_exit_code: None,
        stash_names_created: Vec::new(),
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
    let action_result = (|| -> Result<(), String> {
        movement.stage = "preserve-local-custody".into();
        let ref_name = preserve_head_ref(&observed.source_root, &pre_sha)?;
        movement.preserved_refs_created.push(ref_name);
        let status = git_output_raw(
            &observed.source_root,
            &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        )?;
        if !status.status.success() {
            return Err("source-status-before-stash-failed".into());
        }
        if !status.stdout.is_empty() {
            let stash_message = unique_name("hermes-maintenance-preserved");
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
            movement
                .stash_names_created
                .push(format!("stash@{{0}}:{stash_message}:{stash_sha}"));
        }
        if updater_is_live(&observed.source_root, &owner)? {
            return Err("native-updater-live-retry".into());
        }
        movement.stage = "native-update".into();
        let args = [
            "update",
            "--yes",
            "--no-gateway-restart",
            "--branch",
            "main",
        ];
        let result = run_owner_command(
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
                if !output.status.success() {
                    return Err("native-updater-returned-nonzero".into());
                }
            }
            Err(error) => return Err(format!("native-updater-timeout-or-capture-failed: {error}")),
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
            || native_state.fingerprint() != observed.native_state_sha256;
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

fn preserve_post_update_worktree(root: &Path, movement: &mut Movement) -> Result<(), String> {
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
        preserve_post_update_worktree(&snapshot.source_root, movement)?;
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
                let switched = git_output(
                    &snapshot.source_root,
                    &["switch", "--quiet", "--force", "--", branch],
                )?;
                if !switched.status.success() {
                    return Err("rollback-original-branch-switch-failed".into());
                }
                let reset = git_output(
                    &snapshot.source_root,
                    &["reset", "--hard", &snapshot.pre_sha],
                )?;
                if !reset.status.success() {
                    return Err("rollback-source-reset-failed".into());
                }
            } else {
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
    restore_launcher(snapshot)?;
    let restored = fs::read(&snapshot.launcher)
        .map_err(|error| format!("rollback-launcher-readback-failed: {error}"))?;
    if restored != snapshot.launcher_bytes {
        return Err("rollback-launcher-byte-readback-mismatch".into());
    }
    static_runnable_probe(&snapshot.launcher, &restored)?;
    prove_launch_isolated(&snapshot.launcher, &snapshot.source_root)?;
    Ok(())
}

fn restore_launcher(snapshot: &RollbackSnapshot) -> Result<(), String> {
    let metadata = fs::symlink_metadata(&snapshot.launcher)
        .map_err(|error| format!("rollback-launcher-stat-failed: {error}"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != snapshot.launcher_uid
        || metadata.nlink() != 1
    {
        return Err("rollback-launcher-custody-changed".into());
    }
    let current = fs::read(&snapshot.launcher)
        .map_err(|error| format!("rollback-launcher-read-failed: {error}"))?;
    if current == snapshot.launcher_bytes {
        if metadata.permissions().mode() & 0o7777 != snapshot.launcher_mode
            || metadata.gid() != snapshot.launcher_gid
        {
            return Err("rollback-launcher-metadata-changed".into());
        }
        return Ok(());
    }
    let parent = snapshot
        .launcher
        .parent()
        .ok_or("rollback-launcher-parent-missing")?;
    let temp = parent.join(format!(
        ".hermes-maintenance-rollback-{}-{}.tmp",
        std::process::id(),
        now_nanos()?
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(snapshot.launcher_mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)
        .map_err(|error| format!("rollback-launcher-temp-create-failed: {error}"))?;
    let write_result = (|| -> Result<(), String> {
        file.write_all(&snapshot.launcher_bytes)
            .map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if (metadata.uid(), metadata.gid()) != (snapshot.launcher_uid, snapshot.launcher_gid)
            && unsafe {
                libc::fchown(
                    file.as_raw_fd(),
                    snapshot.launcher_uid,
                    snapshot.launcher_gid,
                )
            } != 0
        {
            return Err("rollback-launcher-owner-restore-failed".into());
        }
        file.set_permissions(fs::Permissions::from_mode(snapshot.launcher_mode))
            .map_err(|error| error.to_string())?;
        Ok(())
    })();
    if let Err(error) = write_result {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    drop(file);
    fs::rename(&temp, &snapshot.launcher).map_err(|error| {
        let _ = fs::remove_file(&temp);
        format!("rollback-launcher-atomic-rename-failed: {error}")
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("rollback-launcher-parent-sync-failed: {error}"))?;
    Ok(())
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
            stash_names_created: movement.stash_names_created.clone(),
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
            stash_names_created: Vec::new(),
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
        stash_names_created: Vec::new(),
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
    let legacy_venv = [root.join("venv/bin/hermes"), root.join(".venv/bin/hermes")];
    let legacy_wrappers = [root.join("hermes"), root.join("bin/hermes")];
    let external = owner.home.join(".local/bin/hermes");
    let allowed_location = launcher == internal
        || legacy_venv.iter().any(|path| launcher == path)
        || legacy_wrappers.iter().any(|path| launcher == path)
        || launcher == external;
    if !allowed_location {
        return Err("launcher-path-not-bound-to-declared-install".into());
    }
    if launcher == internal || legacy_venv.iter().any(|path| launcher == path) {
        return Ok(());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "launcher-not-recognized-text")?;
    let root_text = root.to_string_lossy();
    let internal_text = internal.to_string_lossy();
    if legacy_wrappers.iter().any(|path| launcher == path)
        && (text.contains("venv/bin")
            || text.contains("hermes_cli.main")
            || text.contains(root_text.as_ref()))
    {
        return Ok(());
    }
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
    stamp_sha256: Option<String>,
    stamp_coherent: bool,
    runtime_facts_sha256: Option<String>,
    layout: String,
    reasons: Vec<String>,
}

impl NativeInstallState {
    fn fingerprint(&self) -> String {
        let stamp = self.stamp_sha256.as_deref().unwrap_or("missing");
        let runtime = self.runtime_facts_sha256.as_deref().unwrap_or("missing");
        digest(format!("{}\0{stamp}\0{runtime}", self.layout).as_bytes())
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
    let mut stamp_sha256 = None;
    let mut stamp_coherent = false;
    // Native bootstrap installs may omit runtimeDir; their managed tools live outside source_root.
    let mut runtime_root = owner.hermes_home.join("tools");
    match stamp_bytes {
        Some(bytes) => {
            stamp_sha256 = Some(digest(&bytes));
            match serde_json::from_slice::<Value>(&bytes) {
                Ok(stamp) if stamp.is_object() => {
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

    let mut runtime_facts_sha256 = None;
    let facts_path = runtime_root.join("facts.json");
    if reject_symlink_components(&runtime_root).is_err() {
        reasons.push("native-runtime-path-not-real".into());
    } else {
        match read_owner_file(&facts_path, owner, 4 * 1024 * 1024, "native-runtime-facts")? {
            Some(bytes) => {
                runtime_facts_sha256 = Some(digest(&bytes));
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
                        stamp_sha256,
                        stamp_coherent,
                        runtime_facts_sha256,
                        layout,
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
        stamp_sha256,
        stamp_coherent,
        runtime_facts_sha256,
        layout,
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
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EWOULDBLOCK) | Some(libc::EAGAIN)
                ) {
                    return Ok(true);
                }
                return Err(format!("upstream-update-lock-probe-failed: {error}"));
            }
            unsafe {
                libc::flock(file.as_raw_fd(), libc::LOCK_UN);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("upstream-update-lock-probe-failed: {error}")),
    }
    for marker in [
        root.join(".hermes-update-in-progress"),
        owner.hermes_home.join(".hermes-update-in-progress"),
    ] {
        if marker_pid_live(&marker)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn marker_pid_live(path: &Path) -> Result<bool, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("native-update-marker-observe-failed: {error}")),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 8192 {
        return Err("native-update-marker-shape-invalid".into());
    }
    let bytes =
        fs::read(path).map_err(|error| format!("native-update-marker-read-failed: {error}"))?;
    let text = String::from_utf8_lossy(&bytes);
    let pid = text.trim().parse::<i32>().ok().or_else(|| {
        serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("pid")
                    .or_else(|| value.get("process_id"))
                    .and_then(Value::as_i64)
                    .and_then(|pid| i32::try_from(pid).ok())
            })
    });
    match pid {
        Some(pid) if pid > 1 => {
            let result = unsafe { libc::kill(pid, 0) };
            if result == 0 {
                Ok(true)
            } else {
                let error = std::io::Error::last_os_error();
                Ok(error.raw_os_error() == Some(libc::EPERM))
            }
        }
        _ => Ok(false),
    }
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
            let metadata = entry.metadata().ok()?;
            if !metadata.is_file() {
                return None;
            }
            Some((metadata.modified().ok()?, entry.path()))
        })
        .max_by_key(|(modified, _)| *modified)
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
