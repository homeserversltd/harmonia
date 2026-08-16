use super::Band;
use std::path::Path;

use crate::module_dispatch::ModuleExecution;

pub(crate) fn enter(enter: &mut impl FnMut(Band) -> Result<(), String>) -> Result<(), String> {
    enter(Band::RenewSelf)
}

/// Renewal owns hotfix selection policy; the established hotfix organ owns operations.
pub(crate) fn select_hotfixes(
    profile: &crate::Profile,
    receipt_dir: &Path,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) {
    crate::run_profile_hotfixes(profile, receipt_dir, invocation);
}

/// Renew-self band entry point for the existing engine-preflight implementation.
pub(crate) fn run(
    module_root: &Path,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<ModuleExecution, String> {
    run_engine_preflight(module_root, receipt_dir, apply, invocation)
}

use crate::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Read;

pub(crate) const PREFLIGHT_SCHEMA: &str = "harmonia.engine.preflight.v1";
const SELF_UPDATE_REEXEC_ENV: &str = "HARMONIA_SELF_UPDATE_REEXEC";
const ENGINE_CONFIG_ENV: &str = "HARMONIA_ENGINE_CONFIG_PATH";
const DEFAULT_ENGINE_CONFIG: &str = "/etc/harmonia/engine.json";
const BOOTSTRAP_ORDER: &str = "credential-validation->source->build->proof->promotion->reexec";
const ENGINE_RATCHET_LOCK_SCHEMA: &str = "harmonia.engine.ratchet_lock.v1";
const DEFAULT_ENGINE_RATCHET_LOCK_NAME: &str = "engine-ratchet-lock.json";
const LEGACY_ROOT_GITCONFIG: &str = "/root/.gitconfig";
const LEGACY_ROOT_FORGEJO_INCLUDE: &str = "/root/.gitconfig.d/forgejo-credentials.inc";
const LEGACY_ROOT_FORGEJO_STORE: &str = "/root/.git-credentials-forgejo";
const LEGACY_OWNER_FORGEJO_STORE: &str = "/home/owner/.git-credentials-forgejo";

#[cfg(test)]
thread_local! {
    static TEST_ENGINE_CONFIG_PATH: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

#[cfg(test)]
fn set_test_engine_config_path(path: Option<PathBuf>) {
    TEST_ENGINE_CONFIG_PATH.with(|slot| {
        *slot.borrow_mut() = path;
    });
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnginePlaneConfig {
    pub source_repo_url: String,
    pub branch: String,
    pub source_dir: PathBuf,
    /// Owner-refreshed local checkout consumed read-only by the root engine lane.
    /// When present, preflight never fetches `source_repo_url`.
    #[serde(default)]
    pub local_source_checkout: Option<PathBuf>,
    pub install_bin: PathBuf,
    pub enabled: bool,
    /// Compatibility field retained for installer/live-config schema parity.
    /// Credential custody is fixed to `owner` operationally and this value is
    /// never consulted after load validation.
    #[serde(default = "default_git_bearer")]
    pub git_bearer: String,
    #[serde(default = "default_remote")]
    pub remote: String,
    #[serde(default)]
    pub build_program: Option<String>,
    #[serde(default)]
    pub build_args: Option<Vec<String>>,
    #[serde(default)]
    pub staged_bin: Option<PathBuf>,
    #[serde(default)]
    pub profile_index: Option<PathBuf>,
    #[serde(default)]
    pub ratchet_lock: Option<PathBuf>,
    #[serde(default)]
    pub artifact_transport: Option<EngineArtifactTransport>,
    #[serde(default)]
    pub artifact_transports: Vec<EngineArtifactTransport>,
    /// Additive body declaration for non-engine Git source components.
    #[serde(default)]
    pub source_components: BTreeMap<String, EngineSourceComponent>,
    /// Compatibility projection for established source callers. Renew-self
    /// never uses selector names or reads any credential from this map.
    #[serde(default)]
    pub credential_scopes: BTreeMap<String, tools::git_artifact::CredentialScope>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EngineSourceComponent {
    pub repo_url: String,
    #[serde(default = "default_artifact_branch")]
    pub branch: String,
}

impl EnginePlaneConfig {
    fn artifact_transport_chain(&self) -> Vec<EngineArtifactTransport> {
        if !self.artifact_transports.is_empty() {
            return self.artifact_transports.clone();
        }
        self.artifact_transport.clone().into_iter().collect()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EngineArtifactTransport {
    #[serde(default)]
    pub name: Option<String>,
    pub repo_url: String,
    #[serde(default = "default_artifact_branch")]
    pub branch: String,
    pub cache_dir: PathBuf,
    #[serde(default = "default_remote")]
    pub remote: String,
}

impl EngineArtifactTransport {
    fn label(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("{}:{}", self.remote, self.repo_url))
    }
}

fn default_artifact_branch() -> String {
    "main".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EngineRatchetLock {
    pub schema: String,
    pub engine_version: String,
    pub source_head_sha: String,
    pub artifacts: std::collections::BTreeMap<String, EngineRatchetArtifact>,
    #[serde(default)]
    pub observed_release: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EngineRatchetArtifact {
    pub name: String,
    pub sha256: String,
}

fn default_git_bearer() -> String {
    "owner".to_string()
}

fn default_remote() -> String {
    "origin".to_string()
}

/// Canonicalize only the estate Forgejo URL forms that are allowed to reach
/// the fixed-custody Git tool. Public HTTPS remains opaque and unchanged.
pub(crate) fn canonicalize_git_candidate(url: &str) -> Result<String, String> {
    let url = url.trim();
    if url.is_empty() {
        return Err("git-candidate-url-empty".into());
    }
    if let Some(rest) = url.strip_prefix("https://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        if authority.is_empty() || authority.contains('@') {
            return Err("git-candidate-https-credential-bearing".into());
        }
        return Ok(url.to_string());
    }
    let path = if let Some(rest) = url.strip_prefix("git@git.home.arpa:") {
        rest
    } else if let Some(rest) = url.strip_prefix("ssh://git@git.home.arpa/") {
        rest
    } else {
        return Err(format!(
            "git-candidate-unsupported-or-credential-bearing-url {url}"
        ));
    };
    if path.contains(['?', '#', '\r', '\n']) {
        return Err("git-candidate-path-query-or-fragment".into());
    }
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() < 2
        || parts
            .iter()
            .any(|part| part.is_empty() || *part == "." || *part == "..")
    {
        return Err(format!("git-candidate-estate-path-invalid {url}"));
    }
    Ok(format!("https://git.home.arpa/{path}"))
}

pub(crate) fn engine_config_path() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = TEST_ENGINE_CONFIG_PATH.with(|slot| slot.borrow().clone()) {
        return path;
    }
    env::var_os(ENGINE_CONFIG_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ENGINE_CONFIG))
}

fn validate_declared_source_path(field: &str, path: &Path) -> Result<(), String> {
    use std::path::Component;
    if !path.is_absolute() {
        return Err(format!(
            "engine-config-{field}-not-absolute path={}",
            path.display()
        ));
    }
    if path == Path::new("/") {
        return Err(format!("engine-config-{field}-unsafe-path-shape path=/"));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::CurDir | Component::ParentDir | Component::Prefix(_)
        )
    }) {
        return Err(format!(
            "engine-config-{field}-unsafe-path-shape path={}",
            path.display()
        ));
    }
    Ok(())
}

pub(crate) fn load_engine_plane_config(path: &Path) -> Result<Option<EnginePlaneConfig>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path)
        .map_err(|e| format!("engine-config-read-failed {}: {e}", path.display()))?;
    let config: EnginePlaneConfig = serde_json::from_str(&text)
        .map_err(|e| format!("engine-config-parse-failed {}: {e}", path.display()))?;
    if config.git_bearer != "owner" {
        return Err(format!(
            "engine-config-git-bearer-forbidden expected=owner actual={}",
            config.git_bearer
        ));
    }
    validate_credential_scopes(&config.credential_scopes)?;
    validate_declared_source_path("source-dir", &config.source_dir)?;
    if let Some(checkout) = config.local_source_checkout.as_deref() {
        validate_declared_source_path("local-source-checkout", checkout)?;
    }
    Ok(Some(config))
}

/// Compatibility accessor for the established source callers. This is a
/// projection only; renew-self does not resolve selectors or read credentials.
pub(crate) fn credential_scopes(
    config: &EnginePlaneConfig,
) -> BTreeMap<String, tools::git_artifact::CredentialScope> {
    config.credential_scopes.clone()
}

fn validate_credential_scopes(
    scopes: &BTreeMap<String, tools::git_artifact::CredentialScope>,
) -> Result<(), String> {
    const FIXED_TOKEN_PATH: &str = "/home/owner/.ssh/forgejo-token";
    for (selector, scope) in scopes {
        if scope.ssh_key_path.is_some() {
            return Err(format!(
                "engine-config-credential-scope-ssh-key-forbidden selector={selector}"
            ));
        }
        if let Some(host) = scope.https_host.as_deref() {
            if host != "git.home.arpa" {
                return Err(format!(
                    "engine-config-credential-scope-https-host-forbidden selector={selector} host={host}"
                ));
            }
        }
        if let Some(path) = scope.https_token_path.as_deref() {
            if path != Path::new(FIXED_TOKEN_PATH) {
                return Err(format!(
                    "engine-config-credential-scope-token-path-forbidden selector={selector} path={}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn install_bin_fingerprint(path: &Path) -> Option<String> {
    sha256_file(path).ok()
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file =
        fs::File::open(path).map_err(|e| format!("sha256-open-failed {}: {e}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("sha256-read-failed {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

pub(crate) fn self_update_reexec_guard_active() -> bool {
    env::var(SELF_UPDATE_REEXEC_ENV).as_deref() == Ok("1")
}

pub(crate) fn should_self_update_reexec(
    apply: bool,
    install_ok: bool,
    before: Option<String>,
    after: Option<String>,
) -> bool {
    apply && install_ok && !self_update_reexec_guard_active() && after.is_some() && before != after
}

fn stage_signal(stage: &str) -> String {
    format!("engine-{stage}-failed")
}

fn retired_compatibility_outcome(stage: &str) -> OperationOutcome {
    OperationOutcome {
        ok: true,
        changed: false,
        skipped: true,
        message: format!(
            "{stage} retired from renew-self; read-only compatibility projection; no mutation"
        ),
        command: None,
    }
}

fn emit_retired_package_receipt(
    preflight_dir: &Path,
    name: &str,
    action: &str,
    outcome: &OperationOutcome,
) -> Result<(), String> {
    write_json(
        &preflight_dir.join(format!("{name}.json")),
        &json!({
            "schema": "harmonia.package_tool.v1", "name": name, "tool": "package",
            "permutation": action, "declared_package_backend": "pacman",
            "ok": outcome.ok, "changed": outcome.changed, "skipped": outcome.skipped,
            "message": outcome.message, "command": outcome.command,
        }),
    )
}

fn emit_retired_keyring_receipt(
    preflight_dir: &Path,
    name: &str,
    apply: bool,
    operation_count: usize,
    outcome: &OperationOutcome,
) -> Result<(), String> {
    write_json(
        &preflight_dir.join(format!("{name}.json")),
        &json!({
            "schema": "harmonia.package_keyring_repair.v1", "name": name, "tool": "package",
            "permutation": "keyring-repair", "ok": outcome.ok, "changed": outcome.changed,
            "skipped": outcome.skipped, "apply": apply, "package": "archlinux-keyring",
            "pacman_present": false, "pacman_key_present": false, "operation_count": operation_count,
            "first_missing_signal": "none",
        }),
    )
}

fn write_source_possession_receipt(
    receipt_dir: &Path,
    result: &CmdResult,
    source_dir: &Path,
    local_source_checkout: Option<&Path>,
    candidate: &tools::git_artifact::SourceCandidate,
    apply: bool,
) -> Result<(), String> {
    // Keep this engine-preflight projection byte-compatible with the legacy
    // command receipt. The source owner retains richer acquisition facts in a
    // separately named additive receipt rather than widening the old schema.
    write_json(
        &receipt_dir.join("source-possession.json"),
        &json!({
            "schema": "harmonia.command_receipt.v1",
            "name": "source-possession",
            "ok": result.ok,
            "exit_code": result.code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "first_missing_signal": if result.ok { "none" } else { "engine-possession-failed" },
        }),
    )?;
    write_json(
        &receipt_dir.join("source-possession-details.json"),
        &json!({
            "schema": "harmonia.source_possession.v1",
            "name": "source-possession-details",
            "ok": result.ok,
            "exit_code": result.code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "first_missing_signal": if result.ok { "none" } else { "engine-possession-failed" },
            "apply": apply,
            "source_dir": source_dir,
            "local_source_checkout": local_source_checkout,
            "candidate_kind": format!("{:?}", candidate.kind),
            "candidate_locator": candidate.locator,
            "destination": source_dir,
            "read_only_custody": !apply,
        }),
    )
}

fn write_bearer_command_receipt(
    receipt_dir: &Path,
    name: &str,
    result: &CmdResult,
    bearer: &str,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{name}.json")),
        &json!({
            "schema": "harmonia.command_receipt.v1",
            "name": name,
            "ok": result.ok,
            "exit_code": result.code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "first_missing_signal": if result.ok { "none" } else { "command-failed" },
            "bearer": bearer,
        }),
    )
}

fn default_build_args(_config: &EnginePlaneConfig) -> Vec<String> {
    vec![
        "build".into(),
        "-p".into(),
        "harmonia".into(),
        "--release".into(),
    ]
}

fn staged_bin(config: &EnginePlaneConfig) -> PathBuf {
    config
        .staged_bin
        .clone()
        .unwrap_or_else(|| config.source_dir.join("target/release/harmonia"))
}

fn profile_index_from(module_root: &Path, config: &EnginePlaneConfig) -> PathBuf {
    config
        .profile_index
        .clone()
        .or_else(|| {
            module_root
                .parent()
                .map(|profile_root| profile_root.join("index.json"))
        })
        .unwrap_or_else(|| PathBuf::from("profiles/homeconsole/index.json"))
}

fn ratchet_lock_path(config_path: &Path, config: &EnginePlaneConfig) -> PathBuf {
    config.ratchet_lock.clone().unwrap_or_else(|| {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("/etc/harmonia"))
            .join(DEFAULT_ENGINE_RATCHET_LOCK_NAME)
    })
}

fn load_ratchet_lock(path: &Path) -> Result<Option<EngineRatchetLock>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path)
        .map_err(|e| format!("engine-ratchet-lock-read-failed {}: {e}", path.display()))?;
    let lock: EngineRatchetLock = serde_json::from_str(&text)
        .map_err(|e| format!("engine-ratchet-lock-parse-failed {}: {e}", path.display()))?;
    if lock.schema != ENGINE_RATCHET_LOCK_SCHEMA {
        return Err(format!(
            "engine-ratchet-lock-schema-unsupported {}",
            lock.schema
        ));
    }
    Ok(Some(lock))
}

fn current_arch_key() -> String {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64".to_string(),
        other => other.to_string(),
    }
}

fn compare_version(candidate: &str, running: &str) -> std::cmp::Ordering {
    let parse = |v: &str| -> Vec<u64> {
        v.split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let a = parse(candidate);
    let b = parse(running);
    for i in 0..a.len().max(b.len()) {
        let av = *a.get(i).unwrap_or(&0);
        let bv = *b.get(i).unwrap_or(&0);
        match av.cmp(&bv) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

fn copy_verified_artifact(
    staged: &Path,
    source: &Path,
    expected_sha: &str,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
    receipt_dir: &Path,
) -> Result<CmdResult, String> {
    if !apply {
        return Ok(CmdResult {
            ok: true,
            code: 0,
            stdout: format!(
                "planned artifact placement {} -> {}",
                source.display(),
                staged.display()
            ),
            stderr: String::new(),
        });
    }
    let actual = sha256_file(source)?;
    if !actual.eq_ignore_ascii_case(expected_sha) {
        return Ok(CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: format!(
                "engine-artifact-sha256-mismatch expected={expected_sha} actual={actual} path={}",
                source.display()
            ),
        });
    }
    let bytes = fs::read(source)
        .map_err(|e| format!("engine-artifact-read-failed {}: {e}", source.display()))?;
    let placed = crate::place_file::execute(crate::place_file::PlaceFileRequest {
        path: staged,
        declared_bytes: &bytes,
        mode: Some(0o755),
        ownership: crate::place_file::DeclaredOwnership {
            uid: None,
            gid: None,
        },
        backup: crate::place_file::BackupPolicy::To(
            &receipt_dir.join("backups/prior-artifact-stage"),
        ),
        invocation,
    })?;
    Ok(CmdResult {
        ok: placed.receipt.ok,
        code: if placed.receipt.ok { 0 } else { -1 },
        stdout: format!(
            "artifact staged {} sha256={actual} changed={}",
            staged.display(),
            placed.movement.changed()
        ),
        stderr: String::new(),
    })
}

fn promote_staged_binary(
    staged: &Path,
    install_bin: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
    receipt_dir: &Path,
) -> Result<CmdResult, String> {
    if !staged.exists() {
        return Ok(CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: format!("staged-binary-missing {}", staged.display()),
        });
    }
    if !apply {
        return Ok(CmdResult {
            ok: true,
            code: 0,
            stdout: format!(
                "planned atomic placement {} -> {}",
                staged.display(),
                install_bin.display()
            ),
            stderr: String::new(),
        });
    }
    let bytes = fs::read(staged)
        .map_err(|e| format!("staged-binary-read-failed {}: {e}", staged.display()))?;
    let placed = crate::place_file::execute(crate::place_file::PlaceFileRequest {
        path: install_bin,
        declared_bytes: &bytes,
        mode: Some(0o755),
        ownership: crate::place_file::DeclaredOwnership {
            uid: None,
            gid: None,
        },
        backup: crate::place_file::BackupPolicy::To(&receipt_dir.join("backups/prior-binary")),
        invocation,
    })?;
    Ok(CmdResult {
        ok: placed.receipt.ok,
        code: if placed.receipt.ok { 0 } else { -1 },
        stdout: format!(
            "atomic placement {} -> {} changed={} backed_up={}",
            staged.display(),
            install_bin.display(),
            placed.movement.changed(),
            placed.movement.backed_up.is_some()
        ),
        stderr: String::new(),
    })
}

fn emit_preflight_receipt(
    preflight_dir: &Path,
    ok: bool,
    apply: bool,
    changed: bool,
    first_missing_signal: &str,
    config_path: &Path,
    config: Option<&EnginePlaneConfig>,
    operation_count: usize,
    reexec_planned: bool,
    lane: &str,
    lock_path: Option<&Path>,
    lock_sha256: Option<&str>,
    staged_sha256: Option<&str>,
    installed_sha256: Option<&str>,
    transport_used: Option<&str>,
    engine_content_head: Option<&str>,
    artifact_transport_attempts: &[serde_json::Value],
) -> Result<(), String> {
    write_json(
        &preflight_dir.join("run.json"),
        &json!({
            "schema": PREFLIGHT_SCHEMA,
            "ok": ok,
            "apply": apply,
            "changed": changed,
            "stage": if ok { "complete" } else { first_missing_signal },
            "first_missing_signal": first_missing_signal,
            "operation_count": operation_count,
            "engine_config": config_path,
            "enabled": config.map(|c| c.enabled),
            "source_repo_url": config.map(|c| c.source_repo_url.as_str()),
            "local_source_checkout": config.and_then(|c| c.local_source_checkout.as_deref()),
            "source_possession_authority": if config.and_then(|c| c.local_source_checkout.as_ref()).is_some() { "declared-local-checkout-owner-plane-freshness" } else { "source-repository-fetch" },
            "branch": config.map(|c| c.branch.as_str()),
            "source_dir": config.map(|c| c.source_dir.as_path()),
            "install_bin": config.map(|c| c.install_bin.as_path()),
            "old_engine_preserved": true,
            "bootstrap_order": BOOTSTRAP_ORDER,
            "pre_sync_source_build": "absent",
            "successor_promoted_only_after": "explain+validate-ladder+plan-run",
            "artifact_ratchet": "version+sha-lock",
            "engine_content_head": engine_content_head.unwrap_or("unknown"),
            "lane": lane,
            "transport_used": transport_used,
            "artifact_transport_attempts": artifact_transport_attempts,
            "ratchet_lock_path": lock_path,
            "ratchet_lock_sha256": lock_sha256,
            "staged_sha256": staged_sha256,
            "installed_sha256": installed_sha256,
            "failure_mode": "honest-staleness",
            "retired_sidecar_gate": "absent",
            "profile_runtime_module": "absent",
            "reexec_once_guard_preserved": true,
            "reexec_planned": reexec_planned,
        }),
    )
}

pub(crate) fn run_engine_preflight(
    module_root: &Path,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<ModuleExecution, String> {
    let preflight_dir = receipt_dir.join("engine-preflight");
    fs::create_dir_all(&preflight_dir).map_err(|e| e.to_string())?;
    let config_path = engine_config_path();
    let Some(config) = load_engine_plane_config(&config_path)? else {
        let signal = "engine-self-possession-unconfigured";
        emit_preflight_receipt(
            &preflight_dir,
            false,
            apply,
            false,
            signal,
            &config_path,
            None,
            0,
            false,
            "unconfigured",
            None,
            None,
            None,
            None,
            None,
            None,
            &[],
        )?;
        return Ok(ModuleExecution {
            ok: false,
            changed: false,
            operation_count: 0,
            first_missing_signal: Some(signal.into()),
            placements: Vec::new(),
        });
    };
    if !config.enabled {
        let signal = "engine-self-possession-disabled";
        emit_preflight_receipt(
            &preflight_dir,
            false,
            apply,
            false,
            signal,
            &config_path,
            Some(&config),
            0,
            false,
            "disabled",
            None,
            None,
            install_bin_fingerprint(&config.install_bin).as_deref(),
            None,
            None,
            None,
            &[],
        )?;
        return Ok(ModuleExecution {
            ok: false,
            changed: false,
            operation_count: 0,
            first_missing_signal: Some(signal.into()),
            placements: Vec::new(),
        });
    }

    write_json(
        &preflight_dir.join("harmonia-engine-preflight-explain.json"),
        &json!({
            "schema": PREFLIGHT_SCHEMA,
            "ok": true,
            "stage": "engine-plane-config-loaded",
            "version": env!("CARGO_PKG_VERSION"),
            "config_path": config_path,
            "source_repo_url": config.source_repo_url,
            "branch": config.branch,
            "source_dir": config.source_dir,
            "install_bin": config.install_bin,
            "reexec_guard_active": self_update_reexec_guard_active(),
            "retired_sidecar_gate": "absent",
        }),
    )?;

    let mut operation_count = 0usize;
    let credential_retirement = retired_compatibility_outcome("root-git-credential-retirement");
    write_json(
        &preflight_dir.join("root-git-credential-retirement.json"),
        &json!({
            "schema": "harmonia.root_git_credential_retirement.v1", "ok": true, "apply": apply,
            "changed": false, "message": credential_retirement.message,
            "forbidden_paths": [LEGACY_ROOT_FORGEJO_INCLUDE, LEGACY_ROOT_FORGEJO_STORE, LEGACY_OWNER_FORGEJO_STORE],
            "root_gitconfig": LEGACY_ROOT_GITCONFIG,
        }),
    )?;
    operation_count += 1;
    let keyring = retired_compatibility_outcome("keyring-trust");
    emit_retired_keyring_receipt(
        &preflight_dir,
        "keyring-trust",
        apply,
        operation_count,
        &keyring,
    )?;
    operation_count += 1;
    let transport = retired_compatibility_outcome("transport-organs");
    emit_retired_package_receipt(&preflight_dir, "transport-organs", "install", &transport)?;
    operation_count += 1;
    let system_sync = retired_compatibility_outcome("system-sync");
    emit_retired_package_receipt(&preflight_dir, "system-sync", "upgrade", &system_sync)?;
    operation_count += 1;
    let mut changed = false;
    let mut first_missing_signal = "none".to_string();
    let lock_path = ratchet_lock_path(&config_path, &config);
    let lock_sha = sha256_file(&lock_path).ok();
    let ratchet_lock = load_ratchet_lock(&lock_path)?;
    let mut lane = "source-fallback".to_string();
    let mut transport_used: Option<String> = None;
    let mut engine_content_head: Option<String> = ratchet_lock
        .as_ref()
        .map(|lock| lock.source_head_sha.clone());
    let mut artifact_transport_attempts: Vec<serde_json::Value> = Vec::new();
    let mut staged_sha: Option<String> = None;
    let install_before = install_bin_fingerprint(&config.install_bin);

    let mut source_outcome = OperationOutcome {
        ok: false,
        changed: false,
        skipped: true,
        message: "source possession pending source decision".into(),
        command: None,
    };
    let mut artifact_outcome = OperationOutcome {
        ok: false,
        changed: false,
        skipped: true,
        message: "artifact lane not configured or not blessed".into(),
        command: None,
    };
    let mut build = CmdResult {
        ok: false,
        code: -1,
        stdout: String::new(),
        stderr: "staged build skipped before successful source possession".into(),
    };
    let mut proof_ok = false;
    let mut proof_failure: Option<String> = None;
    let mut promote = CmdResult {
        ok: false,
        code: -1,
        stdout: String::new(),
        stderr: "promotion skipped before successful proof battery".into(),
    };
    let mut reexec_planned = false;
    let staged = staged_bin(&config);

    if first_missing_signal == "none" {
        if let Some(lock) = ratchet_lock.as_ref() {
            let arch = current_arch_key();
            if let Some(artifact) = lock.artifacts.get(&arch) {
                let version_order =
                    compare_version(&lock.engine_version, env!("CARGO_PKG_VERSION"));
                if version_order == std::cmp::Ordering::Greater
                    || install_before.as_deref() != Some(artifact.sha256.as_str())
                {
                    let transport_chain = config.artifact_transport_chain();
                    for (index, transport) in transport_chain.iter().enumerate() {
                        let attempt_index = index + 1;
                        let transport_label = transport.label();
                        let repo_url = canonicalize_git_candidate(&transport.repo_url)?;
                        let request = tools::git_artifact::Request::new(
                            Some(repo_url.clone()),
                            transport.cache_dir.clone(),
                            transport.branch.clone(),
                            transport.remote.clone(),
                        );
                        let git_outcome = if apply {
                            crate::pull_repo::apply(
                                &request,
                                invocation.ok_or("invocation-key-missing")?,
                            )
                        } else {
                            tools::git_artifact::plan(&request)
                        };
                        let git_cmd = CmdResult {
                            ok: git_outcome.command.ok,
                            code: git_outcome.command.code,
                            stdout: git_outcome.command.stdout.clone(),
                            stderr: git_outcome.command.stderr.clone(),
                        };
                        write_command_receipt(
                            &preflight_dir,
                            &format!("artifact-transport-{attempt_index}"),
                            &git_cmd,
                        )?;
                        if attempt_index == 1 {
                            write_command_receipt(&preflight_dir, "artifact-transport", &git_cmd)?;
                        }
                        operation_count += 1;
                        if !git_outcome.ok {
                            artifact_transport_attempts.push(json!({
                                "index": attempt_index,
                                "transport": transport_label,
                                "repo_url": transport.repo_url,
                                "branch": transport.branch,
                                "cache_dir": transport.cache_dir,
                                "remote": transport.remote,
                                "outcome": "miss",
                                "reason": "fetch-failed",
                                "ok": false,
                                "code": git_cmd.code,
                            }));
                            continue;
                        }

                        let artifact_path = transport.cache_dir.join(&artifact.name);
                        if !artifact_path.exists() {
                            let missing_cmd = CmdResult {
                                ok: false,
                                code: -1,
                                stdout: String::new(),
                                stderr: format!(
                                    "engine-artifact-absent name={} transport={} path={}",
                                    artifact.name,
                                    transport_label,
                                    artifact_path.display()
                                ),
                            };
                            write_command_receipt(
                                &preflight_dir,
                                &format!("artifact-stage-{attempt_index}"),
                                &missing_cmd,
                            )?;
                            operation_count += 1;
                            artifact_transport_attempts.push(json!({
                                "index": attempt_index,
                                "transport": transport_label,
                                "repo_url": transport.repo_url,
                                "branch": transport.branch,
                                "cache_dir": transport.cache_dir,
                                "remote": transport.remote,
                                "outcome": "miss",
                                "reason": "artifact-absent",
                                "artifact_name": artifact.name,
                                "ok": false,
                            }));
                            continue;
                        }

                        let stage_cmd = copy_verified_artifact(
                            &staged,
                            &artifact_path,
                            &artifact.sha256,
                            apply,
                            invocation,
                            &preflight_dir,
                        )?;
                        write_command_receipt(
                            &preflight_dir,
                            &format!("artifact-stage-{attempt_index}"),
                            &stage_cmd,
                        )?;
                        if attempt_index == 1 {
                            write_command_receipt(&preflight_dir, "artifact-stage", &stage_cmd)?;
                        }
                        operation_count += 1;
                        artifact_outcome = OperationOutcome {
                            ok: stage_cmd.ok,
                            changed: stage_cmd.ok && apply,
                            skipped: false,
                            message: format!(
                                "artifact lane version={} arch={} source_head_sha={} transport={}",
                                lock.engine_version, arch, lock.source_head_sha, transport_label
                            ),
                            command: Some(stage_cmd.clone()),
                        };
                        if artifact_outcome.ok {
                            lane = "artifact".to_string();
                            transport_used = Some(transport_label.clone());
                            staged_sha = Some(artifact.sha256.clone());
                            artifact_transport_attempts.push(json!({
                                "index": attempt_index,
                                "transport": transport_label,
                                "repo_url": transport.repo_url,
                                "branch": transport.branch,
                                "cache_dir": transport.cache_dir,
                                "remote": transport.remote,
                                "outcome": "served",
                                "artifact_name": artifact.name,
                                "sha256": artifact.sha256,
                                "ok": true,
                            }));
                            break;
                        }

                        artifact_transport_attempts.push(json!({
                            "index": attempt_index,
                            "transport": transport_label,
                            "repo_url": transport.repo_url,
                            "branch": transport.branch,
                            "cache_dir": transport.cache_dir,
                            "remote": transport.remote,
                            "outcome": "hard-red",
                            "reason": "sha256-mismatch",
                            "artifact_name": artifact.name,
                            "ok": false,
                        }));
                        first_missing_signal = stage_signal("artifact-sha256");
                        break;
                    }
                    if lane != "artifact"
                        && first_missing_signal == "none"
                        && !transport_chain.is_empty()
                    {
                        artifact_outcome = OperationOutcome {
                            ok: false,
                            changed: false,
                            skipped: false,
                            message: "artifact transport chain missed; source fallback selected"
                                .into(),
                            command: None,
                        };
                    }
                } else {
                    lane = "artifact".to_string();
                    staged_sha = install_before.clone();
                    artifact_outcome = OperationOutcome {
                        ok: true,
                        changed: false,
                        skipped: false,
                        message: format!(
                            "engine-current no-op version={} sha256={}",
                            lock.engine_version, artifact.sha256
                        ),
                        command: None,
                    };
                    write_command_receipt(
                        &preflight_dir,
                        "artifact-current",
                        &CmdResult {
                            ok: true,
                            code: 0,
                            stdout: artifact_outcome.message.clone(),
                            stderr: String::new(),
                        },
                    )?;
                    operation_count += 1;
                }
            } else {
                write_command_receipt(
                    &preflight_dir,
                    "artifact-transport",
                    &CmdResult {
                        ok: false,
                        code: -1,
                        stdout: String::new(),
                        stderr: format!("engine-ratchet-arch-missing arch={arch}"),
                    },
                )?;
                operation_count += 1;
            }
        }
    }

    let artifact_current_noop = lane == "artifact"
        && artifact_outcome.ok
        && !artifact_outcome.changed
        && install_before.is_some()
        && staged_sha == install_before;

    let mut source_build_sha = String::new();
    if first_missing_signal == "none" && lane != "artifact" {
        let candidate = if let Some(checkout) = config.local_source_checkout.as_ref() {
            tools::git_artifact::SourceCandidate {
                kind: tools::git_artifact::SourceCandidateKind::LocalCheckout,
                locator: checkout.to_string_lossy().into_owned(),
                credential_selector: None,
            }
        } else {
            tools::git_artifact::SourceCandidate {
                kind: tools::git_artifact::SourceCandidateKind::Git,
                locator: canonicalize_git_candidate(&config.source_repo_url)?,
                credential_selector: None,
            }
        };
        let source_plan = tools::git_artifact::SourcePlan {
            candidates: vec![candidate.clone()],
            reference: config.branch.clone(),
            destination: config.source_dir.clone(),
            expected_commit: None,
            bearer: "owner".to_string(),
            credentials: std::collections::BTreeMap::new(),
        };
        let source = if apply {
            crate::pull_repo::acquire_source(&source_plan, invocation)
        } else if config.local_source_checkout.is_some() {
            // The local checkout is an owner-refreshed, read-only source. The
            // generic remote observer intentionally handles Git transports only;
            // use the same declared-candidate probe for the local lane instead
            // of manufacturing an unavailable result.
            let probe = tools::git_artifact::probe_declared_remote_head(&source_plan);
            tools::git_artifact::SourceOutcome {
                ok: probe.remote_sha.is_some(),
                changed: false,
                receipt: tools::git_artifact::SourceReceipt {
                    attempts: probe.failed_attempts,
                    served_index: probe.candidate_index,
                    resolved_commit: probe.remote_sha,
                    promotion: format!(
                        "{} candidate={} destination={}",
                        probe.state,
                        config.local_source_checkout.as_deref().unwrap().display(),
                        config.source_dir.display()
                    ),
                },
            }
        } else {
            crate::pull_repo::observe_source(&source_plan).unwrap_or(
                tools::git_artifact::SourceOutcome {
                    ok: false,
                    changed: false,
                    receipt: tools::git_artifact::SourceReceipt {
                        attempts: Vec::new(),
                        served_index: None,
                        resolved_commit: None,
                        promotion: "source-observation-unavailable".into(),
                    },
                },
            )
        };
        source_build_sha = match source.receipt.resolved_commit.clone() {
            Some(commit) => {
                engine_content_head = Some(commit.clone());
                commit
            }
            None => {
                first_missing_signal = stage_signal("engine-source-head");
                String::new()
            }
        };
        let source_cmd = CmdResult {
            ok: source.ok,
            code: if source.ok { 0 } else { -1 },
            stdout: source.receipt.promotion.clone(),
            stderr: if source.ok {
                String::new()
            } else {
                source.receipt.promotion.clone()
            },
        };
        write_source_possession_receipt(
            &preflight_dir,
            &source_cmd,
            &config.source_dir,
            config.local_source_checkout.as_deref(),
            &candidate,
            apply,
        )?;
        source_outcome = OperationOutcome {
            ok: source.ok,
            changed: source.changed,
            skipped: false,
            message: source.receipt.promotion.clone(),
            command: Some(source_cmd),
        };
        operation_count += 1;
        changed |= source_outcome.changed;
        if !source_outcome.ok {
            first_missing_signal = stage_signal("engine-possession");
        }
        lane = if config.local_source_checkout.is_some() {
            "local-checkout".to_string()
        } else {
            "source-fallback".to_string()
        };
    } else {
        write_command_receipt(
            &preflight_dir,
            "source-possession",
            &CmdResult {
                ok: true,
                code: 0,
                stdout: format!("source fallback skipped lane={lane}"),
                stderr: String::new(),
            },
        )?;
        operation_count += 1;
    }

    if first_missing_signal == "none"
        && matches!(lane.as_str(), "source-fallback" | "local-checkout")
    {
        let environment: Vec<(String, String)> = Vec::new();
        let build_result = crate::build_crate::run_build_with_mode(
            &config.source_dir,
            &source_build_sha,
            install_before.as_deref(),
            &config.install_bin,
            &staged,
            apply,
            &environment,
            tools::command::DEFAULT_TIMEOUT_SECS,
            &preflight_dir.join("harmonia-atoms.log"),
            "owner",
            invocation,
            crate::build_crate::IdentityMode::RegularExecutable,
        )?;
        build = build_result
            .as_ref()
            .map(|observation| CmdResult {
                ok: observation.ok,
                code: observation.code.unwrap_or(-1),
                stdout: observation.stdout.clone(),
                stderr: observation.stderr.clone(),
            })
            .unwrap_or(CmdResult {
                ok: true,
                code: 0,
                stdout: "build-crate converged-quiet".into(),
                stderr: String::new(),
            });
        write_bearer_command_receipt(&preflight_dir, "staged-build", &build, "owner")?;
        operation_count += 1;
        if !build.ok {
            first_missing_signal = stage_signal("staged-build");
        } else {
            staged_sha = sha256_file(&staged).ok();
        }
    } else {
        let skipped_message = if first_missing_signal == "none" {
            format!("staged build skipped lane={lane}")
        } else {
            "staged build skipped before successful source possession".to_string()
        };
        write_command_receipt(
            &preflight_dir,
            "staged-build",
            &CmdResult {
                ok: true,
                code: 0,
                stdout: skipped_message,
                stderr: String::new(),
            },
        )?;
        operation_count += 1;
    }

    if first_missing_signal == "none" && !artifact_current_noop && install_before != staged_sha {
        let proof =
            crate::check_health::proof_battery(&crate::check_health::ProofBatteryRequest {
                receipt_dir: &preflight_dir,
                staged: &staged,
                module_root,
                profile_index: &profile_index_from(module_root, &config),
                apply,
            })?;
        proof_ok = proof.0;
        proof_failure = proof.1;
        operation_count += proof.2;
        if !proof_ok {
            first_missing_signal = proof_failure
                .clone()
                .unwrap_or_else(|| stage_signal("proof-battery"));
        }
    }

    if first_missing_signal == "none" && !artifact_current_noop && install_before != staged_sha {
        promote = promote_staged_binary(
            &staged,
            &config.install_bin,
            apply,
            invocation,
            &preflight_dir,
        )?;
        write_command_receipt(&preflight_dir, "promote-successor", &promote)?;
        operation_count += 1;
        if !promote.ok {
            first_missing_signal = stage_signal("promote-successor");
        }
    } else {
        write_command_receipt(&preflight_dir, "promote-successor", &promote)?;
        operation_count += 1;
    }

    let install_after = install_bin_fingerprint(&config.install_bin);
    if first_missing_signal == "none" {
        changed = changed || install_before != install_after;
        reexec_planned = should_self_update_reexec(
            apply,
            promote.ok,
            install_before.clone(),
            install_after.clone(),
        );
    }
    let ok = first_missing_signal == "none";
    emit_preflight_receipt(
        &preflight_dir,
        ok,
        apply,
        changed,
        &first_missing_signal,
        &config_path,
        Some(&config),
        operation_count,
        reexec_planned,
        &lane,
        Some(&lock_path),
        lock_sha.as_deref(),
        staged_sha.as_deref(),
        install_after.as_deref(),
        transport_used.as_deref(),
        engine_content_head.as_deref(),
        &artifact_transport_attempts,
    )?;
    crate::hyalos::forward_receipt(
        "harmonia.renew_self.preflight",
        &format!(
            "ok={ok} apply={apply} changed={changed} first_missing_signal={first_missing_signal}"
        ),
        Some(
            json!({"ok": ok, "apply": apply, "changed": changed, "first_missing_signal": first_missing_signal, "attest_owner": "hyalos.forward_receipt"}),
        ),
        Some(ok),
    );

    let mut execution = ModuleExecution::from_operations(
        vec![
            ("root-git-credential-retirement", credential_retirement),
            ("keyring-trust", keyring),
            ("transport-organs", transport),
            ("system-sync", system_sync),
            ("artifact-lane", artifact_outcome),
            ("source-possession", source_outcome),
            (
                "staged-build",
                OperationOutcome {
                    ok: build.ok,
                    changed: false,
                    skipped: !apply,
                    message: "staged engine build".into(),
                    command: Some(build),
                },
            ),
            (
                "proof-battery",
                OperationOutcome {
                    ok: proof_ok || !ok && !matches!(first_missing_signal.as_str(), "none"),
                    changed: false,
                    skipped: first_missing_signal != "none" && proof_failure.is_none(),
                    message: "staged engine proof battery".into(),
                    command: None,
                },
            ),
            (
                "promote-successor",
                OperationOutcome {
                    ok: promote.ok,
                    changed: changed && ok,
                    skipped: !ok,
                    message: "promote staged successor after proof".into(),
                    command: Some(promote),
                },
            ),
        ],
        "engine-preflight",
    );
    execution.ok = ok;
    execution.changed = changed && ok;
    execution.operation_count = operation_count;
    execution.first_missing_signal = if ok { None } else { Some(first_missing_signal) };

    if ok && reexec_planned {
        write_json(
            &preflight_dir.join("harmonia-self-update-reexec.json"),
            &json!({"schema":"harmonia.runtime.self_update_reexec.v1","ok":true,"install_bin":config.install_bin,"reason":"engine pre-flight promoted a proved Harmonia successor; re-exec same argv before module convergence"}),
        )?;
        let args: Vec<String> = env::args().skip(1).collect();
        let key = invocation
            .ok_or_else(|| "harmonia-self-update-reexec-invocation-missing".to_string())?;
        let plan = crate::atoms::r#do::replace_process::Plan {
            successor: config.install_bin.clone(),
            argv: args,
            guard_name: SELF_UPDATE_REEXEC_ENV.into(),
            guard_value: "1".into(),
            receipt_path: preflight_dir.join("harmonia-self-update-reexec.json"),
        };
        return crate::atoms::r#do::replace_process::replace(&plan, key)
            .map(|_| unreachable!())
            .map_err(|err| format!("harmonia-self-update-reexec-failed: {err}"));
    }
    Ok(execution)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_only_estate_forgejo_forms() {
        assert_eq!(
            canonicalize_git_candidate("git@git.home.arpa:HOMESERVERSLTD/harmonia.git").unwrap(),
            "https://git.home.arpa/HOMESERVERSLTD/harmonia.git"
        );
        assert_eq!(
            canonicalize_git_candidate("ssh://git@git.home.arpa/HOMESERVERSLTD/harmonia").unwrap(),
            "https://git.home.arpa/HOMESERVERSLTD/harmonia"
        );
        assert_eq!(
            canonicalize_git_candidate("https://github.com/example/repo.git").unwrap(),
            "https://github.com/example/repo.git"
        );
        assert!(canonicalize_git_candidate("ssh://git@git.example:22/owner/repo").is_err());
        assert!(canonicalize_git_candidate("https://user:token@git.home.arpa/owner/repo").is_err());
    }
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn temp_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("harmonia-engine-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn with_engine_env<T>(root: &Path, f: impl FnOnce(&Path) -> T) -> T {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("engine env lock");
        let config_path = root.join("engine.json");
        set_test_engine_config_path(Some(config_path.clone()));
        let result = f(&config_path);
        set_test_engine_config_path(None);
        result
    }

    fn fake_tool(path: &Path, body: &str) {
        fs::write(path, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    fn fixture_profile(root: &Path) -> (PathBuf, PathBuf) {
        let profile_root = root.join("etc/harmonia/profiles/tv");
        let module_root = profile_root.join("modules");
        let module_dir = module_root.join("identity");
        fs::create_dir_all(&module_dir).unwrap();
        fs::write(
            profile_root.join("index.json"),
            r#"{"id":"tv","identity":"arch-tv","package_authority":{"os_family":"arch","package_manager":"pacman"},"modules":["identity"]}"#,
        )
        .unwrap();
        fs::write(
            module_dir.join("manifest.json"),
            r#"{"schema":"harmonia.module_ladder.v1","id":"identity","version":"1.0.0","ladder":[{"step_id":"noop","tool":"command","permutation":"capture","args":{"program":"/usr/bin/true"}}]}"#,
        )
        .unwrap();
        (profile_root.join("index.json"), module_root)
    }

    fn write_engine_config(
        path: &Path,
        source_repo_url: &str,
        build_program: &Path,
        staged_bin: &Path,
        install_bin: &Path,
        profile_index: &Path,
        source_dir: &Path,
    ) {
        fs::write(
            path,
            serde_json::json!({
                "source_repo_url": source_repo_url,
                "branch": "main",
                "source_dir": source_dir,
                "install_bin": install_bin,
                "enabled": true,
                "build_program": build_program,
                "build_args": [],
                "staged_bin": staged_bin,
                "profile_index": profile_index,
            })
            .to_string(),
        )
        .unwrap();
    }

    fn capture(program: &str, args: &[&str], cwd: &Path) {
        let result = tools::command::capture_with_cwd(program, args, cwd.to_str());
        assert!(result.ok, "{} {:?}: {}", program, args, result.stderr);
    }

    fn fixture_repo(root: &Path) -> String {
        let repo = root.join("repo");
        fs::create_dir_all(&repo).unwrap();
        capture("/usr/bin/git", &["init", "-b", "main"], &repo);
        capture(
            "/usr/bin/git",
            &["config", "user.email", "harmonia@example.invalid"],
            &repo,
        );
        capture(
            "/usr/bin/git",
            &["config", "user.name", "Harmonia Test"],
            &repo,
        );
        fs::write(repo.join("README.md"), "fixture\n").unwrap();
        capture("/usr/bin/git", &["add", "README.md"], &repo);
        capture("/usr/bin/git", &["commit", "-m", "seed"], &repo);
        repo.display().to_string()
    }

    fn with_fake_bootstrap<T>(root: &Path, pacman_body: &str, f: impl FnOnce() -> T) -> T {
        let pacman = root.join("fake-pacman");
        let pacman_key = root.join("fake-pacman-key");
        fake_tool(&pacman, pacman_body);
        fake_tool(
            &pacman_key,
            "#!/usr/bin/env sh\necho pacman-key ok\nexit 0\n",
        );
        crate::tools::package::set_test_pacman_path(Some(pacman.display().to_string()));
        std::env::set_var("HARMONIA_PACMAN_KEY_PATH", pacman_key.display().to_string());
        std::env::set_var(SELF_UPDATE_REEXEC_ENV, "1");
        std::env::set_var("HARMONIA_SUBSCRIPTION_PATH", root.join("subscription.json"));
        let result = f();
        std::env::remove_var("HARMONIA_SUBSCRIPTION_PATH");
        std::env::remove_var(SELF_UPDATE_REEXEC_ENV);
        std::env::remove_var("HARMONIA_PACMAN_KEY_PATH");
        crate::tools::package::set_test_pacman_path(None);
        result
    }

    fn artifact_binary_body(label: &str) -> String {
        format!(
            "#!/usr/bin/env sh\ncase \"$1\" in\n  explain) echo {label}; exit 0 ;;\n  validate-ladder) echo {label}; exit 0 ;;\n  plan-run) echo {label}; exit 0 ;;\n  *) echo unexpected >&2; exit 2 ;;\nesac\n"
        )
    }

    fn fixture_artifact_repo(root: &Path, artifact_name: &str, artifact_body: &str) -> String {
        let repo = root.join("artifact-repo");
        fs::create_dir_all(&repo).unwrap();
        capture("/usr/bin/git", &["init", "-b", "main"], &repo);
        capture(
            "/usr/bin/git",
            &["config", "user.email", "harmonia@example.invalid"],
            &repo,
        );
        capture(
            "/usr/bin/git",
            &["config", "user.name", "Harmonia Test"],
            &repo,
        );
        let artifact = repo.join(artifact_name);
        fake_tool(&artifact, artifact_body);
        capture("/usr/bin/git", &["add", artifact_name], &repo);
        capture("/usr/bin/git", &["commit", "-m", "artifact"], &repo);
        repo.display().to_string()
    }

    fn write_artifact_engine_config(
        path: &Path,
        source_repo_url: &str,
        artifact_repo_url: &str,
        build_program: &Path,
        staged_bin: &Path,
        install_bin: &Path,
        profile_index: &Path,
        source_dir: &Path,
        artifact_cache: &Path,
        lock_path: &Path,
    ) {
        fs::write(
            path,
            serde_json::json!({
                "source_repo_url": source_repo_url,
                "branch": "main",
                "source_dir": source_dir,
                "install_bin": install_bin,
                "enabled": true,
                "build_program": build_program,
                "build_args": [],
                "staged_bin": staged_bin,
                "profile_index": profile_index,
                "ratchet_lock": lock_path,
                "artifact_transport": {
                    "repo_url": artifact_repo_url,
                    "branch": "main",
                    "cache_dir": artifact_cache
                }
            })
            .to_string(),
        )
        .unwrap();
    }

    fn write_artifact_chain_engine_config(
        path: &Path,
        source_repo_url: &str,
        transports: Vec<serde_json::Value>,
        build_program: &Path,
        staged_bin: &Path,
        install_bin: &Path,
        profile_index: &Path,
        source_dir: &Path,
        lock_path: &Path,
    ) {
        fs::write(
            path,
            serde_json::json!({
                "source_repo_url": source_repo_url,
                "branch": "main",
                "source_dir": source_dir,
                "install_bin": install_bin,
                "enabled": true,
                "build_program": build_program,
                "build_args": [],
                "staged_bin": staged_bin,
                "profile_index": profile_index,
                "ratchet_lock": lock_path,
                "artifact_transports": transports,
            })
            .to_string(),
        )
        .unwrap();
    }

    fn write_ratchet_lock(path: &Path, version: &str, artifact_name: &str, sha: &str) {
        fs::write(
            path,
            serde_json::json!({
                "schema": ENGINE_RATCHET_LOCK_SCHEMA,
                "engine_version": version,
                "source_head_sha": "b0b75c546e2c0a19a9bc7eef0f71823be5d68cb5",
                "artifacts": {
                    "x86_64": {"name": artifact_name, "sha256": sha}
                }
            })
            .to_string(),
        )
        .unwrap();
    }

    #[test]
    fn self_update_reexec_requires_binary_fingerprint_change() {
        assert!(!should_self_update_reexec(
            true,
            true,
            Some("a".to_string()),
            Some("a".to_string())
        ));
        assert!(should_self_update_reexec(
            true,
            true,
            Some("a".to_string()),
            Some("b".to_string())
        ));
        assert!(!should_self_update_reexec(
            false,
            true,
            Some("a".to_string()),
            Some("b".to_string())
        ));
    }

    #[test]
    fn preflight_schema_names_engine_plane() {
        assert_eq!(PREFLIGHT_SCHEMA, "harmonia.engine.preflight.v1");
    }

    #[test]
    fn absent_engine_config_reports_unconfigured_not_green_noop() {
        let root = temp_root("unconfigured");
        with_engine_env(&root, |_config_path| {
            let (_, module_root) = fixture_profile(&root);
            let receipts = root.join("receipts");
            let execution = run_engine_preflight(
                &module_root,
                &receipts,
                true,
                Some(crate::invocation_face::mint(&["--apply".into()]).0.unwrap()),
            )
            .unwrap();
            assert!(!execution.ok);
            assert_eq!(
                execution.first_missing_signal.as_deref(),
                Some("engine-self-possession-unconfigured")
            );
            let receipt = fs::read_to_string(receipts.join("engine-preflight/run.json")).unwrap();
            assert!(receipt.contains("engine-self-possession-unconfigured"));
            assert!(receipt.contains("retired_sidecar_gate"));
        });
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn staged_promote_happy_path_uses_proved_successor() {
        let root = temp_root("happy");
        with_engine_env(&root, |config_path| {
            let (profile_index, module_root) = fixture_profile(&root);
            let repo = fixture_repo(&root);
            let staged = root.join("staged/harmonia");
            let install_bin = root.join("bin/harmonia");
            fs::create_dir_all(install_bin.parent().unwrap()).unwrap();
            fs::write(&install_bin, "old-engine\n").unwrap();
            let build = root.join("build-success.sh");
            fake_tool(
                &build,
                &format!(
                    "#!/usr/bin/env sh\nmkdir -p '{}'\ncat > '{}' <<'EOF'\n#!/usr/bin/env sh\ncase \"$1\" in\n  explain) echo ok=true; exit 0 ;;\n  validate-ladder) echo ok=true; exit 0 ;;\n  plan-run) echo ok=true; exit 0 ;;\n  *) echo unexpected >&2; exit 2 ;;\nesac\nEOF\nchmod 755 '{}'\nexit 0\n",
                    staged.parent().unwrap().display(),
                    staged.display(),
                    staged.display(),
                ),
            );
            write_engine_config(
                config_path,
                "https://git.home.arpa/HOMESERVERSLTD/harmonia.git",
                &build,
                &staged,
                &install_bin,
                &profile_index,
                Path::new(&repo),
            );
            let mut engine: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(config_path).unwrap()).unwrap();
            engine["local_source_checkout"] = serde_json::json!(&repo);
            fs::write(config_path, engine.to_string()).unwrap();
            let pacman = "#!/usr/bin/env sh\necho upgrading\nexit 0\n";
            let receipts = root.join("receipts");
            let execution = with_fake_bootstrap(&root, pacman, || {
                run_engine_preflight(
                    &module_root,
                    &receipts,
                    true,
                    Some(crate::invocation_face::mint(&["--apply".into()]).0.unwrap()),
                )
                .unwrap()
            });
            assert!(execution.ok, "{:?}", execution.first_missing_signal);
            assert_eq!(fs::read(&install_bin).unwrap(), fs::read(&staged).unwrap());
            let receipt = fs::read_to_string(receipts.join("engine-preflight/run.json")).unwrap();
            assert!(
                receipt.contains("\"lane\": \"local-checkout\""),
                "{receipt}"
            );
            assert!(
                receipt.contains("declared-local-checkout-owner-plane-freshness"),
                "{receipt}"
            );
            let source_receipt =
                fs::read_to_string(receipts.join("engine-preflight/source-possession.json"))
                    .unwrap();
            let source_details = fs::read_to_string(
                receipts.join("engine-preflight/source-possession-details.json"),
            )
            .unwrap();
            assert!(source_details.contains("owner_freshness_lane=external-owner-plane"));
            assert!(!source_receipt.contains("Username for"));
            assert!(receipt.contains("old_engine_preserved"));
            assert!(receipt.contains("successor_promoted_only_after"));
            assert!(receipt.contains("retired_sidecar_gate"));
            assert!(receipts
                .join("engine-preflight/proof-explain.json")
                .exists());
            assert!(receipts
                .join("engine-preflight/proof-validate-ladder.json")
                .exists());
            assert!(receipts
                .join("engine-preflight/proof-plan-run.json")
                .exists());
        });
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn artifact_lane_happy_path_uses_blessed_lock_and_proof_battery() {
        let root = temp_root("artifact-happy");
        with_engine_env(&root, |config_path| {
            let (profile_index, module_root) = fixture_profile(&root);
            let source_repo = fixture_repo(&root);
            let source_dir = root.join("source");
            let staged = root.join("staged/harmonia");
            let install_bin = root.join("bin/harmonia");
            fs::create_dir_all(install_bin.parent().unwrap()).unwrap();
            fs::write(&install_bin, "old-engine\n").unwrap();
            let artifact_name = "harmonia-x86_64";
            let artifact_body = artifact_binary_body("artifact-ok");
            let artifact_repo = fixture_artifact_repo(&root, artifact_name, &artifact_body);
            let artifact_sha =
                sha256_file(&root.join("artifact-repo").join(artifact_name)).unwrap();
            let lock = root.join("engine-ratchet-lock.json");
            write_ratchet_lock(&lock, "0.1.1", artifact_name, &artifact_sha);
            let build = root.join("build-should-not-run.sh");
            fake_tool(
                &build,
                "#!/usr/bin/env sh\necho source-build-ran >&2\nexit 9\n",
            );
            write_artifact_engine_config(
                config_path,
                &source_repo,
                &artifact_repo,
                &build,
                &staged,
                &install_bin,
                &profile_index,
                &source_dir,
                &root.join("artifact-cache"),
                &lock,
            );
            let receipts = root.join("receipts");
            let pacman = "#!/usr/bin/env sh\necho ok\nexit 0\n";
            let execution = with_fake_bootstrap(&root, pacman, || {
                run_engine_preflight(
                    &module_root,
                    &receipts,
                    true,
                    Some(crate::invocation_face::mint(&["--apply".into()]).0.unwrap()),
                )
                .unwrap()
            });
            assert!(execution.ok, "{:?}", execution.first_missing_signal);
            assert_eq!(sha256_file(&install_bin).unwrap(), artifact_sha);
            let receipt = fs::read_to_string(receipts.join("engine-preflight/run.json")).unwrap();
            assert!(receipt.contains("\"lane\": \"artifact\""), "{receipt}");
            assert!(receipt.contains("version+sha-lock"), "{receipt}");
            assert!(receipts
                .join("engine-preflight/artifact-stage.json")
                .exists());
            assert!(receipts
                .join("engine-preflight/proof-explain.json")
                .exists());
        });
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn artifact_sha_mismatch_refuses_before_promotion() {
        let root = temp_root("artifact-tamper");
        with_engine_env(&root, |config_path| {
            let (profile_index, module_root) = fixture_profile(&root);
            let source_repo = fixture_repo(&root);
            let source_dir = root.join("source");
            let staged = root.join("staged/harmonia");
            let install_bin = root.join("bin/harmonia");
            fs::create_dir_all(install_bin.parent().unwrap()).unwrap();
            fs::write(&install_bin, "old-engine\n").unwrap();
            let artifact_name = "harmonia-x86_64";
            let artifact_repo =
                fixture_artifact_repo(&root, artifact_name, &artifact_binary_body("tampered"));
            let lock = root.join("engine-ratchet-lock.json");
            write_ratchet_lock(
                &lock,
                "0.1.1",
                artifact_name,
                "0000000000000000000000000000000000000000000000000000000000000000",
            );
            let build = root.join("build-should-not-run.sh");
            fake_tool(&build, "#!/usr/bin/env sh\nexit 9\n");
            write_artifact_engine_config(
                config_path,
                &source_repo,
                &artifact_repo,
                &build,
                &staged,
                &install_bin,
                &profile_index,
                &source_dir,
                &root.join("artifact-cache"),
                &lock,
            );
            let receipts = root.join("receipts");
            let pacman = "#!/usr/bin/env sh\necho ok\nexit 0\n";
            let execution = with_fake_bootstrap(&root, pacman, || {
                run_engine_preflight(
                    &module_root,
                    &receipts,
                    true,
                    Some(crate::invocation_face::mint(&["--apply".into()]).0.unwrap()),
                )
                .unwrap()
            });
            assert!(!execution.ok);
            assert_eq!(
                execution.first_missing_signal.as_deref(),
                Some("engine-artifact-sha256-failed")
            );
            assert_eq!(fs::read_to_string(&install_bin).unwrap(), "old-engine\n");
            let promote_receipt =
                fs::read_to_string(receipts.join("engine-preflight/promote-successor.json"))
                    .unwrap();
            assert!(!promote_receipt.contains("atomic swap"));
        });
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn artifact_already_current_is_noop_without_reexec() {
        let root = temp_root("artifact-current");
        with_engine_env(&root, |config_path| {
            let (profile_index, module_root) = fixture_profile(&root);
            let source_repo = fixture_repo(&root);
            let artifact_name = "harmonia-x86_64";
            let installed = artifact_binary_body("current");
            let install_bin = root.join("bin/harmonia");
            fs::create_dir_all(install_bin.parent().unwrap()).unwrap();
            fake_tool(&install_bin, &installed);
            let sha = sha256_file(&install_bin).unwrap();
            let artifact_repo = fixture_artifact_repo(&root, artifact_name, &installed);
            let lock = root.join("engine-ratchet-lock.json");
            write_ratchet_lock(&lock, env!("CARGO_PKG_VERSION"), artifact_name, &sha);
            let build = root.join("build-should-not-run.sh");
            fake_tool(&build, "#!/usr/bin/env sh\nexit 9\n");
            write_artifact_engine_config(
                config_path,
                &source_repo,
                &artifact_repo,
                &build,
                &root.join("staged/harmonia"),
                &install_bin,
                &profile_index,
                &root.join("source"),
                &root.join("artifact-cache"),
                &lock,
            );
            let receipts = root.join("receipts");
            let pacman = "#!/usr/bin/env sh\necho ok\nexit 0\n";
            let execution = with_fake_bootstrap(&root, pacman, || {
                run_engine_preflight(
                    &module_root,
                    &receipts,
                    true,
                    Some(crate::invocation_face::mint(&["--apply".into()]).0.unwrap()),
                )
                .unwrap()
            });
            assert!(execution.ok);
            let receipt = fs::read_to_string(receipts.join("engine-preflight/run.json")).unwrap();
            assert!(receipt.contains("\"reexec_planned\": false"), "{receipt}");
            assert!(
                fs::read_to_string(receipts.join("engine-preflight/artifact-current.json"))
                    .unwrap()
                    .contains("engine-current no-op")
            );
        });
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn artifact_transport_failure_falls_back_to_source_lane() {
        let root = temp_root("artifact-fallback");
        with_engine_env(&root, |config_path| {
            let (profile_index, module_root) = fixture_profile(&root);
            let source_repo = fixture_repo(&root);
            let source_dir = root.join("source");
            let staged = root.join("staged/harmonia");
            let install_bin = root.join("bin/harmonia");
            fs::create_dir_all(install_bin.parent().unwrap()).unwrap();
            fs::write(&install_bin, "old-engine\n").unwrap();
            let lock = root.join("engine-ratchet-lock.json");
            write_ratchet_lock(
                &lock,
                "0.1.1",
                "missing-artifact",
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            );
            let build = root.join("build-success.sh");
            fake_tool(
                &build,
                &format!(
                    "#!/usr/bin/env sh\nmkdir -p '{}'\ncat > '{}' <<'EOF'\n{}EOF\nchmod 755 '{}'\n",
                    staged.parent().unwrap().display(),
                    staged.display(),
                    artifact_binary_body("source-fallback"),
                    staged.display()
                ),
            );
            write_artifact_engine_config(
                config_path,
                &source_repo,
                "/definitely/missing/artifacts",
                &build,
                &staged,
                &install_bin,
                &profile_index,
                &source_dir,
                &root.join("artifact-cache"),
                &lock,
            );
            let receipts = root.join("receipts");
            let pacman = "#!/usr/bin/env sh\necho ok\nexit 0\n";
            let execution = with_fake_bootstrap(&root, pacman, || {
                run_engine_preflight(
                    &module_root,
                    &receipts,
                    true,
                    Some(crate::invocation_face::mint(&["--apply".into()]).0.unwrap()),
                )
                .unwrap()
            });
            assert!(execution.ok, "{:?}", execution.first_missing_signal);
            let receipt = fs::read_to_string(receipts.join("engine-preflight/run.json")).unwrap();
            assert!(
                receipt.contains("\"lane\": \"source-fallback\""),
                "{receipt}"
            );
        });
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn artifact_chain_primary_miss_second_transport_serves() {
        let root = temp_root("artifact-chain-second");
        with_engine_env(&root, |config_path| {
            let (profile_index, module_root) = fixture_profile(&root);
            let source_repo = fixture_repo(&root);
            let empty_repo = fixture_repo(&root.join("empty-artifacts"));
            let source_dir = root.join("source");
            let staged = root.join("staged/harmonia");
            let install_bin = root.join("bin/harmonia");
            fs::create_dir_all(install_bin.parent().unwrap()).unwrap();
            fs::write(&install_bin, "old-engine\n").unwrap();
            let artifact_name = "harmonia-x86_64";
            let artifact_body = artifact_binary_body("second-served");
            let artifact_repo = fixture_artifact_repo(&root, artifact_name, &artifact_body);
            let artifact_sha =
                sha256_file(&root.join("artifact-repo").join(artifact_name)).unwrap();
            let lock = root.join("engine-ratchet-lock.json");
            write_ratchet_lock(&lock, "0.1.1", artifact_name, &artifact_sha);
            let build = root.join("build-should-not-run.sh");
            fake_tool(
                &build,
                "#!/usr/bin/env sh\necho source-build-ran >&2\nexit 9\n",
            );
            write_artifact_chain_engine_config(
                config_path,
                &source_repo,
                vec![
                    serde_json::json!({"name":"estate-forge","repo_url": empty_repo,"branch":"main","cache_dir": root.join("artifact-cache/estate")}),
                    serde_json::json!({"name":"github-canonical","repo_url": artifact_repo,"branch":"main","cache_dir": root.join("artifact-cache/github")}),
                ],
                &build,
                &staged,
                &install_bin,
                &profile_index,
                &source_dir,
                &lock,
            );
            let receipts = root.join("receipts");
            let pacman = "#!/usr/bin/env sh\necho ok\nexit 0\n";
            let execution = with_fake_bootstrap(&root, pacman, || {
                run_engine_preflight(
                    &module_root,
                    &receipts,
                    true,
                    Some(crate::invocation_face::mint(&["--apply".into()]).0.unwrap()),
                )
                .unwrap()
            });
            assert!(execution.ok, "{:?}", execution.first_missing_signal);
            assert_eq!(sha256_file(&install_bin).unwrap(), artifact_sha);
            let receipt: serde_json::Value = serde_json::from_str(
                &fs::read_to_string(receipts.join("engine-preflight/run.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(receipt["transport_used"], "github-canonical");
            assert_eq!(receipt["artifact_transport_attempts"][0]["outcome"], "miss");
            assert_eq!(
                receipt["artifact_transport_attempts"][0]["reason"],
                "artifact-absent"
            );
            assert_eq!(
                receipt["artifact_transport_attempts"][1]["outcome"],
                "served"
            );
        });
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn artifact_chain_sha_mismatch_stops_before_second_transport() {
        let root = temp_root("artifact-chain-tamper-stop");
        with_engine_env(&root, |config_path| {
            let (profile_index, module_root) = fixture_profile(&root);
            let source_repo = fixture_repo(&root);
            let source_dir = root.join("source");
            let staged = root.join("staged/harmonia");
            let install_bin = root.join("bin/harmonia");
            fs::create_dir_all(install_bin.parent().unwrap()).unwrap();
            fs::write(&install_bin, "old-engine\n").unwrap();
            let artifact_name = "harmonia-x86_64";
            let tampered_repo =
                fixture_artifact_repo(&root, artifact_name, &artifact_binary_body("tampered"));
            let good_repo_root = root.join("good-second");
            let good_repo = fixture_artifact_repo(
                &good_repo_root,
                artifact_name,
                &artifact_binary_body("good"),
            );
            let good_sha =
                sha256_file(&good_repo_root.join("artifact-repo").join(artifact_name)).unwrap();
            let lock = root.join("engine-ratchet-lock.json");
            write_ratchet_lock(&lock, "0.1.1", artifact_name, &good_sha);
            let build = root.join("build-should-not-run.sh");
            fake_tool(&build, "#!/usr/bin/env sh\nexit 9\n");
            write_artifact_chain_engine_config(
                config_path,
                &source_repo,
                vec![
                    serde_json::json!({"name":"estate-forge","repo_url": tampered_repo,"branch":"main","cache_dir": root.join("artifact-cache/estate")}),
                    serde_json::json!({"name":"github-canonical","repo_url": good_repo,"branch":"main","cache_dir": root.join("artifact-cache/github")}),
                ],
                &build,
                &staged,
                &install_bin,
                &profile_index,
                &source_dir,
                &lock,
            );
            let receipts = root.join("receipts");
            let pacman = "#!/usr/bin/env sh\necho ok\nexit 0\n";
            let execution = with_fake_bootstrap(&root, pacman, || {
                run_engine_preflight(
                    &module_root,
                    &receipts,
                    true,
                    Some(crate::invocation_face::mint(&["--apply".into()]).0.unwrap()),
                )
                .unwrap()
            });
            assert!(!execution.ok);
            assert_eq!(
                execution.first_missing_signal.as_deref(),
                Some("engine-artifact-sha256-failed")
            );
            assert!(!receipts
                .join("engine-preflight/artifact-transport-2.json")
                .exists());
            let receipt: serde_json::Value = serde_json::from_str(
                &fs::read_to_string(receipts.join("engine-preflight/run.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(receipt["transport_used"], serde_json::Value::Null);
            assert_eq!(
                receipt["artifact_transport_attempts"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                receipt["artifact_transport_attempts"][0]["outcome"],
                "hard-red"
            );
        });
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn artifact_chain_exhausted_misses_fall_back_to_source_lane() {
        let root = temp_root("artifact-chain-exhausted");
        with_engine_env(&root, |config_path| {
            let (profile_index, module_root) = fixture_profile(&root);
            let source_repo = fixture_repo(&root);
            let source_dir = root.join("source");
            let staged = root.join("staged/harmonia");
            let install_bin = root.join("bin/harmonia");
            fs::create_dir_all(install_bin.parent().unwrap()).unwrap();
            fs::write(&install_bin, "old-engine\n").unwrap();
            let empty_repo = fixture_repo(&root.join("empty-one"));
            let missing_repo = root.join("missing-two").display().to_string();
            let lock = root.join("engine-ratchet-lock.json");
            write_ratchet_lock(
                &lock,
                "0.1.1",
                "missing-artifact",
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            );
            let build = root.join("build-success.sh");
            fake_tool(
                &build,
                &format!(
                    "#!/usr/bin/env sh\nmkdir -p '{}'\ncat > '{}' <<'EOF'\n{}EOF\nchmod 755 '{}'\n",
                    staged.parent().unwrap().display(),
                    staged.display(),
                    artifact_binary_body("source-fallback"),
                    staged.display()
                ),
            );
            write_artifact_chain_engine_config(
                config_path,
                &source_repo,
                vec![
                    serde_json::json!({"name":"estate-forge","repo_url": empty_repo,"branch":"main","cache_dir": root.join("artifact-cache/estate")}),
                    serde_json::json!({"name":"github-canonical","repo_url": missing_repo,"branch":"main","cache_dir": root.join("artifact-cache/github")}),
                ],
                &build,
                &staged,
                &install_bin,
                &profile_index,
                &source_dir,
                &lock,
            );
            let receipts = root.join("receipts");
            let pacman = "#!/usr/bin/env sh\necho ok\nexit 0\n";
            let execution = with_fake_bootstrap(&root, pacman, || {
                run_engine_preflight(
                    &module_root,
                    &receipts,
                    true,
                    Some(crate::invocation_face::mint(&["--apply".into()]).0.unwrap()),
                )
                .unwrap()
            });
            assert!(execution.ok, "{:?}", execution.first_missing_signal);
            let receipt: serde_json::Value = serde_json::from_str(
                &fs::read_to_string(receipts.join("engine-preflight/run.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(receipt["lane"], "source-fallback");
            assert_eq!(
                receipt["artifact_transport_attempts"]
                    .as_array()
                    .unwrap()
                    .len(),
                2
            );
            assert_eq!(receipt["artifact_transport_attempts"][0]["outcome"], "miss");
            assert_eq!(receipt["artifact_transport_attempts"][1]["outcome"], "miss");
        });
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ratchet_lock_schema_denies_unknown_fields() {
        let root = temp_root("lock-schema");
        let lock = root.join("engine-ratchet-lock.json");
        fs::write(&lock, r#"{"schema":"harmonia.engine.ratchet_lock.v1","engine_version":"0.1.1","source_head_sha":"abc","artifacts":{"x86_64":{"name":"harmonia","sha256":"abc","extra":true}}}"#).unwrap();
        let err = load_ratchet_lock(&lock).unwrap_err();
        assert!(err.contains("engine-ratchet-lock-parse-failed"), "{err}");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sync_failure_blocks_source_build_and_preserves_old_binary() {
        let root = temp_root("sync-failure");
        with_engine_env(&root, |config_path| {
            let (profile_index, module_root) = fixture_profile(&root);
            let repo = fixture_repo(&root);
            let source_dir = root.join("source");
            let staged = root.join("staged/harmonia");
            let install_bin = root.join("bin/harmonia");
            fs::create_dir_all(install_bin.parent().unwrap()).unwrap();
            fs::write(&install_bin, "old-engine\n").unwrap();
            let build = root.join("build-should-not-run.sh");
            fake_tool(&build, "#!/usr/bin/env sh\necho build-ran >&2\nexit 9\n");
            write_engine_config(
                config_path,
                &repo,
                &build,
                &staged,
                &install_bin,
                &profile_index,
                &source_dir,
            );
            let pacman = "#!/usr/bin/env sh\nif [ \"$1\" = \"-Syu\" ]; then echo sync failed >&2; exit 42; fi\necho ok\nexit 0\n";
            let receipts = root.join("receipts");
            let execution = with_fake_bootstrap(&root, pacman, || {
                run_engine_preflight(
                    &module_root,
                    &receipts,
                    true,
                    Some(crate::invocation_face::mint(&["--apply".into()]).0.unwrap()),
                )
                .unwrap()
            });
            assert!(!execution.ok);
            assert_eq!(
                execution.first_missing_signal.as_deref(),
                Some("engine-system-sync-failed")
            );
            assert_eq!(fs::read_to_string(&install_bin).unwrap(), "old-engine\n");
            let build_receipt =
                fs::read_to_string(receipts.join("engine-preflight/staged-build.json")).unwrap();
            assert!(build_receipt.contains("skipped before successful source possession"));
        });
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn proof_failure_blocks_swap_and_preserves_old_binary() {
        let root = temp_root("proof-failure");
        with_engine_env(&root, |config_path| {
            let (profile_index, module_root) = fixture_profile(&root);
            let repo = fixture_repo(&root);
            let source_dir = root.join("source");
            let staged = root.join("staged/harmonia");
            let install_bin = root.join("bin/harmonia");
            fs::create_dir_all(install_bin.parent().unwrap()).unwrap();
            fs::write(&install_bin, "old-engine\n").unwrap();
            let build = root.join("build-proof-fail.sh");
            fake_tool(
                &build,
                &format!(
                    "#!/usr/bin/env sh\nmkdir -p '{}'\ncat > '{}' <<'EOF'\n#!/usr/bin/env sh\ncase \"$1\" in\n  explain) exit 0 ;;\n  validate-ladder) echo invalid >&2; exit 44 ;;\n  plan-run) exit 0 ;;\nesac\nEOF\nchmod 755 '{}'\nexit 0\n",
                    staged.parent().unwrap().display(),
                    staged.display(),
                    staged.display(),
                ),
            );
            write_engine_config(
                config_path,
                &repo,
                &build,
                &staged,
                &install_bin,
                &profile_index,
                &source_dir,
            );
            let pacman = "#!/usr/bin/env sh\necho ok\nexit 0\n";
            let receipts = root.join("receipts");
            let execution = with_fake_bootstrap(&root, pacman, || {
                run_engine_preflight(
                    &module_root,
                    &receipts,
                    true,
                    Some(crate::invocation_face::mint(&["--apply".into()]).0.unwrap()),
                )
                .unwrap()
            });
            assert!(!execution.ok);
            assert_eq!(
                execution.first_missing_signal.as_deref(),
                Some("engine-proof-validate-ladder-failed")
            );
            assert_eq!(fs::read_to_string(&install_bin).unwrap(), "old-engine\n");
            let promote =
                fs::read_to_string(receipts.join("engine-preflight/promote-successor.json"))
                    .unwrap();
            assert!(promote.contains("promotion skipped before successful proof battery"));
        });
        let _ = fs::remove_dir_all(root);
    }
}
