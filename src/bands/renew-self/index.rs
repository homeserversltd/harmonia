use super::Band;
use std::path::Path;

use crate::module_dispatch::ModuleExecution;

#[path = "schedule.rs"]
pub(crate) mod schedule;

pub(crate) fn enter(enter: &mut impl FnMut(Band) -> Result<(), String>) -> Result<(), String> {
    enter(Band::RenewSelf)
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

/// Only this proof result is safe to defer until StageProfile has molted the
/// installed module root. All other preflight failures retain normal semantics.
pub(crate) fn is_stale_staged_validation_failure(execution: &ModuleExecution) -> bool {
    matches!(
        execution.first_missing_signal.as_deref(),
        Some("engine-proof-validate-ladder-failed") | Some("engine-proof-plan-run-failed")
    )
}

use crate::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};

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

#[derive(Debug, Clone, Deserialize, Serialize)]
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
pub(crate) struct EngineRatchetLock {
    pub schema: String,
    pub engine_version: String,
    pub source_head_sha: String,
    pub artifacts: std::collections::BTreeMap<String, EngineRatchetArtifact>,
    #[serde(default)]
    pub observed_release: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

fn validate_engine_plane_config(config: EnginePlaneConfig) -> Result<EnginePlaneConfig, String> {
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
    Ok(config)
}

fn parse_validate_engine_plane_config(
    text: &str,
    path: &Path,
) -> Result<EnginePlaneConfig, String> {
    let config: EnginePlaneConfig = serde_json::from_str(text)
        .map_err(|e| format!("engine-config-parse-failed {}: {e}", path.display()))?;
    validate_engine_plane_config(config)
}

fn migrate_retired_engine_config(path: &Path, receipt_dir: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let text = fs::read_to_string(path)
        .map_err(|e| format!("engine-config-read-failed {}: {e}", path.display()))?;
    let mut value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("engine-config-parse-failed {}: {e}", path.display()))?;
    let Some(object) = value.as_object_mut() else {
        return Err(format!(
            "engine-config-parse-failed {}: top-level-not-object",
            path.display()
        ));
    };
    let retired = [
        "git_https_credential_host",
        "git_https_credential_token_path",
    ];
    let migrated: Vec<&str> = retired
        .iter()
        .copied()
        .filter(|key| object.remove(*key).is_some())
        .collect();
    if migrated.is_empty() {
        return Ok(());
    }
    let cleaned = serde_json::to_string_pretty(&value)
        .map_err(|e| format!("engine-config-parse-failed {}: {e}", path.display()))?;
    let _ = parse_validate_engine_plane_config(&cleaned, path)?;
    let metadata = fs::metadata(path)
        .map_err(|e| format!("engine-config-stat-failed {}: {e}", path.display()))?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let temp = parent.join(format!(
        ".{}.migration-{}",
        path.file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("engine.json"),
        std::process::id()
    ));
    let cleanup = |error: String| {
        let _ = fs::remove_file(&temp);
        Err(error)
    };
    let mut file = match OpenOptions::new().write(true).create_new(true).open(&temp) {
        Ok(file) => file,
        Err(e) => {
            return Err(format!(
                "engine-config-migration-write-failed {}: {e}",
                temp.display()
            ))
        }
    };
    if let Err(e) = file.write_all(cleaned.as_bytes()) {
        return cleanup(format!(
            "engine-config-migration-write-failed {}: {e}",
            temp.display()
        ));
    }
    if let Err(e) = file.set_permissions(metadata.permissions()) {
        return cleanup(format!(
            "engine-config-migration-permissions-failed {}: {e}",
            temp.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        let name = match CString::new(temp.as_os_str().as_bytes()) {
            Ok(name) => name,
            Err(_) => {
                return cleanup(format!(
                    "engine-config-migration-owner-failed {}",
                    temp.display()
                ))
            }
        };
        if unsafe { libc::chown(name.as_ptr(), metadata.uid(), metadata.gid()) } != 0 {
            return cleanup(format!(
                "engine-config-migration-owner-failed {}: {}",
                temp.display(),
                std::io::Error::last_os_error()
            ));
        }
    }
    if let Err(e) = file.sync_all() {
        return cleanup(format!(
            "engine-config-migration-sync-failed {}: {e}",
            temp.display()
        ));
    }
    drop(file);
    if let Err(e) = fs::rename(&temp, path) {
        return cleanup(format!(
            "engine-config-migration-promote-failed {}: {e}",
            path.display()
        ));
    }
    if let Ok(dir) = fs::File::open(parent) {
        dir.sync_all().map_err(|e| {
            format!(
                "engine-config-migration-parent-sync-failed {}: {e}",
                parent.display()
            )
        })?;
    }
    write_json(
        &receipt_dir.join("engine-config-migration.json"),
        &json!({
            "schema": "harmonia.engine.config_migration.v1", "ok": true,
            "path": path, "migrated_keys": migrated, "unknown_keys_remain_fatal": true,
        }),
    )?;
    Ok(())
}

pub(crate) fn load_engine_plane_config(path: &Path) -> Result<Option<EnginePlaneConfig>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path)
        .map_err(|e| format!("engine-config-read-failed {}: {e}", path.display()))?;
    let config = parse_validate_engine_plane_config(&text, path)?;
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

pub(crate) fn renew_self_bench(
    root: &Path,
    key: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<serde_json::Value, String> {
    let key = key.ok_or("renew-self-bench-invocation-key-missing")?;
    let receipts = root.join("receipts");
    let module_root = root.join("profiles/tv/modules");
    let identity = module_root.join("identity");
    let profile_index = root.join("profiles/tv/index.json");
    let staged = root.join("staged/harmonia");
    let installed = root.join("bin/harmonia");
    fs::create_dir_all(&identity).map_err(|e| e.to_string())?;
    fs::create_dir_all(
        installed
            .parent()
            .ok_or("renew-self-install-parent-missing")?,
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        &profile_index,
        r#"{"id":"tv","identity":"arch-tv","modules":["identity"]}"#,
    )
    .map_err(|e| e.to_string())?;
    fs::write(identity.join("manifest.json"), r#"{"schema":"harmonia.module_ladder.v1","id":"identity","version":"1.0.0","ladder":[{"step_id":"noop","tool":"command","permutation":"capture","args":{"program":"/usr/bin/true"}}]}"#)
        .map_err(|e| e.to_string())?;
    fs::write(&installed, b"old-engine\n").map_err(|e| e.to_string())?;
    let write_successor = |body: &str| -> Result<(), String> {
        fs::create_dir_all(staged.parent().ok_or("renew-self-stage-parent-missing")?)
            .map_err(|e| e.to_string())?;
        fs::write(&staged, body).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        std::fs::set_permissions(&staged, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .map_err(|e| e.to_string())?;
        Ok(())
    };
    write_successor("#!/usr/bin/env sh\ncase \"$1\" in\n  explain|validate-ladder|plan-run) exit 0 ;;\n  *) exit 2 ;;\nesac\n")?;
    let (proof_ok, _, _) =
        crate::check_health::proof_battery(&crate::check_health::ProofBatteryRequest {
            receipt_dir: &receipts,
            staged: &staged,
            module_root: &module_root,
            profile_index: &profile_index,
            apply: true,
        })?;
    let proof_receipt: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(receipts.join("proof-plan-run.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let promotion = if proof_ok {
        promote_staged_binary(&staged, &installed, true, Some(key), &receipts)?
    } else {
        CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: "promotion skipped before successful proof battery".into(),
        }
    };
    write_command_receipt(&receipts, "promote-successor", &promotion)?;
    let promotion_receipt: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(receipts.join("promote-successor.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let promoted = proof_receipt["ok"].as_bool() == Some(true)
        && promotion_receipt["ok"].as_bool() == Some(true)
        && fs::read(&installed).map_err(|e| e.to_string())?
            == fs::read(&staged).map_err(|e| e.to_string())?;
    let promoted_bytes = fs::read(&installed).map_err(|e| e.to_string())?;
    write_successor("#!/usr/bin/env sh\ncase \"$1\" in\n  explain) exit 0 ;;\n  validate-ladder) exit 44 ;;\n  plan-run) exit 0 ;;\n  *) exit 2 ;;\nesac\n")?;
    let (failed_proof, failed_signal, _) =
        crate::check_health::proof_battery(&crate::check_health::ProofBatteryRequest {
            receipt_dir: &receipts,
            staged: &staged,
            module_root: &module_root,
            profile_index: &profile_index,
            apply: true,
        })?;
    let failed_receipt: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(receipts.join("proof-validate-ladder.json"))
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let refused = !failed_proof
        && failed_signal.as_deref() == Some("engine-proof-validate-ladder-failed")
        && failed_receipt["ok"].as_bool() == Some(false);
    let preserved = fs::read(&installed).map_err(|e| e.to_string())? == promoted_bytes;
    Ok(
        json!({"success_swap_after_proof": promoted, "proof_failure_preserves_old_binary": refused && preserved, "reexec": false, "ok": promoted && refused && preserved}),
    )
}
pub(crate) fn run_engine_preflight(
    module_root: &Path,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<ModuleExecution, String> {
    let preflight_dir = receipt_dir.join("engine-preflight");
    crate::atoms::attest::prepare_receipt_parent(&preflight_dir)?;
    let config_path = engine_config_path();
    migrate_retired_engine_config(&config_path, &preflight_dir)?;
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
        ok: true,
        code: 0,
        stdout: "promotion skipped before successful proof battery".into(),
        stderr: String::new(),
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

    let promotion_due =
        first_missing_signal == "none" && !artifact_current_noop && install_before != staged_sha;
    let mut promotion_attempted = false;
    if promotion_due {
        promotion_attempted = true;
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

    let promotion_skipped = !promotion_attempted;
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
                    ok: promotion_skipped || promote.ok,
                    changed: changed && ok && !promotion_skipped,
                    skipped: promotion_skipped,
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
