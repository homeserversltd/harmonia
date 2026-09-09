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
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
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
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::Read;

pub(crate) const PREFLIGHT_SCHEMA: &str = "harmonia.engine.preflight.v1";
const SELF_UPDATE_REEXEC_ENV: &str = "HARMONIA_SELF_UPDATE_REEXEC";
const SELF_UPDATE_REEXEC_GENERATION: u64 = 1;
const SELF_UPDATE_REEXEC_RUNNING_FINGERPRINT_MISSING: &str =
    "harmonia-self-update-reexec-running-fingerprint-missing";
const ENGINE_CONFIG_ENV: &str = "HARMONIA_ENGINE_CONFIG_PATH";
const DEFAULT_ENGINE_CONFIG: &str = "/etc/harmonia/engine.json";
const ENGINE_RATCHET_LOCK_SCHEMA: &str = "harmonia.engine.ratchet_lock.v1";
const DEFAULT_ENGINE_RATCHET_LOCK_NAME: &str = "engine-ratchet-lock.json";
const HARMONIA_BUILD_TARGET: &str = "x86_64-unknown-linux-gnu";
const HARMONIA_BUILD_SHA_ENV: &str = "HARMONIA_BUILD_SHA";
const HARMONIA_BUILD_ENV_SHA_ENV: &str = "HARMONIA_BUILD_ENV_SHA";
const HARMONIA_COMPONENT_ENV: &str = "HARMONIA_COMPONENT";

#[derive(Debug, Clone, PartialEq, Eq)]
struct BuildEnvironmentIdentity {
    environment: Vec<(String, String)>,
    env_sha: Option<String>,
}

fn is_valid_acquired_source_head(source_sha: &str) -> bool {
    source_sha.len() == 40 && source_sha.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn trim_trailing_crlf(value: &str) -> &str {
    value.trim_end_matches(|character: char| character == '\r' || character == '\n')
}

fn build_environment_sha(
    rustc_version: &str,
    cargo_version: &str,
    target_triple: &str,
    component: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(rustc_version.as_bytes());
    digest.update(b"\n");
    digest.update(cargo_version.as_bytes());
    digest.update(b"\n");
    digest.update(target_triple.as_bytes());
    digest.update(b"\n");
    digest.update(component.as_bytes());
    digest.update(b"\n");
    format!("{:x}", digest.finalize())
}

fn build_environment_for_source_head(
    source_sha: &str,
    rustc_version: &str,
    cargo_version: &str,
    target_triple: &str,
) -> BuildEnvironmentIdentity {
    if !is_valid_acquired_source_head(source_sha) {
        return BuildEnvironmentIdentity {
            environment: Vec::new(),
            env_sha: None,
        };
    }
    let env_sha = build_environment_sha(
        trim_trailing_crlf(rustc_version),
        trim_trailing_crlf(cargo_version),
        target_triple,
        crate::COMPILED_COMPONENT,
    );
    BuildEnvironmentIdentity {
        environment: vec![
            (HARMONIA_BUILD_SHA_ENV.into(), source_sha.into()),
            (HARMONIA_BUILD_ENV_SHA_ENV.into(), env_sha.clone()),
            (
                HARMONIA_COMPONENT_ENV.into(),
                crate::COMPILED_COMPONENT.into(),
            ),
        ],
        env_sha: Some(env_sha),
    }
}

fn capture_build_environment(source_sha: &str) -> Result<BuildEnvironmentIdentity, String> {
    if !is_valid_acquired_source_head(source_sha) {
        return Ok(build_environment_for_source_head(
            source_sha,
            "",
            "",
            HARMONIA_BUILD_TARGET,
        ));
    }
    let rustc = crate::atoms::command::capture("rustc", &["-Vv"]);
    if !rustc.ok {
        return Err(format!(
            "engine-toolchain-rustc-version-failed: {}",
            rustc.stderr
        ));
    }
    let cargo = crate::atoms::command::capture("cargo", &["-V"]);
    if !cargo.ok {
        return Err(format!(
            "engine-toolchain-cargo-version-failed: {}",
            cargo.stderr
        ));
    }
    Ok(build_environment_for_source_head(
        source_sha,
        trim_trailing_crlf(&rustc.stdout),
        trim_trailing_crlf(&cargo.stdout),
        HARMONIA_BUILD_TARGET,
    ))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnginePlaneConfig {
    pub install_bin: PathBuf,
    pub enabled: bool,
    /// Local staging/build mechanics only; source identity is certificate-owned.
    #[serde(default = "default_build_root")]
    pub build_root: PathBuf,
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
    #[serde(default = "default_artifact_kind")]
    pub kind: String,
    #[serde(default)]
    pub name: Option<String>,
    pub cache_dir: PathBuf,
    #[serde(default = "default_remote")]
    pub remote: String,
}

impl EngineArtifactTransport {
    fn label(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("{}:{}", self.remote, self.kind))
    }
}

fn default_artifact_kind() -> String {
    "git".to_string()
}

fn default_build_root() -> PathBuf {
    PathBuf::from("/var/lib/harmonia/engine-source")
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
    validate_declared_source_path("install-bin", &config.install_bin)?;
    if let Some(path) = config.staged_bin.as_deref() {
        validate_declared_source_path("staged-bin", path)?;
    }
    if let Some(path) = config.profile_index.as_deref() {
        validate_declared_source_path("profile-index", path)?;
    }
    if let Some(path) = config.ratchet_lock.as_deref() {
        validate_declared_source_path("ratchet-lock", path)?;
    }
    for transport in config.artifact_transport_chain() {
        validate_declared_source_path("artifact-cache-dir", &transport.cache_dir)?;
    }
    Ok(config)
}

const RETIRED_ENGINE_TOP_LEVEL_FIELDS: &[&str] = &[
    "source_repo_url",
    "branch",
    "source_dir",
    "local_source_checkout",
    "git_bearer",
    "source_components",
    "credential_scopes",
];

fn parse_validate_engine_plane_config(
    text: &str,
    path: &Path,
) -> Result<(EnginePlaneConfig, Vec<String>), String> {
    let mut raw: Value = serde_json::from_str(text)
        .map_err(|e| format!("engine-config-parse-failed {}: {e}", path.display()))?;
    let mut retired = Vec::new();
    if let Value::Object(object) = &mut raw {
        for field in RETIRED_ENGINE_TOP_LEVEL_FIELDS {
            if object.remove(*field).is_some() {
                record_retired_engine_config_field(&mut retired, field);
            }
        }
        if let Some(Value::Array(transports)) = object.get_mut("artifact_transports") {
            for transport in transports {
                let Value::Object(transport) = transport else {
                    continue;
                };
                if transport.remove("repo_url").is_some() {
                    record_retired_engine_config_field(
                        &mut retired,
                        "artifact_transports[].repo_url",
                    );
                }
                if transport.remove("branch").is_some() {
                    record_retired_engine_config_field(
                        &mut retired,
                        "artifact_transports[].branch",
                    );
                }
            }
        }
    }
    let config: EnginePlaneConfig = serde_json::from_value(raw)
        .map_err(|e| format!("engine-config-parse-failed {}: {e}", path.display()))?;
    let config = validate_engine_plane_config(config)?;
    Ok((config, retired))
}

fn record_retired_engine_config_field(retired: &mut Vec<String>, field: &str) {
    if !retired.iter().any(|existing| existing == field) {
        retired.push(field.to_string());
    }
}

pub(crate) fn load_engine_plane_config(path: &Path) -> Result<Option<EnginePlaneConfig>, String> {
    load_engine_plane_config_with_debt(path).map(|config| config.map(|(config, _retired)| config))
}

pub(crate) fn load_engine_plane_config_with_debt(
    path: &Path,
) -> Result<Option<(EnginePlaneConfig, Vec<String>)>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path)
        .map_err(|e| format!("engine-config-read-failed {}: {e}", path.display()))?;
    let config = parse_validate_engine_plane_config(&text, path)?;
    Ok(Some(config))
}

pub(crate) fn install_bin_fingerprint(path: &Path) -> Option<String> {
    sha256_file(path).ok()
}

fn running_binary_fingerprint() -> Option<String> {
    let running_path = fs::read_link("/proc/self/exe")
        .ok()
        .or_else(|| env::current_exe().ok())?;
    install_bin_fingerprint(&running_path)
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
    promotion_changed: bool,
    running_sha: Option<String>,
    installed_sha: Option<String>,
) -> bool {
    promotion_changed
        && !self_update_reexec_guard_active()
        && running_sha.is_some()
        && installed_sha.is_some()
        && running_sha != installed_sha
}

fn promotion_changed(
    apply: bool,
    promote_ok: bool,
    install_before: Option<&str>,
    installed_after: Option<&str>,
) -> bool {
    apply && promote_ok && installed_after.is_some() && install_before != installed_after
}

#[derive(Debug, Clone, Serialize)]
struct SelfUpdateReexec {
    from_sha: String,
    to_sha: String,
    generation: u64,
}

fn self_update_reexec_receipt(
    promotion_changed: bool,
    running_sha: Option<String>,
    installed_sha: Option<String>,
) -> Option<SelfUpdateReexec> {
    should_self_update_reexec(
        promotion_changed,
        running_sha.clone(),
        installed_sha.clone(),
    )
    .then(|| SelfUpdateReexec {
        from_sha: running_sha.unwrap_or_default(),
        to_sha: installed_sha.unwrap_or_default(),
        generation: SELF_UPDATE_REEXEC_GENERATION,
    })
}

fn mark_reexec_failure(preflight_dir: &Path, signal: &str) -> Result<(), String> {
    let path = preflight_dir.join("run.json");
    let mut receipt: Value = serde_json::from_str(
        &fs::read_to_string(&path)
            .map_err(|error| format!("engine-reexec-receipt-read-failed: {error}"))?,
    )
    .map_err(|error| format!("engine-reexec-receipt-parse-failed: {error}"))?;
    receipt["ok"] = json!(false);
    receipt["stage"] = json!(signal);
    receipt["first_missing_signal"] = json!(signal);
    write_json(&path, &receipt)
}

fn stage_signal(stage: &str) -> String {
    format!("engine-{stage}-failed")
}

fn write_source_possession_receipt(
    receipt_dir: &Path,
    result: &CmdResult,
    source_dir: &Path,
    candidate: &tools::git_artifact::SourceCandidate,
    apply: bool,
) -> Result<(), String> {
    // Source authority is the certificate; this receipt records only the
    // resulting owner-lane operation and local destination mechanics.
    write_json(
        &receipt_dir.join("source-possession.json"),
        &json!({
            "schema": "harmonia.command_receipt.v1",
            "name": "source-possession",
            "ok": result.ok,
            "exit_code": result.code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "skipped": result.stdout.contains("skipped=true"),
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
            "source_authority": "device-profile-certificate-sources",
            "candidate_kind": format!("{:?}", candidate.kind),
            "candidate_locator": candidate.locator,
            "destination": source_dir,
            "read_only_custody": !apply,
            "credential_selector": "validated-and-ignored",
            "git_bearer": "owner",
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
        .unwrap_or_else(|| config.build_root.join("target/release/harmonia"))
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
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
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
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
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
    config_path: &Path,
    config: &EnginePlaneConfig,
    retired_engine_config_fields: &[String],
    component: &str,
    engine_component_ignored: Option<&str>,
    source_head: Option<&str>,
    staged_sha: Option<&str>,
    installed_sha: Option<&str>,
    ok: bool,
    apply: bool,
    changed: bool,
    first_missing_signal: &str,
    operation_count: usize,
    staged_build_identity: Option<&BuildEnvironmentIdentity>,
    reexec: Option<&SelfUpdateReexec>,
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
            "retired_engine_config_fields": retired_engine_config_fields,
            "enabled": config.enabled,
            "source_authority": "device-profile-certificate-sources",
            "compiled_component": component,
            "engine_component_ignored": engine_component_ignored,
            "build_root": config.build_root,
            "install_bin": config.install_bin,
            "source_head": source_head.unwrap_or("unknown"),
            "staged_sha256": staged_sha,
            "installed_sha256": installed_sha,
            "staged_build_identity": staged_build_identity.and_then(|identity| identity.env_sha.as_deref().zip(source_head).map(|(env_sha, source_sha)| json!({"source_sha": source_sha, "env_sha": env_sha}))),
            "reexec": reexec,
            "git_bearer": "owner",
            "artifact_transport_count": config.artifact_transport_chain().len(),
            "failure_mode": "honest-source-resolution",
        }),
    )
}

fn failed_execution(signal: &str) -> ModuleExecution {
    ModuleExecution {
        ok: false,
        changed: false,
        operation_count: 0,
        first_missing_signal: Some(signal.to_string()),
        placements: Vec::new(),
    }
}

fn engine_source_gate_for_component(
    certificate_path: &Path,
    component: &str,
) -> Result<(String, crate::bands::pull_source::SourceResolution), String> {
    let resolution_receipt = crate::bands::pull_source::resolve_source(
        crate::bands::pull_source::SourceAuthority::Certificate(certificate_path),
        component,
        "engine-plane",
        "source-acquisition",
        None,
        None,
    );
    if let Some(blocker) = resolution_receipt.blocker {
        if blocker == format!("source-component-undeclared component={component}") {
            return Err(format!(
                "device-profile-engine-source-absent component={component}"
            ));
        }
        return Err(blocker);
    }
    let resolution = resolution_receipt
        .resolution
        .ok_or_else(|| "engine-source-resolution-blocked".to_string())?;
    Ok((component.to_string(), resolution))
}

fn engine_source_gate(
    certificate_path: &Path,
) -> Result<(String, crate::bands::pull_source::SourceResolution), String> {
    engine_source_gate_for_component(certificate_path, crate::COMPILED_COMPONENT)
}

fn ignored_engine_component(certificate_path: &Path, compiled_component: &str) -> Option<String> {
    crate::device_profile::legacy_engine_component_at(certificate_path)
        .ok()
        .flatten()
        .filter(|value| value != compiled_component)
}

fn ignored_engine_component_receipt_line(value: Option<&str>) -> String {
    value
        .map(|value| format!("engine_component_ignored: {value}"))
        .unwrap_or_default()
}

fn forward_preflight_receipt(
    ok: bool,
    apply: bool,
    changed: bool,
    first_missing_signal: &str,
    component: &str,
    engine_component_ignored: Option<&str>,
    retired_engine_config_fields: &[String],
) {
    let ignored_component_line =
        match ignored_engine_component_receipt_line(engine_component_ignored) {
            line if line.is_empty() => line,
            line => format!(" {line}"),
        };
    crate::hyalos::forward_receipt(
        "harmonia.renew_self.preflight",
        &format!(
            "ok={ok} apply={apply} changed={changed} first_missing_signal={first_missing_signal}{ignored_component_line}"
        ),
        Some(
            json!({"ok": ok, "apply": apply, "changed": changed, "first_missing_signal": first_missing_signal, "compiled_component": component, "engine_component_ignored": engine_component_ignored, "retired_engine_config_fields": retired_engine_config_fields, "attest_owner": "hyalos.forward_receipt"}),
        ),
        Some(ok),
    );
}

pub(crate) fn run_engine_preflight(
    module_root: &Path,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<ModuleExecution, String> {
    let preflight_dir = receipt_dir.join("engine-preflight");
    crate::atoms::attest::prepare_receipt_parent(&preflight_dir)?;
    let config_path = engine_config_path();
    let Some((config, retired_engine_config_fields)) =
        load_engine_plane_config_with_debt(&config_path)?
    else {
        let signal = "engine-self-possession-unconfigured";
        write_json(
            &preflight_dir.join("run.json"),
            &json!({
                "schema": PREFLIGHT_SCHEMA,
                "ok": false,
                "apply": apply,
                "changed": false,
                "first_missing_signal": signal,
                "engine_config": config_path,
                "retired_engine_config_fields": [],
                "source_authority": "device-profile-certificate-sources",
                "reexec": null,
            }),
        )?;
        return Ok(failed_execution(signal));
    };
    if !config.enabled {
        let signal = "engine-self-possession-disabled";
        emit_preflight_receipt(
            &preflight_dir,
            &config_path,
            &config,
            &retired_engine_config_fields,
            "unknown",
            None,
            None,
            None,
            install_bin_fingerprint(&config.install_bin).as_deref(),
            false,
            apply,
            false,
            signal,
            0,
            None,
            None,
        )?;
        return Ok(failed_execution(signal));
    }

    let certificate_path = crate::device_profile::device_profile_certificate_path();
    let engine_component_ignored =
        ignored_engine_component(&certificate_path, crate::COMPILED_COMPONENT);
    let source_gate = engine_source_gate(&certificate_path);
    let component_for_receipt = source_gate
        .as_ref()
        .ok()
        .map(|(component, _)| component.clone())
        .unwrap_or_else(|| crate::COMPILED_COMPONENT.to_string());
    let (component, resolution) = match source_gate {
        Ok(resolved) => resolved,
        Err(signal) => {
            emit_preflight_receipt(
                &preflight_dir,
                &config_path,
                &config,
                &retired_engine_config_fields,
                &component_for_receipt,
                engine_component_ignored.as_deref(),
                None,
                None,
                install_bin_fingerprint(&config.install_bin).as_deref(),
                false,
                apply,
                false,
                &signal,
                0,
                None,
                None,
            )?;
            return Ok(failed_execution(&signal));
        }
    };
    let expected_commit = (resolution.requested_ref.len() == 40
        && resolution
            .requested_ref
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()))
    .then(|| resolution.requested_ref.clone());
    let source_plan = crate::bands::pull_source::bridge_acquisition_plan(
        &resolution,
        config.build_root.clone(),
        expected_commit,
    );
    let source = crate::bands::pull_source::execute_source(&source_plan, apply, invocation);
    let source_command = CmdResult {
        ok: source.ok,
        code: if source.ok { 0 } else { -1 },
        stdout: source.receipt.promotion.clone(),
        stderr: if source.ok {
            String::new()
        } else {
            source.receipt.promotion.clone()
        },
    };
    if let Some(candidate) = source_plan.candidates.first() {
        write_source_possession_receipt(
            &preflight_dir,
            &source_command,
            &source_plan.destination,
            candidate,
            apply,
        )?;
    }
    let mut operation_count = 1usize;
    let source_head = source.receipt.resolved_commit.clone();
    let mut changed = source.changed;
    let mut first_missing_signal = if source.ok {
        "none".to_string()
    } else {
        "engine-source-acquisition-failed".to_string()
    };
    let running_before = running_binary_fingerprint();
    let install_before = install_bin_fingerprint(&config.install_bin);
    let staged = staged_bin(&config);
    let mut staged_sha = None;
    let mut staged_build_identity = None;
    let mut build = CmdResult {
        ok: false,
        code: -1,
        stdout: String::new(),
        stderr: "engine build skipped before source acquisition".to_string(),
    };
    if source.ok {
        let Some(source_head) = source_head.as_deref() else {
            first_missing_signal = "engine-source-head-absent".to_string();
            emit_preflight_receipt(
                &preflight_dir,
                &config_path,
                &config,
                &retired_engine_config_fields,
                &component,
                engine_component_ignored.as_deref(),
                None,
                None,
                install_before.as_deref(),
                false,
                apply,
                changed,
                &first_missing_signal,
                operation_count,
                None,
                None,
            )?;
            return Ok(failed_execution(&first_missing_signal));
        };
        let build_identity = capture_build_environment(source_head)?;
        let observation = crate::build_crate::run_build_with_mode(
            &config.build_root,
            source_head,
            install_before.as_deref(),
            &config.install_bin,
            &staged,
            apply,
            &build_identity.environment,
            crate::atoms::r#do::build_crate::DEFAULT_TIMEOUT_SECS,
            &preflight_dir.join("harmonia-atoms.log"),
            "owner",
            invocation,
            crate::build_crate::IdentityMode::RegularExecutable,
        )?;
        build = observation
            .map(|value| CmdResult {
                ok: value.ok,
                code: value.code.unwrap_or(-1),
                stdout: value.stdout,
                stderr: value.stderr,
            })
            .unwrap_or(CmdResult {
                ok: true,
                code: 0,
                stdout: "build-crate converged-quiet skipped=true".into(),
                stderr: String::new(),
            });
        operation_count += 1;
        write_bearer_command_receipt(&preflight_dir, "staged-build", &build, "owner")?;
        staged_build_identity = Some(build_identity);
        if !build.ok {
            first_missing_signal = "engine-staged-build-failed".to_string();
        } else if let Ok(value) = sha256_file(&staged) {
            staged_sha = Some(value);
        }
    } else {
        write_command_receipt(&preflight_dir, "staged-build", &build)?;
        operation_count += 1;
    }

    let mut promote = CmdResult {
        ok: true,
        code: 0,
        stdout: "promotion skipped before successful proof".into(),
        stderr: String::new(),
    };
    if first_missing_signal == "none" && apply && staged_sha.is_some() {
        let proof =
            crate::check_health::proof_battery(&crate::check_health::ProofBatteryRequest {
                receipt_dir: &preflight_dir,
                staged: &staged,
                module_root,
                profile_index: &profile_index_from(module_root, &config),
                apply,
            })?;
        operation_count += proof.2;
        if !proof.0 {
            first_missing_signal = proof
                .1
                .unwrap_or_else(|| "engine-proof-battery-failed".to_string());
        } else {
            promote = promote_staged_binary(
                &staged,
                &config.install_bin,
                true,
                invocation,
                &preflight_dir,
            )?;
            operation_count += 1;
            if !promote.ok {
                first_missing_signal = "engine-promotion-failed".to_string();
            } else {
                changed = true;
            }
        }
    }
    write_command_receipt(&preflight_dir, "promote-successor", &promote)?;
    let installed_after = install_bin_fingerprint(&config.install_bin);
    let install_changed = promotion_changed(
        apply,
        promote.ok,
        install_before.as_deref(),
        installed_after.as_deref(),
    );
    let reexec = if first_missing_signal == "none" {
        if install_changed && running_before.is_none() {
            first_missing_signal = SELF_UPDATE_REEXEC_RUNNING_FINGERPRINT_MISSING.to_string();
            None
        } else {
            self_update_reexec_receipt(install_changed, running_before, installed_after.clone())
        }
    } else {
        None
    };
    let ok = first_missing_signal == "none";
    emit_preflight_receipt(
        &preflight_dir,
        &config_path,
        &config,
        &retired_engine_config_fields,
        &component,
        engine_component_ignored.as_deref(),
        source_head.as_deref(),
        staged_sha.as_deref(),
        installed_after.as_deref(),
        ok,
        apply,
        changed,
        &first_missing_signal,
        operation_count,
        staged_build_identity.as_ref(),
        reexec.as_ref(),
    )?;
    if reexec.is_some() {
        let Some(invocation) = invocation else {
            let signal = "harmonia-self-update-reexec-invocation-missing";
            mark_reexec_failure(&preflight_dir, signal)?;
            forward_preflight_receipt(
                false,
                apply,
                changed,
                signal,
                &component,
                engine_component_ignored.as_deref(),
                &retired_engine_config_fields,
            );
            return Err(signal.to_string());
        };
        let plan = crate::atoms::r#do::replace_process::Plan {
            successor: config.install_bin.clone(),
            argv: env::args().skip(1).collect(),
            guard_name: SELF_UPDATE_REEXEC_ENV.to_string(),
            guard_value: "1".to_string(),
            receipt_path: preflight_dir.join("replace-process.json"),
        };
        if let Err(error) = crate::atoms::r#do::replace_process::replace(&plan, invocation) {
            let signal = format!("harmonia-self-update-reexec-failed: {error}");
            if let Err(receipt_error) = mark_reexec_failure(&preflight_dir, &signal) {
                return Err(format!("{signal}; receipt update failed: {receipt_error}"));
            }
            forward_preflight_receipt(
                false,
                apply,
                changed,
                &signal,
                &component,
                engine_component_ignored.as_deref(),
                &retired_engine_config_fields,
            );
            return Err(signal);
        }
        unreachable!("replace-process::replace only returns after exec failure");
    }
    forward_preflight_receipt(
        ok,
        apply,
        changed,
        &first_missing_signal,
        &component,
        engine_component_ignored.as_deref(),
        &retired_engine_config_fields,
    );
    Ok(ModuleExecution {
        ok,
        changed: changed && ok,
        operation_count,
        first_missing_signal: (!ok).then_some(first_missing_signal),
        placements: Vec::new(),
    })
}

#[cfg(test)]
mod release_transport_tests {
    use super::{
        build_environment_for_source_head, build_environment_sha, capture_build_environment,
        emit_preflight_receipt, engine_source_gate, engine_source_gate_for_component,
        ignored_engine_component, ignored_engine_component_receipt_line, install_bin_fingerprint,
        parse_validate_engine_plane_config, promote_staged_binary, promotion_changed,
        self_update_reexec_guard_active, self_update_reexec_receipt, should_self_update_reexec,
        EngineArtifactTransport, SELF_UPDATE_REEXEC_ENV,
    };
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};
    use tempfile::{tempdir, NamedTempFile};

    static REEXEC_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    struct ReexecEnvGuard(Option<std::ffi::OsString>);

    impl ReexecEnvGuard {
        fn activate() -> Self {
            let previous = std::env::var_os(SELF_UPDATE_REEXEC_ENV);
            std::env::set_var(SELF_UPDATE_REEXEC_ENV, "1");
            Self(previous)
        }
    }

    impl Drop for ReexecEnvGuard {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => std::env::set_var(SELF_UPDATE_REEXEC_ENV, value),
                None => std::env::remove_var(SELF_UPDATE_REEXEC_ENV),
            }
        }
    }

    #[test]
    fn retired_engine_config_fields_are_stripped_and_reported_deterministically() {
        let (config, retired) = parse_validate_engine_plane_config(
            r#"{
                "install_bin": "/usr/local/bin/harmonia",
                "enabled": true,
                "source_repo_url": {"nonsense": [true, 7]},
                "branch": [null, {"not": "a-branch"}],
                "source_dir": 42,
                "local_source_checkout": false,
                "git_bearer": {"token": ["not", "a", "bearer"]},
                "source_components": {"not": "an-array"},
                "credential_scopes": "not-an-array",
                "artifact_transports": [
                    {
                        "kind": "git",
                        "name": "cache-one",
                        "cache_dir": "/var/cache/harmonia-one",
                        "remote": "origin",
                        "repo_url": {"not": "a-url"},
                        "branch": [1, 2, 3]
                    },
                    {
                        "kind": "git",
                        "name": "cache-two",
                        "cache_dir": "/var/cache/harmonia-two",
                        "remote": "origin",
                        "repo_url": ["not", "a", "url"],
                        "branch": {"not": "a-branch"}
                    }
                ]
            }"#,
            Path::new("/etc/harmonia/engine.json"),
        )
        .unwrap();

        assert_eq!(
            retired,
            vec![
                "source_repo_url",
                "branch",
                "source_dir",
                "local_source_checkout",
                "git_bearer",
                "source_components",
                "credential_scopes",
                "artifact_transports[].repo_url",
                "artifact_transports[].branch",
            ]
        );
        assert_eq!(config.install_bin, PathBuf::from("/usr/local/bin/harmonia"));
        assert!(config.enabled);
        assert_eq!(config.artifact_transports.len(), 2);
        let parsed_config = serde_json::to_string(&config).unwrap();
        for retired_value in [
            "nonsense",
            "a-branch",
            "not-an-array",
            "bearer",
            "a-url",
            "not",
        ] {
            assert!(
                !parsed_config.contains(retired_value),
                "retired value leaked: {retired_value}"
            );
        }
    }

    #[test]
    fn genuinely_unknown_engine_config_field_still_fails_strict_parse() {
        let error = parse_validate_engine_plane_config(
            r#"{"install_bin":"/usr/local/bin/harmonia","enabled":true,"genuinely_unknown":"sentinel"}"#,
            Path::new("/etc/harmonia/engine.json"),
        )
        .unwrap_err();
        assert!(error.contains("engine-config-parse-failed"));
        assert!(error.contains("genuinely_unknown"));
    }

    #[test]
    fn current_engine_config_shape_reports_no_retired_fields() {
        let (config, retired) = parse_validate_engine_plane_config(
            r#"{"install_bin":"/usr/local/bin/harmonia","enabled":true}"#,
            Path::new("/etc/harmonia/engine.json"),
        )
        .unwrap();
        assert!(retired.is_empty());
        assert_eq!(config.install_bin, PathBuf::from("/usr/local/bin/harmonia"));
    }

    #[test]
    fn engine_config_uses_local_mechanics_and_certificate_source_authority() {
        let config: super::EnginePlaneConfig = serde_json::from_str(
            r#"{"install_bin":"/usr/local/bin/harmonia","enabled":true,"build_root":"/var/lib/harmonia/source","artifact_transport":{"kind":"git","name":"cache","cache_dir":"/var/cache/harmonia","remote":"origin"}}"#,
        ).unwrap();
        assert_eq!(config.build_root, PathBuf::from("/var/lib/harmonia/source"));
        assert_eq!(config.artifact_transport.unwrap().remote, "origin");
    }

    #[test]
    fn artifact_transport_has_no_source_or_credential_authority() {
        let transport: EngineArtifactTransport = serde_json::from_str(
            r#"{"kind":"git","name":"cache","cache_dir":"/var/cache/harmonia","remote":"origin"}"#,
        )
        .unwrap();
        assert_eq!(transport.kind, "git");
        assert_eq!(transport.cache_dir, PathBuf::from("/var/cache/harmonia"));
    }

    #[test]
    fn valid_build_environment_has_build_identity_and_known_env_hash() {
        let source_sha = "0123456789abcdef0123456789abcdef01234567";
        let identity = build_environment_for_source_head(
            source_sha,
            "rustc 1.85.0 (fake)",
            "cargo 1.85.0 (fake)",
            "x86_64-unknown-linux-gnu",
        );

        assert_eq!(identity.environment.len(), 3);
        assert_eq!(
            identity.environment,
            vec![
                ("HARMONIA_BUILD_SHA".to_string(), source_sha.to_string()),
                (
                    "HARMONIA_BUILD_ENV_SHA".to_string(),
                    "0e5eb85d1e4bda0a9e1ab61a3e0c21fd31bb198df218061c31168969ea51d4f1".to_string(),
                ),
                (
                    "HARMONIA_COMPONENT".to_string(),
                    crate::COMPILED_COMPONENT.to_string(),
                ),
            ]
        );
        assert_eq!(
            identity.env_sha.as_deref(),
            Some("0e5eb85d1e4bda0a9e1ab61a3e0c21fd31bb198df218061c31168969ea51d4f1")
        );
    }

    #[test]
    fn invalid_build_environment_is_empty_and_has_neither_variable() {
        let identity = capture_build_environment("not-a-valid-source-head").unwrap();

        assert!(identity.environment.is_empty());
        assert_eq!(identity.env_sha, None);
    }

    #[test]
    fn fixed_input_build_environment_hash_is_deterministic_and_trailing_crlf_equivalent() {
        let source_sha = "0123456789abcdef0123456789abcdef01234567";
        let first = build_environment_for_source_head(
            source_sha,
            "rustc 1.85.0 (fake)",
            "cargo 1.85.0 (fake)",
            "x86_64-unknown-linux-gnu",
        );
        let second = build_environment_for_source_head(
            source_sha,
            "rustc 1.85.0 (fake)\r\n\n",
            "cargo 1.85.0 (fake)\n\r",
            "x86_64-unknown-linux-gnu",
        );

        assert_eq!(
            build_environment_sha(
                "rustc 1.85.0 (fake)",
                "cargo 1.85.0 (fake)",
                "x86_64-unknown-linux-gnu",
                crate::COMPILED_COMPONENT,
            ),
            build_environment_sha(
                "rustc 1.85.0 (fake)",
                "cargo 1.85.0 (fake)",
                "x86_64-unknown-linux-gnu",
                crate::COMPILED_COMPONENT,
            )
        );
        assert_eq!(first, second);
    }

    #[test]
    fn build_environment_hash_changes_when_compiled_component_changes() {
        let first = build_environment_sha(
            "rustc 1.85.0 (fake)",
            "cargo 1.85.0 (fake)",
            "x86_64-unknown-linux-gnu",
            "harmonia",
        );
        let second = build_environment_sha(
            "rustc 1.85.0 (fake)",
            "cargo 1.85.0 (fake)",
            "x86_64-unknown-linux-gnu",
            "harmonia-monad",
        );

        assert_ne!(first, second);
    }

    fn certificate_fixture(
        legacy_component: Option<&str>,
        source_components: &[&str],
    ) -> NamedTempFile {
        let mut kernel = json!({"profile": "homeserver"});
        if let Some(component) = legacy_component {
            kernel["engine_component"] = json!(component);
        }
        let sources = source_components
            .iter()
            .map(|component| {
                (
                    (*component).to_string(),
                    json!({
                        "ref": "main",
                        "candidates": [{
                            "kind": "git",
                            "url": format!("https://git.home.arpa/HOMESERVERSLTD/{component}.git")
                        }]
                    }),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        let certificate = json!({
            "schema": "homeserver.device-profile.v1",
            "kernel": kernel,
            "source_policy": "developer",
            "sources": sources,
        });
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), serde_json::to_vec(&certificate).unwrap()).unwrap();
        file
    }

    #[test]
    fn public_source_resolves_without_legacy_engine_component() {
        let certificate = certificate_fixture(None, &["harmonia"]);
        let (component, resolution) =
            engine_source_gate_for_component(certificate.path(), "harmonia").unwrap();

        assert_eq!(component, "harmonia");
        assert_eq!(resolution.component, "harmonia");
        assert_eq!(resolution.requested_ref, "main");
    }

    #[test]
    fn public_and_private_identity_sources_resolve_independently() {
        let private_component = ["harmonia", "monad"].join("-");
        let components = vec!["harmonia", private_component.as_str()];
        let certificate = certificate_fixture(None, &components);

        for component in components {
            let (resolved_component, resolution) =
                engine_source_gate_for_component(certificate.path(), component).unwrap();
            assert_eq!(resolved_component, component);
            assert_eq!(resolution.component, component);
            assert_eq!(resolution.requested_ref, "main");
        }
    }

    #[test]
    fn missing_compiled_identity_source_refuses_exactly_and_preserves_installed_engine() {
        let certificate = certificate_fixture(Some("legacy"), &["not-the-engine"]);
        let root = tempfile::tempdir().unwrap();
        let installed_engine = root.path().join("installed/harmonia");
        std::fs::create_dir_all(installed_engine.parent().unwrap()).unwrap();
        std::fs::write(&installed_engine, b"old-engine-sentinel").unwrap();
        let source_destination = root.path().join("source");
        let build_destination = root.path().join("build");

        let result = engine_source_gate(certificate.path());

        assert!(matches!(
            result,
            Err(signal) if signal == format!(
                "device-profile-engine-source-absent component={}",
                crate::COMPILED_COMPONENT
            )
        ));
        assert_eq!(
            std::fs::read(&installed_engine).unwrap(),
            b"old-engine-sentinel"
        );
        assert!(!source_destination.exists());
        assert!(!build_destination.exists());
    }

    #[test]
    fn disagreeing_legacy_engine_component_is_ignored_with_receipt_line() {
        let certificate =
            certificate_fixture(Some("legacy-component"), &[crate::COMPILED_COMPONENT]);
        let ignored = ignored_engine_component(certificate.path(), crate::COMPILED_COMPONENT)
            .expect("disagreeing legacy field is reported");

        assert_eq!(ignored, "legacy-component");
        assert_eq!(
            ignored_engine_component_receipt_line(Some(&ignored)),
            "engine_component_ignored: legacy-component"
        );
        assert!(engine_source_gate(certificate.path()).is_ok());
    }

    #[test]
    fn promoted_stub_successor_from_absent_install_receipts_reexec_and_guard_blocks_second_exec() {
        let _env_lock = REEXEC_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap();
        let root = tempdir().unwrap();
        let running = root.path().join("running-harmonia");
        let successor = root.path().join("stub-successor");
        let installed = root.path().join("installed/harmonia");
        let preflight_dir = root.path().join("engine-preflight");
        std::fs::create_dir_all(&preflight_dir).unwrap();
        std::fs::write(&running, b"running-engine").unwrap();
        std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
        std::fs::write(&successor, b"promoted-stub-successor").unwrap();
        let from_sha = install_bin_fingerprint(&running).unwrap();
        let install_before = install_bin_fingerprint(&installed);
        assert!(install_before.is_none());
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let promotion = promote_staged_binary(
            &successor,
            &installed,
            true,
            Some(&invocation),
            &preflight_dir,
        )
        .unwrap();
        assert!(promotion.ok);
        let installed_after = install_bin_fingerprint(&installed);
        let to_sha = installed_after.clone().unwrap();
        assert!(promotion_changed(
            true,
            promotion.ok,
            install_before.as_deref(),
            installed_after.as_deref(),
        ));

        let config = super::EnginePlaneConfig {
            install_bin: installed.clone(),
            enabled: true,
            build_root: root.path().join("build-root"),
            remote: "origin".into(),
            build_program: None,
            build_args: None,
            staged_bin: None,
            profile_index: None,
            ratchet_lock: None,
            artifact_transport: None,
            artifact_transports: Vec::new(),
        };
        let reexec = self_update_reexec_receipt(true, Some(from_sha.clone()), Some(to_sha.clone()))
            .expect("changed promoted successor requires reexec");
        emit_preflight_receipt(
            &preflight_dir,
            &root.path().join("engine.json"),
            &config,
            &[],
            "harmonia",
            None,
            None,
            None,
            Some(&to_sha),
            true,
            true,
            true,
            "none",
            1,
            None,
            Some(&reexec),
        )
        .unwrap();
        let receipt: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(preflight_dir.join("run.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["reexec"]["from_sha"], from_sha);
        assert_eq!(receipt["reexec"]["to_sha"], to_sha);
        assert_eq!(receipt["reexec"]["generation"], 1);

        let _env_guard = ReexecEnvGuard::activate();
        assert!(self_update_reexec_guard_active());
        assert!(!should_self_update_reexec(
            true,
            Some("old".into()),
            Some("new".into()),
        ));
        assert!(
            self_update_reexec_receipt(true, Some("old".into()), Some("new".into()),).is_none()
        );
    }

    #[test]
    fn no_promotion_receipts_null_reexec() {
        let root = tempdir().unwrap();
        let config = super::EnginePlaneConfig {
            install_bin: root.path().join("install-bin"),
            enabled: true,
            build_root: root.path().join("build-root"),
            remote: "origin".into(),
            build_program: None,
            build_args: None,
            staged_bin: None,
            profile_index: None,
            ratchet_lock: None,
            artifact_transport: None,
            artifact_transports: Vec::new(),
        };
        let preflight_dir = root.path().join("engine-preflight");
        std::fs::create_dir_all(&preflight_dir).unwrap();
        assert!(!promotion_changed(false, false, None, None));
        assert!(!promotion_changed(true, true, Some("same"), Some("same")));
        emit_preflight_receipt(
            &preflight_dir,
            &root.path().join("engine.json"),
            &config,
            &[],
            "harmonia",
            None,
            None,
            None,
            None,
            true,
            true,
            false,
            "none",
            0,
            None,
            None,
        )
        .unwrap();
        let receipt: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(preflight_dir.join("run.json")).unwrap())
                .unwrap();
        assert!(receipt["reexec"].is_null());
    }
}
