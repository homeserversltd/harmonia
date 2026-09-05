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
const ENGINE_CONFIG_ENV: &str = "HARMONIA_ENGINE_CONFIG_PATH";
const DEFAULT_ENGINE_CONFIG: &str = "/etc/harmonia/engine.json";
const ENGINE_RATCHET_LOCK_SCHEMA: &str = "harmonia.engine.ratchet_lock.v1";
const DEFAULT_ENGINE_RATCHET_LOCK_NAME: &str = "engine-ratchet-lock.json";

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
    source_head: Option<&str>,
    staged_sha: Option<&str>,
    installed_sha: Option<&str>,
    ok: bool,
    apply: bool,
    changed: bool,
    first_missing_signal: &str,
    operation_count: usize,
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
            "engine_component": component,
            "build_root": config.build_root,
            "install_bin": config.install_bin,
            "source_head": source_head.unwrap_or("unknown"),
            "staged_sha256": staged_sha,
            "installed_sha256": installed_sha,
            "credential_selector": serde_json::Value::Null,
            "credentials": [],
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

fn engine_source_gate(
    certificate_path: &Path,
) -> Result<(String, crate::bands::pull_source::SourceResolution), String> {
    let component = crate::device_profile::certificate_engine_component_at(certificate_path)?;
    let resolution_receipt = crate::bands::pull_source::resolve_source(
        certificate_path,
        &component,
        "engine-plane",
        "source-acquisition",
    );
    let resolution = match resolution_receipt.resolution {
        Some(resolution) => resolution,
        None => {
            return Err(resolution_receipt
                .blocker
                .unwrap_or_else(|| "engine-source-resolution-blocked".to_string()))
        }
    };
    Ok((component, resolution))
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
            install_bin_fingerprint(&config.install_bin).as_deref(),
            false,
            apply,
            false,
            signal,
            0,
        )?;
        return Ok(failed_execution(signal));
    }

    let certificate_path = crate::device_profile::device_profile_certificate_path();
    let source_gate = engine_source_gate(&certificate_path);
    let component_for_receipt = source_gate
        .as_ref()
        .ok()
        .map(|(component, _)| component.clone())
        .or_else(|| crate::device_profile::certificate_engine_component_at(&certificate_path).ok())
        .unwrap_or_else(|| "unknown".to_string());
    let (component, resolution) = match source_gate {
        Ok(resolved) => resolved,
        Err(signal) => {
            emit_preflight_receipt(
                &preflight_dir,
                &config_path,
                &config,
                &retired_engine_config_fields,
                &component_for_receipt,
                None,
                None,
                install_bin_fingerprint(&config.install_bin).as_deref(),
                false,
                apply,
                false,
                &signal,
                0,
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
    let install_before = install_bin_fingerprint(&config.install_bin);
    let staged = staged_bin(&config);
    let mut staged_sha = None;
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
                None,
                None,
                install_before.as_deref(),
                false,
                apply,
                changed,
                &first_missing_signal,
                operation_count,
            )?;
            return Ok(failed_execution(&first_missing_signal));
        };
        let observation = crate::build_crate::run_build_with_mode(
            &config.build_root,
            source_head,
            install_before.as_deref(),
            &config.install_bin,
            &staged,
            apply,
            &[],
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
    let ok = first_missing_signal == "none";
    emit_preflight_receipt(
        &preflight_dir,
        &config_path,
        &config,
        &retired_engine_config_fields,
        &component,
        source_head.as_deref(),
        staged_sha.as_deref(),
        installed_after.as_deref(),
        ok,
        apply,
        changed,
        &first_missing_signal,
        operation_count,
    )?;
    crate::hyalos::forward_receipt(
        "harmonia.renew_self.preflight",
        &format!(
            "ok={ok} apply={apply} changed={changed} first_missing_signal={first_missing_signal}"
        ),
        Some(
            json!({"ok": ok, "apply": apply, "changed": changed, "first_missing_signal": first_missing_signal, "retired_engine_config_fields": retired_engine_config_fields, "attest_owner": "hyalos.forward_receipt"}),
        ),
        Some(ok),
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
    use super::{engine_source_gate, parse_validate_engine_plane_config, EngineArtifactTransport};
    use std::path::{Path, PathBuf};

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
    fn absent_engine_component_blocks_before_mutation_and_preserves_old_engine() {
        let root = tempfile::tempdir().unwrap();
        let certificate_path = root.path().join("profile.json");
        std::fs::write(
            &certificate_path,
            r#"{
                "schema": "homeserver.device-profile.v1",
                "kernel": { "profile": "homeserver" },
                "source_policy": "developer",
                "sources": {
                    "harmonia": {
                        "ref": "main",
                        "candidates": [{
                            "kind": "git",
                            "url": "https://git.home.arpa/HOMESERVERSLTD/harmonia.git"
                        }]
                    }
                }
            }"#,
        )
        .unwrap();
        let installed_engine = root.path().join("installed/harmonia");
        std::fs::create_dir_all(installed_engine.parent().unwrap()).unwrap();
        std::fs::write(&installed_engine, b"old-engine-sentinel").unwrap();
        let source_destination = root.path().join("source");
        let build_destination = root.path().join("build");

        let result = engine_source_gate(&certificate_path);

        assert!(matches!(
            result,
            Err(signal) if signal == "device-profile-kernel-engine-component-missing"
        ));
        assert_eq!(
            std::fs::read(&installed_engine).unwrap(),
            b"old-engine-sentinel"
        );
        assert!(!source_destination.exists());
        assert!(!build_destination.exists());
    }
}
