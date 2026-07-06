use crate::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::cell::RefCell;
use std::env;
use std::fs;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) const PREFLIGHT_SCHEMA: &str = "harmonia.engine.preflight.v1";
const SELF_UPDATE_REEXEC_ENV: &str = "HARMONIA_SELF_UPDATE_REEXEC";
const ENGINE_CONFIG_ENV: &str = "HARMONIA_ENGINE_CONFIG_PATH";
const DEFAULT_ENGINE_CONFIG: &str = "/etc/harmonia/engine.json";
const BOOTSTRAP_ORDER: &str = "keyring->transport->system-sync->engine-possession->verify";
const TRANSPORT_PACKAGES: &[&str] = &["ca-certificates", "git", "curl", "pacman"];
const ENGINE_RATCHET_LOCK_SCHEMA: &str = "harmonia.engine.ratchet_lock.v1";
const DEFAULT_ENGINE_RATCHET_LOCK_NAME: &str = "engine-ratchet-lock.json";

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
    pub install_bin: PathBuf,
    pub enabled: bool,
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
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EngineArtifactTransport {
    pub repo_url: String,
    #[serde(default = "default_artifact_branch")]
    pub branch: String,
    pub cache_dir: PathBuf,
    #[serde(default = "default_remote")]
    pub remote: String,
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

fn default_remote() -> String {
    "origin".to_string()
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

pub(crate) fn load_engine_plane_config(path: &Path) -> Result<Option<EnginePlaneConfig>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path)
        .map_err(|e| format!("engine-config-read-failed {}: {e}", path.display()))?;
    let config: EnginePlaneConfig = serde_json::from_str(&text)
        .map_err(|e| format!("engine-config-parse-failed {}: {e}", path.display()))?;
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

fn command_from_config(
    program: &str,
    args: &[String],
    cwd: Option<&Path>,
    apply: bool,
) -> CmdResult {
    if !apply {
        return CmdResult {
            ok: true,
            code: 0,
            stdout: format!("planned: {} {}", program, args.join(" ")),
            stderr: String::new(),
        };
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    tools::command::capture_with_cwd(program, &arg_refs, cwd.and_then(Path::to_str))
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
) -> Result<CmdResult, String> {
    if !apply {
        return Ok(CmdResult {
            ok: true,
            code: 0,
            stdout: format!(
                "planned artifact copy {} -> {}",
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
    if let Some(parent) = staged.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::copy(source, staged).map_err(|e| {
        format!(
            "engine-artifact-stage-copy-failed {} -> {}: {e}",
            source.display(),
            staged.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(staged, fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
    }
    Ok(CmdResult {
        ok: true,
        code: 0,
        stdout: format!("artifact staged {} sha256={actual}", staged.display()),
        stderr: String::new(),
    })
}

fn update_engine_subscription(
    version: &str,
    lane: &str,
    lock_sha: Option<&str>,
    apply: bool,
) -> Result<(), String> {
    if !apply {
        return Ok(());
    }
    crate::subscription::update_engine_plane(
        &crate::subscription::subscription_path(),
        version,
        lane,
        lock_sha,
    )
}

fn sorted_ladder_manifests(module_root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut manifests = Vec::new();
    if module_root.is_dir() {
        for entry in fs::read_dir(module_root).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let manifest = entry.path().join("manifest.json");
            if manifest.exists() {
                manifests.push(manifest);
            }
        }
    }
    manifests.sort();
    Ok(manifests)
}

fn proof_battery(
    preflight_dir: &Path,
    staged: &Path,
    module_root: &Path,
    profile_index: &Path,
    apply: bool,
) -> Result<(bool, Option<String>, usize), String> {
    let mut operations = 0usize;
    let staged_str = staged.to_string_lossy().to_string();
    let explain = command_from_config(&staged_str, &["explain".into()], None, apply);
    write_command_receipt(preflight_dir, "proof-explain", &explain)?;
    operations += 1;
    if !explain.ok {
        return Ok((
            false,
            Some("engine-proof-explain-failed".into()),
            operations,
        ));
    }

    let manifests = sorted_ladder_manifests(module_root)?;
    if manifests.is_empty() {
        let missing = CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: format!(
                "deployed-spine-ladder-manifest-missing {}",
                module_root.display()
            ),
        };
        write_command_receipt(preflight_dir, "proof-validate-ladder", &missing)?;
        operations += 1;
        return Ok((
            false,
            Some("engine-proof-validate-ladder-failed".into()),
            operations,
        ));
    }
    for (index, manifest) in manifests.iter().enumerate() {
        let receipt_name = if index == 0 {
            "proof-validate-ladder".to_string()
        } else {
            format!("proof-validate-ladder-{index}")
        };
        let validate = command_from_config(
            &staged_str,
            &[
                "validate-ladder".into(),
                manifest.to_string_lossy().to_string(),
            ],
            None,
            apply,
        );
        write_command_receipt(preflight_dir, &receipt_name, &validate)?;
        operations += 1;
        if !validate.ok {
            return Ok((
                false,
                Some("engine-proof-validate-ladder-failed".into()),
                operations,
            ));
        }
    }

    let plan = command_from_config(
        &staged_str,
        &[
            "plan-run".into(),
            profile_index.to_string_lossy().to_string(),
            "--receipt-dir".into(),
            preflight_dir
                .join("proof-plan-run-receipts")
                .to_string_lossy()
                .to_string(),
        ],
        None,
        apply,
    );
    write_command_receipt(preflight_dir, "proof-plan-run", &plan)?;
    operations += 1;
    if !plan.ok {
        return Ok((
            false,
            Some("engine-proof-plan-run-failed".into()),
            operations,
        ));
    }
    Ok((true, None, operations))
}

fn promote_staged_binary(
    staged: &Path,
    install_bin: &Path,
    apply: bool,
) -> Result<CmdResult, String> {
    if !apply {
        return Ok(CmdResult {
            ok: true,
            code: 0,
            stdout: format!(
                "planned atomic swap {} -> {}",
                staged.display(),
                install_bin.display()
            ),
            stderr: String::new(),
        });
    }
    if !staged.exists() {
        return Ok(CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: format!("staged-binary-missing {}", staged.display()),
        });
    }
    if let Some(parent) = install_bin.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = install_bin.with_extension("harmonia-new");
    fs::copy(staged, &tmp).map_err(|e| format!("staged-copy-failed {}: {e}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    }
    fs::rename(&tmp, install_bin).map_err(|e| {
        format!(
            "atomic-swap-failed {} -> {}: {e}",
            tmp.display(),
            install_bin.display()
        )
    })?;
    Ok(CmdResult {
        ok: true,
        code: 0,
        stdout: format!(
            "atomic swap {} -> {}",
            staged.display(),
            install_bin.display()
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
            "branch": config.map(|c| c.branch.as_str()),
            "source_dir": config.map(|c| c.source_dir.as_path()),
            "install_bin": config.map(|c| c.install_bin.as_path()),
            "old_engine_preserved": true,
            "bootstrap_order": BOOTSTRAP_ORDER,
            "pre_sync_source_build": "absent",
            "successor_promoted_only_after": "explain+validate-ladder+plan-run",
            "artifact_ratchet": "version+sha-lock",
            "engine_content_head": config.map(|c| c.branch.as_str()).unwrap_or("unknown"),
            "lane": lane,
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
        )?;
        return Ok(ModuleExecution {
            ok: false,
            changed: false,
            operation_count: 0,
            first_missing_signal: Some(signal.into()),
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
            None,
            install_bin_fingerprint(&config.install_bin).as_deref(),
        )?;
        return Ok(ModuleExecution {
            ok: false,
            changed: false,
            operation_count: 0,
            first_missing_signal: Some(signal.into()),
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
    let lock_path = ratchet_lock_path(&config_path, &config);
    let lock_sha = sha256_file(&lock_path).ok();
    let ratchet_lock = load_ratchet_lock(&lock_path)?;
    let mut lane = "source-fallback".to_string();
    let mut staged_sha: Option<String> = None;
    let install_before = install_bin_fingerprint(&config.install_bin);
    let keyring = tools::package::keyring_repair_tool(
        &preflight_dir,
        "keyring-trust",
        "archlinux-keyring",
        apply,
        1800,
    )?;
    operation_count += 1;
    let transport_packages: Vec<String> = TRANSPORT_PACKAGES
        .iter()
        .map(|v| (*v).to_string())
        .collect();
    let transport = if keyring.ok {
        tools::package::package_tool(
            &preflight_dir,
            "transport-organs",
            "install",
            &transport_packages,
            apply,
        )?
    } else {
        OperationOutcome {
            ok: false,
            changed: false,
            skipped: true,
            message: "transport organs skipped because keyring trust failed".into(),
            command: None,
        }
    };
    if !keyring.ok {
        tools::package::write_package_receipt(
            &preflight_dir,
            "transport-organs",
            "install",
            &transport,
        )?;
    }
    operation_count += 1;

    let system_sync = if keyring.ok && transport.ok {
        tools::package::package_tool(&preflight_dir, "system-sync", "upgrade", &[], apply)?
    } else {
        OperationOutcome {
            ok: false,
            changed: false,
            skipped: true,
            message: "system sync skipped because bootstrap transport failed".into(),
            command: None,
        }
    };
    if !(keyring.ok && transport.ok) {
        tools::package::write_package_receipt(
            &preflight_dir,
            "system-sync",
            "upgrade",
            &system_sync,
        )?;
    }
    operation_count += 1;

    let mut changed = keyring.changed || transport.changed || system_sync.changed;
    let mut first_missing_signal = "none".to_string();
    if !keyring.ok {
        first_missing_signal = stage_signal("keyring-trust");
    } else if !transport.ok {
        first_missing_signal = stage_signal("transport-organs");
    } else if !system_sync.ok {
        first_missing_signal = stage_signal("system-sync");
    }

    let mut source_outcome = OperationOutcome {
        ok: false,
        changed: false,
        skipped: true,
        message: "source possession skipped before successful system sync".into(),
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
        if let (Some(lock), Some(transport)) =
            (ratchet_lock.as_ref(), config.artifact_transport.as_ref())
        {
            let arch = current_arch_key();
            if let Some(artifact) = lock.artifacts.get(&arch) {
                let version_order =
                    compare_version(&lock.engine_version, env!("CARGO_PKG_VERSION"));
                if version_order == std::cmp::Ordering::Greater
                    || install_before.as_deref() != Some(artifact.sha256.as_str())
                {
                    let request = tools::git_artifact::Request::new(
                        Some(transport.repo_url.clone()),
                        transport.cache_dir.clone(),
                        transport.branch.clone(),
                        transport.remote.clone(),
                    );
                    let git_outcome = if apply {
                        tools::git_artifact::apply(&request)
                    } else {
                        tools::git_artifact::plan(&request)
                    };
                    let git_cmd = CmdResult {
                        ok: git_outcome.command.ok,
                        code: git_outcome.command.code,
                        stdout: git_outcome.command.stdout.clone(),
                        stderr: git_outcome.command.stderr.clone(),
                    };
                    write_command_receipt(&preflight_dir, "artifact-transport", &git_cmd)?;
                    operation_count += 1;
                    if git_outcome.ok {
                        let artifact_path = transport.cache_dir.join(&artifact.name);
                        let stage_cmd = copy_verified_artifact(
                            &staged,
                            &artifact_path,
                            &artifact.sha256,
                            apply,
                        )?;
                        write_command_receipt(&preflight_dir, "artifact-stage", &stage_cmd)?;
                        operation_count += 1;
                        artifact_outcome = OperationOutcome {
                            ok: stage_cmd.ok,
                            changed: stage_cmd.ok && apply,
                            skipped: false,
                            message: format!(
                                "artifact lane version={} arch={} source_head_sha={}",
                                lock.engine_version, arch, lock.source_head_sha
                            ),
                            command: Some(stage_cmd),
                        };
                        if artifact_outcome.ok {
                            lane = "artifact".to_string();
                            staged_sha = Some(artifact.sha256.clone());
                        } else {
                            first_missing_signal = stage_signal("artifact-sha256");
                        }
                    } else {
                        artifact_outcome = OperationOutcome {
                            ok: false,
                            changed: false,
                            skipped: false,
                            message: "artifact transport failed; source fallback selected".into(),
                            command: Some(git_cmd),
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

    if first_missing_signal == "none" && lane != "artifact" {
        lane = "source-fallback".to_string();
        let git_request = tools::git_artifact::Request::new(
            Some(config.source_repo_url.clone()),
            config.source_dir.clone(),
            config.branch.clone(),
            config.remote.clone(),
        );
        let git_outcome = if apply {
            tools::git_artifact::apply(&git_request)
        } else {
            tools::git_artifact::plan(&git_request)
        };
        let git_cmd = CmdResult {
            ok: git_outcome.command.ok,
            code: git_outcome.command.code,
            stdout: git_outcome.command.stdout.clone(),
            stderr: git_outcome.command.stderr.clone(),
        };
        write_command_receipt(&preflight_dir, "source-possession", &git_cmd)?;
        source_outcome = OperationOutcome {
            ok: git_outcome.ok,
            changed: git_outcome.changed,
            skipped: false,
            message: git_outcome.message,
            command: Some(git_cmd),
        };
        operation_count += 1;
        changed |= source_outcome.changed;
        if !source_outcome.ok {
            first_missing_signal = stage_signal("engine-possession");
        }
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

    if first_missing_signal == "none" && lane == "source-fallback" {
        let build_program = config.build_program.as_deref().unwrap_or("cargo");
        let build_args = config
            .build_args
            .clone()
            .unwrap_or_else(|| default_build_args(&config));
        build = command_from_config(build_program, &build_args, Some(&config.source_dir), apply);
        write_command_receipt(&preflight_dir, "staged-build", &build)?;
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
        let proof = proof_battery(
            &preflight_dir,
            &staged,
            module_root,
            &profile_index_from(module_root, &config),
            apply,
        )?;
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
        promote = promote_staged_binary(&staged, &config.install_bin, apply)?;
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
        if let Err(err) =
            update_engine_subscription(env!("CARGO_PKG_VERSION"), &lane, lock_sha.as_deref(), apply)
        {
            first_missing_signal = format!("engine-subscription-ledger-failed:{err}");
        }
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
    )?;

    let mut execution = ModuleExecution::from_operations(
        vec![
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
        let mut cmd = Command::new(&config.install_bin);
        cmd.args(env::args().skip(1));
        cmd.env(SELF_UPDATE_REEXEC_ENV, "1");
        let err = cmd.exec();
        return Err(format!("harmonia-self-update-reexec-failed: {err}"));
    }
    Ok(execution)
}

#[cfg(test)]
mod tests {
    use super::*;
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
            r#"{"id":"tv","identity":"arch-tv","modules":["identity"]}"#,
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
            let execution = run_engine_preflight(&module_root, &receipts, true).unwrap();
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
            let source_dir = root.join("source");
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
                &repo,
                &build,
                &staged,
                &install_bin,
                &profile_index,
                &source_dir,
            );
            let pacman = "#!/usr/bin/env sh\necho upgrading\nexit 0\n";
            let receipts = root.join("receipts");
            let execution = with_fake_bootstrap(&root, pacman, || {
                run_engine_preflight(&module_root, &receipts, true).unwrap()
            });
            assert!(execution.ok, "{:?}", execution.first_missing_signal);
            assert_eq!(fs::read(&install_bin).unwrap(), fs::read(&staged).unwrap());
            let receipt = fs::read_to_string(receipts.join("engine-preflight/run.json")).unwrap();
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
                run_engine_preflight(&module_root, &receipts, true).unwrap()
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
                run_engine_preflight(&module_root, &receipts, true).unwrap()
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
                run_engine_preflight(&module_root, &receipts, true).unwrap()
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
                run_engine_preflight(&module_root, &receipts, true).unwrap()
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
                run_engine_preflight(&module_root, &receipts, true).unwrap()
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
                run_engine_preflight(&module_root, &receipts, true).unwrap()
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
