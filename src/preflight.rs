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
const LEGACY_ROOT_GITCONFIG: &str = "/root/.gitconfig";
const LEGACY_ROOT_FORGEJO_INCLUDE: &str = "/root/.gitconfig.d/forgejo-credentials.inc";
const LEGACY_ROOT_FORGEJO_STORE: &str = "/root/.git-credentials-forgejo";
const LEGACY_OWNER_FORGEJO_STORE: &str = "/home/owner/.git-credentials-forgejo";
const CADUCEUS_COMPONENT: &str = "caduceus";
const CADUCEUS_SOURCE_DIR: &str = "/opt/caduceus/source";
const CADUCEUS_STAFF_SOURCE_ROOT: &str = "/opt/caduceus/source/data/staff-actuators";
const CADUCEUS_STAFF_RECEIPT: &str = "caduceus-staff-shelf-sweep.json";
const CADUCEUS_SOURCE_RECEIPT: &str = "caduceus-source-possession.json";

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
    #[serde(default = "default_git_bearer")]
    pub git_bearer: String,
    /// Absolute owner-readable private-key path for Forgejo SSH transport.
    /// The parent validates path identity only; the dropped Git child owns use.
    #[serde(default)]
    pub git_ssh_key_path: Option<PathBuf>,
    /// Optional HTTPS forge host that may receive the command-local credential helper.
    #[serde(default)]
    pub git_https_credential_host: Option<String>,
    /// Optional owner-readable token file used only by the dropped Git child for that host.
    #[serde(default)]
    pub git_https_credential_token_path: Option<PathBuf>,
    /// Body-local opaque selector custody. This map names material only; the
    /// certificate remains the sole source of ordered candidate locators.
    #[serde(default)]
    pub credential_scopes: BTreeMap<String, tools::git_artifact::CredentialScope>,
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

/// Apply the optional, engine-owned HTTPS credential selector to a module Git
/// request.  A body without engine configuration remains credential-less.
pub(crate) fn with_configured_https_credentials(
    request: tools::git_artifact::Request,
) -> Result<tools::git_artifact::Request, String> {
    let Some(config) = load_engine_plane_config(&engine_config_path())? else {
        return Ok(request);
    };
    Ok(request.with_https_credentials(
        config.git_https_credential_host,
        config.git_https_credential_token_path,
    ))
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

fn default_remote() -> String {
    "origin".to_string()
}

fn default_git_bearer() -> String {
    "owner".to_string()
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
    let mut config: EnginePlaneConfig = serde_json::from_str(&text)
        .map_err(|e| format!("engine-config-parse-failed {}: {e}", path.display()))?;
    config.source_dir = PathBuf::from(SOURCE_ROOT);
    config.local_source_checkout = config
        .local_source_checkout
        .as_ref()
        .map(|_| PathBuf::from(SOURCE_ROOT));
    validate_credential_scopes(&config.credential_scopes)?;
    Ok(Some(config))
}

/// Return only named body-local credential material for source acquisition.
/// This function never opens a key or token; Git's dropped bearer child is the
/// sole reader of those files.
pub(crate) fn credential_scopes(
    config: &EnginePlaneConfig,
) -> BTreeMap<String, tools::git_artifact::CredentialScope> {
    config.credential_scopes.clone()
}

fn validate_credential_scopes(
    scopes: &BTreeMap<String, tools::git_artifact::CredentialScope>,
) -> Result<(), String> {
    for (selector, scope) in scopes {
        if !source_resolver::selector_is_safe(selector) {
            return Err(format!(
                "engine-credential-scope-selector-invalid selector={selector}"
            ));
        }
        for path in [&scope.ssh_key_path, &scope.https_token_path]
            .into_iter()
            .flatten()
        {
            if !path.is_absolute() {
                return Err(format!(
                    "engine-credential-scope-path-not-absolute selector={selector} path={}",
                    path.display()
                ));
            }
            if path.to_string_lossy().contains("://") {
                return Err(format!(
                    "engine-credential-scope-url-forbidden selector={selector}"
                ));
            }
        }
        if let Some(host) = scope.https_host.as_deref() {
            if !credential_host_is_safe(host) {
                return Err(format!(
                    "engine-credential-scope-host-invalid selector={selector}"
                ));
            }
        }
    }
    Ok(())
}

fn credential_host_is_safe(host: &str) -> bool {
    !host.is_empty()
        && !host.contains("://")
        && !host.contains('/')
        && !host.contains('\\')
        && !host.contains('@')
        && !host.chars().any(char::is_whitespace)
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

fn retire_root_git_credential_wiring(apply: bool) -> OperationOutcome {
    let paths = [
        Path::new(LEGACY_ROOT_FORGEJO_INCLUDE),
        Path::new(LEGACY_ROOT_FORGEJO_STORE),
        Path::new(LEGACY_OWNER_FORGEJO_STORE),
    ];
    if !apply {
        return OperationOutcome {
            ok: true,
            changed: false,
            skipped: false,
            message: format!(
                "planned removal of legacy root Forgejo credential wiring: {}, {}, include from {}",
                paths[0].display(),
                paths[1].display(),
                LEGACY_ROOT_GITCONFIG
            ),
            command: None,
        };
    }

    let mut changed = false;
    let mut actions = Vec::new();
    for path in paths {
        if path.exists() {
            if let Err(err) = fs::remove_file(path) {
                return OperationOutcome {
                    ok: false,
                    changed,
                    skipped: false,
                    message: format!("legacy root Forgejo credential removal failed: {err}"),
                    command: None,
                };
            }
            changed = true;
            actions.push(format!("removed={}", path.display()));
        }
    }

    let root_config = Path::new(LEGACY_ROOT_GITCONFIG);
    if root_config.exists() {
        let text = match fs::read_to_string(root_config) {
            Ok(text) => text,
            Err(err) => {
                return OperationOutcome {
                    ok: false,
                    changed,
                    skipped: false,
                    message: format!("legacy root Git config read failed: {err}"),
                    command: None,
                };
            }
        };
        let mut removed_include = false;
        let mut retained = Vec::new();
        for line in text.lines() {
            let normalized = line.trim().replace('\t', " ");
            let legacy_include = normalized.split_once('=').is_some_and(|(key, value)| {
                key.trim() == "path" && value.trim() == LEGACY_ROOT_FORGEJO_INCLUDE
            });
            if legacy_include {
                removed_include = true;
            } else {
                retained.push(line);
            }
        }
        if removed_include {
            while retained
                .last()
                .is_some_and(|line| line.trim().is_empty() || line.trim() == "[include]")
            {
                retained.pop();
            }
            if retained.iter().all(|line| line.trim().is_empty()) {
                if let Err(err) = fs::remove_file(root_config) {
                    return OperationOutcome {
                        ok: false,
                        changed,
                        skipped: false,
                        message: format!("legacy root Git config removal failed: {err}"),
                        command: None,
                    };
                }
                actions.push(format!("removed={}", root_config.display()));
            } else {
                let replacement = format!("{}\n", retained.join("\n"));
                if let Err(err) = fs::write(root_config, replacement) {
                    return OperationOutcome {
                        ok: false,
                        changed,
                        skipped: false,
                        message: format!("legacy root Git config rewrite failed: {err}"),
                        command: None,
                    };
                }
                actions.push(format!("retired_include_from={}", root_config.display()));
            }
            changed = true;
        }
    }

    OperationOutcome {
        ok: true,
        changed,
        skipped: false,
        message: if actions.is_empty() {
            "legacy root Forgejo credential wiring absent".to_string()
        } else {
            actions.join(" ")
        },
        command: None,
    }
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

/// Run a command whose working directory is the declared source checkout as
/// its resolved Git bearer.  The privileged parent retains only the later
/// promotion of the already-built staged binary.
fn command_from_config_as_bearer(
    program: &str,
    args: &[String],
    cwd: &Path,
    bearer: &str,
    apply: bool,
) -> CmdResult {
    if !apply {
        return CmdResult {
            ok: true,
            code: 0,
            stdout: format!("planned as {bearer}: {} {}", program, args.join(" ")),
            stderr: String::new(),
        };
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    tools::command::capture_with_cwd_as_bearer(program, &arg_refs, cwd.to_str(), bearer)
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

fn local_source_checkout_possession(config: &EnginePlaneConfig) -> CmdResult {
    let Some(checkout) = config.local_source_checkout.as_deref() else {
        return CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: "local-source-checkout-unconfigured".to_string(),
        };
    };
    if checkout != config.source_dir {
        return CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: format!(
                "local-source-checkout-must-equal-source-dir checkout={} source_dir={}",
                checkout.display(),
                config.source_dir.display()
            ),
        };
    }
    let Some(cwd) = checkout.to_str() else {
        return CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: format!("local-source-checkout-non-utf8 {}", checkout.display()),
        };
    };
    let mut transcript = Vec::new();
    for (label, args) in [
        ("work-tree", vec!["rev-parse", "--is-inside-work-tree"]),
        ("head", vec!["rev-parse", "--verify", "HEAD"]),
        ("branch", vec!["symbolic-ref", "--quiet", "--short", "HEAD"]),
    ] {
        let result = tools::command::capture_with_cwd_as_bearer(
            "/usr/bin/git",
            &args,
            Some(cwd),
            &config.git_bearer,
        );
        transcript.push(format!("{label}: {}", result.stdout.trim()));
        if !result.ok {
            return CmdResult {
                ok: false,
                code: result.code,
                stdout: transcript.join("\n"),
                stderr: result.stderr,
            };
        }
        if label == "branch" && result.stdout.trim() != config.branch {
            return CmdResult {
                ok: false,
                code: 1,
                stdout: transcript.join("\n"),
                stderr: format!(
                    "local-source-checkout-branch-mismatch expected={} actual={}",
                    config.branch,
                    result.stdout.trim()
                ),
            };
        }
    }
    CmdResult {
        ok: true,
        code: 0,
        stdout: format!(
            "local source checkout possessed read-only path={} owner_freshness_lane=external-owner-plane\n{}",
            checkout.display(),
            transcript.join("\n")
        ),
        stderr: String::new(),
    }
}

/// Converge the Caduceus Python staff package and its launchers after the
/// engine's source-possession lane. This engine-owned maintenance runs through
/// the preflight on every update.
fn converge_caduceus_staff_shelf(
    preflight_dir: &Path,
    apply: bool,
    source_ready: bool,
) -> Result<OperationOutcome, String> {
    let source_root = PathBuf::from(CADUCEUS_STAFF_SOURCE_ROOT);
    let receipt_path = preflight_dir.join(CADUCEUS_STAFF_RECEIPT);
    if !source_ready || !source_root.is_dir() {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: format!(
                "Caduceus staff source not possessed at {}",
                source_root.display()
            ),
            command: None,
        };
        write_json(
            &receipt_path,
            &json!({
                "schema": "harmonia.tool_receipt.v1",
                "operation_id": "caduceus-staff-shelf-sweep",
                "tool": "files",
                "action": "source-shelf-sweep",
                "ok": true,
                "checked": 0,
                "changed": false,
                "entries": [],
                "skipped": true,
                "message": outcome.message,
                "first_missing_signal": "caduceus-source-not-possessed",
                "observed_state": {"source_root": source_root, "possessed": false, "source_ready": source_ready},
                "desired_state": {"target_shelf": "/usr/local/sbin/caduceus_staff", "launcher_target_root": "/usr/local/sbin"},
                "diff_decision": "unavailable",
                "movement": "none",
                "truthful_changed": false,
            }),
        )?;
        return Ok(outcome);
    }

    let request = tools::files::SourceShelfSweepRequest {
        source_root: source_root.clone(),
        shelf_source: PathBuf::from("caduceus_staff"),
        target_shelf: PathBuf::from("/usr/local/sbin/caduceus_staff"),
        launcher_source_root: source_root,
        launcher_target_root: PathBuf::from("/usr/local/sbin"),
        launcher_pattern: "caduceus-*".into(),
        shelf_owner: "root".into(),
        shelf_group: "root".into(),
        shelf_directory_mode: 0o755,
        shelf_file_mode: 0o644,
        launcher_mode: 0o755,
        prune: true,
        launcher_exclude: Vec::new(),
        provenance_state: None,
        receipt_name: "caduceus-staff-shelf-sweep-detail".into(),
    };
    let sweep = tools::files::source_shelf_sweep(&request, preflight_dir, apply)?;
    let outcome = OperationOutcome {
        ok: sweep.ok,
        changed: sweep.changed,
        skipped: !apply,
        message: sweep.message.clone(),
        command: None,
    };
    write_json(
        &receipt_path,
        &json!({
            "schema": "harmonia.tool_receipt.v1",
            "operation_id": "caduceus-staff-shelf-sweep",
            "tool": "files",
            "action": "source-shelf-sweep",
            "ok": sweep.ok,
            "checked": sweep.entries.len(),
            "changed": sweep.changed,
            "entries": sweep.entries,
            "skipped": !apply,
            "message": sweep.message,
            "first_missing_signal": if sweep.ok { "none" } else { sweep.first_blocker.as_str() },
            "observed_state": {"source_inventory_count": sweep.source_inventory_count, "target_inventory_count_before": sweep.target_inventory_count_before, "current": sweep.current},
            "desired_state": {"target_shelf": request.target_shelf, "launcher_target_root": request.launcher_target_root, "prune": request.prune},
            "diff_decision": if sweep.current && !sweep.changed { "empty" } else { "different" },
            "movement": if sweep.changed { "shelf-promote-or-bounded-removal" } else if sweep.current { "none" } else { "report-only" },
            "truthful_changed": sweep.changed,
        }),
    )?;
    Ok(outcome)
}

/// Possess the Caduceus source for the engine-owned staff shelf only when the
/// body certificate declares that component. The certificate selects source
/// candidates and the engine config supplies only owner-held credential scopes;
/// `acquire_source` performs the remote-versus-destination comparison before it
/// stages or promotes anything.
///
/// This is deliberately non-gating for engine self-possession. A missing or
/// failed Caduceus acquisition leaves the staff sweep skipped with its existing
/// `caduceus-source-not-possessed` signal instead of failing the whole preflight.
fn possess_caduceus_source_for_staff_shelf(
    config: &EnginePlaneConfig,
    preflight_dir: &Path,
    apply: bool,
) -> Result<(OperationOutcome, bool), String> {
    let receipt_path = preflight_dir.join(CADUCEUS_SOURCE_RECEIPT);
    let certificate = device_profile_certificate_path();
    let resolution_receipt = resolve_source(
        &certificate,
        CADUCEUS_COMPONENT,
        "engine-plane",
        "caduceus-staff-shelf-source-possession",
    );
    let Some(resolution) = resolution_receipt.resolution.clone() else {
        let blocker = resolution_receipt
            .blocker
            .clone()
            .unwrap_or_else(|| "source-resolution-plan-missing".to_string());
        write_json(
            &receipt_path,
            &json!({
                "schema": "harmonia.engine.caduceus_source_possession.v1",
                "ok": true,
                "apply": apply,
                "changed": false,
                "skipped": true,
                "component": CADUCEUS_COMPONENT,
                "destination": CADUCEUS_SOURCE_DIR,
                "source_resolution": resolution_receipt,
                "first_missing_signal": "caduceus-source-not-possessed",
                "reason": blocker,
                "movement": "none",
            }),
        )?;
        return Ok((
            OperationOutcome {
                ok: true,
                changed: false,
                skipped: true,
                message: "Caduceus source is not declared by this body certificate".into(),
                command: None,
            },
            false,
        ));
    };

    let expected_commit = (resolution.requested_ref.len() == 40
        && resolution
            .requested_ref
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()))
    .then(|| resolution.requested_ref.clone());
    let plan = bridge_acquisition_plan(
        &resolution,
        PathBuf::from(CADUCEUS_SOURCE_DIR),
        config.git_bearer.clone(),
        expected_commit,
        credential_scopes(config),
    );
    if !apply {
        let probe = tools::git_artifact::probe_declared_remote_head(&plan);
        write_json(
            &receipt_path,
            &json!({
                "schema": "harmonia.engine.caduceus_source_possession.v1",
                "ok": true,
                "apply": false,
                "changed": false,
                "skipped": true,
                "component": CADUCEUS_COMPONENT,
                "destination": CADUCEUS_SOURCE_DIR,
                "source_resolution": resolution_receipt,
                "remote_probe": {
                    "state": probe.state,
                    "candidate_index": probe.candidate_index,
                    "locator": probe.locator,
                    "reference": probe.reference,
                    "remote_sha": probe.remote_sha,
                    "ok": probe.command.ok,
                    "failed_attempt_count": probe.failed_attempts.len(),
                },
                "first_missing_signal": "none",
                "movement": "report-only",
            }),
        )?;
        return Ok((
            OperationOutcome {
                ok: true,
                changed: false,
                skipped: true,
                message: "Caduceus source possession is report-only".into(),
                command: None,
            },
            Path::new(CADUCEUS_STAFF_SOURCE_ROOT).is_dir(),
        ));
    }

    let acquisition = tools::git_artifact::acquire_source(&plan);
    let command = CmdResult {
        ok: acquisition.ok,
        code: if acquisition.ok { 0 } else { 1 },
        stdout: acquisition.receipt.promotion.clone(),
        stderr: (!acquisition.ok)
            .then(|| acquisition.receipt.promotion.clone())
            .unwrap_or_default(),
    };
    write_command_receipt(preflight_dir, "caduceus-source-possession", &command)?;
    let source_ready = acquisition.ok && Path::new(CADUCEUS_STAFF_SOURCE_ROOT).is_dir();
    write_json(
        &receipt_path,
        &json!({
            "schema": "harmonia.engine.caduceus_source_possession.v1",
            "ok": acquisition.ok,
            "apply": true,
            "changed": acquisition.changed,
            "skipped": !source_ready,
            "component": CADUCEUS_COMPONENT,
            "destination": CADUCEUS_SOURCE_DIR,
            "source_resolution": resolution_receipt,
            "attempts": acquisition.receipt.attempts.iter().map(|attempt| json!({
                "index": attempt.index,
                "kind": format!("{:?}", attempt.kind).to_ascii_lowercase(),
                "locator": attempt.locator,
                "credential_selector": attempt.credential_selector,
                "disposition": attempt.disposition,
                "resolved_commit": attempt.resolved_commit,
                "external_freshness": attempt.external_freshness,
                "detail": attempt.detail,
            })).collect::<Vec<_>>(),
            "served_index": acquisition.receipt.served_index,
            "resolved_commit": acquisition.receipt.resolved_commit,
            "promotion": acquisition.receipt.promotion,
            "first_missing_signal": if source_ready { "none" } else { "caduceus-source-not-possessed" },
            "movement": if acquisition.changed { "source-promoted" } else if source_ready { "none" } else { "none" },
        }),
    )?;
    Ok((
        OperationOutcome {
            // Source possession is auxiliary to the engine's own update. Its
            // detailed receipt retains failure truth while the preflight carries
            // on to emit the shelf's established honest skip receipt.
            ok: true,
            changed: acquisition.changed,
            skipped: !source_ready,
            message: if source_ready {
                "Caduceus source possessed for engine staff shelf".into()
            } else {
                "Caduceus source possession unavailable; staff shelf will skip".into()
            },
            command: Some(command),
        },
        source_ready,
    ))
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
            "engine_content_head": config.map(|c| c.branch.as_str()).unwrap_or("unknown"),
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
            &[],
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
            None,
            &[],
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
    let root_git_credential_retirement = retire_root_git_credential_wiring(apply);
    write_json(
        &preflight_dir.join("root-git-credential-retirement.json"),
        &json!({
            "schema": "harmonia.root_git_credential_retirement.v1",
            "ok": root_git_credential_retirement.ok,
            "apply": apply,
            "changed": root_git_credential_retirement.changed,
            "message": root_git_credential_retirement.message,
            "forbidden_paths": [LEGACY_ROOT_FORGEJO_INCLUDE, LEGACY_ROOT_FORGEJO_STORE, LEGACY_OWNER_FORGEJO_STORE],
            "root_gitconfig": LEGACY_ROOT_GITCONFIG,
        }),
    )?;
    operation_count += 1;
    let lock_path = ratchet_lock_path(&config_path, &config);
    let lock_sha = sha256_file(&lock_path).ok();
    let ratchet_lock = load_ratchet_lock(&lock_path)?;
    let mut lane = "source-fallback".to_string();
    let mut transport_used: Option<String> = None;
    let mut artifact_transport_attempts: Vec<serde_json::Value> = Vec::new();
    let mut staged_sha: Option<String> = None;
    let install_before = install_bin_fingerprint(&config.install_bin);
    let keyring = if root_git_credential_retirement.ok {
        tools::package::keyring_repair_tool(
            &preflight_dir,
            "keyring-trust",
            "archlinux-keyring",
            apply,
            1800,
        )?
    } else {
        OperationOutcome {
            ok: false,
            changed: false,
            skipped: true,
            message: "keyring trust skipped because root Git credential retirement failed".into(),
            command: None,
        }
    };
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

    let mut changed = root_git_credential_retirement.changed
        || keyring.changed
        || transport.changed
        || system_sync.changed;
    let mut first_missing_signal = "none".to_string();
    if !root_git_credential_retirement.ok {
        first_missing_signal = stage_signal("root-git-credential-retirement");
    } else if !keyring.ok {
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
                        let request = tools::git_artifact::Request::new(
                            Some(transport.repo_url.clone()),
                            transport.cache_dir.clone(),
                            transport.branch.clone(),
                            transport.remote.clone(),
                        )
                        .with_bearer(config.git_bearer.clone())
                        .with_ssh_key_path(config.git_ssh_key_path.clone())
                        .with_https_credentials(
                            config.git_https_credential_host.clone(),
                            config.git_https_credential_token_path.clone(),
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

    if first_missing_signal == "none" && lane != "artifact" {
        if config.local_source_checkout.is_some() {
            lane = "local-checkout".to_string();
            let git_cmd = local_source_checkout_possession(&config);
            write_command_receipt(&preflight_dir, "source-possession", &git_cmd)?;
            source_outcome = OperationOutcome {
                ok: git_cmd.ok,
                changed: false,
                skipped: false,
                message: "declared local source checkout read-only possession".into(),
                command: Some(git_cmd),
            };
        } else {
            lane = "source-fallback".to_string();
            let git_request = tools::git_artifact::Request::new(
                Some(config.source_repo_url.clone()),
                config.source_dir.clone(),
                config.branch.clone(),
                config.remote.clone(),
            )
            .with_bearer(config.git_bearer.clone())
            .with_ssh_key_path(config.git_ssh_key_path.clone())
            .with_https_credentials(
                config.git_https_credential_host.clone(),
                config.git_https_credential_token_path.clone(),
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
        }
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

    let (caduceus_source_possession, caduceus_source_ready) =
        match possess_caduceus_source_for_staff_shelf(&config, &preflight_dir, apply) {
            Ok(result) => result,
            Err(error) => (
                OperationOutcome {
                    // The shelf is an engine primitive, but a source-resolution
                    // receipt failure must not fail-fast the engine preflight.
                    ok: true,
                    changed: false,
                    skipped: true,
                    message: format!(
                        "Caduceus source possession unavailable; staff shelf will skip: {error}"
                    ),
                    command: None,
                },
                false,
            ),
        };
    operation_count += 1;
    changed |= caduceus_source_possession.changed;

    let caduceus_staff_shelf =
        match converge_caduceus_staff_shelf(&preflight_dir, apply, caduceus_source_ready) {
            Ok(outcome) => outcome,
            Err(error) => OperationOutcome {
                ok: false,
                changed: false,
                skipped: true,
                message: error,
                command: None,
            },
        };
    operation_count += 1;
    changed |= caduceus_staff_shelf.changed;
    if !caduceus_staff_shelf.ok && first_missing_signal == "none" {
        first_missing_signal = "caduceus-staff-shelf-sweep-failed".into();
    }


    if first_missing_signal == "none"
        && matches!(lane.as_str(), "source-fallback" | "local-checkout")
    {
        let build_program = config.build_program.as_deref().unwrap_or("cargo");
        let build_args = config
            .build_args
            .clone()
            .unwrap_or_else(|| default_build_args(&config));
        build = command_from_config_as_bearer(
            build_program,
            &build_args,
            &config.source_dir,
            &config.git_bearer,
            apply,
        );
        write_bearer_command_receipt(&preflight_dir, "staged-build", &build, &config.git_bearer)?;
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
        transport_used.as_deref(),
        &artifact_transport_attempts,
    )?;

    let mut execution = ModuleExecution::from_operations(
        vec![
            (
                "root-git-credential-retirement",
                root_git_credential_retirement,
            ),
            ("keyring-trust", keyring),
            ("transport-organs", transport),
            ("system-sync", system_sync),
            ("artifact-lane", artifact_outcome),
            ("source-possession", source_outcome),
            ("caduceus-source-possession", caduceus_source_possession),
            ("caduceus-staff-shelf-sweep", caduceus_staff_shelf),
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
                run_engine_preflight(&module_root, &receipts, true).unwrap()
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
            assert!(source_receipt.contains("owner_freshness_lane=external-owner-plane"));
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
                run_engine_preflight(&module_root, &receipts, true).unwrap()
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
                run_engine_preflight(&module_root, &receipts, true).unwrap()
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
                run_engine_preflight(&module_root, &receipts, true).unwrap()
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
