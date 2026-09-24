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

pub(crate) fn is_content_seat_failure(signal: &str) -> bool {
    matches!(
        signal,
        "engine-content-seat-move-failed" | "engine-content-seat-head-mismatch"
    )
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
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;

pub(crate) const PREFLIGHT_SCHEMA: &str = "harmonia.engine.preflight.v1";
const SELF_UPDATE_REEXEC_ENV: &str = "HARMONIA_SELF_UPDATE_REEXEC";
const SELF_UPDATE_REEXEC_GENERATION: u64 = 1;
const SELF_UPDATE_REEXEC_RUNNING_FINGERPRINT_MISSING: &str =
    "harmonia-self-update-reexec-running-fingerprint-missing";
pub(crate) const ENGINE_INSTALL_BIN: &str = "/usr/local/bin/harmonia";
pub(crate) const ENGINE_SOURCE_ROOT: &str = "/var/lib/harmonia/engine-source";

#[cfg(test)]
#[derive(Clone)]
struct EngineTestSeam {
    source_root: PathBuf,
    artifact_release: Option<crate::atoms::ask::fetch_artifact::Download>,
}

#[cfg(test)]
thread_local! {
    static ENGINE_TEST_SEAM: std::cell::RefCell<Option<EngineTestSeam>> = const { std::cell::RefCell::new(None) };
}

/// Scoped, thread-local inputs for end-to-end engine artifact-lane fixtures.
/// The real preflight, source acquisition, and StageProfile molt still execute.
#[cfg(test)]
pub(crate) struct EngineTestSeamGuard(Option<EngineTestSeam>);

#[cfg(test)]
impl Drop for EngineTestSeamGuard {
    fn drop(&mut self) {
        let previous = self.0.take();
        ENGINE_TEST_SEAM.with(|seam| *seam.borrow_mut() = previous);
    }
}

/// Install fixture-local source and already-validated release inputs for the
/// current test thread. `None` release means a flagless/absent release.
#[cfg(test)]
pub(crate) fn install_engine_test_seam(
    source_root: PathBuf,
    artifact_release: Option<crate::atoms::ask::fetch_artifact::Download>,
) -> EngineTestSeamGuard {
    let seam = EngineTestSeam {
        source_root,
        artifact_release,
    };
    let previous = ENGINE_TEST_SEAM.with(|current| current.replace(Some(seam)));
    EngineTestSeamGuard(previous)
}

pub(crate) fn engine_source_root() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = ENGINE_TEST_SEAM.with(|seam| {
        seam.borrow()
            .as_ref()
            .map(|value| value.source_root.clone())
    }) {
        return path;
    }
    PathBuf::from(ENGINE_SOURCE_ROOT)
}

#[cfg(test)]
fn injected_engine_release() -> Option<Option<crate::atoms::ask::fetch_artifact::Download>> {
    ENGINE_TEST_SEAM.with(|seam| {
        seam.borrow()
            .as_ref()
            .map(|value| value.artifact_release.clone())
    })
}
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

pub(crate) fn install_bin_fingerprint(path: &Path) -> Option<String> {
    sha256_file(path).ok()
}

fn running_binary_fingerprint() -> Option<String> {
    #[cfg(test)]
    if let Ok(fingerprint) = env::var("HARMONIA_TEST_ENGINE_RUNNING_SHA") {
        return Some(fingerprint);
    }
    let proc_exe = Path::new("/proc/self/exe");
    if fs::metadata(proc_exe).is_ok() {
        return install_bin_fingerprint(proc_exe);
    }
    install_bin_fingerprint(&env::current_exe().ok()?)
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

pub(crate) fn should_self_update_reexec_for_guard(
    promotion_changed: bool,
    running_sha: Option<&str>,
    installed_sha: Option<&str>,
    guard_active: bool,
) -> bool {
    promotion_changed
        && !guard_active
        && running_sha.is_some()
        && installed_sha.is_some()
        && running_sha != installed_sha
}

pub(crate) fn should_self_update_reexec(
    promotion_changed: bool,
    running_sha: Option<String>,
    installed_sha: Option<String>,
) -> bool {
    should_self_update_reexec_for_guard(
        promotion_changed,
        running_sha.as_deref(),
        installed_sha.as_deref(),
        self_update_reexec_guard_active(),
    )
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
    receipt["changed"] = json!(false);
    receipt["installed_sha256"] = json!(install_bin_fingerprint(&engine_install_bin()));
    receipt["stage"] = json!(signal);
    receipt["first_missing_signal"] = json!(signal);
    if signal.contains("replace-process-rollback-failed") {
        receipt["old_engine_preserved"] = json!(false);
    }
    write_json(&path, &receipt)
}

fn read_install_preimage(path: &Path) -> Result<(Option<Vec<u8>>, Option<u32>), String> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((None, None)),
        Err(error) => return Err(format!("engine-install-preimage-metadata-failed: {error}")),
    };
    let bytes =
        fs::read(path).map_err(|error| format!("engine-install-preimage-read-failed: {error}"))?;
    Ok((Some(bytes), Some(metadata.permissions().mode())))
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
    // Source authority is appliance configuration; this receipt records only the
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
            "source_authority": "appliance-config-sources",
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

pub(crate) fn engine_install_bin() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = env::var_os("HARMONIA_TEST_ENGINE_INSTALL_BIN") {
        return PathBuf::from(path);
    }
    PathBuf::from(ENGINE_INSTALL_BIN)
}

fn rollback_process_plan(
    installed: &Path,
    receipt_path: &Path,
    bytes: Option<Vec<u8>>,
    mode: Option<u32>,
) -> crate::atoms::r#do::replace_process::Plan {
    crate::atoms::r#do::replace_process::Plan {
        successor: installed.to_path_buf(),
        argv: Vec::new(),
        guard_name: SELF_UPDATE_REEXEC_ENV.into(),
        guard_value: "1".into(),
        receipt_path: receipt_path.to_path_buf(),
        rollback_bytes: bytes,
        rollback_mode: mode,
    }
}

pub(crate) fn staged_bin() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = env::var_os("HARMONIA_TEST_ENGINE_STAGED_BIN") {
        return PathBuf::from(path);
    }
    engine_source_root().join("target/release/harmonia")
}

fn profile_index_from(module_root: &Path) -> PathBuf {
    module_root
        .parent()
        .map(|profile_root| profile_root.join("index.json"))
        .unwrap_or_else(|| PathBuf::from("profiles/homeconsole/index.json"))
}

pub(crate) fn promote_staged_binary(
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
    let content_seat = fs::read_to_string(preflight_dir.join("content-seat.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    let previous_preservation = fs::read_to_string(preflight_dir.join("run.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|receipt| receipt.get("old_engine_preserved").and_then(Value::as_bool))
        .unwrap_or(true);
    let rollback_failed = first_missing_signal.contains("engine-rollback-failed")
        || first_missing_signal.contains("replace-process-rollback-failed");
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
            "source_authority": "appliance-config-sources",
            "compiled_component": component,
            "engine_component_ignored": engine_component_ignored,
            "build_root": ENGINE_SOURCE_ROOT,
            "install_bin": ENGINE_INSTALL_BIN,
            "source_head": source_head.unwrap_or("unknown"),
            "content_head_observed": content_seat
                .as_ref()
                .and_then(|seat| seat.get("observed_head"))
                .cloned()
                .unwrap_or(Value::Null),
            "content_head_matches": content_seat
                .as_ref()
                .and_then(|seat| seat.get("matches"))
                .cloned()
                .unwrap_or(Value::Null),
            "content_seat_failure": content_seat
                .as_ref()
                .and_then(|seat| seat.get("first_missing_signal"))
                .cloned()
                .unwrap_or(Value::Null),
            "staged_sha256": staged_sha,
            "installed_sha256": installed_sha,
            "staged_build_identity": staged_build_identity.and_then(|identity| identity.env_sha.as_deref().zip(source_head).map(|(env_sha, source_sha)| json!({"source_sha": source_sha, "env_sha": env_sha}))),
            "reexec": reexec,
            "git_bearer": "owner",
            "failure_mode": "honest-staleness",
            "artifact_ratchet": "version+sha-lock",
            "engine_lane": null,
            "resolved_tag": null,
            "blocked_target": null,
            "nudge": "evidence",
            "bless": "the-apply-press",
            "old_engine_preserved": previous_preservation && !rollback_failed,
        }),
    )
}

fn update_engine_preflight_contract(
    preflight_dir: &Path,
    lane: Option<&str>,
    resolved_tag: Option<&str>,
    blocked_target: Option<&str>,
) -> Result<(), String> {
    let path = preflight_dir.join("run.json");
    let mut receipt: Value = serde_json::from_str(
        &fs::read_to_string(&path)
            .map_err(|error| format!("engine-preflight-receipt-read-failed: {error}"))?,
    )
    .map_err(|error| format!("engine-preflight-receipt-parse-failed: {error}"))?;
    receipt["artifact_ratchet"] = json!("version+sha-lock");
    receipt["engine_lane"] = lane.map_or(Value::Null, |value| json!(value));
    receipt["resolved_tag"] = resolved_tag.map_or(Value::Null, |value| json!(value));
    receipt["blocked_target"] = blocked_target.map_or(Value::Null, |value| json!(value));
    receipt["nudge"] = json!("evidence");
    receipt["bless"] = json!("the-apply-press");
    receipt["failure_mode"] = json!("honest-staleness");
    write_json(&path, &receipt)
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
    let config_path = crate::bands::pull_source::appliance_config_path();
    engine_source_gate_for_component_at(&config_path, certificate_path, component)
}

fn engine_source_gate_for_component_at(
    config_path: &Path,
    certificate_path: &Path,
    component: &str,
) -> Result<(String, crate::bands::pull_source::SourceResolution), String> {
    let resolution_receipt = crate::bands::pull_source::resolve_source(
        crate::bands::pull_source::SourceAuthority::ApplianceConfig {
            config_path,
            profile_path: certificate_path,
        },
        component,
        "engine-plane",
        "source-acquisition",
        None,
        None,
    );
    if let Some(blocker) = resolution_receipt.blocker {
        if blocker == format!("source-component-undeclared component={component}") {
            return Err(format!(
                "appliance-config-source-absent component={component}"
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

fn release_identity_from_candidate(locator: &str) -> Result<(String, String), String> {
    let canonical = canonicalize_git_candidate(locator)?;
    let (scheme, rest) = canonical
        .split_once("://")
        .ok_or_else(|| format!("engine-release-candidate-url-unparseable target={locator}"))?;
    let (authority, path) = rest
        .split_once('/')
        .ok_or_else(|| format!("engine-release-candidate-path-missing target={locator}"))?;
    if scheme != "https" || authority != "git.home.arpa" {
        return Err(format!(
            "engine-release-candidate-unsupported-forgejo-host target={locator}"
        ));
    }
    let mut parts = path.trim_matches('/').split('/');
    let owner = parts.next().unwrap_or_default();
    let raw_repo = parts.next().unwrap_or_default();
    if owner.is_empty() || raw_repo.is_empty() || parts.next().is_some() {
        return Err(format!(
            "engine-release-candidate-repo-ambiguous target={locator}"
        ));
    }
    let repo = raw_repo.strip_suffix(".git").unwrap_or(raw_repo);
    if repo.is_empty() {
        return Err(format!(
            "engine-release-candidate-repo-invalid target={locator}"
        ));
    }
    Ok((
        "https://git.home.arpa/api/v1".into(),
        format!("{owner}/{repo}"),
    ))
}

fn release_identity_for_preflight(locator: &str) -> Result<(String, String), String> {
    #[cfg(test)]
    if injected_engine_release().is_some() {
        return Ok((
            "https://fixture.invalid/api/v1".into(),
            "fixture/engine".into(),
        ));
    }
    release_identity_from_candidate(locator)
}

fn source_fallback_plan(
    resolution: &crate::bands::pull_source::SourceResolution,
    expected_commit: &str,
) -> crate::tools::git_artifact::SourcePlan {
    crate::bands::pull_source::bridge_acquisition_plan(
        resolution,
        engine_source_root(),
        Some(expected_commit.to_owned()),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContentSeatObservation {
    observed_head: Option<String>,
    matches: bool,
    move_ok: bool,
}

fn write_content_seat_observation(
    plan: &crate::tools::git_artifact::SourcePlan,
    expected_head: &str,
    apply: bool,
    outcome: &crate::tools::git_artifact::SourceOutcome,
    preflight_dir: &Path,
) -> Result<ContentSeatObservation, String> {
    let local = crate::atoms::ask::pull_repo::source_head(&plan.destination, &plan.bearer);
    let observed_head = local
        .ok
        .then(|| local.stdout.trim().to_owned())
        .filter(|head| crate::atoms::git_artifact::is_lower_hex_sha(head));
    let matches = outcome.ok && observed_head.as_deref() == Some(expected_head);
    let signal = if !outcome.ok {
        Some("engine-content-seat-move-failed")
    } else if !matches {
        Some("engine-content-seat-head-mismatch")
    } else {
        None
    };
    write_json(
        &preflight_dir.join("content-seat.json"),
        &json!({
            "schema": "harmonia.engine.content_seat.v1",
            "expected_head": expected_head,
            "observed_head": observed_head,
            "matches": matches,
            "observed": true,
            "could_change": apply,
            "attempt": if apply { "acquire-exact-source-head" } else { "observe-only" },
            "final": if matches { "paired" } else { "mismatch" },
            "first_missing_signal": signal,
            "promotion_allowed": signal.is_none(),
            "source_mutation": apply && outcome.changed,
            "promotion": outcome.receipt.promotion,
        }),
    )?;
    Ok(ContentSeatObservation {
        observed_head,
        matches,
        move_ok: outcome.ok,
    })
}

fn download_engine_release_for_preflight(
    component: &str,
    release_repo: &str,
    api_root: &str,
    source_sha: &str,
) -> Result<Option<crate::atoms::ask::fetch_artifact::Download>, String> {
    #[cfg(test)]
    if let Some(injected) = injected_engine_release() {
        return Ok(injected);
    }
    crate::atoms::ask::fetch_artifact::download_engine_release(
        component,
        release_repo,
        api_root,
        source_sha,
        None,
    )
}

fn observe_or_acquire_content_seat(
    resolution: &crate::bands::pull_source::SourceResolution,
    expected_head: &str,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
    preflight_dir: &Path,
) -> Result<ContentSeatObservation, String> {
    let plan = source_fallback_plan(resolution, expected_head);
    let outcome = crate::bands::pull_source::execute_source(&plan, apply, invocation);
    write_content_seat_observation(&plan, expected_head, apply, &outcome, preflight_dir)
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
            json!({"ok": ok, "apply": apply, "changed": changed, "first_missing_signal": first_missing_signal, "compiled_component": component, "engine_component_ignored": engine_component_ignored, "attest_owner": "hyalos.forward_receipt"}),
        ),
        Some(ok),
        None,
    );
}

fn rollback_after_install(
    plan: &crate::atoms::r#do::replace_process::Plan,
    preflight_dir: &Path,
    signal: &str,
) -> String {
    let rollback = crate::atoms::r#do::replace_process::rollback_installed(plan);
    let preserved = rollback.is_ok();
    let mut reported = match rollback {
        Ok(()) => signal.to_string(),
        Err(error) => format!("{signal}; engine-rollback-failed: {error}"),
    };
    if let Err(error) = mark_reexec_failure(preflight_dir, &reported) {
        reported = format!("{reported}; engine-red-receipt-failed: {error}");
    }
    if !preserved {
        let path = preflight_dir.join("run.json");
        if let Ok(mut receipt) = fs::read_to_string(&path)
            .and_then(|text| serde_json::from_str::<Value>(&text).map_err(std::io::Error::other))
        {
            receipt["old_engine_preserved"] = json!(false);
            if let Err(error) = write_json(&path, &receipt) {
                reported = format!("{reported}; engine-rollback-red-receipt-failed: {error}");
            }
        }
    }
    reported
}

pub(crate) fn run_engine_preflight(
    module_root: &Path,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<ModuleExecution, String> {
    let preflight_dir = receipt_dir.join("engine-preflight");
    crate::atoms::attest::prepare_receipt_parent(&preflight_dir)?;
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
                &component_for_receipt,
                engine_component_ignored.as_deref(),
                None,
                None,
                install_bin_fingerprint(&engine_install_bin()).as_deref(),
                false,
                apply,
                false,
                &signal,
                0,
                None,
                None,
            )?;
            update_engine_preflight_contract(&preflight_dir, None, None, Some(&signal))?;
            return Ok(failed_execution(&signal));
        }
    };
    let source_plan =
        crate::bands::pull_source::bridge_acquisition_plan(&resolution, engine_source_root(), None);
    let remote_probe = crate::atoms::ask::pull_repo::probe_declared_remote_head(&source_plan);
    let source_head = remote_probe.remote_sha.clone();
    let mut lane: Option<String> = None;
    let mut blocked_target: Option<String> = None;
    let mut operation_count = 1usize;
    let mut changed = false;
    let mut first_missing_signal = "none".to_string();
    let install_bin = engine_install_bin();
    let install_before = install_bin_fingerprint(&install_bin);
    let staged = staged_bin();
    let mut staged_sha = None;
    let mut staged_build_identity = None;
    let mut build = CmdResult {
        ok: false,
        code: -1,
        stdout: String::new(),
        stderr: "engine build skipped before source acquisition".to_string(),
    };
    let mut staged_from_artifact = false;
    let resolved_sha = source_head
        .as_deref()
        .filter(|sha| crate::atoms::git_artifact::is_lower_hex_sha(sha));
    if resolved_sha.is_none() {
        blocked_target = Some(format!(
            "{}@{}",
            remote_probe
                .locator
                .as_deref()
                .unwrap_or("configured-source"),
            resolution.requested_ref
        ));
        first_missing_signal = format!(
            "engine-source-head-unresolved target={}",
            blocked_target.as_deref().unwrap_or("configured-source")
        );
    } else if let Some(candidate) = remote_probe.locator.as_deref() {
        let target = format!("{candidate}@{}", resolved_sha.unwrap_or_default());
        match release_identity_for_preflight(candidate) {
            Err(error) => {
                blocked_target = Some(target.clone());
                first_missing_signal = format!("engine-artifact-refused target={target}: {error}");
            }
            Ok((api_root, release_repo)) => {
                match download_engine_release_for_preflight(
                    &component,
                    &release_repo,
                    &api_root,
                    resolved_sha.unwrap_or_default(),
                ) {
                    Ok(Some(download)) => {
                        lane = Some("artifact".into());
                        if apply {
                            let invocation = invocation.ok_or_else(|| {
                                "engine-artifact-stage-invocation-missing".to_string()
                            })?;
                            if let Some(parent) = staged.parent() {
                                fs::create_dir_all(parent).map_err(|error| {
                                    format!("engine-artifact-stage-parent-failed: {error}")
                                })?;
                            }
                            let placed =
                                crate::place_file::execute(crate::place_file::PlaceFileRequest {
                                    path: &staged,
                                    declared_bytes: &download.bytes,
                                    mode: Some(0o755),
                                    ownership: crate::place_file::DeclaredOwnership {
                                        uid: None,
                                        gid: None,
                                    },
                                    backup: crate::place_file::BackupPolicy::To(
                                        &preflight_dir.join("backups/prior-staged-binary"),
                                    ),
                                    invocation: Some(invocation),
                                });
                            match placed {
                                Ok(placed) => {
                                    build = CmdResult {
                                        ok: placed.receipt.ok,
                                        code: if placed.receipt.ok { 0 } else { -1 },
                                        stdout: format!(
                                            "artifact placement {} bytes={} mode=0755 changed={} backed_up={}",
                                            staged.display(),
                                            download.bytes.len(),
                                            placed.movement.changed(),
                                            placed.movement.backed_up.is_some()
                                        ),
                                        stderr: String::new(),
                                    };
                                    staged_from_artifact = placed.receipt.ok;
                                    changed = placed.movement.changed();
                                }
                                Err(error) => {
                                    build = CmdResult {
                                        ok: false,
                                        code: -1,
                                        stdout: String::new(),
                                        stderr: format!(
                                            "engine-artifact-stage-failed target={target}: {error}"
                                        ),
                                    };
                                    first_missing_signal = "engine-artifact-stage-failed".into();
                                }
                            }
                        } else {
                            build = CmdResult {
                                ok: true,
                                code: 0,
                                stdout: format!(
                                    "planned artifact placement {} bytes={} mode=0755",
                                    staged.display(),
                                    download.bytes.len()
                                ),
                                stderr: String::new(),
                            };
                        }
                        write_command_receipt(&preflight_dir, "staged-build", &build)?;
                        if build.ok && first_missing_signal == "none" {
                            let content_seat = observe_or_acquire_content_seat(
                                &resolution,
                                resolved_sha.unwrap_or_default(),
                                apply,
                                invocation,
                                &preflight_dir,
                            )?;
                            operation_count += 1;
                            if !content_seat.move_ok {
                                first_missing_signal = "engine-content-seat-move-failed".into();
                            } else if !content_seat.matches {
                                first_missing_signal = "engine-content-seat-head-mismatch".into();
                            }
                        }
                    }
                    Ok(None) => {
                        let pinned_plan =
                            source_fallback_plan(&resolution, resolved_sha.unwrap_or_default());
                        let source = crate::bands::pull_source::execute_source(
                            &pinned_plan,
                            apply,
                            invocation,
                        );
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
                        let content_seat = write_content_seat_observation(
                            &pinned_plan,
                            resolved_sha.unwrap_or_default(),
                            apply,
                            &source,
                            &preflight_dir,
                        )?;
                        if let Some(candidate) = pinned_plan.candidates.first() {
                            write_source_possession_receipt(
                                &preflight_dir,
                                &source_command,
                                &pinned_plan.destination,
                                candidate,
                                apply,
                            )?;
                        }
                        lane = Some("source".into());
                        operation_count += 1;
                        if !source.ok {
                            first_missing_signal = "engine-content-seat-move-failed".into();
                        } else if !content_seat.matches {
                            first_missing_signal = if content_seat.observed_head.is_none() {
                                "engine-content-seat-move-failed".into()
                            } else {
                                "engine-content-seat-head-mismatch".into()
                            };
                        } else {
                            changed = source.changed;
                        }
                    }
                    Err(error) => {
                        blocked_target = Some(target.clone());
                        first_missing_signal =
                            format!("engine-artifact-refused target={target}: {error}");
                    }
                }
            }
        }
    }
    if lane.as_deref() == Some("source") && first_missing_signal == "none" {
        let Some(source_head) = source_head.as_deref() else {
            first_missing_signal = "engine-source-head-absent".to_string();
            update_engine_preflight_contract(
                &preflight_dir,
                lane.as_deref(),
                None,
                blocked_target.as_deref(),
            )?;
            return Ok(failed_execution(&first_missing_signal));
        };
        let build_identity = capture_build_environment(source_head)?;
        let observation = crate::build_crate::run_build_with_mode(
            &engine_source_root(),
            source_head,
            install_before.as_deref(),
            &install_bin,
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
    } else if staged_from_artifact {
        staged_sha = sha256_file(&staged).ok();
        operation_count += 1;
    } else {
        write_command_receipt(&preflight_dir, "staged-build", &build)?;
        operation_count += 1;
    }

    post_stage_preflight(
        module_root,
        &preflight_dir,
        &install_bin,
        &staged,
        install_before,
        component,
        engine_component_ignored,
        source_head.clone(),
        apply,
        invocation,
        lane,
        resolved_sha,
        blocked_target,
        operation_count,
        changed,
        first_missing_signal,
        staged_sha,
        staged_build_identity,
        |plan, invocation| crate::atoms::r#do::replace_process::replace(plan, invocation),
    )
}

fn post_stage_preflight(
    module_root: &Path,
    preflight_dir: &Path,
    install_bin: &Path,
    staged: &Path,
    install_before: Option<String>,
    component: String,
    engine_component_ignored: Option<String>,
    source_head: Option<String>,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
    lane: Option<String>,
    resolved_sha: Option<&str>,
    blocked_target: Option<String>,
    mut operation_count: usize,
    mut changed: bool,
    mut first_missing_signal: String,
    mut staged_sha: Option<String>,
    staged_build_identity: Option<BuildEnvironmentIdentity>,
    mut exec: impl FnMut(
        &crate::atoms::r#do::replace_process::Plan,
        &crate::atoms::r#do::InvocationKey,
    ) -> Result<(), String>,
) -> Result<ModuleExecution, String> {
    let mut promote = CmdResult {
        ok: true,
        code: 0,
        stdout: "promotion skipped before successful proof".into(),
        stderr: String::new(),
    };
    let mut reexec = None;
    if first_missing_signal == "none" && apply {
        let staged_digest = match staged_sha.as_deref() {
            Some(digest) => Some(digest.to_string()),
            None => match sha256_file(&staged) {
                Ok(digest) => {
                    staged_sha = Some(digest.clone());
                    Some(digest)
                }
                Err(error) => {
                    first_missing_signal = format!("engine-staged-digest-failed: {error}");
                    None
                }
            },
        };
        if let Some(staged_digest) = staged_digest {
            let proof =
                crate::check_health::proof_battery(&crate::check_health::ProofBatteryRequest {
                    receipt_dir: &preflight_dir,
                    staged: &staged,
                    module_root,
                    profile_index: &profile_index_from(module_root),
                    apply,
                })?;
            operation_count += proof.2;
            if !proof.0 {
                first_missing_signal = proof
                    .1
                    .unwrap_or_else(|| "engine-proof-battery-failed".to_string());
            } else {
                let (rollback_bytes, rollback_mode) = match read_install_preimage(&install_bin) {
                    Ok(preimage) => preimage,
                    Err(error) => {
                        first_missing_signal = error;
                        (None, None)
                    }
                };
                if first_missing_signal == "none"
                    && self_update_reexec_guard_active()
                    && install_before.as_deref() != Some(staged_digest.as_str())
                {
                    first_missing_signal = "engine-reexec-guard-installed-digest-mismatch".into();
                }
                if first_missing_signal == "none" {
                    let rollback_plan = rollback_process_plan(
                        &install_bin,
                        &preflight_dir.join("replace-process.json"),
                        rollback_bytes.clone(),
                        rollback_mode,
                    );
                    let mut rollback_done = false;
                    promote = match promote_staged_binary(
                        &staged,
                        &install_bin,
                        true,
                        invocation,
                        &preflight_dir,
                    ) {
                        Ok(result) => result,
                        Err(error) => {
                            rollback_done = true;
                            first_missing_signal = rollback_after_install(
                                &rollback_plan,
                                &preflight_dir,
                                &format!("engine-promotion-failed: {error}"),
                            );
                            CmdResult {
                                ok: false,
                                code: -1,
                                stdout: String::new(),
                                stderr: error,
                            }
                        }
                    };
                    operation_count += 1;
                    if !promote.ok {
                        if !rollback_done {
                            first_missing_signal = rollback_after_install(
                                &rollback_plan,
                                &preflight_dir,
                                &format!("engine-promotion-failed: {}", promote.stderr),
                            );
                        }
                        changed = false;
                    } else {
                        let installed_digest = install_bin_fingerprint(&install_bin);
                        if installed_digest.as_deref() != Some(staged_digest.as_str()) {
                            first_missing_signal = rollback_after_install(
                                &rollback_plan,
                                &preflight_dir,
                                "engine-installed-digest-mismatch",
                            );
                            changed = false;
                        } else {
                            let changed_now =
                                install_before.as_deref() != installed_digest.as_deref();
                            changed |= changed_now;
                            let running_digest = running_binary_fingerprint();
                            let guard_active = self_update_reexec_guard_active();
                            if guard_active
                                && running_digest.as_deref() != installed_digest.as_deref()
                            {
                                first_missing_signal =
                                    "engine-reexec-guard-running-digest-mismatch".into();
                            } else if running_digest.is_none() {
                                first_missing_signal = rollback_after_install(
                                    &rollback_plan,
                                    &preflight_dir,
                                    SELF_UPDATE_REEXEC_RUNNING_FINGERPRINT_MISSING,
                                );
                            } else if should_self_update_reexec(
                                changed_now
                                    || running_digest.as_deref() != installed_digest.as_deref(),
                                running_digest.clone(),
                                installed_digest.clone(),
                            ) {
                                let from_sha = running_digest.unwrap_or_default();
                                let to_sha = installed_digest.clone().unwrap_or_default();
                                let proof = self_update_reexec_receipt(
                                    true,
                                    Some(from_sha.clone()),
                                    Some(to_sha.clone()),
                                );
                                reexec = proof;
                                if let Err(error) = write_command_receipt(
                                    &preflight_dir,
                                    "promote-successor",
                                    &promote,
                                ) {
                                    first_missing_signal = rollback_after_install(
                                        &rollback_plan,
                                        &preflight_dir,
                                        &format!("engine-promote-receipt-failed: {error}"),
                                    );
                                    reexec = None;
                                } else if let Err(error) = emit_preflight_receipt(
                                    &preflight_dir,
                                    &component,
                                    engine_component_ignored.as_deref(),
                                    source_head.as_deref(),
                                    Some(&staged_digest),
                                    Some(&to_sha),
                                    true,
                                    apply,
                                    true,
                                    "none",
                                    operation_count,
                                    staged_build_identity.as_ref(),
                                    reexec.as_ref(),
                                ) {
                                    first_missing_signal = rollback_after_install(
                                        &rollback_plan,
                                        &preflight_dir,
                                        &format!("engine-preflight-receipt-failed: {error}"),
                                    );
                                    reexec = None;
                                } else if let Err(error) = update_engine_preflight_contract(
                                    &preflight_dir,
                                    lane.as_deref(),
                                    resolved_sha,
                                    blocked_target.as_deref(),
                                ) {
                                    first_missing_signal = rollback_after_install(
                                        &rollback_plan,
                                        &preflight_dir,
                                        &format!("engine-preflight-contract-failed: {error}"),
                                    );
                                    reexec = None;
                                } else if let Some(invocation) = invocation {
                                    let mut plan = rollback_process_plan(
                                        &install_bin,
                                        &preflight_dir.join("replace-process.json"),
                                        rollback_bytes,
                                        rollback_mode,
                                    );
                                    plan.argv = env::args().skip(1).collect();
                                    match exec(&plan, invocation) {
                                        Ok(()) => {
                                            // A returning success means the successor owns the next
                                            // run receipt; never finalize this pre-exec snapshot.
                                            return Ok(ModuleExecution {
                                                ok: true,
                                                changed: true,
                                                operation_count,
                                                first_missing_signal: None,
                                                placements: Vec::new(),
                                            });
                                        }
                                        Err(error) => {
                                            changed = false;
                                            first_missing_signal =
                                                format!("engine-reexec-failed: {error}");
                                            if let Err(receipt_error) = mark_reexec_failure(
                                                &preflight_dir,
                                                &first_missing_signal,
                                            ) {
                                                first_missing_signal = format!(
                                                    "{first_missing_signal}; engine-reexec-red-receipt-failed: {receipt_error}"
                                                );
                                            }
                                            reexec = None;
                                        }
                                    }
                                } else {
                                    first_missing_signal = rollback_after_install(
                                        &rollback_plan,
                                        &preflight_dir,
                                        "engine-reexec-invocation-missing",
                                    );
                                    reexec = None;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    write_command_receipt(&preflight_dir, "promote-successor", &promote)?;
    let installed_after = install_bin_fingerprint(&install_bin);
    let ok = first_missing_signal == "none";
    emit_preflight_receipt(
        &preflight_dir,
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
    update_engine_preflight_contract(
        &preflight_dir,
        lane.as_deref(),
        resolved_sha,
        blocked_target.as_deref(),
    )?;
    forward_preflight_receipt(
        ok,
        apply,
        changed,
        &first_missing_signal,
        &component,
        engine_component_ignored.as_deref(),
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
        SELF_UPDATE_REEXEC_ENV, build_environment_for_source_head, build_environment_sha,
        capture_build_environment, emit_preflight_receipt, engine_source_gate,
        engine_source_gate_for_component, engine_source_gate_for_component_at,
        ignored_engine_component, ignored_engine_component_receipt_line, install_bin_fingerprint,
        promote_staged_binary, promotion_changed, release_identity_from_candidate,
        rollback_process_plan, self_update_reexec_guard_active, self_update_reexec_receipt,
        should_self_update_reexec, should_self_update_reexec_for_guard, source_fallback_plan,
        update_engine_preflight_contract,
    };
    use serde_json::json;
    use std::sync::{Mutex, OnceLock};
    use tempfile::{NamedTempFile, tempdir};

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
    fn running_fingerprint_reads_deleted_proc_executable_magic_link() {
        const CHILD_MARKER: &str = "HARMONIA_TEST_DELETED_EXE_CHILD";
        const EXPECTED_SHA: &str = "HARMONIA_TEST_DELETED_EXE_SHA";

        if std::env::var_os(CHILD_MARKER).is_some() {
            std::env::remove_var("HARMONIA_TEST_ENGINE_RUNNING_SHA");
            let executable = std::env::current_exe().unwrap();
            let expected = std::env::var(EXPECTED_SHA).unwrap();
            std::fs::remove_file(&executable).unwrap();
            let target = std::fs::read_link("/proc/self/exe").unwrap();
            assert!(
                target.to_string_lossy().ends_with(" (deleted)"),
                "{target:?}"
            );
            assert!(!executable.exists());
            assert_eq!(
                super::running_binary_fingerprint().as_deref(),
                Some(expected.as_str())
            );
            return;
        }

        let root = tempdir().unwrap();
        let executable = std::env::current_exe().unwrap();
        let expected = install_bin_fingerprint(&executable).unwrap();
        let copied_executable = root.path().join("deleted-executable-test");
        std::fs::copy(&executable, &copied_executable).unwrap();
        let test_name = std::thread::current().name().unwrap().to_string();
        let output = std::process::Command::new(&copied_executable)
            .args(["--exact", &test_name, "--nocapture"])
            .env(CHILD_MARKER, "1")
            .env(EXPECTED_SHA, expected)
            .env_remove("HARMONIA_TEST_ENGINE_RUNNING_SHA")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child test failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn content_seat_receipt_reports_exact_pair_and_report_only_mismatch_without_mutation() {
        use super::write_content_seat_observation;
        use crate::tools::git_artifact::{SourcePlan, SourceReceipt};

        let root = tempdir().unwrap();
        let receipt_dir = root.path().join("receipts");
        std::fs::create_dir_all(&receipt_dir).unwrap();
        let content = root.path().join("content");
        std::fs::create_dir_all(&content).unwrap();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(&content)
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q"]);
        git(&["config", "user.name", "Harmonia Test"]);
        git(&["config", "user.email", "harmonia-test@example.invalid"]);
        std::fs::write(content.join("module.txt"), "first\n").unwrap();
        git(&["add", "module.txt"]);
        git(&["commit", "-qm", "first"]);
        let expected = crate::atoms::ask::pull_repo::source_head(&content, "owner")
            .stdout
            .trim()
            .to_string();
        let plan = SourcePlan {
            candidates: Vec::new(),
            reference: expected.clone(),
            source_policy: "artifact".into(),
            destination: content.clone(),
            expected_commit: Some(expected.clone()),
            bearer: "owner".into(),
        };
        let outcome = |observed: &str| crate::tools::git_artifact::SourceOutcome {
            ok: true,
            changed: false,
            receipt: SourceReceipt {
                attempts: Vec::new(),
                served_index: Some(0),
                resolved_commit: Some(observed.into()),
                promotion: "observed source head".into(),
            },
        };

        let paired = write_content_seat_observation(
            &plan,
            &expected,
            true,
            &outcome(&expected),
            &receipt_dir,
        )
        .unwrap();
        assert!(paired.matches);
        let receipt: serde_json::Value = serde_json::from_slice(
            &std::fs::read(receipt_dir.join("content-seat.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["expected_head"], expected);
        assert_eq!(receipt["observed_head"], expected);
        assert_eq!(receipt["matches"], true);
        assert_eq!(receipt["attempt"], "acquire-exact-source-head");
        assert_eq!(receipt["could_change"], true);
        assert_eq!(receipt["source_mutation"], false);
        assert_eq!(receipt["promotion_allowed"], true);

        std::fs::write(content.join("module.txt"), "second\n").unwrap();
        git(&["add", "module.txt"]);
        git(&["commit", "-qm", "second"]);
        let drift = crate::atoms::ask::pull_repo::source_head(&content, "owner")
            .stdout
            .trim()
            .to_string();
        let mismatched = write_content_seat_observation(
            &plan,
            &expected,
            false,
            &outcome(&expected),
            &receipt_dir,
        )
        .unwrap();
        assert!(!mismatched.matches);
        let receipt: serde_json::Value = serde_json::from_slice(
            &std::fs::read(receipt_dir.join("content-seat.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["observed_head"], drift);
        assert_eq!(receipt["matches"], false);
        assert_eq!(receipt["first_missing_signal"], "engine-content-seat-head-mismatch");
        assert_eq!(receipt["attempt"], "observe-only");
        assert_eq!(receipt["source_mutation"], false);
        assert_eq!(receipt["promotion_allowed"], false);
    }

    #[test]
    fn content_seat_move_failure_keeps_installed_engine_unpromoted() {
        use super::post_stage_preflight;

        let root = tempdir().unwrap();
        let preflight = root.path().join("engine-preflight");
        let installed = root.path().join("installed-harmonia");
        let staged = root.path().join("staged-harmonia");
        let module_root = root.path().join("profiles/demo/modules");
        std::fs::create_dir_all(&preflight).unwrap();
        std::fs::create_dir_all(&module_root).unwrap();
        std::fs::write(&installed, b"old engine").unwrap();
        std::fs::write(&staged, b"candidate engine").unwrap();
        let old_digest = install_bin_fingerprint(&installed).unwrap();
        let staged_digest = install_bin_fingerprint(&staged).unwrap();
        let target = "0123456789abcdef0123456789abcdef01234567";

        let execution = post_stage_preflight(
            &module_root,
            &preflight,
            &installed,
            &staged,
            Some(old_digest),
            "harmonia".into(),
            None,
            Some(target.into()),
            true,
            None,
            Some("artifact".into()),
            Some(target),
            None,
            1,
            false,
            "engine-content-seat-move-failed".into(),
            Some(staged_digest),
            None,
            |_, _| panic!("content-seat failure must skip process replacement"),
        )
        .unwrap();

        assert!(!execution.ok);
        assert_eq!(execution.first_missing_signal.as_deref(), Some("engine-content-seat-move-failed"));
        assert_eq!(std::fs::read(&installed).unwrap(), b"old engine");
        let receipt: serde_json::Value = serde_json::from_slice(
            &std::fs::read(preflight.join("run.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["ok"], false);
        assert_eq!(receipt["stage"], "engine-content-seat-move-failed");
        assert_eq!(receipt["old_engine_preserved"], true);
    }

    #[test]
    fn preimage_requires_metadata_and_retains_executable_mode() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempdir().unwrap();
        let path = root.path().join("engine");
        std::fs::write(&path, b"old engine").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o751)).unwrap();
        let (bytes, mode) = super::read_install_preimage(&path).unwrap();
        assert_eq!(bytes.as_deref(), Some(&b"old engine"[..]));
        assert_eq!(mode.map(|mode| mode & 0o7777), Some(0o751));
        let missing = super::read_install_preimage(&root.path().join("absent")).unwrap();
        assert_eq!(missing, (None, None));
    }

    #[test]
    fn failed_rollback_marks_old_engine_not_preserved() {
        let root = tempdir().unwrap();
        let preflight = root.path().join("preflight");
        std::fs::create_dir_all(&preflight).unwrap();
        super::write_json(
            &preflight.join("run.json"),
            &serde_json::json!({"old_engine_preserved": true}),
        )
        .unwrap();
        let plan = rollback_process_plan(
            &root.path().join("missing-parent/engine"),
            &preflight.join("replace-process.json"),
            Some(b"old engine".to_vec()),
            Some(0o755),
        );
        let signal = super::rollback_after_install(&plan, &preflight, "engine-test-failure");
        assert!(signal.contains("engine-rollback-failed"));
        super::emit_preflight_receipt(
            &preflight, "harmonia", None, None, None, None, false, true, false, &signal, 1, None,
            None,
        )
        .unwrap();
        super::update_engine_preflight_contract(&preflight, None, None, None).unwrap();
        let receipt: serde_json::Value =
            serde_json::from_slice(&std::fs::read(preflight.join("run.json")).unwrap()).unwrap();
        assert_eq!(receipt["old_engine_preserved"], false, "signal={signal}");
        assert_eq!(receipt["ok"], false);
    }

    #[test]
    fn rollback_failure_signal_marks_engine_unpreserved_without_prior_receipt() {
        let root = tempdir().unwrap();
        let preflight = root.path().join("preflight");
        std::fs::create_dir_all(&preflight).unwrap();
        let signal = "engine-promotion-failed; engine-rollback-failed: restore refused";
        emit_preflight_receipt(
            &preflight, "harmonia", None, None, None, None, false, true, false, signal, 1, None,
            None,
        )
        .unwrap();
        update_engine_preflight_contract(&preflight, None, None, None).unwrap();
        let receipt: serde_json::Value =
            serde_json::from_slice(&std::fs::read(preflight.join("run.json")).unwrap()).unwrap();
        assert_eq!(receipt["old_engine_preserved"], false);
        assert_eq!(receipt["first_missing_signal"], signal);
        assert_eq!(receipt["ok"], false);
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
    fn serving_candidate_derives_release_owner_and_repo_without_guessing() {
        assert_eq!(
            release_identity_from_candidate("git@git.home.arpa:HOMESERVERSLTD/harmonia.git")
                .unwrap(),
            (
                "https://git.home.arpa/api/v1".to_string(),
                "HOMESERVERSLTD/harmonia".to_string()
            )
        );
        assert!(
            release_identity_from_candidate(
                "https://git.home.arpa/HOMESERVERSLTD/harmonia/extra.git"
            )
            .is_err()
        );
        assert_eq!(
            release_identity_from_candidate("https://github.com/HOMESERVERSLTD/harmonia.git")
                .unwrap_err(),
            "engine-release-candidate-unsupported-forgejo-host target=https://github.com/HOMESERVERSLTD/harmonia.git"
        );
    }

    #[test]
    fn preflight_receipt_records_lane_and_never_waits_for_bless() {
        let root = tempdir().unwrap();
        let preflight = root.path().join("engine-preflight");
        std::fs::create_dir_all(&preflight).unwrap();
        let source = "a".repeat(40);
        let staged = "b".repeat(64);
        emit_preflight_receipt(
            &preflight,
            "harmonia",
            None,
            Some(&source),
            Some(&staged),
            Some(&staged),
            true,
            true,
            true,
            "none",
            3,
            None,
            None,
        )
        .unwrap();
        update_engine_preflight_contract(&preflight, Some("artifact"), Some(&source), None)
            .unwrap();
        let receipt: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(preflight.join("run.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["artifact_ratchet"], "version+sha-lock");
        assert_eq!(receipt["engine_lane"], "artifact");
        assert_eq!(receipt["nudge"], "evidence");
        assert_eq!(receipt["bless"], "the-apply-press");
        assert_eq!(receipt["stage"], "complete");
        assert!(receipt.get("waiting_for_bless").is_none());
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
    fn source_fallback_keeps_configured_ref_and_pins_resolved_release_commit() {
        let resolved_release_tag = "0123456789abcdef0123456789abcdef01234567";
        let resolution = crate::bands::pull_source::SourceResolution {
            schema: "harmonia.engine.source_resolution.v1",
            source_policy: "developer".into(),
            component: "harmonia".into(),
            requested_ref: "main".into(),
            candidates: vec![crate::bands::pull_source::SourceCandidatePlan {
                kind: "git".into(),
                locator: "https://git.home.arpa/HOMESERVERSLTD/harmonia.git".into(),
                credential_selector: None,
                freshness_authority: None,
            }],
        };
        let plan = source_fallback_plan(&resolution, resolved_release_tag);
        assert_eq!(plan.reference, "main");
        assert_eq!(plan.expected_commit.as_deref(), Some(resolved_release_tag));
        assert_ne!(plan.reference, "HEAD");
        assert!(plan.expected_commit.as_deref().is_some_and(
            |value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        ));
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

        let config_path = root.path().join("config.json");
        std::fs::write(&config_path, br#"{"sources":{}}"#).unwrap();

        let result = engine_source_gate_for_component_at(
            &config_path,
            certificate.path(),
            crate::COMPILED_COMPONENT,
        );

        assert!(matches!(
            &result,
            Err(signal) if signal == &format!(
                "appliance-config-source-absent component={}",
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
        assert!(should_self_update_reexec_for_guard(
            true,
            Some("old-generation"),
            Some("new-generation"),
            false,
        ));
        assert!(!should_self_update_reexec_for_guard(
            false,
            Some("current-generation"),
            Some("current-generation"),
            true,
        ));
        assert!(!should_self_update_reexec_for_guard(
            true,
            Some("old-generation"),
            Some("new-generation"),
            true,
        ));

        let reexec = self_update_reexec_receipt(true, Some(from_sha.clone()), Some(to_sha.clone()))
            .expect("changed promoted successor requires reexec");
        emit_preflight_receipt(
            &preflight_dir,
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
    fn proof_passing_successor_runs_real_post_stage_branch_and_receipts_before_exec() {
        use std::os::unix::fs::PermissionsExt;

        let _env_lock = REEXEC_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let root = tempdir().unwrap();
        let installed = root.path().join("installed/harmonia");
        let staged = root.path().join("staged/harmonia");
        let module_root = root.path().join("profile/modules");
        let profile_index = root.path().join("profile/index.json");
        let preflight = root.path().join("engine-preflight");
        std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
        std::fs::create_dir_all(module_root.join("sample")).unwrap();
        std::fs::create_dir_all(&preflight).unwrap();
        std::fs::write(&installed, b"old installed engine").unwrap();
        std::fs::write(&staged, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(module_root.join("sample/manifest.json"), b"{}\n").unwrap();
        std::fs::write(&profile_index, b"{}\n").unwrap();
        let installed_before = install_bin_fingerprint(&installed).unwrap();
        let from_sha = super::running_binary_fingerprint().unwrap();
        let to_sha = install_bin_fingerprint(&staged).unwrap();
        assert_ne!(from_sha, to_sha);
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();

        let execution = super::post_stage_preflight(
            &module_root,
            &preflight,
            &installed,
            &staged,
            Some(installed_before),
            "harmonia".into(),
            None,
            None,
            true,
            Some(&invocation),
            Some("source".into()),
            None,
            None,
            1,
            false,
            "none".into(),
            Some(to_sha.clone()),
            None,
            |plan, _| {
                let receipt: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(preflight.join("run.json")).unwrap())
                        .unwrap();
                assert_eq!(receipt["ok"], true);
                assert_eq!(receipt["installed_sha256"], to_sha);
                assert_eq!(receipt["reexec"]["from_sha"], from_sha);
                assert_eq!(receipt["reexec"]["to_sha"], to_sha);
                assert_eq!(plan.successor, installed);
                Ok(())
            },
        )
        .unwrap();
        assert!(execution.ok, "{:?}", execution.first_missing_signal);
        assert_eq!(
            install_bin_fingerprint(&installed).as_deref(),
            Some(to_sha.as_str())
        );
    }

    #[test]
    fn installed_candidate_equal_but_running_old_still_reexecs() {
        use std::os::unix::fs::PermissionsExt;

        let _env_lock = REEXEC_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let root = tempdir().unwrap();
        let installed = root.path().join("installed/harmonia");
        let staged = root.path().join("staged/harmonia");
        let module_root = root.path().join("profile/modules");
        let preflight = root.path().join("engine-preflight");
        std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
        std::fs::create_dir_all(module_root.join("sample")).unwrap();
        std::fs::create_dir_all(&preflight).unwrap();
        std::fs::write(&staged, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::copy(&staged, &installed).unwrap();
        std::fs::write(module_root.join("sample/manifest.json"), b"{}\n").unwrap();
        std::fs::write(root.path().join("profile/index.json"), b"{}\n").unwrap();
        let digest = install_bin_fingerprint(&installed).unwrap();
        let running = super::running_binary_fingerprint().unwrap();
        assert_ne!(running, digest);
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let execution = super::post_stage_preflight(
            &module_root,
            &preflight,
            &installed,
            &staged,
            Some(digest.clone()),
            "harmonia".into(),
            None,
            None,
            true,
            Some(&invocation),
            Some("source".into()),
            None,
            None,
            1,
            false,
            "none".into(),
            Some(digest.clone()),
            None,
            |plan, _| {
                let receipt: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(preflight.join("run.json")).unwrap(),
                )
                .unwrap();
                assert_eq!(receipt["ok"], true);
                assert_eq!(receipt["reexec"]["from_sha"], running);
                assert_eq!(receipt["reexec"]["to_sha"], digest);
                assert_eq!(plan.successor, installed);
                Ok(())
            },
        )
        .unwrap();
        assert!(execution.ok, "{:?}", execution.first_missing_signal);
    }

    #[test]
    fn guarded_stale_running_digest_fails_closed_without_second_exec() {
        use std::os::unix::fs::PermissionsExt;

        let _env_lock = REEXEC_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _env_guard = ReexecEnvGuard::activate();
        let root = tempdir().unwrap();
        let installed = root.path().join("installed/harmonia");
        let staged = root.path().join("staged/harmonia");
        let module_root = root.path().join("profile/modules");
        let preflight = root.path().join("engine-preflight");
        std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
        std::fs::create_dir_all(module_root.join("sample")).unwrap();
        std::fs::create_dir_all(&preflight).unwrap();
        std::fs::write(&staged, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::copy(&staged, &installed).unwrap();
        std::fs::write(module_root.join("sample/manifest.json"), b"{}\n").unwrap();
        std::fs::write(root.path().join("profile/index.json"), b"{}\n").unwrap();
        let digest = install_bin_fingerprint(&installed).unwrap();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();

        let execution = super::post_stage_preflight(
            &module_root,
            &preflight,
            &installed,
            &staged,
            Some(digest.clone()),
            "harmonia".into(),
            None,
            None,
            true,
            Some(&invocation),
            Some("source".into()),
            None,
            None,
            1,
            false,
            "none".into(),
            Some(digest.clone()),
            None,
            |_, _| panic!("guarded stale engine must not attempt a second exec"),
        )
        .unwrap();
        assert!(!execution.ok);
        assert_eq!(
            execution.first_missing_signal.as_deref(),
            Some("engine-reexec-guard-running-digest-mismatch")
        );
        assert_eq!(install_bin_fingerprint(&installed).as_deref(), Some(digest.as_str()));
        let receipt: serde_json::Value =
            serde_json::from_slice(&std::fs::read(preflight.join("run.json")).unwrap()).unwrap();
        assert_eq!(receipt["old_engine_preserved"], true);
        assert_eq!(receipt["first_missing_signal"], "engine-reexec-guard-running-digest-mismatch");
    }

    #[test]
    fn guarded_current_engine_proceeds_without_unnecessary_exec() {
        use std::os::unix::fs::PermissionsExt;

        let _env_lock = REEXEC_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _env_guard = ReexecEnvGuard::activate();
        let root = tempdir().unwrap();
        let installed = root.path().join("installed/harmonia");
        let staged = root.path().join("staged/harmonia");
        let module_root = root.path().join("profile/modules");
        let preflight = root.path().join("engine-preflight");
        std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
        std::fs::create_dir_all(module_root.join("sample")).unwrap();
        std::fs::create_dir_all(&preflight).unwrap();
        std::fs::write(&staged, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::write(&installed, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&installed, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(module_root.join("sample/manifest.json"), b"{}\n").unwrap();
        std::fs::write(root.path().join("profile/index.json"), b"{}\n").unwrap();
        let digest = install_bin_fingerprint(&installed).unwrap();
        std::env::set_var("HARMONIA_TEST_ENGINE_RUNNING_SHA", &digest);
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();

        let execution = super::post_stage_preflight(
            &module_root,
            &preflight,
            &installed,
            &staged,
            Some(digest.clone()),
            "harmonia".into(),
            None,
            None,
            true,
            Some(&invocation),
            Some("source".into()),
            None,
            None,
            1,
            false,
            "none".into(),
            Some(digest.clone()),
            None,
            |_, _| panic!("matching guarded engine must not re-exec"),
        )
        .unwrap();
        std::env::remove_var("HARMONIA_TEST_ENGINE_RUNNING_SHA");
        assert!(execution.ok, "{:?}", execution.first_missing_signal);
        assert_eq!(install_bin_fingerprint(&installed).as_deref(), Some(digest.as_str()));
        let receipt: serde_json::Value =
            serde_json::from_slice(&std::fs::read(preflight.join("run.json")).unwrap()).unwrap();
        assert_eq!(receipt["ok"], true);
        assert_eq!(receipt["old_engine_preserved"], true);
        assert_eq!(receipt["reexec"], serde_json::Value::Null);
    }

    #[test]
    fn failed_successor_proof_runs_real_post_stage_branch_and_keeps_installed_preimage() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempdir().unwrap();
        let installed = root.path().join("installed/harmonia");
        let staged = root.path().join("staged/harmonia");
        let module_root = root.path().join("profile/modules-empty");
        let profile_index = root.path().join("profile/index.json");
        let preflight = root.path().join("engine-preflight");
        std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&module_root).unwrap();
        std::fs::create_dir_all(&preflight).unwrap();
        std::fs::write(&installed, b"installed old engine").unwrap();
        std::fs::write(&staged, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&profile_index, b"{}\n").unwrap();
        let installed_sha = install_bin_fingerprint(&installed).unwrap();
        let staged_sha = install_bin_fingerprint(&staged).unwrap();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();

        let execution = super::post_stage_preflight(
            &module_root,
            &preflight,
            &installed,
            &staged,
            Some(installed_sha.clone()),
            "harmonia".into(),
            None,
            None,
            true,
            Some(&invocation),
            Some("source".into()),
            None,
            None,
            1,
            false,
            "none".into(),
            Some(staged_sha.clone()),
            None,
            |_plan, _invocation| panic!("proof failure must never attempt process replacement"),
        )
        .unwrap();
        assert!(!execution.ok);
        assert_eq!(
            execution.first_missing_signal.as_deref(),
            Some("engine-proof-validate-ladder-failed")
        );
        let receipt: serde_json::Value =
            serde_json::from_slice(&std::fs::read(preflight.join("run.json")).unwrap()).unwrap();
        assert_eq!(receipt["ok"], false);
        assert_eq!(receipt["stage"], "engine-proof-validate-ladder-failed");
        assert_eq!(receipt["installed_sha256"], installed_sha);
        assert_eq!(receipt["staged_sha256"], staged_sha);
        assert_eq!(std::fs::read(installed).unwrap(), b"installed old engine");
    }

    #[test]
    fn reexec_rollback_failure_remains_red_and_marks_old_engine_not_preserved() {
        use std::os::unix::fs::PermissionsExt;

        let _env_lock = REEXEC_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let root = tempdir().unwrap();
        let installed = root.path().join("installed/harmonia");
        let staged = root.path().join("staged/harmonia");
        let module_root = root.path().join("profile/modules");
        let profile_index = root.path().join("profile/index.json");
        let preflight = root.path().join("engine-preflight");
        std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
        std::fs::create_dir_all(module_root.join("sample")).unwrap();
        std::fs::create_dir_all(&preflight).unwrap();
        std::fs::write(&installed, b"old installed engine").unwrap();
        std::fs::write(&staged, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(module_root.join("sample/manifest.json"), b"{}\n").unwrap();
        std::fs::write(&profile_index, b"{}\n").unwrap();
        let staged_sha = install_bin_fingerprint(&staged).unwrap();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();

        let execution = super::post_stage_preflight(
            &module_root,
            &preflight,
            &installed,
            &staged,
            None,
            "harmonia".into(),
            None,
            None,
            true,
            Some(&invocation),
            Some("source".into()),
            None,
            None,
            1,
            false,
            "none".into(),
            Some(staged_sha),
            None,
            |_, _| {
                std::fs::remove_file(&installed).unwrap();
                std::fs::create_dir(&installed).unwrap();
                std::fs::write(installed.join("blocks-restore"), b"not empty").unwrap();
                Err("replace-process-rollback-failed: fixture restore refusal".into())
            },
        )
        .unwrap();
        assert!(!execution.ok);
        assert!(
            execution
                .first_missing_signal
                .as_deref()
                .unwrap()
                .contains("replace-process-rollback-failed")
        );
        let receipt: serde_json::Value =
            serde_json::from_slice(&std::fs::read(preflight.join("run.json")).unwrap()).unwrap();
        assert_eq!(receipt["ok"], false);
        assert_eq!(receipt["old_engine_preserved"], false);
        assert_eq!(receipt["reexec"], serde_json::Value::Null);
        assert!(
            receipt["stage"]
                .as_str()
                .unwrap()
                .contains("replace-process-rollback-failed")
        );
    }

    #[test]
    fn no_promotion_receipts_null_reexec() {
        let root = tempdir().unwrap();
        let preflight_dir = root.path().join("engine-preflight");
        std::fs::create_dir_all(&preflight_dir).unwrap();
        assert!(!promotion_changed(false, false, None, None));
        assert!(!promotion_changed(true, true, Some("same"), Some("same")));
        emit_preflight_receipt(
            &preflight_dir,
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
