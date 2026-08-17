use super::command;
use super::comparison::{self, DiffDecision};
use crate::{write_json, CmdResult, OperationOutcome};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(test)]
use std::cell::RefCell;
use std::env;
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_TIMEOUT_SECS: u64 = 3600;
const DEFAULT_AUR_BASE_URL: &str = "https://aur.archlinux.org";
pub(crate) const DEFAULT_BUILD_ROOT: &str = "/var/tmp/harmonia/aur";
const HARMONIA_AUR_UPSTREAM_STATE_ENV: &str = "HARMONIA_AUR_UPSTREAM_STATE";

#[cfg(test)]
thread_local! {
    static TEST_UPSTREAM_STATE_PATH: RefCell<Option<String>> = const { RefCell::new(None) };

}

#[allow(dead_code)]
pub(crate) fn set_test_upstream_state_path(path: Option<String>) {
    #[cfg(test)]
    TEST_UPSTREAM_STATE_PATH.with(|slot| {
        *slot.borrow_mut() = path;
    });
    #[cfg(not(test))]
    let _ = path;
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AurRatchetLock {
    pub schema: String,
    pub package: String,
    pub pinned_version: String,
    pub pkgbuild_sha: String,
    #[serde(default)]
    pub aur_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AurUpstreamState {
    pub schema: String,
    pub package: String,
    pub available_version: String,
    pub pkgbuild_sha: String,
    pub observed_source: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AurCheckReceipt {
    pub schema: &'static str,
    pub package: String,
    pub pinned_version: String,
    pub pinned_pkgbuild_sha: String,
    pub available_version: Option<String>,
    pub available_pkgbuild_sha: Option<String>,
    pub upstream_source_observed: Option<String>,
    pub newer_available: bool,
    pub ok: bool,
    pub changed: bool,
    pub first_missing_signal: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AurBuildReceipt {
    pub schema: &'static str,
    pub package: String,
    pub pinned_version: String,
    pub pinned_pkgbuild_sha: String,
    pub build_dir: PathBuf,
    pub produced_package_path: Option<PathBuf>,
    pub artifact_sha256: Option<String>,
    pub installed_version_before: Option<String>,
    pub install_requested: bool,
    pub installed_converged: bool,
    pub first_blocker: Option<String>,
    pub pkgver_neutralized: bool,
    pub timeout_policy: String,
    pub safety_posture: String,
    pub unprivileged_builder: String,
    pub ok: bool,
    pub changed: bool,
    pub command: Option<CmdResult>,
    pub install_command: Option<CmdResult>,
    pub install_verify_command: Option<CmdResult>,
}

pub(crate) fn read_lock(path: &Path, package: &str) -> Result<AurRatchetLock, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("aur-ratchet-lock-read-failed {}: {e}", path.display()))?;
    let lock: AurRatchetLock = serde_json::from_str(&text)
        .map_err(|e| format!("aur-ratchet-lock-parse-failed {}: {e}", path.display()))?;
    if lock.schema != "harmonia.aur.ratchet_lock.v1" {
        return Err(format!(
            "aur-ratchet-lock-schema-unsupported-{}",
            lock.schema
        ));
    }
    if lock.package != package {
        return Err(format!(
            "aur-ratchet-lock-package-mismatch expected={package} actual={}",
            lock.package
        ));
    }
    validate_pin_shape(&lock)?;
    Ok(lock)
}

pub(crate) fn validate_pin_shape(lock: &AurRatchetLock) -> Result<(), String> {
    if lock.package.trim().is_empty() {
        return Err("aur-package-empty".into());
    }
    if lock.pinned_version.trim().is_empty() {
        return Err("aur-pinned-version-empty".into());
    }
    if !is_git_sha(&lock.pkgbuild_sha) {
        return Err("aur-pkgbuild-sha-not-hex40".into());
    }
    Ok(())
}

pub(crate) fn is_git_sha(value: &str) -> bool {
    value.len() == 40 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn upstream_state_path(arg: Option<&str>) -> Option<String> {
    if let Some(value) = arg.filter(|value| !value.trim().is_empty()) {
        return Some(value.to_string());
    }
    #[cfg(test)]
    if let Some(path) = TEST_UPSTREAM_STATE_PATH.with(|slot| slot.borrow().clone()) {
        return Some(path);
    }
    env::var(HARMONIA_AUR_UPSTREAM_STATE_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

pub(crate) fn read_upstream_state(
    path: Option<&str>,
    package: &str,
) -> Result<AurUpstreamState, String> {
    let state = if let Some(path) = upstream_state_path(path) {
        let text = fs::read_to_string(&path)
            .map_err(|e| format!("aur-upstream-state-read-failed {path}: {e}"))?;
        let value: Value = serde_json::from_str(&text)
            .map_err(|e| format!("aur-upstream-state-parse-failed {path}: {e}"))?;
        let state_value = value
            .get("packages")
            .and_then(|packages| packages.get(package))
            .cloned()
            .unwrap_or(value);
        serde_json::from_value(state_value)
            .map_err(|e| format!("aur-upstream-state-package-invalid {package}: {e}"))?
    } else {
        observe_live_upstream_state(package)?
    };
    validate_upstream_state(state, package)
}

fn validate_upstream_state(
    state: AurUpstreamState,
    package: &str,
) -> Result<AurUpstreamState, String> {
    if state.schema != "harmonia.aur.upstream_state.v1" {
        return Err(format!(
            "aur-upstream-state-schema-unsupported-{}",
            state.schema
        ));
    }
    if state.package != package {
        return Err(format!(
            "aur-upstream-state-package-mismatch expected={package} actual={}",
            state.package
        ));
    }
    if !is_git_sha(&state.pkgbuild_sha) {
        return Err("aur-upstream-pkgbuild-sha-not-hex40".into());
    }
    Ok(state)
}

fn observe_live_upstream_state(package: &str) -> Result<AurUpstreamState, String> {
    let info_url = format!("{DEFAULT_AUR_BASE_URL}/rpc/v5/info/{package}");
    let info = command::capture_with_timeout("/usr/bin/curl", &["-fsSL", &info_url], 30);
    if !info.ok {
        return Err(format!(
            "aur-upstream-rpc-unreachable {package}: {}",
            first_blocker(&info)
        ));
    }
    let value: Value = serde_json::from_str(&info.stdout)
        .map_err(|e| format!("aur-upstream-rpc-parse-failed {package}: {e}"))?;
    let version = value
        .get("results")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("Version"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("aur-upstream-version-missing {package}"))?;
    let repo_url = format!("{DEFAULT_AUR_BASE_URL}/{package}.git");
    let head = command::capture_with_timeout("/usr/bin/git", &["ls-remote", &repo_url, "HEAD"], 30);
    if !head.ok {
        return Err(format!(
            "aur-upstream-git-unreachable {package}: {}",
            first_blocker(&head)
        ));
    }
    let sha = head
        .stdout
        .split_whitespace()
        .next()
        .ok_or_else(|| format!("aur-upstream-head-missing {package}"))?
        .to_string();
    Ok(AurUpstreamState {
        schema: "harmonia.aur.upstream_state.v1".into(),
        package: package.to_string(),
        available_version: version.to_string(),
        pkgbuild_sha: sha,
        observed_source: format!("aur-rpc+git:{info_url}"),
    })
}

pub(crate) fn check(
    receipt_dir: &Path,
    receipt_name: &str,
    package: &str,
    lock_path: &Path,
    upstream_state: Option<&str>,
) -> Result<OperationOutcome, String> {
    let observation = crate::atoms::ask::ratchet_aur::check(package, lock_path, upstream_state)?;
    let newer_available =
        observation.verdict == crate::atoms::ask::ratchet_aur::Verdict::UpstreamMovedPastPin;
    let receipt = AurCheckReceipt {
        schema: "harmonia.aur.check.v1",
        package: package.to_string(),
        pinned_version: observation.lock.pinned_version.clone(),
        pinned_pkgbuild_sha: observation.lock.pkgbuild_sha.clone(),
        available_version: Some(observation.upstream.available_version.clone()),
        available_pkgbuild_sha: Some(observation.upstream.pkgbuild_sha.clone()),
        upstream_source_observed: Some(observation.upstream.observed_source.clone()),
        newer_available,
        ok: true,
        changed: false,
        first_missing_signal: "none".into(),
    };
    let receipt_path = receipt_dir.join(format!("{receipt_name}.json"));
    write_json(
        &receipt_path,
        &serde_json::to_value(&receipt).map_err(|error| error.to_string())?,
    )?;
    augment_comparison_receipt(
        &receipt_path,
        serde_json::json!({
            "pinned_version": observation.lock.pinned_version,
            "pinned_pkgbuild_sha": observation.lock.pkgbuild_sha,
            "available_version": observation.upstream.available_version,
            "available_pkgbuild_sha": observation.upstream.pkgbuild_sha,
            "upstream_source": observation.upstream.observed_source,
        }),
        serde_json::json!({"ratchet_lock_matches_upstream": !newer_available}),
        DiffDecision::Empty,
        None,
        false,
    )?;
    let outcome = OperationOutcome {
        ok: true,
        changed: false,
        skipped: false,
        message: format!("aur check {package}"),
        command: None,
    };
    crate::atoms::r#do::ratchet_aur::report(
        &receipt_dir.join(format!("{receipt_name}.attest.jsonl")),
        observation.verdict,
        &outcome,
    )?;
    Ok(outcome)
}

pub(crate) fn install(
    receipt_dir: &Path,
    receipt_name: &str,
    package: &str,
    timeout_secs: u64,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let timeout_secs = bounded_timeout(timeout_secs);
    let build_dir = Path::new(DEFAULT_BUILD_ROOT).join(package);
    let builder = if unsafe { libc::geteuid() } == 0 {
        "nobody"
    } else {
        "current-user"
    };
    let run = crate::atoms::r#do::ratchet_aur::install(
        receipt_dir,
        receipt_name,
        package,
        timeout_secs,
        apply,
        invocation,
    )?;
    let decision = run.decision();
    let observed = run.observation().clone();
    let movement = match &run {
        comparison::ComparisonRun::Current { .. } => None,
        comparison::ComparisonRun::Moved { movement, .. } => Some(movement),
    };
    let outcome = match movement {
        Some(movement) => movement.clone(),
        None => {
            let receipt = serde_json::json!({
                "schema": "harmonia.aur.install.v1", "package": package, "build_dir": build_dir,
                "timeout_policy": format!("bounded-timeout-seconds={timeout_secs}"),
                "safety_posture": "current-aur-head;no-pin;no-upstream-check-cycle;unprivileged-makepkg",
                "unprivileged_builder": builder, "ok": true, "changed": false,
                "installed_converged": true, "first_blocker": null,
            });
            write_json(&receipt_dir.join(format!("{receipt_name}.json")), &receipt)?;
            OperationOutcome {
                ok: true,
                changed: false,
                skipped: false,
                message: format!("aur install idle {package}"),
                command: None,
            }
        }
    };
    let receipt_path = receipt_dir.join(format!("{receipt_name}.json"));
    augment_comparison_receipt(
        &receipt_path,
        serde_json::json!({"installed_version": observed}),
        serde_json::json!({"package_installed": true}),
        decision,
        movement,
        outcome.changed,
    )?;
    Ok(outcome)
}

pub(crate) fn write_install_failure(
    receipt_dir: &Path,
    receipt_name: &str,
    package: &str,
    mut receipt: Value,
    command: CmdResult,
) -> Result<OperationOutcome, String> {
    receipt["first_blocker"] = Value::String(meaningful_stderr_tail(&command));
    write_json(&receipt_dir.join(format!("{receipt_name}.json")), &receipt)?;
    Ok(OperationOutcome {
        ok: false,
        changed: false,
        skipped: false,
        message: format!("aur install {package}"),
        command: Some(command),
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_pinned(
    receipt_dir: &Path,
    receipt_name: &str,
    package: &str,
    lock_path: &Path,
    build_root: &Path,
    source_dir: Option<&str>,
    builder_user: Option<&str>,
    timeout_secs: u64,
    install: bool,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let lock = read_lock(lock_path, package)?;
    let timeout_secs = bounded_timeout(timeout_secs);
    let build_dir = build_root.join(package);
    let builder = if unsafe { libc::geteuid() } == 0 {
        builder_user.unwrap_or("nobody").to_string()
    } else {
        "current-user".to_string()
    };
    let run = crate::atoms::r#do::ratchet_aur::build_pinned(
        receipt_dir,
        receipt_name,
        package,
        lock_path,
        build_root,
        source_dir,
        builder_user,
        timeout_secs,
        install,
        apply,
        invocation,
    )?;
    let decision = run.decision();
    let observed = run.observation().installed_version.clone();
    let movement = match &run {
        comparison::ComparisonRun::Current { .. } => None,
        comparison::ComparisonRun::Moved { movement, .. } => Some(movement),
    };
    let outcome = if let Some(movement) = movement {
        movement.clone()
    } else {
        let receipt = AurBuildReceipt {
            schema: "harmonia.aur.build_pinned.v1", package: package.to_string(),
            pinned_version: lock.pinned_version.clone(), pinned_pkgbuild_sha: lock.pkgbuild_sha.clone(),
            build_dir, produced_package_path: None, artifact_sha256: None, installed_version_before: observed.clone(),
            install_requested: install, installed_converged: true, first_blocker: None,
            pkgver_neutralized: false, timeout_policy: format!("bounded-timeout-seconds={timeout_secs}"),
            safety_posture: "bounded-timeout;no-curl-pipe-bash;no-partial-db-sync;exact-pkgbuild-sha;unprivileged-makepkg".into(),
            unprivileged_builder: builder, ok: true, changed: false, command: None,
            install_command: None, install_verify_command: None,
        };
        write_build_receipt(receipt_dir, receipt_name, &receipt)?;
        if install {
            write_json(
                &receipt_dir.join(format!("{receipt_name}.install.json")),
                &serde_json::json!({
                    "schema": "harmonia.aur.install_pinned.v1", "package": package,
                    "expected_version": lock.pinned_version, "ok": true, "changed": false,
                    "first_blocker": null, "build_proof": receipt_dir.join(format!("{receipt_name}.json")),
                    "installed_converged": true
                }),
            )?;
        }
        OperationOutcome {
            ok: true,
            changed: false,
            skipped: false,
            message: format!("aur build-pinned idle {package}"),
            command: None,
        }
    };
    augment_comparison_receipt(
        &receipt_dir.join(format!("{receipt_name}.json")),
        serde_json::json!({"installed_version": observed, "pinned_version": lock.pinned_version, "pinned_pkgbuild_sha": lock.pkgbuild_sha}),
        serde_json::json!({"pinned_package_built": true, "pinned_package_installed": install}),
        decision,
        movement,
        outcome.changed,
    )?;
    crate::atoms::r#do::ratchet_aur::report(
        &receipt_dir.join(format!("{receipt_name}.attest.jsonl")),
        run.observation().verdict,
        &outcome,
    )?;
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]

pub(crate) fn installed_version(package: &str) -> Option<String> {
    installed_version_from_result(&installed_version_command(package))
}

pub(crate) fn installed_version_command(package: &str) -> CmdResult {
    let pacman = crate::atoms::package::pacman_program();
    if !Path::new(&pacman).exists() {
        return CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: format!("pacman-not-found {pacman}"),
        };
    }
    command::capture(&pacman, &["-Q", package])
}

pub(crate) fn installed_version_from_result(result: &CmdResult) -> Option<String> {
    if !result.ok {
        return None;
    }
    let mut fields = result.stdout.split_whitespace();
    let _name = fields.next()?;
    fields.next().map(ToString::to_string)
}

pub(crate) fn install_built_package(path: &Path, timeout_secs: u64) -> CmdResult {
    let pacman = crate::atoms::package::pacman_program();
    let path = path.to_string_lossy().to_string();
    command::capture_with_timeout(&pacman, &["-U", "--noconfirm", &path], timeout_secs)
}

pub(crate) fn bounded_timeout(timeout_secs: u64) -> u64 {
    match timeout_secs {
        1..=14400 => timeout_secs,
        _ => DEFAULT_TIMEOUT_SECS,
    }
}

pub(crate) fn prepare_and_build(
    lock: &AurRatchetLock,
    package: &str,
    build_dir: &Path,
    source_dir: Option<&str>,
    builder: &str,
    timeout_secs: u64,
) -> Result<(CmdResult, Option<PathBuf>, bool), String> {
    if build_dir.exists() {
        fs::remove_dir_all(build_dir).map_err(|e| format!("aur-build-dir-clean-failed: {e}"))?;
    }
    fs::create_dir_all(build_dir.parent().unwrap_or_else(|| Path::new(".")))
        .map_err(|e| format!("aur-build-root-create-failed: {e}"))?;
    if let Some(source) = source_dir {
        copy_dir(Path::new(source), build_dir)?;
    } else {
        let url = lock
            .aur_url
            .clone()
            .unwrap_or_else(|| format!("{DEFAULT_AUR_BASE_URL}/{package}.git"));
        let target = build_dir.to_string_lossy().to_string();
        let clone =
            command::capture_with_timeout("/usr/bin/git", &["clone", &url, &target], timeout_secs);
        if !clone.ok {
            return Ok((clone, None, false));
        }
    }
    let head =
        command::capture_with_cwd("/usr/bin/git", &["rev-parse", "HEAD"], build_dir.to_str());
    if !head.ok {
        return Ok((head, None, false));
    }
    let checkout = command::capture_with_cwd_and_timeout(
        "/usr/bin/git",
        &["checkout", &lock.pkgbuild_sha],
        build_dir.to_str(),
        timeout_secs,
    );
    if !checkout.ok {
        return Ok((checkout, None, false));
    }
    let verified =
        command::capture_with_cwd("/usr/bin/git", &["rev-parse", "HEAD"], build_dir.to_str());
    if !verified.ok || verified.stdout.trim() != lock.pkgbuild_sha {
        return Err(format!(
            "aur-pkgbuild-sha-mismatch expected={} actual={}",
            lock.pkgbuild_sha,
            verified.stdout.trim()
        ));
    }
    prepare_build_dir_for_builder(build_dir, builder)?;
    let pkgver_neutralized = neutralize_pkgver_function(build_dir, builder, timeout_secs)?;
    let makepkg = makepkg_command(builder, timeout_secs, build_dir)?;
    let produced = if makepkg.ok {
        pinned_pkg_tar(build_dir, package, &lock.pinned_version)?
    } else {
        None
    };
    Ok((makepkg, produced, pkgver_neutralized))
}

pub(crate) fn prepare_current_build(
    package: &str,
    build_dir: &Path,
    builder: &str,
    timeout_secs: u64,
) -> Result<(CmdResult, Option<PathBuf>), String> {
    if build_dir.exists() {
        fs::remove_dir_all(build_dir).map_err(|e| format!("aur-build-dir-clean-failed: {e}"))?;
    }
    fs::create_dir_all(build_dir.parent().unwrap_or_else(|| Path::new(".")))
        .map_err(|e| format!("aur-build-root-create-failed: {e}"))?;
    let target = build_dir.to_string_lossy().to_string();
    let url = format!("{DEFAULT_AUR_BASE_URL}/{package}.git");
    let clone =
        command::capture_with_timeout("/usr/bin/git", &["clone", &url, &target], timeout_secs);
    if !clone.ok {
        return Ok((clone, None));
    }
    prepare_build_dir_for_builder(build_dir, builder)?;
    let makepkg = makepkg_command(builder, timeout_secs, build_dir)?;
    let produced = if makepkg.ok {
        current_pkg_tar(build_dir, package)?
    } else {
        None
    };
    Ok((makepkg, produced))
}

pub(crate) fn neutralize_pkgver_function(
    build_dir: &Path,
    builder: &str,
    timeout_secs: u64,
) -> Result<bool, String> {
    let pkgbuild = build_dir.join("PKGBUILD");
    let before = fs::read_to_string(&pkgbuild)
        .map_err(|e| format!("aur-pkgbuild-read-failed {}: {e}", pkgbuild.display()))?;
    let (after, changed) = neutralize_pkgver_function_text(&before)?;
    if !changed {
        return Ok(false);
    }
    fs::write(&pkgbuild, after)
        .map_err(|e| format!("aur-pkgver-neutralize-failed {}: {e}", pkgbuild.display()))?;
    if unsafe { libc::geteuid() } == 0 && builder != "current-user" {
        let verify = command::capture_with_options(
            "/usr/bin/runuser",
            &["-u", builder, "--", "/usr/bin/test", "-w", "PKGBUILD"],
            command::CaptureOptions::new()
                .cwd(build_dir.to_str())
                .timeout_secs(timeout_secs),
        );
        if !verify.ok {
            return Err(format!(
                "aur-pkgver-neutralize-builder-write-check-failed {}",
                first_blocker(&verify)
            ));
        }
    }
    Ok(true)
}

pub(crate) fn neutralize_pkgver_function_text(text: &str) -> Result<(String, bool), String> {
    let mut out = Vec::new();
    let mut lines = text.lines();
    let mut changed = false;
    while let Some(line) = lines.next() {
        if line.trim_start().starts_with("pkgver()") {
            changed = true;
            if !line.contains('{') {
                return Err("aur-pkgver-function-unsupported-shape".into());
            }
            if line[line.find('{').unwrap() + 1..].contains('}') {
                continue;
            }
            let mut closed = false;
            for inner in lines.by_ref() {
                if inner.trim_start().starts_with('}') {
                    closed = true;
                    break;
                }
            }
            if !closed {
                return Err("aur-pkgver-function-unclosed".into());
            }
        } else {
            out.push(line);
        }
    }
    let mut rendered = out.join("\n");
    if text.ends_with('\n') || changed {
        rendered.push('\n');
    }
    Ok((rendered, changed))
}

pub(crate) fn makepkg_command(
    builder: &str,
    timeout_secs: u64,
    cwd: &Path,
) -> Result<CmdResult, String> {
    if unsafe { libc::geteuid() } == 0 {
        if builder.trim().is_empty() || builder == "root" || builder == "current-user" {
            return Err("aur-unprivileged-builder-required-when-root".into());
        }
        Ok(command::capture_with_options(
            "/usr/bin/runuser",
            &[
                "-u",
                builder,
                "--",
                "/usr/bin/makepkg",
                "--cleanbuild",
                "--force",
                "--noconfirm",
            ],
            command::CaptureOptions::new()
                .cwd(cwd.to_str())
                .timeout_secs(timeout_secs),
        ))
    } else {
        let makepkg =
            env::var("HARMONIA_MAKEPKG_PATH").unwrap_or_else(|_| "/usr/bin/makepkg".into());
        Ok(command::capture_with_cwd_and_timeout(
            &makepkg,
            &["--cleanbuild", "--force", "--noconfirm"],
            cwd.to_str(),
            timeout_secs,
        ))
    }
}

pub(crate) fn pinned_pkg_tar(
    build_dir: &Path,
    package: &str,
    pinned_version: &str,
) -> Result<Option<PathBuf>, String> {
    let mut packages = Vec::new();
    let expected_prefix = format!("{package}-{pinned_version}-");
    let debug_prefix = format!("{package}-debug-");
    for entry in fs::read_dir(build_dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("");
        if name.starts_with(&expected_prefix)
            && !name.starts_with(&debug_prefix)
            && name.contains(".pkg.tar")
        {
            packages.push(path);
        }
    }
    packages.sort();
    match packages.len() {
        0 => Ok(None),
        1 => Ok(packages.pop()),
        _ => Err(format!(
            "aur-produced-package-ambiguous package={package} version={pinned_version}"
        )),
    }
}

pub(crate) fn current_pkg_tar(build_dir: &Path, package: &str) -> Result<Option<PathBuf>, String> {
    let mut packages = Vec::new();
    let expected_prefix = format!("{package}-");
    let debug_prefix = format!("{package}-debug-");
    for entry in fs::read_dir(build_dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("");
        if name.starts_with(&expected_prefix)
            && !name.starts_with(&debug_prefix)
            && name.contains(".pkg.tar")
        {
            packages.push(path);
        }
    }
    packages.sort();
    match packages.len() {
        0 => Ok(None),
        1 => Ok(packages.pop()),
        _ => Err(format!("aur-produced-package-ambiguous package={package}")),
    }
}

pub(crate) fn prepare_build_dir_for_builder(build_dir: &Path, builder: &str) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 || builder == "current-user" {
        return Ok(());
    }
    let c_user = CString::new(builder).map_err(|_| "aur-builder-user-invalid".to_string())?;
    let passwd = unsafe { libc::getpwnam(c_user.as_ptr()) };
    if passwd.is_null() {
        return Err(format!("aur-builder-user-missing-{builder}"));
    }
    let uid = unsafe { (*passwd).pw_uid };
    let gid = unsafe { (*passwd).pw_gid };
    chown_recursive(build_dir, uid, gid)
}

#[cfg(unix)]
pub(crate) fn chown_recursive(
    path: &Path,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("aur-build-dir-chown-path-invalid {}", path.display()))?;
    if unsafe { libc::chown(c_path.as_ptr(), uid, gid) } != 0 {
        return Err(format!("aur-build-dir-chown-failed {}", path.display()));
    }
    if path.is_dir() {
        for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            chown_recursive(&entry.path(), uid, gid)?;
        }
    }
    Ok(())
}

pub(crate) fn copy_dir(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| e.to_string())?;
    for entry in fs::read_dir(src).map_err(|e| format!("aur-source-dir-read-failed: {e}"))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let ty = entry.file_type().map_err(|e| e.to_string())?;
        let target = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else if ty.is_file() {
            fs::copy(entry.path(), target).map_err(|e| format!("aur-source-copy-failed: {e}"))?;
        }
    }
    Ok(())
}

pub(crate) fn meaningful_stderr_tail(command: &CmdResult) -> String {
    let mut tail: Vec<&str> = command
        .stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !is_curl_progress_line(line))
        .rev()
        .take(3)
        .collect();
    tail.reverse();
    if !tail.is_empty() {
        return tail.join(" | ");
    }
    if let Some(line) = command
        .stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
    {
        return line.to_string();
    }
    format!("aur-command-exit-{}", command.code)
}

fn is_curl_progress_line(line: &str) -> bool {
    line.starts_with("% Total")
        || (line.contains("Dload") && line.contains("Upload") && line.contains("Speed"))
        || line.split_whitespace().all(|field| {
            field
                .chars()
                .all(|ch| ch.is_ascii_digit() || matches!(ch, '.' | '%' | '-' | ':'))
        })
}

pub(crate) fn first_blocker(command: &CmdResult) -> String {
    if !command.stderr.trim().is_empty() {
        command
            .stderr
            .trim()
            .lines()
            .next()
            .unwrap_or("aur-build-failed")
            .to_string()
    } else if !command.stdout.trim().is_empty() {
        command
            .stdout
            .trim()
            .lines()
            .next()
            .unwrap_or("aur-build-failed")
            .to_string()
    } else {
        format!("aur-command-exit-{}", command.code)
    }
}

fn augment_comparison_receipt(
    path: &Path,
    observed_state: Value,
    desired_state: Value,
    decision: DiffDecision,
    movement: Option<&OperationOutcome>,
    changed: bool,
) -> Result<(), String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("aur-receipt-read-failed {}: {e}", path.display()))?;
    let mut receipt: Value = serde_json::from_str(&text)
        .map_err(|e| format!("aur-receipt-parse-failed {}: {e}", path.display()))?;
    let fields = receipt
        .as_object_mut()
        .ok_or_else(|| format!("aur-receipt-object-required {}", path.display()))?;
    fields.insert("observed_state".into(), observed_state);
    fields.insert("desired_state".into(), desired_state);
    fields.insert(
        "diff_decision".into(),
        Value::String(
            match decision {
                DiffDecision::Empty => "empty",
                DiffDecision::Different => "different",
            }
            .into(),
        ),
    );
    fields.insert(
        "movement".into(),
        movement
            .map(|movement| {
                serde_json::json!({
                    "ok": movement.ok,
                    "changed": movement.changed,
                    "skipped": movement.skipped,
                    "message": movement.message,
                    "command": movement.command,
                })
            })
            .unwrap_or(Value::Null),
    );
    fields.insert("changed".into(), Value::Bool(changed));
    write_json(path, &receipt)
}

pub(crate) fn write_build_receipt(
    receipt_dir: &Path,
    receipt_name: &str,
    receipt: &AurBuildReceipt,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{receipt_name}.json")),
        &serde_json::to_value(receipt).map_err(|e| e.to_string())?,
    )
}

pub(crate) fn validate_ladder_args(
    permutation: &str,
    args: &std::collections::BTreeMap<String, Value>,
) -> Result<(), String> {
    let package = args
        .get("package")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if package.is_empty() {
        return Err("aur-package-empty".into());
    }
    if permutation == "check" || permutation == "build-pinned" {
        let lock = args
            .get("lock")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if lock.is_empty() {
            return Err("aur-lock-empty".into());
        }
    }
    if permutation == "build-pinned" {
        let build_root = args
            .get("build_root")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if build_root.is_empty() {
            return Err("aur-build-root-empty".into());
        }
        if let Some(timeout) = args.get("timeout_secs").and_then(Value::as_u64) {
            if timeout == 0 || timeout > 14400 {
                return Err("aur-timeout-out-of-bounds".into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ladder::{load_ladder_manifest, validate_ladder};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("harmonia-aur-{name}-{stamp}"))
    }

    fn sample_sha() -> String {
        "0123456789abcdef0123456789abcdef01234567".to_string()
    }

    #[test]
    fn install_failure_receipt_keeps_meaningful_makepkg_stderr_tail() {
        let root = temp_root("install-meaningful-blocker");
        fs::create_dir_all(&root).unwrap();
        let command = CmdResult {
            ok: false,
            code: 1,
            stdout: String::new(),
            stderr: concat!(
                "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n",
                "                                 Dload  Upload   Total   Spent    Left  Speed\n",
                "  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0\n",
                "curl: (22) The requested URL returned error: 404\n",
                "==> ERROR: Failure while downloading https://example.invalid/oh-my-posh.tar.gz\n"
            )
            .into(),
        };
        let outcome = write_install_failure(
            &root,
            "aur-install",
            "oh-my-posh",
            serde_json::json!({
                "schema": "harmonia.aur.install.v1",
                "first_blocker": null
            }),
            command,
        )
        .unwrap();
        assert!(!outcome.ok);
        let receipt: Value =
            serde_json::from_str(&fs::read_to_string(root.join("aur-install.json")).unwrap())
                .unwrap();
        let blocker = receipt["first_blocker"].as_str().unwrap();
        assert!(blocker.contains("curl: (22)"));
        assert!(blocker.contains("==> ERROR: Failure while downloading"));
        assert!(!blocker.contains("% Total"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn check_compares_pin_to_injected_upstream_without_mutation() {
        let root = temp_root("check");
        fs::create_dir_all(&root).unwrap();
        let lock = root.join("lock.json");
        let upstream = root.join("upstream.json");
        fs::write(
            &lock,
            serde_json::json!({
                "schema": "harmonia.aur.ratchet_lock.v1",
                "package": "oh-my-posh-bin",
                "pinned_version": "1.0.0",
                "pkgbuild_sha": sample_sha()
            })
            .to_string(),
        )
        .unwrap();
        fs::write(
            &upstream,
            serde_json::json!({
                "schema": "harmonia.aur.upstream_state.v1",
                "package": "oh-my-posh-bin",
                "available_version": "1.1.0",
                "pkgbuild_sha": "fedcba9876543210fedcba9876543210fedcba98",
                "observed_source": "test-seam"
            })
            .to_string(),
        )
        .unwrap();
        let receipt_dir = root.join("receipts");
        let out = check(
            &receipt_dir,
            "aur-check",
            "oh-my-posh-bin",
            &lock,
            Some(upstream.to_str().unwrap()),
        )
        .unwrap();
        assert!(out.ok);
        assert!(!out.changed);
        let receipt: Value =
            serde_json::from_str(&fs::read_to_string(receipt_dir.join("aur-check.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["schema"], "harmonia.aur.check.v1");
        assert_eq!(receipt["newer_available"], true);
        assert_eq!(receipt["upstream_source_observed"], "test-seam");
        let lock_after = fs::read_to_string(&lock).unwrap();
        assert!(lock_after.contains("1.0.0"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn validate_ladder_rejects_build_without_build_root() {
        let root = temp_root("manifest");
        let module = root.join("module");
        fs::create_dir_all(&module).unwrap();
        fs::write(
            module.join("manifest.json"),
            serde_json::json!({
                "schema": "harmonia.module.ladder.v1",
                "id": "bad-aur",
                "version": "1.0.0",
                "description": "bad aur manifest",
                "constants": {},
                "ladder": [{
                    "step_id": "aur-build",
                    "tool": "aur",
                    "permutation": "build-pinned",
                    "args": {"package": "oh-my-posh-bin", "lock": "lock.json"},
                    "on_failure": "stop"
                }]
            })
            .to_string(),
        )
        .unwrap();
        let manifest = load_ladder_manifest(&module.join("manifest.json")).unwrap();
        let err = validate_ladder(&manifest).unwrap_err();
        assert_eq!(err.defect, "missing-argument-build_root");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn build_pinned_rejects_source_commit_mismatch_before_makepkg() {
        let root = temp_root("build-mismatch");
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        command::capture_with_cwd("/usr/bin/git", &["init", "-b", "main"], source.to_str());
        command::capture_with_cwd(
            "/usr/bin/git",
            &["config", "user.email", "harmonia@example.invalid"],
            source.to_str(),
        );
        command::capture_with_cwd(
            "/usr/bin/git",
            &["config", "user.name", "Harmonia Test"],
            source.to_str(),
        );
        fs::write(
            source.join("PKGBUILD"),
            "pkgname=oh-my-posh-bin\npkgver=1.0.0\n",
        )
        .unwrap();
        command::capture_with_cwd("/usr/bin/git", &["add", "PKGBUILD"], source.to_str());
        command::capture_with_cwd("/usr/bin/git", &["commit", "-m", "seed"], source.to_str());
        let lock = root.join("lock.json");
        fs::write(
            &lock,
            serde_json::json!({
                "schema": "harmonia.aur.ratchet_lock.v1",
                "package": "oh-my-posh-bin",
                "pinned_version": "1.0.0",
                "pkgbuild_sha": sample_sha()
            })
            .to_string(),
        )
        .unwrap();
        let receipt_dir = root.join("receipts");
        let out = build_pinned(
            &receipt_dir,
            "aur-build",
            "oh-my-posh-bin",
            &lock,
            &root.join("build"),
            Some(source.to_str().unwrap()),
            Some("aur-builder"),
            30,
            false,
            true,
        )
        .unwrap();
        assert!(!out.ok);
        let receipt: Value =
            serde_json::from_str(&fs::read_to_string(receipt_dir.join("aur-build.json")).unwrap())
                .unwrap();
        assert!(receipt["first_blocker"]
            .as_str()
            .unwrap()
            .contains("unable to read tree"));
        assert_eq!(receipt["produced_package_path"], Value::Null);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn build_pinned_install_is_truthful_idle_noop_when_installed_pin_matches() {
        let root = temp_root("idle-install");
        fs::create_dir_all(&root).unwrap();
        let fake_pacman = root.join("fake-pacman");
        fs::write(
            &fake_pacman,
            "#!/usr/bin/env sh\nif [ \"$1\" = \"-Q\" ] && [ \"$2\" = \"oh-my-posh-bin\" ]; then echo 'oh-my-posh-bin 29.20.1-1'; exit 0; fi\necho unexpected pacman call >&2\nexit 2\n",
        )
        .unwrap();
        #[cfg(unix)]
        fs::set_permissions(&fake_pacman, fs::Permissions::from_mode(0o755)).unwrap();
        crate::atoms::package::set_test_pacman_path(Some(fake_pacman.display().to_string()));
        let lock = root.join("lock.json");
        fs::write(
            &lock,
            serde_json::json!({
                "schema": "harmonia.aur.ratchet_lock.v1",
                "package": "oh-my-posh-bin",
                "pinned_version": "29.20.1-1",
                "pkgbuild_sha": "ed800be1c781d41ce83ce6e693d6e00e868883c9"
            })
            .to_string(),
        )
        .unwrap();
        let receipt_dir = root.join("receipts");
        let out = build_pinned(
            &receipt_dir,
            "aur-build",
            "oh-my-posh-bin",
            &lock,
            &root.join("build"),
            None,
            Some("aur-builder"),
            30,
            true,
            true,
        )
        .unwrap();
        crate::atoms::package::set_test_pacman_path(None);
        assert!(out.ok);
        assert!(!out.changed);
        assert!(!root.join("build/oh-my-posh-bin").exists());
        let receipt: Value =
            serde_json::from_str(&fs::read_to_string(receipt_dir.join("aur-build.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["installed_version_before"], "29.20.1-1");
        assert_eq!(receipt["installed_converged"], true);
        assert_eq!(receipt["changed"], false);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn build_pinned_plans_with_unprivileged_safety_receipt() {
        let root = temp_root("build-plan");
        fs::create_dir_all(&root).unwrap();
        let lock = root.join("lock.json");
        fs::write(
            &lock,
            serde_json::json!({
                "schema": "harmonia.aur.ratchet_lock.v1",
                "package": "oh-my-posh-bin",
                "pinned_version": "1.0.0",
                "pkgbuild_sha": sample_sha()
            })
            .to_string(),
        )
        .unwrap();
        let receipt_dir = root.join("receipts");
        let out = build_pinned(
            &receipt_dir,
            "aur-build",
            "oh-my-posh-bin",
            &lock,
            &root.join("build"),
            None,
            Some("aur-builder"),
            30,
            false,
            false,
        )
        .unwrap();
        assert!(out.ok);
        assert!(out.skipped);
        let receipt: Value =
            serde_json::from_str(&fs::read_to_string(receipt_dir.join("aur-build.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["schema"], "harmonia.aur.build_pinned.v1");
        assert!(receipt["safety_posture"]
            .as_str()
            .unwrap()
            .contains("unprivileged-makepkg"));
        assert!(receipt["timeout_policy"]
            .as_str()
            .unwrap()
            .contains("bounded-timeout"));
        let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn build_pinned_neutralizes_pkgver_function_before_exact_package_selection() {
        let root = temp_root("pkgver-neutralize");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("PKGBUILD"),
            "pkgname=oh-my-posh-bin\npkgver=29.20.1\npkgrel=1\npkgver() {\n  curl -fsSL https://github.com/JanDeDobbeleer/oh-my-posh/releases/latest\n}\nsource=(fixture)\n",
        )
        .unwrap();
        let changed = neutralize_pkgver_function(&root, "current-user", 30).unwrap();
        assert!(changed);
        let pkgbuild = fs::read_to_string(root.join("PKGBUILD")).unwrap();
        assert!(pkgbuild.contains("pkgver=29.20.1"));
        assert!(pkgbuild.contains("pkgrel=1"));
        assert!(!pkgbuild.contains("pkgver()"));
        assert!(!pkgbuild.contains("curl -fsSL"));
        let main = root.join("oh-my-posh-bin-29.20.1-1-x86_64.pkg.tar.zst");
        fs::write(&main, "main").unwrap();
        let selected = pinned_pkg_tar(&root, "oh-my-posh-bin", "29.20.1-1")
            .unwrap()
            .unwrap();
        assert_eq!(selected, main);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn pinned_pkg_tar_selects_exact_package_and_excludes_debug_split() {
        let root = temp_root("pkg-select");
        fs::create_dir_all(&root).unwrap();
        let main = root.join("oh-my-posh-bin-29.20.1-1-x86_64.pkg.tar.zst");
        let debug = root.join("oh-my-posh-bin-debug-29.20.1-1-x86_64.pkg.tar.zst");
        fs::write(&main, "main").unwrap();
        fs::write(&debug, "debug").unwrap();
        let selected = pinned_pkg_tar(&root, "oh-my-posh-bin", "29.20.1-1")
            .unwrap()
            .unwrap();
        assert_eq!(
            selected.file_name().and_then(|v| v.to_str()),
            main.file_name().and_then(|v| v.to_str())
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn pinned_pkg_tar_does_not_select_debug_when_main_missing() {
        let root = temp_root("pkg-select-debug-only");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("oh-my-posh-bin-debug-29.20.1-1-x86_64.pkg.tar.zst"),
            "debug",
        )
        .unwrap();
        assert!(pinned_pkg_tar(&root, "oh-my-posh-bin", "29.20.1-1")
            .unwrap()
            .is_none());
        let _ = fs::remove_dir_all(root);
    }
}
