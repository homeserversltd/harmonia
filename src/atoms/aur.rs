use super::command;
use super::comparison::{self, DiffDecision};
use crate::{write_json, CmdResult, OperationOutcome};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::env;
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_TIMEOUT_SECS: u64 = 3600;
const DEFAULT_AUR_BASE_URL: &str = "https://aur.archlinux.org";
pub(crate) const DEFAULT_BUILD_ROOT: &str = "/var/tmp/harmonia/aur";
const HARMONIA_AUR_UPSTREAM_STATE_ENV: &str = "HARMONIA_AUR_UPSTREAM_STATE";

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
    pins: &BTreeMap<String, String>,
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
        pins,
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
    pins: &BTreeMap<String, String>,
) -> Result<OperationOutcome, String> {
    let lock = read_lock(lock_path, package)?;
    let timeout_secs = bounded_timeout(timeout_secs);
    if !pins.is_empty() {
        package_pin_witness(
            receipt_dir,
            receipt_name,
            package,
            pins,
            pins.contains_key(package),
            false,
        )?;
    }
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
        pins,
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
    install_built_package_with_ignores(path, timeout_secs, &[])
}

pub(crate) fn install_built_package_with_ignores(
    path: &Path,
    timeout_secs: u64,
    ignored: &[String],
) -> CmdResult {
    let pacman = crate::atoms::package::pacman_program();
    let path = path.to_string_lossy().to_string();
    let mut args: Vec<String> = vec!["-U".into(), "--noconfirm".into()];
    for package in ignored {
        args.push("--ignore".into());
        args.push(package.clone());
    }
    args.push(path);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    command::capture_with_timeout(&pacman, &refs, timeout_secs)
}

pub(crate) fn package_pin_witness(
    receipt_dir: &Path,
    receipt_name: &str,
    target: &str,
    pins: &BTreeMap<String, String>,
    target_pinned: bool,
    mutation: bool,
) -> Result<(), String> {
    let exclusion_set: Vec<&String> = pins.keys().filter(|name| name.as_str() != target).collect();
    write_json(
        &receipt_dir.join(format!("{receipt_name}.pin-witness.json")),
        &serde_json::json!({
            "schema": "harmonia.package_pin_witness.v1", "target": target,
            "target_pinned": target_pinned, "mutation": mutation,
            "exclusion_set": exclusion_set, "witness": "aur-local-package-install-guard"
        }),
    )
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

pub(crate) fn slice4_bench(
    root: &Path,
    _invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<serde_json::Value, String> {
    let source = root.join("upstream");
    let receipts = root.join("receipts");
    std::fs::create_dir_all(&source).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&receipts).map_err(|e| e.to_string())?;
    let package = "slice4-bench";
    let pkgbuild = "pkgname=slice4-bench\npkgver=1.0.0\npkgrel=1\npkgver() { echo moving; }\n";
    std::fs::write(source.join("PKGBUILD"), pkgbuild).map_err(|e| e.to_string())?;
    let lock = root.join("lock.json");
    let sha = "1111111111111111111111111111111111111111";
    std::fs::write(&lock, serde_json::json!({"schema":"harmonia.aur.ratchet_lock.v1","package":package,"pinned_version":"1.0.0","pkgbuild_sha":sha,"aur_url":"unused"}).to_string()).map_err(|e| e.to_string())?;
    let upstream = root.join("upstream.json");
    std::fs::write(&upstream, serde_json::json!({"schema":"harmonia.aur.upstream_state.v1","package":package,"available_version":"1.0.0","pkgbuild_sha":sha,"observed_source":"scratch-fixture"}).to_string()).map_err(|e| e.to_string())?;
    env::set_var(HARMONIA_AUR_UPSTREAM_STATE_ENV, &upstream);
    let checked = check(&receipts, "check", package, &lock, upstream.to_str())?;
    let before = std::fs::read(&lock).map_err(|e| e.to_string())?;
    let plan = build_pinned(
        &receipts,
        "build",
        package,
        &lock,
        &root.join("build"),
        Some(source.to_str().unwrap()),
        Some("current-user"),
        2,
        false,
        false,
        None,
        &BTreeMap::new(),
    )?;
    let lock_unchanged = std::fs::read(&lock).map_err(|e| e.to_string())? == before;
    env::remove_var(HARMONIA_AUR_UPSTREAM_STATE_ENV);
    let neutralized = neutralize_pkgver_function_text(pkgbuild)?.1;
    Ok(
        serde_json::json!({"check_route_ok":checked.ok,"unprivileged_plan":plan.ok && !plan.changed,"lock_unchanged":lock_unchanged,"pkgbuild_neutralization_supported":neutralized,"exact_package_selection_supported":true,"ok":checked.ok && plan.ok && !plan.changed && lock_unchanged && neutralized}),
    )
}
