use crate::OperationOutcome;
use crate::atoms::aur::{augment_comparison_receipt, first_blocker, read_lock, write_build_receipt, AurBuildReceipt, AurCheckReceipt, AurRatchetLock, DEFAULT_AUR_BASE_URL};
use crate::atoms::r#do::install_aur::{bounded_timeout, package_pin_witness};
use crate::atoms::comparison::{self, DiffDecision};
use std::collections::BTreeMap;
use crate::atoms::command;
use std::env;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::fs;
use crate::CmdResult;
use crate::atoms::attest::build_aur_pinned::write_pinned_artifacts_receipt as write_build_receipt_json;
use std::path::{Path, PathBuf};
pub(crate) mod aur_ops;
pub(crate) fn check(
    receipt_dir: &Path, receipt_name: &str, package: &str, lock_path: &Path, upstream_state: Option<&str>,
) -> Result<OperationOutcome, String> {
    let observation = crate::atoms::ask::build_aur_pinned::check(package, lock_path, upstream_state)?;
    let newer_available = observation.verdict == crate::atoms::ask::build_aur_pinned::Verdict::UpstreamMovedPastPin;
    let receipt = AurCheckReceipt { schema: "harmonia.aur.check.v1", package: package.to_string(), pinned_version: observation.lock.pinned_version.clone(), pinned_pkgbuild_sha: observation.lock.pkgbuild_sha.clone(), available_version: Some(observation.upstream.available_version.clone()), available_pkgbuild_sha: Some(observation.upstream.pkgbuild_sha.clone()), upstream_source_observed: Some(observation.upstream.observed_source.clone()), newer_available, ok: true, changed: false, first_missing_signal: "none".into() };
    let receipt_path = receipt_dir.join(format!("{receipt_name}.json"));
    write_build_receipt_json(&receipt_path, &serde_json::to_value(&receipt).map_err(|e| e.to_string())?)?;
    augment_comparison_receipt(&receipt_path, serde_json::json!({"pinned_version": observation.lock.pinned_version, "pinned_pkgbuild_sha": observation.lock.pkgbuild_sha, "available_version": observation.upstream.available_version, "available_pkgbuild_sha": observation.upstream.pkgbuild_sha, "upstream_source": observation.upstream.observed_source}), serde_json::json!({"ratchet_lock_matches_upstream": !newer_available}), DiffDecision::Empty, None, false)?;
    let outcome=OperationOutcome { ok:true, changed:false, skipped:false, message:format!("aur check {package}"), command:None };
    crate::atoms::attest::build_aur_pinned::report(&receipt_dir.join(format!("{receipt_name}.attest.jsonl")), observation.verdict.as_str(), outcome.ok, outcome.message.clone())?;
    Ok(outcome)
}

pub(crate) fn aur_build_pinned_action(
    receipt_dir: &Path,
    receipt_name: &str,
    package: &str,
    lock_path: &Path,
    build_root: &Path,
    source_dir: Option<&str>,
    builder_user: Option<&str>,
    timeout_secs: u64,
    _install: bool,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let lock = read_lock(lock_path, package)?;
    let timeout_secs = bounded_timeout(timeout_secs);
    let build_dir = build_root.join(package);
    let safety_posture = "bounded-timeout;no-curl-pipe-bash;no-partial-db-sync;exact-pkgbuild-sha;unprivileged-makepkg";
    let unprivileged_builder = if unsafe { libc::geteuid() } == 0 {
        builder_user.unwrap_or("nobody").to_string()
    } else {
        "current-user".to_string()
    };
    let mut receipt = AurBuildReceipt {
        schema: "harmonia.aur.build_pinned.v1",
        package: package.to_string(),
        pinned_version: lock.pinned_version.clone(),
        pinned_pkgbuild_sha: lock.pkgbuild_sha.clone(),
        build_dir: build_dir.clone(),
        produced_package_path: None,
        artifact_sha256: None,
        installed_version_before: None,
        install_requested: false,
        installed_converged: false,
        first_blocker: None,
        pkgver_neutralized: false,
        timeout_policy: format!("bounded-timeout-seconds={timeout_secs}"),
        safety_posture: safety_posture.into(),
        unprivileged_builder: unprivileged_builder.clone(),
        ok: false,
        changed: false,
        command: None,
        install_command: None,
        install_verify_command: None,
    };

    if !apply {
        receipt.ok = true;
        receipt.first_blocker = Some("planned-only".into());
        write_build_receipt(receipt_dir, receipt_name, &receipt)?;
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: format!("aur build-pinned planned {package}"),
            command: None,
        });
    }

    let result = prepare_and_build(
        &lock,
        package,
        &build_dir,
        source_dir,
        &unprivileged_builder,
        timeout_secs,
    );
    match result {
        Ok((command, package_path, pkgver_neutralized)) => {
            receipt.pkgver_neutralized = pkgver_neutralized;
            receipt.ok = command.ok;
            receipt.changed = command.ok;
            receipt.command = Some(command.clone());
            if command.ok {
                receipt.produced_package_path = package_path.clone();
                receipt.artifact_sha256 = package_path
                    .as_ref()
                    .and_then(|path| std::fs::read(path).ok())
                    .map(|bytes| crate::atoms::file_sha256(&bytes));
            } else {
                receipt.first_blocker = Some(first_blocker(&command));
            }
        }
        Err(err) => {
            receipt.first_blocker = Some(err);
        }
    }
    write_build_receipt(receipt_dir, receipt_name, &receipt)?;
    Ok(OperationOutcome {
        ok: receipt.ok,
        changed: receipt.changed,
        skipped: false,
        message: format!("aur build-pinned {package}"),
        command: receipt.command,
    })
}
use crate::atoms::r#do::InvocationKey;
use crate::atoms::comparison::ActionAuthorization;
pub(crate) fn aur_build_pinned(_authorization: &ActionAuthorization, _invocation: &InvocationKey, callback: impl FnOnce() -> Result<crate::OperationOutcome, String>) -> Result<crate::OperationOutcome, String> { callback() }

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
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
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
    let run = aur_ops::build_pinned(
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
            write_build_receipt_json(
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
    crate::atoms::attest::build_aur_pinned::report(
        &receipt_dir.join(format!("{receipt_name}.attest.jsonl")),
        run.observation().verdict.as_str(),
        outcome.ok,
        outcome.message.clone(),
    )?;
    Ok(outcome)
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
