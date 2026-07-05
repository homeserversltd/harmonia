use super::{command, ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::{write_json, CmdResult, OperationOutcome};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(test)]
use std::cell::RefCell;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub const NAME: &str = "aur";
pub const DESCRIPTION: &str =
    "AUR ratchet primitive for pinned-state check and exact pinned build receipts.";
pub const PERMUTATIONS: &[ToolPermutation] = &[
    ToolPermutation::new(
        "check",
        "compare a ratchet lock pin against observed AUR upstream state without mutation",
        &[
            ToolArg::required("package", ToolArgKind::String),
            ToolArg::required("lock", ToolArgKind::String),
            ToolArg::optional("upstream_state", ToolArgKind::String),
        ],
    ),
    ToolPermutation::new(
        "build-pinned",
        "build exactly the pinned AUR PKGBUILD git commit through an unprivileged builder",
        &[
            ToolArg::required("package", ToolArgKind::String),
            ToolArg::required("lock", ToolArgKind::String),
            ToolArg::required("build_root", ToolArgKind::String),
            ToolArg::optional("source_dir", ToolArgKind::String),
            ToolArg::optional("builder_user", ToolArgKind::String),
            ToolArg::optional("timeout_secs", ToolArgKind::Integer),
        ],
    ),
];
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION, PERMUTATIONS);

const DEFAULT_TIMEOUT_SECS: u64 = 3600;
const DEFAULT_AUR_BASE_URL: &str = "https://aur.archlinux.org";
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
    pub first_blocker: Option<String>,
    pub timeout_policy: String,
    pub safety_posture: String,
    pub unprivileged_builder: String,
    pub ok: bool,
    pub changed: bool,
    pub command: Option<CmdResult>,
}

fn read_lock(path: &Path, package: &str) -> Result<AurRatchetLock, String> {
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

fn is_git_sha(value: &str) -> bool {
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

fn read_upstream_state(path: Option<&str>, package: &str) -> Result<AurUpstreamState, String> {
    let Some(path) = upstream_state_path(path) else {
        return Err("aur-upstream-state-not-injected".into());
    };
    let text = fs::read_to_string(&path)
        .map_err(|e| format!("aur-upstream-state-read-failed {path}: {e}"))?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|e| format!("aur-upstream-state-parse-failed {path}: {e}"))?;
    let state_value = value
        .get("packages")
        .and_then(|packages| packages.get(package))
        .cloned()
        .unwrap_or(value);
    let state: AurUpstreamState = serde_json::from_value(state_value)
        .map_err(|e| format!("aur-upstream-state-package-invalid {package}: {e}"))?;
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

pub(crate) fn check(
    receipt_dir: &Path,
    receipt_name: &str,
    package: &str,
    lock_path: &Path,
    upstream_state: Option<&str>,
) -> Result<OperationOutcome, String> {
    let lock = read_lock(lock_path, package)?;
    let state = read_upstream_state(upstream_state, package)?;
    let newer_available = state.pkgbuild_sha != lock.pkgbuild_sha
        || version_changed(&lock.pinned_version, &state.available_version);
    let receipt = AurCheckReceipt {
        schema: "harmonia.aur.check.v1",
        package: package.to_string(),
        pinned_version: lock.pinned_version,
        pinned_pkgbuild_sha: lock.pkgbuild_sha,
        available_version: Some(state.available_version),
        available_pkgbuild_sha: Some(state.pkgbuild_sha),
        upstream_source_observed: Some(state.observed_source),
        newer_available,
        ok: true,
        changed: false,
        first_missing_signal: "none".into(),
    };
    write_json(
        &receipt_dir.join(format!("{receipt_name}.json")),
        &serde_json::to_value(&receipt).map_err(|e| e.to_string())?,
    )?;
    Ok(OperationOutcome {
        ok: true,
        changed: false,
        skipped: false,
        message: format!("aur check {package}"),
        command: None,
    })
}

fn version_changed(pinned: &str, available: &str) -> bool {
    pinned != available
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
        first_blocker: None,
        timeout_policy: format!("bounded-timeout-seconds={timeout_secs}"),
        safety_posture: safety_posture.into(),
        unprivileged_builder: unprivileged_builder.clone(),
        ok: false,
        changed: false,
        command: None,
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
        Ok((command, package_path)) => {
            receipt.ok = command.ok;
            receipt.changed = command.ok;
            receipt.command = Some(command.clone());
            if command.ok {
                receipt.produced_package_path = package_path;
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

fn bounded_timeout(timeout_secs: u64) -> u64 {
    match timeout_secs {
        1..=14400 => timeout_secs,
        _ => DEFAULT_TIMEOUT_SECS,
    }
}

fn prepare_and_build(
    lock: &AurRatchetLock,
    package: &str,
    build_dir: &Path,
    source_dir: Option<&str>,
    builder: &str,
    timeout_secs: u64,
) -> Result<(CmdResult, Option<PathBuf>), String> {
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
            return Ok((clone, None));
        }
    }
    let head =
        command::capture_with_cwd("/usr/bin/git", &["rev-parse", "HEAD"], build_dir.to_str());
    if !head.ok {
        return Ok((head, None));
    }
    let checkout = command::capture_with_cwd_and_timeout(
        "/usr/bin/git",
        &["checkout", &lock.pkgbuild_sha],
        build_dir.to_str(),
        timeout_secs,
    );
    if !checkout.ok {
        return Ok((checkout, None));
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
    let makepkg = makepkg_command(builder, timeout_secs, build_dir)?;
    let produced = if makepkg.ok {
        newest_pkg_tar(build_dir)?
    } else {
        None
    };
    Ok((makepkg, produced))
}

fn makepkg_command(builder: &str, timeout_secs: u64, cwd: &Path) -> Result<CmdResult, String> {
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
        Ok(command::capture_with_cwd_and_timeout(
            "/usr/bin/makepkg",
            &["--cleanbuild", "--force", "--noconfirm"],
            cwd.to_str(),
            timeout_secs,
        ))
    }
}

fn newest_pkg_tar(build_dir: &Path) -> Result<Option<PathBuf>, String> {
    let mut packages = Vec::new();
    for entry in fs::read_dir(build_dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("");
        if name.contains(".pkg.tar") {
            packages.push(path);
        }
    }
    packages.sort();
    Ok(packages.pop())
}

fn copy_dir(src: &Path, dst: &Path) -> Result<(), String> {
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

fn first_blocker(command: &CmdResult) -> String {
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

fn write_build_receipt(
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
    let lock = args
        .get("lock")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if lock.is_empty() {
        return Err("aur-lock-empty".into());
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
}
