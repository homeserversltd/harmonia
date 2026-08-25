use super::command;
use super::comparison::DiffDecision;
use crate::{write_json, CmdResult, OperationOutcome};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_TIMEOUT_SECS: u64 = 3600;
pub(crate) const DEFAULT_AUR_BASE_URL: &str = "https://aur.archlinux.org";
pub(crate) const DEFAULT_BUILD_ROOT: &str = "/var/tmp/harmonia/aur";
const HARMONIA_AUR_UPSTREAM_STATE_ENV: &str = "HARMONIA_AUR_UPSTREAM_STATE";

// Compatibility names remain seated here while actuation is owned by do-atoms.
pub(crate) use crate::atoms::r#do::build_aur_pinned::build_pinned;
pub(crate) use crate::atoms::r#do::install_aur::install;
pub(crate) use crate::atoms::r#do::build_aur_pinned::check;
pub(crate) use crate::atoms::r#do::build_aur_pinned::demo;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct AurRatchetLock {
    pub schema: String,
    pub package: String,
    pub pinned_version: String,
    pub pkgbuild_sha: String,
    #[serde(default)]
    pub aur_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

pub(crate) fn augment_comparison_receipt(
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
