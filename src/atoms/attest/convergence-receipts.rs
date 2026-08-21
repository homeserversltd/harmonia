use crate::*;
use serde_json::json;
use std::path::{Path, PathBuf};

pub(crate) const HOME_CONSOLE_UPDATE_RECEIPT_LATEST: &str =
    "/var/lib/harmonia/receipts/homeconsole-update-latest";
pub(crate) const HOME_SERVER_UPDATE_RECEIPT_LATEST: &str =
    "/var/lib/harmonia/receipts/homeserver-update-latest";
pub(crate) const TV_UPDATE_RECEIPT_LATEST: &str = "/var/lib/harmonia/receipts/tv-update-latest";

pub(crate) fn homeconsole_update_receipt_latest() -> PathBuf {
    PathBuf::from(HOME_CONSOLE_UPDATE_RECEIPT_LATEST)
}
pub(crate) fn homeserver_update_receipt_latest() -> PathBuf {
    PathBuf::from(HOME_SERVER_UPDATE_RECEIPT_LATEST)
}
pub(crate) fn tv_update_receipt_latest() -> PathBuf {
    PathBuf::from(TV_UPDATE_RECEIPT_LATEST)
}
pub(crate) fn materialize_tv_receipt_dir(
    receipt_dir: &Path,
    run_id: &str,
) -> Result<PathBuf, String> {
    let file_name = receipt_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let use_per_run = matches!(file_name, "latest" | "tv-update-latest" | "tv-latest")
        || file_name.ends_with("-latest");
    if !use_per_run {
        return Ok(receipt_dir.to_path_buf());
    }
    let parent = receipt_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| receipt_dir.to_path_buf());
    let base = file_name
        .strip_suffix("-latest")
        .filter(|stem| !stem.is_empty())
        .unwrap_or("tv-update");
    let per_run = parent.join(format!("{base}-{run_id}"));
    crate::atoms::attest::prepare_receipt_parent(&per_run)?;
    refresh_tv_latest_symlink(receipt_dir, &per_run)?;
    Ok(per_run)
}
fn refresh_tv_latest_symlink(latest_path: &Path, target: &Path) -> Result<(), String> {
    crate::atoms::attest::promote_current_link(latest_path, target, "tv-update-latest", false)
}
pub(crate) fn materialize_homeconsole_receipt_dir(
    receipt_dir: &Path,
    run_id: &str,
) -> Result<PathBuf, String> {
    let file_name = receipt_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let use_per_run = matches!(file_name, "latest" | "homeconsole-update-latest")
        || file_name.ends_with("-latest");
    if !use_per_run {
        return Ok(receipt_dir.to_path_buf());
    }
    let parent = receipt_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| receipt_dir.to_path_buf());
    let base = file_name
        .strip_suffix("-latest")
        .filter(|stem| !stem.is_empty())
        .unwrap_or("homeconsole-update");
    let per_run = parent.join(format!("{base}-{run_id}"));
    crate::atoms::attest::prepare_receipt_parent(&per_run)?;
    refresh_latest_symlink(receipt_dir, &per_run)?;
    Ok(per_run)
}
pub(crate) fn materialize_homeserver_receipt_dir(
    receipt_dir: &Path,
    run_id: &str,
) -> Result<PathBuf, String> {
    let file_name = receipt_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let use_per_run = matches!(file_name, "latest" | "homeserver-update-latest")
        || file_name.ends_with("-latest");
    if !use_per_run {
        return Ok(receipt_dir.to_path_buf());
    }
    let parent = receipt_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| receipt_dir.to_path_buf());
    let base = file_name
        .strip_suffix("-latest")
        .filter(|stem| !stem.is_empty())
        .unwrap_or("homeserver-update");
    let per_run = parent.join(format!("{base}-{run_id}"));
    crate::atoms::attest::prepare_receipt_parent(&per_run)?;
    refresh_homeserver_latest_symlink(receipt_dir, &per_run)?;
    Ok(per_run)
}
fn refresh_homeserver_latest_symlink(latest_path: &Path, target: &Path) -> Result<(), String> {
    crate::atoms::attest::promote_current_link(
        latest_path,
        target,
        "homeserver-update-latest",
        false,
    )
}
fn refresh_latest_symlink(latest_path: &Path, target: &Path) -> Result<(), String> {
    crate::atoms::attest::promote_current_link(
        latest_path,
        target,
        "homeconsole-update-latest",
        true,
    )
}
pub(crate) fn write_convergence_skipped_receipt(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
    reason: &str,
    lock_path: &Path,
    requested_receipt_dir: &Path,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join("convergence-skipped.json"),
        &json!({
            "schema": "harmonia.convergence.skipped.v1",
            "ok": true,
            "changed": false,
            "mutation": apply,
            "reason": reason,
            "profile_id": profile.id,
            "identity": profile.identity,
            "lock_path": lock_path,
            "requested_receipt_dir": requested_receipt_dir,
            "receipt_dir": receipt_dir,
            "suite_ok": true,
        }),
    )?;
    let mut events = crate::atoms::attest::create_receipt_file(&receipt_dir.join("events.jsonl"))?;
    event(
        &mut events,
        "convergence-skipped",
        true,
        &format!("reason={reason}"),
    )
}
pub(crate) fn emit_convergence_skipped_stdout(receipt_dir: &Path, reason: &str, profile_id: &str) {
    println!("schema=harmonia.convergence.skipped.v1");
    hyalos::forward_receipt(
        "schema=harmonia.convergence.skipped.v1",
        &format!("schema=harmonia.convergence.skipped.v1 ok={}", true),
        Some(serde_json::json!({"schema": "harmonia.convergence.skipped.v1", "ok": true})),
        Some(true),
    );
    println!("ok=true");
    println!("changed=false");
    println!("profile_id={profile_id}");
    println!("reason={reason}");
    println!("receipt_dir={}", receipt_dir.display());
}
