use crate::*;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) const HOME_CONSOLE_UPDATE_RECEIPT_LATEST: &str =
    "/var/lib/harmonia/receipts/homeconsole-update-latest";
pub(crate) const HOME_CONSOLE_UPDATE_RECEIPT_LEGACY: &str =
    "/var/lib/harmonia/receipts/homeconsole-latest";
pub(crate) const HOME_SERVER_UPDATE_RECEIPT_LATEST: &str =
    "/var/lib/harmonia/receipts/homeserver-update-latest";
pub(crate) const TV_UPDATE_RECEIPT_LATEST: &str = "/var/lib/harmonia/receipts/tv-update-latest";
pub(crate) const TV_UPDATE_RECEIPT_LEGACY: &str = "/var/lib/harmonia/receipts/tv-latest";

pub(crate) fn homeconsole_update_receipt_latest() -> PathBuf {
    PathBuf::from(HOME_CONSOLE_UPDATE_RECEIPT_LATEST)
}
pub(crate) fn homeconsole_update_receipt_legacy() -> PathBuf {
    PathBuf::from(HOME_CONSOLE_UPDATE_RECEIPT_LEGACY)
}
pub(crate) fn homeserver_update_receipt_latest() -> PathBuf {
    PathBuf::from(HOME_SERVER_UPDATE_RECEIPT_LATEST)
}
pub(crate) fn tv_update_receipt_latest() -> PathBuf {
    PathBuf::from(TV_UPDATE_RECEIPT_LATEST)
}
pub(crate) fn tv_update_receipt_legacy() -> PathBuf {
    PathBuf::from(TV_UPDATE_RECEIPT_LEGACY)
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
    fs::create_dir_all(&per_run).map_err(|e| e.to_string())?;
    migrate_tv_blocking_receipt_path(receipt_dir, run_id)?;
    refresh_tv_latest_symlink(receipt_dir, &per_run)?;
    Ok(per_run)
}
fn migrate_tv_blocking_receipt_path(latest_path: &Path, run_id: &str) -> Result<(), String> {
    if !latest_path.exists() || latest_path.is_symlink() {
        return Ok(());
    }
    if latest_path.is_dir() {
        let parent = latest_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| latest_path.to_path_buf());
        let migrated = parent.join(format!("tv-update-legacy-{run_id}"));
        fs::rename(latest_path, &migrated).map_err(|e| {
            format!(
                "tv-update-latest-migrate-failed {} -> {}: {e}",
                latest_path.display(),
                migrated.display()
            )
        })?;
        return Ok(());
    }
    fs::remove_file(latest_path).map_err(|e| e.to_string())
}
fn refresh_tv_latest_symlink(latest_path: &Path, target: &Path) -> Result<(), String> {
    if latest_path.exists() {
        fs::remove_file(latest_path).map_err(|e| e.to_string())?;
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, latest_path).map_err(|e| {
        format!(
            "tv-update-latest-symlink-failed {} -> {}: {e}",
            target.display(),
            latest_path.display()
        )
    })?;
    #[cfg(not(unix))]
    return Err("tv-update-latest-symlink-unsupported".to_string());
    Ok(())
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
    fs::create_dir_all(&per_run).map_err(|e| e.to_string())?;
    migrate_blocking_receipt_path(receipt_dir, run_id)?;
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
    fs::create_dir_all(&per_run).map_err(|e| e.to_string())?;
    migrate_homeserver_blocking_receipt_path(receipt_dir, run_id)?;
    refresh_homeserver_latest_symlink(receipt_dir, &per_run)?;
    Ok(per_run)
}
fn migrate_homeserver_blocking_receipt_path(
    latest_path: &Path,
    run_id: &str,
) -> Result<(), String> {
    if !latest_path.exists() || latest_path.is_symlink() {
        return Ok(());
    }
    if latest_path.is_dir() {
        let parent = latest_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| latest_path.to_path_buf());
        let migrated = parent.join(format!("homeserver-update-legacy-{run_id}"));
        fs::rename(latest_path, &migrated).map_err(|e| {
            format!(
                "homeserver-update-latest-migrate-failed {} -> {}: {e}",
                latest_path.display(),
                migrated.display()
            )
        })?;
        return Ok(());
    }
    fs::remove_file(latest_path).map_err(|e| e.to_string())
}
pub(crate) fn migrate_blocking_receipt_path(
    latest_path: &Path,
    run_id: &str,
) -> Result<(), String> {
    if !latest_path.exists() || latest_path.is_symlink() {
        return Ok(());
    }
    if latest_path.is_dir() {
        let parent = latest_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| latest_path.to_path_buf());
        let migrated = parent.join(format!("homeconsole-update-legacy-{run_id}"));
        fs::rename(latest_path, &migrated).map_err(|e| {
            format!(
                "homeconsole-update-latest-migrate-failed {} -> {}: {e}",
                latest_path.display(),
                migrated.display()
            )
        })?;
        return Ok(());
    }
    fs::remove_file(latest_path).map_err(|e| e.to_string())
}
fn refresh_homeserver_latest_symlink(latest_path: &Path, target: &Path) -> Result<(), String> {
    if latest_path.exists() {
        fs::remove_file(latest_path).map_err(|e| e.to_string())?;
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, latest_path).map_err(|e| {
        format!(
            "homeserver-update-latest-symlink-failed {} -> {}: {e}",
            target.display(),
            latest_path.display()
        )
    })?;
    #[cfg(not(unix))]
    return Err("homeserver-update-latest-symlink-unsupported".to_string());
    Ok(())
}
fn refresh_latest_symlink(latest_path: &Path, target: &Path) -> Result<(), String> {
    if latest_path.exists() {
        if latest_path.is_symlink() {
            fs::remove_file(latest_path).map_err(|e| e.to_string())?;
        } else if latest_path.is_dir() {
            return Err(format!(
                "homeconsole-update-latest-still-directory {}",
                latest_path.display()
            ));
        } else {
            fs::remove_file(latest_path).map_err(|e| e.to_string())?;
        }
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, latest_path).map_err(|e| {
            format!(
                "homeconsole-update-latest-symlink-failed {} -> {}: {e}",
                target.display(),
                latest_path.display()
            )
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = (latest_path, target);
        return Err("homeconsole-update-latest-symlink-unsupported".to_string());
    }
    Ok(())
}
pub(crate) fn write_convergence_skipped_receipt(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
    reason: &str,
    lock_path: &Path,
    requested_receipt_dir: &Path,
) -> Result<(), String> {
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
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
    let mut events =
        fs::File::create(receipt_dir.join("events.jsonl")).map_err(|e| e.to_string())?;
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
