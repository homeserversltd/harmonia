use crate::*;
use serde_json::json;
use std::path::{Path, PathBuf};

const CANONICAL_RECEIPT_ROOT: &str = "/var/lib/harmonia/receipts";

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

pub(crate) struct ReceiptDirectory {
    pub(crate) path: PathBuf,
    pub(crate) latest: Option<PathBuf>,
    pub(crate) stem: String,
}

fn receipt_sibling_path(path: &Path, name: &str) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(name),
        _ => PathBuf::from(name),
    }
}

pub(crate) fn latest_receipt_stem(path: &Path, fallback_stem: &str) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    if name == "latest" {
        return Some(fallback_stem.to_string());
    }
    name.strip_suffix("-latest").map(|stem| {
        if stem.is_empty() {
            fallback_stem.to_string()
        } else {
            stem.to_string()
        }
    })
}

/// Allocate an exclusive per-run sibling for a latest receipt alias. Ordinary
/// receipt paths retain their historical direct-write destination.
pub(crate) fn allocate_receipt_directory(
    receipt_dir: &Path,
    run_id: &str,
    fallback_stem: &str,
) -> Result<ReceiptDirectory, String> {
    let Some(stem) = latest_receipt_stem(receipt_dir, fallback_stem) else {
        return Ok(ReceiptDirectory {
            path: receipt_dir.to_path_buf(),
            latest: None,
            stem: fallback_stem.to_string(),
        });
    };
    let parent = receipt_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    crate::atoms::attest::prepare_receipt_parent(parent)?;
    let mut collision = 0u64;
    loop {
        let suffix = if collision == 0 {
            String::new()
        } else {
            format!("-{collision}")
        };
        let name = format!("{stem}-{run_id}{suffix}");
        let candidate = receipt_sibling_path(receipt_dir, &name);
        match std::fs::create_dir(&candidate) {
            Ok(()) => {
                crate::atoms::attest::prepare_receipt_parent(&candidate)?;
                return Ok(ReceiptDirectory {
                    path: candidate,
                    latest: Some(receipt_dir.to_path_buf()),
                    stem,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                collision = collision
                    .checked_add(1)
                    .ok_or_else(|| "receipt-run-directory-collision-exhausted".to_string())?;
            }
            Err(error) => {
                return Err(format!(
                    "receipt-run-directory-create-failed {}: {error}",
                    candidate.display()
                ));
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn rename_receipt_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let from = std::ffi::CString::new(from.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let to = std::ffi::CString::new(to.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn rename_receipt_noreplace(_from: &Path, _to: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-clobber rename requires Linux renameat2",
    ))
}

pub(crate) struct ReceiptParentLock {
    _directory: std::fs::File,
}

pub(crate) fn lock_receipt_parent(
    latest_path: &Path,
    error_prefix: &str,
) -> Result<ReceiptParentLock, String> {
    use std::os::fd::AsRawFd;
    let parent = latest_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = std::fs::File::open(parent).map_err(|error| {
        format!(
            "{error_prefix}-parent-open-failed {}: {error}",
            parent.display()
        )
    })?;
    let result = unsafe {
        libc::flock(
            directory.as_raw_fd(),
            libc::LOCK_EX | libc::LOCK_NB,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            return Err(format!(
                "{error_prefix}-parent-busy {}",
                parent.display()
            ));
        }
        return Err(format!(
            "{error_prefix}-parent-lock-failed {}: {error}",
            parent.display()
        ));
    }
    Ok(ReceiptParentLock {
        _directory: directory,
    })
}

fn canonical_receipt_root(error_prefix: &str) -> Result<(PathBuf, u64), String> {
    let root = PathBuf::from(CANONICAL_RECEIPT_ROOT);
    let mut component_path = PathBuf::from("/");
    for component in root.components() {
        match component {
            std::path::Component::RootDir => continue,
            std::path::Component::Normal(component) => component_path.push(component),
            _ => return Err(format!("{error_prefix}-canonical-root-invalid")),
        }
        let metadata = std::fs::symlink_metadata(&component_path).map_err(|error| {
            format!(
                "{error_prefix}-canonical-root-observe-failed {}: {error}",
                component_path.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(format!(
                "{error_prefix}-canonical-root-component-unsafe {}",
                component_path.display()
            ));
        }
    }
    let resolved = std::fs::canonicalize(&root).map_err(|error| {
        format!(
            "{error_prefix}-canonical-root-resolve-failed {}: {error}",
            root.display()
        )
    })?;
    if resolved != root {
        return Err(format!(
            "{error_prefix}-canonical-root-mismatch expected={} got={}",
            root.display(),
            resolved.display()
        ));
    }
    let metadata = std::fs::symlink_metadata(&root).map_err(|error| {
        format!(
            "{error_prefix}-canonical-root-observe-failed {}: {error}",
            root.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok((root, metadata.dev()))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(format!("{error_prefix}-same-device-check-unsupported"))
    }
}

fn has_regular_receipt_marker(directory: &Path) -> Result<bool, String> {
    for marker in ["run.json", "ruyi.json"] {
        let path = directory.join(marker);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "receipt-marker-observe-failed {}: {error}",
                    path.display()
                ));
            }
        }
    }
    Ok(false)
}

fn has_no_receipt_marker(directory: &Path) -> Result<bool, String> {
    for marker in ["run.json", "ruyi.json"] {
        let path = directory.join(marker);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "receipt-marker-observe-failed {}: {error}",
                    path.display()
                ));
            }
        }
    }
    Ok(true)
}

#[cfg(target_os = "linux")]
fn mountpoints_beneath(directory: &Path) -> Result<Vec<PathBuf>, String> {
    use std::os::unix::ffi::OsStringExt;
    fn unescape_mountinfo(value: &[u8]) -> Vec<u8> {
        let mut decoded = Vec::with_capacity(value.len());
        let mut index = 0;
        while index < value.len() {
            if value[index] == b'\\'
                && index + 3 < value.len()
                && value[index + 1..index + 4]
                    .iter()
                    .all(|byte| (b'0'..=b'7').contains(byte))
            {
                let byte = (value[index + 1] - b'0') * 64
                    + (value[index + 2] - b'0') * 8
                    + (value[index + 3] - b'0');
                decoded.push(byte);
                index += 4;
            } else {
                decoded.push(value[index]);
                index += 1;
            }
        }
        decoded
    }

    let contents = std::fs::read("/proc/self/mountinfo")
        .map_err(|error| format!("receipt-mountinfo-read-failed: {error}"))?;
    let mut mountpoints = Vec::new();
    for line in contents.split(|byte| *byte == b'\n') {
        let fields = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        if let Some(field) = fields.get(4) {
            let mountpoint = PathBuf::from(std::ffi::OsString::from_vec(unescape_mountinfo(field)));
            if mountpoint == directory || mountpoint.starts_with(directory) {
                mountpoints.push(mountpoint);
            }
        }
    }
    Ok(mountpoints)
}

#[cfg(not(target_os = "linux"))]
fn mountpoints_beneath(_directory: &Path) -> Result<Vec<PathBuf>, String> {
    Err("receipt-mountpoint-check-unsupported".to_string())
}

fn validate_canonical_receipt_removal_target(path: &Path) -> Result<(), String> {
    let (root, root_device) = canonical_receipt_root("receipt-prune")?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| "receipt-prune-parentless-path".to_string())?;
    let resolved_parent = std::fs::canonicalize(parent).map_err(|error| {
        format!(
            "receipt-prune-parent-resolve-failed {}: {error}",
            parent.display()
        )
    })?;
    if parent != root.as_path() || resolved_parent != root {
        return Err(format!(
            "receipt-prune-outside-canonical-root {}",
            path.display()
        ));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("receipt-prune-target-observe-failed {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(format!("receipt-prune-target-not-real-directory {}", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.dev() != root_device {
            return Err(format!("receipt-prune-target-device-mismatch {}", path.display()));
        }
    }
    let resolved_path = std::fs::canonicalize(path)
        .map_err(|error| format!("receipt-prune-target-resolve-failed {}: {error}", path.display()))?;
    if resolved_path.parent() != Some(root.as_path()) {
        return Err(format!("receipt-prune-target-not-root-child {}", path.display()));
    }
    let mountpoints = mountpoints_beneath(&resolved_path)?;
    if let Some(mountpoint) = mountpoints.first() {
        return Err(format!(
            "receipt-prune-target-contains-mountpoint {}",
            mountpoint.display()
        ));
    }
    Ok(())
}

fn validate_receipt_removal_target(path: &Path) -> Result<(), String> {
    validate_canonical_receipt_removal_target(path)?;
    if !has_regular_receipt_marker(path)? {
        return Err("receipt-prune-target-unshaped".to_string());
    }
    Ok(())
}

pub(crate) fn ensure_latest_receipt_replaceable(
    latest_path: &Path,
    error_prefix: &str,
) -> Result<(), String> {
    let latest_name = latest_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{error_prefix}-latest-name-invalid {}", latest_path.display()))?;
    if latest_name != "latest" && !latest_name.ends_with("-latest") {
        return Err(format!(
            "{error_prefix}-latest-path-not-alias {}",
            latest_path.display()
        ));
    }
    match std::fs::symlink_metadata(latest_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Ok(()),
        Ok(metadata) if metadata.file_type().is_dir() => {
            validate_canonical_receipt_removal_target(latest_path).map_err(|reason| {
                format!(
                    "{error_prefix}-latest-garbage-skipped {}: {reason}",
                    latest_path.display()
                )
            })?;
            match std::fs::remove_dir_all(latest_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => {
                    return Err(format!(
                        "{error_prefix}-latest-garbage-remove-failed {}: {error}",
                        latest_path.display()
                    ));
                }
            }
            let parent = latest_path.parent().unwrap_or_else(|| Path::new("."));
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("{error_prefix}-latest-garbage-sync-failed: {error}"))
        }
        Ok(_) => Err(format!(
            "{error_prefix}-latest-nonsymlink-occupied {}",
            latest_path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "{error_prefix}-latest-observe-failed {}: {error}",
            latest_path.display()
        )),
    }
}

pub(crate) fn promote_receipt_latest_locked(
    latest_path: &Path,
    target: &Path,
    _run_id: &str,
    error_prefix: &str,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        ensure_latest_receipt_replaceable(latest_path, error_prefix)?;
        let latest_name = latest_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("{error_prefix}-latest-name-invalid {}", latest_path.display()))?;
        let run_leaf = target.file_name().and_then(|name| name.to_str()).unwrap_or("run");
        let target_parent = target.parent().unwrap_or_else(|| Path::new(""));
        let latest_parent = latest_path.parent().unwrap_or_else(|| Path::new(""));
        let link_target = if target.is_absolute() {
            target.to_path_buf()
        } else if target_parent == latest_parent {
            target.file_name().map(PathBuf::from).unwrap_or_else(|| target.to_path_buf())
        } else {
            target.to_path_buf()
        };
        let parent = latest_path.parent().unwrap_or_else(|| Path::new("."));
        let mut collision = 0u64;
        loop {
            let temp = receipt_sibling_path(
                latest_path,
                &format!(".{latest_name}.harmonia-{run_leaf}-{collision}.tmp"),
            );
            match symlink(&link_target, &temp) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    collision = collision.checked_add(1).ok_or_else(|| {
                        format!("{error_prefix}-temporary-link-name-exhausted")
                    })?;
                    continue;
                }
                Err(error) => {
                    return Err(format!(
                        "{error_prefix}-symlink-failed {} -> {}: {error}",
                        link_target.display(), temp.display()
                    ));
                }
            }
            let latest_exists = match std::fs::symlink_metadata(latest_path) {
                Ok(metadata) if metadata.file_type().is_symlink() => true,
                Ok(_) => {
                    let _ = std::fs::remove_file(&temp);
                    return Err(format!(
                        "{error_prefix}-latest-nonsymlink-occupied {}",
                        latest_path.display()
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => {
                    let _ = std::fs::remove_file(&temp);
                    return Err(format!(
                        "{error_prefix}-latest-observe-failed {}: {error}",
                        latest_path.display()
                    ));
                }
            };
            let promote = if latest_exists {
                std::fs::rename(&temp, latest_path)
            } else {
                rename_receipt_noreplace(&temp, latest_path)
            };
            match promote {
                Ok(()) => {
                    std::fs::File::open(parent)
                        .and_then(|directory| directory.sync_all())
                        .map_err(|error| format!("{error_prefix}-parent-sync-failed: {error}"))?;
                    return Ok(());
                }
                Err(error) if !latest_exists && error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let _ = std::fs::remove_file(&temp);
                    ensure_latest_receipt_replaceable(latest_path, error_prefix)?;
                    continue;
                }
                Err(error) => {
                    let _ = std::fs::remove_file(&temp);
                    return Err(format!(
                        "{error_prefix}-latest-link-promote-failed {} -> {}: {error}",
                        temp.display(), latest_path.display()
                    ));
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (latest_path, target, _run_id);
        Err(format!("{error_prefix}-symlink-unsupported"))
    }
}

pub(crate) fn clear_fixed_refusal_after_green(
    latest_path: &Path,
    target: &Path,
    stem: &str,
) -> Result<(), String> {
    let run_path = target.join("run.json");
    match std::fs::symlink_metadata(&run_path) {
        Ok(metadata) if metadata.file_type().is_file() => {}
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("receipt-green-run-observe-failed {}: {error}", run_path.display())),
    }
    let bytes = std::fs::read(&run_path)
        .map_err(|error| format!("receipt-green-run-read-failed {}: {error}", run_path.display()))?;
    let receipt = serde_json::from_slice::<serde_json::Value>(&bytes)
        .map_err(|error| format!("receipt-green-run-parse-failed {}: {error}", run_path.display()))?;
    let green = receipt.get("schema").and_then(serde_json::Value::as_str)
        == Some("harmonia.run_profile.v1")
        && receipt.get("ok").and_then(serde_json::Value::as_bool) == Some(true)
        && receipt.get("mutation").and_then(serde_json::Value::as_bool) == Some(true)
        && receipt.get("suite_ok").and_then(serde_json::Value::as_bool) != Some(false)
        && receipt.get("overall_ok").and_then(serde_json::Value::as_bool) != Some(false);
    if !green {
        return Ok(());
    }
    let refusal = receipt_sibling_path(latest_path, &format!("{stem}-refusal.json"));
    match std::fs::symlink_metadata(&refusal) {
        Ok(metadata) if metadata.file_type().is_file() => match std::fs::remove_file(&refusal) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("receipt-refusal-clear-failed {}: {error}", refusal.display())),
        },
        Ok(_) => Err(format!("receipt-refusal-clear-not-regular {}", refusal.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("receipt-refusal-clear-observe-failed {}: {error}", refusal.display())),
    }
}

/// Compatibility wrapper for callers that do not already hold the parent flock.
pub(crate) fn promote_receipt_latest(
    latest_path: &Path,
    target: &Path,
    _stem: &str,
    run_id: &str,
    error_prefix: &str,
) -> Result<(), String> {
    let _parent_lock = lock_receipt_parent(latest_path, error_prefix)?;
    promote_receipt_latest_locked(latest_path, target, run_id, error_prefix)
}

pub(crate) fn parse_family_run(name: &str, stem: &str) -> Option<(u128, u128, bool)> {
    // Exact family language: ^{literal stem}-(?:run-[0-9]+(?:-[0-9]+)?|displaced-run-[0-9]+(?:-[0-9]+)?)$.
    let name = name.strip_prefix(&format!("{stem}-"))?;
    let (displaced, name) = if let Some(name) = name.strip_prefix("displaced-") {
        (true, name)
    } else {
        (false, name)
    };
    let name = name.strip_prefix("run-")?;
    let mut fields = name.split('-');
    let stamp = fields.next()?;
    if stamp.is_empty() || !stamp.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let collision = match fields.next() {
        Some(value) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
            value.parse::<u128>().ok()?
        }
        Some(_) => return None,
        None => 0,
    };
    if fields.next().is_some() {
        return None;
    }
    Some((stamp.parse().ok()?, collision, displaced))
}

pub(crate) const RECEIPT_PRUNE_DELETION_CAP: usize = 500;
pub(crate) const RECEIPT_PRUNE_ATTEMPT_CAP: usize = 1000;

#[derive(Clone, Debug, Default)]
pub(crate) struct ReceiptPruneReport {
    pub(crate) deletion_attempts: usize,
    pub(crate) deleted_directories: usize,
    pub(crate) capped: bool,
    pub(crate) pruning_confined: bool,
    pub(crate) retained_run_ids: Vec<String>,
    pub(crate) warnings: Vec<String>,
}

impl ReceiptPruneReport {
    pub(crate) fn summarize_warnings(&mut self) {
        const VISIBLE_WARNINGS: usize = 2;
        const OMITTED_PREFIX: &str = "receipt-cleanup-warnings-omitted count=";
        let mut unique = Vec::new();
        let mut previously_omitted = 0usize;
        for warning in self.warnings.drain(..) {
            if let Some(count) = warning
                .strip_prefix(OMITTED_PREFIX)
                .and_then(|count| count.parse::<usize>().ok())
            {
                previously_omitted = previously_omitted.max(count);
            } else if !unique.contains(&warning) {
                unique.push(warning);
            }
        }
        let omitted = previously_omitted + unique.len().saturating_sub(VISIBLE_WARNINGS);
        unique.truncate(VISIBLE_WARNINGS);
        if omitted > 0 {
            unique.push(format!("{OMITTED_PREFIX}{omitted}"));
        }
        self.warnings = unique;
    }
}

#[derive(Clone, Debug)]
struct ReceiptRunCandidate {
    run_id: String,
    stamp: String,
    collision: u128,
    displaced: bool,
    family: bool,
    markerless: bool,
    path: PathBuf,
}

fn receipt_ledger_run_id(candidate: &ReceiptRunCandidate) -> String {
    candidate.run_id.clone()
}

fn legacy_staff_run_id(name: &str) -> Option<String> {
    let digits = name.strip_prefix("run-")?;
    (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| name.to_owned())
}

fn compare_decimal(left: &str, right: &str) -> std::cmp::Ordering {
    let left = left.trim_start_matches('0');
    let right = right.trim_start_matches('0');
    let left = if left.is_empty() { "0" } else { left };
    let right = if right.is_empty() { "0" } else { right };
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn receipt_run_candidates(
    latest_path: &Path,
    stem: &str,
) -> Result<(Vec<ReceiptRunCandidate>, Vec<String>), String> {
    let parent = latest_path.parent().unwrap_or_else(|| Path::new("."));
    let entries = std::fs::read_dir(parent)
        .map_err(|error| format!("receipt-family-read-failed {}: {error}", parent.display()))?;
    let mut candidates = Vec::new();
    let mut warnings = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                warnings.push(format!("receipt-family-entry-read-failed: {error}"));
                continue;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                warnings.push(format!("receipt-family-entry-observe-failed {}: {error}", path.display()));
                continue;
            }
        };
        if !file_type.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let parsed = if let Some((stamp, collision, displaced)) = parse_family_run(&name, stem) {
            let prefix = format!("{stem}-");
            let run_id = name.strip_prefix(&prefix).unwrap_or_default().to_owned();
            Some((stamp.to_string(), collision, displaced, run_id, true))
        } else {
            legacy_staff_run_id(&name).map(|run_id| {
                let stamp = run_id.strip_prefix("run-").unwrap_or_default().to_owned();
                (stamp, 0, false, run_id, false)
            })
        };
        let Some((stamp, collision, displaced, run_id, family)) = parsed else {
            continue;
        };
        let markerless = match has_regular_receipt_marker(&path) {
            Ok(true) => false,
            Ok(false) if family => match has_no_receipt_marker(&path) {
                Ok(true) => true,
                Ok(false) => {
                    warnings.push(format!("receipt-prune-unshaped-directory {}", path.display()));
                    continue;
                }
                Err(error) => {
                    warnings.push(error);
                    continue;
                }
            },
            Ok(false) => {
                warnings.push(format!("receipt-prune-unshaped-directory {}", path.display()));
                continue;
            }
            Err(error) => {
                warnings.push(error);
                continue;
            }
        };
        candidates.push(ReceiptRunCandidate {
            run_id,
            stamp,
            collision,
            displaced,
            family,
            markerless,
            path,
        });
    }
    candidates.sort_by(|left, right| {
        compare_decimal(&left.stamp, &right.stamp)
            .then(left.collision.cmp(&right.collision))
            .then(left.displaced.cmp(&right.displaced))
            .then(left.path.cmp(&right.path))
    });
    Ok((candidates, warnings))
}

fn in_flight_receipt_run_candidate(
    latest_path: &Path,
    stem: &str,
    run_id: &str,
) -> Result<Option<ReceiptRunCandidate>, String> {
    let name = format!("{stem}-{run_id}");
    let Some((stamp, collision, displaced)) = parse_family_run(&name, stem) else {
        return Ok(None);
    };
    let Some(parent) = latest_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(None);
    };
    let path = parent.join(&name);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "receipt-in-flight-directory-observe-failed {}: {error}",
                path.display()
            ));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Ok(None);
    }
    Ok(Some(ReceiptRunCandidate {
        run_id: run_id.to_owned(),
        stamp: stamp.to_string(),
        collision,
        displaced,
        family: true,
        markerless: false,
        path,
    }))
}

fn latest_target_path(latest_path: &Path) -> Result<Option<PathBuf>, String> {
    let metadata = match std::fs::symlink_metadata(latest_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("receipt-latest-observe-failed {}: {error}", latest_path.display())),
    };
    if metadata.file_type().is_dir() || metadata.file_type().is_file() {
        // A real directory is promotion garbage; a regular file has no link
        // target to retain. Neither names a run candidate.
        return Ok(None);
    }
    if !metadata.file_type().is_symlink() {
        return Err(format!("receipt-latest-not-symlink {}", latest_path.display()));
    }
    let target = std::fs::read_link(latest_path)
        .map_err(|error| format!("receipt-latest-link-read-failed {}: {error}", latest_path.display()))?;
    let target = if target.is_absolute() {
        target
    } else {
        latest_path.parent().unwrap_or_else(|| Path::new(".")).join(target)
    };
    std::fs::canonicalize(&target)
        .map(Some)
        .map_err(|error| format!("receipt-latest-target-resolve-failed {}: {error}", target.display()))
}

fn comparable_receipt_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn successful_aggregate_run(candidate: &ReceiptRunCandidate) -> bool {
    let path = candidate.path.join("run.json");
    let Ok(metadata) = std::fs::symlink_metadata(&path) else {
        return false;
    };
    if !metadata.file_type().is_file() {
        return false;
    }
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    let Ok(receipt) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    candidate.family
        && receipt.get("schema").and_then(serde_json::Value::as_str)
            == Some("harmonia.run_profile.v1")
        && receipt.get("ok").and_then(serde_json::Value::as_bool) == Some(true)
        && receipt.get("mutation").and_then(serde_json::Value::as_bool) == Some(true)
        && receipt.get("suite_ok").and_then(serde_json::Value::as_bool) != Some(false)
        && receipt.get("overall_ok").and_then(serde_json::Value::as_bool) != Some(false)
}

struct ReceiptRetentionSelection {
    paths: std::collections::BTreeSet<PathBuf>,
    run_ids: std::collections::BTreeSet<String>,
}

fn select_retained_receipt_runs(
    candidates: &[ReceiptRunCandidate],
    latest_target: Option<&Path>,
    retention: usize,
    current_run_id: Option<&str>,
) -> ReceiptRetentionSelection {
    let mut selection = ReceiptRetentionSelection {
        paths: std::collections::BTreeSet::new(),
        run_ids: std::collections::BTreeSet::new(),
    };
    let mut retain = |candidate: &ReceiptRunCandidate| {
        selection.paths.insert(candidate.path.clone());
        if !candidate.markerless {
            selection.run_ids.insert(candidate.run_id.clone());
        }
    };
    if let Some(target) = latest_target {
        if let Some(candidate) = candidates
            .iter()
            .find(|candidate| comparable_receipt_path(&candidate.path) == comparable_receipt_path(target))
        {
            retain(candidate);
        }
    }
    for candidate in candidates
        .iter()
        .rev()
        .filter(|candidate| candidate.family && !candidate.markerless)
        .take(retention)
    {
        retain(candidate);
    }
    if let Some(candidate) = candidates.iter().rev().find(|candidate| successful_aggregate_run(candidate)) {
        retain(candidate);
    }
    if let Some(run_id) = current_run_id {
        for candidate in candidates
            .iter()
            .filter(|candidate| {
                candidate.family && !candidate.markerless && candidate.run_id.as_str() == run_id
            })
        {
            retain(candidate);
        }
    }
    selection
}

fn markerless_family_run_is_older(
    candidate: &ReceiptRunCandidate,
    current_order: Option<&(String, u128)>,
) -> bool {
    let Some((current_stamp, current_collision)) = current_order else {
        return false;
    };
    match compare_decimal(&candidate.stamp, current_stamp) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => candidate.collision < *current_collision,
    }
}

/// Run IDs corresponding to the same retained set used by post-promotion pruning.
pub(crate) fn retained_receipt_run_ids(
    latest_path: &Path,
    stem: &str,
    retention: usize,
    current_run_id: Option<&str>,
) -> Result<(Vec<String>, Vec<String>), String> {
    let (mut candidates, mut warnings) = receipt_run_candidates(latest_path, stem)?;
    if let Some(run_id) = current_run_id {
        match in_flight_receipt_run_candidate(latest_path, stem, run_id) {
            Ok(Some(candidate)) => {
                if let Some(existing) = candidates.iter_mut().find(|existing| existing.path == candidate.path) {
                    // Only this exact in-flight directory may bypass the marker gate.
                    existing.markerless = false;
                } else {
                    candidates.push(candidate);
                    candidates.sort_by(|left, right| {
                        compare_decimal(&left.stamp, &right.stamp)
                            .then(left.collision.cmp(&right.collision))
                            .then(left.displaced.cmp(&right.displaced))
                            .then(left.path.cmp(&right.path))
                    });
                }
            }
            Ok(None) => {}
            Err(warning) => warnings.push(warning),
        }
    }
    let latest_target = match latest_target_path(latest_path) {
        Ok(target) => target,
        Err(warning) => {
            warnings.push(warning);
            None
        }
    };
    let retained = select_retained_receipt_runs(
        &candidates,
        latest_target.as_deref(),
        retention,
        current_run_id,
    );
    let mut seen = std::collections::BTreeSet::new();
    let run_ids = candidates
        .iter()
        .filter(|candidate| retained.run_ids.contains(&candidate.run_id))
        .filter_map(|candidate| {
            let run_id = receipt_ledger_run_id(candidate);
            seen.insert(run_id.clone()).then_some(run_id)
        })
        .collect();
    let mut warning_report = ReceiptPruneReport {
        warnings,
        ..ReceiptPruneReport::default()
    };
    warning_report.summarize_warnings();
    Ok((run_ids, warning_report.warnings))
}

fn finish_prune_report(mut report: ReceiptPruneReport) -> ReceiptPruneReport {
    report.summarize_warnings();
    report
}

/// Compatibility wrapper for callers without the effective current run path.
pub(crate) fn prune_receipt_family_locked(
    latest_path: &Path,
    stem: &str,
    retention: usize,
) -> ReceiptPruneReport {
    prune_receipt_family_locked_inner(latest_path, stem, retention, None)
}

/// Prune exact receipt families while preserving the effective current run.
pub(crate) fn prune_receipt_family_locked_for_current(
    latest_path: &Path,
    stem: &str,
    retention: usize,
    current_run_dir: &Path,
) -> ReceiptPruneReport {
    prune_receipt_family_locked_inner(latest_path, stem, retention, Some(current_run_dir))
}

fn is_current_receipt_run(
    candidate: &ReceiptRunCandidate,
    current_run_dir: Option<&Path>,
    current_run_comparable: Option<&Path>,
) -> bool {
    let Some(current_run_dir) = current_run_dir else {
        return false;
    };
    candidate.path.as_path() == current_run_dir
        || current_run_comparable.is_some_and(|current| {
            comparable_receipt_path(&candidate.path).as_path() == current
        })
}

fn prune_receipt_family_locked_inner(
    latest_path: &Path,
    stem: &str,
    retention: usize,
    current_run_dir: Option<&Path>,
) -> ReceiptPruneReport {
    let mut report = ReceiptPruneReport::default();
    let (root, _) = match canonical_receipt_root("receipt-prune") {
        Ok(root) => root,
        Err(error) => {
            report.warnings.push(error);
            return finish_prune_report(report);
        }
    };
    let parent = latest_path.parent().unwrap_or_else(|| Path::new("."));
    match std::fs::canonicalize(parent) {
        Ok(resolved) if parent == root.as_path() && resolved == root => {}
        Ok(_) => {
            report.warnings.push(format!(
                "receipt-prune-outside-canonical-root {}",
                parent.display()
            ));
            return finish_prune_report(report);
        }
        Err(error) => {
            report.warnings.push(format!(
                "receipt-prune-parent-resolve-failed {}: {error}",
                parent.display()
            ));
            return finish_prune_report(report);
        }
    }
    report.pruning_confined = true;
    let (candidates, scan_warnings) = match receipt_run_candidates(latest_path, stem) {
        Ok(scan) => scan,
        Err(error) => {
            report.warnings.push(error);
            return finish_prune_report(report);
        }
    };
    report.warnings.extend(scan_warnings);
    let latest_target = match latest_target_path(latest_path) {
        Ok(target) => target,
        Err(error) => {
            report.warnings.push(error);
            return finish_prune_report(report);
        }
    };
    let current_run_order = match current_run_dir {
        Some(path) => match validate_canonical_receipt_removal_target(path) {
            Ok(()) => match path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| parse_family_run(name, stem))
            {
                Some((stamp, collision, _)) => Some((stamp.to_string(), collision)),
                None => {
                    report.warnings.push("receipt-prune-current-run-name-not-family".to_string());
                    None
                }
            },
            Err(reason) => {
                report.warnings.push(format!("receipt-prune-current-run-untrusted: {reason}"));
                None
            }
        },
        None => None,
    };
    let current_run_comparable = current_run_dir.map(comparable_receipt_path);
    let selection = select_retained_receipt_runs(&candidates, latest_target.as_deref(), retention, None);
    let mut retained_seen = std::collections::BTreeSet::new();
    report.retained_run_ids = candidates
        .iter()
        .filter(|candidate| selection.paths.contains(&candidate.path) && !candidate.markerless)
        .filter_map(|candidate| {
            retained_seen
                .insert(candidate.run_id.clone())
                .then(|| candidate.run_id.clone())
        })
        .collect();
    let mut parent_changed = false;
    let mut capped_remaining = 0usize;
    for (index, candidate) in candidates.iter().enumerate() {
        if selection.paths.contains(&candidate.path)
            || is_current_receipt_run(
                candidate,
                current_run_dir,
                current_run_comparable.as_deref(),
            )
        {
            continue;
        }
        if candidate.markerless && !markerless_family_run_is_older(candidate, current_run_order.as_ref()) {
            report.warnings.push(if current_run_order.is_some() {
                format!("receipt-prune-markerless-not-older {}", candidate.path.display())
            } else {
                "receipt-prune-markerless-current-run-unavailable".to_string()
            });
            continue;
        }
        if report.deletion_attempts >= RECEIPT_PRUNE_ATTEMPT_CAP
            || report.deleted_directories >= RECEIPT_PRUNE_DELETION_CAP
        {
            report.capped = true;
            capped_remaining = candidates[index..]
                .iter()
                .filter(|candidate| {
                    !selection.paths.contains(&candidate.path)
                        && !is_current_receipt_run(
                            candidate,
                            current_run_dir,
                            current_run_comparable.as_deref(),
                        )
                        && (!candidate.markerless
                            || markerless_family_run_is_older(candidate, current_run_order.as_ref()))
                })
                .count();
            break;
        }
        let validation = if candidate.markerless {
            validate_canonical_receipt_removal_target(&candidate.path)
        } else {
            validate_receipt_removal_target(&candidate.path)
        };
        if let Err(reason) = validation {
            report.warnings.push(format!("receipt-prune-skipped: {reason}"));
            continue;
        }
        report.deletion_attempts += 1;
        match std::fs::remove_dir_all(&candidate.path) {
            Ok(()) => {
                report.deleted_directories += 1;
                parent_changed = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => report.warnings.push(format!(
                "receipt-prune-failed {}: {error}",
                candidate.path.display()
            )),
        }
    }
    if report.capped {
        report.warnings.push(format!(
            "receipt-prune-cap-reached attempt_cap={} deletion_cap={} remaining={capped_remaining}",
            RECEIPT_PRUNE_ATTEMPT_CAP,
            RECEIPT_PRUNE_DELETION_CAP,
        ));
    }
    if parent_changed {
        let parent = latest_path.parent().unwrap_or_else(|| Path::new("."));
        if let Err(error) = std::fs::File::open(parent).and_then(|directory| directory.sync_all()) {
            report.warnings.push(format!("receipt-prune-parent-sync-failed {}: {error}", parent.display()));
        }
    }
    finish_prune_report(report)
}

/// Store early refusals without creating a parent or a run directory.
pub(crate) fn write_fixed_refusal_receipt(
    receipt_dir: &Path,
    fallback_stem: &str,
    receipt: &serde_json::Value,
) -> Result<(), String> {
    let parent = receipt_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| "receipt-refusal-parentless-path".to_string())?;
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err(format!("receipt-refusal-parent-not-directory {}", parent.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("receipt-refusal-parent-missing {}", parent.display()))
        }
        Err(error) => {
            return Err(format!("receipt-refusal-parent-observe-failed {}: {error}", parent.display()))
        }
    }
    let run_id = crate::receipts::run_id_from_stamp();
    let recorded_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0);
    let mut stamped = receipt.clone();
    let object = stamped
        .as_object_mut()
        .ok_or_else(|| "receipt-refusal-not-object".to_string())?;
    object.insert("recorded_at".to_string(), json!(recorded_at));
    object.insert("run_id".to_string(), json!(run_id));
    let run_identity = json!({
        "run_id": run_id,
        "profile_id": object.get("profile_id").cloned().unwrap_or(serde_json::Value::Null),
        "identity": object.get("identity").cloned().unwrap_or(serde_json::Value::Null),
        "identity_source": object.get("identity_source").cloned().unwrap_or(serde_json::Value::Null),
    });
    object.insert("run_identity".to_string(), run_identity);
    let destination = match latest_receipt_stem(receipt_dir, fallback_stem) {
        Some(stem) => receipt_sibling_path(receipt_dir, &format!("{stem}-refusal.json")),
        None => {
            let metadata = std::fs::symlink_metadata(receipt_dir).map_err(|error| {
                format!("receipt-refusal-directory-observe-failed {}: {error}", receipt_dir.display())
            })?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(format!("receipt-refusal-directory-not-real {}", receipt_dir.display()));
            }
            receipt_dir.join("run.json")
        }
    };
    crate::atoms::attest::write_json_atomic(&destination, &stamped)
}

pub(crate) fn materialize_latest_receipt_dir(
    receipt_dir: &Path,
    run_id: &str,
    fallback_stem: &str,
    _error_prefix: &str,
) -> Result<PathBuf, String> {
    // The caller creates the run directory before acquiring the parent flock
    // for promotion and pruning.
    Ok(allocate_receipt_directory(receipt_dir, run_id, fallback_stem)?.path)
}

pub(crate) fn materialize_tv_receipt_dir(
    receipt_dir: &Path,
    run_id: &str,
) -> Result<PathBuf, String> {
    materialize_latest_receipt_dir(receipt_dir, run_id, "tv-update", "tv-update-latest")
}
pub(crate) fn materialize_homeconsole_receipt_dir(
    receipt_dir: &Path,
    run_id: &str,
) -> Result<PathBuf, String> {
    materialize_latest_receipt_dir(
        receipt_dir,
        run_id,
        "homeconsole-update",
        "homeconsole-update-latest",
    )
}
pub(crate) fn materialize_homeserver_receipt_dir(
    receipt_dir: &Path,
    run_id: &str,
) -> Result<PathBuf, String> {
    materialize_latest_receipt_dir(
        receipt_dir,
        run_id,
        "homeserver-update",
        "homeserver-update-latest",
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
        &format!(
            "schema=harmonia.convergence.skipped.v1 ok=true reason={reason}"
        ),
        Some(serde_json::json!({
            "schema": "harmonia.convergence.skipped.v1",
            "ok": true,
            "changed": false,
            "reason": reason,
            "profile_id": profile_id,
            "first_missing_signal": reason,
        })),
        Some(true),
        None,
    );
    println!("ok=true");
    println!("changed=false");
    println!("profile_id={profile_id}");
    println!("reason={reason}");
    println!("receipt_dir={}", receipt_dir.display());
}
