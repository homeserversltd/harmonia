use super::Band;
use crate::interactables::{self, DriftSummary, Interactable};
use crate::ladder::LadderManifest;
use crate::tools::files::{FileConvergenceOutcome, FileConvergenceRequest};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::fs;
use std::collections::BTreeSet;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn enter(enter: &mut impl FnMut(Band) -> Result<(), String>) -> Result<(), String> {
    enter(Band::ProposeEdits)
}
fn stamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into())
}
fn iso8601_now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let timestamp = seconds.min(i64::MAX as u64) as libc::time_t;
    let mut utc: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::gmtime_r(&timestamp, &mut utc) }.is_null() {
        return "1970-01-01T00:00:00Z".into();
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        utc.tm_year + 1900,
        utc.tm_mon + 1,
        utc.tm_mday,
        utc.tm_hour,
        utc.tm_min,
        utc.tm_sec
    )
}
fn stable_id(module_id: &str, target: &Path) -> String {
    let digest = Sha256::digest(format!("{module_id}:{}", target.display()).as_bytes());
    format!("config-proposal-{}", &format!("{digest:x}")[..16])
}

pub(crate) fn persist_feed(path: &Path, feed: &interactables::InteractablesFeed) -> Result<(), String> {
    let value = serde_json::to_value(feed).map_err(|error| format!("interactables-feed-serialize-failed: {error}"))?;
    crate::write_json(path, &value)?;
    #[cfg(unix)]
    fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).map_err(|error| format!("interactables-feed-mode-failed {}: {error}", path.display()))?;
    let proposal_root = path.parent().unwrap_or_else(|| Path::new(".")).join("proposals");
    fs::create_dir_all(&proposal_root).map_err(|error| error.to_string())?;
    let live_records = feed.interactables.iter().map(|item| format!("{}.json", item.id)).collect::<BTreeSet<_>>();
    for entry in fs::read_dir(&proposal_root).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        if entry.file_type().map_err(|error| error.to_string())?.is_file() && name.to_str().is_some_and(|name| name.starts_with("config-proposal-") && name.ends_with(".json") && !live_records.contains(name)) {
            fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
        }
    }
    for item in &feed.interactables {
        crate::write_json(&proposal_root.join(format!("{}.json", item.id)), &serde_json::to_value(item).map_err(|error| error.to_string())?)?;
    }
    crate::atoms::attest::attest(&path.parent().unwrap_or_else(|| Path::new(".")).join("proposals.attest.jsonl"), &crate::atoms::Receipt { atom: "propose-edits".into(), ok: true, drift: crate::atoms::Drift::Current, message: format!("proposal-persistence-transition count={}", feed.interactables.len()) }, &[])?;
    Ok(())
}

pub(crate) fn refresh_interactables_for_convergence(
    manifest: &LadderManifest,
    request: &FileConvergenceRequest,
    outcome: &FileConvergenceOutcome,
) -> Result<(), String> {
    let path = std::env::var_os("HARMONIA_INTERACTABLES_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/interactables.json"));
    refresh_interactables_at_path(&path, manifest, request, outcome)
}

pub(crate) fn refresh_interactables_at_path(
    path: &Path,
    manifest: &LadderManifest,
    request: &FileConvergenceRequest,
    outcome: &FileConvergenceOutcome,
) -> Result<(), String> {
    let mut feed = interactables::load_feed(path)?;
    let now = stamp();
    let available_at = iso8601_now();
    for entry in &outcome.entries {
        let id = stable_id(&manifest.id, &entry.target);
        let created_at = feed
            .interactables
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.created_at.clone())
            .unwrap_or_else(|| now.clone());
        feed.interactables.retain(|e| e.id != id);
        if !entry.source_exists || !entry.target_exists_before {
            continue;
        }
        let drift = DriftSummary {
            content: !entry.content_equal_before,
            mode: !entry.mode_equal_before,
            ownership: entry.ownership_changed,
        };
        if !drift.content && !drift.mode && !drift.ownership {
            continue;
        }
        crate::tools::files::validate_interactable_target(&entry.target)?;
        feed.interactables.push(Interactable {
            id,
            module_id: manifest.id.clone(),
            name: format!("{}: {}", manifest.id, entry.relative_path),
            description: manifest.description.clone(),
            kind: "hard-stamp".into(),
            target_path: entry.target.clone(),
            reference_source_path: entry.source.clone(),
            drift,
            created_at,
            refreshed_at: now.clone(),
            available_at: Some(available_at.clone()),
            has_run: false,
            mode: entry.final_mode,
            owner: request.owner.clone(),
            group: request.group.clone(),
            source_sha: None,
            target_sha: None,
            commits_behind: None,
        });
    }
    feed.interactables.sort_by(|a, b| a.id.cmp(&b.id));
    persist_feed(&path, &feed)?;
    let log = path.parent().unwrap_or_else(|| Path::new(".")).join("proposals.attest.jsonl");
    crate::atoms::attest::attest(&log, &crate::atoms::Receipt {
        atom: "propose-edits".into(), ok: true, drift: crate::atoms::Drift::Current,
        message: format!("proposal-feed-refreshed count={}", feed.interactables.len()),
    }, &[])
}
