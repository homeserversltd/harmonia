use crate::ladder::LadderManifest;
use crate::tools::files::{FileConvergenceOutcome, FileConvergenceRequest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::env;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn iso8601_now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let timestamp = seconds.min(i64::MAX as u64) as libc::time_t;
    let mut utc: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::gmtime_r(&timestamp, &mut utc) }.is_null() {
        return "1970-01-01T00:00:00Z".to_string();
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

const FEED_SCHEMA: &str = "harmonia.interactables.feed.v1";
const DEFAULT_FEED_PATH: &str = "/var/lib/harmonia/interactables.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InteractablesFeed {
    schema: String,
    #[serde(default)]
    interactables: Vec<Interactable>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Interactable {
    id: String,
    module_id: String,
    name: String,
    #[serde(default)]
    description: String,
    kind: String,
    target_path: PathBuf,
    reference_source_path: PathBuf,
    drift: DriftSummary,
    created_at: String,
    refreshed_at: String,
    /// UTC time when this item became available, or was last re-reported.
    /// Legacy rows omit this field and deserialize as null.
    #[serde(default)]
    available_at: Option<String>,
    has_run: bool,
    #[serde(default)]
    mode: Option<u32>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    group: Option<String>,
    /// Local source commit compared with `target_sha` for source-shaped items.
    /// File convergence proposals have no source-commit authority, so this
    /// remains null without changing their existing shape.
    #[serde(default)]
    source_sha: Option<String>,
    /// Observed target commit for source-shaped items, when the possession lane
    /// can observe it without a separate source acquisition.
    #[serde(default)]
    target_sha: Option<String>,
    /// Number of commits from `source_sha` to `target_sha`; null means the
    /// source lane did not establish a comparable Git pair.
    #[serde(default)]
    commits_behind: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DriftSummary {
    content: bool,
    mode: bool,
    ownership: bool,
}

fn feed_path() -> PathBuf {
    env::var_os("HARMONIA_INTERACTABLES_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_FEED_PATH))
}

fn stamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn stable_id(module_id: &str, target: &Path) -> String {
    let digest = Sha256::digest(format!("{module_id}:{}", target.display()).as_bytes());
    format!("hard-stamp-{}", &format!("{digest:x}")[..16])
}

fn load_feed(path: &Path) -> Result<InteractablesFeed, String> {
    match fs::read_to_string(path) {
        Ok(text) => {
            let feed: InteractablesFeed = serde_json::from_str(&text)
                .map_err(|error| format!("interactables-feed-parse-failed {}: {error}", path.display()))?;
            if feed.schema != FEED_SCHEMA {
                return Err(format!("interactables-feed-schema-unsupported {}", feed.schema));
            }
            Ok(feed)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(InteractablesFeed {
            schema: FEED_SCHEMA.to_string(),
            interactables: Vec::new(),
        }),
        Err(error) => Err(format!("interactables-feed-read-failed {}: {error}", path.display())),
    }
}

fn save_feed(path: &Path, feed: &InteractablesFeed) -> Result<(), String> {
    let value = serde_json::to_value(feed)
        .map_err(|error| format!("interactables-feed-serialize-failed: {error}"))?;
    crate::write_json(path, &value)?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))
        .map_err(|error| format!("interactables-feed-mode-failed {}: {error}", path.display()))?;
    Ok(())
}

pub(crate) fn refresh_interactables_for_convergence(
    manifest: &LadderManifest,
    request: &FileConvergenceRequest,
    outcome: &FileConvergenceOutcome,
) -> Result<(), String> {
    let path = feed_path();
    refresh_interactables_at_path(&path, manifest, request, outcome)
}

fn refresh_interactables_at_path(
    path: &Path,
    manifest: &LadderManifest,
    request: &FileConvergenceRequest,
    outcome: &FileConvergenceOutcome,
) -> Result<(), String> {
    let mut feed = load_feed(path)?;
    let declared_targets: BTreeSet<PathBuf> = request.files.iter().map(|file| {
        request.target_root.join(&file.relative_path)
    }).collect();
    feed.interactables.retain(|existing| {
        existing.module_id != manifest.id || declared_targets.contains(&existing.target_path)
    });
    let now = stamp();
    let available_at = iso8601_now();
    for entry in &outcome.entries {
        let id = stable_id(&manifest.id, &entry.target);
        let created_at = feed
            .interactables
            .iter()
            .find(|existing| existing.id == id)
            .map(|existing| existing.created_at.clone())
            .unwrap_or_else(|| now.clone());
        feed.interactables.retain(|existing| existing.id != id);
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
            kind: "hard-stamp".to_string(),
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
    feed.interactables.sort_by(|left, right| left.id.cmp(&right.id));
    save_feed(&path, &feed)
}

pub(crate) fn interactable_command(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("list") => interactable_list(&args[1..]),
        Some("run") => interactable_run(&args[1..]),
        _ => Err("interactable requires list [--json] or run <id>".to_string()),
    }
}

fn interactable_list(args: &[String]) -> Result<(), String> {
    if args.iter().any(|arg| arg != "--json") {
        return Err("interactable list accepts only --json".to_string());
    }
    let feed = load_feed(&feed_path())?;
    if args.iter().any(|arg| arg == "--json") {
        println!("{}", serde_json::to_string_pretty(&feed).map_err(|error| error.to_string())?);
    } else {
        println!("schema={FEED_SCHEMA}");
        println!("pending_count={}", feed.interactables.len());
        for item in feed.interactables {
            println!("id={} module_id={} kind={} target={}", item.id, item.module_id, item.kind, item.target_path.display());
        }
    }
    Ok(())
}

fn interactable_run(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("interactable run requires exactly one <id>".to_string());
    }
    let path = feed_path();
    let mut feed = load_feed(&path)?;
    let position = feed
        .interactables
        .iter()
        .position(|item| item.id == args[0])
        .ok_or_else(|| format!("interactable-unknown-id {}", args[0]))?;
    let item = feed.interactables[position].clone();
    if item.kind != "hard-stamp" {
        return Err(format!("interactable-kind-unsupported {}", item.kind));
    }
    let backup_root = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("interactables-backups");
    let mut receipt = crate::tools::files::hard_stamp_interactable(
        &item.id,
        &item.reference_source_path,
        &item.target_path,
        item.mode,
        item.owner.as_deref(),
        item.group.as_deref(),
        &backup_root,
    )?;
    receipt["has_run"] = serde_json::Value::Bool(true);
    feed.interactables[position].has_run = true;
    feed.interactables.remove(position);
    save_feed(&path, &feed)?;
    println!("{}", serde_json::to_string_pretty(&receipt).map_err(|error| error.to_string())?);
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::files::FileSpec;
    use std::collections::BTreeMap;

    fn item(module_id: &str, target: PathBuf) -> Interactable {
        Interactable { id: stable_id(module_id, &target), module_id: module_id.to_string(), name: module_id.to_string(), description: String::new(), kind: "hard-stamp".to_string(), target_path: target.clone(), reference_source_path: PathBuf::from("/declared/files_root").join(target.file_name().unwrap()), drift: DriftSummary { content: true, mode: false, ownership: false }, created_at: "0".to_string(), refreshed_at: "0".to_string(), available_at: None, has_run: false, mode: Some(0o644), owner: None, group: None, source_sha: None, target_sha: None, commits_behind: None }
    }

    #[test]
    fn refresh_prunes_interactable_no_longer_declared_by_its_module() {
        let scratch = std::env::temp_dir().join(format!("harmonia-interactables-prune-{}", std::process::id()));
        let path = scratch.join("interactables.json");
        let current = PathBuf::from("/home/owner/.config/kate/katerc");
        let removed = PathBuf::from("/home/owner/.local/share/kate/anonymous.katesession");
        save_feed(&path, &InteractablesFeed { schema: FEED_SCHEMA.to_string(), interactables: vec![item("desktop-config-payload", current.clone()), item("desktop-config-payload", removed)] }).unwrap();
        let manifest = LadderManifest { schema: crate::ladder::SCHEMA.to_string(), id: "desktop-config-payload".to_string(), version: "1.0.0".to_string(), description: String::new(), role: None, optional: false, optional_warning: None, group: None, constants: BTreeMap::new(), caduceus_commands: Vec::new(), files_root: Some("files_root".to_string()), config_deploy: Some("interactable".to_string()), ladder: Vec::new(), base_dir: scratch.join("module") };
        let request = FileConvergenceRequest { source_root: scratch.join("module/files_root"), target_root: PathBuf::from("/home/owner"), files: vec![FileSpec { relative_path: PathBuf::from(".config/kate/katerc"), mode: Some(0o644) }], backup_existing: false, receipt_name: "desktop-config".to_string(), owner: Some("owner".to_string()), group: None };
        let outcome = FileConvergenceOutcome { ok: true, changed: false, ownership_changed: false, checked: 1, written: 0, backed_up: 0, missing: Vec::new(), missing_target_birth_debts: Vec::new(), entries: Vec::new(), message: String::new() };
        refresh_interactables_at_path(&path, &manifest, &request, &outcome).unwrap();
        let feed = load_feed(&path).unwrap();
        assert_eq!(feed.interactables.len(), 1);
        assert_eq!(feed.interactables[0].target_path, current);
        let _ = fs::remove_dir_all(scratch);
    }
}
