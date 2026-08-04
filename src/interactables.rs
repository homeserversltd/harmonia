use crate::ladder::LadderManifest;
use crate::tools::files::{FileConvergenceOutcome, FileConvergenceRequest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
    description: String,
    kind: String,
    target_path: PathBuf,
    reference_source_path: PathBuf,
    drift: DriftSummary,
    created_at: String,
    refreshed_at: String,
    has_run: bool,
    #[serde(default)]
    mode: Option<u32>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    group: Option<String>,
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
    crate::write_json(path, &value)
}

pub(crate) fn refresh_interactables_for_convergence(
    manifest: &LadderManifest,
    request: &FileConvergenceRequest,
    outcome: &FileConvergenceOutcome,
) -> Result<(), String> {
    let path = feed_path();
    let mut feed = load_feed(&path)?;
    let now = stamp();
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
            has_run: false,
            mode: entry.final_mode,
            owner: request.owner.clone(),
            group: request.group.clone(),
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
