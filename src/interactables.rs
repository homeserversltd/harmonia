use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::path::{Path, PathBuf};

const FEED_SCHEMA: &str = "harmonia.config_proposals.feed.v1";
const DEFAULT_FEED_PATH: &str = "/var/lib/harmonia/interactables.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InteractablesFeed {
    schema: String,
    #[serde(default)]
    pub(crate) interactables: Vec<Interactable>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Interactable {
    pub(crate) id: String,
    pub(crate) module_id: String,
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) description: String,
    pub(crate) kind: String,
    pub(crate) target_path: PathBuf,
    pub(crate) reference_source_path: PathBuf,
    pub(crate) drift: DriftSummary,
    pub(crate) created_at: String,
    pub(crate) refreshed_at: String,
    /// UTC time when this item became available, or was last re-reported.
    /// Legacy rows omit this field and deserialize as null.
    #[serde(default)]
    pub(crate) available_at: Option<String>,
    pub(crate) has_run: bool,
    #[serde(default)]
    pub(crate) mode: Option<u32>,
    #[serde(default)]
    pub(crate) owner: Option<String>,
    #[serde(default)]
    pub(crate) group: Option<String>,
    /// Local source commit compared with `target_sha` for source-shaped items.
    /// File convergence proposals have no source-commit authority, so this
    /// remains null without changing their existing shape.
    #[serde(default)]
    pub(crate) source_sha: Option<String>,
    /// Observed target commit for source-shaped items, when the possession lane
    /// can observe it without a separate source acquisition.
    #[serde(default)]
    pub(crate) target_sha: Option<String>,
    /// Number of commits from `source_sha` to `target_sha`; null means the
    /// source lane did not establish a comparable Git pair.
    #[serde(default)]
    pub(crate) commits_behind: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DriftSummary {
    pub(crate) content: bool,
    pub(crate) mode: bool,
    pub(crate) ownership: bool,
}

fn feed_path() -> PathBuf {
    env::var_os("HARMONIA_INTERACTABLES_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_FEED_PATH))
}

fn stable_id(module_id: &str, target: &Path) -> String {
    let digest = Sha256::digest(format!("{module_id}:{}", target.display()).as_bytes());
    format!("config-proposal-{}", &format!("{digest:x}")[..16])
}

pub(crate) fn make_feed(interactables: Vec<Interactable>) -> InteractablesFeed {
    InteractablesFeed { schema: FEED_SCHEMA.to_string(), interactables }
}

pub(crate) fn load_feed(path: &Path) -> Result<InteractablesFeed, String> {
    let observed_text = crate::atoms::ask::optional_text(path)?;
    match observed_text {
        Some(text) => {
            let feed: InteractablesFeed = serde_json::from_str(&text)
                .map_err(|error| format!("interactables-feed-parse-failed {}: {error}", path.display()))?;
            if feed.schema != FEED_SCHEMA && feed.schema != "harmonia.interactables.feed.v1" {
                return Err(format!("interactables-feed-schema-unsupported {}", feed.schema));
            }
            Ok(InteractablesFeed { schema: FEED_SCHEMA.to_string(), ..feed })
        }
        None => Ok(InteractablesFeed {
            schema: FEED_SCHEMA.to_string(),
            interactables: Vec::new(),
        }),
    }
}

#[cfg(test)]
pub(crate) fn save_feed(path: &Path, feed: &InteractablesFeed) -> Result<(), String> {
    crate::bands::propose_edits::persist_feed(path, feed)
}

pub(crate) fn pending_config_proposal_count() -> usize {
    load_feed(&feed_path()).map(|feed| feed.interactables.len()).unwrap_or(0)
}

pub(crate) fn interactable_command(
    args: &[String],
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("list") => interactable_list(&args[1..]),
        Some("run") | Some("accept") => interactable_run(&args[1..], invocation),
        _ => Err("config-proposal requires list [--json] or accept <id>".to_string()),
    }
}

fn interactable_list(args: &[String]) -> Result<(), String> {
    if args.iter().any(|arg| arg != "--json") {
        return Err("config-proposal list accepts only --json".to_string());
    }
    let feed = load_feed(&feed_path())?;
    if args.iter().any(|arg| arg == "--json") {
        println!("{}", serde_json::to_string_pretty(&feed).map_err(|error| error.to_string())?);
    } else {
        println!("schema={FEED_SCHEMA}");
        println!("proposal_count={}", feed.interactables.len());
        for item in feed.interactables {
            println!("id={} module_id={} kind={} target={}", item.id, item.module_id, item.kind, item.target_path.display());
        }
    }
    Ok(())
}

fn interactable_run(
    args: &[String],
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<(), String> {
    if args.len() != 1 {
        return Err("config-proposal accept requires exactly one <id>".to_string());
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
        invocation,
    )?;
    receipt["has_run"] = serde_json::Value::Bool(true);
    feed.interactables[position].has_run = true;
    feed.interactables.remove(position);
    crate::bands::propose_edits::persist_feed(&path, &feed)?;
    println!("{}", serde_json::to_string_pretty(&receipt).map_err(|error| error.to_string())?);
    Ok(())
}


#[cfg(test)]
fn refresh_interactables_at_path(path: &Path, manifest: &crate::ladder::LadderManifest, request: &crate::tools::files::FileConvergenceRequest, outcome: &crate::tools::files::FileConvergenceOutcome) -> Result<(), String> {
    crate::bands::propose_edits::refresh_interactables_at_path(path, manifest, request, outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ladder::LadderManifest;
    use crate::tools::files::{FileConvergenceOutcome, FileConvergenceRequest, FileSpec};
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
