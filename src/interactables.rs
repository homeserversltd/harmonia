use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const FEED_SCHEMA: &str = "harmonia.config_proposals.feed.v1";
const DEFAULT_FEED_PATH: &str = "/var/lib/harmonia/interactables.json";

pub(crate) struct OperatorHand(());

fn operator_hand() -> OperatorHand {
    OperatorHand(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct InteractablesFeed {
    schema: String,
    #[serde(default)]
    pub(crate) interactables: Vec<Interactable>,
    #[serde(default)]
    pub(crate) receipts: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Recognition-wall evidence. These fields are additive so old feeds remain readable.
    #[serde(default)]
    pub(crate) live_sha: Option<String>,
    #[serde(default)]
    pub(crate) reference_sha: Option<String>,
    #[serde(default)]
    pub(crate) recognition_score: Option<f64>,
    #[serde(default)]
    pub(crate) script: String,
    #[serde(default)]
    pub(crate) show_only_if: String,
    #[serde(default)]
    pub(crate) completion_check: String,
}

/// Compare configuration by meaningful lines, not formatting noise. The score is
/// the shared normalized-line set divided by the known-good/reference set.
pub(crate) fn normalized_line_score(live: &str, reference: &str) -> f64 {
    use std::collections::BTreeSet;
    let lines = |text: &str| -> BTreeSet<String> {
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    };
    let live = lines(live);
    let reference = lines(reference);
    let denominator = reference.len();
    if denominator == 0 {
        0.0
    } else {
        live.intersection(&reference).count() as f64 / denominator as f64
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RecognitionCandidate<'a> {
    pub(crate) reference_id: &'a str,
    pub(crate) bytes: &'a [u8],
}
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RecognitionResult {
    pub(crate) score: f64,
    pub(crate) reference_id: String,
}
pub(crate) fn recognize_against_known_goods(
    live: &[u8],
    candidates: &[RecognitionCandidate<'_>],
) -> Option<RecognitionResult> {
    candidates
        .iter()
        .map(|c| RecognitionResult {
            score: normalized_line_score(
                &String::from_utf8_lossy(live),
                &String::from_utf8_lossy(c.bytes),
            ),
            reference_id: c.reference_id.to_string(),
        })
        .max_by(|a, b| {
            a.score
                .total_cmp(&b.score)
                .then_with(|| b.reference_id.cmp(&a.reference_id))
        })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

pub(crate) fn make_feed(interactables: Vec<Interactable>) -> InteractablesFeed {
    InteractablesFeed {
        schema: FEED_SCHEMA.to_string(),
        interactables,
        receipts: Vec::new(),
    }
}

pub(crate) fn load_feed(path: &Path) -> Result<InteractablesFeed, String> {
    let observed_text = crate::atoms::ask::optional_text(path)?;
    match observed_text {
        Some(text) => {
            let feed: InteractablesFeed = serde_json::from_str(&text).map_err(|error| {
                format!(
                    "interactables-feed-parse-failed {}: {error}",
                    path.display()
                )
            })?;
            if feed.schema != FEED_SCHEMA && feed.schema != "harmonia.interactables.feed.v1" {
                return Err(format!(
                    "interactables-feed-schema-unsupported {}",
                    feed.schema
                ));
            }
            Ok(InteractablesFeed {
                schema: FEED_SCHEMA.to_string(),
                ..feed
            })
        }
        None => Ok(InteractablesFeed {
            schema: FEED_SCHEMA.to_string(),
            interactables: Vec::new(),
            receipts: Vec::new(),
        }),
    }
}

pub(crate) fn pending_config_proposal_count() -> usize {
    load_feed(&feed_path())
        .map(|feed| feed.interactables.len())
        .unwrap_or(0)
}

pub(crate) fn interactable_command(
    args: &[String],
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("list") => interactable_list(&args[1..]),
        Some("run") | Some("accept") | Some("swap") => interactable_run(&args[1..], invocation),
        _ => Err("config-proposal requires list [--json] or accept <id> owner".to_string()),
    }
}

fn interactable_list(args: &[String]) -> Result<(), String> {
    if args.iter().any(|arg| arg != "--json") {
        return Err("config-proposal list accepts only --json".to_string());
    }
    let feed = load_feed(&feed_path())?;
    if args.iter().any(|arg| arg == "--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&feed).map_err(|error| error.to_string())?
        );
    } else {
        println!("schema={FEED_SCHEMA}");
        println!("proposal_count={}", feed.interactables.len());
        for item in feed.interactables {
            println!(
                "id={} module_id={} kind={} target={}",
                item.id,
                item.module_id,
                item.kind,
                item.target_path.display()
            );
        }
    }
    Ok(())
}

fn interactable_run(
    args: &[String],
    _invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<(), String> {
    if args.len() != 2 || args[1] != "owner" {
        return Err("config-proposal accept requires exactly <interactable-id> owner".to_string());
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
    crate::atoms::files::validate_interactable_target(&item.target_path)?;
    if !item.reference_source_path.is_file() {
        return Err(format!(
            "interactable-reference-source-missing {}",
            item.reference_source_path.display()
        ));
    }
    let target_metadata = fs::symlink_metadata(&item.target_path).map_err(|error| {
        format!(
            "interactable-target-stat-failed {}: {error}",
            item.target_path.display()
        )
    })?;
    if !target_metadata.file_type().is_file() {
        return Err(format!(
            "interactable-target-not-regular-file {}",
            item.target_path.display()
        ));
    }
    let desired_uid = item
        .owner
        .as_deref()
        .map(crate::atoms::files::resolve_uid)
        .transpose()?
        .unwrap_or_else(|| target_metadata.uid());
    let desired_gid = item
        .group
        .as_deref()
        .map(crate::atoms::files::resolve_gid)
        .transpose()?
        .unwrap_or_else(|| target_metadata.gid());
    let desired_mode = item
        .mode
        .or_else(|| crate::atoms::files::source_mode(&item.reference_source_path).ok())
        .ok_or_else(|| "interactable-reference-source-mode-failed".to_string())?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().to_string())
        .unwrap_or_else(|_| "0".to_string());
    let backup = backup_root.join(&item.id).join(format!(
        "{}-{}",
        stamp,
        item.target_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("target")
    ));
    let desired_bytes = fs::read(&item.reference_source_path).map_err(|error| {
        format!(
            "interactable-reference-source-read-failed {}: {error}",
            item.reference_source_path.display()
        )
    })?;
    let projectio_receipt = crate::atoms::projectio::strike(crate::atoms::projectio::Request {
        target: &item.target_path,
        desired_bytes: &desired_bytes,
        mode: desired_mode,
        uid: desired_uid,
        gid: desired_gid,
        backup_path: &backup,
        witness: crate::atoms::projectio::owner_acceptance(operator_hand()),
    })?;
    let mut receipt = serde_json::json!({
        "schema": "harmonia.interactables.hard_stamp.receipt.v1",
        "ok": true,
        "id": item.id.clone(),
        "kind": "hard-stamp",
        "backup_path": projectio_receipt.backup_path.clone(),
        "backed_up_to": projectio_receipt.backup_path.clone(),
        "before_sha256": projectio_receipt.before_sha256.clone(),
        "reference_sha256": projectio_receipt.struck_sha256.clone(),
        "target_sha256": projectio_receipt.target_sha256.clone(),
        "target": item.target_path.clone(),
        "reference_source": item.reference_source_path.clone(),
        "changed": true,
    });
    receipt["has_run"] = serde_json::Value::Bool(true);
    receipt["config_state"] = serde_json::Value::String("interactable".into());
    feed.interactables[position].has_run = true;
    feed.receipts.push(serde_json::json!({
        "schema": "harmonia.config_state.receipt.v1",
        "config_state": "interactable",
        "id": item.id,
        "target": item.target_path,
        "reference_id": item.reference_source_path,
        "score": item.recognition_score,
        "actuator": receipt.clone(),
    }));
    feed.interactables.remove(position);
    crate::bands::propose_edits::persist_feed(&path, &feed)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&receipt).map_err(|error| error.to_string())?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};

    static INTERACTABLES_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    #[test]
    fn recognition_wall_uses_known_good_line_denominator() {
        assert_eq!(normalized_line_score(" a \n\n b\n", "a\nb\nc\n"), 2.0 / 3.0);
        assert_eq!(normalized_line_score("one", "two"), 0.0);
        assert_eq!(normalized_line_score("\n \n", ""), 0.0);
    }

    #[test]
    fn recognition_uses_maximum_known_good_and_reference_id_tie_break() {
        let candidates = [
            RecognitionCandidate {
                reference_id: "zeta",
                bytes: b"a\nb\n",
            },
            RecognitionCandidate {
                reference_id: "alpha",
                bytes: b"a\nb\n",
            },
            RecognitionCandidate {
                reference_id: "middle",
                bytes: b"unrelated\n",
            },
        ];
        let result = recognize_against_known_goods(b"a\nb\n", &candidates).unwrap();
        assert_eq!(result.score, 1.0);
        assert_eq!(result.reference_id, "alpha");
    }

    #[test]
    fn fixture_recognition_cases_straddle_wall() {
        let reference = include_str!("../tests/fixtures/harmonia/known-good.conf");
        let above = include_str!("../tests/fixtures/harmonia/live-above-wall.conf");
        let below = include_str!("../tests/fixtures/harmonia/live-below-wall.conf");
        assert!(normalized_line_score(above, reference) >= 0.33);
        assert!(normalized_line_score(below, reference) < 0.33);
    }

    fn fixture(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "harmonia-interactable-accept-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn item(root: &std::path::Path) -> Interactable {
        Interactable {
            id: "config-proposal-accept-regression".into(),
            module_id: "regression".into(),
            name: "config proposal acceptance".into(),
            description: String::new(),
            kind: "hard-stamp".into(),
            target_path: root.join("config_deploy:interactable/target.conf"),
            reference_source_path: root.join("source.conf"),
            drift: DriftSummary {
                content: true,
                mode: false,
                ownership: false,
            },
            created_at: "0".into(),
            refreshed_at: "0".into(),
            available_at: None,
            has_run: false,
            mode: Some(0o644),
            owner: None,
            group: None,
            source_sha: None,
            target_sha: None,
            commits_behind: None,
            live_sha: None,
            reference_sha: None,
            recognition_score: None,
            script: String::new(),
            show_only_if: String::new(),
            completion_check: String::new(),
        }
    }

    #[test]
    fn config_proposal_accept_stamps_target_with_backup_and_readback() {
        let root = fixture("operator");
        let feed_path = root.join("interactables.json");
        let target = root.join("config_deploy:interactable/target.conf");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(root.join("source.conf"), b"desired\n").unwrap();
        fs::write(&target, b"current\n").unwrap();
        let proposal = item(&root);
        assert!(matches!(
            crate::atoms::files::classify_target(&target),
            crate::atoms::files::TargetClass::Config
        ));
        crate::bands::propose_edits::persist_feed(&feed_path, &make_feed(vec![proposal.clone()]))
            .unwrap();

        let _env_lock = INTERACTABLES_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap();
        let prior_feed = std::env::var_os("HARMONIA_INTERACTABLES_PATH");
        std::env::set_var("HARMONIA_INTERACTABLES_PATH", &feed_path);
        let backup_root = feed_path
            .parent()
            .unwrap()
            .join("interactables-backups/config-proposal-accept-regression");
        assert!(interactable_run(&[proposal.id.clone()], None).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"current\n");
        assert_eq!(load_feed(&feed_path).unwrap().interactables.len(), 1);
        assert!(!backup_root.exists());
        assert!(interactable_run(&[proposal.id.clone(), "not-owner".into()], None).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"current\n");
        assert_eq!(load_feed(&feed_path).unwrap().interactables.len(), 1);
        assert!(!backup_root.exists());
        let result = interactable_run(&[proposal.id.clone(), "owner".into()], None);
        match prior_feed {
            Some(value) => std::env::set_var("HARMONIA_INTERACTABLES_PATH", value),
            None => std::env::remove_var("HARMONIA_INTERACTABLES_PATH"),
        }
        result.unwrap();
        let final_feed = load_feed(&feed_path).unwrap();
        let receipt = final_feed.receipts.last().unwrap();
        assert_eq!(
            receipt
                .get("config_state")
                .and_then(serde_json::Value::as_str),
            Some("interactable")
        );
        assert_eq!(
            receipt.get("id").and_then(serde_json::Value::as_str),
            Some(proposal.id.as_str())
        );
        assert_eq!(
            receipt
                .get("actuator")
                .and_then(serde_json::Value::as_object)
                .and_then(|v| v.get("has_run"))
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        let backup_dir = fs::read_dir(&backup_root).unwrap();
        let backups: Vec<_> = backup_dir.map(|entry| entry.unwrap().path()).collect();
        assert_eq!(backups.len(), 1);
        assert_eq!(fs::read(&backups[0]).unwrap(), b"current\n");
        assert_eq!(fs::read(&target).unwrap(), b"desired\n");
        assert!(load_feed(&feed_path).unwrap().interactables.is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}
