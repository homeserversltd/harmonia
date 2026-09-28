use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) const FEED_SCHEMA: &str = "harmonia.config_proposals.feed.v1";
pub(crate) const LEGACY_FEED_SCHEMA: &str = "harmonia.interactables.feed.v1";
const DEFAULT_FEED_PATH: &str = "/var/lib/harmonia/interactables.json";

pub(crate) fn is_ruyi_born_kind(kind: &str) -> bool {
    matches!(kind, "ruyi-bump" | "dns-record" | "toolchain-ratchet")
}

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
    #[serde(flatten)]
    pub(crate) extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Interactable {
    pub(crate) id: String,
    pub(crate) module_id: String,
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) description: String,
    pub(crate) kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) target_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reference_source_path: Option<PathBuf>,
    pub(crate) drift: DriftSummary,
    pub(crate) created_at: String,
    pub(crate) refreshed_at: String,
    /// UTC time when this item became available, or was last re-reported.
    /// Legacy rows omit this field and deserialize as null.
    #[serde(default)]
    pub(crate) available_at: Option<String>,
    #[serde(default)]
    pub(crate) silenced: bool,
    #[serde(default)]
    pub(crate) silenced_at: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) diff: Option<String>,
    #[serde(default)]
    pub(crate) script: String,
    #[serde(default)]
    pub(crate) show_only_if: String,
    #[serde(default)]
    pub(crate) completion_check: String,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub(crate) evidence: serde_json::Value,
    #[serde(flatten)]
    pub(crate) extra: serde_json::Map<String, serde_json::Value>,
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
        extra: serde_json::Map::new(),
    }
}

pub(crate) fn load_feed(path: &Path) -> Result<InteractablesFeed, String> {
    let mut feed = load_feed_raw(path)?;
    feed.interactables
        .retain(|item| item.kind != "engine-replacement");
    Ok(feed)
}

pub(crate) fn ruyi_born_proposals() -> Result<Vec<Value>, String> {
    let feed = load_feed(&feed_path())?;
    Ok(feed
        .interactables
        .iter()
        .filter(|item| is_ruyi_born_kind(&item.kind))
        .map(|item| {
            serde_json::json!({
                "id": item.id.clone(),
                "kind": item.kind.clone(),
                "name": item.name.clone(),
                "description": item.description.clone(),
                "evidence": item.evidence.clone(),
                "refreshed_at": item.refreshed_at.clone(),
                "silenced": item.silenced
            })
        })
        .collect())
}

pub(crate) fn load_feed_raw(path: &Path) -> Result<InteractablesFeed, String> {
    let observed_text = crate::atoms::ask::optional_text(path)?;
    match observed_text {
        Some(text) => {
            let raw: Value = serde_json::from_str(&text).map_err(|error| {
                format!(
                    "interactables-feed-parse-failed {}: {error}",
                    path.display()
                )
            })?;
            let feed: InteractablesFeed = serde_json::from_value(raw.clone()).map_err(|error| {
                format!(
                    "interactables-feed-parse-failed {}: {error}",
                    path.display()
                )
            })?;
            if feed.schema != FEED_SCHEMA && feed.schema != LEGACY_FEED_SCHEMA {
                return Err(format!(
                    "interactables-feed-schema-unsupported {}",
                    feed.schema
                ));
            }
            if let Ok(seat) = &crate::atoms::ask::mint_seats::interactables_at_start().feed {
                let mut compatible = raw;
                if let Some(rows) = compatible
                    .get_mut("interactables")
                    .and_then(serde_json::Value::as_array_mut)
                {
                    rows.retain(|row| {
                        row.get("kind").and_then(serde_json::Value::as_str)
                            != Some("engine-replacement")
                    });
                }
                seat.validate_compatible(&compatible, &[LEGACY_FEED_SCHEMA])?;
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
            extra: serde_json::Map::new(),
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
    invocation: Option<&crate::Invocation>,
) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("list") => interactable_list(&args[1..]),
        Some("inspect") => interactable_inspect(&args[1..]),
        Some("silence") => interactable_set_silenced(&args[1..], true),
        Some("unsilence") => interactable_set_silenced(&args[1..], false),
        Some("run") | Some("accept") | Some("swap") => interactable_run(&args[1..], invocation),
        _ => Err(
            "interactable requires list [--json] [--silenced], inspect <id> [--json], run <id>, silence <id>, or unsilence <id>".to_string(),
        ),
    }
}

fn interactable_list(args: &[String]) -> Result<(), String> {
    if args
        .iter()
        .any(|arg| arg != "--json" && arg != "--silenced")
    {
        return Err("config-proposal list accepts only --json and --silenced".to_string());
    }
    let feed = load_feed(&feed_path())?;
    let silenced = args.iter().any(|arg| arg == "--silenced");
    let mut filtered_feed = feed.clone();
    filtered_feed.interactables = feed
        .interactables
        .iter()
        .filter(|item| item.silenced == silenced)
        .cloned()
        .collect();
    if args.iter().any(|arg| arg == "--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&filtered_feed).map_err(|error| error.to_string())?
        );
    } else {
        println!("schema={FEED_SCHEMA}");
        println!("proposal_count={}", filtered_feed.interactables.len());
        for item in filtered_feed.interactables {
            println!(
                "id={} module_id={} kind={} target={} name={} evidence={}",
                item.id,
                item.module_id,
                item.kind,
                item.target_path
                    .as_deref()
                    .map(Path::display)
                    .map(|path| path.to_string())
                    .unwrap_or_default(),
                item.name,
                serde_json::to_string(&item.evidence).map_err(|error| error.to_string())?
            );
        }
    }
    Ok(())
}

fn interactable_set_silenced(args: &[String], silenced: bool) -> Result<(), String> {
    if args.len() != 1 {
        return Err(format!(
            "interactable {} requires exactly one <id>",
            if silenced { "silence" } else { "unsilence" }
        ));
    }
    let path = feed_path();
    let mut feed = load_feed(&path)?;
    let item = feed
        .interactables
        .iter_mut()
        .find(|item| item.id == args[0])
        .ok_or_else(|| format!("interactable-unknown-id {}", args[0]))?;
    item.silenced = silenced;
    item.silenced_at = if silenced {
        Some(crate::bands::propose_edits::iso8601_now())
    } else {
        None
    };
    let item = item.clone();
    crate::bands::propose_edits::persist_feed_with_intent(
        &path,
        crate::bands::propose_edits::FeedPersistenceIntent::Upsert {
            entries: vec![item],
            remove_ids: BTreeSet::new(),
            sort_by_id: false,
        },
    )
    .map(|_| ())
}

fn interactable_inspect(args: &[String]) -> Result<(), String> {
    let (id, json) = match args {
        [id] => (id, false),
        [id, flag] if flag == "--json" => (id, true),
        _ => {
            return Err(
                "interactable inspect requires exactly <id> followed optionally by --json"
                    .to_string(),
            )
        }
    };
    let feed = load_feed(&feed_path())?;
    let item = feed
        .interactables
        .iter()
        .find(|item| item.id == id.as_str())
        .ok_or_else(|| format!("interactable-unknown-id {id}"))?;
    let diff = item
        .diff
        .as_deref()
        .ok_or_else(|| format!("interactable-diff-absent {id}"))?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(item).map_err(|error| error.to_string())?
        );
    } else {
        print!("{diff}");
    }
    Ok(())
}

fn interactable_run(
    args: &[String],
    invocation: Option<&crate::Invocation>,
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
    match item.kind.as_str() {
        "ruyi-bump" => return run_ruyi_bump(&path, &mut feed, position, &item),
        "toolchain-ratchet" => {
            return run_toolchain_ratchet(&path, &mut feed, position, &item, invocation)
        }
        "dns-record" => {
            return run_dns_record(
                &path,
                &mut feed,
                position,
                &item,
                invocation.and_then(crate::Invocation::key),
            )
        }
        "hard-stamp" => {}
        _ => return Err(format!("interactable-kind-unsupported {}", item.kind)),
    }
    let backup_root = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("interactables-backups");
    let target_path = item
        .target_path
        .as_deref()
        .ok_or_else(|| "interactable-target-path-absent".to_string())?;
    let reference_source_path = item
        .reference_source_path
        .as_deref()
        .ok_or_else(|| "interactable-reference-source-absent".to_string())?;
    crate::atoms::files::validate_interactable_target(target_path)?;
    if !reference_source_path.is_file() {
        return Err(format!(
            "interactable-reference-source-missing {}",
            reference_source_path.display()
        ));
    }
    let target_metadata = fs::symlink_metadata(target_path).map_err(|error| {
        format!(
            "interactable-target-stat-failed {}: {error}",
            target_path.display()
        )
    })?;
    if !target_metadata.file_type().is_file() {
        return Err(format!(
            "interactable-target-not-regular-file {}",
            target_path.display()
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
        .or_else(|| crate::atoms::files::source_mode(reference_source_path).ok())
        .ok_or_else(|| "interactable-reference-source-mode-failed".to_string())?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().to_string())
        .unwrap_or_else(|_| "0".to_string());
    let backup = backup_root.join(&item.id).join(format!(
        "{}-{}",
        stamp,
        target_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("target")
    ));
    let desired_bytes = fs::read(reference_source_path).map_err(|error| {
        format!(
            "interactable-reference-source-read-failed {}: {error}",
            reference_source_path.display()
        )
    })?;
    let projectio_receipt = crate::atoms::projectio::strike(crate::atoms::projectio::Request {
        target: target_path,
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
    let feed_receipt = serde_json::json!({
        "schema": "harmonia.config_state.receipt.v1",
        "config_state": "interactable",
        "id": item.id,
        "target": item.target_path,
        "reference_id": item.reference_source_path,
        "score": item.recognition_score,
        "actuator": receipt.clone(),
    });
    crate::bands::propose_edits::persist_feed_with_intent(
        &path,
        crate::bands::propose_edits::FeedPersistenceIntent::Remove {
            ids: [item.id.clone()].into_iter().collect(),
            receipts: vec![feed_receipt],
        },
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&receipt).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn term_state(newest: Option<&str>, wears: Option<&str>) -> &'static str {
    match (newest, wears) {
        (Some(a), Some(b)) if a == b => "same",
        (Some(_), Some(_)) => "older",
        _ => "unknown",
    }
}

fn member_source<'a>(row: &'a serde_json::Value, name: &str) -> Option<&'a str> {
    row.pointer(&format!("/member_flags/{name}/source_sha"))
        .and_then(serde_json::Value::as_str)
}

fn has_member_flag(row: &serde_json::Value, name: &str) -> bool {
    row.pointer(&format!("/member_flags/{name}"))
        .is_some_and(|flag| flag.is_object() || flag.is_string())
}

fn face_source<'a>(row: &'a serde_json::Value, member: &str) -> Option<&'a str> {
    member_source(row, member)
}

fn canonical_dns_name(value: &str) -> Option<String> {
    let name = value.strip_suffix('.').unwrap_or(value);
    (!name.is_empty()
        && !name.ends_with('.')
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        }))
    .then(|| format!("{name}."))
}

fn parse_toolchain_version(value: &str) -> Option<[u64; 3]> {
    let components = value.split('.').collect::<Vec<_>>();
    if components.len() != 3
        || components.iter().any(|component| {
            component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return None;
    }
    Some([
        components[0].parse().ok()?,
        components[1].parse().ok()?,
        components[2].parse().ok()?,
    ])
}

fn rustup_list_flags(line: &str) -> Option<(&str, Vec<&str>)> {
    let (toolchain, flags) = line.trim().split_once('(')?;
    let flags = flags.strip_suffix(')')?;
    let toolchain = toolchain.trim();
    if toolchain.is_empty() {
        return None;
    }
    Some((
        toolchain,
        flags
            .split(',')
            .map(str::trim)
            .filter(|flag| !flag.is_empty())
            .collect(),
    ))
}

fn rustup_toolchain_matches_watermark(toolchain: &str, watermark: &str) -> bool {
    toolchain == watermark
        || toolchain
            .strip_prefix(watermark)
            .is_some_and(|suffix| suffix.starts_with('-'))
}

pub(crate) fn reconcile_ruyi(
    profile: &crate::Profile,
    self_row: &serde_json::Value,
    roster: &serde_json::Value,
    staves: &[serde_json::Value],
    is_gateway: bool,
) -> Result<Vec<String>, String> {
    let path = feed_path();
    let mut feed = load_feed(&path)?;
    let created = feed
        .interactables
        .iter()
        .filter(|item| is_ruyi_born_kind(&item.kind))
        .map(|item| (item.id.clone(), item.created_at.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    let unknown = feed
        .interactables
        .iter()
        .filter(|item| is_ruyi_born_kind(&item.kind))
        .map(|item| (item.id.clone(), item.extra.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    let remove_ids = feed
        .interactables
        .iter()
        .filter(|item| is_ruyi_born_kind(&item.kind))
        .map(|item| item.id.clone())
        .collect::<BTreeSet<_>>();
    feed.interactables
        .retain(|item| !is_ruyi_born_kind(&item.kind));
    let module = profile
        .caduceus_module_id()
        .ok_or_else(|| "ruyi-caduceus-module-absent".to_string())?;
    let self_mac = self_row.get("mac").and_then(serde_json::Value::as_str);
    let declaration = profile.syzygy_declaration.as_ref();
    let compare_sbin = declaration
        .is_some_and(|declaration| declaration.members.iter().any(|member| member == "sbin"));
    let face_name = declaration
        .and_then(|declaration| {
            let face = declaration.gui_face.as_deref()?;
            let member = face.to_ascii_lowercase();
            declaration
                .members
                .iter()
                .any(|declared| declared == &member)
                .then_some(member)
        })
        .filter(|face| matches!(face.as_str(), "arcadia" | "coronatio"));
    let newest = [
        self_row
            .get("caduceus_sha")
            .and_then(serde_json::Value::as_str),
        member_source(self_row, "sbin"),
        face_name
            .as_deref()
            .and_then(|member| face_source(self_row, member)),
    ];
    let now = now_seconds();
    let mut held_back_by = Vec::new();
    for peer in staves {
        let Some(mac) = peer.get("mac").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if Some(mac) == self_mac {
            continue;
        }
        let peer_view = peer
            .pointer("/perspective/self")
            .or_else(|| roster.pointer(&format!("/perspectives/{mac}/self")));
        let peer_caduceus = peer.get("caduceus_sha").and_then(serde_json::Value::as_str);
        let compare_peer_sbin =
            compare_sbin && peer_view.is_some_and(|row| has_member_flag(row, "sbin"));
        let peer_face_name = peer_view
            .and_then(|row| row.get("gui_face"))
            .and_then(serde_json::Value::as_str);
        let compare_peer_face = face_name.as_deref().is_some_and(|member| {
            peer_face_name.is_some_and(|peer_face| {
                peer_face.eq_ignore_ascii_case(member)
                    && peer_view.is_some_and(|row| has_member_flag(row, member))
            })
        });
        let wears = [
            peer_caduceus,
            compare_peer_sbin
                .then(|| peer_view.and_then(|row| member_source(row, "sbin")))
                .flatten(),
            compare_peer_face
                .then(|| {
                    peer_view.and_then(|row| {
                        face_name
                            .as_deref()
                            .and_then(|member| face_source(row, member))
                    })
                })
                .flatten(),
        ];
        let terms = [
            term_state(newest[0], wears[0]),
            if compare_peer_sbin {
                term_state(newest[1], wears[1])
            } else {
                "not-compared"
            },
            if compare_peer_face {
                term_state(newest[2], wears[2])
            } else {
                "not-compared"
            },
        ];
        if terms
            .iter()
            .all(|term| *term == "same" || *term == "not-compared")
        {
            continue;
        }
        let hostname = peer
            .get("hostname")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let canonical_name = peer
            .get("canonical_name")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let last_checked = peer.get("last_seen").and_then(serde_json::Value::as_u64);
        let last_event_age_s = last_checked.map(|last| now.saturating_sub(last));
        let last_event_age = last_event_age_s
            .map(|age| format!("{age}s"))
            .unwrap_or_else(|| "unknown".to_string());
        let description = format!(
            "For {hostname} {mac}, the worn terms are (caduceus={}, sbin={}, face={}), the newest terms are (caduceus={}, sbin={}, face={}), the compared-term states are (caduceus={}, sbin={}, face={}), and the last-event age is {last_event_age}.",
            wears[0].unwrap_or("unknown"),
            wears[1].unwrap_or("not-compared"),
            wears[2].unwrap_or("not-compared"),
            newest[0].unwrap_or("unknown"),
            if compare_peer_sbin { newest[1].unwrap_or("unknown") } else { "not-compared" },
            if compare_peer_face { newest[2].unwrap_or("unknown") } else { "not-compared" },
            terms[0],
            terms[1],
            terms[2],
        );
        let id = format!("ruyi-bump-{}", mac.replace(':', ""));
        held_back_by.push(mac.to_string());
        feed.interactables.push(Interactable {
            id: id.clone(),
            module_id: module.to_string(),
            name: format!("{hostname} {mac}"),
            description,
            kind: "ruyi-bump".into(),
            target_path: None,
            reference_source_path: None,
            drift: DriftSummary {
                content: true,
                mode: false,
                ownership: false,
            },
            created_at: created.get(&id).cloned().unwrap_or_else(|| now.to_string()),
            refreshed_at: now.to_string(),
            available_at: None,
            silenced: false,
            silenced_at: None,
            has_run: false,
            mode: None,
            owner: None,
            group: None,
            source_sha: None,
            target_sha: None,
            commits_behind: None,
            live_sha: None,
            reference_sha: None,
            recognition_score: None,
            diff: None,
            script: format!("harmonia interactable run {id}"),
            show_only_if: String::new(),
            completion_check: String::new(),
            evidence: serde_json::json!({
                "mac": mac, "hostname": hostname, "canonical_name": canonical_name,
                "wears": {"caduceus": wears[0], "sbin": wears[1], "face": wears[2]},
                "newest": {"caduceus": newest[0], "sbin": newest[1], "face": newest[2]},
                "terms": {"caduceus": terms[0], "sbin": terms[1], "face": terms[2]},
                "last_checked_in_at": last_checked,
                "last_event_age_s": last_event_age_s
            }),
            extra: unknown.get(&id).cloned().unwrap_or_default(),
        });
    }
    let installed = crate::atoms::command::capture("rustc", &["-Vv"]);
    let installed_version = installed
        .ok
        .then(|| {
            installed.stdout.lines().find_map(|line| {
                line.strip_prefix("release:")
                    .map(str::trim)
                    .map(str::to_owned)
            })
        })
        .flatten();
    let rustup_lane = profile
        .modules
        .iter()
        .any(|module| module == "rust-build-toolchain")
        && Path::new("/opt/rustup").is_dir();
    let lane = if profile
        .package_authority
        .as_ref()
        .is_some_and(|authority| authority.package_manager == "pacman")
    {
        "pacman"
    } else if rustup_lane {
        "rustup"
    } else {
        "none"
    };
    let flag_watermark = self_row
        .get("member_flags")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flat_map(|flags| flags.iter())
        .filter_map(|(component, flag)| {
            // Both provenance and version belong to the nested release flag;
            // never infer either from the enclosing member's worn build.
            let source_sha = flag.pointer("/release_flag/source_sha")?.as_str()?;
            let version = flag.pointer("/release_flag/rustc_version")?.as_str()?;
            let parsed = parse_toolchain_version(version)?;
            Some((
                parsed,
                version.to_owned(),
                component.clone(),
                source_sha.to_owned(),
            ))
        })
        .max_by(|left, right| left.0.cmp(&right.0).then_with(|| right.2.cmp(&left.2)));
    if let (Some((watermark, watermark_version, component, source_sha)), Some(installed_version)) =
        (flag_watermark, installed_version)
    {
        if let Some(installed_parsed) = parse_toolchain_version(&installed_version) {
            if installed_parsed < watermark && lane != "none" {
                let id = "toolchain-ratchet".to_string();
                let plan = if lane == "rustup" {
                    "rustup-climb"
                } else {
                    "pacman-evidence"
                };
                let witness = serde_json::json!({
                    "component": component,
                    "source_sha": source_sha,
                    "mac": self_mac,
                });
                feed.interactables.push(Interactable {
                    id: id.clone(),
                    module_id: if lane == "rustup" {
                        "rust-build-toolchain".to_string()
                    } else {
                        module.to_string()
                    },
                    name: "Ratchet this body's Rust toolchain".into(),
                    description: format!("Installed rustc {installed_version} is below release watermark {watermark_version} ({component} {source_sha})."),
                    kind: "toolchain-ratchet".into(),
                    target_path: None,
                    reference_source_path: None,
                    drift: DriftSummary { content: true, mode: false, ownership: false },
                    created_at: created.get(&id).cloned().unwrap_or_else(|| now.to_string()),
                    refreshed_at: now.to_string(), available_at: None, silenced: false,
                    silenced_at: None, has_run: false, mode: None, owner: None, group: None,
                    source_sha: None, target_sha: None, commits_behind: None,
                    live_sha: None, reference_sha: None, recognition_score: None, diff: None,
                    script: format!("harmonia interactable run {id}"),
                    show_only_if: String::new(), completion_check: String::new(),
                    evidence: serde_json::json!({
                        "installed": installed_version,
                        "watermark": watermark_version,
                        "witness": witness,
                        "lane": lane,
                        "plan": plan,
                    }),
                    extra: unknown.get(&id).cloned().unwrap_or_default(),
                });
            }
        }
    }
    if is_gateway {
        if let Some(unresolved) = roster
            .get("dns_unresolved")
            .and_then(serde_json::Value::as_array)
        {
            let dns_module = profile.dns_module_id().unwrap_or(module);
            for entry in unresolved {
                let Some(hostname) = entry.get("hostname").and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                let Some(canonical) = entry
                    .get("canonical_name")
                    .and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                let Some(ipv4) = entry.get("ipv4").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                let Some(canonical) = canonical_dns_name(canonical) else {
                    continue;
                };
                if ipv4.parse::<std::net::Ipv4Addr>().is_err()
                    || hostname.contains('/')
                    || hostname.contains('\\')
                    || hostname.contains('\n')
                    || hostname.contains('\r')
                {
                    continue;
                }
                let record = format!("local-data: \"{canonical} IN A {ipv4}\"");
                let id = format!("dns-record-{hostname}");
                feed.interactables.push(Interactable {
                    id: id.clone(),
                    module_id: dns_module.to_string(),
                    name: format!("Add DNS record for {hostname}"),
                    description: format!(
                        "Add the validated home.arpa address for {hostname} to Unbound."
                    ),
                    kind: "dns-record".into(),
                    target_path: None,
                    reference_source_path: None,
                    drift: DriftSummary {
                        content: true,
                        mode: false,
                        ownership: false,
                    },
                    created_at: created.get(&id).cloned().unwrap_or_else(|| now.to_string()),
                    refreshed_at: now.to_string(),
                    available_at: None,
                    silenced: false,
                    silenced_at: None,
                    has_run: false,
                    mode: None,
                    owner: None,
                    group: None,
                    source_sha: None,
                    target_sha: None,
                    commits_behind: None,
                    live_sha: None,
                    reference_sha: None,
                    recognition_score: None,
                    diff: None,
                    script: format!("harmonia interactable run {id}"),
                    show_only_if: String::new(),
                    completion_check: String::new(),
                    evidence: serde_json::json!({"mac": entry.get("mac"), "hostname": hostname,
                        "canonical_name": canonical, "ipv4": ipv4, "record": record}),
                    extra: unknown.get(&id).cloned().unwrap_or_default(),
                });
            }
        }
    }
    feed.interactables.sort_by(|a, b| a.id.cmp(&b.id));
    let entries = feed
        .interactables
        .iter()
        .filter(|item| is_ruyi_born_kind(&item.kind))
        .cloned()
        .collect();
    crate::bands::propose_edits::persist_feed_with_intent(
        &path,
        crate::bands::propose_edits::FeedPersistenceIntent::Upsert {
            entries,
            remove_ids,
            sort_by_id: true,
        },
    )?;
    Ok(held_back_by)
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn run_ruyi_bump(
    path: &Path,
    _feed: &mut InteractablesFeed,
    _position: usize,
    item: &Interactable,
) -> Result<(), String> {
    let Some(port) = crate::bands::stage_profile::read_device_caduceus_seat_port()? else {
        eprintln!("ruyi-seat-undeclared");
        return Err("ruyi-seat-undeclared".into());
    };
    let mac = item
        .evidence
        .get("mac")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "ruyi-bump-mac-absent".to_string())?;
    let hostname = item
        .evidence
        .get("hostname")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "ruyi-bump-hostname-absent".to_string())?;
    let perspective = crate::atoms::ask::ruyi::read_perspective()?;
    let self_row = perspective
        .get("self")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let host = crate::atoms::ask::ruyi::registrant::routed_host(&self_row)?;
    let (seat_reply, status) =
        crate::atoms::ask::beam::delete(&format!("http://{host}:{port}/api/v1/ruyi/{mac}"))
            .map_err(|error| {
                eprintln!("{error} id={}", item.id);
                error
            })?;
    if !(200..300).contains(&status) && status != 404 {
        eprintln!("ruyi-bump-seat-refused id={} status={status}", item.id);
        return Err(format!("ruyi-bump-seat-refused-{status}"));
    }
    let seat_reply = serde_json::from_str::<serde_json::Value>(&seat_reply)
        .unwrap_or_else(|_| serde_json::json!(seat_reply));
    let receipt = serde_json::json!({
        "schema": crate::atoms::ask::mint_seats::RUYI_BUMP_RECEIPT,
        "ok": true, "id": item.id, "mac": mac, "hostname": hostname,
        "seat_reply": seat_reply, "at": now_seconds()
    });
    if let Ok(seat) = &crate::atoms::ask::mint_seats::interactables_at_start().ruyi_bump_receipt {
        seat.validate(&receipt)?;
    }
    crate::bands::propose_edits::persist_feed_with_intent(
        path,
        crate::bands::propose_edits::FeedPersistenceIntent::Remove {
            ids: [item.id.clone()].into_iter().collect(),
            receipts: vec![receipt.clone()],
        },
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&receipt).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn persist_toolchain_preflight_refusal(
    path: &Path,
    item: &Interactable,
    reason: String,
    observed: Value,
) -> Result<(), String> {
    let receipt_observed = observed.clone();
    let before = item.evidence.get("installed").cloned().unwrap_or(Value::Null);
    let readback = observed.pointer("/readback").cloned().unwrap_or(Value::Null);
    let observed_release = observed.pointer("/readback/release").cloned().unwrap_or(Value::Null);
    let receipt = serde_json::json!({
        "schema": "harmonia.config_state.receipt.v1",
        "config_state": "interactable",
        "id": item.id,
        "target": null,
        "reference_id": null,
        "score": null,
        "kind": "toolchain-ratchet",
        "before": before,
        "after": observed_release,
        "watermark": item.evidence.get("watermark").cloned().unwrap_or(Value::Null),
        "witness": item.evidence.get("witness").cloned().unwrap_or(Value::Null),
        "lane": item.evidence.get("lane").cloned().unwrap_or(Value::Null),
        "readback": readback,
        "observed": receipt_observed,
        "actuator": {
            "has_run": true,
            "changed": false,
            "kind": "toolchain-ratchet",
            "observed": observed,
            "could-change": "install the declared Rust release with the rustup-owned module shims",
            "attempt": [],
            "final-state": {"release": observed_release, "converged": false}
        },
        "commands": [],
        "apply": Value::Null,
        "ok": false,
        "first_missing_signal": reason
    });
    crate::bands::propose_edits::persist_feed_with_intent(
        path,
        crate::bands::propose_edits::FeedPersistenceIntent::AppendReceipts(vec![receipt.clone()]),
    )
    .map_err(|error| format!("toolchain-ratchet-refusal-receipt-persistence-failed: {error}"))?;
    println!("{}", serde_json::to_string_pretty(&receipt).map_err(|error| error.to_string())?);
    Err(format!("{}; item-retained", receipt["first_missing_signal"].as_str().unwrap_or("toolchain-ratchet-preflight-refused")))
}

fn run_toolchain_ratchet(
    path: &Path,
    _feed: &mut InteractablesFeed,
    _position: usize,
    item: &Interactable,
    invocation: Option<&crate::Invocation>,
) -> Result<(), String> {
    let mut observed = serde_json::json!({});
    let key = match invocation.and_then(crate::Invocation::key) {
        Some(key) => key,
        None => return persist_toolchain_preflight_refusal(path, item, "toolchain-ratchet-invocation-key-missing".into(), observed),
    };
    let evidence = &item.evidence;
    observed["evidence"] = evidence.clone();
    let installed_before = match evidence.get("installed").and_then(Value::as_str) {
        Some(version) => version,
        None => return persist_toolchain_preflight_refusal(path, item, "toolchain-ratchet-installed-version-absent".into(), observed),
    };
    observed["installed"] = serde_json::json!(installed_before);
    // This lane-independent comparator permits pacman bodies without a shim.
    let comparator = crate::atoms::command::capture("rustc", &["-Vv"]);
    observed["comparator"] = serde_json::json!({"ok": comparator.ok, "stdout": comparator.stdout});
    if !comparator.ok {
        return persist_toolchain_preflight_refusal(path, item, "toolchain-ratchet-installed-comparator-failed".into(), observed);
    }
    let installed_verbose = comparator.stdout;
    let installed_now = match installed_verbose.lines().find_map(|line| line.strip_prefix("release:").map(str::trim)) {
        Some(version) => version.to_owned(),
        None => return persist_toolchain_preflight_refusal(path, item, "toolchain-ratchet-installed-readback-absent".into(), observed),
    };
    let current_readback = serde_json::json!({"path":"rustc", "release":installed_now, "verbose":installed_verbose});
    observed["readback"] = current_readback.clone();
    if installed_now != installed_before {
        return persist_toolchain_preflight_refusal(path, item, format!("toolchain-ratchet-feed-stale expected={installed_before} actual={installed_now}"), observed);
    }
    let watermark = match evidence.get("watermark").and_then(Value::as_str) {
        Some(version) => version,
        None => return persist_toolchain_preflight_refusal(path, item, "toolchain-ratchet-watermark-absent".into(), observed),
    };
    observed["watermark"] = serde_json::json!(watermark);
    let installed_parsed = match parse_toolchain_version(&installed_now) {
        Some(version) => version,
        None => return persist_toolchain_preflight_refusal(path, item, "toolchain-ratchet-installed-version-invalid".into(), observed),
    };
    let watermark_parsed = match parse_toolchain_version(&watermark) {
        Some(version) => version,
        None => return persist_toolchain_preflight_refusal(path, item, "toolchain-ratchet-watermark-invalid".into(), observed),
    };
    if installed_parsed >= watermark_parsed {
        return persist_toolchain_preflight_refusal(path, item, format!("toolchain-ratchet-watermark-stale installed={installed_now} watermark={watermark}"), observed);
    }
    if evidence.pointer("/witness/component").and_then(Value::as_str).is_none()
        || evidence.pointer("/witness/source_sha").and_then(Value::as_str).is_none()
    {
        return persist_toolchain_preflight_refusal(path, item, "toolchain-ratchet-witness-provenance-absent".into(), observed);
    }
    let lane = match evidence.get("lane").and_then(Value::as_str) {
        Some(lane) => lane,
        None => return persist_toolchain_preflight_refusal(path, item, "toolchain-ratchet-lane-absent".into(), observed),
    };
    let witness = evidence.get("witness").cloned().unwrap_or(Value::Null);
    observed["witness"] = witness.clone();
    observed["lane"] = serde_json::json!(lane);
    let (profile, profile_path) = match crate::resolve_certificate_profile() {
        Ok(profile) => profile,
        Err(reason) => return persist_toolchain_preflight_refusal(path, item, reason, observed),
    };
    let actual_lane = if profile.package_authority.as_ref().is_some_and(|authority| authority.package_manager == "pacman") {
        "pacman"
    } else if profile.modules.iter().any(|module| module == "rust-build-toolchain") && Path::new("/opt/rustup").is_dir() {
        "rustup"
    } else {
        "none"
    };
    if actual_lane != lane {
        return persist_toolchain_preflight_refusal(path, item, format!("toolchain-ratchet-lane-stale expected={actual_lane} actual={lane}"), observed);
    }
    if lane == "pacman" {
        let receipt = serde_json::json!({
            "schema": "harmonia.config_state.receipt.v1",
            "config_state": "interactable",
            "id": item.id,
            "target": null,
            "reference_id": null,
            "score": null,
            "actuator": {
                "has_run": true,
                "changed": false,
                "kind": "toolchain-ratchet",
                "observed": {"installed": installed_now, "watermark": watermark},
                "could-change": "pacman package authority is outside this interactable's mutation lane",
                "attempt": [],
                "final-state": {"release": installed_now, "converged": false}
            },
            "kind": "toolchain-ratchet",
            "before": installed_now,
            "after": installed_now,
            "watermark": watermark,
            "witness": witness,
            "lane": lane,
            "distro_evidence": format!("installed rustc release {installed_now}; watermark {watermark}"),
            "commands": [],
            "readback": current_readback,
            "apply": Value::Null,
            "ok": false,
            "first_missing_signal": "pacman-toolchain-not-applied"
        });
        crate::bands::propose_edits::persist_feed_with_intent(
            path,
            crate::bands::propose_edits::FeedPersistenceIntent::AppendReceipts(vec![receipt.clone()]),
        )?;
        println!("{}", serde_json::to_string_pretty(&receipt).map_err(|error| error.to_string())?);
        return Err("pacman-toolchain-evidence-recorded-item-retained".into());
    }
    let module_id = match lane {
        "rustup" => "rust-build-toolchain",
        _ => return persist_toolchain_preflight_refusal(path, item, format!("toolchain-ratchet-lane-invalid {lane}"), observed),
    };
    if !profile.modules.iter().any(|module| module == module_id) {
        return persist_toolchain_preflight_refusal(path, item, format!("toolchain-ratchet-module-not-declared {module_id}"), observed);
    }
    let module_root = crate::default_module_root(&profile_path);
    let module_dir = match crate::bands::stage_profile::resolve_module_dir(&module_root, module_id) {
        Ok(path) => path,
        Err(reason) => return persist_toolchain_preflight_refusal(path, item, reason, observed),
    };
    let manifest_path = module_dir.join("manifest.json");
    let manifest = match crate::load_ladder_manifest(&manifest_path) {
        Ok(manifest) => manifest,
        Err(reason) => return persist_toolchain_preflight_refusal(path, item, reason, observed),
    };
    if manifest.id != module_id {
        return persist_toolchain_preflight_refusal(path, item, format!("toolchain-ratchet-module-id-mismatch {module_id} {}", manifest.id), observed);
    }
    let files_root_rel = match manifest.files_root.as_deref() {
        Some(root) => root,
        None => return persist_toolchain_preflight_refusal(path, item, "toolchain-ratchet-files-root-undeclared".into(), observed),
    };
    let files_root_path = Path::new(files_root_rel);
    if files_root_path.is_absolute() || files_root_path.components().any(|part| matches!(part, std::path::Component::ParentDir)) {
        return persist_toolchain_preflight_refusal(path, item, "toolchain-ratchet-files-root-invalid".into(), observed);
    }
    let files_root = module_dir.join(files_root_path);
    if !files_root.is_dir() {
        return persist_toolchain_preflight_refusal(path, item, format!("toolchain-ratchet-files-root-missing {}", files_root.display()), observed);
    }
    for name in ["rustc", "cargo", "rustup"] {
        let source = files_root.join("usr/local/bin").join(name);
        if !source.is_file() {
            return persist_toolchain_preflight_refusal(path, item, format!("toolchain-ratchet-shim-source-missing {}", source.display()), observed);
        }
    }
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos()).unwrap_or(0);
    let mut receipt = serde_json::json!({
        "schema": "harmonia.config_state.receipt.v1", "config_state": "interactable",
        "id": item.id, "target": null, "reference_id": null, "score": null,
        "actuator": {
            "has_run": true, "changed": false, "kind": "toolchain-ratchet",
            "observed": {"installed": installed_before, "watermark": watermark},
            "could-change": "install the declared release watermark with the rustup-owned module shims",
            "attempt": [], "final-state": {"release": installed_before, "converged": false}
        },
        "before": installed_before, "after": Value::Null, "watermark": watermark, "witness": witness, "lane": lane,
        "commands": [], "readback": Value::Null, "apply": Value::Null,
        "ok": false, "first_missing_signal": "toolchain-ratchet-not-completed"
    });
    let mut commands = Vec::<Value>::new();
    let mut remove_item = false;
    let result: Result<(), String> = (|| {
        if lane != "rustup" || module_id != "rust-build-toolchain" {
            return Err("toolchain-ratchet-lane-module-mismatch".into());
        }
        if unsafe { libc::geteuid() } != 0 {
            return Err("toolchain-ratchet-requires-root".into());
        }
        let (mode, invocation_key) = match crate::UpdateMode::from_apply_flag_with_invocation(true, Some(key)) {
            crate::UpdateMode::ApplySoftware(auth, key) => (auth, key),
            crate::UpdateMode::Observe => return Err("toolchain-ratchet-apply-authorization-missing".into()),
        };
        let toolchains = run_logged("/opt/cargo/bin/rustup", &["toolchain", "list"], &mut commands)?
            .get("stdout")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let prior_toolchain = toolchains
            .lines()
            .find_map(|line| {
                let (toolchain, flags) = rustup_list_flags(line)?;
                flags
                    .iter()
                    .any(|flag| *flag == "default")
                    .then(|| toolchain.to_owned())
            })
            .ok_or_else(|| "rustup-default-toolchain-unreadable".to_string())?;
        let existed = toolchains.lines().any(|line| {
            line.split_whitespace()
                .next()
                .is_some_and(|toolchain| rustup_toolchain_matches_watermark(toolchain, watermark))
        });
        let files = ["rustc", "cargo", "rustup"]
            .into_iter()
            .map(|name| crate::tools::files::FileSpec {
                relative_path: PathBuf::from(format!("usr/local/bin/{name}")),
                mode: None,
            })
            .collect();
        let request = crate::tools::files::FileConvergenceRequest {
            source_root: files_root,
            target_root: PathBuf::from("/"),
            files,
            backup_existing: true,
            receipt_name: format!("toolchain-ratchet-{timestamp}"),
            owner: Some("root".into()),
            group: Some("root".into()),
        };
        let file_receipt_dir = PathBuf::from(format!(
            "/var/lib/harmonia/receipts/toolchain-ratchet-files-{timestamp}"
        ));
        let outcome = match crate::atoms::r#do::place_file::converge_files_authorized(
            &request,
            &file_receipt_dir,
            Some(&mode),
            invocation_key,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                receipt["shim_convergence"] = serde_json::json!({
                    "ok": false,
                    "first_missing_signal": error,
                });
                let rollback = restore_rustup_default(
                    &prior_toolchain,
                    installed_before,
                    watermark,
                    existed,
                    &mut commands,
                    &mut receipt,
                );
                if let Err(failure) = rollback {
                    receipt["rollback_failure"] = serde_json::json!(failure);
                }
                return Err(error);
            }
        };
        receipt["shim_convergence"] = serde_json::to_value(&outcome).unwrap_or(Value::Null);
        if !outcome.ok {
            let missing = if !outcome.missing.is_empty() {
                "missing-target-file".to_string()
            } else {
                outcome.message.clone()
            };
            receipt["shim_convergence"]["first_missing_signal"] =
                serde_json::json!(missing);
            receipt["first_missing_signal"] = serde_json::json!(missing);
            let rollback = restore_rustup_default(
                &prior_toolchain,
                installed_before,
                watermark,
                existed,
                &mut commands,
                &mut receipt,
            );
            if let Err(failure) = rollback {
                receipt["rollback_failure"] = serde_json::json!(failure);
            }
            return Err(missing);
        }

        if let Err(error) = run_logged_env("/usr/local/bin/rustup", &["toolchain", "install", watermark, "--profile", "minimal"], &mut commands) {
            receipt["first_missing_signal"] = original_tool_sentence(&commands, &error);
            let rollback = restore_rustup_default(&prior_toolchain, installed_before, watermark, existed, &mut commands, &mut receipt);
            if let Err(failure) = rollback {
                receipt["rollback_failure"] = serde_json::json!(failure);
            }
            return Err(error);
        }
        if let Err(error) = run_logged("/usr/local/bin/rustup", &["default", watermark], &mut commands) {
            receipt["first_missing_signal"] = original_tool_sentence(&commands, &error);
            let rollback = restore_rustup_default(&prior_toolchain, installed_before, watermark, existed, &mut commands, &mut receipt);
            if let Err(failure) = rollback {
                receipt["rollback_failure"] = serde_json::json!(failure);
            }
            return Err(error);
        }
        let readback = match run_rustc_readback(&mut commands) {
            Ok(readback) => readback,
            Err(error) => {
                receipt["first_missing_signal"] = serde_json::json!(error);
                let rollback = restore_rustup_default(&prior_toolchain, installed_before, watermark, existed, &mut commands, &mut receipt);
                if let Err(failure) = rollback {
                    receipt["rollback_failure"] = serde_json::json!(failure);
                }
                return Err(error);
            }
        };
        receipt["readback"] = readback.clone();
        receipt["after"] = readback.get("release").cloned().unwrap_or(Value::Null);
        let readback_version = readback.get("release").and_then(Value::as_str).unwrap_or("");
        if readback_version != watermark {
            let error = format!("toolchain-ratchet-readback-mismatch expected={watermark} actual={readback_version}");
            receipt["first_missing_signal"] = serde_json::json!(error);
            let rollback = restore_rustup_default(&prior_toolchain, installed_before, watermark, existed, &mut commands, &mut receipt);
            if let Err(failure) = rollback {
                receipt["rollback_failure"] = serde_json::json!(failure);
            }
            return Err(error);
        }

        let receipt_dir = PathBuf::from(format!(
            "/var/lib/harmonia/receipts/toolchain-ratchet-{timestamp}"
        ));
        if let Err(error) = fs::create_dir_all(&receipt_dir) {
            let failure = format!("toolchain-ratchet-receipt-dir-failed: {error}");
            receipt["first_missing_signal"] = serde_json::json!(failure);
            let rollback = restore_rustup_default(
                &prior_toolchain,
                installed_before,
                watermark,
                existed,
                &mut commands,
                &mut receipt,
            );
            if let Err(rollback_failure) = rollback {
                receipt["rollback_failure"] = serde_json::json!(rollback_failure);
            }
            return Err(failure);
        }
        let executable = match std::env::current_exe() {
            Ok(executable) => executable,
            Err(error) => {
                let failure = format!("toolchain-ratchet-current-exe-failed: {error}");
                receipt["first_missing_signal"] = serde_json::json!(failure);
                let rollback = restore_rustup_default(
                    &prior_toolchain,
                    installed_before,
                    watermark,
                    existed,
                    &mut commands,
                    &mut receipt,
                );
                if let Err(rollback_failure) = rollback {
                    receipt["rollback_failure"] = serde_json::json!(rollback_failure);
                }
                return Err(failure);
            }
        };
        let mut command = std::process::Command::new(executable);
        command.arg("update")
            .arg("--apply")
            .arg("--receipt-dir")
            .arg(&receipt_dir)
            .env("RUSTUP_HOME", "/opt/rustup")
            .env("CARGO_HOME", "/opt/cargo")
            .env("HARMONIA_TOOLCHAIN_RATCHET_HANDOFF", "1");
        let output = match command.output() {
            Ok(output) => output,
            Err(error) => {
                let failure = format!("toolchain-ratchet-apply-spawn-failed: {error}");
                receipt["first_missing_signal"] = serde_json::json!(failure);
                let rollback = restore_rustup_default(
                    &prior_toolchain,
                    installed_before,
                    watermark,
                    existed,
                    &mut commands,
                    &mut receipt,
                );
                if let Err(rollback_failure) = rollback {
                    receipt["rollback_failure"] = serde_json::json!(rollback_failure);
                }
                return Err(failure);
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let run_path = receipt_dir.join("run.json");
        let run: Value = fs::read_to_string(&run_path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or(Value::Null);
        receipt["apply"] = serde_json::json!({
            "command": "harmonia update --apply",
            "exit_code": output.status.code(),
            "stdout": stdout,
            "stderr": stderr,
            "run_id": run.get("run_id"),
            "ok": run.get("ok"),
            "first_missing_signal": run.get("first_missing_signal"),
            "receipt_path": run_path,
        });
        if !output.status.success() || run.get("ok").and_then(Value::as_bool) != Some(true) {
            receipt["first_missing_signal"] = run
                .get("first_missing_signal")
                .cloned()
                .or_else(|| (!stderr.trim().is_empty()).then(|| serde_json::json!(stderr.trim())))
                .unwrap_or_else(|| serde_json::json!("toolchain-ratchet-apply-failed"));
            let rollback = restore_rustup_default(
                &prior_toolchain,
                installed_before,
                watermark,
                existed,
                &mut commands,
                &mut receipt,
            );
            if let Err(rollback_failure) = rollback {
                receipt["first_missing_signal"] = serde_json::json!(rollback_failure);
                receipt["rollback_failure"] = serde_json::json!(rollback_failure);
                return Err(format!("toolchain-ratchet-rollback-failed: {rollback_failure}"));
            }
            return Err("toolchain-ratchet-apply-failed".into());
        }
        receipt["ok"] = Value::Bool(true);
        receipt["first_missing_signal"] = serde_json::json!("none");
        remove_item = true;
        Ok(())
    })();
    if let Err(reason) = &result {
        if receipt["first_missing_signal"] == "toolchain-ratchet-not-completed" {
            receipt["first_missing_signal"] = serde_json::json!(reason);
        }
    }
    receipt["commands"] = Value::Array(commands.clone());
    let after = receipt.get("after").cloned().unwrap_or(Value::Null);
    receipt["actuator"] = serde_json::json!({
        "has_run": true,
        "changed": after.as_str().is_some_and(|release| release != installed_before),
        "kind": "toolchain-ratchet",
        "observed": {
            "installed_before": installed_before,
            "watermark": watermark,
            "readback": receipt.get("readback").cloned().unwrap_or(Value::Null),
        },
        "could-change": "install and select the declared Rust release, then converge software",
        "attempt": commands,
        "final-state": {"release": after, "converged": receipt["ok"] == Value::Bool(true)},
    });
    let intent = if remove_item {
        crate::bands::propose_edits::FeedPersistenceIntent::Remove {
            ids: [item.id.clone()].into_iter().collect(), receipts: vec![receipt.clone()],
        }
    } else {
        crate::bands::propose_edits::FeedPersistenceIntent::AppendReceipts(vec![receipt.clone()])
    };
    crate::bands::propose_edits::persist_feed_with_intent(path, intent)?;
    println!("{}", serde_json::to_string_pretty(&receipt).map_err(|error| error.to_string())?);
    result
}

fn restore_rustup_default(
    prior_toolchain: &str,
    installed_before: &str,
    watermark: &str,
    existed: bool,
    commands: &mut Vec<Value>,
    receipt: &mut Value,
) -> Result<(), String> {
    let mut failures = Vec::new();
    let default_result = run_logged(
        "/usr/local/bin/rustup",
        &["default", prior_toolchain],
        commands,
    );
    if let Err(error) = &default_result {
        failures.push(format!("rollback-default-failed: {error}"));
    }
    let uninstall_result = if existed {
        None
    } else {
        let result = run_logged(
            "/usr/local/bin/rustup",
            &["toolchain", "uninstall", watermark],
            commands,
        );
        if let Err(error) = &result {
            failures.push(format!("rollback-uninstall-failed: {error}"));
        }
        Some(result)
    };
    let readback_result = run_rustc_readback(commands);
    match &readback_result {
        Ok(readback) => {
            let actual = readback
                .get("release")
                .and_then(Value::as_str)
                .unwrap_or("");
            if actual != installed_before {
                failures.push(format!(
                    "rollback-readback-mismatch expected={installed_before} actual={actual}"
                ));
            }
            receipt["readback"] = readback.clone();
            receipt["after"] = readback.get("release").cloned().unwrap_or(Value::Null);
        }
        Err(error) => {
            receipt["readback"] = serde_json::json!({"path":"/usr/local/bin/rustc", "error":error});
            receipt["after"] = Value::Null;
            failures.push(format!("rollback-readback-failed: {error}"));
        }
    }
    receipt["rollback"] = serde_json::json!({
        "default": default_result.is_ok(),
        "uninstall": uninstall_result.as_ref().map(Result::is_ok),
        "readback": readback_result.as_ref().ok(),
        "errors": failures.clone(),
    });
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn original_tool_sentence(commands: &[Value], error: &str) -> Value {
    commands
        .last()
        .and_then(|row| {
            (row.get("exit_code").and_then(Value::as_i64) != Some(0))
                .then(|| row.get("stderr"))
                .flatten()
        })
        .and_then(Value::as_str)
        .filter(|stderr| !stderr.is_empty())
        .map(|stderr| serde_json::json!(stderr))
        .unwrap_or_else(|| serde_json::json!(error))
}

fn run_logged(program: &str, args: &[&str], commands: &mut Vec<Value>) -> Result<Value, String> {
    run_logged_env(program, args, commands)
}

fn run_logged_env(program: &str, args: &[&str], commands: &mut Vec<Value>) -> Result<Value, String> {
    let output = std::process::Command::new(program).args(args)
        .env("RUSTUP_HOME", "/opt/rustup").env("CARGO_HOME", "/opt/cargo")
        .output().map_err(|error| format!("{program}-spawn-failed: {error}"))?;
    let row = serde_json::json!({"program": program, "args": args, "exit_code": output.status.code(),
        "stdout": String::from_utf8_lossy(&output.stdout), "stderr": String::from_utf8_lossy(&output.stderr)});
    commands.push(row.clone());
    if output.status.success() { Ok(row) } else {
        Err(format!("{program}-failed exit={:?}: {}", output.status.code(), String::from_utf8_lossy(&output.stderr).trim()))
    }
}

fn run_rustc_readback(commands: &mut Vec<Value>) -> Result<Value, String> {
    let output = std::process::Command::new("/usr/local/bin/rustc").arg("-Vv")
        .env("RUSTUP_HOME", "/opt/rustup").env("CARGO_HOME", "/opt/cargo")
        .output().map_err(|error| format!("rustc-readback-spawn-failed: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    commands.push(serde_json::json!({"program":"/usr/local/bin/rustc", "args":["-Vv"],
        "exit_code":output.status.code(), "stdout":stdout, "stderr":String::from_utf8_lossy(&output.stderr)}));
    if !output.status.success() { return Err("rustc-readback-failed".into()); }
    let release = stdout
        .lines()
        .find_map(|line| line.strip_prefix("release:").map(str::trim))
        .filter(|release| !release.is_empty())
        .ok_or_else(|| "rustc-readback-release-absent".to_string())?;
    Ok(serde_json::json!({"path":"/usr/local/bin/rustc", "release":release, "verbose":stdout}))
}

fn configured_unbound_target() -> PathBuf {
    #[cfg(any(test, feature = "test-facade"))]
    if let Some(root) = env::var_os("HARMONIA_INTERACTABLE_CONFIG_ROOT") {
        return PathBuf::from(root).join("etc/unbound/unbound.conf");
    }
    PathBuf::from("/etc/unbound/unbound.conf")
}

fn insert_dns_record(original: &[u8], record: &str) -> Result<Vec<u8>, String> {
    if record.contains('\n') || record.contains('\r') {
        return Err("dns-record-line-invalid".into());
    }
    let text =
        std::str::from_utf8(original).map_err(|_| "dns-record-config-not-utf8".to_string())?;
    let mut lines = text.lines().map(str::to_owned).collect::<Vec<_>>();
    let server = lines
        .iter()
        .position(|line| line.trim() == "server:")
        .ok_or_else(|| "dns-record-server-block-absent".to_string())?;
    let end = lines
        .iter()
        .enumerate()
        .skip(server + 1)
        .find(|(_, line)| {
            !line.trim().is_empty() && !line.starts_with(' ') && !line.starts_with('\t')
        })
        .map(|(index, _)| index)
        .unwrap_or(lines.len());
    if lines[server + 1..end]
        .iter()
        .any(|line| line.trim() == record)
    {
        return Ok(original.to_vec());
    }
    let last_local = (server + 1..end)
        .rev()
        .find(|index| lines[*index].trim_start().starts_with("local-data:"));
    let insertion = last_local.map(|index| index + 1).unwrap_or(end);
    let indent = last_local
        .map(|index| lines[index].len() - lines[index].trim_start().len())
        .unwrap_or(4);
    lines.insert(insertion, format!("{}{record}", " ".repeat(indent)));
    let mut candidate = lines.join("\n").into_bytes();
    if text.ends_with('\n') {
        candidate.push(b'\n');
    }
    Ok(candidate)
}

fn persist_dns_receipt(
    path: &Path,
    _feed: &mut InteractablesFeed,
    receipt: &serde_json::Value,
) -> Result<(), String> {
    if let Ok(seat) = &crate::atoms::ask::mint_seats::interactables_at_start().dns_record_receipt {
        seat.validate(receipt)?;
    }
    crate::bands::propose_edits::persist_feed_with_intent(
        path,
        crate::bands::propose_edits::FeedPersistenceIntent::AppendReceipts(vec![receipt.clone()]),
    )
    .map(|_| ())
}

fn run_dns_record(
    path: &Path,
    feed: &mut InteractablesFeed,
    _position: usize,
    item: &Interactable,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<(), String> {
    let perspective = crate::atoms::ask::ruyi::read_perspective()?;
    let self_row = perspective
        .get("self")
        .filter(|row| row.is_object())
        .ok_or_else(|| "ruyi-current-self-unavailable".to_string())?;
    let gateway = crate::atoms::ask::ruyi::registrant::default_gateway()?;
    if !crate::atoms::ask::ruyi::registrant::self_is_gateway(&perspective, gateway, self_row) {
        return Err("interactable-kind-not-for-this-body".into());
    }
    let record = item
        .evidence
        .get("record")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "dns-record-evidence-invalid".to_string())?;
    let target = configured_unbound_target();
    let metadata = fs::symlink_metadata(&target)
        .map_err(|error| format!("dns-record-target-stat-failed: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("dns-record-target-not-regular-file".into());
    }
    let original =
        fs::read(&target).map_err(|error| format!("dns-record-target-read-failed: {error}"))?;
    let candidate = insert_dns_record(&original, record)?;
    let scratch = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("interactable-candidates")
        .join(format!("{}.conf", item.id));
    fs::create_dir_all(scratch.parent().unwrap()).map_err(|e| e.to_string())?;
    fs::write(&scratch, &candidate)
        .map_err(|e| format!("dns-record-candidate-write-failed: {e}"))?;
    #[cfg(any(test, feature = "test-facade"))]
    let check_program = env::var("HARMONIA_UNBOUND_CHECKCONF")
        .unwrap_or_else(|_| "/usr/sbin/unbound-checkconf".into());
    #[cfg(not(any(test, feature = "test-facade")))]
    let check_program = "/usr/sbin/unbound-checkconf".to_string();
    let check = crate::atoms::ask::read_only_command_with_timeout(
        &check_program,
        &[scratch.to_string_lossy().into_owned()],
        Duration::from_secs(10),
    );
    let mut receipt = serde_json::json!({
        "schema": crate::atoms::ask::mint_seats::DNS_RECORD_RECEIPT,
        "ok": false, "id": item.id, "hostname": item.evidence.get("hostname"),
        "record": record, "checkconf": {"ok": check.ok, "code": check.code,
        "stdout": check.stdout, "stderr": check.stderr}, "reload": null, "at": now_seconds()
    });
    if !check.ok {
        persist_dns_receipt(path, feed, &receipt)?;
        eprintln!("dns-record-checkconf-failed {}", receipt["checkconf"]);
        return Err("dns-record-checkconf-failed".into());
    }
    let invocation =
        invocation.ok_or_else(|| "dns-record-systemd-invocation-key-missing".to_string())?;
    let backup = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("interactables-backups")
        .join(&item.id)
        .join(format!("{}-unbound.conf", now_seconds()));
    let projection = match crate::atoms::projectio::strike(crate::atoms::projectio::Request {
        target: &target,
        desired_bytes: &candidate,
        mode: metadata.mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
        backup_path: &backup,
        witness: crate::atoms::projectio::owner_acceptance(operator_hand()),
    }) {
        Ok(projection) => projection,
        Err(error) => {
            receipt["projectio"] = serde_json::json!({"ok": false, "error": error});
            persist_dns_receipt(path, feed, &receipt)?;
            return Err("dns-record-projectio-failed".into());
        }
    };
    receipt["projectio"] = serde_json::to_value(&projection).map_err(|e| e.to_string())?;
    let reload_run = crate::atoms::comparison::execute_once(
        "dns-record-systemd-reload",
        || Ok::<_, String>(()),
        |_| crate::atoms::comparison::DiffDecision::Different,
        |authorization, _| {
            crate::atoms::r#do::change_unit::unit_change_scoped(
                &authorization,
                invocation,
                "unbound",
                crate::atoms::r#do::change_unit::UnitVerb::Reload,
                false,
                None,
                30,
            )
        },
    )?;
    let reload = match reload_run {
        crate::atoms::comparison::ComparisonRun::Moved { movement, .. } => movement,
        crate::atoms::comparison::ComparisonRun::Current { .. } => {
            return Err("dns-record-reload-not-authorized".into())
        }
    };
    receipt["reload"] = serde_json::json!({"ok": reload.ok, "code": reload.code,
        "stdout": reload.stdout, "stderr": reload.stderr});
    receipt["ok"] = serde_json::json!(reload.ok);
    if let Ok(seat) = &crate::atoms::ask::mint_seats::interactables_at_start().dns_record_receipt {
        seat.validate(&receipt)?;
    }
    let intent = if reload.ok {
        crate::bands::propose_edits::FeedPersistenceIntent::Remove {
            ids: [item.id.clone()].into_iter().collect(),
            receipts: vec![receipt.clone()],
        }
    } else {
        crate::bands::propose_edits::FeedPersistenceIntent::AppendReceipts(vec![receipt.clone()])
    };
    crate::bands::propose_edits::persist_feed_with_intent(path, intent)?;
    if !reload.ok {
        return Err("dns-record-reload-failed".into());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&receipt).map_err(|e| e.to_string())?
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

    fn sentinel_interactable() -> Interactable {
        Interactable {
            id: "test-sentinel".into(),
            module_id: "test".into(),
            name: "test sentinel".into(),
            description: String::new(),
            kind: "test-sentinel".into(),
            target_path: None,
            reference_source_path: None,
            drift: DriftSummary {
                content: false,
                mode: false,
                ownership: false,
            },
            created_at: "100".into(),
            refreshed_at: "100".into(),
            available_at: None,
            silenced: false,
            silenced_at: None,
            has_run: false,
            mode: None,
            owner: None,
            group: None,
            source_sha: None,
            target_sha: None,
            commits_behind: None,
            live_sha: None,
            reference_sha: None,
            recognition_score: None,
            diff: None,
            script: String::new(),
            show_only_if: String::new(),
            completion_check: String::new(),
            evidence: serde_json::json!({}),
            extra: serde_json::Map::new(),
        }
    }

    fn item(root: &std::path::Path) -> Interactable {
        Interactable {
            id: "config-proposal-accept-regression".into(),
            module_id: "regression".into(),
            name: "config proposal acceptance".into(),
            description: String::new(),
            kind: "hard-stamp".into(),
            target_path: Some(root.join("config_deploy:interactable/target.conf")),
            reference_source_path: Some(root.join("source.conf")),
            drift: DriftSummary {
                content: true,
                mode: false,
                ownership: false,
            },
            created_at: "0".into(),
            refreshed_at: "0".into(),
            available_at: None,
            silenced: false,
            silenced_at: None,
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
            diff: None,
            script: String::new(),
            show_only_if: String::new(),
            completion_check: String::new(),
            evidence: serde_json::Value::Null,
            extra: serde_json::Map::new(),
        }
    }

    #[test]
    fn toolchain_version_parser_accepts_only_three_decimal_components() {
        assert_eq!(parse_toolchain_version("1.82.0"), Some([1, 82, 0]));
        for value in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "1.2.3-nightly",
            "1..3",
            "1.2.x",
            "18446744073709551616.0.0",
        ] {
            assert_eq!(parse_toolchain_version(value), None, "{value}");
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
        let result = interactable_run(&[proposal.id.clone()], None);
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
