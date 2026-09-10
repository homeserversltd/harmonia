use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) const FEED_SCHEMA: &str = "harmonia.config_proposals.feed.v1";
pub(crate) const LEGACY_FEED_SCHEMA: &str = "harmonia.interactables.feed.v1";
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
    let observed_text = crate::atoms::ask::optional_text(path)?;
    match observed_text {
        Some(text) => {
            let feed: InteractablesFeed = serde_json::from_str(&text).map_err(|error| {
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
                let raw = serde_json::to_value(&feed).map_err(|error| error.to_string())?;
                seat.validate_compatible(&raw, &[LEGACY_FEED_SCHEMA])?;
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
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
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
    crate::bands::propose_edits::persist_feed(&path, &feed)
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
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
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
        "dns-record" => {
            return run_dns_record(&path, &mut feed, position, &item, invocation)
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

fn face_source(row: &serde_json::Value) -> Option<&str> {
    member_source(row, "face").or_else(|| {
        row.get("gui_face")
            .and_then(serde_json::Value::as_str)
            .map(str::to_ascii_lowercase)
            .and_then(|name| member_source(row, &name))
    })
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
                && label.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                })
        }))
    .then(|| format!("{name}."))
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
        .filter(|item| matches!(item.kind.as_str(), "ruyi-bump" | "dns-record"))
        .map(|item| (item.id.clone(), item.created_at.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    let unknown = feed
        .interactables
        .iter()
        .filter(|item| matches!(item.kind.as_str(), "ruyi-bump" | "dns-record"))
        .map(|item| (item.id.clone(), item.extra.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    feed.interactables
        .retain(|item| item.kind != "ruyi-bump" && item.kind != "dns-record");
    let module = profile
        .caduceus_module_id()
        .ok_or_else(|| "ruyi-caduceus-module-absent".to_string())?;
    let self_mac = self_row.get("mac").and_then(serde_json::Value::as_str);
    let newest = [
        self_row.get("caduceus_sha").and_then(serde_json::Value::as_str),
        member_source(self_row, "sbin"),
        face_source(self_row),
    ];
    let now = now_seconds();
    let mut held_back_by = Vec::new();
    for peer in staves {
        let Some(mac) = peer.get("mac").and_then(serde_json::Value::as_str) else { continue; };
        if Some(mac) == self_mac { continue; }
        let peer_view = peer
            .pointer("/perspective/self")
            .or_else(|| roster.pointer(&format!("/perspectives/{mac}/self")));
        let wears = [
            peer.get("caduceus_sha").and_then(serde_json::Value::as_str),
            peer_view.and_then(|row| member_source(row, "sbin")),
            peer_view.and_then(face_source),
        ];
        let terms = [
            term_state(newest[0], wears[0]),
            term_state(newest[1], wears[1]),
            term_state(newest[2], wears[2]),
        ];
        if terms.iter().all(|term| *term == "same") { continue; }
        let hostname = peer.get("hostname").and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let canonical_name = peer.get("canonical_name").cloned().unwrap_or(serde_json::Value::Null);
        let last_checked = peer.get("last_seen").and_then(serde_json::Value::as_u64);
        let last_event_age_s = last_checked.map(|last| now.saturating_sub(last));
        let last_event_age = last_event_age_s
            .map(|age| format!("{age}s"))
            .unwrap_or_else(|| "unknown".to_string());
        let description = format!(
            "For {hostname} {mac}, the worn triple is (caduceus={}, sbin={}, face={}), the newest triple is (caduceus={}, sbin={}, face={}), the term triple is (caduceus={}, sbin={}, face={}), and the last-event age is {last_event_age}.",
            wears[0].unwrap_or("unknown"),
            wears[1].unwrap_or("unknown"),
            wears[2].unwrap_or("unknown"),
            newest[0].unwrap_or("unknown"),
            newest[1].unwrap_or("unknown"),
            newest[2].unwrap_or("unknown"),
            terms[0],
            terms[1],
            terms[2],
        );
        let id = format!("ruyi-bump-{}", mac.replace(':', ""));
        held_back_by.push(mac.to_string());
        feed.interactables.push(Interactable {
            id: id.clone(), module_id: module.to_string(),
            name: format!("{hostname} {mac}"),
            description,
            kind: "ruyi-bump".into(), target_path: None, reference_source_path: None,
            drift: DriftSummary { content: true, mode: false, ownership: false },
            created_at: created.get(&id).cloned().unwrap_or_else(|| now.to_string()),
            refreshed_at: now.to_string(), available_at: None,
            silenced: false, silenced_at: None,
            has_run: false, mode: None, owner: None, group: None, source_sha: None,
            target_sha: None, commits_behind: None, live_sha: None, reference_sha: None,
            recognition_score: None, diff: None,
            script: format!("harmonia interactable run {id}"),
            show_only_if: String::new(), completion_check: String::new(),
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
    if is_gateway {
        if let Some(unresolved) = roster.get("dns_unresolved").and_then(serde_json::Value::as_array) {
            let dns_module = profile.dns_module_id().unwrap_or(module);
            for entry in unresolved {
                let Some(hostname) = entry.get("hostname").and_then(serde_json::Value::as_str) else { continue; };
                let Some(canonical) = entry.get("canonical_name").and_then(serde_json::Value::as_str) else { continue; };
                let Some(ipv4) = entry.get("ipv4").and_then(serde_json::Value::as_str) else { continue; };
                let Some(canonical) = canonical_dns_name(canonical) else { continue; };
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
                    id: id.clone(), module_id: dns_module.to_string(), name: format!("Add DNS record for {hostname}"),
                    description: format!("Add the validated home.arpa address for {hostname} to Unbound."),
                    kind: "dns-record".into(), target_path: None, reference_source_path: None,
                    drift: DriftSummary { content: true, mode: false, ownership: false },
                    created_at: created.get(&id).cloned().unwrap_or_else(|| now.to_string()),
                    refreshed_at: now.to_string(), available_at: None,
                    silenced: false, silenced_at: None,
                    has_run: false, mode: None, owner: None, group: None, source_sha: None,
                    target_sha: None, commits_behind: None, live_sha: None, reference_sha: None,
                    recognition_score: None, diff: None,
                    script: format!("harmonia interactable run {id}"),
                    show_only_if: String::new(), completion_check: String::new(),
                    evidence: serde_json::json!({"mac": entry.get("mac"), "hostname": hostname,
                        "canonical_name": canonical, "ipv4": ipv4, "record": record}),
                    extra: unknown.get(&id).cloned().unwrap_or_default(),
                });
            }
        }
    }
    feed.interactables.sort_by(|a, b| a.id.cmp(&b.id));
    crate::bands::propose_edits::persist_feed(&path, &feed)?;
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
    feed: &mut InteractablesFeed,
    position: usize,
    item: &Interactable,
) -> Result<(), String> {
    let Some(port) = crate::bands::stage_profile::read_device_caduceus_seat_port()? else {
        eprintln!("ruyi-seat-undeclared");
        return Err("ruyi-seat-undeclared".into());
    };
    let mac = item.evidence.get("mac").and_then(serde_json::Value::as_str)
        .ok_or_else(|| "ruyi-bump-mac-absent".to_string())?;
    let hostname = item.evidence.get("hostname").and_then(serde_json::Value::as_str)
        .ok_or_else(|| "ruyi-bump-hostname-absent".to_string())?;
    let perspective = crate::atoms::ask::ruyi::read_perspective()?;
    let self_row = perspective.get("self").cloned().unwrap_or(serde_json::Value::Null);
    let host = crate::atoms::ask::ruyi::registrant::routed_host(&self_row)?;
    let (seat_reply, status) = crate::atoms::ask::beam::delete(
        &format!("http://{host}:{port}/api/v1/ruyi/{mac}"),
    )
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
    feed.receipts.push(receipt.clone());
    feed.interactables.remove(position);
    crate::bands::propose_edits::persist_feed(path, feed)?;
    println!("{}", serde_json::to_string_pretty(&receipt).map_err(|e| e.to_string())?);
    Ok(())
}

fn configured_unbound_target() -> PathBuf {
    #[cfg(any(test, feature = "test-facade"))]
    if let Some(root) = env::var_os("HARMONIA_INTERACTABLE_CONFIG_ROOT") {
        return PathBuf::from(root).join("etc/unbound/unbound.conf");
    }
    PathBuf::from("/etc/unbound/unbound.conf")
}

fn insert_dns_record(original: &[u8], record: &str) -> Result<Vec<u8>, String> {
    if record.contains('\n') || record.contains('\r') { return Err("dns-record-line-invalid".into()); }
    let text = std::str::from_utf8(original).map_err(|_| "dns-record-config-not-utf8".to_string())?;
    let mut lines = text.lines().map(str::to_owned).collect::<Vec<_>>();
    let server = lines.iter().position(|line| line.trim() == "server:")
        .ok_or_else(|| "dns-record-server-block-absent".to_string())?;
    let end = lines.iter().enumerate().skip(server + 1)
        .find(|(_, line)| {
            !line.trim().is_empty() && !line.starts_with(' ') && !line.starts_with('\t')
        })
        .map(|(index, _)| index).unwrap_or(lines.len());
    if lines[server + 1..end].iter().any(|line| line.trim() == record) {
        return Ok(original.to_vec());
    }
    let last_local = (server + 1..end).rev()
        .find(|index| lines[*index].trim_start().starts_with("local-data:"));
    let insertion = last_local.map(|index| index + 1).unwrap_or(end);
    let indent = last_local
        .map(|index| lines[index].len() - lines[index].trim_start().len())
        .unwrap_or(4);
    lines.insert(insertion, format!("{}{record}", " ".repeat(indent)));
    let mut candidate = lines.join("\n").into_bytes();
    if text.ends_with('\n') { candidate.push(b'\n'); }
    Ok(candidate)
}

fn persist_dns_receipt(
    path: &Path,
    feed: &mut InteractablesFeed,
    receipt: &serde_json::Value,
) -> Result<(), String> {
    if let Ok(seat) =
        &crate::atoms::ask::mint_seats::interactables_at_start().dns_record_receipt
    {
        seat.validate(receipt)?;
    }
    feed.receipts.push(receipt.clone());
    crate::bands::propose_edits::persist_feed(path, feed)
}

fn run_dns_record(
    path: &Path,
    feed: &mut InteractablesFeed,
    position: usize,
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
    let record = item.evidence.get("record").and_then(serde_json::Value::as_str)
        .ok_or_else(|| "dns-record-evidence-invalid".to_string())?;
    let target = configured_unbound_target();
    let metadata = fs::symlink_metadata(&target)
        .map_err(|error| format!("dns-record-target-stat-failed: {error}"))?;
    if !metadata.file_type().is_file() { return Err("dns-record-target-not-regular-file".into()); }
    let original = fs::read(&target).map_err(|error| format!("dns-record-target-read-failed: {error}"))?;
    let candidate = insert_dns_record(&original, record)?;
    let scratch = path.parent().unwrap_or_else(|| Path::new("."))
        .join("interactable-candidates").join(format!("{}.conf", item.id));
    fs::create_dir_all(scratch.parent().unwrap()).map_err(|e| e.to_string())?;
    fs::write(&scratch, &candidate).map_err(|e| format!("dns-record-candidate-write-failed: {e}"))?;
    #[cfg(any(test, feature = "test-facade"))]
    let check_program = env::var("HARMONIA_UNBOUND_CHECKCONF")
        .unwrap_or_else(|_| "/usr/sbin/unbound-checkconf".into());
    #[cfg(not(any(test, feature = "test-facade")))]
    let check_program = "/usr/sbin/unbound-checkconf".to_string();
    let check = crate::atoms::ask::read_only_command_with_timeout(
        &check_program, &[scratch.to_string_lossy().into_owned()], Duration::from_secs(10));
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
    let invocation = invocation
        .ok_or_else(|| "dns-record-systemd-invocation-key-missing".to_string())?;
    let backup = path.parent().unwrap_or_else(|| Path::new("."))
        .join("interactables-backups").join(&item.id)
        .join(format!("{}-unbound.conf", now_seconds()));
    let projection = match crate::atoms::projectio::strike(crate::atoms::projectio::Request {
        target: &target, desired_bytes: &candidate, mode: metadata.mode() & 0o7777,
        uid: metadata.uid(), gid: metadata.gid(), backup_path: &backup,
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
    feed.receipts.push(receipt.clone());
    if reload.ok { feed.interactables.remove(position); }
    crate::bands::propose_edits::persist_feed(path, feed)?;
    if !reload.ok { return Err("dns-record-reload-failed".into()); }
    println!("{}", serde_json::to_string_pretty(&receipt).map_err(|e| e.to_string())?);
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
