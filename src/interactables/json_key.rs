//! One-key ConfigPlane proposals. Values stay in the declaration, not the feed.
use super::{DriftSummary, Interactable};
use crate::bands::propose_edits::{persist_feed_with_intent, FeedPersistenceIntent};
use crate::tools::ladder::LadderManifest;
use crate::tools::routine::ValidatedStep;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const PERMUTATION: &str = "json-key-proposal";
const MARKER: &str = "json_key_proposal";
// A single-transaction cache, never retained after the reply.
const MAX_JSON_BYTES: u64 = 4 * 1024 * 1024;

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct KeyState {
    present: bool,
    sha256: Option<String>,
}

impl KeyState {
    fn of(value: Option<&Value>) -> Self {
        Self {
            present: value.is_some(),
            sha256: value.map(|value| digest(value.to_string().as_bytes())),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Marker {
    key: String,
    step_id: String,
    manifest_sha256: String,
    #[serde(default)]
    profile_index: Option<PathBuf>,
    before: KeyState,
    after: KeyState,
}

pub(crate) fn planned_args(args: &BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    let mut planned = args.clone();
    let value = planned.remove("value");
    planned.insert(
        "desired_key_state".into(),
        json!(KeyState::of(value.as_ref())),
    );
    planned
}

fn target_allowed(target: &Path) -> Result<(), String> {
    if !target.is_absolute()
        || target
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err("json-key-target-path-invalid".into());
    }
    crate::atoms::files::validate_interactable_target(target)?;
    if target == Path::new("/etc/appliance/profile.json")
        || target == Path::new("/etc/appliance/config.factory")
    {
        return Err("json-key-identity-target-refused".into());
    }
    if !matches!(
        crate::atoms::files::classify_target(target),
        crate::atoms::files::TargetClass::Config
    ) {
        return Err("json-key-config-plane-required".into());
    }
    Ok(())
}

pub(crate) fn validate_args(args: &BTreeMap<String, Value>) -> Result<(), String> {
    let target = args
        .get("target")
        .and_then(Value::as_str)
        .ok_or("json-key-target-required")?;
    target_allowed(Path::new(target))?;
    if args.get("key").and_then(Value::as_str).is_none() {
        return Err("json-key-key-required".into());
    }
    let name = args
        .get("receipt_name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or("json-key-receipt-name-required")?;
    crate::atoms::files::validate_receipt_name(name)
}

fn read_regular(path: &Path, prefix: &str) -> Result<(Vec<u8>, Metadata), String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            format!(
                "{prefix}-{}",
                if error.kind() == std::io::ErrorKind::NotFound {
                    "absent"
                } else {
                    "open-refused"
                }
            )
        })?;
    let metadata = file
        .metadata()
        .map_err(|_| format!("{prefix}-stat-failed"))?;
    if !metadata.is_file() {
        return Err(format!("{prefix}-not-regular"));
    }
    if metadata.len() > MAX_JSON_BYTES {
        return Err(format!("{prefix}-too-large"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_JSON_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| format!("{prefix}-read-failed"))?;
    if bytes.len() as u64 > MAX_JSON_BYTES {
        return Err(format!("{prefix}-too-large"));
    }
    Ok((bytes, metadata))
}

struct Member {
    name: String,
    key_start: usize,
    value_start: usize,
    value_end: usize,
    comma: Option<usize>,
}

struct Document {
    bytes: Vec<u8>,
    object: Map<String, Value>,
    members: Vec<Member>,
    close: usize,
}

fn whitespace(bytes: &[u8], mut at: usize) -> usize {
    while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    at
}

impl Document {
    fn parse(bytes: Vec<u8>) -> Result<Self, String> {
        // Never return a parser error containing a literal value.
        let root: Value =
            serde_json::from_slice(&bytes).map_err(|_| "json-key-target-unparseable")?;
        let Value::Object(object) = root else {
            return Err("json-key-target-not-object".into());
        };
        let mut at = whitespace(&bytes, 0) + 1;
        let mut members = Vec::new();
        let mut names = BTreeSet::new();
        loop {
            at = whitespace(&bytes, at);
            if bytes.get(at) == Some(&b'}') {
                break;
            }
            let key_start = at;
            at += 1; // Entire document is already valid JSON; this is a quoted key.
            while bytes[at] != b'"' {
                at += if bytes[at] == b'\\' { 2 } else { 1 };
            }
            at += 1;
            let name: String = serde_json::from_slice(&bytes[key_start..at])
                .map_err(|_| "json-key-target-unparseable")?;
            if !names.insert(name.clone()) {
                return Err("json-key-target-duplicate-key".into());
            }
            at = whitespace(&bytes, at) + 1; // Colon.
            let value_start = whitespace(&bytes, at);
            let mut stream =
                serde_json::Deserializer::from_slice(&bytes[value_start..]).into_iter::<Value>();
            stream
                .next()
                .ok_or("json-key-target-unparseable")?
                .map_err(|_| "json-key-target-unparseable")?;
            let value_end = value_start + stream.byte_offset();
            at = whitespace(&bytes, value_end);
            let comma = (bytes.get(at) == Some(&b',')).then_some(at);
            members.push(Member {
                name,
                key_start,
                value_start,
                value_end,
                comma,
            });
            if comma.is_some() {
                at += 1;
            } else {
                break;
            }
        }
        let close = whitespace(&bytes, at);
        Ok(Self {
            bytes,
            object,
            members,
            close,
        })
    }

    fn edit(&self, key: &str, value: Option<&Value>) -> Result<Vec<u8>, String> {
        let found = self.members.iter().position(|member| member.name == key);
        let (start, end, replacement) = match (found, value) {
            (Some(index), Some(value)) => {
                let member = &self.members[index];
                (
                    member.value_start,
                    member.value_end,
                    value.to_string().into_bytes(),
                )
            }
            (Some(index), None) => {
                let member = &self.members[index];
                if let Some(comma) = member.comma {
                    let start = if index == 0 {
                        whitespace(&self.bytes, 0) + 1
                    } else {
                        self.members[index - 1]
                            .comma
                            .ok_or("json-key-edit-invalid")?
                            + 1
                    };
                    (start, comma + 1, Vec::new())
                } else if index > 0 {
                    (
                        self.members[index - 1]
                            .comma
                            .ok_or("json-key-edit-invalid")?,
                        member.value_end,
                        Vec::new(),
                    )
                } else {
                    (member.key_start, member.value_end, Vec::new())
                }
            }
            (None, Some(value)) => {
                let at = self
                    .members
                    .last()
                    .map(|member| member.value_end)
                    .unwrap_or(self.close);
                let prefix = if self.members.is_empty() { "" } else { "," };
                (
                    at,
                    at,
                    format!("{prefix}{}:{value}", json!(key)).into_bytes(),
                )
            }
            (None, None) => return Ok(self.bytes.clone()),
        };
        let mut bytes = self.bytes[..start].to_vec();
        bytes.extend_from_slice(&replacement);
        bytes.extend_from_slice(&self.bytes[end..]);
        let checked = Self::parse(bytes)?;
        let mut expected = self.object.clone();
        if let Some(value) = value {
            expected.insert(key.into(), value.clone());
        } else {
            expected.remove(key);
        }
        if checked.object != expected {
            return Err("json-key-edit-readback-invalid".into());
        }
        // Prove the formatting claim: every other value retains its literal bytes.
        for member in self.members.iter().filter(|member| member.name != key) {
            let other = checked
                .members
                .iter()
                .find(|other| other.name == member.name)
                .ok_or("json-key-unowned-key-lost")?;
            if self.bytes[member.value_start..member.value_end]
                != checked.bytes[other.value_start..other.value_end]
            {
                return Err("json-key-unowned-value-changed".into());
            }
        }
        Ok(checked.bytes)
    }
}

fn observe(target: &Path) -> Result<(Document, Metadata), String> {
    target_allowed(target)?;
    let (bytes, metadata) = read_regular(target, "json-key-target")?;
    // Refuse aliases into identity or credential custody, including parent symlinks.
    let canonical = fs::canonicalize(target).map_err(|_| "json-key-target-resolve-failed")?;
    if canonical != target {
        return Err("json-key-target-alias-refused".into());
    }
    Ok((Document::parse(bytes)?, metadata))
}

fn proposal_id(target: &Path, key: &str) -> String {
    let identity = json!([target, key]);
    format!("json-key-{}", digest(identity.to_string().as_bytes()))
}

fn merge_marker(old: Option<&Value>, new: &Value) -> Value {
    if let Value::Object(fields) = new {
        let mut result = old.and_then(Value::as_object).cloned().unwrap_or_default();
        for (key, value) in fields {
            result.insert(key.clone(), merge_marker(result.get(key), value));
        }
        Value::Object(result)
    } else {
        new.clone()
    }
}

pub(crate) fn propose(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    receipt_dir: &Path,
) -> Result<crate::OperationOutcome, String> {
    validate_args(&step.args)?;
    let target = Path::new(
        step.args["target"]
            .as_str()
            .ok_or("json-key-target-required")?,
    );
    let key = step.args["key"].as_str().ok_or("json-key-key-required")?;
    let (document, _) = observe(target)?;
    let before = KeyState::of(document.object.get(key));
    let after = KeyState::of(step.args.get("value"));
    let id = proposal_id(target, key);
    let path = super::feed_path();
    let feed = super::load_feed(&path)?;
    let prior = feed.interactables.iter().find(|item| item.id == id);
    let current = document.object.get(key) == step.args.get("value");
    if current {
        if prior.is_some() {
            persist_feed_with_intent(
                &path,
                FeedPersistenceIntent::Remove {
                    ids: [id].into_iter().collect(),
                    receipts: Vec::new(),
                },
            )?;
        }
        return Ok(crate::OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "json-key-current".into(),
            command: None,
        });
    }
    // Check the candidate now, but never write it on the update path.
    document.edit(key, step.args.get("value"))?;
    let manifest_path = manifest.base_dir.join("manifest.json");
    if !manifest_path.is_absolute() {
        return Err("json-key-manifest-path-invalid".into());
    }
    let (source, _) = read_regular(&manifest_path, "json-key-manifest")?;
    let source_sha = digest(&source);
    let marker = Marker {
        key: key.into(),
        step_id: step.step_id.clone(),
        manifest_sha256: source_sha.clone(),
        profile_index: manifest.selected_profile_index.clone(),
        before: before.clone(),
        after: after.clone(),
    };
    let mut extra = prior.map(|item| item.extra.clone()).unwrap_or_default();
    let marker_value = merge_marker(extra.get(MARKER), &json!(marker));
    let unchanged = prior.is_some_and(|item| {
        item.reference_source_path.as_deref() == Some(manifest_path.as_path())
            && item.extra.get(MARKER) == Some(&marker_value)
    });
    extra.insert(MARKER.into(), marker_value);
    if !unchanged {
        let now = crate::bands::propose_edits::iso8601_now();
        let item = Interactable {
            id: id.clone(), module_id: manifest.id.clone(), name: format!("{}: JSON key proposal", manifest.id),
            description: "Only the owner's explicit run changes this top-level key; other keys are preserved.".into(),
            kind: "hard-stamp".into(), target_path: Some(target.into()),
            reference_source_path: Some(manifest_path),
            drift: DriftSummary { content: true, mode: false, ownership: false },
            created_at: prior.map(|item| item.created_at.clone()).unwrap_or_else(|| now.clone()),
            refreshed_at: now.clone(), available_at: Some(now), silenced: false, silenced_at: None,
            has_run: false, mode: None, owner: None, group: None,
            source_sha: None, target_sha: None, commits_behind: None, live_sha: None,
            reference_sha: Some(source_sha), recognition_score: None,
            diff: Some(json!({"key":key,"before":before,"after":after}).to_string()),
            script: String::new(), show_only_if: String::new(), completion_check: String::new(),
            evidence: Value::Null, extra,
        };
        persist_feed_with_intent(
            &path,
            FeedPersistenceIntent::Upsert {
                entries: vec![item],
                remove_ids: BTreeSet::new(),
                sort_by_id: true,
            },
        )?;
    }
    let outcome = crate::OperationOutcome {
        ok: true,
        changed: false,
        skipped: false,
        message: json!({"config_state":"interactable","proposal_id":id,"target":target,
            "key":key,"before":before,"after":after,"changed":false})
        .to_string(),
        command: None,
    };
    crate::receipts::write_tool_receipt(
        receipt_dir,
        step.args["receipt_name"]
            .as_str()
            .ok_or("json-key-receipt-name-required")?,
        "files",
        PERMUTATION,
        &outcome,
    )?;
    Ok(outcome)
}

pub(crate) fn run(
    path: &Path,
    item: &Interactable,
    invocation: Option<&crate::Invocation>,
) -> Result<(), String> {
    invocation
        .and_then(crate::Invocation::key)
        .ok_or("json-key-owner-acceptance-required")?;
    let marker: Marker = serde_json::from_value(
        item.extra
            .get(MARKER)
            .cloned()
            .ok_or("json-key-proposal-marker-absent")?,
    )
    .map_err(|_| "json-key-proposal-marker-invalid")?;
    let target = item
        .target_path
        .as_deref()
        .ok_or("json-key-proposal-target-absent")?;
    if item.kind != "hard-stamp" || item.id != proposal_id(target, &marker.key) {
        return Err("json-key-proposal-id-binding-invalid".into());
    }
    let source_path = item
        .reference_source_path
        .as_deref()
        .ok_or("json-key-proposal-source-absent")?;
    let (source, _) = read_regular(source_path, "json-key-manifest")?;
    if digest(&source) != marker.manifest_sha256
        || item.reference_sha.as_deref() != Some(marker.manifest_sha256.as_str())
    {
        return Err("json-key-proposal-source-stale".into());
    }
    let manifest = crate::tools::ladder::load_ladder_manifest_with_context(
        source_path,
        false,
        marker.profile_index.as_deref(),
    )
    .map_err(|_| "json-key-manifest-invalid")?;
    if manifest.id != item.module_id {
        return Err("json-key-proposal-module-stale".into());
    }
    let steps = crate::tools::ladder::validate_ladder(&manifest)
        .map_err(|_| "json-key-manifest-invalid")?;
    let step = steps
        .iter()
        .find(|step| step.step_id == marker.step_id)
        .ok_or("json-key-proposal-step-stale")?;
    if step.tool != "files" || step.permutation != PERMUTATION {
        return Err("json-key-proposal-step-stale".into());
    }
    validate_args(&step.args)?;
    if step
        .args
        .get("target")
        .and_then(Value::as_str)
        .map(Path::new)
        != Some(target)
        || step.args.get("key").and_then(Value::as_str) != Some(marker.key.as_str())
        || KeyState::of(step.args.get("value")) != marker.after
    {
        return Err("json-key-proposal-declaration-stale".into());
    }
    let (document, metadata) = observe(target)?;
    let before = KeyState::of(document.object.get(&marker.key));
    let changed = document.object.get(&marker.key) != step.args.get("value");
    // Adding/removing a member necessarily changes separator layout. Only an
    // existing-value replacement (or a no-op) preserves all outside-value bytes.
    let formatting_preserved =
        !changed || (document.object.contains_key(&marker.key) && step.args.contains_key("value"));
    if changed && before != marker.before {
        return Err("json-key-proposal-preimage-stale".into());
    }
    let mut backup_path = None;
    let mut after = before.clone();
    if changed {
        let bytes = document.edit(&marker.key, step.args.get("value"))?;
        let (reread, current_metadata) = read_regular(target, "json-key-target")?;
        let (source_reread, _) = read_regular(source_path, "json-key-manifest")?;
        if reread != document.bytes
            || current_metadata.ino() != metadata.ino()
            || current_metadata.dev() != metadata.dev()
            || digest(&source_reread) != marker.manifest_sha256
        {
            return Err("json-key-proposal-changed-before-act".into());
        }
        let backup_dir = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("interactables-backups")
            .join(&item.id);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&backup_dir)
            .map_err(|_| "json-key-backup-parent-create-failed")?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "json-key-backup-clock-failed")?
            .as_nanos();
        let backup = backup_dir.join(format!(
            "{stamp}-{}",
            target
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("target")
        ));
        // The sole mutation route: an explicit owner run, never update --apply.
        let struck = crate::atoms::projectio::strike_if_current(
            crate::atoms::projectio::Request {
                target,
                desired_bytes: &bytes,
                mode: metadata.mode() & 0o7777,
                uid: metadata.uid(),
                gid: metadata.gid(),
                backup_path: &backup,
                witness: crate::atoms::projectio::owner_acceptance(super::operator_hand()),
            },
            &document.bytes,
            &metadata,
        )?;
        // Do not serialize Projectio::Receipt: it contains struck_bytes.
        backup_path = Some(struck.backup_path);
        let (readback, _) = observe(target)?;
        after = KeyState::of(readback.object.get(&marker.key));
        if after != marker.after {
            return Err("json-key-readback-mismatch".into());
        }
    }
    persist_feed_with_intent(
        path,
        FeedPersistenceIntent::Remove {
            ids: [item.id.clone()].into_iter().collect(),
            receipts: Vec::new(),
        },
    )?;
    // Receipts go home; no completed receipt or value is cached in the feed.
    println!(
        "{}",
        json!({"schema":"harmonia.interactables.hard_stamp.receipt.v1",
        "ok":true,"id":item.id,"kind":"hard-stamp","config_state":"interactable",
        "target":target,"key":marker.key,"before":before,"after":after,
        "changed":changed,"has_run":true,"formatting_preserved":formatting_preserved,
        "untouched_values_preserved":true,"key_order_preserved":true,
        "formatting_scope":"outside-owned-value","backup_path":backup_path,
        "mode":metadata.mode() & 0o7777,"uid":metadata.uid(),"gid":metadata.gid(),
        "first_missing_signal":"none"})
    );
    Ok(())
}
