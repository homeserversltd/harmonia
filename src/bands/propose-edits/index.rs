use super::Band;
use crate::interactables::{self, DriftSummary, Interactable};
use crate::tools::files::{FileConvergenceOutcome, FileConvergenceRequest};
use crate::tools::ladder::{LadderManifest, ProjectedRoutineChild, ValidatedStep};
use crate::ModuleExecution;
use crate::{
    LoadedModule, PackageAuthority, Profile, ProfileProjection, SoftwareApplyAuthorization,
    UpdateMode,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::cell::RefCell;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

thread_local! {
    static CURRENT_CONFIG_RECOGNITIONS: RefCell<BTreeMap<String, Value>> = RefCell::new(BTreeMap::new());
    static CONFIG_SOURCE_STEP: RefCell<Option<String>> = const { RefCell::new(None) };
    static CONFIG_ACTIVE_LANE: RefCell<Option<String>> = const { RefCell::new(None) };
}

pub(crate) struct ConfigActiveLaneGuard(Option<String>);

impl ConfigActiveLaneGuard {
    pub(crate) fn enter(lane: Option<&str>) -> Self {
        Self(CONFIG_ACTIVE_LANE.with(|current| current.replace(lane.map(str::to_owned))))
    }
}

impl Drop for ConfigActiveLaneGuard {
    fn drop(&mut self) {
        CONFIG_ACTIVE_LANE.with(|current| current.replace(self.0.take()));
    }
}

/// A lowered file child belongs to its source ladder step, not to its generated name.
/// Keep that identity only for this routine call and restore it on every return.
pub(crate) struct ConfigSourceStepGuard(Option<String>);

impl ConfigSourceStepGuard {
    pub(crate) fn enter(step_id: &str) -> Self {
        Self(CONFIG_SOURCE_STEP.with(|current| current.replace(Some(step_id.to_owned()))))
    }
}

impl Drop for ConfigSourceStepGuard {
    fn drop(&mut self) {
        CONFIG_SOURCE_STEP.with(|current| current.replace(self.0.take()));
    }
}

pub(crate) fn reset_config_state_recognitions() {
    CURRENT_CONFIG_RECOGNITIONS.with(|state| state.borrow_mut().clear());
}

pub(crate) fn take_config_state_recognitions() -> BTreeMap<String, Value> {
    CURRENT_CONFIG_RECOGNITIONS.with(|state| std::mem::take(&mut *state.borrow_mut()))
}

/// A key-level offer was observed by this invocation. Keep its identity for
/// pruning, never its private preimage in the public config-surface reply.
pub(crate) fn remember_config_proposal(id: &str) {
    CURRENT_CONFIG_RECOGNITIONS.with(|state| {
        state.borrow_mut().entry(id.to_owned()).or_insert(Value::Null);
    });
}

pub(crate) fn enter(enter: &mut impl FnMut(Band) -> Result<(), String>) -> Result<(), String> {
    enter(Band::ProposeEdits)
}
fn stamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into())
}
pub(crate) fn iso8601_now() -> String {
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
enum ConfigAncestor {
    Generated,
    Unnamed,
    Named { oid: String, bytes: Vec<u8> },
}

fn config_history_path(manifest: &LadderManifest, source: &Path, target: &Path, reference: &[u8]) -> Option<(PathBuf, PathBuf)> {
    let profile_index = manifest.selected_profile_index.as_ref()?;
    let profile = profile_index.parent()?.file_name()?.to_str()?;
    let root = crate::bands::renew_self::engine_source_root().canonicalize().ok()?;
    let module = crate::bands::stage_profile::source_module_path(&root, profile, &manifest.id).ok()?.canonicalize().ok()?;
    if !module.starts_with(&root) { return None; }
    let path = if let Ok(relative) = source.strip_prefix(&manifest.base_dir) {
        crate::atoms::files::validate_relative_path(relative).ok()?;
        module.join(relative)
    } else {
        let files_root = manifest.files_root.as_ref()?;
        let relative = target.strip_prefix("/").ok()?;
        crate::atoms::files::validate_relative_path(relative).ok()?;
        module.join(files_root).join(relative)
    };
    if fs::read(&path).ok()?.as_slice() != reference { return None; }
    let relative = path.strip_prefix(&root).ok()?.to_path_buf();
    crate::atoms::files::validate_relative_path(&relative).ok()?;
    Some((root, relative))
}

fn history_command(root: &Path) -> std::process::Command {
    let mut command = std::process::Command::new("git");
    command.arg("--no-optional-locks").arg("-c").arg(format!("safe.directory={}", root.display())).arg("-C").arg(root)
        .env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_TERMINAL_PROMPT", "0")
        .env_remove("GIT_DIR").env_remove("GIT_WORK_TREE").env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY").env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES");
    command
}

fn history_git(root: &Path, args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>, String> {
    use std::io::Write;
    use std::process::Stdio;
    let mut command = history_command(root);
    command.args(args)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = command.spawn().map_err(|error| format!("config-history-git-start: {error}"))?;
    if let Some(bytes) = input {
        child.stdin.take().ok_or("config-history-stdin-missing")?.write_all(bytes)
            .map_err(|error| format!("config-history-stdin: {error}"))?;
    }
    let output = child.wait_with_output().map_err(|error| format!("config-history-git-wait: {error}"))?;
    if !output.status.success() { return Err("config-history-git-failed".into()); }
    Ok(output.stdout)
}

fn git_oid(bytes: &[u8]) -> Option<String> {
    let oid = std::str::from_utf8(bytes).ok()?.trim();
    if matches!(oid.len(), 40 | 64) && oid.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        Some(oid.to_owned())
    } else { None }
}

fn history_blob_at(root: &Path, commit: &str, path: &Path) -> Option<(String, Vec<u8>)> {
    if git_oid(commit.as_bytes()).is_none() { return None; }
    let spec = format!("{}:{}", commit, path.to_str()?);
    let oid = git_oid(&history_git(root, &["rev-parse", "--verify", &spec], None).ok()?)?;
    let bytes = history_git(root, &["cat-file", "blob", &oid], None).ok()?;
    Some((oid, bytes))
}

fn resolve_config_ancestor(manifest: &LadderManifest, source: &Path, target: &Path, live: &[u8], reference: &[u8], prior: Option<&Interactable>, prior_head: Option<&str>) -> Result<ConfigAncestor, String> {
    if let Some(oid) = prior.and_then(|item| item.extra.get("ancestor_sha")).and_then(Value::as_str) {
        let oid = git_oid(oid.as_bytes()).ok_or("config-history-ancestor-id-invalid")?;
        let root = crate::bands::renew_self::engine_source_root().canonicalize()
            .map_err(|error| format!("config-history-root-unavailable: {error}"))?;
        let bytes = history_git(&root, &["cat-file", "blob", &oid], None)?;
        return Ok(ConfigAncestor::Named { oid, bytes });
    }
    let source_is_tracked_candidate = source.starts_with(&manifest.base_dir)
        || manifest.files_root.as_ref().and_then(|root| target.strip_prefix("/").ok()
            .map(|relative| manifest.base_dir.join(root).join(relative)))
            .and_then(|path| fs::read(path).ok()).is_some_and(|bytes| bytes == reference);
    let Some((root, path)) = config_history_path(manifest, source, target, reference) else {
        return Ok(if source_is_tracked_candidate { ConfigAncestor::Unnamed } else { ConfigAncestor::Generated });
    };
    let live_oid = git_oid(&history_git(&root, &["hash-object", "--stdin"], Some(live))?)
        .ok_or("config-history-live-id-invalid")?;
    let find = format!("--find-object={live_oid}");
    let path_text = path.to_str().ok_or("config-history-path-not-utf8")?;
    let mut child = history_command(&root).args(["log", "--format=%H", &find, "--", path_text])
        .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null()).spawn()
        .map_err(|error| format!("config-history-log-start: {error}"))?;
    let stdout = child.stdout.take().ok_or("config-history-log-output-missing")?;
    let mut found = None;
    let mut read_error = None;
    use std::io::BufRead;
    for line in std::io::BufReader::new(stdout).lines() {
        match line {
            Ok(line) if found.is_none() => {
                if let Some((oid, bytes)) = history_blob_at(&root, &line, &path) {
                    if oid == live_oid && bytes == live { found = Some((oid, bytes)); }
                }
            }
            Ok(_) => {}
            Err(error) => { read_error = Some(error); break; }
        }
    }
    let status = child.wait().map_err(|error| format!("config-history-log-wait: {error}"))?;
    if let Some(error) = read_error { return Err(format!("config-history-log-read: {error}")); }
    if !status.success() { return Err("config-history-log-failed".into()); }
    if let Some((oid, bytes)) = found { return Ok(ConfigAncestor::Named { oid, bytes }); }
    if let Some(head) = prior_head {
        if let Some((oid, bytes)) = history_blob_at(&root, head, &path) {
            if bytes != reference { return Ok(ConfigAncestor::Named { oid, bytes }); }
        }
    }
    Ok(ConfigAncestor::Unnamed)
}

fn is_legacy_config(item: &Interactable) -> bool {
    !item.extra.contains_key("ancestor_sha")
        && item.extra.get("generated_config").and_then(Value::as_bool) != Some(true)
}

pub(crate) fn config_offer_eligible(manifest: &LadderManifest, source: &Path, target: &Path) -> Result<bool, String> {
    let reference = read_regular_file_no_follow(source, "config-check-source")?;
    config_offer_eligible_bytes(manifest, source, target, &reference)
}

pub(crate) fn config_offer_eligible_bytes(manifest: &LadderManifest, source: &Path, target: &Path, reference: &[u8]) -> Result<bool, String> {
    let live = read_regular_file_no_follow(target, "config-check-target")?;
    if live == reference || interactables::normalized_line_score(&String::from_utf8_lossy(&live), &String::from_utf8_lossy(reference)) < 0.33 { return Ok(false); }
    let feed = interactables::load_feed(&crate::ledger::database_path())?;
    let prior = feed.interactables.iter().find(|item| is_config_proposal_id(&item.id) && item.kind == "hard-stamp" && item.module_id == manifest.id && item.target_path.as_deref() == Some(target));

    let prior_head = crate::bands::renew_self::content_prior_head();
    match resolve_config_ancestor(manifest, source, target, &live, reference, prior, prior_head.as_deref())? {
        ConfigAncestor::Generated => Ok(true),
        ConfigAncestor::Unnamed => Ok(prior.is_some_and(|item| item.extra.contains_key("ancestor_sha"))),
        ConfigAncestor::Named { bytes, .. } => {
            if bytes == reference { return Ok(false); }
            let (merged, _) = land_config_slice(&bytes, &live, reference)?;
            Ok(merged != live)
        }
    }
}

fn land_config_slice(ancestor: &[u8], live: &[u8], reference: &[u8]) -> Result<(Vec<u8>, &'static str), String> {
    let ancestor = std::str::from_utf8(ancestor).map_err(|_| "config-slice-ancestor-not-utf8")?;
    let live = std::str::from_utf8(live).map_err(|_| "config-slice-live-not-utf8")?;
    let reference = std::str::from_utf8(reference).map_err(|_| "config-slice-reference-not-utf8")?;
    let options = threeway_merge::MergeOptions::default();
    let observed = threeway_merge::merge_strings(ancestor, live, reference, &options)
        .map_err(|error| format!("config-slice-merge-failed: {error}"))?;
    let conflict = observed.has_conflicts();
    let bytes = if conflict {
        let favor = threeway_merge::MergeOptions {
            favor: Some(threeway_merge::MergeFavor::Theirs),
            ..options
        };
        threeway_merge::merge_strings(ancestor, live, reference, &favor)
            .map_err(|error| format!("config-slice-merge-failed: {error}"))?.content
    } else {
        observed.content
    };
    let case = if conflict { "conflict" } else if ancestor == live { "default-moved" } else { "default-rolled" };
    Ok((bytes.into_bytes(), case))
}

fn proposal_diff(target: &Path, live: &[u8], proposed: &[u8]) -> Option<String> {
    const LIMIT: usize = 256 * 1024;
    if live == proposed || live.len() > LIMIT || proposed.len() > LIMIT {
        return None;
    }
    let live = std::str::from_utf8(live).ok()?;
    let proposed = std::str::from_utf8(proposed).ok()?;
    Some(similar::TextDiff::from_lines(live, proposed)
        .unified_diff()
        .context_radius(3)
        .header(&format!("{} (yours)", target.display()), &format!("{} (after Yes)", target.display()))
        .to_string())
}

fn stable_id(surface: &Path, live_sha: &str, reference_sha: &str) -> String {
    let digest =
        Sha256::digest(format!("{}:{live_sha}:{reference_sha}", surface.display()).as_bytes());
    format!("config-proposal-{}", &format!("{digest:x}")[..16])
}

pub(crate) fn compiled_absent_proposal_id(surface: &Path, reference_sha: &str) -> String {
    let digest =
        Sha256::digest(format!("{}:absent:{reference_sha}", surface.display()).as_bytes());
    format!("config-proposal-{}", &format!("{digest:x}")[..16])
}

fn is_config_proposal_id(id: &str) -> bool {
    id.strip_prefix("config-proposal-")
        .is_some_and(|key| key.len() == 16 && key.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
}

// Validated-symlink proposals carry a full SHA-256, as do command
// proposals. Only the symlink marker makes a full digest a file row.
fn is_prunable_config_proposal_id(entry: &interactables::Interactable) -> bool {
    if is_config_proposal_id(&entry.id) { return true; }
    entry.extra.get("validated_symlink").is_some_and(|marker| !marker.is_null())
        && entry.id.strip_prefix("config-proposal-")
        .is_some_and(|key| key.len() == 64
            && key.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
}

fn read_regular_file_no_follow(path: &Path, context: &str) -> Result<Vec<u8>, String> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .map_err(|error| format!("{context}-read-failed {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("{context}-observe-failed {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{context}-not-regular {}", path.display()));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("{context}-read-failed {}: {error}", path.display()))?;
    Ok(bytes)
}

fn proposal_reference(id: &str) -> Result<PathBuf, String> {
    if !is_config_proposal_id(id) {
        return Err("config-proposal-source-id-invalid".to_string());
    }
    // This is a product reference, not a caller's staging location. The source
    // bytes live in keyed SQLite state; no snapshot file is created here.
    Ok(Path::new("/var/lib/harmonia/proposal-sources").join(format!("{id}.source")))
}

pub(crate) enum FeedPersistenceIntent {
    Upsert {
        entries: Vec<Interactable>,
        remove_ids: BTreeSet<String>,
        sort_by_id: bool,
    },
    ConfigUpsert {
        entries: Vec<Interactable>,
        remove_ids: BTreeSet<String>,
        observed: Vec<Interactable>,
        checks: Vec<(PathBuf, Option<String>)>,
    },
    ReconcileRuyi {
        entries: Vec<Interactable>,
        remove_ids: BTreeSet<String>,
        observed: Vec<Interactable>,
    },
    Remove {
        ids: BTreeSet<String>,
        receipts: Vec<Value>,
    },

    AppendReceipts(Vec<Value>),
    HermesAppearanceOffer {
        module_id: String,
        entry: Option<Interactable>,
    },
    CompleteHermesAppearance {
        module_id: String,
        item_id: String,
        receipt: Value,
    },
}

fn compose_feed(
    connection: &rusqlite::Connection,
    mut feed: interactables::InteractablesFeed,
    intent: &FeedPersistenceIntent,
) -> Result<interactables::InteractablesFeed, String> {
    Ok(match intent {
        FeedPersistenceIntent::Upsert {
            entries,
            remove_ids,
            sort_by_id,
        } => {
            feed.interactables
                .retain(|item| !remove_ids.contains(&item.id));
            for entry in entries {
                if let Some(current) = feed
                    .interactables
                    .iter_mut()
                    .find(|current| current.id == entry.id)
                {
                    let mut replacement = entry.clone();
                    replacement.silenced = current.silenced;
                    replacement.silenced_at = current.silenced_at.clone();
                    replacement.has_run = current.has_run;
                    for (key, value) in &current.extra {
                        replacement
                            .extra
                            .entry(key.clone())
                            .or_insert(value.clone());
                    }
                    let mut stable = replacement.clone();
                    stable.created_at = current.created_at.clone();
                    stable.refreshed_at = current.refreshed_at.clone();
                    stable.available_at = current.available_at.clone();
                    if serde_json::to_value(&stable).is_ok_and(|candidate| {
                        serde_json::to_value(&*current).is_ok_and(|prior| candidate == prior)
                    }) {
                        replacement = stable;
                    }
                    *current = replacement;
                } else {
                    feed.interactables.push(entry.clone());
                }
            }
            if *sort_by_id {
                feed.interactables.sort_by(|a, b| a.id.cmp(&b.id));
            }
            feed
        }
        FeedPersistenceIntent::ConfigUpsert { entries, remove_ids, observed, checks } => {
            let mut targets = checks.iter().map(|(target, _)| target.clone()).collect::<BTreeSet<_>>();
            targets.extend(observed.iter().filter(|item| remove_ids.contains(&item.id)).filter_map(|item| item.target_path.clone()));
            let projection = |items: &[Interactable]| -> Result<BTreeMap<String, Value>, String> {
                items.iter().filter(|item| item.target_path.as_ref().is_some_and(|path| targets.contains(path)))
                    .map(|item| Ok((item.id.clone(), serde_json::to_value(item).map_err(|error| error.to_string())?)))
                    .collect()
            };
            if projection(observed)? != projection(&feed.interactables)? {
                return Err("config-proposal-observation-stale".into());
            }
            for (target, expected) in checks {
                if let Some(expected) = expected {
                    let current = read_regular_file_no_follow(target, "config-interactable-target")?;
                    if format!("{:x}", Sha256::digest(&current)) != *expected {
                        return Err("config-proposal-target-changed-since-observation".into());
                    }
                } else {
                    match fs::symlink_metadata(target) {
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
                        Ok(_) => return Err("config-proposal-target-changed-since-observation".into()),
                        Err(error) => return Err(format!("config-proposal-target-observe-failed: {error}")),
                    }
                }
            }
            return compose_feed(connection, feed, &FeedPersistenceIntent::Upsert {
                entries: entries.clone(), remove_ids: remove_ids.clone(), sort_by_id: true,
            });
        }
        FeedPersistenceIntent::ReconcileRuyi { entries, remove_ids, observed } => {
            let projection = |items: &[Interactable]| -> Result<BTreeMap<String, Value>, String> {
                items.iter().filter(|item| interactables::is_ruyi_born_kind(&item.kind))
                    .map(|item| Ok((item.id.clone(), serde_json::to_value(item).map_err(|error| error.to_string())?)))
                    .collect()
            };
            if projection(observed)? != projection(&feed.interactables)? {
                return Err("ruyi-proposal-observation-stale".into());
            }
            return compose_feed(connection, feed, &FeedPersistenceIntent::Upsert {
                entries: entries.clone(), remove_ids: remove_ids.clone(), sort_by_id: true,
            });
        }
        FeedPersistenceIntent::Remove { ids, receipts } => {
            feed.interactables.retain(|item| !ids.contains(&item.id));
            feed.receipts.extend(receipts.iter().cloned());
            feed
        }

        FeedPersistenceIntent::AppendReceipts(receipts) => {
            feed.receipts.extend(receipts.iter().cloned());
            feed
        }
        FeedPersistenceIntent::HermesAppearanceOffer { module_id, entry } => {
            let adopted = crate::ledger::adopted_homes_on(connection, module_id)?;
            let entry = entry.clone().and_then(|entry| {
                crate::tools::hermes_appearance::constrain_offer_to_unadopted(entry, &adopted)
            });
            let keep_index = entry.as_ref().and_then(|candidate| {
                feed.interactables.iter().position(|current| {
                    current.kind == "hermes-appearance"
                        && current.module_id == *module_id
                        && current.evidence == candidate.evidence
                        && current.reference_source_path == candidate.reference_source_path
                })
            });
            let extra_capacity = if entry.is_some() { 1 } else { 0 };
            let mut retained = Vec::with_capacity(feed.interactables.len() + extra_capacity);
            for (index, current) in feed.interactables.drain(..).enumerate() {
                if current.kind == "hermes-appearance" && current.module_id == *module_id {
                    if Some(index) == keep_index {
                        retained.push(current);
                    }
                } else {
                    retained.push(current);
                }
            }
            if keep_index.is_none() {
                if let Some(entry) = entry {
                    retained.push(entry);
                }
            }
            feed.interactables = retained;
            feed
        }
        FeedPersistenceIntent::CompleteHermesAppearance {
            module_id,
            item_id,
            receipt,
        } => {
            feed.receipts.push(receipt.clone());
            feed.interactables.retain(|current| {
                !(current.kind == "hermes-appearance"
                    && current.module_id == *module_id
                    && current.id == *item_id)
            });
            feed
        }
    })
}

pub(crate) fn persist_feed_with_intent(
    path: &Path,
    intent: FeedPersistenceIntent,
) -> Result<usize, String> {
    persist_feed_with_config(path, intent, &[]).map(|writes| writes.unwrap_or(0))
}

pub(crate) fn persist_feed_with_config(
    _path: &Path,
    intent: FeedPersistenceIntent,
    config: &[crate::ledger::ConfigProposal],
) -> Result<Option<usize>, String> {
    crate::ledger::with_proposal_transaction(|connection| {
        let before = connection.total_changes();
        if let FeedPersistenceIntent::AppendReceipts(receipts) = &intent {
            for receipt in receipts { crate::ledger::record_appearance_facts(connection, receipt)?; }
            crate::ledger::validate_proposals_on(connection)?;
            return Ok(Some((connection.total_changes() - before) as usize));
        }
        if let FeedPersistenceIntent::Remove { ids, receipts } = &intent {
            for id in ids { crate::ledger::remove_proposal_on(connection, id)?; }
            for receipt in receipts { crate::ledger::record_appearance_facts(connection, receipt)?; }
            crate::ledger::validate_proposals_on(connection)?;
            return Ok(Some((connection.total_changes() - before) as usize));
        }
        let current = crate::ledger::load_proposals_on(connection)?;
        let feed = compose_feed(connection, current, &intent)?;
        crate::ledger::save_proposals_on(connection, &feed, config)?;
        if matches!(&intent, FeedPersistenceIntent::ReconcileRuyi { .. }) {
            crate::ledger::retire_unmatched_ruyi_on(connection)?;
        }

        Ok(Some((connection.total_changes() - before) as usize))
    })
}

pub(crate) fn resolve_config_proposal_locked(
    connection: &rusqlite::Connection,
    id: &str,
    receipts: Vec<Value>,
) -> Result<bool, String> {
    if !crate::ledger::remove_proposal_on(connection, id)? {
        return Ok(false);
    }
    for receipt in &receipts { crate::ledger::record_appearance_facts(connection, receipt)?; }
    crate::ledger::validate_proposals_on(connection)?;
    Ok(true)
}

// A negative declaration judgment is safe only when every target-bearing
// argument can be resolved from the projected declaration. Runtime `from`
// values and unreadable file roots are unknown, never evidence of absence.
fn has_runtime_reference(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.contains_key("from") || map.values().any(has_runtime_reference),
        Value::Array(items) => items.iter().any(has_runtime_reference),
        _ => false,
    }
}

fn declaration_owns_target(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    target: &Path,
) -> Option<bool> {
    let keys: &[&str] = match (step.tool.as_str(), step.permutation.as_str()) {
        ("place-file", "place") => &["path"],
        ("files", "managed-files") => &[],
        ("files", "compile-fragments") => &["target_path", "output_path"],
        ("files", "json-key-proposal") => &["target"],
        ("files", "validated-symlink" | "symlink-converge" | "validated-file-symlink") => &[],
        ("files", "converge" | "directory-sync") => {
            if step.args.contains_key("files") { &["target_root", "files"] }
            else if step.permutation == "directory-sync" { &["target_root", "source_root"] }
            else { &["target_root"] }
        },
        _ => return Some(false),
    };
    if keys.iter().filter_map(|key| step.args.get(*key)).any(has_runtime_reference) {
        return None;
    }
    match (step.tool.as_str(), step.permutation.as_str()) {
        ("place-file", "place") => Some(step.args.get("path")?.as_str().map(Path::new)? == target),
        ("files", "managed-files") => {
            if let Some(files) = step.args.get("files") {
                let mut found = false;
                for file in files.as_array()? {
                    found |= Path::new(file.get("path")?.as_str()?) == target;
                }
                Some(found)
            } else {
                Some(crate::tools::files::materialize_managed_files(step, manifest)
                    .ok()?.iter().any(|file| Path::new(&file.path) == target))
            }
        }
        ("files", "compile-fragments") => Some(step.args.get("target_path")
            .or_else(|| step.args.get("output_path"))?.as_str().map(Path::new)? == target),
        ("files", "json-key-proposal") => Some(step.args.get("target")?.as_str().map(Path::new)? == target),
        ("files", "validated-symlink" | "symlink-converge" | "validated-file-symlink") => {
            let declared_form = step.args.contains_key("source") && step.args.contains_key("target");
            let keys: &[&str] = if declared_form { &["target"] }
                else { &["path", "link", "destination", "target_path"] };
            if keys.iter().filter_map(|key| step.args.get(*key)).any(has_runtime_reference) {
                return None;
            }
            Some(keys.iter().find_map(|key| step.args.get(*key).and_then(Value::as_str))
                .map(Path::new)? == target)
        }
        ("files", "converge" | "directory-sync") => {
            let root = Path::new(step.args.get("target_root")?.as_str()?);
            if let Some(files) = step.args.get("files") {
                let mut found = false;
                for file in files.as_array()? {
                    found |= root.join(file.as_str()?) == target;
                }
                return Some(found);
            }
            if step.permutation != "directory-sync" { return Some(false); }
            let Ok(relative) = target.strip_prefix(root) else { return Some(false); };
            crate::atoms::files::validate_relative_path(relative).ok()?;
            let source = step.args.get("source_root")?.as_str()?;
            let source_root = crate::tools::files::resolve_ladder_path(manifest, source);
            if !fs::metadata(&source_root).ok()?.is_dir() { return None; }
            match fs::symlink_metadata(source_root.join(relative)) {
                Ok(metadata) => Some(!metadata.file_type().is_dir()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(false),
                Err(_) => None,
            }
        }
        _ => Some(false),
    }
}

fn module_declares_target(
    projection: &ProfileProjection,
    module: &str,
    target: &Path,
) -> Option<bool> {
    let projected = projection.modules.get(module)?;
    let LoadedModule::Ladder(manifest) = &projected.loaded else { return None; };
    let mut unknown = false;
    for step in &projected.steps {
        match declaration_owns_target(step, manifest, target) {
            Some(true) => return Some(true),
            None => unknown = true,
            _ => {}
        }
        if let Some(children) = projected.routines.get(&step.step_id) {
            for child in children {
                let child = ValidatedStep {
                    step_id: child.name.clone(), tool: child.tool.clone(),
                    permutation: child.permutation.clone(), args: child.args.clone(),
                    on_failure: child.on_failure,
                };
                match declaration_owns_target(&child, manifest, target) {
                    Some(true) => return Some(true),
                    None => unknown = true,
                    _ => {}
                }
            }
        }
    }
    if unknown { None } else { Some(false) }
}

pub(crate) fn prune_stale_interactables(
    profile: &Profile,
    observed_modules: &BTreeSet<String>,
    eligible_modules: &BTreeSet<String>,
    projection: &ProfileProjection,
    events: &mut crate::receipts::EventSink,
) -> Result<Vec<(String, String)>, String> {
    let path = crate::ledger::database_path();
    prune_stale_interactables_with_observations(&path, profile, observed_modules, eligible_modules, Some(projection), events)
}

pub(crate) fn prune_stale_interactables_at_path(
    path: &Path,
    profile: &Profile,
    events: &mut crate::receipts::EventSink,
) -> Result<(), String> {
    prune_stale_interactables_with_observations(path, profile, &BTreeSet::new(), &BTreeSet::new(), None, events).map(|_| ())
}

fn prune_stale_interactables_with_observations(
    path: &Path,
    profile: &Profile,
    observed_modules: &BTreeSet<String>,
    eligible_modules: &BTreeSet<String>,
    projection: Option<&ProfileProjection>,
    _events: &mut crate::receipts::EventSink,
) -> Result<Vec<(String, String)>, String> {
    let active = profile.modules.iter().cloned().collect::<BTreeSet<_>>();
    let recognized: BTreeSet<String> = CURRENT_CONFIG_RECOGNITIONS.with(|state| state.borrow().keys().cloned().collect());
    // Import before taking the preimage, not inside the later prune transaction.
    drop(crate::ledger::writer()?);
    let snapshot = interactables::load_feed_raw(path)?.interactables.into_iter()
        .map(|item| Ok((item.id.clone(), serde_json::to_value(item).map_err(|error| error.to_string())?)))
        .collect::<Result<std::collections::BTreeMap<_,_>,String>>()?;
    if observed_modules.is_empty() && snapshot.is_empty() && !crate::ledger::has_unmatched_proposals()? {
        return Ok(Vec::new());
    }
    // Classify against the same write-locked snapshot that is persisted: a
    // producer may have refreshed the row after an earlier observation.
    let retired = crate::ledger::with_proposal_transaction(|connection| {
        let mut feed = crate::ledger::load_proposals_on(connection)?;
        let mut retained = Vec::with_capacity(feed.interactables.len());
        let mut undeclared = Vec::new();
        for entry in feed.interactables.drain(..) {
            let unchanged = snapshot.get(&entry.id).is_some_and(|prior| {
                serde_json::to_value(&entry).is_ok_and(|current| current == *prior)
            });
            if !unchanged {
                retained.push(entry);
                continue;
            }
            let target_undeclared = entry.kind == "hard-stamp"
                && is_prunable_config_proposal_id(&entry)
                && active.contains(&entry.module_id)
                && eligible_modules.contains(&entry.module_id)
                && !recognized.contains(&entry.id)
                && entry.target_path.as_deref().is_some_and(|target| {
                    projection.and_then(|view| module_declares_target(view, &entry.module_id, target))
                        == Some(false)
                });
            if target_undeclared {
                undeclared.push((entry.module_id.clone(), entry.id.clone()));
                continue;
            }
            let row_backed = crate::ledger::has_proposal_source_on(connection, &entry.id)?;
            let remove = if entry.kind == "engine-replacement" {
                true
            } else if !active.contains(&entry.module_id) {
                true
            } else if interactables::homeserver_clock_utc::is_generated_proposal(&entry) {
                profile.id != "homeserver" || profile.identity != "homeserver"
            } else if interactables::household_zone::is_generated_proposal(&entry) {
                crate::device_profile::certificate_product().as_deref() != Ok("homeserver")
            } else if interactables::household_zone::is_generated_set_proposal(&entry) {
                !matches!(crate::device_profile::certificate_product().as_deref(), Ok("hometv" | "homesi" | "homeconsole"))
            } else if row_backed && observed_modules.contains(&entry.module_id) && !recognized.contains(&entry.id) {
                true
            } else {
                !interactables::is_ruyi_born_kind(&entry.kind) && !row_backed
                    && !entry.reference_source_path.as_deref().is_some_and(Path::is_file)
            };
            if !remove { retained.push(entry); }
        }
        feed.interactables = retained;
        crate::ledger::save_proposals_on(connection, &feed, &[])?;
        crate::ledger::retire_unseen_documents_on(connection, &active, observed_modules, &recognized)?;
        Ok(undeclared)
    })?;
    for (module, id) in &retired {
        eprintln!("harmonia verb=retire-config-proposal module={module} id={id} outcome=success reason=target-undeclared");
    }
    Ok(retired)
}

pub(crate) fn refresh_interactables_for_convergence(
    manifest: &LadderManifest,
    request: &FileConvergenceRequest,
    outcome: &FileConvergenceOutcome,
) -> Result<Vec<ConfigRecognition>, String> {
    let path = crate::ledger::database_path();
    refresh_interactables_at_path_with_policy(&path, manifest, request, outcome, false)
}

pub(crate) fn refresh_interactables_for_compiled_convergence(
    manifest: &LadderManifest,
    request: &FileConvergenceRequest,
    outcome: &FileConvergenceOutcome,
) -> Result<Vec<ConfigRecognition>, String> {
    let path = crate::ledger::database_path();
    refresh_interactables_at_path_with_policy(&path, manifest, request, outcome, true)
}

pub(crate) fn refresh_interactables_for_convergence_at_step(
    manifest: &LadderManifest,
    request: &FileConvergenceRequest,
    outcome: &FileConvergenceOutcome,
    step_id: &str,
) -> Result<Vec<ConfigRecognition>, String> {
    let path = crate::ledger::database_path();
    refresh_interactables_at_path_with_policy_and_step(
        &path, manifest, request, outcome, false, Some(step_id),
    )
}

pub(crate) fn refresh_interactables_for_compiled_convergence_at_step(
    manifest: &LadderManifest,
    request: &FileConvergenceRequest,
    outcome: &FileConvergenceOutcome,
    step_id: &str,
) -> Result<Vec<ConfigRecognition>, String> {
    let path = crate::ledger::database_path();
    refresh_interactables_at_path_with_policy_and_step(
        &path, manifest, request, outcome, true, Some(step_id),
    )
}

pub(crate) fn refresh_interactables_at_path(
    path: &Path,
    manifest: &LadderManifest,
    request: &FileConvergenceRequest,
    outcome: &FileConvergenceOutcome,
) -> Result<Vec<ConfigRecognition>, String> {
    refresh_interactables_at_path_with_policy(path, manifest, request, outcome, false)
}

fn refresh_interactables_at_path_with_policy(
    path: &Path,
    manifest: &LadderManifest,
    request: &FileConvergenceRequest,
    outcome: &FileConvergenceOutcome,
    compiled_artifact_authoritative: bool,
) -> Result<Vec<ConfigRecognition>, String> {
    refresh_interactables_at_path_with_policy_and_step(
        path, manifest, request, outcome, compiled_artifact_authoritative, None,
    )
}

fn refresh_interactables_at_path_with_policy_and_step(
    path: &Path,
    manifest: &LadderManifest,
    request: &FileConvergenceRequest,
    outcome: &FileConvergenceOutcome,
    compiled_artifact_authoritative: bool,
    step_id: Option<&str>,
) -> Result<Vec<ConfigRecognition>, String> {
    if outcome.config_state == Some(crate::atoms::files::ConfigConvergenceState::InteractableExempt)
    {
        return Ok(Vec::new());
    }
    // Import the legacy projection before taking the optimistic preimage.
    drop(crate::ledger::writer()?);
    let mut feed = interactables::load_feed(path)?;
    let observed = feed.interactables.clone();
    let mut recognitions = Vec::new();
    let mut config = Vec::new();
    let mut remove_ids = BTreeSet::new();
    let mut upsert_ids = BTreeSet::new();
    let mut checks = Vec::new();
    let now = stamp();
    let available_at = iso8601_now();
    for entry in &outcome.entries {
        if !entry.source_exists {
            continue;
        }
        let target_absent = !entry.target_exists_before;
        let is_own_config = |item: &Interactable| {
            is_config_proposal_id(&item.id)
                && item.kind == "hard-stamp"
                && item.module_id == manifest.id
                && item.target_path.as_deref() == Some(entry.target.as_path())
        };
        if target_absent {
            remove_ids.extend(feed.interactables.iter().filter(|item| is_own_config(item)).map(|item| item.id.clone()));
            feed.interactables.retain(|item| !is_own_config(item));
            continue;
        }
        let drift = DriftSummary {
            content: target_absent || !entry.content_equal_before,
            mode: !target_absent && !entry.mode_equal_before,
            ownership: entry.ownership_changed,
        };
        if !target_absent && !drift.content && !drift.mode && !drift.ownership {
            remove_ids.extend(
                feed.interactables.iter().filter(|item| is_own_config(item)).map(|item| item.id.clone()),
            );
            feed.interactables.retain(|item| !is_own_config(item));
            continue;
        }
        crate::tools::files::validate_interactable_target(&entry.target)?;
        if target_absent {
            match fs::symlink_metadata(&entry.target) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => return Err(format!("compiled-target-appeared-before-proposal {}", entry.target.display())),
                Err(error) => return Err(format!("compiled-target-observe-failed {}: {error}", entry.target.display())),
            }
        } else {
            let metadata = fs::symlink_metadata(&entry.target).map_err(|error| {
                format!("config-interactable-target-observe-failed {}: {error}", entry.target.display())
            })?;
            if !metadata.file_type().is_file() {
                return Err(format!("config-interactable-target-not-regular {}", entry.target.display()));
            }
        }
        let reference_metadata = fs::symlink_metadata(&entry.source).map_err(|error| {
            format!("config-interactable-reference-observe-failed {}: {error}", entry.source.display())
        })?;
        if !reference_metadata.file_type().is_file() {
            return Err(format!("config-interactable-reference-not-regular {}", entry.source.display()));
        }
        let live_bytes = if target_absent {
            Vec::new()
        } else {
            read_regular_file_no_follow(&entry.target, "config-interactable-target")?
        };
        let reference_bytes =
            read_regular_file_no_follow(&entry.source, "config-interactable-reference")?;
        if !target_absent {
            let metadata = fs::symlink_metadata(&entry.target).map_err(|error|
                format!("config-interactable-target-observe-failed {}: {error}", entry.target.display()))?;
            let current_equal = live_bytes == reference_bytes;
            let mode_equal = Some(metadata.mode() & 0o777) == entry.final_mode;
            let current_diff = if current_equal { None } else {
                crate::atoms::files::unified_file_diff(&entry.source, &entry.target)?.text
            };
            if current_equal != entry.content_equal_before || mode_equal != entry.mode_equal_before
                || Some(metadata.uid()) != entry.observed_uid_before
                || Some(metadata.gid()) != entry.observed_gid_before
                || current_diff != entry.diff {
                return Err(format!("config-proposal-observation-stale {}", entry.target.display()));
            }
        }
        let live_sha = (!target_absent).then(|| format!("{:x}", Sha256::digest(&live_bytes)));
        let reference_sha = format!("{:x}", Sha256::digest(&reference_bytes));
        checks.push((entry.target.clone(), live_sha.clone()));
        let id = if target_absent {
            compiled_absent_proposal_id(&entry.target, &reference_sha)
        } else {
            stable_id(&entry.target, live_sha.as_deref().unwrap_or_default(), &reference_sha)
        };
        let reference_source = proposal_reference(&id)?;
        let reference_source_id = reference_source.to_string_lossy().into_owned();
        let target_proposal_count = feed
            .interactables
            .iter()
            .filter(|item| is_own_config(item))
            .count();
        let prior_for_target = feed.interactables.iter().find(|item| is_own_config(item)).cloned();
        let prior_silence = prior_for_target
            .as_ref()
            .map(|e| (e.silenced, e.silenced_at.clone()))
            .unwrap_or((false, None));
        let prior_same_id = feed.interactables.iter().find(|item| item.id == id).cloned();
        if prior_same_id.as_ref().is_some_and(|item| !is_own_config(item)) {
            // A feed key cannot replace another owner's row.
            continue;
        }
        let created_at = prior_same_id
            .as_ref()
            .map(|item| item.created_at.clone())
            .unwrap_or_else(|| now.clone());
        let recognized = if target_absent {
            interactables::RecognitionResult {
                score: 0.0,
                reference_id: reference_source_id.clone(),
            }
        } else {
            interactables::recognize_against_known_goods(
                &live_bytes,
                &[interactables::RecognitionCandidate {
                    reference_id: &reference_source_id,
                    bytes: &reference_bytes,
                }],
            )
            .ok_or_else(|| "config-recognition-no-known-good".to_string())?
        };
        let score = recognized.score;
        let threshold = 0.33;
        let state = if score >= threshold {
            "interactable"
        } else {
            "refused-unrecognized"
        };
        let config_state = serde_json::json!({
                "schema": "harmonia.config_state.v1", "config_state": state, "id": id.clone(),
                "target": entry.target.clone(), "reference": reference_source.clone(), "score": score,
                "live_sha": live_sha.clone(), "compiled_target_absent": target_absent,
                "reference_sha": reference_sha.clone(), "threshold": threshold,
                "reference_id": reference_source.clone()
            });
        if score < threshold {
            // A refusal is an observation, not a proposal row.
            CURRENT_CONFIG_RECOGNITIONS.with(|state| {
                state.borrow_mut().insert(id.clone(), config_state.clone());
            });
            remove_ids.extend(
                feed.interactables.iter().filter(|item| is_own_config(item)).map(|item| item.id.clone()),
            );
            feed.interactables.retain(|item| !is_own_config(item));
            recognitions.push(ConfigRecognition {
                config_state: state.to_string(), score,
                reference_id: Some(recognized.reference_id.clone()),
                nearest_reference: Some(reference_source.clone()), target: entry.target.clone(),
                live_sha: live_sha.clone(), target_absent, reference_sha: reference_sha.clone(),
                interactable_id: None,
            });
            continue;
        }
        let owner_kept = || ConfigRecognition {
            config_state: "owner-kept".to_string(), score,
            reference_id: Some(recognized.reference_id.clone()),
            nearest_reference: Some(reference_source.clone()), target: entry.target.clone(),
            live_sha: live_sha.clone(), target_absent, reference_sha: reference_sha.clone(),
            interactable_id: None,
        };
        let resolved = if target_absent || compiled_artifact_authoritative {
            ConfigAncestor::Generated
        } else {
            resolve_config_ancestor(manifest, &entry.source, &entry.target, &live_bytes, &reference_bytes, prior_for_target.as_ref(), request.prior_head())?
        };
        if matches!(resolved, ConfigAncestor::Unnamed) {
            if prior_for_target.as_ref().is_some_and(is_legacy_config) {
                remove_ids.extend(feed.interactables.iter().filter(|item| is_own_config(item)).map(|item| item.id.clone()));
                feed.interactables.retain(|item| !is_own_config(item));
            }
            recognitions.push(owner_kept());
            continue;
        }
        if let ConfigAncestor::Named { bytes, .. } = &resolved {
            if bytes == &reference_bytes {
                remove_ids.extend(feed.interactables.iter().filter(|item| is_own_config(item)).map(|item| item.id.clone()));
                feed.interactables.retain(|item| !is_own_config(item));
                recognitions.push(owner_kept());
                continue;
            }
        }
        let config_act_binding = step_id
            .map(|step_id| config_act_binding(manifest, step_id))
            .transpose()?;
        let generated_config = matches!(resolved, ConfigAncestor::Generated);
        let (proposal_bytes, slice) = match resolved {
            ConfigAncestor::Named { oid, bytes } => {
                let (merged, case) = land_config_slice(&bytes, &live_bytes, &reference_bytes)?;
                let sentence = match case {
                    "default-moved" => "HomeServer updated this file's default.",
                    "default-rolled" => "HomeServer updated this file's default. Your own changes stay as they are.",
                    _ => "HomeServer updated a line you also changed. Yes keeps HomeServer's line there; your other changes stay.",
                };
                (merged, Some((oid, serde_json::json!({"case": case, "sentence": sentence}))))
            }
            _ => (reference_bytes.clone(), None),
        };
        if !target_absent && proposal_bytes == live_bytes {
            remove_ids.extend(feed.interactables.iter().filter(|item| is_own_config(item)).map(|item| item.id.clone()));
            feed.interactables.retain(|item| !is_own_config(item));
            recognitions.push(owner_kept());
            continue;
        }
        CURRENT_CONFIG_RECOGNITIONS.with(|state| {
            state.borrow_mut().insert(id.clone(), config_state.clone());
        });
        let proposal_diff_text = proposal_diff(&entry.target, &live_bytes, &proposal_bytes);
        config.push(crate::ledger::ConfigProposal {
            id: id.clone(), state: config_state, source: proposal_bytes,
        });
        let interactable_id = id.clone();
        let mut refreshed = Interactable {
            id: id.clone(),
            module_id: manifest.id.clone(),
            name: format!("{}: {}", manifest.id, entry.relative_path),
            description: manifest.description.clone(),
            kind: "hard-stamp".into(),
            target_path: Some(entry.target.clone()),
            reference_source_path: Some(reference_source.clone()),
            drift,
            created_at,
            refreshed_at: now.clone(),
            available_at: Some(available_at.clone()),
            silenced: prior_silence.0,
            silenced_at: prior_silence.1,
            has_run: false,
            mode: entry.final_mode,
            owner: request.owner.clone(),
            group: request.group.clone(),
            source_sha: None,
            target_sha: None,
            commits_behind: None,
            live_sha: live_sha.clone(),
            reference_sha: Some(reference_sha.clone()),
            recognition_score: Some(score),
            diff: proposal_diff_text,
            script: format!("harmonia interactable run {} owner", interactable_id),
            show_only_if: "config_state=interactable".into(),
            completion_check: format!("sha256:{reference_sha}"),
            evidence: serde_json::Value::Null,
            extra: serde_json::Map::new(),
        };
        if let Some(prior) = &prior_same_id {
            refreshed.created_at = prior.created_at.clone();
            refreshed.refreshed_at = prior.refreshed_at.clone();
            refreshed.available_at = prior.available_at.clone();
            refreshed.silenced = prior.silenced;
            refreshed.silenced_at = prior.silenced_at.clone();
            refreshed.has_run = prior.has_run;
            refreshed.evidence = prior.evidence.clone();
            refreshed.extra = prior.extra.clone();
        }
        refreshed.extra.remove("ancestor_sha");
        refreshed.extra.remove("slice");
        refreshed.extra.remove("generated_config");
        if generated_config {
            refreshed.extra.insert("generated_config".into(), Value::Bool(true));
        }
        if let Some((oid, details)) = slice {
            refreshed.extra.insert("ancestor_sha".into(), Value::String(oid));
            refreshed.extra.insert("slice".into(), details);
        }
        if target_absent {
            refreshed.extra.insert(
                "compiled_target_absent".into(),
                serde_json::Value::Bool(true),
            );
        } else {
            refreshed.extra.remove("compiled_target_absent");
        }
        refreshed.extra.remove("config_act_binding");
        if let Some(binding) = &config_act_binding {
            refreshed
                .extra
                .insert("config_act_binding".into(), binding.clone());
        }
        let unchanged = prior_same_id.as_ref().is_some_and(|prior| {
            (!target_absent || target_proposal_count == 1)
                && serde_json::to_value(prior).ok() == serde_json::to_value(&refreshed).ok()
        });
        if !unchanged {
            // A changed offer supersedes the applicable prior rows for this surface.
            remove_ids.extend(
                feed.interactables
                    .iter()
                    .filter(|item| is_own_config(item))
                    .map(|item| item.id.clone()),
            );
            feed.interactables.retain(|item| !is_own_config(item));
            if let Some(prior) = &prior_same_id {
                refreshed.available_at = prior.available_at.clone();
            }
            refreshed.refreshed_at = now.clone();
            feed.interactables.push(refreshed);
            upsert_ids.insert(interactable_id.clone());
        }
        recognitions.push(ConfigRecognition {
            config_state: state.to_string(),
            score,
            reference_id: Some(recognized.reference_id),
            nearest_reference: Some(reference_source),
            target: entry.target.clone(),
            live_sha,
            target_absent,
            reference_sha,
            interactable_id: Some(interactable_id),
        });
    }
    feed.interactables.sort_by(|a, b| a.id.cmp(&b.id));
    let published = persist_feed_with_config(
        &path,
        FeedPersistenceIntent::ConfigUpsert {
            entries: feed
                .interactables
                .iter()
                .filter(|item| upsert_ids.contains(&item.id))
                .cloned()
                .collect(),
            remove_ids,
            observed,
            checks,
        },
        &config,
    )?.is_some();
    if !published {
        for recognition in &mut recognitions { recognition.interactable_id = None; }
    }
    Ok(recognitions)
}

/// Observe the declared link without following its leaf. A file collision is
/// not permission to replace it, even when the owner accepts a link proposal.
pub(crate) fn validated_symlink_observation(step: &ValidatedStep) -> Result<Value, String> {
    let path_arg = |key: &str| -> Result<PathBuf, String> {
        let value = step.args.get(key).and_then(Value::as_str)
            .ok_or_else(|| format!("validated-symlink-{key}-unresolved-{}", step.step_id))?;
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(format!("validated-symlink-{key}-not-absolute {}", path.display()));
        }
        if let crate::atoms::files::TargetClass::Refused(reason) =
            crate::atoms::files::classify_target(&path)
        {
            return Err(format!("validated-symlink-{key}-refused-{reason}"));
        }
        Ok(path)
    };
    let source = path_arg("source")?;
    let target = path_arg("target")?;
    let source_bytes = read_regular_file_no_follow(&source, "validated-symlink-source")?;
    let link_target = match fs::symlink_metadata(&target) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let link = fs::read_link(&target)
                .map_err(|error| format!("validated-symlink-link-read-failed: {error}"))?;
            Some(link.to_str().ok_or("validated-symlink-link-target-not-utf8")?.to_owned())
        }
        Ok(_) => return Err(format!("validated-symlink-link-not-link {}", target.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("validated-symlink-link-observe-failed: {error}")),
    };
    Ok(serde_json::json!({
        "source": source, "target": target, "link_target": link_target,
        "source_sha256": format!("{:x}", Sha256::digest(&source_bytes)),
    }))
}

pub(crate) fn validated_symlink_proposal_id(
    module_id: &str,
    binding: &Value,
    observed: &Value,
) -> Result<String, String> {
    let identity = serde_json::json!({
        "module_id": module_id,
        "manifest_path": binding.get("manifest_path"),
        "manifest_sha256": binding.get("manifest_sha256"),
        "target_step_id": binding.get("target_step_id"),
        "source": observed.get("source"), "target": observed.get("target"),
        "link_target": observed.get("link_target"),
        "source_sha256": observed.get("source_sha256"),
    });
    let bytes = serde_json::to_vec(&identity).map_err(|error| error.to_string())?;
    Ok(format!("config-proposal-{:x}", Sha256::digest(&bytes)))
}

/// Automatic presses project a pending configuration act, never the link.
/// Keep observation and publication under the same lock as owner acceptance.
pub(crate) fn refresh_validated_symlink(
    step: &ValidatedStep,
    manifest: &LadderManifest,
) -> Result<bool, String> {
    let path = crate::ledger::database_path();
    crate::ledger::with_proposal_transaction(|connection| {
        let observed = validated_symlink_observation(step)?;
        let binding = config_act_binding(manifest, &step.step_id)?;
        let feed = crate::ledger::load_proposals_on(connection)?;
        let target = PathBuf::from(observed["target"].as_str()
            .ok_or("validated-symlink-target-unresolved")?);
        let matching_ids = feed.interactables.iter()
            .filter(|item| item.module_id == manifest.id
                && item.target_path.as_ref() == Some(&target)
                && item.extra.get("validated_symlink").is_some_and(|value| !value.is_null()))
            .map(|item| item.id.clone()).collect::<BTreeSet<_>>();
        if observed["link_target"] == observed["source"] {
            if !matching_ids.is_empty() {
                let feed = compose_feed(connection, feed, &FeedPersistenceIntent::Upsert {
                    entries: Vec::new(), remove_ids: matching_ids, sort_by_id: true,
                })?;
                crate::ledger::save_proposals_on(connection, &feed, &[])?;
            }
            return Ok(false);
        }
        let id = validated_symlink_proposal_id(&manifest.id, &binding, &observed)?;
        let source_text = observed["source"].as_str()
            .ok_or("validated-symlink-source-unresolved")?;
        // Escape control characters and backslashes so even unusual valid
        // link names remain unambiguous single-line diff text and headers.
        let display_target = PathBuf::from(target.to_string_lossy().escape_debug().to_string());
        let before = observed["link_target"].as_str()
            .map(|current| format!("link → {}\n", current.escape_debug()))
            .unwrap_or_default();
        let after = format!("link → {}\n", source_text.escape_debug());
        let diff = proposal_diff(&display_target, before.as_bytes(), after.as_bytes());
        // The final proposal prune retires row-backed offers not produced by
        // this successful module observation. Link offers participate in that
        // same per-run lifecycle; neither a new nor a quiet offer is stale.
        let recognition = serde_json::json!({
            "module_id": manifest.id,
            "step_id": step.step_id,
            "config_state": "interactable",
            "target": observed["target"],
            "target_absent": observed["link_target"].is_null(),
            "reference_sha": observed["source_sha256"],
            "interactable_id": id,
            "validated_symlink": observed,
        });
        let prior = feed.interactables.iter().find(|item| item.id == id);
        let prior_state = crate::ledger::config_state(&path, &id)?;
        if prior.is_some_and(|item| {
            item.extra.get("validated_symlink") == Some(&observed)
                && item.extra.get("config_act_binding") == Some(&binding)
                && item.diff == diff
        }) && prior_state.as_ref().is_some_and(|state| {
            state.get("validated_symlink") == Some(&observed)
                && state.get("config_act_binding") == Some(&binding)
        }) {
            CURRENT_CONFIG_RECOGNITIONS.with(|state| {
                state.borrow_mut().insert(id.clone(), recognition.clone());
            });
            return Ok(true);
        }
        let now = iso8601_now();
        let mut extra = prior.map(|item| item.extra.clone()).unwrap_or_default();
        extra.insert("validated_symlink".into(), observed.clone());
        extra.insert("config_act_binding".into(), binding.clone());
        let source = PathBuf::from(observed["source"].as_str()
            .ok_or("validated-symlink-source-unresolved")?);
        let item = Interactable {
            id: id.clone(), module_id: manifest.id.clone(),
            name: format!("{}: {}", manifest.id, step.step_id),
            description: format!("Enable {} after validating its configuration.", target.display()),
            kind: "hard-stamp".into(), target_path: Some(target.clone()),
            reference_source_path: Some(source.clone()),
            drift: DriftSummary { content: true, mode: false, ownership: false },
            created_at: prior.map(|item| item.created_at.clone()).unwrap_or_else(|| now.clone()),
            refreshed_at: now.clone(),
            available_at: prior.map(|item| item.available_at.clone()).unwrap_or_else(|| Some(now.clone())),
            silenced: prior.is_some_and(|item| item.silenced),
            silenced_at: prior.and_then(|item| item.silenced_at.clone()),
            has_run: false, mode: None, owner: None, group: None,
            source_sha: None, target_sha: None, commits_behind: None,
            live_sha: observed["link_target"].as_str()
                .map(|value| format!("{:x}", Sha256::digest(value.as_bytes()))),
            reference_sha: observed["source_sha256"].as_str().map(str::to_owned),
            recognition_score: None,
            diff,
            script: format!("harmonia interactable run {id}"),
            show_only_if: "link_state=drift".into(),
            completion_check: format!("symlink:{}", source.display()),
            evidence: Value::Null, extra,
        };
        let mut state = prior_state.unwrap_or_else(|| serde_json::json!({}));
        let object = state.as_object_mut().ok_or("validated-symlink-state-not-object")?;
        object.insert("validated_symlink".into(), observed);
        object.insert("config_act_binding".into(), binding);
        object.insert("updated_at".into(), Value::String(now));
        let config = [crate::ledger::ConfigProposal {
            id: id.clone(), state,
            // A link acts on its declared source, not on a copied file snapshot.
            source: Vec::new(),
        }];
        let feed = compose_feed(connection, feed, &FeedPersistenceIntent::Upsert {
            entries: vec![item],
            remove_ids: matching_ids.into_iter().filter(|candidate| candidate != &id).collect(),
            sort_by_id: true,
        })?;
        crate::ledger::save_proposals_on(connection, &feed, &config)?;
        CURRENT_CONFIG_RECOGNITIONS.with(|state| {
            state.borrow_mut().insert(id, recognition);
        });
        Ok(true)
    })
}

pub(crate) fn config_act_binding(
    manifest: &LadderManifest,
    step_id: &str,
) -> Result<Value, String> {
    let manifest_path = manifest.base_dir.join("manifest.json");
    let manifest_path = if manifest_path.is_absolute() {
        manifest_path
    } else {
        std::env::current_dir()
            .map_err(|error| format!("config-act-manifest-cwd-failed: {error}"))?
            .join(manifest_path)
    };
    if manifest_path.file_name().and_then(|name| name.to_str()) != Some("manifest.json")
        || manifest_path
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            != Some(manifest.id.as_str())
    {
        return Err("config-act-manifest-binding-invalid".into());
    }
    let metadata = fs::symlink_metadata(&manifest_path).map_err(|error| {
        format!("config-act-manifest-stat-failed {}: {error}", manifest_path.display())
    })?;
    if !metadata.file_type().is_file() || metadata.len() > 256 * 1024 {
        return Err("config-act-manifest-not-regular-or-too-large".into());
    }
    let bytes = read_regular_file_no_follow(&manifest_path, "config-act-manifest")?;
    let source_step_id = CONFIG_SOURCE_STEP.with(|current| current.borrow().clone())
        .unwrap_or_else(|| step_id.to_owned());
    if !manifest.ladder.iter().any(|step| step.step_id == source_step_id) {
        return Err("config-act-source-step-binding-invalid".into());
    }
    let selected_profile_index = manifest.selected_profile_index.as_ref().map(|path| {
        if path.is_absolute() {
            Ok(path.clone())
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(path))
                .map_err(|error| format!("config-act-profile-cwd-failed: {error}"))
        }
    }).transpose()?;
    Ok(serde_json::json!({
        "manifest_path": manifest_path,
        "manifest_sha256": format!("{:x}", Sha256::digest(&bytes)),
        "target_step_id": source_step_id,
        "active_lane": CONFIG_ACTIVE_LANE.with(|current| current.borrow().clone()),
        "selected_profile_index": selected_profile_index,
    }))
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ConfigRecognition {
    pub(crate) config_state: String,
    pub(crate) score: f64,
    pub(crate) reference_id: Option<String>,
    pub(crate) nearest_reference: Option<PathBuf>,
    pub(crate) target: PathBuf,
    pub(crate) live_sha: Option<String>,
    pub(crate) target_absent: bool,
    pub(crate) reference_sha: String,
    pub(crate) interactable_id: Option<String>,
}

/// Execute the complete ProposeEdits band lifecycle for one projected module.
/// Selection, preconditions, authority gating, failure policy, and accumulation
/// intentionally live here rather than in the ladder compatibility executor.
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_manifest_band(
    manifest: &LadderManifest,
    module_dir: &Path,
    source_module_dir: &Path,
    auth: Option<&SoftwareApplyAuthorization>,
    pa: Option<&PackageAuthority>,
    key: Option<&crate::atoms::r#do::InvocationKey>,
    mode_apply: bool,
    routine_states: &mut BTreeMap<String, crate::ModuleWalkState>,
    projected_steps: &[ValidatedStep],
    projected_routines: &BTreeMap<String, Vec<ProjectedRoutineChild>>,
    halted_steps: &mut crate::bands::HaltedSteps,
    active_lane: Option<&str>,
    module_changed_before_band: bool,
) -> Result<ModuleExecution, String> {
    let _config_lane = ConfigActiveLaneGuard::enter(active_lane);
    crate::atoms::attest::prepare_receipt_parent(module_dir)?;
    let mut result = ModuleExecution {
        ok: true,
        changed: false,
        operation_count: 0,
        first_missing_signal: None,
        placements: Vec::new(),
    };
    for step in projected_steps {
        if step.tool == "routine" {
            let children = projected_routines
                .get(&step.step_id)
                .ok_or_else(|| "routine-step-missing".to_string())?;
            if !children
                .iter()
                .any(|child| child.band == crate::bands::Band::ProposeEdits)
            {
                continue;
            }
        } else if crate::tools::routine::placement_for_step(step)?
            != crate::bands::Band::ProposeEdits
        {
            continue;
        }
        if crate::bands::step_halted(halted_steps, &manifest.id, &step.step_id) {
            let origin_band = halted_steps
                .get(&(manifest.id.clone(), step.step_id.clone()))
                .cloned()
                .expect("halted step retains its originating band");
            result.placements.push(serde_json::json!({"step_id":step.step_id,"tool":step.tool,"permutation":step.permutation,"band":"ProposeEdits","status":"blocked","blocked_by":{"step_id":step.step_id,"origin_band":origin_band},"module":manifest.id}));
            continue;
        }
        if let Some(precondition) = if step.tool == "routine" {
            None
        } else {
            crate::tools::routine::command_precondition(&step.args)?
        } {
            result.operation_count += 1;
            let probe = crate::bands::compare::execute_command_precondition(
                step,
                &precondition,
                manifest,
                module_dir,
            )?;
            result.placements.push(serde_json::json!({"step_id":format!("{}#precondition", step.step_id),"tool":step.tool,"permutation":step.permutation,"band":"ProposeEdits","status":if probe.ok {"completed"} else {"blocked"},"ok":probe.ok,"changed":probe.changed,"skipped":probe.skipped,"message":probe.message,"command":probe.command,"module":manifest.id,"precondition_for":step.step_id}));
            if !probe.ok {
                result.ok = false;
                // Output is untrusted, potentially multiline and credential-bearing.
                // The module crossing needs the coded outcome, not a transcript.
                let detail = probe
                    .command
                    .as_ref()
                    .map(|r| format!("exit_code={}", r.code))
                    .unwrap_or_else(|| "command-precondition-failed".to_string());
                let signal = format!(
                    "step_id={} state=blocked probe_error={detail}",
                    step.step_id
                );
                result.first_missing_signal.get_or_insert(signal);
                if manifest.isolation.as_deref() == Some("per-step") {
                    crate::bands::halt_step(
                        halted_steps,
                        &manifest.id,
                        &step.step_id,
                        crate::bands::Band::ProposeEdits,
                    );
                    continue;
                }
                break;
            }
        }
        result.operation_count += 1;
        let outcome = if step.tool == "routine" {
            crate::tools::routine::execute_routine(
                step,
                manifest,
                module_dir,
                auth,
                pa,
                mode_apply,
                key,
                Some(routine_states),
                crate::bands::Band::ProposeEdits,
                projected_routines
                    .get(&step.step_id)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            )?
        } else {
            crate::tools::routine::execute_validated_step_with_source(
                step,
                manifest,
                module_dir,
                source_module_dir,
                auth,
                pa,
                module_changed_before_band || result.changed,
                key,
                active_lane,
            )?
        };
        if step.tool == "routine" {
            let routine = routine_states
                .get(&step.step_id)
                .ok_or_else(|| "routine-state-missing".to_string())?;
            for child in projected_routines
                .get(&step.step_id)
                .map(Vec::as_slice)
                .unwrap_or(&[])
            {
                if child.band != crate::bands::Band::ProposeEdits {
                    continue;
                }
                let receipt = routine
                    .children
                    .iter()
                    .find(|r| r.get("name").and_then(Value::as_str) == Some(child.name.as_str()))
                    .ok_or_else(|| format!("routine-child-receipt-missing-{}", child.name))?;
                result.placements.push(serde_json::json!({"step_id":child.name,"tool":child.tool,"permutation":child.permutation,"band":"ProposeEdits","status":receipt.get("state").and_then(Value::as_str).unwrap_or("failed"),"ok":receipt.get("ok").and_then(Value::as_bool).unwrap_or(false),"changed":receipt.get("changed").and_then(Value::as_bool).unwrap_or(false),"module":manifest.id,"routine":step.step_id}));
            }
        } else {
            result.placements.push(serde_json::json!({"step_id":step.step_id,"tool":step.tool,"permutation":step.permutation,"band":"ProposeEdits","status":if outcome.skipped {"skipped"} else if outcome.ok {"completed"} else {"failed"},"ok":outcome.ok,"changed":outcome.changed,"skipped":outcome.skipped,"message":outcome.message,"command":outcome.command,"module":manifest.id}));
        }
        result.changed |= outcome.changed;
        if !outcome.ok {
            result.ok = false;
            result.first_missing_signal.get_or_insert_with(|| {
                format!("step_id={} defect={}", step.step_id, outcome.message)
            });
            if manifest.isolation.as_deref() == Some("per-step") {
                crate::bands::halt_step(
                    halted_steps,
                    &manifest.id,
                    &step.step_id,
                    crate::bands::Band::ProposeEdits,
                );
            }
            if step.on_failure == crate::tools::ladder::OnFailure::Stop
                && manifest.isolation.as_deref() != Some("per-step")
            {
                break;
            }
        }
    }
    Ok(result)
}

use crate::receipts::event;
pub(crate) fn execute_manifest_modules(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: &UpdateMode,
    mode_apply: bool,
    disabled_modules: &BTreeSet<String>,
    projection: &ProfileProjection,
    states: &mut BTreeMap<String, ModuleExecution>,
    routines: &mut BTreeMap<String, BTreeMap<String, crate::ModuleWalkState>>,
    halted: &mut BTreeSet<String>,
    halted_steps: &mut crate::bands::HaltedSteps,
    module_count: &mut usize,
    operation_count: &mut usize,
    changed: &mut bool,
    ok: &mut bool,
    first_missing_signal: &mut String,
    events: &mut crate::receipts::EventSink,
    active_lane: Option<&str>,
) -> Result<(), String> {
    for module_id in &profile.modules {
        if disabled_modules.contains(module_id)
            || halted.contains(module_id)
            || projection.authority_excluded.contains(module_id)
        {
            continue;
        }
        let Some(projected) = projection.modules.get(module_id) else {
            let err = projection
                .errors
                .get(module_id)
                .cloned()
                .unwrap_or_else(|| format!("module-not-in-projection-{module_id}"));
            let state = states.entry(module_id.clone()).or_insert(ModuleExecution {
                ok: true,
                changed: false,
                operation_count: 0,
                first_missing_signal: None,
                placements: Vec::new(),
            });
            state.ok = false;
            state.first_missing_signal.get_or_insert(err.clone());
            halted.insert(module_id.clone());
            if !projection.outside_set(module_id, mode_apply) { *ok = false; }
            if *first_missing_signal == "none" {
                *first_missing_signal = err.clone();
            }
            event(events, "module-rejected", false, &err)?;
            continue;
        };
        let per_step_isolation = matches!(
            &projected.loaded,
            LoadedModule::Ladder(manifest) if manifest.isolation.as_deref() == Some("per-step")
        );
        *module_count = profile.modules.len();
        let result = match &projected.loaded {
            LoadedModule::Ladder(manifest) => execute_manifest_band(
                manifest,
                &receipt_dir.join("modules").join(module_id),
                &crate::bands::stage_profile::resolve_module_dir(module_root, module_id)?,
                mode.software_authorization(),
                profile.package_authority.as_ref(),
                mode.invocation(),
                mode_apply,
                routines.entry(module_id.clone()).or_default(),
                &projected.steps,
                &projected.routines,
                halted_steps,
                active_lane,
                states.get(module_id).is_some_and(|state| state.changed),
            ),
            LoadedModule::Sidecar(_) => Err("module-sidecar-not-band-executable".to_string()),
        };
        let state = states.entry(module_id.clone()).or_insert(ModuleExecution {
            ok: true,
            changed: false,
            operation_count: 0,
            first_missing_signal: None,
            placements: Vec::new(),
        });
        match result {
            Ok(part) => {
                state.operation_count += part.operation_count;
                state.changed |= part.changed;
                state.placements.extend(part.placements);
                *operation_count += part.operation_count;
                *changed |= part.changed;
                if !part.ok {
                    state.ok = false;
                    state.first_missing_signal = state
                        .first_missing_signal
                        .take()
                        .or(part.first_missing_signal);
                    if !projection.outside_set(module_id, mode_apply) { *ok = false; }
                    if !per_step_isolation {
                        halted.insert(module_id.clone());
                    }
                    if *first_missing_signal == "none" {
                        *first_missing_signal = state
                            .first_missing_signal
                            .clone()
                            .unwrap_or_else(|| format!("module-failed-{module_id}"));
                    }
                }
                event(
                    events,
                    "module-band",
                    part.ok,
                    &format!(
                        "{} band=ProposeEdits steps={}",
                        module_id, part.operation_count
                    ),
                )?;
            }
            Err(err) => {
                state.ok = false;
                state.first_missing_signal.get_or_insert(err.clone());
                if !per_step_isolation {
                    halted.insert(module_id.clone());
                }
                if !projection.outside_set(module_id, mode_apply) { *ok = false; }
                if *first_missing_signal == "none" {
                    *first_missing_signal = err.clone();
                }
                event(events, "module-rejected", false, &err)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod refresh_interactables_tests {
    use super::{persist_feed, prune_stale_interactables_at_path};
    use crate::interactables::{self, DriftSummary, Interactable};
    use crate::Profile;
    use std::fs;
    use std::path::Path;


    fn unrelated_item(root: &Path) -> Interactable {
        Interactable {
            id: "unrelated-proposal".into(),
            module_id: "other-module".into(),
            name: "unrelated proposal".into(),
            description: "keep me".into(),
            kind: "hard-stamp".into(),
            target_path: Some(root.join("other.conf")),
            reference_source_path: Some(root.join("other-source.conf")),
            drift: DriftSummary {
                content: true,
                mode: false,
                ownership: false,
            },
            created_at: "0".into(),
            refreshed_at: "0".into(),
            available_at: Some("0".into()),
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
            script: "keep".into(),
            show_only_if: "".into(),
            completion_check: "".into(),
            evidence: serde_json::Value::Null,
            extra: serde_json::Map::new(),
        }
    }



    fn prune_item(
        root: &Path,
        id: &str,
        module_id: &str,
        target_path: PathBuf,
        reference_source_path: PathBuf,
        has_run: bool,
    ) -> Interactable {
        let mut item = unrelated_item(root);
        item.id = id.into();
        item.module_id = module_id.into();
        item.target_path = Some(target_path);
        item.reference_source_path = Some(reference_source_path);
        item.has_run = has_run;
        item
    }



}
