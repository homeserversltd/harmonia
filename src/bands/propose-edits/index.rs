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
use std::os::unix::fs::OpenOptionsExt;
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

pub(crate) fn persist_feed(
    path: &Path,
    feed: &interactables::InteractablesFeed,
) -> Result<(), String> {
    persist_feed_with_writes(path, feed).map(|_| ())
}

pub(crate) fn persist_feed_with_writes(
    path: &Path,
    feed: &interactables::InteractablesFeed,
) -> Result<usize, String> {
    persist_feed_with_intent(path, FeedPersistenceIntent::Replace(feed.clone()))
}

pub(crate) enum FeedPersistenceIntent {
    Replace(interactables::InteractablesFeed),
    Upsert {
        entries: Vec<Interactable>,
        remove_ids: BTreeSet<String>,
        sort_by_id: bool,
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
    mut feed: interactables::InteractablesFeed,
    intent: &FeedPersistenceIntent,
) -> interactables::InteractablesFeed {
    match intent {
        FeedPersistenceIntent::Replace(replacement) => replacement.clone(),
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
            let adopted = feed
                .receipts
                .iter()
                .filter(|receipt| {
                    receipt.get("schema").and_then(Value::as_str)
                        == Some("harmonia.interactables.hermes_appearance.receipt.v1")
                        && receipt.get("module_id").and_then(Value::as_str)
                            == Some(module_id.as_str())
                })
                .flat_map(|receipt| {
                    receipt
                        .get("homes")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                })
                .filter(|home| home.get("ok").and_then(Value::as_bool) == Some(true))
                .filter_map(|home| {
                    home.get("home")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .collect::<BTreeSet<_>>();
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
            let previous = feed
                .receipts
                .iter()
                .filter(|current| is_hermes_appearance_receipt(current, module_id))
                .cloned()
                .collect::<Vec<_>>();
            let merged = merge_hermes_appearance_receipts(receipt.clone(), &previous);
            let first_match = feed
                .receipts
                .iter()
                .position(|current| is_hermes_appearance_receipt(current, module_id));
            let extra_capacity = if first_match.is_none() { 1 } else { 0 };
            let mut receipts = Vec::with_capacity(feed.receipts.len() + extra_capacity);
            let mut inserted = false;
            for current in feed.receipts.drain(..) {
                if is_hermes_appearance_receipt(&current, module_id) {
                    if !inserted {
                        receipts.push(merged.clone());
                        inserted = true;
                    }
                } else {
                    receipts.push(current);
                }
            }
            if !inserted {
                receipts.push(merged);
            }
            feed.receipts = receipts;
            feed.interactables.retain(|current| {
                !(current.kind == "hermes-appearance"
                    && current.module_id == *module_id
                    && current.id == *item_id)
            });
            feed
        }
    }
}

fn is_hermes_appearance_receipt(receipt: &Value, module_id: &str) -> bool {
    receipt.get("schema").and_then(Value::as_str)
        == Some("harmonia.interactables.hermes_appearance.receipt.v1")
        && receipt.get("module_id").and_then(Value::as_str) == Some(module_id)
}

fn merge_hermes_appearance_receipts(mut current: Value, previous: &[Value]) -> Value {
    const RECEIPT_FIELDS: &[&str] = &[
        "schema", "ok", "id", "kind", "changed", "skin_name", "skin_sha256",
        "module_id", "homes", "first_missing_signal", "rollback_signal",
    ];
    const HOME_FIELDS: &[&str] = &[
        "home", "ok", "changed", "before_skin", "after_skin",
        "skin_sha256_before", "skin_sha256_after", "selected_skin_snapshot",
        "skin_sha256_snapshot", "config_backup_path", "asset_backup_path",
    ];
    let Some(current_object) = current.as_object_mut() else {
        return current;
    };
    let mut adopted = BTreeMap::<String, Value>::new();
    for prior in previous.iter().rev() {
        let Some(prior_object) = prior.as_object() else { continue };
        for (key, value) in prior_object {
            if !RECEIPT_FIELDS.contains(&key.as_str()) {
                current_object.entry(key.clone()).or_insert_with(|| value.clone());
            }
        }
        for row in prior.get("homes").and_then(Value::as_array).into_iter().flatten() {
            if row.get("ok").and_then(Value::as_bool) != Some(true) {
                continue;
            }
            if let Some(home) = row.get("home").and_then(Value::as_str) {
                adopted.entry(home.to_owned()).or_insert_with(|| row.clone());
            }
        }
    }
    let rows = current_object
        .entry("homes")
        .or_insert_with(|| Value::Array(Vec::new()));
    let Some(rows) = rows.as_array_mut() else { return current };
    for row in rows.iter_mut() {
        let Some(home) = row.get("home").and_then(Value::as_str).map(str::to_owned) else {
            continue;
        };
        if row.get("ok").and_then(Value::as_bool) == Some(true) {
            if let Some(prior) = adopted.remove(&home) {
                if let (Some(current_row), Some(prior_row)) = (row.as_object_mut(), prior.as_object()) {
                    for (key, value) in prior_row {
                        if !HOME_FIELDS.contains(&key.as_str()) {
                            current_row.entry(key.clone()).or_insert_with(|| value.clone());
                        }
                    }
                }
            }
        }
    }
    rows.extend(adopted.into_values());
    current
}

pub(crate) fn persist_feed_with_intent(
    path: &Path,
    intent: FeedPersistenceIntent,
) -> Result<usize, String> {
    persist_feed_with_config(path, intent, &[]).map(|writes| writes.unwrap_or(0))
}

pub(crate) fn persist_feed_with_config(
    path: &Path,
    intent: FeedPersistenceIntent,
    config: &[crate::ledger::ConfigProposal],
) -> Result<Option<usize>, String> {
    crate::atoms::attest::with_proposal_projection_lock(path, || {
        let feed = match &intent {
            FeedPersistenceIntent::Replace(feed) => feed.clone(),
            _ => {
                let current = interactables::load_feed(path)?;
                let composed = compose_feed(current.clone(), &intent);
                if matches!(&intent, FeedPersistenceIntent::HermesAppearanceOffer { .. })
                    && serde_json::to_value(&current)
                        .map_err(|error| format!("interactables-feed-serialize-failed: {error}"))?
                        == serde_json::to_value(&composed)
                            .map_err(|error| format!("interactables-feed-serialize-failed: {error}"))?
                {
                    return Ok(Some(0));
                }
                composed
            }
        };
        if let Err(error) = crate::ledger::prepare_config_proposals(path, &feed, config) {
            // A failed source write must not expose an unusable new offer.
            // Hold the prior projection and report the failure without blocking
            // the module's independent software convergence.
            report_proposal_row_failure(&error);
            return Ok(None);
        }
        persist_feed_locked(path, &feed, config).map(Some)
    })
}

fn report_proposal_row_failure(error: &str) {
    let signal = crate::deeds::coded_signal(error);
    crate::deeds::reporting_failure("profile_ledger", &signal);
    let _ = crate::deeds::record("proposal-rows", "harmonia-interactables", false, false,
        None, None, None, Some(&signal), None);
}

fn persist_feed_locked(
    path: &Path,
    feed: &interactables::InteractablesFeed,
    config: &[crate::ledger::ConfigProposal],
) -> Result<usize, String> {
    let feed_bytes = {
        let mut bytes = serde_json::to_vec_pretty(feed)
            .map_err(|error| format!("interactables-feed-serialize-failed: {error}"))?;
        bytes.push(b'\n');
        bytes
    };
    let records = feed
        .interactables
        .iter()
        .map(|item| {
            let mut bytes = serde_json::to_vec_pretty(item).map_err(|error| error.to_string())?;
            bytes.push(b'\n');
            Ok((format!("{}.json", item.id), bytes))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let writes = crate::atoms::attest::refresh_proposal_projection_locked(
        path,
        &feed_bytes,
        &records,
        crate::atoms::attest::ProposalOwnerPolicy::CurrentProcess,
    )?;
    if let Err(error) = crate::ledger::sync_proposals(path, feed, config) {
        report_proposal_row_failure(&error);
    }
    if writes>0 { crate::deeds::record("config-proposals", "harmonia-interactables", true,true,None,None,None,None,Some(writes as u64))?; }
    Ok(writes)
}

/// Resolve an accepted file proposal while the caller holds the projection lock.
/// This deliberately calls the locked writer directly instead of reacquiring the flock.
pub(crate) fn resolve_config_proposal_locked(
    path: &Path,
    id: &str,
    receipts: Vec<Value>,
) -> Result<bool, String> {
    let feed = interactables::load_feed(path)?;
    if !feed.interactables.iter().any(|item| item.id == id) {
        return Ok(false);
    }
    let feed = compose_feed(
        feed,
        &FeedPersistenceIntent::Remove {
            ids: [id.to_string()].into_iter().collect(),
            receipts,
        },
    );
    persist_feed_locked(path, &feed, &[])?;
    Ok(true)
}

pub(crate) fn prune_stale_interactables(
    profile: &Profile,
    observed_modules: &BTreeSet<String>,
    events: &mut crate::receipts::EventSink,
) -> Result<(), String> {
    let path = std::env::var_os("HARMONIA_INTERACTABLES_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/interactables.json"));
    prune_stale_interactables_with_observations(&path, profile, observed_modules, events)
}

pub(crate) fn prune_stale_interactables_at_path(
    path: &Path,
    profile: &Profile,
    events: &mut crate::receipts::EventSink,
) -> Result<(), String> {
    prune_stale_interactables_with_observations(path, profile, &BTreeSet::new(), events)
}

fn prune_stale_interactables_with_observations(
    path: &Path,
    profile: &Profile,
    observed_modules: &BTreeSet<String>,
    _events: &mut crate::receipts::EventSink,
) -> Result<(), String> {
    let mut feed = interactables::load_feed_raw(path)?;
    let active_modules = profile.modules.iter().cloned().collect::<BTreeSet<_>>();
    let mut removed_ids = BTreeSet::new();

    for entry in feed.interactables.drain(..) {
        let row_backed = crate::ledger::has_proposal_source(path, &entry.id)?;
        let reason = if entry.kind == "engine-replacement" {
            Some("retired-kind")
        } else if !active_modules.contains(&entry.module_id) {
            Some("module-absent-from-profile")
        } else if interactables::homeserver_clock_utc::is_generated_proposal(&entry)
            && (profile.id != "homeserver" || profile.identity != "homeserver")
        {
            Some("profile-absent-from-current-certificate")
        } else if interactables::homeserver_clock_utc::is_generated_proposal(&entry) {
            None
        } else if row_backed && observed_modules.contains(&entry.module_id)
            && !CURRENT_CONFIG_RECOGNITIONS.with(|state| state.borrow().contains_key(&entry.id))
        {
            // Only a successfully observed module can retire an offer it no
            // longer produces. A failed/missing observation is not resolution.
            Some("config-proposal-no-longer-produced")
        } else if !interactables::is_ruyi_born_kind(&entry.kind)
            && !row_backed
            && !entry
                .reference_source_path
                .as_deref()
                .is_some_and(Path::is_file)
        {
            Some("reference-absent")
        } else {
            None
        };
        if reason.is_some() {
            removed_ids.insert(entry.id.clone());
        }
    }
    if removed_ids.is_empty() {
        return Ok(());
    }
    persist_feed_with_intent(
        path,
        FeedPersistenceIntent::Remove {
            ids: removed_ids,
            receipts: Vec::new(),
        },
    )?;
    Ok(())
}

pub(crate) fn refresh_interactables_for_convergence(
    manifest: &LadderManifest,
    request: &FileConvergenceRequest,
    outcome: &FileConvergenceOutcome,
) -> Result<Vec<ConfigRecognition>, String> {
    let path = std::env::var_os("HARMONIA_INTERACTABLES_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/interactables.json"));
    refresh_interactables_at_path_with_policy(&path, manifest, request, outcome, false)
}

pub(crate) fn refresh_interactables_for_compiled_convergence(
    manifest: &LadderManifest,
    request: &FileConvergenceRequest,
    outcome: &FileConvergenceOutcome,
) -> Result<Vec<ConfigRecognition>, String> {
    let path = std::env::var_os("HARMONIA_INTERACTABLES_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/interactables.json"));
    refresh_interactables_at_path_with_policy(&path, manifest, request, outcome, true)
}

pub(crate) fn refresh_interactables_for_convergence_at_step(
    manifest: &LadderManifest,
    request: &FileConvergenceRequest,
    outcome: &FileConvergenceOutcome,
    step_id: &str,
) -> Result<Vec<ConfigRecognition>, String> {
    let path = std::env::var_os("HARMONIA_INTERACTABLES_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/interactables.json"));
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
    let path = std::env::var_os("HARMONIA_INTERACTABLES_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/interactables.json"));
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
    let mut feed = interactables::load_feed(path)?;
    let mut recognitions = Vec::new();
    let mut config = Vec::new();
    let mut remove_ids = BTreeSet::new();
    let mut upsert_ids = BTreeSet::new();
    let now = stamp();
    let available_at = iso8601_now();
    for entry in &outcome.entries {
        if !entry.source_exists {
            continue;
        }
        let target_absent = !entry.target_exists_before;
        let config_target = matches!(
            crate::atoms::files::classify_target(&entry.target),
            crate::atoms::files::TargetClass::Config
        );
        if target_absent
            && (!config_target
                || outcome.config_state
                    != Some(crate::atoms::files::ConfigConvergenceState::ProposalEligible))
        {
            continue;
        }
        let drift = DriftSummary {
            content: target_absent || !entry.content_equal_before,
            mode: !target_absent && !entry.mode_equal_before,
            ownership: entry.ownership_changed,
        };
        if !target_absent && !drift.content && !drift.mode && !drift.ownership {
            if compiled_artifact_authoritative {
                remove_ids.extend(
                    feed.interactables
                        .iter()
                        .filter(|item| item.target_path.as_deref() == Some(entry.target.as_path()))
                        .filter(|item| {
                            item.extra
                                .get("compiled_target_absent")
                                .and_then(Value::as_bool)
                                == Some(true)
                        })
                        .map(|item| item.id.clone()),
                );
                feed.interactables.retain(|item| {
                    item.target_path.as_deref() != Some(entry.target.as_path())
                        || item
                            .extra
                            .get("compiled_target_absent")
                            .and_then(Value::as_bool)
                            != Some(true)
                });
            }
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
        let live_sha = (!target_absent).then(|| format!("{:x}", Sha256::digest(&live_bytes)));
        let reference_sha = format!("{:x}", Sha256::digest(&reference_bytes));
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
            .filter(|item| item.target_path.as_deref() == Some(entry.target.as_path()))
            .count();
        let prior_for_target = feed
            .interactables
            .iter()
            .find(|e| e.target_path.as_deref() == Some(entry.target.as_path()))
            .cloned();
        let prior_silence = prior_for_target
            .as_ref()
            .map(|e| (e.silenced, e.silenced_at.clone()))
            .unwrap_or((false, None));
        let prior_same_id = feed.interactables.iter().find(|item| item.id == id).cloned();
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
        let threshold = if target_absent || compiled_artifact_authoritative {
            0.0
        } else {
            0.33
        };
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
        // Refused recognition has no live proposal. Its evidence belongs only
        // to this invocation's reply, never an orphan row or a stale sidecar.
        CURRENT_CONFIG_RECOGNITIONS.with(|state| {
            state.borrow_mut().insert(id.clone(), config_state.clone());
        });
        if score < threshold {
            remove_ids.extend(
                feed.interactables
                    .iter()
                    .filter(|item| item.target_path.as_deref() == Some(entry.target.as_path()))
                    .map(|item| item.id.clone()),
            );
            feed.interactables
                .retain(|item| item.target_path.as_deref() != Some(entry.target.as_path()));
            recognitions.push(ConfigRecognition {
                config_state: state.to_string(),
                score,
                reference_id: Some(recognized.reference_id),
                nearest_reference: Some(reference_source.clone()),
                target: entry.target.clone(),
                live_sha: live_sha.clone(),
                target_absent,
                reference_sha: reference_sha.clone(),
                interactable_id: None,
            });
            continue;
        }
        let config_act_binding = step_id
            .map(|step_id| config_act_binding(manifest, step_id))
            .transpose()?;
        config.push(crate::ledger::ConfigProposal {
            id: id.clone(), state: config_state, source: reference_bytes,
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
            diff: entry.diff.clone(),
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
            // A changed offer supersedes the prior set for this surface.
            remove_ids.extend(
                feed.interactables
                    .iter()
                    .filter(|item| item.target_path.as_deref() == Some(entry.target.as_path()))
                    .map(|item| item.id.clone()),
            );
            feed.interactables
                .retain(|item| item.target_path.as_deref() != Some(entry.target.as_path()));
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
        FeedPersistenceIntent::Upsert {
            entries: feed
                .interactables
                .iter()
                .filter(|item| upsert_ids.contains(&item.id))
                .cloned()
                .collect(),
            remove_ids,
            sort_by_id: true,
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
    let path = interactables::feed_path();
    crate::atoms::attest::with_proposal_projection_lock(&path, || {
        let observed = validated_symlink_observation(step)?;
        let binding = config_act_binding(manifest, &step.step_id)?;
        let feed = interactables::load_feed(&path)?;
        let target = PathBuf::from(observed["target"].as_str()
            .ok_or("validated-symlink-target-unresolved")?);
        let matching_ids = feed.interactables.iter()
            .filter(|item| item.module_id == manifest.id
                && item.target_path.as_ref() == Some(&target)
                && item.extra.get("validated_symlink").is_some_and(|value| !value.is_null()))
            .map(|item| item.id.clone()).collect::<BTreeSet<_>>();
        if observed["link_target"] == observed["source"] {
            if !matching_ids.is_empty() {
                let feed = compose_feed(feed, &FeedPersistenceIntent::Upsert {
                    entries: Vec::new(), remove_ids: matching_ids, sort_by_id: true,
                });
                persist_feed_locked(&path, &feed, &[])?;
            }
            return Ok(false);
        }
        let id = validated_symlink_proposal_id(&manifest.id, &binding, &observed)?;
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
            available_at: prior.and_then(|item| item.available_at.clone()).or_else(|| Some(now.clone())),
            silenced: prior.is_some_and(|item| item.silenced),
            silenced_at: prior.and_then(|item| item.silenced_at.clone()),
            has_run: false, mode: None, owner: None, group: None,
            source_sha: None, target_sha: None, commits_behind: None,
            live_sha: observed["link_target"].as_str()
                .map(|value| format!("{:x}", Sha256::digest(value.as_bytes()))),
            reference_sha: observed["source_sha256"].as_str().map(str::to_owned),
            recognition_score: None,
            diff: Some(format!("{} -> {} (currently {})", target.display(), source.display(),
                observed["link_target"].as_str().unwrap_or("absent"))),
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
        let feed = compose_feed(feed, &FeedPersistenceIntent::Upsert {
            entries: vec![item],
            remove_ids: matching_ids.into_iter().filter(|candidate| candidate != &id).collect(),
            sort_by_id: true,
        });
        if let Err(error) = crate::ledger::prepare_config_proposals(&path, &feed, &config) {
            report_proposal_row_failure(&error);
            return Ok(false);
        }
        persist_feed_locked(&path, &feed, &config)?;
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
            *ok = false;
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
                    *ok = false;
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
                *ok = false;
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

    #[test]
    fn prune_stale_interactables_hides_and_removes_retired_engine_rows_only() {
        let root = std::env::temp_dir().join(format!(
            "harmonia-prune-interactables-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let feed_path = root.join("interactables.json");
        let events_path = root.join("events.jsonl");
        let reference = root.join("known-good.conf");
        let shared_target = root.join("shared.conf");
        fs::write(&reference, b"known-good\n").unwrap();

        let backup = root
            .join("interactables-backups")
            .join("ghost-entry")
            .join("has-run-copy");
        fs::create_dir_all(backup.parent().unwrap()).unwrap();
        fs::write(&backup, b"preserve me\n").unwrap();

        let entries = vec![
            prune_item(
                &root,
                "live-entry",
                "live-module",
                root.join("live.conf"),
                reference.clone(),
                false,
            ),
            prune_item(
                &root,
                "absent-entry",
                "absent-module",
                root.join("absent.conf"),
                reference.clone(),
                false,
            ),
            prune_item(
                &root,
                "missing-entry",
                "missing-module",
                root.join("missing.conf"),
                root.join("missing-reference.conf"),
                false,
            ),
            prune_item(
                &root,
                "ghost-entry",
                "ghost-module",
                shared_target.clone(),
                root.join("ghost-reference.conf"),
                true,
            ),
            prune_item(
                &root,
                "survivor-entry",
                "survivor-module",
                shared_target.clone(),
                reference.clone(),
                false,
            ),
            {
                let mut engine = prune_item(
                    &root,
                    "engine-replacement-entry",
                    "harmonia",
                    root.join("staged-engine"),
                    reference.clone(),
                    false,
                );
                engine.kind = "engine-replacement".into();
                engine
            },
        ];
        persist_feed(&feed_path, &interactables::make_feed(entries)).unwrap();
        let visible_before_prune = interactables::load_feed(&feed_path).unwrap();
        assert!(visible_before_prune
            .interactables
            .iter()
            .all(|item| item.kind != "engine-replacement"));
        assert!(interactables::load_feed_raw(&feed_path)
            .unwrap()
            .interactables
            .iter()
            .any(|item| item.kind == "engine-replacement"));
        let mut events = File::create(&events_path).unwrap();
        let profile = Profile {
            id: "fixture-profile".into(),
            identity: "fixture-identity".into(),
            package_authority: None,
            modules: vec![
                "live-module".into(),
                "missing-module".into(),
                "survivor-module".into(),
            ],
            hotfixes: Vec::new(),
            syzygy_declaration: None,
        };

        prune_stale_interactables_at_path(&feed_path, &profile, &mut events).unwrap();
        drop(events);

        let retained = interactables::load_feed(&feed_path).unwrap().interactables;
        assert_eq!(
            retained
                .iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>(),
            vec!["live-entry", "survivor-entry"]
        );
        assert_eq!(fs::read(&backup).unwrap(), b"preserve me\n");

        let receipts = fs::read_to_string(&events_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            receipts,
            vec![
                serde_json::json!({
                    "schema": "harmonia.interactables.prune.v1",
                    "id": "absent-entry",
                    "module_id": "absent-module",
                    "target_path": root.join("absent.conf"),
                    "reason": "module-absent-from-profile",
                }),
                serde_json::json!({
                    "schema": "harmonia.interactables.prune.v1",
                    "id": "missing-entry",
                    "module_id": "missing-module",
                    "target_path": root.join("missing.conf"),
                    "reason": "reference-absent",
                }),
                serde_json::json!({
                    "schema": "harmonia.interactables.prune.v1",
                    "id": "ghost-entry",
                    "module_id": "ghost-module",
                    "target_path": shared_target,
                    "reason": "module-absent-from-profile",
                }),
                serde_json::json!({
                    "schema": "harmonia.interactables.prune.v1",
                    "id": "engine-replacement-entry",
                    "module_id": "harmonia",
                    "target_path": root.join("staged-engine"),
                    "reason": "retired-kind",
                }),
            ]
        );
        assert!(receipts
            .iter()
            .all(|receipt| { receipt.as_object().is_some_and(|fields| fields.len() == 5) }));
        println!(
            "prune_receipt={}",
            serde_json::to_string(&receipts[0]).unwrap()
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn prune_stale_interactables_keeps_ruyi_born_rows_without_references() {
        let root =
            std::env::temp_dir().join(format!("harmonia-prune-ruyi-born-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let feed_path = root.join("interactables.json");
        let events_path = root.join("events.jsonl");
        let present_reference = root.join("known-good.conf");
        fs::write(&present_reference, b"known-good\n").unwrap();

        let present_hard_stamp = prune_item(
            &root,
            "present-hard-stamp",
            "active-module",
            root.join("present.conf"),
            present_reference,
            false,
        );
        let absent_hard_stamp = prune_item(
            &root,
            "absent-hard-stamp",
            "active-module",
            root.join("absent.conf"),
            root.join("missing-reference.conf"),
            false,
        );
        let mut toolchain_ratchet = prune_item(
            &root,
            "toolchain-ratchet",
            "active-module",
            root.join("toolchain"),
            root.join("unused-reference.conf"),
            false,
        );
        toolchain_ratchet.kind = "toolchain-ratchet".into();
        toolchain_ratchet.reference_source_path = None;
        toolchain_ratchet.extra.insert(
            "preserve-me".into(),
            serde_json::Value::String("serialized intact".into()),
        );
        let mut ruyi_bump = prune_item(
            &root,
            "ruyi-bump",
            "active-module",
            root.join("ruyi"),
            root.join("unused-reference.conf"),
            false,
        );
        ruyi_bump.kind = "ruyi-bump".into();
        ruyi_bump.reference_source_path = None;

        let ratchet_bytes_before = serde_json::to_vec(&toolchain_ratchet).unwrap();
        persist_feed(
            &feed_path,
            &interactables::make_feed(vec![
                present_hard_stamp,
                absent_hard_stamp,
                toolchain_ratchet,
                ruyi_bump,
            ]),
        )
        .unwrap();
        let mut events = File::create(&events_path).unwrap();
        let profile = Profile {
            id: "fixture-profile".into(),
            identity: "fixture-identity".into(),
            package_authority: None,
            modules: vec!["active-module".into()],
            hotfixes: Vec::new(),
            syzygy_declaration: None,
        };

        prune_stale_interactables_at_path(&feed_path, &profile, &mut events).unwrap();
        drop(events);

        let retained = interactables::load_feed_raw(&feed_path)
            .unwrap()
            .interactables;
        assert_eq!(
            retained
                .iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>(),
            vec!["present-hard-stamp", "toolchain-ratchet", "ruyi-bump"]
        );
        let ratchet_after = retained
            .iter()
            .find(|item| item.id == "toolchain-ratchet")
            .unwrap();
        assert_eq!(
            serde_json::to_vec(ratchet_after).unwrap(),
            ratchet_bytes_before
        );

        let receipts = fs::read_to_string(&events_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            receipts,
            vec![serde_json::json!({
                "schema": "harmonia.interactables.prune.v1",
                "id": "absent-hard-stamp",
                "module_id": "active-module",
                "target_path": root.join("absent.conf"),
                "reason": "reference-absent",
            })]
        );

        fs::remove_dir_all(root).unwrap();
    }

}
