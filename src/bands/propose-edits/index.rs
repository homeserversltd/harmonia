use super::Band;
use crate::interactables::{self, DriftSummary, Interactable};
use crate::ladder::{LadderManifest, ProjectedRoutineChild, ValidatedStep};
use crate::tools::files::{FileConvergenceOutcome, FileConvergenceRequest};
use crate::ModuleExecution;
use crate::{
    LoadedModule, PackageAuthority, Profile, ProfileProjection, SoftwareApplyAuthorization,
    UpdateMode,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;
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
    let writes = crate::atoms::attest::refresh_proposal_projection(
        path,
        &feed_bytes,
        &records,
        crate::atoms::attest::ProposalOwnerPolicy::CurrentProcess,
    )?;
    crate::atoms::attest::attest(
        &path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("proposals.attest.jsonl"),
        &crate::atoms::Receipt {
            atom: "propose-edits".into(),
            ok: true,
            drift: crate::atoms::Drift::Current,
            message: format!(
                "proposal-persistence-transition count={}",
                feed.interactables.len()
            ),
        },
        &[],
    )?;
    Ok(writes)
}

pub(crate) fn proposal_refresh_demo() -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct SnapshotEntry {
        relative_path: PathBuf,
        kind: &'static str,
        mode: u32,
        uid: u32,
        gid: u32,
        inode: u64,
        mtime_seconds: i64,
        mtime_nanoseconds: i64,
        size: u64,
        sha256: Option<Vec<u8>>,
        symlink_target: Option<Vec<u8>>,
    }

    fn snapshot(root: &Path) -> Result<Vec<SnapshotEntry>, String> {
        fn visit(
            root: &Path,
            current: &Path,
            entries: &mut Vec<SnapshotEntry>,
        ) -> Result<(), String> {
            let mut children = std::fs::read_dir(current)
                .map_err(|error| format!("read-dir {}: {error}", current.display()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("read-dir-entry {}: {error}", current.display()))?;
            children.sort_by_key(|entry| entry.file_name());
            for entry in children {
                let path = entry.path();
                let metadata = std::fs::symlink_metadata(&path)
                    .map_err(|error| format!("symlink-metadata {}: {error}", path.display()))?;
                let relative_path = path
                    .strip_prefix(root)
                    .map_err(|error| format!("relative-path {}: {error}", path.display()))?
                    .to_path_buf();
                let file_type = metadata.file_type();
                let (kind, sha256, symlink_target) = if file_type.is_file() {
                    let bytes = std::fs::read(&path)
                        .map_err(|error| format!("read-file {}: {error}", path.display()))?;
                    ("file", Some(Sha256::digest(bytes).to_vec()), None)
                } else if file_type.is_dir() {
                    ("dir", None, None)
                } else if file_type.is_symlink() {
                    let target = std::fs::read_link(&path)
                        .map_err(|error| format!("read-link {}: {error}", path.display()))?;
                    (
                        "symlink",
                        None,
                        Some(target.as_os_str().as_bytes().to_vec()),
                    )
                } else {
                    return Err(format!("unsupported-node-kind {}", path.display()));
                };
                entries.push(SnapshotEntry {
                    relative_path,
                    kind,
                    mode: metadata.mode() & 0o7777,
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                    inode: metadata.ino(),
                    mtime_seconds: metadata.mtime(),
                    mtime_nanoseconds: metadata.mtime_nsec(),
                    size: metadata.len(),
                    sha256,
                    symlink_target,
                });
                if file_type.is_dir() {
                    visit(root, &path, entries)?;
                }
            }
            Ok(())
        }

        let mut entries = Vec::new();
        visit(root, root, &mut entries)?;
        entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        Ok(entries)
    }

    let root = std::env::temp_dir().join(format!(
        "harmonia-proposal-refresh-demo-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    let feed_path = root.join("interactables.json");
    let item = Interactable {
        id: "config-proposal-demo".into(),
        module_id: "demo".into(),
        name: "demo proposal".into(),
        description: "proposal refresh demo".into(),
        kind: "hard-stamp".into(),
        target_path: root.join("target"),
        reference_source_path: root.join("source"),
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
    };
    let feed = interactables::make_feed(vec![item]);
    let first_writes = persist_feed_with_writes(&feed_path, &feed)?;
    let quiet_before = snapshot(&root.join("proposals"))?;
    let second_writes = persist_feed_with_writes(&feed_path, &feed)?;
    let quiet_after = snapshot(&root.join("proposals"))?;
    let target_snapshot_unchanged = quiet_before == quiet_after;
    let record_path = root.join("proposals/config-proposal-demo.json");
    let metadata = std::fs::metadata(&record_path).map_err(|error| error.to_string())?;
    let mode_ok = metadata.permissions().mode() & 0o777 == 0o644;
    let owner_ok = (metadata.uid(), metadata.gid())
        == (unsafe { libc::geteuid() }, unsafe { libc::getegid() });
    std::fs::write(
        root.join("proposals/config-proposal-stale.json"),
        b"stale\n",
    )
    .map_err(|error| error.to_string())?;
    std::fs::set_permissions(
        root.join("proposals/config-proposal-stale.json"),
        std::fs::Permissions::from_mode(0o644),
    )
    .map_err(|error| error.to_string())?;
    let empty = interactables::make_feed(Vec::new());
    let stale_refresh = persist_feed_with_writes(&feed_path, &empty)?;
    let stale_removed = !root.join("proposals/config-proposal-stale.json").exists();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        &feed_path,
        root.join("proposals/config-proposal-collision.json"),
    )
    .map_err(|error| error.to_string())?;
    let collision_before = snapshot(&root.join("proposals"))?;
    let collision_blocked = persist_feed_with_writes(&feed_path, &feed).is_err();
    let collision_after = snapshot(&root.join("proposals"))?;
    let collision_snapshot_unchanged = collision_before == collision_after;
    let _ = std::fs::remove_file(root.join("proposals/config-proposal-collision.json"));
    let result = serde_json::json!({
        "schema": "harmonia.proposal-refresh-demo.v1",
        "ok": first_writes > 0 && mode_ok && owner_ok && stale_removed && collision_blocked && second_writes == 0 && target_snapshot_unchanged && collision_snapshot_unchanged,
        "first_writes": first_writes,
        "mode": "0644",
        "mode_observed": mode_ok,
        "owner_observed": owner_ok,
        "stale_regular_removed": stale_removed,
        "stale_refresh_writes": stale_refresh,
        "symlink_collision_blocked": collision_blocked,
        "second_identical_writes": second_writes,
        "target_snapshot_unchanged": target_snapshot_unchanged,
        "collision_snapshot_unchanged": collision_snapshot_unchanged,
    });
    let _ = std::fs::remove_dir_all(&root);
    println!(
        "{}",
        serde_json::to_string(&result).map_err(|error| error.to_string())?
    );
    if result["ok"] != true {
        return Err("proposal-refresh-demo-failed".into());
    }
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
    let log = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("proposals.attest.jsonl");
    crate::atoms::attest::attest(
        &log,
        &crate::atoms::Receipt {
            atom: "propose-edits".into(),
            ok: true,
            drift: crate::atoms::Drift::Current,
            message: format!("proposal-feed-refreshed count={}", feed.interactables.len()),
        },
        &[],
    )
}

/// Execute the complete ProposeEdits band lifecycle for one projected module.
/// Selection, preconditions, authority gating, failure policy, and accumulation
/// intentionally live here rather than in the ladder compatibility executor.
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_manifest_band(
    manifest: &LadderManifest,
    module_dir: &Path,
    auth: Option<&SoftwareApplyAuthorization>,
    pa: Option<&PackageAuthority>,
    key: Option<crate::atoms::r#do::InvocationKey>,
    mode_apply: bool,
    routine_states: &mut BTreeMap<String, crate::ModuleWalkState>,
    projected_steps: &[ValidatedStep],
    projected_routines: &BTreeMap<String, Vec<ProjectedRoutineChild>>,
    active_lane: Option<&str>,
) -> Result<ModuleExecution, String> {
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
            if !probe.ok {
                result.ok = false;
                let detail = probe
                    .command
                    .as_ref()
                    .map(|r| format!("exit_code={} stderr={}", r.code, r.stderr))
                    .unwrap_or_else(|| probe.message.clone());
                let signal = format!(
                    "step_id={} state=blocked probe_error={detail}",
                    step.step_id
                );
                result.first_missing_signal.get_or_insert(signal);
                result.placements.push(serde_json::json!({"step_id":step.step_id,"tool":step.tool,"permutation":step.permutation,"band":"ProposeEdits","status":"blocked","module":manifest.id}));
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
            crate::tools::routine::execute_validated_step(
                step,
                manifest,
                module_dir,
                auth,
                pa,
                false,
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
            result.placements.push(serde_json::json!({"step_id":step.step_id,"tool":step.tool,"permutation":step.permutation,"band":"ProposeEdits","status":if outcome.ok {"completed"} else {"failed"},"module":manifest.id}));
        }
        result.changed |= outcome.changed;
        if !outcome.ok {
            result.ok = false;
            result.first_missing_signal.get_or_insert_with(|| {
                format!("step_id={} defect={}", step.step_id, outcome.message)
            });
            if step.on_failure == crate::ladder::OnFailure::Stop {
                break;
            }
        }
    }
    Ok(result)
}

use crate::receipts::event;
pub(crate) fn execute_manifest_modules(
    profile: &Profile,
    receipt_dir: &Path,
    mode: UpdateMode,
    mode_apply: bool,
    disabled_modules: &BTreeSet<String>,
    projection: &ProfileProjection,
    states: &mut BTreeMap<String, ModuleExecution>,
    routines: &mut BTreeMap<String, BTreeMap<String, crate::ModuleWalkState>>,
    halted: &mut BTreeSet<String>,
    module_count: &mut usize,
    operation_count: &mut usize,
    changed: &mut bool,
    ok: &mut bool,
    first_missing_signal: &mut String,
    events: &mut File,
    active_lane: Option<&str>,
) -> Result<(), String> {
    for module_id in &profile.modules {
        if disabled_modules.contains(module_id) || halted.contains(module_id) {
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
        *module_count = profile.modules.len();
        let result = match &projected.loaded {
            LoadedModule::Ladder(manifest) => execute_manifest_band(
                manifest,
                &receipt_dir.join("modules").join(module_id),
                mode.software_authorization(),
                profile.package_authority.as_ref(),
                mode.invocation(),
                mode_apply,
                routines.entry(module_id.clone()).or_default(),
                &projected.steps,
                &projected.routines,
                active_lane,
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
                    halted.insert(module_id.clone());
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
                halted.insert(module_id.clone());
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
