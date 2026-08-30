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
use std::fs;
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
fn stable_id(surface: &Path, live_sha: &str, reference_sha: &str) -> String {
    let digest =
        Sha256::digest(format!("{}:{live_sha}:{reference_sha}", surface.display()).as_bytes());
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

pub(crate) fn refresh_interactables_for_convergence(
    manifest: &LadderManifest,
    request: &FileConvergenceRequest,
    outcome: &FileConvergenceOutcome,
) -> Result<Vec<ConfigRecognition>, String> {
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
) -> Result<Vec<ConfigRecognition>, String> {
    let mut feed = interactables::load_feed(path)?;
    let mut recognitions = Vec::new();
    let now = stamp();
    let available_at = iso8601_now();
    for entry in &outcome.entries {
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
        let live_bytes = fs::read(&entry.target).unwrap_or_default();
        let reference_bytes = fs::read(&entry.source).unwrap_or_default();
        let live_sha = format!("{:x}", Sha256::digest(&live_bytes));
        let reference_sha = format!("{:x}", Sha256::digest(&reference_bytes));
        let id = stable_id(&entry.target, &live_sha, &reference_sha);
        let created_at = feed
            .interactables
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.created_at.clone())
            .unwrap_or_else(|| now.clone());
        // A new pair supersedes stale offers for this surface only.
        feed.interactables.retain(|e| e.target_path != entry.target);
        let recognized = interactables::recognize_against_known_goods(
            &live_bytes,
            &[interactables::RecognitionCandidate {
                reference_id: &entry.source.to_string_lossy(),
                bytes: &reference_bytes,
            }],
        )
        .ok_or_else(|| "config-recognition-no-known-good".to_string())?;
        let score = recognized.score;
        let state = if score >= 0.33 {
            "interactable"
        } else {
            "refused-unrecognized"
        };
        let state_receipt = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(format!(
                "config-state-{}.json",
                id.strip_prefix("config-proposal-").unwrap_or(&id)
            ));
        crate::atoms::attest::write_json_atomic(
            &state_receipt,
            &serde_json::json!({
                "schema": "harmonia.config_state.v1", "config_state": state, "id": id.clone(),
                "target": entry.target.clone(), "reference": entry.source.clone(), "score": score,
                "live_sha": live_sha.clone(), "reference_sha": reference_sha.clone(),
                "threshold": 0.33, "reference_id": entry.source.clone()
            }),
        )?;
        if score < 0.33 {
            recognitions.push(ConfigRecognition {
                config_state: state.to_string(),
                score,
                reference_id: Some(recognized.reference_id),
                nearest_reference: Some(entry.source.clone()),
                target: entry.target.clone(),
                live_sha: live_sha.clone(),
                reference_sha: reference_sha.clone(),
                interactable_id: None,
            });
            continue;
        }
        let interactable_id = id.clone();
        feed.interactables.push(Interactable {
            id: id.clone(),
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
            live_sha: Some(live_sha.clone()),
            reference_sha: Some(reference_sha.clone()),
            recognition_score: Some(score),
            script: format!("harmonia interactable run {} owner", interactable_id),
            show_only_if: "config_state=interactable".into(),
            completion_check: format!("sha256:{reference_sha}"),
        });
        recognitions.push(ConfigRecognition {
            config_state: state.to_string(),
            score,
            reference_id: Some(recognized.reference_id),
            nearest_reference: Some(entry.source.clone()),
            target: entry.target.clone(),
            live_sha,
            reference_sha,
            interactable_id: Some(interactable_id),
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
    )?;
    Ok(recognitions)
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ConfigRecognition {
    pub(crate) config_state: String,
    pub(crate) score: f64,
    pub(crate) reference_id: Option<String>,
    pub(crate) nearest_reference: Option<PathBuf>,
    pub(crate) target: PathBuf,
    pub(crate) live_sha: String,
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
    auth: Option<&SoftwareApplyAuthorization>,
    pa: Option<&PackageAuthority>,
    key: Option<&crate::atoms::r#do::InvocationKey>,
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
            result.placements.push(serde_json::json!({"step_id":format!("{}#precondition", step.step_id),"tool":step.tool,"permutation":step.permutation,"band":"ProposeEdits","status":if probe.ok {"completed"} else {"blocked"},"ok":probe.ok,"changed":probe.changed,"skipped":probe.skipped,"message":probe.message,"command":probe.command,"module":manifest.id,"precondition_for":step.step_id}));
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
            result.placements.push(serde_json::json!({"step_id":step.step_id,"tool":step.tool,"permutation":step.permutation,"band":"ProposeEdits","status":if outcome.ok {"completed"} else {"failed"},"ok":outcome.ok,"changed":outcome.changed,"skipped":outcome.skipped,"message":outcome.message,"command":outcome.command,"module":manifest.id}));
        }
        result.changed |= outcome.changed;
        if !outcome.ok {
            result.ok = false;
            result.first_missing_signal.get_or_insert_with(|| {
                format!("step_id={} defect={}", step.step_id, outcome.message)
            });
            if step.on_failure == crate::tools::ladder::OnFailure::Stop {
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
    mode: &UpdateMode,
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

#[cfg(test)]
mod refresh_interactables_tests {
    use super::refresh_interactables_at_path;
    use crate::interactables::{self, DriftSummary, Interactable};
    use crate::tools::files::{
        FileConvergenceEntry, FileConvergenceOutcome, FileConvergenceRequest, FileSpec,
    };
    use crate::tools::ladder::LadderManifest;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn scratch() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "harmonia-refresh-interactables-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn unrelated_item(root: &Path) -> Interactable {
        Interactable {
            id: "unrelated-proposal".into(),
            module_id: "other-module".into(),
            name: "unrelated proposal".into(),
            description: "keep me".into(),
            kind: "hard-stamp".into(),
            target_path: root.join("other.conf"),
            reference_source_path: root.join("other-source.conf"),
            drift: DriftSummary {
                content: true,
                mode: false,
                ownership: false,
            },
            created_at: "0".into(),
            refreshed_at: "0".into(),
            available_at: Some("0".into()),
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
            script: "keep".into(),
            show_only_if: "".into(),
            completion_check: "".into(),
        }
    }

    fn manifest() -> LadderManifest {
        LadderManifest {
            schema: "harmonia.module.ladder.v1".into(),
            id: "fixture-module".into(),
            version: "1".into(),
            description: "fixture description".into(),
            role: None,
            optional: false,
            optional_warning: None,
            category: None,
            group: None,
            constants: BTreeMap::new(),
            package_pins: BTreeMap::new(),
            package_ceilings: BTreeMap::new(),
            caduceus_commands: Vec::new(),
            files_root: None,
            config_deploy: Some("interactable".into()),
            ladder: Vec::new(),
            base_dir: PathBuf::new(),
        }
    }

    fn request(root: &Path) -> FileConvergenceRequest {
        FileConvergenceRequest {
            source_root: root.join("source-root"),
            target_root: root.join("config_deploy:interactable"),
            files: vec![FileSpec {
                relative_path: "target.conf".into(),
                mode: Some(0o644),
            }],
            backup_existing: true,
            receipt_name: "fixture-refresh".into(),
            owner: Some("owner".into()),
            group: Some("group".into()),
        }
    }

    fn outcome(source: &Path, target: &Path) -> FileConvergenceOutcome {
        FileConvergenceOutcome {
            ok: true,
            changed: true,
            ownership_changed: false,
            checked: 1,
            written: 1,
            backed_up: 1,
            missing: Vec::new(),
            missing_target_birth_debts: Vec::new(),
            entries: vec![FileConvergenceEntry {
                relative_path: "target.conf".into(),
                source: source.to_path_buf(),
                target: target.to_path_buf(),
                source_exists: true,
                target_exists_before: true,
                content_equal_before: false,
                mode_equal_before: true,
                target_exists_after: true,
                content_equal_after: true,
                mode_equal_after: true,
                changed: true,
                backed_up_to: None,
                final_mode: Some(0o644),
                ownership_source: "request".into(),
                observed_uid_before: None,
                observed_gid_before: None,
                observed_uid_after: None,
                observed_gid_after: None,
                ownership_changed: false,
                observed_uid: None,
                observed_gid: None,
                diff: None,
                diff_omitted: None,
            }],
            message: "fixture".into(),
        }
    }

    #[test]
    fn refresh_interactables_at_path_refreshes_dedupes_and_refuses_below_wall() {
        let root = scratch();
        let feed_path = root.join("interactables.json");
        let source = root.join("known-good.conf");
        let target = root.join("config_deploy:interactable/target.conf");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(
            &source,
            include_bytes!("../../../tests/fixtures/harmonia/known-good.conf"),
        )
        .unwrap();
        fs::write(
            &target,
            include_bytes!("../../../tests/fixtures/harmonia/live-above-wall.conf"),
        )
        .unwrap();
        super::persist_feed(
            &feed_path,
            &interactables::make_feed(vec![unrelated_item(&root)]),
        )
        .unwrap();

        let manifest = manifest();
        let request = request(&root);
        let first = refresh_interactables_at_path(
            &feed_path,
            &manifest,
            &request,
            &outcome(&source, &target),
        )
        .unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].config_state, "interactable");
        assert!(first[0].score >= 0.33);
        assert!(first[0]
            .reference_id
            .as_ref()
            .is_some_and(|value| !value.is_empty()));
        assert!(first[0].nearest_reference.is_some());
        assert!(first[0]
            .interactable_id
            .as_ref()
            .is_some_and(|value| !value.is_empty()));
        assert_eq!(
            fs::read(&target).unwrap(),
            include_bytes!("../../../tests/fixtures/harmonia/live-above-wall.conf").as_slice()
        );
        let first_feed = interactables::load_feed(&feed_path).unwrap();
        assert_eq!(first_feed.interactables.len(), 2);
        let proposal = first_feed
            .interactables
            .iter()
            .find(|item| item.target_path == target)
            .unwrap();
        assert!(!proposal.name.is_empty());
        assert!(!proposal.description.is_empty());
        assert!(proposal
            .available_at
            .as_ref()
            .is_some_and(|value| !value.is_empty()));
        assert!(!proposal.script.is_empty());
        assert!(!proposal.show_only_if.is_empty());
        assert!(!proposal.completion_check.is_empty());

        let second = refresh_interactables_at_path(
            &feed_path,
            &manifest,
            &request,
            &outcome(&source, &target),
        )
        .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(
            interactables::load_feed(&feed_path)
                .unwrap()
                .interactables
                .len(),
            2
        );

        fs::write(
            &target,
            include_bytes!("../../../tests/fixtures/harmonia/live-below-wall.conf"),
        )
        .unwrap();
        let refused = refresh_interactables_at_path(
            &feed_path,
            &manifest,
            &request,
            &outcome(&source, &target),
        )
        .unwrap();
        assert_eq!(refused.len(), 1);
        assert_eq!(refused[0].config_state, "refused-unrecognized");
        assert!(refused[0].score < 0.33);
        let final_feed = interactables::load_feed(&feed_path).unwrap();
        assert_eq!(final_feed.interactables.len(), 1);
        assert_eq!(final_feed.interactables[0].id, "unrelated-proposal");
        assert_eq!(
            fs::read(&target).unwrap(),
            include_bytes!("../../../tests/fixtures/harmonia/live-below-wall.conf").as_slice()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
