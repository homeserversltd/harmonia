//! One declared-absent file removal organ.
#![allow(dead_code)]

use crate::atoms::{self, Drift, Receipt};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemovalObservation {
    RegularFile,
    Absent,
}

impl RemovalObservation {
    fn as_str(self) -> &'static str {
        match self {
            Self::RegularFile => "regular-file",
            Self::Absent => "absent",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileRemovalEntry {
    pub relative_path: String,
    pub target: PathBuf,
    pub found_before: String,
    pub exists_after: bool,
    pub result: String,
    pub changed: bool,
    pub observed_state: serde_json::Value,
    pub desired_state: serde_json::Value,
    pub diff_decision: String,
    pub movement: String,
    pub truthful_changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileRemovalOutcome {
    pub ok: bool,
    pub changed: bool,
    pub checked: usize,
    pub removed: usize,
    pub entries: Vec<FileRemovalEntry>,
    pub message: String,
}

pub(crate) fn execute(
    target_root: &Path,
    paths: &[String],
    receipt_dir: &Path,
    receipt_name: &str,
    apply: bool,
    invocation: Option<&atoms::r#do::InvocationKey>,
    no_follow: bool,
    collision_policy: &str,
    rollback_policy: &str,
) -> Result<FileRemovalOutcome, String> {
    validate_request(paths, receipt_name)?;
    if !no_follow || collision_policy != "refuse" || rollback_policy != "exact" {
        return Err("remove-file-policy-unsupported".into());
    }
    let mut entries = Vec::new();
    let mut removed = 0usize;
    let mut changed = false;
    let mut failure = None;
    for relative_path in paths {
        let target = target_root.join(relative_path);
        let run = crate::atoms::declaration::execute(
            "remove-file",
            "remove-file",
            || probe::file(&target),
            |state| match state {
                RemovalObservation::RegularFile => {
                    crate::atoms::comparison::DiffDecision::Different
                }
                RemovalObservation::Absent => crate::atoms::comparison::DiffDecision::Empty,
            },
            |authorization, _| {
            let authorization = &authorization;
                let Some(invocation) = invocation else {
                    return Ok(false);
                };
                mutation::remove(
                    authorization,
                    invocation,
                    &target,
                    atoms::r#do::remove_file::RemovePolicy {
                        no_follow,
                        collision_refuse: collision_policy == "refuse",
                        rollback_exact: rollback_policy == "exact",
                    },
                )
            },
        );
        let run = match run {
            Ok(run) => run,
            Err(error) => {
                failure = Some(error);
                break;
            }
        };
        let state = *run.observation();
        let diff_decision = match run.decision() {
            crate::atoms::comparison::DiffDecision::Empty => "empty",
            crate::atoms::comparison::DiffDecision::Different => "different",
        };
        let (movement, truthful_changed) = match &run {
            crate::atoms::comparison::ComparisonRun::Current { .. } => ("none", false),
            crate::atoms::comparison::ComparisonRun::Moved { movement, .. } if *movement => {
                ("remove-file", true)
            }
            crate::atoms::comparison::ComparisonRun::Moved { .. } => ("report-only", false),
        };
        if truthful_changed {
            match probe::file(&target) {
                Ok(RemovalObservation::Absent) => {
                    removed += 1;
                    changed = true;
                }
                Ok(RemovalObservation::RegularFile) => {
                    failure = Some(format!(
                        "files-remove-post-remove-readback-failed {}",
                        target.display()
                    ));
                    break;
                }
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
        let state = state.as_str();
        entries.push(FileRemovalEntry {
            relative_path: relative_path.clone(),
            target: target.clone(),
            found_before: state.into(),
            exists_after: !truthful_changed && state == "regular-file",
            result: if state == "absent" {
                "absent"
            } else if truthful_changed {
                "removed"
            } else {
                "planned-removal"
            }
            .into(),
            changed: truthful_changed,
            observed_state: json!({"state": state}),
            desired_state: json!({"state": "absent"}),
            diff_decision: diff_decision.into(),
            movement: movement.into(),
            truthful_changed,
        });
    }
    let ok = failure.is_none();
    let outcome = FileRemovalOutcome {
        ok,
        changed,
        checked: paths.len(),
        removed,
        entries,
        message: failure
            .unwrap_or_else(|| format!("{} declared files removed or absent", paths.len())),
    };
    receipt::report(target_root, receipt_dir, receipt_name, apply, &outcome)?;
    Ok(outcome)
}

fn validate_request(paths: &[String], receipt_name: &str) -> Result<(), String> {
    if paths.is_empty() {
        return Err("files-remove-empty-request".to_string());
    }
    validate_receipt_name(receipt_name)?;
    let mut seen = BTreeSet::new();
    for raw in paths {
        let path = Path::new(raw);
        if path.as_os_str().is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(format!("files-relative-path-rejected {}", path.display()));
        }
        if !seen.insert(path.to_path_buf()) {
            return Err(format!(
                "files-duplicate-relative-path-rejected {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn validate_receipt_name(receipt_name: &str) -> Result<(), String> {
    if receipt_name.is_empty() {
        return Ok(());
    }
    let path = Path::new(receipt_name);
    if path.is_absolute() || path.components().count() != 1 {
        return Err(format!("files-receipt-name-rejected {receipt_name}"));
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(format!("files-receipt-name-rejected {receipt_name}"));
    };
    if name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return Err(format!("files-receipt-name-rejected {receipt_name}"));
    }
    Ok(())
}

pub fn remove_declared_files(
    target_root: &Path,
    paths: &[String],
    receipt_dir: &Path,
    receipt_name: &str,
    apply: bool,
    invocation: Option<&atoms::r#do::InvocationKey>,
) -> Result<FileRemovalOutcome, String> {
    execute(
        target_root,
        paths,
        receipt_dir,
        receipt_name,
        apply,
        invocation,
        true,
        "refuse",
        "exact",
    )
}

pub fn declaration() -> Result<Option<&'static crate::atoms::declaration::Declaration>, String> {
    crate::atoms::declaration::get("remove-file")
}

mod probe {
    use super::*;

    pub(super) fn file(path: &Path) -> Result<RemovalObservation, String> {
        match atoms::ask::remove_file::probe(path) {
            Ok(observation) if observation.preimage.kind == Some(atoms::ask::FsKind::File) => {
                Ok(RemovalObservation::RegularFile)
            }
            Ok(observation) if !observation.preimage.present => Ok(RemovalObservation::Absent),
            Ok(_) => Err(format!(
                "files-remove-target-not-regular-file {}",
                path.display()
            )),
            Err(error) => Err(format!(
                "files-remove-metadata-failed {}: {error}",
                path.display()
            )),
        }
    }
}

mod mutation {
    use super::*;
    use crate::atoms::comparison::ActionAuthorization;

    pub(super) fn remove(
        authorization: &ActionAuthorization,
        invocation: &atoms::r#do::InvocationKey,
        target: &Path,
        policy: atoms::r#do::remove_file::RemovePolicy,
    ) -> Result<bool, String> {
        atoms::r#do::remove_file::remove_file_with_policy(
            authorization,
            invocation,
            target,
            policy,
        )
        .map_err(|error| format!("files-remove-failed {}: {error}", target.display()))?;
        Ok(true)
    }
}

mod receipt {
    use super::*;

    pub(super) fn report(
        target_root: &Path,
        receipt_dir: &Path,
        receipt_name: &str,
        apply: bool,
        outcome: &FileRemovalOutcome,
    ) -> Result<(), String> {
        fs::create_dir_all(receipt_dir).map_err(|error| error.to_string())?;
        let receipt = receipt_dir.join(if receipt_name.ends_with(".json") {
            receipt_name.to_string()
        } else {
            format!("{receipt_name}.json")
        });
        let value = json!({
            "schema": "harmonia.files.remove.v1", "ok": outcome.ok, "apply": apply,
            "target_root": target_root, "checked": outcome.checked, "removed": outcome.removed,
            "changed": outcome.changed, "entries": outcome.entries,
            "first_missing_signal": if outcome.ok { "none" } else { outcome.message.as_str() },
        });
        atoms::attest::remove_file::write_existing(
            &receipt,
            &value,
            &receipt_dir.join("harmonia-atoms.log"),
            Receipt {
                atom: "remove-file".into(),
                ok: outcome.ok,
                drift: Drift::Current,
                message: outcome.message.clone(),
            },
        )
    }
}
