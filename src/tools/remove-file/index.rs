//! One declared-absent file removal organ.
#![allow(dead_code)]

use crate::atoms::{self, Drift, Receipt};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

#[path = "act/index.rs"]
mod act;
#[path = "observe/index.rs"]
mod observe;
#[path = "report-home/index.rs"]
mod report_home;

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
    invocation: Option<atoms::r#do::InvocationKey>,
) -> Result<FileRemovalOutcome, String> {
    validate_request(paths, receipt_name)?;
    let invocation = invocation;
    let mut entries = Vec::new();
    let mut removed = 0usize;
    let mut changed = false;
    let mut failure = None;
    for relative_path in paths {
        let target = target_root.join(relative_path);
        let run = crate::tools::comparison::execute(
            || observe::file(&target),
            |state| match state {
                RemovalObservation::RegularFile => {
                    crate::tools::comparison::DiffDecision::Different
                }
                RemovalObservation::Absent => crate::tools::comparison::DiffDecision::Empty,
            },
            |authorization, _| {
                let Some(invocation) = invocation else {
                    return Ok(false);
                };
                act::remove(authorization, invocation, &target)
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
            crate::tools::comparison::DiffDecision::Empty => "empty",
            crate::tools::comparison::DiffDecision::Different => "different",
        };
        let (movement, truthful_changed) = match &run {
            crate::tools::comparison::ComparisonRun::Current { .. } => ("none", false),
            crate::tools::comparison::ComparisonRun::Moved { movement, .. } if *movement => {
                ("remove-file", true)
            }
            crate::tools::comparison::ComparisonRun::Moved { .. } => ("report-only", false),
        };
        if truthful_changed {
            match observe::file(&target) {
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
    report_home::report(target_root, receipt_dir, receipt_name, apply, &outcome)?;
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
