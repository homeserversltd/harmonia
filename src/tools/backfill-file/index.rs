//! One single-act tool that brings one file to its declared bytes and metadata.
#![allow(dead_code)]

use crate::atoms::{self, Drift, Receipt};
use std::path::{Path, PathBuf};

#[path = "act/index.rs"]
mod act;
#[path = "observe/index.rs"]
mod observe;
#[path = "report-home/index.rs"]
mod report_home;

#[derive(Debug, Clone, Copy)]
pub(crate) struct DeclaredOwnership {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum BackupPolicy<'a> {
    None,
    Observed(&'a Path),
}

pub(crate) struct BackfillFileRequest<'a> {
    pub path: &'a Path,
    pub declared_bytes: &'a [u8],
    pub mode: Option<u32>,
    pub ownership: DeclaredOwnership,
    pub backup: BackupPolicy<'a>,
    pub invocation: Option<atoms::r#do::InvocationKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BackfillFileObservation {
    pub existed: bool,
    pub backup_exists: bool,
    pub regular: bool,
    pub bytes_equal: bool,
    pub mode: Option<u32>,
    pub mode_equal: bool,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub owner_equal: bool,
    pub group_equal: bool,
}

impl BackfillFileObservation {
    fn current(&self) -> bool {
        self.regular && self.bytes_equal && self.mode_equal && self.owner_equal && self.group_equal
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub(crate) struct BackfillFileMovement {
    pub bytes: bool,
    pub mode: bool,
    pub owner: bool,
    pub created: bool,
    pub backed_up: Option<PathBuf>,
}

impl BackfillFileMovement {
    pub(crate) fn changed(&self) -> bool {
        self.bytes || self.mode || self.owner || self.created
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct HotfixFileBackfillOutcome {
    pub ok: bool,
    pub changed: bool,
    pub target_path: PathBuf,
    pub movement: String,
}

#[derive(Debug)]
pub(crate) struct BackfillFileOutcome {
    pub observation: BackfillFileObservation,
    pub movement: BackfillFileMovement,
    pub receipt: Receipt,
    pub hotfix_receipt: HotfixFileBackfillOutcome,
}

pub(crate) fn resolve_ownership(owner: Option<&str>) -> Result<DeclaredOwnership, String> {
    let uid = owner.map(resolve_uid).transpose()?;
    Ok(DeclaredOwnership { uid, gid: None })
}
#[cfg(unix)]
fn resolve_uid(value: &str) -> Result<u32, String> {
    if let Ok(uid) = value.parse::<u32>() {
        return Ok(uid);
    }
    let name = std::ffi::CString::new(value).map_err(|_| "hotfix-owner-invalid".to_string())?;
    let entry = unsafe { libc::getpwnam(name.as_ptr()) };
    if entry.is_null() {
        Err(format!("hotfix-owner-unknown {value}"))
    } else {
        Ok(unsafe { (*entry).pw_uid })
    }
}
#[cfg(not(unix))]
fn resolve_uid(value: &str) -> Result<u32, String> {
    Err(format!("hotfix-owner-unsupported {value}"))
}

fn validate_target(path: &Path) -> Result<(), String> {
    use std::path::Component;
    let file_name = path.file_name().and_then(|v| v.to_str()).unwrap_or("");
    let home_dotfile = path.starts_with("/home")
        && path
            .components()
            .any(|c| matches!(c,Component::Normal(v) if v.to_string_lossy().starts_with('.')));
    let key_material=file_name.starts_with("id_") || [".key",".pem",".p12",".pfx"].iter().any(|x|file_name.ends_with(x)) || path.components().any(|c| matches!(c,Component::Normal(v) if matches!(v.to_str(),Some("key")|Some("keys")|Some("private")|Some("credentials")|Some("secrets"))));
    let accounts = matches!(
        path.to_str(),
        Some("/etc/passwd" | "/etc/shadow" | "/etc/group" | "/etc/gshadow" | "/etc/sudoers")
    );
    let homeserver = matches!(
        path.to_str(),
        Some("/etc/homeserver/config.json" | "/etc/homeserver.json")
    ) || path.starts_with("/var/www/homeserver");
    if !path.is_absolute()
        || path.components().any(|c| matches!(c, Component::ParentDir))
        || path.starts_with("/root")
        || home_dotfile
        || file_name == "authorized_keys"
        || key_material
        || accounts
        || homeserver
        || path
            .components()
            .any(|c| matches!(c,Component::Normal(v) if v==".ssh"))
    {
        return Err(format!(
            "hotfix-target-identity-or-config-wall {}",
            path.display()
        ));
    }
    Ok(())
}

pub(crate) fn execute(request: BackfillFileRequest<'_>) -> Result<BackfillFileOutcome, String> {
    validate_target(request.path)?;
    let backup_path = match request.backup {
        BackupPolicy::Observed(path) => Some(path),
        BackupPolicy::None => None,
    };
    let run = crate::tools::comparison::execute(
        || {
            observe::file(
                request.path,
                request.declared_bytes,
                request.mode,
                request.ownership,
                backup_path,
            )
        },
        |observation| {
            if observation.current() {
                crate::tools::comparison::DiffDecision::Empty
            } else {
                crate::tools::comparison::DiffDecision::Different
            }
        },
        |authorization, observation| {
            let Some(invocation) = request.invocation else {
                return Ok(BackfillFileMovement::default());
            };
            act::place(
                authorization,
                invocation,
                request.path,
                request.declared_bytes,
                request.mode,
                request.ownership,
                act::BackfillFileAction {
                    bytes: !observation.bytes_equal,
                    mode: !observation.mode_equal,
                    owner: !observation.owner_equal || !observation.group_equal,
                    created: !observation.existed,
                    backup_to: match request.backup {
                        BackupPolicy::Observed(path)
                            if observation.existed
                                && (!observation.bytes_equal
                                    || !observation.mode_equal
                                    || !observation.owner_equal
                                    || !observation.group_equal) =>
                        {
                            Some(path)
                        }
                        BackupPolicy::None | BackupPolicy::Observed(_) => None,
                    },
                    backup_exists: observation.backup_exists,
                    existing_target_needs_change: observation.existed
                        && (!observation.bytes_equal
                            || !observation.mode_equal
                            || !observation.owner_equal
                            || !observation.group_equal),
                },
            )
        },
    )?;
    let movement = match &run {
        crate::tools::comparison::ComparisonRun::Current { .. } => BackfillFileMovement::default(),
        crate::tools::comparison::ComparisonRun::Moved { movement, .. } => movement.clone(),
    };
    let observation = if movement.changed() {
        let post_action = observe::file(
            request.path,
            request.declared_bytes,
            request.mode,
            request.ownership,
            backup_path,
        )
        .map_err(|_| format!("backfill-file-readback-failed {}", request.path.display()))?;
        if !post_action.current() {
            return Err(format!(
                "backfill-file-readback-failed {}",
                request.path.display()
            ));
        }
        post_action
    } else {
        run.observation().clone()
    };
    let drift = if observation.current() {
        Drift::Current
    } else {
        Drift::File {
            expected_sha256: atoms::file_sha256(request.declared_bytes),
            actual_sha256: observation
                .regular
                .then(|| std::fs::read(request.path).ok())
                .flatten()
                .map(|bytes| atoms::file_sha256(&bytes)),
        }
    };
    let receipt = report_home::receipt(request.path, drift, &movement);
    let hotfix_receipt = report_home::hotfix_receipt(request.path, movement.changed());
    Ok(BackfillFileOutcome {
        observation,
        movement,
        receipt,
        hotfix_receipt,
    })
}

pub(crate) fn observe_predicate(
    predicate: Option<&serde_json::Value>,
    payload: Option<&serde_json::Value>,
) -> Result<(bool, serde_json::Value), String> {
    observe::predicate(predicate, payload)
}
