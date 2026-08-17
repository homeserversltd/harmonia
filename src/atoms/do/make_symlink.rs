//! Indexed implementation spine for validated file-and-symlink promotion.
//!
//! The source remains one Rust privacy scope through `include!`, while each
//! independently named transaction boundary owns an indexed directory.

use crate::atoms;
use crate::{CmdResult, OperationOutcome};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

pub fn declaration() -> Result<Option<&'static crate::atoms::declaration::Declaration>, String> {
    crate::atoms::declaration::get("make-symlink")
}

#[derive(Clone)]
struct SymlinkObservation {
    desired: Vec<u8>,
    desired_mode: u32,
    source: SavedFile,
    link: SavedLink,
    source_candidate: PathBuf,
    link_candidate: PathBuf,
    source_candidate_exists: bool,
    link_candidate_exists: bool,
}

fn observe_symlink(
    request: &ValidatedFileSymlinkRequest<'_>,
) -> Result<SymlinkObservation, String> {
    let desired = atoms::ask::file(request.desired_source)
        .map(|observation| observation.bytes)
        .map_err(|_| "validated-file-symlink-desired-source-missing".to_string())?;
    let desired_mode = atoms::ask::file_mode(request.desired_source)?;
    let (source_candidate, link_candidate) = candidate_paths(request)?;
    let source_candidate_exists = atoms::ask::path_kind(&source_candidate)?.is_some();
    let link_candidate_exists = atoms::ask::path_kind(&link_candidate)?.is_some();
    Ok(SymlinkObservation {
        desired,
        desired_mode,
        source: save_file(request.source)?,
        link: save_link(request.target)?,
        source_candidate,
        link_candidate,
        source_candidate_exists,
        link_candidate_exists,
    })
}

fn candidate_paths(
    request: &ValidatedFileSymlinkRequest<'_>,
) -> Result<(PathBuf, PathBuf), String> {
    let pid = std::process::id();
    let source_parent = request
        .source
        .parent()
        .ok_or_else(|| "validated-file-symlink-source-parent-missing".to_string())?;
    let target_parent = request
        .target
        .parent()
        .ok_or_else(|| "validated-file-symlink-target-parent-missing".to_string())?;
    Ok((
        source_parent.join(format!(
            ".{}.harmonia-source-candidate-{pid}",
            request
                .source
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or("source")
        )),
        target_parent.join(format!(
            "{}.harmonia-link-candidate-{pid}",
            request
                .target
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or("link")
        )),
    ))
}

#[derive(Clone)]
struct SavedFile {
    bytes: Option<Vec<u8>>,
    mode: Option<u32>,
}

#[derive(Clone)]
struct SavedLink {
    exists: bool,
    target: Option<PathBuf>,
}

fn save_file(path: &Path) -> Result<SavedFile, String> {
    match atoms::ask::path_kind(path) {
        Ok(Some(atoms::ask::PathKind::RegularFile)) => Ok(SavedFile {
            bytes: Some(atoms::ask::file(path).map_err(|e| e.to_string())?.bytes),
            mode: Some(atoms::ask::file_mode(path)?),
        }),
        Ok(Some(_)) => Err(format!(
            "validated-file-symlink-source-not-file {}",
            path.display()
        )),
        Ok(None) => Ok(SavedFile {
            bytes: None,
            mode: None,
        }),
        Err(error) => Err(format!(
            "validated-file-symlink-source-observe-failed {}: {error}",
            path.display()
        )),
    }
}

fn save_link(path: &Path) -> Result<SavedLink, String> {
    match atoms::ask::path_kind(path) {
        Ok(Some(atoms::ask::PathKind::Symlink)) => Ok(SavedLink {
            exists: true,
            target: Some(atoms::ask::link_target(path).map_err(|error| {
                format!(
                    "validated-file-symlink-target-observe-failed {}: {error}",
                    path.display()
                )
            })?),
        }),
        Ok(Some(_)) => Err(format!(
            "validated-file-symlink-target-not-link {}",
            path.display()
        )),
        Ok(None) => Ok(SavedLink {
            exists: false,
            target: None,
        }),
        Err(error) => Err(format!(
            "validated-file-symlink-target-observe-failed {}: {error}",
            path.display()
        )),
    }
}

fn restore_file(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    path: &Path,
    saved: &SavedFile,
) -> Result<(), String> {
    match &saved.bytes {
        Some(bytes) => atoms::r#do::file_write(
            authorization,
            invocation,
            path,
            bytes,
            atoms::r#do::FileWriteOptions {
                write_bytes: true,
                mode: saved.mode,
                uid: None,
                gid: None,
                backup_to: None,
            },
        )
        .map(|_| ()),
        None => {
            if atoms::ask::path_kind(path)?.is_some() {
                atoms::r#do::remove_file(authorization, invocation, path).map_err(|e| {
                    format!(
                        "validated-file-symlink-restore-source-remove-failed {}: {e}",
                        path.display()
                    )
                })?;
            }
            Ok(())
        }
    }
}

fn restore_link(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    path: &Path,
    saved: &SavedLink,
) -> Result<(), String> {
    if atoms::ask::path_kind(path)?.is_some() {
        atoms::r#do::remove_file(authorization, invocation, path).map_err(|e| {
            format!(
                "validated-file-symlink-restore-link-remove-failed {}: {e}",
                path.display()
            )
        })?;
    }
    if saved.exists {
        let link = saved
            .target
            .as_ref()
            .ok_or_else(|| "validated-file-symlink-restore-link-unobserved".to_string())?;
        atoms::r#do::symlink(authorization, invocation, link, path).map_err(|e| {
            format!(
                "validated-file-symlink-restore-link-create-failed {}: {e}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn source_matches_saved(path: &Path, saved: &SavedFile) -> bool {
    match (atoms::ask::path_kind(path), &saved.bytes) {
        (Ok(None), None) => true,
        (Ok(Some(atoms::ask::PathKind::RegularFile)), Some(bytes)) => {
            atoms::ask::file(path)
                .ok()
                .map(|file| file.bytes)
                .as_deref()
                == Some(bytes.as_slice())
                && atoms::ask::file_mode(path).ok() == saved.mode
        }
        _ => false,
    }
}

fn link_matches_saved(path: &Path, saved: &SavedLink) -> bool {
    match atoms::ask::path_kind(path) {
        Ok(Some(atoms::ask::PathKind::Symlink)) => {
            saved.exists && atoms::ask::link_target(path).ok() == saved.target
        }
        Ok(None) => !saved.exists,
        _ => false,
    }
}

fn residual_changed(
    source: &Path,
    source_before: &SavedFile,
    target: &Path,
    link_before: &SavedLink,
) -> bool {
    !source_matches_saved(source, source_before) || !link_matches_saved(target, link_before)
}

#[derive(Clone, Copy)]
pub(crate) struct ValidatedFileSymlinkRequest<'a> {
    pub receipt_dir: &'a Path,
    pub name: &'a str,
    pub desired_source: &'a Path,
    pub source: &'a Path,
    pub target: &'a Path,
    pub validator_program: &'a str,
    pub validator_args: &'a [String],
    pub reload_program: Option<&'a str>,
    pub reload_args: &'a [String],
    pub timeout_secs: u64,
    pub apply: bool,
}

#[derive(Default)]
struct PromotionState {
    source: bool,
    link: bool,
}

#[derive(Default)]
struct RestorationState {
    attempted: bool,
    ok: Option<bool>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum FileSymlinkMutation {
    Source,
    Link,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub(crate) enum FileSymlinkFault {
    StageSource,
    StageLink,
    BeforeSourcePromotion,
    AfterSourcePromotion,
    BeforeLinkRestage,
    BeforeLinkPromotion,
    AfterLinkPromotion,
    DuringSourceRestoration,
    #[cfg(test)]
    ReplaceSourceWithDanglingSymlinkDuringRestoration,
    DuringLinkRestoration,
}

#[cfg(test)]
thread_local! {
    static FILE_SYMLINK_FAULT: std::cell::Cell<u16> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn set_file_symlink_faults(faults: &[FileSymlinkFault]) {
    let mask = faults
        .iter()
        .fold(0u16, |mask, fault| mask | (1 << (*fault as u8)));
    FILE_SYMLINK_FAULT.with(|slot| slot.set(mask));
}

#[cfg(test)]
pub(crate) fn set_file_symlink_fault(fault: Option<FileSymlinkFault>) {
    set_file_symlink_faults(&fault.into_iter().collect::<Vec<_>>());
}

fn file_symlink_fault(_fault: FileSymlinkFault) -> Result<(), String> {
    #[cfg(test)]
    {
        let fault = _fault;
        let bit = 1 << (fault as u8);
        let injected = FILE_SYMLINK_FAULT.with(|slot| {
            let mask = slot.get();
            slot.set(mask & !bit);
            mask & bit != 0
        });
        if injected {
            return Err(format!("injected {fault:?}"));
        }
    }
    Ok(())
}

#[cfg(test)]
fn replace_source_with_dangling_symlink_during_restoration(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    path: &Path,
) -> Result<bool, String> {
    let fault = FileSymlinkFault::ReplaceSourceWithDanglingSymlinkDuringRestoration;
    let bit = 1 << (fault as u8);
    let injected = FILE_SYMLINK_FAULT.with(|slot| {
        let mask = slot.get();
        slot.set(mask & !bit);
        mask & bit != 0
    });
    if !injected {
        return Ok(false);
    }
    atoms::r#do::remove_file(authorization, invocation, path)?;
    atoms::r#do::symlink(
        authorization,
        invocation,
        &path.with_extension("residual"),
        path,
    )?;
    Ok(true)
}

fn rollback_file_symlink(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    mutations: &[FileSymlinkMutation],
    source: &Path,
    source_before: &SavedFile,
    target: &Path,
    link_before: &SavedLink,
) -> Option<String> {
    let mut first_error = None;
    for mutation in mutations.iter().rev() {
        let result = match mutation {
            FileSymlinkMutation::Source => {
                #[cfg(test)]
                match replace_source_with_dangling_symlink_during_restoration(
                    authorization,
                    invocation,
                    source,
                ) {
                    Ok(true) => {
                        Err("injected residual dangling source symlink during restoration".into())
                    }
                    Ok(false) => file_symlink_fault(FileSymlinkFault::DuringSourceRestoration)
                        .and_then(|_| {
                            restore_file(authorization, invocation, source, source_before)
                        }),
                    Err(error) => Err(error),
                }
                #[cfg(not(test))]
                file_symlink_fault(FileSymlinkFault::DuringSourceRestoration)
                    .and_then(|_| restore_file(authorization, invocation, source, source_before))
            }
            FileSymlinkMutation::Link => {
                file_symlink_fault(FileSymlinkFault::DuringLinkRestoration)
                    .and_then(|_| restore_link(authorization, invocation, target, link_before))
            }
        };
        if let Err(error) = result {
            first_error.get_or_insert(error);
        }
    }
    first_error
}

/// Comparison is the sole gate for promotion; the legacy body is reachable only
/// from the non-empty action arm.
pub(crate) fn execute(
    request: ValidatedFileSymlinkRequest<'_>,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    if request.apply && invocation.is_none() {
        return Err("validated-file-symlink-apply-invocation-required".into());
    }
    let run = crate::atoms::comparison::execute(
        "make-symlink",
        || observe_symlink(&request),
        |observation| {
            if observation.desired.as_slice()
                == observation.source.bytes.as_deref().unwrap_or_default()
                && observation.link.target.as_deref() == Some(request.source)
                && observation.desired_mode == observation.source.mode.unwrap_or_default()
            {
                crate::atoms::comparison::DiffDecision::Empty
            } else {
                crate::atoms::comparison::DiffDecision::Different
            }
        },
        |authorization, observation| {
            let Some(invocation) = invocation else {
                return write_receipt(&request, TerminalReceipt::no_change(true));
            };
            execute_action(authorization, invocation, request, observation)
        },
    )?;
    match run {
        crate::atoms::comparison::ComparisonRun::Current { .. } => {
            write_receipt(&request, TerminalReceipt::no_change(true))
        }
        crate::atoms::comparison::ComparisonRun::Moved {
            observation,
            movement,
            ..
        } => {
            let SymlinkObservation {
                desired,
                desired_mode,
                source: source_before,
                link: link_before,
                ..
            } = observation;
            let path = request.receipt_dir.join(format!("{}.json", request.name));
            let mut receipt: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&path).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            let object = receipt
                .as_object_mut()
                .ok_or_else(|| "validated-file-symlink-receipt-not-object".to_string())?;
            object.insert(
                "observed_state".into(),
                json!({
                    "desired_bytes": desired,
                    "source_bytes": source_before.bytes,
                    "source_mode": source_before.mode,
                    "link_target": link_before.target,
                }),
            );
            object.insert(
                "desired_state".into(),
                json!({"source_bytes": desired, "source_mode": desired_mode, "link_target": request.source}),
            );
            object.insert("diff_decision".into(), json!("different"));
            object.insert("truthful_changed".into(), json!(movement.changed));
            crate::write_json(&path, &receipt)?;
            Ok(movement)
        }
    }
}

/// Validates desired bytes through a hidden source candidate and a non-hidden sibling
/// link candidate, so Nginx's `sites-enabled/*` include observes the exact candidate.
fn execute_action(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    request: ValidatedFileSymlinkRequest<'_>,
    observation: &SymlinkObservation,
) -> Result<OperationOutcome, String> {
    let desired = &observation.desired;
    let desired_mode = observation.desired_mode;
    let source_before = observation.source.clone();
    let link_before = observation.link.clone();
    let source_candidate = observation.source_candidate.clone();
    let link_candidate = observation.link_candidate.clone();
    let source_candidate_observed = observation.source_candidate_exists;
    let link_candidate_observed = observation.link_candidate_exists;
    let source_current = source_before.bytes.as_deref() == Some(desired.as_slice())
        && source_before.mode == Some(desired_mode);
    let link_current = link_before.target.as_deref() == Some(request.source);
    if (source_current && link_current) || !request.apply {
        return write_receipt(&request, TerminalReceipt::no_change(true));
    }

    let source_parent = request
        .source
        .parent()
        .ok_or_else(|| "validated-file-symlink-source-parent-missing".to_string())?;
    let target_parent = request
        .target
        .parent()
        .ok_or_else(|| "validated-file-symlink-target-parent-missing".to_string())?;
    atoms::r#do::create_dir_all(authorization, invocation, source_parent)?;
    atoms::r#do::create_dir_all(authorization, invocation, target_parent)?;
    let source_candidate_exists = std::cell::Cell::new(source_candidate_observed);
    let link_candidate_exists = std::cell::Cell::new(link_candidate_observed);
    let mut clean = || {
        if source_candidate_exists.get()
            && atoms::r#do::remove_file(authorization, invocation, &source_candidate).is_ok()
        {
            source_candidate_exists.set(false);
        }
        if link_candidate_exists.get()
            && atoms::r#do::remove_file(authorization, invocation, &link_candidate).is_ok()
        {
            link_candidate_exists.set(false);
        }
    };
    clean();
    if let Err(error) = file_symlink_fault(FileSymlinkFault::StageSource).and_then(|_| {
        atoms::r#do::file_write(
            authorization,
            invocation,
            &source_candidate,
            desired,
            atoms::r#do::FileWriteOptions {
                write_bytes: true,
                mode: Some(desired_mode),
                uid: None,
                gid: None,
                backup_to: None,
            },
        )
        .map(|_| {
            source_candidate_exists.set(true);
        })
    }) {
        clean();
        return write_receipt(
            &request,
            TerminalReceipt::refusal(format!(
                "validated-file-symlink-stage-source-failed: {error}"
            )),
        );
    }
    #[cfg(unix)]
    if let Err(error) = file_symlink_fault(FileSymlinkFault::StageLink).and_then(|_| {
        atoms::r#do::symlink(
            authorization,
            invocation,
            &source_candidate,
            &link_candidate,
        )
        .map(|_| {
            link_candidate_exists.set(true);
        })
    }) {
        clean();
        return write_receipt(
            &request,
            TerminalReceipt::refusal(format!("validated-file-symlink-stage-link-failed: {error}")),
        );
    }
    #[cfg(not(unix))]
    return Err("validated-file-symlink-unsupported".into());
    let validator_refs: Vec<&str> = request.validator_args.iter().map(String::as_str).collect();
    let validator = crate::atoms::command::capture_with_timeout(
        request.validator_program,
        &validator_refs,
        request.timeout_secs,
    );
    if !validator.ok {
        clean();
        let mut receipt = TerminalReceipt::refusal("validated-file-symlink-validator-failed");
        receipt.validation_ran = true;
        receipt.validator = Some(validator);
        return write_receipt(&request, receipt);
    }

    let mut mutations = Vec::with_capacity(2);
    let mut promotion_error = None;
    if !source_current {
        if let Err(error) =
            file_symlink_fault(FileSymlinkFault::BeforeSourcePromotion).and_then(|_| {
                atoms::r#do::rename(authorization, invocation, &source_candidate, request.source)
            })
        {
            promotion_error = Some(format!(
                "validated-file-symlink-promote-source-failed: {error}"
            ));
        } else {
            source_candidate_exists.set(false);
            mutations.push(FileSymlinkMutation::Source);
            if let Err(error) = file_symlink_fault(FileSymlinkFault::AfterSourcePromotion) {
                promotion_error = Some(format!(
                    "validated-file-symlink-fault-after-source-promotion: {error}"
                ));
            }
        }
    }
    if promotion_error.is_none() && !link_current {
        if link_candidate_exists.get()
            && atoms::r#do::remove_file(authorization, invocation, &link_candidate).is_ok()
        {
            link_candidate_exists.set(false);
        }
        #[cfg(unix)]
        if let Err(error) = file_symlink_fault(FileSymlinkFault::BeforeLinkRestage).and_then(|_| {
            atoms::r#do::symlink(authorization, invocation, request.source, &link_candidate).map(
                |_| {
                    link_candidate_exists.set(true);
                },
            )
        }) {
            promotion_error = Some(format!(
                "validated-file-symlink-restage-live-link-failed: {error}"
            ));
        }
        if promotion_error.is_none() {
            if let Err(error) =
                file_symlink_fault(FileSymlinkFault::BeforeLinkPromotion).and_then(|_| {
                    atoms::r#do::rename(authorization, invocation, &link_candidate, request.target)
                })
            {
                promotion_error = Some(format!(
                    "validated-file-symlink-promote-link-failed: {error}"
                ));
            } else {
                link_candidate_exists.set(false);
                mutations.push(FileSymlinkMutation::Link);
                if let Err(error) = file_symlink_fault(FileSymlinkFault::AfterLinkPromotion) {
                    promotion_error = Some(format!(
                        "validated-file-symlink-fault-after-link-promotion: {error}"
                    ));
                }
            }
        }
    }
    let promotion = PromotionState {
        source: mutations
            .iter()
            .any(|m| matches!(m, FileSymlinkMutation::Source)),
        link: mutations
            .iter()
            .any(|m| matches!(m, FileSymlinkMutation::Link)),
    };
    if let Some(error) = promotion_error {
        let restoration_error = rollback_file_symlink(
            authorization,
            invocation,
            &mutations,
            request.source,
            &source_before,
            request.target,
            &link_before,
        );
        clean();
        let changed =
            residual_changed(request.source, &source_before, request.target, &link_before);
        let restored = !changed;
        let signal = if restored {
            error
        } else {
            format!(
                "validated-file-symlink-restoration-failed: {}",
                restoration_error
                    .unwrap_or_else(|| "residual state differs from saved state".into())
            )
        };
        return write_receipt(
            &request,
            TerminalReceipt {
                ok: false,
                changed,
                validation_ran: true,
                promotion,
                restoration: RestorationState {
                    attempted: !mutations.is_empty(),
                    ok: Some(restored),
                },
                validator: Some(validator),
                reconcile: None,
                signal,
            },
        );
    }
    clean();
    let mut reconcile = None;
    let mut ok = true;
    let mut restoration = RestorationState::default();
    let mut changed = promotion.source || promotion.link;
    let mut signal = "none".to_string();
    if let Some(program) = request.reload_program.filter(|value| !value.is_empty()) {
        let observed = atoms::r#do::command_with_timeout(
            authorization,
            invocation,
            program,
            request.reload_args,
            std::time::Duration::from_secs(request.timeout_secs),
        )?;
        let result = CmdResult {
            ok: observed.ok,
            code: observed.code.unwrap_or(-1),
            stdout: observed.stdout,
            stderr: observed.stderr,
        };
        if !result.ok {
            let restoration_error = rollback_file_symlink(
                authorization,
                invocation,
                &mutations,
                request.source,
                &source_before,
                request.target,
                &link_before,
            );
            changed =
                residual_changed(request.source, &source_before, request.target, &link_before);
            let restored = !changed;
            restoration = RestorationState {
                attempted: true,
                ok: Some(restored),
            };
            ok = false;
            signal = if restored {
                "validated-file-symlink-reconcile-failed-restored".into()
            } else {
                format!(
                    "validated-file-symlink-restoration-failed: {}",
                    restoration_error
                        .unwrap_or_else(|| "residual state differs from saved state".into())
                )
            };
        }
        reconcile = Some(result);
    }
    write_receipt(
        &request,
        TerminalReceipt {
            ok,
            changed,
            validation_ran: true,
            promotion,
            restoration,
            validator: Some(validator),
            reconcile,
            signal,
        },
    )
}

struct TerminalReceipt {
    ok: bool,
    changed: bool,
    validation_ran: bool,
    promotion: PromotionState,
    restoration: RestorationState,
    validator: Option<CmdResult>,
    reconcile: Option<CmdResult>,
    signal: String,
}

impl TerminalReceipt {
    fn refusal(signal: impl Into<String>) -> Self {
        Self {
            ok: false,
            changed: false,
            validation_ran: false,
            promotion: PromotionState::default(),
            restoration: RestorationState::default(),
            validator: None,
            reconcile: None,
            signal: signal.into(),
        }
    }

    fn no_change(ok: bool) -> Self {
        Self {
            ok,
            changed: false,
            validation_ran: false,
            promotion: PromotionState::default(),
            restoration: RestorationState::default(),
            validator: None,
            reconcile: None,
            signal: "none".into(),
        }
    }
}

fn write_receipt(
    request: &ValidatedFileSymlinkRequest<'_>,
    receipt: TerminalReceipt,
) -> Result<OperationOutcome, String> {
    let observed_state = json!({
        "source": atoms::ask::path_kind(request.source).ok().flatten().map(|kind| {
            json!({"kind": if kind == atoms::ask::PathKind::RegularFile { "regular-file" } else { "other" }, "mode": atoms::ask::file_mode(request.source).ok()})
        }),
        "link_target": atoms::ask::link_target(request.target).ok(),
    });
    let desired_state = json!({"source_bytes_present": atoms::ask::path_kind(request.desired_source).ok().flatten().is_some(), "link_target": request.source});
    let diff_decision = if receipt.changed {
        "different"
    } else {
        "empty"
    };
    let receipt_path = request.receipt_dir.join(format!("{}.json", request.name));
    crate::write_json(
        &receipt_path,
        &json!({
            "schema":"harmonia.files.validated_file_symlink.v1",
            "ok":receipt.ok,
            "apply":request.apply,
            "changed":receipt.changed,
            "validation":{"ran":receipt.validation_ran,"result":receipt.validator},
            "promotion":{"source":receipt.promotion.source,"link":receipt.promotion.link},
            "reconcile":receipt.reconcile,
            "restoration":{"attempted":receipt.restoration.attempted,"ok":receipt.restoration.ok},
            "first_missing_signal":receipt.signal,
            "observed_state":observed_state,
            "desired_state":desired_state,
            "diff_decision":diff_decision,
            "movement": {"source": receipt.promotion.source, "link": receipt.promotion.link},
            "truthful_changed": receipt.changed,
        }),
    )?;
    atoms::attest::attest(
        &request.receipt_dir.join("harmonia-atoms.log"),
        &atoms::Receipt {
            atom: "make-symlink".into(),
            ok: receipt.ok,
            drift: atoms::Drift::Current,
            message: receipt.signal.clone(),
        },
        &[],
    )?;
    Ok(OperationOutcome {
        ok: receipt.ok,
        changed: receipt.changed,
        skipped: !request.apply,
        message: "validated file symlink".into(),
        command: None,
    })
}
