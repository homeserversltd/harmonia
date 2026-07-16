//! Reversible validated file-and-symlink promotion transaction.
//!
//! This module owns transactional state, saved-state observation, rollback,
//! receipt projection, deterministic test faults, and focused tests.

use crate::tools::files::{atomic_write_bytes, file_mode};
use crate::{CmdResult, OperationOutcome};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

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

fn save_file(path: &Path) -> Result<SavedFile, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(SavedFile {
            bytes: Some(fs::read(path).map_err(|e| e.to_string())?),
            mode: Some(file_mode(path)?),
        }),
        Ok(_) => Err(format!(
            "validated-file-symlink-source-not-file {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(SavedFile {
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
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Ok(SavedLink {
            exists: true,
            target: Some(fs::read_link(path).map_err(|error| {
                format!(
                    "validated-file-symlink-target-observe-failed {}: {error}",
                    path.display()
                )
            })?),
        }),
        Ok(_) => Err(format!(
            "validated-file-symlink-target-not-link {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(SavedLink {
            exists: false,
            target: None,
        }),
        Err(error) => Err(format!(
            "validated-file-symlink-target-observe-failed {}: {error}",
            path.display()
        )),
    }
}

fn restore_file(path: &Path, saved: &SavedFile) -> Result<(), String> {
    match &saved.bytes {
        Some(bytes) => atomic_write_bytes(path, bytes, saved.mode),
        None => {
            if path.exists() || path.is_symlink() {
                fs::remove_file(path).map_err(|e| {
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

fn restore_link(path: &Path, saved: &SavedLink) -> Result<(), String> {
    if path.exists() || path.is_symlink() {
        fs::remove_file(path).map_err(|e| {
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
        #[cfg(unix)]
        std::os::unix::fs::symlink(link, path).map_err(|e| {
            format!(
                "validated-file-symlink-restore-link-create-failed {}: {e}",
                path.display()
            )
        })?;
        #[cfg(not(unix))]
        return Err("validated-file-symlink-unsupported".into());
    }
    Ok(())
}

fn source_matches_saved(path: &Path, saved: &SavedFile) -> bool {
    match (&saved.bytes, fs::read(path), file_mode(path)) {
        (Some(bytes), Ok(observed), Ok(mode)) => observed == *bytes && saved.mode == Some(mode),
        (None, Err(error), _) if error.kind() == std::io::ErrorKind::NotFound => true,
        _ => false,
    }
}

fn link_matches_saved(path: &Path, saved: &SavedLink) -> bool {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            saved.exists && fs::read_link(path).ok() == saved.target
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => !saved.exists,
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

#[derive(Debug, Clone, Copy)]
enum FileSymlinkMutation {
    Source,
    Link,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum FileSymlinkFault {
    StageSource,
    StageLink,
    BeforeSourcePromotion,
    AfterSourcePromotion,
    BeforeLinkRestage,
    BeforeLinkPromotion,
    AfterLinkPromotion,
    DuringSourceRestoration,
    DuringLinkRestoration,
}

#[cfg(test)]
thread_local! {
    static FILE_SYMLINK_FAULT: std::cell::Cell<u16> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn set_file_symlink_faults(faults: &[FileSymlinkFault]) {
    let mask = faults
        .iter()
        .fold(0u16, |mask, fault| mask | (1 << (*fault as u8)));
    FILE_SYMLINK_FAULT.with(|slot| slot.set(mask));
}

#[cfg(test)]
fn set_file_symlink_fault(fault: Option<FileSymlinkFault>) {
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

fn rollback_file_symlink(
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
                file_symlink_fault(FileSymlinkFault::DuringSourceRestoration)
                    .and_then(|_| restore_file(source, source_before))
            }
            FileSymlinkMutation::Link => {
                file_symlink_fault(FileSymlinkFault::DuringLinkRestoration)
                    .and_then(|_| restore_link(target, link_before))
            }
        };
        if let Err(error) = result {
            first_error.get_or_insert(error);
        }
    }
    first_error
}

fn write_receipt(
    request: &ValidatedFileSymlinkRequest<'_>,
    receipt: TerminalReceipt,
) -> Result<OperationOutcome, String> {
    crate::write_json(
        &request.receipt_dir.join(format!("{}.json", request.name)),
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
        }),
    )?;
    Ok(OperationOutcome {
        ok: receipt.ok,
        changed: receipt.changed,
        skipped: !request.apply,
        message: "validated file symlink".into(),
        command: None,
    })
}

/// Validates desired bytes through a hidden source candidate and a non-hidden sibling
/// link candidate, so Nginx's `sites-enabled/*` include observes the exact candidate.
pub(crate) fn execute(
    request: ValidatedFileSymlinkRequest<'_>,
) -> Result<OperationOutcome, String> {
    let desired = match fs::read(request.desired_source) {
        Ok(value) => value,
        Err(_) => {
            return write_receipt(
                &request,
                TerminalReceipt::refusal("validated-file-symlink-desired-source-missing"),
            )
        }
    };
    let desired_mode = file_mode(request.desired_source)?;
    let source_before = save_file(request.source)?;
    let link_before = match save_link(request.target) {
        Ok(saved) => saved,
        Err(signal) => return write_receipt(&request, TerminalReceipt::refusal(signal)),
    };
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
    fs::create_dir_all(source_parent).map_err(|e| e.to_string())?;
    fs::create_dir_all(target_parent).map_err(|e| e.to_string())?;
    let pid = std::process::id();
    let source_candidate = source_parent.join(format!(
        ".{}.harmonia-source-candidate-{pid}",
        request
            .source
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("source")
    ));
    let link_candidate = target_parent.join(format!(
        "{}.harmonia-link-candidate-{pid}",
        request
            .target
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("link")
    ));
    let clean = || {
        let _ = fs::remove_file(&source_candidate);
        let _ = fs::remove_file(&link_candidate);
    };
    clean();
    if let Err(error) = file_symlink_fault(FileSymlinkFault::StageSource)
        .and_then(|_| atomic_write_bytes(&source_candidate, &desired, Some(desired_mode)))
    {
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
        std::os::unix::fs::symlink(&source_candidate, &link_candidate).map_err(|e| e.to_string())
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
    let validator = crate::tools::command::capture_with_timeout(
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
        if let Err(error) = file_symlink_fault(FileSymlinkFault::BeforeSourcePromotion)
            .and_then(|_| fs::rename(&source_candidate, request.source).map_err(|e| e.to_string()))
        {
            promotion_error = Some(format!(
                "validated-file-symlink-promote-source-failed: {error}"
            ));
        } else {
            mutations.push(FileSymlinkMutation::Source);
            if let Err(error) = file_symlink_fault(FileSymlinkFault::AfterSourcePromotion) {
                promotion_error = Some(format!(
                    "validated-file-symlink-fault-after-source-promotion: {error}"
                ));
            }
        }
    }
    if promotion_error.is_none() && !link_current {
        let _ = fs::remove_file(&link_candidate);
        #[cfg(unix)]
        if let Err(error) = file_symlink_fault(FileSymlinkFault::BeforeLinkRestage).and_then(|_| {
            std::os::unix::fs::symlink(request.source, &link_candidate).map_err(|e| e.to_string())
        }) {
            promotion_error = Some(format!(
                "validated-file-symlink-restage-live-link-failed: {error}"
            ));
        }
        if promotion_error.is_none() {
            if let Err(error) =
                file_symlink_fault(FileSymlinkFault::BeforeLinkPromotion).and_then(|_| {
                    fs::rename(&link_candidate, request.target).map_err(|e| e.to_string())
                })
            {
                promotion_error = Some(format!(
                    "validated-file-symlink-promote-link-failed: {error}"
                ));
            } else {
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
        let refs: Vec<&str> = request.reload_args.iter().map(String::as_str).collect();
        let result =
            crate::tools::command::capture_with_timeout(program, &refs, request.timeout_secs);
        if !result.ok {
            let restoration_error = rollback_file_symlink(
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

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn validated_file_symlink(
    receipt_dir: &Path,
    name: &str,
    desired_source: &Path,
    source: &Path,
    target: &Path,
    validator_program: &str,
    validator_args: &[String],
    reload_program: Option<&str>,
    reload_args: &[String],
    timeout_secs: u64,
    apply: bool,
) -> Result<OperationOutcome, String> {
    execute(ValidatedFileSymlinkRequest {
        receipt_dir,
        name,
        desired_source,
        source,
        target,
        validator_program,
        validator_args,
        reload_program,
        reload_args,
        timeout_secs,
        apply,
    })
}

#[cfg(test)]
mod validated_file_symlink_tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture(name: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("harmonia-vfs-{name}-{}-{id}", std::process::id()));
        let desired = root.join("desired.conf");
        let source = root.join("sites-available/site.conf");
        let target = root.join("sites-enabled/site.conf");
        let old = root.join("old.conf");
        let receipts = root.join("receipts");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&desired, b"new bytes\n").unwrap();
        fs::write(&source, b"old bytes\n").unwrap();
        #[cfg(unix)]
        fs::set_permissions(&desired, fs::Permissions::from_mode(0o640)).unwrap();
        fs::write(&old, b"old target\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&old, &target).unwrap();
        (root, desired, source, target, receipts)
    }

    fn run(
        _root: &Path,
        desired: &Path,
        source: &Path,
        target: &Path,
        receipts: &Path,
        reload: Option<&str>,
    ) -> crate::OperationOutcome {
        validated_file_symlink(
            receipts,
            "step",
            desired,
            source,
            target,
            "/bin/true",
            &[],
            reload,
            &[],
            5,
            true,
        )
        .unwrap()
    }

    #[test]
    fn promotion_preserves_desired_bytes_and_link_target() {
        let (root, desired, source, target, receipts) = fixture("promotion");
        let outcome = run(&root, &desired, &source, &target, &receipts, None);
        assert!(outcome.ok);
        assert_eq!(fs::read(&source).unwrap(), b"new bytes\n");
        assert_eq!(fs::read_link(&target).unwrap(), source);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reconcile_failure_rolls_back_only_promoted_mutations_in_reverse_order() {
        let (root, desired, source, target, receipts) = fixture("reconcile");
        let old_link = fs::read_link(&target).unwrap();
        let outcome = run(
            &root,
            &desired,
            &source,
            &target,
            &receipts,
            Some("/bin/false"),
        );
        assert!(!outcome.ok && !outcome.changed);
        assert_eq!(fs::read(&source).unwrap(), b"old bytes\n");
        assert_eq!(fs::read_link(&target).unwrap(), old_link);
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(receipts.join("step.json")).unwrap()).unwrap();
        assert_eq!(receipt["changed"], false);
        assert_eq!(receipt["restoration"]["ok"], true);
        assert_eq!(receipt["promotion"]["source"], true);
        assert_eq!(receipt["promotion"]["link"], true);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn promotion_boundary_does_not_restore_untouched_live_link() {
        let (root, desired, source, target, receipts) = fixture("promotion-boundary");
        let old_link = fs::read_link(&target).unwrap();
        set_file_symlink_fault(Some(FileSymlinkFault::AfterSourcePromotion));
        let outcome = run(&root, &desired, &source, &target, &receipts, None);
        assert!(!outcome.ok);
        assert_eq!(fs::read(&source).unwrap(), b"old bytes\n");
        assert_eq!(fs::read_link(&target).unwrap(), old_link);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restoration_boundary_reports_failed_restore_without_touching_unmutated_source() {
        let (root, desired, source, target, receipts) = fixture("restoration-boundary");
        set_file_symlink_fault(Some(FileSymlinkFault::DuringLinkRestoration));
        let outcome = run(
            &root,
            &desired,
            &source,
            &target,
            &receipts,
            Some("/bin/false"),
        );
        assert!(!outcome.ok);
        assert!(outcome.changed);
        assert_eq!(fs::read(&source).unwrap(), b"old bytes\n");
        assert_eq!(fs::read_link(&target).unwrap(), source);
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(receipts.join("step.json")).unwrap()).unwrap();
        assert_eq!(receipt["changed"], true);
        assert_eq!(receipt["promotion"]["source"], true);
        assert_eq!(receipt["promotion"]["link"], true);
        assert_eq!(receipt["restoration"]["ok"], false);
        assert!(receipt["first_missing_signal"]
            .as_str()
            .unwrap()
            .contains("DuringLinkRestoration"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_restoration_failure_reports_residual_changed_in_outcome_and_receipt() {
        let (root, desired, source, target, receipts) = fixture("source-restoration-boundary");
        set_file_symlink_faults(&[
            FileSymlinkFault::BeforeLinkRestage,
            FileSymlinkFault::DuringSourceRestoration,
        ]);
        let outcome = run(&root, &desired, &source, &target, &receipts, None);
        assert!(!outcome.ok && outcome.changed);
        assert_eq!(fs::read(&source).unwrap(), b"new bytes\n");
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(receipts.join("step.json")).unwrap()).unwrap();
        assert_eq!(receipt["changed"], true);
        assert_eq!(receipt["restoration"]["ok"], false);
        assert_eq!(receipt["promotion"]["source"], true);
        assert_eq!(receipt["promotion"]["link"], false);
        fs::remove_dir_all(root).unwrap();
    }

    fn assert_candidates_clean(root: &Path) {
        for dir in [root.join("sites-available"), root.join("sites-enabled")] {
            let candidates: Vec<_> = fs::read_dir(dir)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().contains("harmonia-"))
                .collect();
            assert!(candidates.is_empty(), "left candidates: {candidates:?}");
        }
    }

    fn assert_initial_state(source: &Path, target: &Path, old_link: &Path) {
        assert_eq!(fs::read(source).unwrap(), b"old bytes\n");
        assert_eq!(fs::read_link(target).unwrap(), old_link);
    }

    #[test]
    fn every_staging_and_promotion_failure_cleans_candidates_and_restores_exact_state() {
        for fault in [
            FileSymlinkFault::StageSource,
            FileSymlinkFault::StageLink,
            FileSymlinkFault::BeforeSourcePromotion,
            FileSymlinkFault::AfterSourcePromotion,
            FileSymlinkFault::BeforeLinkRestage,
            FileSymlinkFault::BeforeLinkPromotion,
            FileSymlinkFault::AfterLinkPromotion,
        ] {
            let (root, desired, source, target, receipts) = fixture("fault-boundary");
            let old_link = fs::read_link(&target).unwrap();
            set_file_symlink_fault(Some(fault));
            let outcome = run(&root, &desired, &source, &target, &receipts, None);
            assert!(!outcome.ok, "fault={fault:?}");
            assert!(!outcome.changed, "fault={fault:?}");
            assert_initial_state(&source, &target, &old_link);
            assert_candidates_clean(&root);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn malformed_candidate_and_occupied_or_dry_target_preserve_live_state() {
        let (root, desired, source, target, receipts) = fixture("refusal");
        let old_link = fs::read_link(&target).unwrap();
        let malformed = validated_file_symlink(
            &receipts,
            "malformed",
            &desired,
            &source,
            &target,
            "/bin/false",
            &[],
            None,
            &[],
            5,
            true,
        )
        .unwrap();
        assert!(!malformed.ok && !malformed.changed);
        assert_initial_state(&source, &target, &old_link);
        assert_candidates_clean(&root);
        let dry = validated_file_symlink(
            &receipts,
            "dry",
            &desired,
            &source,
            &target,
            "/bin/true",
            &[],
            None,
            &[],
            5,
            false,
        )
        .unwrap();
        assert!(dry.ok && !dry.changed && dry.skipped);
        assert_initial_state(&source, &target, &old_link);
        fs::remove_file(&target).unwrap();
        fs::write(&target, b"occupied").unwrap();
        let occupied = validated_file_symlink(
            &receipts,
            "occupied",
            &desired,
            &source,
            &target,
            "/bin/true",
            &[],
            None,
            &[],
            5,
            true,
        )
        .unwrap();
        assert!(!occupied.ok && !occupied.changed);
        assert_eq!(fs::read(&target).unwrap(), b"occupied");
        assert_eq!(fs::read(&source).unwrap(), b"old bytes\n");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_and_link_drift_combinations_promote_only_the_drifted_surface() {
        let (root, desired, source, target, receipts) = fixture("drift-link");
        fs::write(&source, b"new bytes\n").unwrap();
        let link_only = run(&root, &desired, &source, &target, &receipts, None);
        assert!(link_only.ok && link_only.changed);
        assert_eq!(fs::read_link(&target).unwrap(), source);
        let old = root.join("old-two.conf");
        fs::write(&old, b"old two\n").unwrap();
        fs::write(&source, b"old bytes\n").unwrap();
        fs::remove_file(&target).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&source, &target).unwrap();
        #[cfg(unix)]
        let target_inode_before = fs::symlink_metadata(&target).unwrap().ino();
        let source_only = run(&root, &desired, &source, &target, &receipts, None);
        assert!(source_only.ok && source_only.changed);
        assert_eq!(fs::read(&source).unwrap(), b"new bytes\n");
        assert_eq!(fs::read_link(&target).unwrap(), source);
        #[cfg(unix)]
        assert_eq!(
            fs::symlink_metadata(&target).unwrap().ino(),
            target_inode_before
        );
        assert_candidates_clean(&root);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn validator_receives_exact_args_and_observes_one_nonhidden_candidate() {
        let (root, desired, source, target, receipts) = fixture("validator-candidate");
        let seen = root.join("validator-seen.txt");
        let enabled = target.parent().unwrap();
        let script = format!(
            "candidate=$(find {} -maxdepth 1 -name 'site.conf.harmonia-link-candidate-*'); test \"$1\" = exact-arg && test \"$(printf '%s\\n' \"$candidate\" | wc -l)\" -eq 1 && test -L \"$candidate\" && (case \"$(readlink \"$candidate\")\" in {}/.site.conf.harmonia-source-candidate-*) ;; *) exit 1;; esac) && cmp -s \"$candidate\" \"{}\" && test \"$(stat -Lc %a \"$candidate\")\" = \"$(stat -c %a \"{}\")\" && test \"$(find {} -maxdepth 1 -name '.site.conf.harmonia-link-candidate-*' | wc -l)\" -eq 0 && printf '%s' \"$1\" > {}",
            enabled.display(),
            source.parent().unwrap().display(),
            desired.display(),
            desired.display(),
            enabled.display(),
            seen.display()
        );
        let outcome = validated_file_symlink(
            &receipts,
            "validator",
            &desired,
            &source,
            &target,
            "/bin/sh",
            &["-c".into(), script, "sh".into(), "exact-arg".into()],
            None,
            &[],
            5,
            true,
        )
        .unwrap();
        assert!(outcome.ok && outcome.changed);
        assert_eq!(fs::read_to_string(seen).unwrap(), "exact-arg");
        assert_candidates_clean(&root);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn first_change_reconciles_once_then_exact_second_run_is_a_noop() {
        let (root, desired, source, target, receipts) = fixture("reload-once");
        let reload_count = root.join("reload-count");
        let reload_script = format!("printf x >> {}", reload_count.display());
        let first = validated_file_symlink(
            &receipts,
            "reload",
            &desired,
            &source,
            &target,
            "/bin/true",
            &[],
            Some("/bin/sh"),
            &["-c".into(), reload_script.clone(), "sh".into()],
            5,
            true,
        )
        .unwrap();
        let second = validated_file_symlink(
            &receipts,
            "reload",
            &desired,
            &source,
            &target,
            "/bin/true",
            &[],
            Some("/bin/sh"),
            &["-c".into(), reload_script, "sh".into()],
            5,
            true,
        )
        .unwrap();
        assert!(first.ok && first.changed);
        assert!(second.ok && !second.changed);
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(receipts.join("reload.json")).unwrap()).unwrap();
        assert_eq!(receipt["changed"], false);
        assert_eq!(receipt["validation"]["ran"], false);
        assert!(receipt["reconcile"].is_null());
        assert_eq!(fs::read_to_string(reload_count).unwrap(), "x");
        fs::remove_dir_all(root).unwrap();
    }
}
