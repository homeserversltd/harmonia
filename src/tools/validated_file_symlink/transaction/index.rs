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
fn replace_source_with_dangling_symlink_during_restoration(path: &Path) -> Result<bool, String> {
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
    fs::remove_file(path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(path.with_extension("residual"), path).map_err(|e| e.to_string())?;
    #[cfg(not(unix))]
    return Err("validated-file-symlink-unsupported".into());
    Ok(true)
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
                #[cfg(test)]
                match replace_source_with_dangling_symlink_during_restoration(source) {
                    Ok(true) => {
                        Err("injected residual dangling source symlink during restoration".into())
                    }
                    Ok(false) => file_symlink_fault(FileSymlinkFault::DuringSourceRestoration)
                        .and_then(|_| restore_file(source, source_before)),
                    Err(error) => Err(error),
                }
                #[cfg(not(test))]
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
