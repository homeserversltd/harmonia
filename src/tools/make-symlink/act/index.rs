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
    authorization: crate::tools::comparison::ActionAuthorization,
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
    authorization: crate::tools::comparison::ActionAuthorization,
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
) -> Result<OperationOutcome, String> {
    let run = crate::tools::comparison::execute(
        || observe_symlink(&request),
        |observation| {
            if observation.desired.as_slice()
                == observation.source.bytes.as_deref().unwrap_or_default()
                && observation.link.target.as_deref() == Some(request.source)
                && observation.desired_mode == observation.source.mode.unwrap_or_default()
            {
                crate::tools::comparison::DiffDecision::Empty
            } else {
                crate::tools::comparison::DiffDecision::Different
            }
        },
        |authorization, observation| {
            let Some(invocation) = atoms::r#do::InvocationKey::from_apply_or_timer(request.apply)
            else {
                return write_receipt(&request, TerminalReceipt::no_change(true));
            };
            execute_action(authorization, invocation, request, observation)
        },
    )?;
    match run {
        crate::tools::comparison::ComparisonRun::Current { .. } => {
            write_receipt(&request, TerminalReceipt::no_change(true))
        }
        crate::tools::comparison::ComparisonRun::Moved {
            observation,
            movement,
            ..
        } => {
            let SymlinkObservation {
                desired,
                desired_mode,
                source: source_before,
                link: link_before,
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
    authorization: crate::tools::comparison::ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    request: ValidatedFileSymlinkRequest<'_>,
    observation: &SymlinkObservation,
) -> Result<OperationOutcome, String> {
    let desired = &observation.desired;
    let desired_mode = observation.desired_mode;
    let source_before = observation.source.clone();
    let link_before = observation.link.clone();
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
        if atoms::ask::path_kind(&source_candidate)
            .ok()
            .flatten()
            .is_some()
        {
            let _ = atoms::r#do::remove_file(authorization, invocation, &source_candidate);
        }
        if atoms::ask::path_kind(&link_candidate)
            .ok()
            .flatten()
            .is_some()
        {
            let _ = atoms::r#do::remove_file(authorization, invocation, &link_candidate);
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
        .map(|_| ())
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
        if let Err(error) =
            file_symlink_fault(FileSymlinkFault::BeforeSourcePromotion).and_then(|_| {
                atoms::r#do::rename(authorization, invocation, &source_candidate, request.source)
            })
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
        if atoms::ask::path_kind(&link_candidate)
            .ok()
            .flatten()
            .is_some()
        {
            let _ = atoms::r#do::remove_file(authorization, invocation, &link_candidate);
        }
        #[cfg(unix)]
        if let Err(error) = file_symlink_fault(FileSymlinkFault::BeforeLinkRestage).and_then(|_| {
            atoms::r#do::symlink(authorization, invocation, request.source, &link_candidate)
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
