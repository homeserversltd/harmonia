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
        "source": fs::symlink_metadata(request.source).ok().map(|m| {
            json!({"kind": if m.file_type().is_file() { "regular-file" } else { "other" }, "mode": file_mode(request.source).ok()})
        }),
        "link_target": fs::read_link(request.target).ok(),
    });
    let desired_state = json!({"source_bytes_present": request.desired_source.exists(), "link_target": request.source});
    let diff_decision = if receipt.changed {
        "different"
    } else {
        "empty"
    };
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
            "observed_state":observed_state,
            "desired_state":desired_state,
            "diff_decision":diff_decision,
            "movement": {"source": receipt.promotion.source, "link": receipt.promotion.link},
            "truthful_changed": receipt.changed,
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
