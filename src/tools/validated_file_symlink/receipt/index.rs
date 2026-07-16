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
