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
    crate::write_json(
        &receipt,
        &json!({
            "schema": "harmonia.files.remove.v1", "ok": outcome.ok, "apply": apply,
            "target_root": target_root, "checked": outcome.checked, "removed": outcome.removed,
            "changed": outcome.changed, "entries": outcome.entries,
            "first_missing_signal": if outcome.ok { "none" } else { outcome.message.as_str() },
        }),
    )?;
    atoms::attest::attest(
        &receipt_dir.join("harmonia-atoms.log"),
        &Receipt {
            atom: "remove-file".into(),
            ok: outcome.ok,
            drift: Drift::Current,
            message: outcome.message.clone(),
        },
        &[],
    )
}
