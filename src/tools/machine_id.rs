use super::{ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::{write_json, OperationOutcome};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const NAME: &str = "machine-id";
pub const DESCRIPTION: &str = "Machine-id lifecycle primitive for explicit host identity truncation with divergence refusal and receipt proof.";
pub const PERMUTATIONS: &[ToolPermutation] = &[ToolPermutation::new(
    "truncate",
    "truncate /etc/machine-id to zero bytes after proving /var/lib/dbus/machine-id is the canonical symlink",
    &[
        ToolArg::optional("etc_machine_id", ToolArgKind::String),
        ToolArg::optional("dbus_machine_id", ToolArgKind::String),
    ],
)];
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION, PERMUTATIONS);

const DEFAULT_ETC_MACHINE_ID: &str = "/etc/machine-id";
const DEFAULT_DBUS_MACHINE_ID: &str = "/var/lib/dbus/machine-id";

pub(crate) fn truncate(
    receipt_dir: &Path,
    name: &str,
    etc_machine_id: Option<&str>,
    dbus_machine_id: Option<&str>,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let etc_path = PathBuf::from(etc_machine_id.unwrap_or(DEFAULT_ETC_MACHINE_ID));
    let dbus_path = PathBuf::from(dbus_machine_id.unwrap_or(DEFAULT_DBUS_MACHINE_ID));

    if !apply {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: format!(
                "planned machine-id truncation after dbus symlink proof etc={} dbus={}",
                etc_path.display(),
                dbus_path.display()
            ),
            command: None,
        };
        write_receipt(
            receipt_dir,
            name,
            &etc_path,
            &dbus_path,
            &outcome,
            None,
            None,
            "planned",
        )?;
        return Ok(outcome);
    }

    let dbus_meta = match fs::symlink_metadata(&dbus_path) {
        Ok(meta) => meta,
        Err(err) => {
            let outcome = refused(format!(
                "dbus-machine-id-metadata-failed path={} error={err}",
                dbus_path.display()
            ));
            write_receipt(
                receipt_dir,
                name,
                &etc_path,
                &dbus_path,
                &outcome,
                None,
                None,
                "metadata-failed",
            )?;
            return Ok(outcome);
        }
    };

    if !dbus_meta.file_type().is_symlink() {
        let kind = if dbus_meta.file_type().is_file() {
            "regular-file"
        } else if dbus_meta.file_type().is_dir() {
            "directory"
        } else {
            "non-symlink"
        };
        let outcome = refused(format!(
            "dbus-machine-id-divergent path={} kind={} expected_symlink_target={}",
            dbus_path.display(),
            kind,
            etc_path.display()
        ));
        write_receipt(
            receipt_dir,
            name,
            &etc_path,
            &dbus_path,
            &outcome,
            None,
            Some(kind),
            "divergent-dbus-machine-id",
        )?;
        return Ok(outcome);
    }

    let target = fs::read_link(&dbus_path).map_err(|err| {
        format!(
            "dbus-machine-id-readlink-failed path={} error={err}",
            dbus_path.display()
        )
    })?;
    if target != etc_path {
        let outcome = refused(format!(
            "dbus-machine-id-divergent path={} symlink_target={} expected_symlink_target={}",
            dbus_path.display(),
            target.display(),
            etc_path.display()
        ));
        write_receipt(
            receipt_dir,
            name,
            &etc_path,
            &dbus_path,
            &outcome,
            None,
            Some("wrong-symlink-target"),
            "divergent-dbus-machine-id",
        )?;
        return Ok(outcome);
    }

    let before_len = fs::metadata(&etc_path)
        .map_err(|err| {
            format!(
                "machine-id-metadata-failed path={} error={err}",
                etc_path.display()
            )
        })?
        .len();
    let changed = before_len != 0;
    if changed {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&etc_path)
            .map_err(|err| {
                format!(
                    "machine-id-open-failed path={} error={err}",
                    etc_path.display()
                )
            })?;
        file.write_all(&[]).map_err(|err| {
            format!(
                "machine-id-truncate-write-failed path={} error={err}",
                etc_path.display()
            )
        })?;
        file.sync_all().map_err(|err| {
            format!(
                "machine-id-truncate-sync-failed path={} error={err}",
                etc_path.display()
            )
        })?;
    }
    let after_len = fs::metadata(&etc_path)
        .map_err(|err| {
            format!(
                "machine-id-post-metadata-failed path={} error={err}",
                etc_path.display()
            )
        })?
        .len();
    let ok = after_len == 0;
    let outcome = OperationOutcome {
        ok,
        changed: ok && changed,
        skipped: false,
        message: if ok {
            "old machine-id is gone; a new identity is minted at next boot; no reboot performed"
                .to_string()
        } else {
            format!("machine-id-truncate-incomplete after_bytes={after_len}")
        },
        command: None,
    };
    write_receipt(
        receipt_dir,
        name,
        &etc_path,
        &dbus_path,
        &outcome,
        Some((before_len, after_len)),
        None,
        if ok { "closed" } else { "truncate-incomplete" },
    )?;
    Ok(outcome)
}

fn refused(message: String) -> OperationOutcome {
    OperationOutcome {
        ok: false,
        changed: false,
        skipped: false,
        message,
        command: None,
    }
}

fn write_receipt(
    receipt_dir: &Path,
    name: &str,
    etc_path: &Path,
    dbus_path: &Path,
    outcome: &OperationOutcome,
    lengths: Option<(u64, u64)>,
    divergence: Option<&str>,
    first_missing_signal: &str,
) -> Result<(), String> {
    let (before_bytes, after_bytes) = lengths
        .map(|(before, after)| (Some(before), Some(after)))
        .unwrap_or((None, None));
    write_json(
        &receipt_dir.join(format!("{}.json", name)),
        &serde_json::json!({
            "schema": "harmonia.machine_id_truncate_receipt.v1",
            "operation_id": name,
            "tool": NAME,
            "action": "truncate",
            "ok": outcome.ok,
            "changed": outcome.changed,
            "skipped": outcome.skipped,
            "message": outcome.message,
            "etc_machine_id": etc_path,
            "dbus_machine_id": dbus_path,
            "before_bytes": before_bytes,
            "after_bytes": after_bytes,
            "old_machine_id_gone": outcome.ok && !outcome.skipped,
            "new_identity_minted_at_next_boot": outcome.ok && !outcome.skipped,
            "reboot_performed": false,
            "divergence": divergence,
            "first_missing_signal": first_missing_signal,
        }),
    )
}
