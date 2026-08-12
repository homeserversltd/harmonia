use super::*;

pub(super) fn receipt(path: &Path, drift: Drift, movement: &BackfillFileMovement) -> Receipt {
    Receipt {
        atom: "backfill-file".into(),
        ok: true,
        drift,
        message: format!(
            "path={}; bytes={}; mode={}; owner={}; created={}; backed_up={}",
            path.display(),
            movement.bytes,
            movement.mode,
            movement.owner,
            movement.created,
            movement
                .backed_up
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default()
        ),
    }
}

pub(super) fn hotfix_receipt(path: &Path, changed: bool) -> HotfixFileBackfillOutcome {
    HotfixFileBackfillOutcome {
        ok: true,
        changed,
        target_path: path.to_path_buf(),
        movement: "atomic-file-backfill".into(),
    }
}
