use super::*;

pub(super) fn receipt(path: &Path, drift: Drift, movement: &PlaceFileMovement) -> Receipt {
    Receipt {
        atom: "place-file".into(),
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
