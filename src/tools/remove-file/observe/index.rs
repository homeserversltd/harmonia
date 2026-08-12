use super::*;

pub(super) fn file(path: &Path) -> Result<RemovalObservation, String> {
    match atoms::ask::path_kind(path) {
        Ok(Some(atoms::ask::PathKind::RegularFile)) => Ok(RemovalObservation::RegularFile),
        Ok(Some(_)) => Err(format!(
            "files-remove-target-not-regular-file {}",
            path.display()
        )),
        Ok(None) => Ok(RemovalObservation::Absent),
        Err(error) => Err(format!(
            "files-remove-metadata-failed {}: {error}",
            path.display()
        )),
    }
}
