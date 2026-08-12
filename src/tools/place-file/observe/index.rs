use super::*;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

pub(super) fn file(
    path: &Path,
    declared_bytes: &[u8],
    declared_mode: Option<u32>,
    ownership: DeclaredOwnership,
) -> Result<PlaceFileObservation, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(format!(
                "place-file-metadata-failed {}: {error}",
                path.display()
            ))
        }
    };
    let existed = metadata.is_some();
    let regular = metadata
        .as_ref()
        .is_some_and(|metadata| metadata.file_type().is_file());
    let bytes_equal = regular
        && std::fs::read(path)
            .map(|bytes| bytes == declared_bytes)
            .map_err(|error| format!("place-file-read-failed {}: {error}", path.display()))?;
    let mode = if regular {
        crate::tools::files::target_mode(path)?
    } else {
        None
    };
    #[cfg(unix)]
    let (uid, gid) = metadata
        .as_ref()
        .map(|metadata| (Some(metadata.uid()), Some(metadata.gid())))
        .unwrap_or((None, None));
    #[cfg(not(unix))]
    let (uid, gid) = (None, None);
    Ok(PlaceFileObservation {
        existed,
        regular,
        bytes_equal,
        mode,
        mode_equal: regular && declared_mode.map_or(true, |wanted| mode == Some(wanted)),
        uid,
        gid,
        owner_equal: regular && ownership.uid.map_or(true, |wanted| uid == Some(wanted)),
        group_equal: regular && ownership.gid.map_or(true, |wanted| gid == Some(wanted)),
    })
}
