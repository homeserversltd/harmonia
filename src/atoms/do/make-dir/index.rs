use crate::atoms::comparison::ActionAuthorization;
use crate::atoms::r#do::InvocationKey;
use crate::atoms::{Drift, Receipt};
use std::fs;

use std::path::{Path, PathBuf};

pub(crate) fn create_dir_all(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    path: &Path,
) -> Result<(), String> {
    let mut missing = Vec::new();
    let mut candidate = PathBuf::from(path);
    while !candidate.as_os_str().is_empty() && !candidate.exists() {
        missing.push(candidate.clone());
        if !candidate.pop() {
            break;
        }
    }

    crate::atoms::projectio::act_make_dir(authorization, path).map_err(|error| error.to_string())?;

    if missing.is_empty() {
        if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Ok(());
        }
        missing.push(path.to_path_buf());
    }
    for directory in missing {
        crate::atoms::projectio::act_mode(authorization, &directory, 0o755)
            .map_err(|error| error.to_string())?;
    }

    let _ = (authorization, invocation);
    Ok(())
}
