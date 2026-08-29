use crate::atoms::comparison::ActionAuthorization;
use crate::atoms::r#do::InvocationKey;
use crate::atoms::{Drift, Receipt};
use std::fs;
use std::os::unix::fs::PermissionsExt;
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

    fs::create_dir_all(path).map_err(|error| error.to_string())?;

    if missing.is_empty() {
        missing.push(path.to_path_buf());
    }
    for directory in missing {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755))
            .map_err(|error| error.to_string())?;
    }

    let _ = (authorization, invocation);
    Ok(())
}
