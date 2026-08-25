use crate::atoms::r#do::InvocationKey;
use crate::atoms::{Drift, Receipt};
use crate::atoms::comparison::ActionAuthorization;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub(crate) struct RemovePolicy {
    pub no_follow: bool,
    pub collision_refuse: bool,
    pub rollback_exact: bool,
}

pub(crate) fn remove_file_with_policy(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    path: &Path,
    policy: RemovePolicy,
) -> Result<(), String> {
    if !policy.no_follow || !policy.collision_refuse || !policy.rollback_exact {
        return Err("remove-file-policy-unsupported".into());
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() {
        return Err("remove-file-collision-refused".into());
    }
    fs::remove_file(path).map_err(|error| error.to_string())?;
    let _ = (authorization, invocation);
    Ok(())
}

pub(crate) fn remove_file(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    path: &Path,
) -> Result<(), String> {
    remove_file_with_policy(
        authorization,
        invocation,
        path,
        RemovePolicy {
            no_follow: true,
            collision_refuse: true,
            rollback_exact: true,
        },
    )
}
