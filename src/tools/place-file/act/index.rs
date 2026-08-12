use super::*;
use crate::tools::comparison::ActionAuthorization;

pub(super) struct Movement {
    pub drift: Drift,
}

pub(super) fn place(
    authorization: ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    path: &Path,
    declared_bytes: &[u8],
    _observation: &Observation,
    drift: &Drift,
) -> Result<Movement, String> {
    atoms::r#do::file_write(authorization, invocation, path, declared_bytes)?;
    Ok(Movement {
        drift: drift.clone(),
    })
}
