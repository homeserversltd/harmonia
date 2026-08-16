use crate::atoms;
use crate::tools::comparison::ActionAuthorization;
pub(super) fn converge(
    authorization: ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    request: &super::Request<'_>,
    observation: &super::observe::Observation,
) -> Result<&'static str, String> {
    atoms::r#do::build_venv::converge(authorization, invocation, request, observation)
}
