use crate::atoms::comparison::ActionAuthorization;
use crate::atoms::r#do::InvocationKey;
use crate::tools::hermes_maintenance::{Movement, Observation, Request};
use crate::SoftwareApplyAuthorization;

pub(crate) fn converge(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    software: &SoftwareApplyAuthorization,
    request: &Request,
    observation: &Observation,
) -> Result<Movement, String> {
    crate::tools::hermes_maintenance::apply(
        authorization,
        invocation,
        software,
        request,
        observation,
    )
}
