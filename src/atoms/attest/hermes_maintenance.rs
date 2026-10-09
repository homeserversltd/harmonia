use crate::tools::hermes_maintenance::{Movement, Observation, Request};

pub(crate) fn receipt(
    request: &Request,
    observation: &Observation,
    apply: bool,
    movement: Option<&Movement>,
) -> Result<(), String> {
    crate::tools::hermes_maintenance::receipt(request, observation, apply, movement)
}

pub(crate) fn failure(
    request: &Request,
    observation: Option<&Observation>,
    apply: bool,
    stage: &str,
    error: &str,
) -> Result<(), String> {
    crate::tools::hermes_maintenance::failure(request, observation, apply, stage, error)
}
