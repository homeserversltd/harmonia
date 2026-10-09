use crate::tools::hermes_maintenance::{Observation, ObservationBinding, Request};

pub(crate) fn observe(
    request: &Request,
    binding: &mut Option<ObservationBinding>,
) -> Result<Observation, String> {
    crate::tools::hermes_maintenance::observe(request, binding)
}
