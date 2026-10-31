use crate::tools::hermes_maintenance::{Observation, ObservationBinding, Request};

pub(crate) fn observe(
    request: &Request,
    binding: &mut Option<ObservationBinding>,
    skipped: &mut Vec<String>,
) -> Result<Observation, String> {
    crate::tools::hermes_maintenance::observe(request, binding, skipped)
}
