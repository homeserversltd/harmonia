use std::path::Path;

pub(crate) use crate::atoms::ask::check_health::{proof_battery, ProofBatteryRequest};
pub(crate) use crate::atoms::health::ProbeRequest;

pub(crate) fn probe(request: &crate::tools::health::ProbeRequest<'_>) -> crate::CmdResult {
    let result = crate::atoms::ask::check_health::probe(request);
    let _ = crate::atoms::attest::check_health::attest(
        Path::new("/var/lib/harmonia/receipts/check-health.attest.jsonl"),
        &result,
    );
    result
}

pub fn declaration() -> Result<Option<&'static crate::tools::declaration::Declaration>, String> {
    crate::tools::declaration::get("check-health")
}

pub(crate) fn curl_probe(request: &ProbeRequest<'_>) -> crate::CmdResult {
    crate::atoms::health::curl_probe(request)
}

pub(crate) fn execute_validated_step(
    step: &crate::tools::ladder::ValidatedStep,
    module_dir: &std::path::Path,
    apply: bool,
) -> Result<crate::OperationOutcome, String> {
    crate::atoms::health::execute_validated_step(step, module_dir, apply)
}
