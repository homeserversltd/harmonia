use std::path::Path;

pub(crate) use crate::atoms::ask::check_health::{proof_battery, ProofBatteryRequest};

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
