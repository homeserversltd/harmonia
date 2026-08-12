//! Observation-only health organ: there is intentionally no act module.
use crate::CmdResult;
use std::path::Path;

#[path = "observe/index.rs"]
mod observe;
#[path = "report-home/index.rs"]
mod report_home;

pub(crate) fn probe(request: &crate::tools::health::ProbeRequest<'_>) -> CmdResult {
    let result = observe::probe(request);
    let _ = report_home(
        Path::new("/var/lib/harmonia/receipts/check-health.attest.jsonl"),
        &result,
    );
    result
}

pub(crate) fn report_home(log: &Path, result: &CmdResult) -> Result<(), String> {
    report_home::attest(log, result)
}
