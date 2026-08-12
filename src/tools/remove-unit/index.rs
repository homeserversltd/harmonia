//! Legacy disable-stop-remove delegation organ.
use crate::atoms;
use crate::CmdResult;
use std::path::Path;
#[path = "act/index.rs"]
mod act;
#[path = "observe/index.rs"]
mod observe;
#[path = "report-home/index.rs"]
mod report_home;
pub(crate) fn observe(
    unit: &str,
    unit_path: Option<&Path>,
    user: bool,
    target: Option<&str>,
    timeout: u64,
) -> crate::tools::systemd::SystemdObservation {
    observe::unit(unit, unit_path, user, target, timeout)
}
pub(crate) fn act(
    authorization: crate::tools::comparison::ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    unit: &str,
    action: &str,
    unit_path: Option<&Path>,
    user: bool,
    target: Option<&str>,
    timeout: u64,
) -> Result<CmdResult, String> {
    act::remove(
        authorization,
        invocation,
        unit,
        action,
        unit_path,
        user,
        target,
        timeout,
    )
}
pub(crate) fn report_home(unit: &str, log: &Path, result: &CmdResult) -> Result<(), String> {
    report_home::attest(unit, log, result)
}
