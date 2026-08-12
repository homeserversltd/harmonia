//! Legacy enable-now delegation organ.
use crate::atoms;
use crate::CmdResult;

#[path = "act/index.rs"]
mod act;
#[path = "observe/index.rs"]
mod observe;
#[path = "report-home/index.rs"]
mod report_home;

pub(crate) fn observe(
    unit: &str,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
) -> crate::tools::systemd::SystemdObservation {
    observe::unit(unit, user, target_user, timeout_secs)
}
pub(crate) fn act(
    authorization: crate::tools::comparison::ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    unit: &str,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
) -> Result<CmdResult, String> {
    act::enable(
        authorization,
        invocation,
        unit,
        user,
        target_user,
        timeout_secs,
    )
}
pub(crate) fn report_home(
    unit: &str,
    log: &std::path::Path,
    result: &CmdResult,
) -> Result<(), String> {
    report_home::attest(unit, log, result)
}
