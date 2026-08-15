//! Typed adapter for household clock convergence.
use crate::{CmdResult, OperationOutcome};
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub backend: String,
    pub operation: String,
    pub timezone: Option<String>,
    pub state_url: Option<String>,
    pub state_path: Option<String>,
    pub timeout_secs: u64,
}
pub(crate) fn run(
    p: &Plan,
    apply: bool,
    i: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let r = crate::set_clock::run(
        &crate::set_clock::Request {
            backend: &p.backend,
            operation: &p.operation,
            timezone: p.timezone.as_deref(),
            state_url: p.state_url.as_deref(),
            state_path: p.state_path.as_deref(),
            timeout_secs: p.timeout_secs,
        },
        apply,
        i,
    )?;
    Ok(OperationOutcome {
        ok: r.ok,
        changed: apply && r.ok,
        skipped: !apply,
        message: format!("set-clock {}", p.operation),
        command: Some(r),
    })
}
