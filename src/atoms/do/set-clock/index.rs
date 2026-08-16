//! Typed adapter for household clock convergence.
use crate::{atoms, CmdResult, OperationOutcome};
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

use crate::tools::comparison::ActionAuthorization;
    use std::time::Duration;

    pub(crate) fn apply(
        authorization: ActionAuthorization,
        invocation: atoms::r#do::InvocationKey,
        request: &crate::set_clock::Request<'_>,
        timezone: Option<&str>,
    ) -> Result<CmdResult, String> {
        if request.operation == "resolve" {
            return command(authorization, invocation, request, "resolve", None);
        }
        let timezone = timezone.ok_or_else(|| "set-clock-timezone-missing".to_string())?;
        let set = command(
            authorization,
            invocation,
            request,
            "set-timezone",
            Some(timezone),
        )?;
        if !set.ok {
            return Ok(set);
        }
        let sync = command(authorization, invocation, request, "ensure-ntp", None)?;
        if sync.ok {
            Ok(set)
        } else {
            Ok(sync)
        }
    }

    fn command(
        authorization: ActionAuthorization,
        invocation: atoms::r#do::InvocationKey,
        request: &crate::set_clock::Request<'_>,
        operation: &str,
        timezone: Option<&str>,
    ) -> Result<CmdResult, String> {
        let (program, args) = match request.backend {
            "caduceus" => {
                let mut args = vec!["time".into(), operation.into()];
                if let Some(zone) = timezone {
                    args.push(zone.into());
                }
                (
                    std::env::var("HARMONIA_CLOCK_CADUCEUS")
                        .unwrap_or_else(|_| "/usr/local/bin/caduceus".into()),
                    args,
                )
            }
            "staff" => {
                let mut args = vec![
                    "PYTHONPATH=/usr/local/sbin:/usr/local/lib/harmonia-household-time".into(),
                ];
                if let Some(path) = request.state_path {
                    args.push(format!("CADUCEUS_HOUSEHOLD_TIME_STATE_PATH={path}"));
                }
                args.extend([
                    "/usr/bin/python3".into(),
                    "-m".into(),
                    "agathodaimon.household_time".into(),
                    operation.into(),
                ]);
                if let Some(zone) = timezone {
                    args.push(zone.into());
                }
                ("/usr/bin/env".into(), args)
            }
            _ => {
                return Ok(CmdResult {
                    ok: false,
                    code: -1,
                    stdout: String::new(),
                    stderr: "household-time-backend-invalid".into(),
                })
            }
        };
        let result = atoms::r#do::command_with_timeout(
            authorization,
            invocation,
            &program,
            &args,
            Duration::from_secs(request.timeout_secs),
        )?;
        Ok(CmdResult {
            ok: result.ok,
            code: result.code.unwrap_or(-1),
            stdout: result.stdout,
            stderr: result.stderr,
        })
    }
