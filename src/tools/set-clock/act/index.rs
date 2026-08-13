use crate::atoms;
use crate::tools::comparison::ActionAuthorization;
use crate::CmdResult;
use std::time::Duration;

pub(super) fn apply(
    authorization: ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    request: &super::Request<'_>,
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
    request: &super::Request<'_>,
    operation: &str,
    timezone: Option<&str>,
) -> Result<CmdResult, String> {
    let (program, args) = match request.backend {
        "caduceus" => {
            let mut args = vec!["time".into(), operation.into()];
            if let Some(zone) = timezone {
                args.push(zone.into());
            }
            ("/usr/local/bin/caduceus", args)
        }
        "staff" => {
            let mut args =
                vec!["PYTHONPATH=/usr/local/sbin:/usr/local/lib/harmonia-household-time".into()];
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
            ("/usr/bin/env", args)
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
        program,
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
