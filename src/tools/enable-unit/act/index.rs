use crate::atoms;
use crate::CmdResult;
pub(super) fn enable(
    authorization: crate::tools::comparison::ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    unit: &str,
    user: bool,
    target: Option<&str>,
    timeout: u64,
) -> Result<CmdResult, String> {
    let result = atoms::r#do::unit_change_scoped(
        authorization,
        invocation,
        unit,
        atoms::r#do::UnitVerb::EnableNow,
        user,
        target,
        timeout,
    )?;
    Ok(CmdResult {
        ok: result.ok,
        code: result.code.unwrap_or(if result.ok { 0 } else { -1 }),
        stdout: result.stdout,
        stderr: result.stderr,
    })
}
