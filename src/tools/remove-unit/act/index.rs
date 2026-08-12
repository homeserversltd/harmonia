use crate::atoms;
use crate::CmdResult;
use std::path::Path;
pub(super) fn remove(
    authorization: crate::tools::comparison::ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    unit: &str,
    action: &str,
    path: Option<&Path>,
    user: bool,
    target: Option<&str>,
    timeout: u64,
) -> Result<CmdResult, String> {
    let result = atoms::r#do::unit_change_scoped(
        authorization,
        invocation,
        unit,
        atoms::r#do::UnitVerb::DisableNow,
        user,
        target,
        timeout,
    )?;
    let mut stdout = result.stdout;
    let mut stderr = result.stderr;
    let mut ok = result.ok;
    let mut code = result.code.unwrap_or(if ok { 0 } else { -1 });
    if ok && action == "disable-stop-remove" && path.is_some() {
        if let Err(error) = atoms::r#do::remove_file(authorization, invocation, path.unwrap()) {
            ok = false;
            code = -1;
            stderr = format!(
                "{}{}systemd-unit-remove-failed {}: {error}",
                stderr,
                if stderr.is_empty() { "" } else { "\n" },
                path.unwrap().display()
            );
        } else {
            if !stdout.is_empty() {
                stdout.push('\n');
            }
            stdout.push_str(&format!("removed unit file: {}", path.unwrap().display()));
        }
    }
    Ok(CmdResult {
        ok,
        code,
        stdout,
        stderr,
    })
}
