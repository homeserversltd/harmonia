use crate::atoms::r#do::InvocationKey;
use crate::atoms::CommandObservation;
use crate::tools::comparison::ActionAuthorization;
use std::path::Path;

pub(crate) fn package_install(
    _authorization: ActionAuthorization,
    _invocation: InvocationKey,
    receipt_dir: &Path,
    packages: &[String],
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
    timeout_secs: u64,
) -> Result<CommandObservation, String> {
    let result = crate::tools::package::pacman_mutate_packages_with_options(
        receipt_dir,
        false,
        packages,
        conflict_policy,
        conflict_paths,
        timeout_secs,
    )?;
    Ok(CommandObservation {
        program: crate::tools::package::pacman_program(),
        args: vec!["-S".into(), "--noconfirm".into(), "--needed".into()],
        ok: result.ok,
        code: Some(result.code),
        stdout: result.stdout,
        stderr: result.stderr,
    })
}
