//! Typed AUR installation observation.
use crate::atoms::CommandObservation;

/// Observe the installed package using the bounded, read-only command membrane.
pub(crate) fn installed_version(package: &str) -> Option<String> {
    super::build_aur_pinned::probe::installed_version(package)
}

pub(crate) fn installed_version_command(package: &str) -> CommandObservation {
    let program = crate::atoms::package::pacman_program();
    if !std::path::Path::new(&program).exists() {
        return CommandObservation {
            program,
            args: vec!["-Q".into(), package.into()],
            ok: false,
            code: None,
            stdout: String::new(),
            stderr: "pacman-not-found".into(),
        };
    }
    crate::atoms::ask::read_only_command_with_timeout(
        &program,
        &["-Q".into(), package.into()],
        std::time::Duration::from_secs(30),
    )
}

pub(crate) fn installed_version_from_observation(result: &CommandObservation) -> Option<String> {
    if !result.ok {
        return None;
    }
    let mut fields = result.stdout.split_whitespace();
    let _ = fields.next()?;
    fields.next().map(ToString::to_string)
}
