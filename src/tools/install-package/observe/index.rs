use crate::atoms;
use std::time::Duration;

pub(super) fn pacman(program: &str, timeout_secs: u64) -> atoms::CommandObservation {
    atoms::ask::read_only_command_with_timeout(
        program,
        &["-Q".to_string()],
        Duration::from_secs(timeout_secs),
    )
}
