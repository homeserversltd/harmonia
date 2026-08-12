use crate::tools::systemd::SystemdObservation;
pub(super) fn unit(
    unit: &str,
    user: bool,
    target: Option<&str>,
    timeout: u64,
) -> SystemdObservation {
    let enabled = crate::atoms::ask::systemd_state_query("is-enabled", unit, user, target, timeout);
    let active = crate::atoms::ask::systemd_state_query("is-active", unit, user, target, timeout);
    let load = crate::atoms::ask::systemd_state_query("load-state", unit, user, target, timeout);
    let file =
        crate::atoms::ask::systemd_state_query("unit-file-state", unit, user, target, timeout);
    let reload =
        crate::atoms::ask::systemd_state_query("needs-reload", unit, user, target, timeout);
    SystemdObservation {
        enabled: enabled
            .code
            .is_some()
            .then(|| enabled.stdout.trim().to_owned()),
        active: active
            .code
            .is_some()
            .then(|| active.stdout.trim().to_owned()),
        load_state: load.code.is_some().then(|| load.stdout.trim().to_owned()),
        unit_file_state: file.code.is_some().then(|| file.stdout.trim().to_owned()),
        needs_reload: reload
            .code
            .is_some()
            .then(|| reload.stdout.trim().to_owned()),
        unit_present: None,
        unit_file_exists: false,
        probe: None,
    }
}
