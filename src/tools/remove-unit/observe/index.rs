use crate::tools::systemd::SystemdObservation;
use std::path::Path;
pub(super) fn unit(
    unit: &str,
    path: Option<&Path>,
    user: bool,
    target: Option<&str>,
    timeout: u64,
) -> SystemdObservation {
    let q = |kind| crate::atoms::ask::systemd_state_query(kind, unit, user, target, timeout);
    let (e, a, l, f, n) = (
        q("is-enabled"),
        q("is-active"),
        q("load-state"),
        q("unit-file-state"),
        q("needs-reload"),
    );
    SystemdObservation {
        enabled: e.code.is_some().then(|| e.stdout.trim().to_owned()),
        active: a.code.is_some().then(|| a.stdout.trim().to_owned()),
        load_state: l.code.is_some().then(|| l.stdout.trim().to_owned()),
        unit_file_state: f.code.is_some().then(|| f.stdout.trim().to_owned()),
        needs_reload: n.code.is_some().then(|| n.stdout.trim().to_owned()),
        unit_present: None,
        unit_file_exists: path
            .is_some_and(|p| crate::atoms::ask::path_kind(p).ok().flatten().is_some()),
        probe: None,
    }
}
