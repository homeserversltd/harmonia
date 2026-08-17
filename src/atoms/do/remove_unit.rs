//! Legacy disable-stop-remove delegation organ.
use crate::atoms;
use crate::CmdResult;
use std::path::Path;
pub(crate) fn observe(
    unit: &str,
    unit_path: Option<&Path>,
    user: bool,
    target: Option<&str>,
    timeout: u64,
) -> crate::atoms::systemd::SystemdObservation {
    probe::unit(unit, unit_path, user, target, timeout)
}
pub(crate) fn act(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    unit: &str,
    action: &str,
    unit_path: Option<&Path>,
    user: bool,
    target: Option<&str>,
    timeout: u64,
) -> Result<CmdResult, String> {
    mutation::remove(
        authorization,
        invocation,
        unit,
        action,
        unit_path,
        user,
        target,
        timeout,
    )
}
pub(crate) fn report_home(unit: &str, log: &Path, result: &CmdResult) -> Result<(), String> {
    receipt::attest(unit, log, result)
}

mod probe {
    use crate::atoms::systemd::SystemdObservation;
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
}

mod mutation {
    use crate::atoms;
    use crate::CmdResult;
    use std::path::Path;
    pub(super) fn remove(
        authorization: crate::atoms::comparison::ActionAuthorization,
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
}

mod receipt {
    use crate::{atoms, CmdResult};
    pub(super) fn attest(
        unit: &str,
        log: &std::path::Path,
        result: &CmdResult,
    ) -> Result<(), String> {
        atoms::attest::attest(
            log,
            &atoms::Receipt {
                atom: "remove-unit".into(),
                ok: result.ok,
                drift: atoms::Drift::Current,
                message: format!(
                    "unit={unit}; code={}; stdout={}; stderr={}",
                    result.code, result.stdout, result.stderr
                ),
            },
            &[],
        )
    }
}
