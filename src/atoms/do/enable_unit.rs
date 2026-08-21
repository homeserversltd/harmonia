//! Enable-now delegation organ.
use crate::atoms;
use crate::CmdResult;

pub(crate) fn observe(
    unit: &str,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
) -> crate::atoms::systemd::SystemdObservation {
    probe::unit(unit, user, target_user, timeout_secs)
}
pub(crate) fn act(
    authorization: crate::atoms::comparison::ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    unit: &str,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
) -> Result<CmdResult, String> {
    mutation::enable(
        authorization,
        invocation,
        unit,
        user,
        target_user,
        timeout_secs,
    )
}
pub(crate) fn report_home(
    unit: &str,
    log: &std::path::Path,
    result: &CmdResult,
) -> Result<(), String> {
    receipt::attest(unit, log, result)
}

mod probe {
    use crate::atoms::systemd::SystemdObservation;
    pub(super) fn unit(
        unit: &str,
        user: bool,
        target: Option<&str>,
        timeout: u64,
    ) -> SystemdObservation {
        let enabled =
            crate::atoms::ask::systemd_state_query("is-enabled", unit, user, target, timeout);
        let active =
            crate::atoms::ask::systemd_state_query("is-active", unit, user, target, timeout);
        let load =
            crate::atoms::ask::systemd_state_query("load-state", unit, user, target, timeout);
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
}

mod mutation {
    use crate::atoms;
    use crate::CmdResult;
    pub(super) fn enable(
        authorization: crate::atoms::comparison::ActionAuthorization,
        invocation: atoms::r#do::InvocationKey,
        unit: &str,
        user: bool,
        target: Option<&str>,
        timeout: u64,
    ) -> Result<CmdResult, String> {
        let result = atoms::r#do::change_unit::unit_change_scoped(
            authorization,
            invocation,
            unit,
            atoms::r#do::change_unit::UnitVerb::EnableNow,
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
                atom: "enable-unit".into(),
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
