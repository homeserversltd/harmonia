use crate::atoms::comparison::ActionAuthorization;
use crate::atoms::r#do::InvocationKey;
use crate::atoms::{CommandObservation, Drift, Receipt};
use std::time::Duration;

pub(crate) enum UnitVerb {
    Start,
    Stop,
    Restart,
    Enable,
    Disable,
    EnableNow,
    DisableNow,
    Mask,
    DaemonReload,
}

impl UnitVerb {
    fn argv(&self) -> &'static [&'static str] {
        match self {
            Self::Start => &["start"],
            Self::Stop => &["stop"],
            Self::Restart => &["restart"],
            Self::Enable => &["enable"],
            Self::Disable => &["disable"],
            Self::EnableNow => &["enable", "--now"],
            Self::DisableNow => &["disable", "--now"],
            Self::Mask => &["mask"],
            Self::DaemonReload => &["daemon-reload"],
        }
    }

    fn targets_unit(&self) -> bool {
        !matches!(self, Self::DaemonReload)
    }
}
pub(crate) fn unit_change(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    unit: &str,
    verb: UnitVerb,
) -> Result<Receipt, String> {
    let program = "/usr/bin/systemctl";
    let args = verb
        .argv()
        .iter()
        .map(|arg| (*arg).to_owned())
        .chain(verb.targets_unit().then(|| unit.to_owned()))
        .collect::<Vec<_>>();
    let result = unit_change_scoped(
        &authorization,
        &invocation,
        unit,
        verb,
        false,
        None,
        30,
    )?;
    Ok(Receipt {
        atom: "do".into(),
        ok: result.ok,
        drift: Drift::Current,
        message: format!(
            "program={program}; args={args:?}; code={:?}; stdout={:?}; stderr={:?}",
            result.code, result.stdout, result.stderr
        ),
    })
}
pub(crate) fn restore_service_state(
    invocation: &InvocationKey,
    state_before: &crate::atoms::ask::change_unit::ServiceStateSnapshot,
) -> Result<(), String> {
    let before = crate::atoms::ask::change_unit::snapshot_service_state(
        &state_before.name,
        state_before.user,
        state_before.target_user.as_deref(),
    )?;
    let needs_enabled = before.enabled != state_before.enabled;
    let needs_active = before.active != state_before.active;
    if !needs_enabled && !needs_active {
        return Ok(());
    }
    let result = crate::atoms::comparison::execute_once(
        "systemd-state-restore",
        || {
            Ok::<_, String>(crate::atoms::ask::change_unit::snapshot_service_state(
                &state_before.name,
                state_before.user,
                state_before.target_user.as_deref(),
            )?)
        },
        |observed| {
            if observed.enabled == state_before.enabled && observed.active == state_before.active {
                crate::atoms::comparison::DiffDecision::Empty
            } else {
                crate::atoms::comparison::DiffDecision::Different
            }
        },
        |authorization, observed| {
            let authorization = &authorization;
            let target_user = state_before.target_user.as_deref();
            if observed.enabled != state_before.enabled {
                let verb = if state_before.enabled {
                    UnitVerb::Enable
                } else {
                    UnitVerb::Disable
                };
                let enabled = unit_change_scoped(
                    authorization,
                    invocation,
                    &state_before.name,
                    verb,
                    state_before.user,
                    target_user,
                    30,
                )?;
                if !enabled.ok {
                    return Err(format!(
                        "systemd-state-restore-enabled-failed-{}",
                        state_before.name
                    ));
                }
                let readback = crate::atoms::ask::change_unit::snapshot_service_state(
                    &state_before.name,
                    state_before.user,
                    target_user,
                )?;
                if readback.enabled != state_before.enabled {
                    return Err(format!(
                        "systemd-state-restore-readback-mismatch-{}-enabled",
                        state_before.name
                    ));
                }
            }
            if observed.active != state_before.active {
                let verb = if state_before.active {
                    UnitVerb::Start
                } else {
                    UnitVerb::Stop
                };
                let active = unit_change_scoped(
                    authorization,
                    invocation,
                    &state_before.name,
                    verb,
                    state_before.user,
                    target_user,
                    30,
                )?;
                if !active.ok {
                    return Err(format!(
                        "systemd-state-restore-active-failed-{}",
                        state_before.name
                    ));
                }
                let readback = crate::atoms::ask::change_unit::snapshot_service_state(
                    &state_before.name,
                    state_before.user,
                    target_user,
                )?;
                if readback.active != state_before.active {
                    return Err(format!(
                        "systemd-state-restore-readback-mismatch-{}-active",
                        state_before.name
                    ));
                }
            }
            Ok(())
        },
    )?;
    let _ = result;
    let final_state = crate::atoms::ask::change_unit::snapshot_service_state(
        &state_before.name,
        state_before.user,
        state_before.target_user.as_deref(),
    )?;
    if final_state.enabled != state_before.enabled || final_state.active != state_before.active {
        return Err(format!(
            "systemd-state-restore-final-mismatch-{}",
            state_before.name
        ));
    }
    Ok(())
}

pub(crate) fn unit_change_scoped(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    unit: &str,
    verb: UnitVerb,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
) -> Result<CommandObservation, String> {
    let mut args = Vec::new();
    if user {
        args.push("--user".into());
        if let Some(target) = target_user.filter(|v| !v.trim().is_empty()) {
            args.push(format!("--machine={target}@.host"));
        }
    }
    args.extend(verb.argv().iter().map(|arg| (*arg).to_owned()));
    if verb.targets_unit() {
        args.push(unit.to_owned());
    }
    super::run_command::command_with_timeout(
        authorization,
        invocation,
        "/usr/bin/systemctl",
        &args,
        Duration::from_secs(timeout_secs),
    )
}
