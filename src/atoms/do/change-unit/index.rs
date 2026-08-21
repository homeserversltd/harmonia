use crate::atoms::r#do::InvocationKey;
use crate::atoms::{CommandObservation, Drift, Receipt};
use crate::atoms::comparison::ActionAuthorization;
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
    let result = super::run_command::run(program, &args);
    Ok(Receipt {
            atom: "do".into(),
            ok: result.ok,
            drift: Drift::Current,
            message: format!(
                "program={program}; args={args:?}; code={:?}; stdout={:?}; stderr={:?}",
                result.code, result.stdout, result.stderr
            ),
        }
    )
}
pub(crate) fn unit_change_scoped(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
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
