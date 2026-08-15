use crate::atoms::r#do::{apply, InvocationKey};
use crate::atoms::{CommandObservation, Drift, Receipt};
use crate::tools::comparison::ActionAuthorization;
use std::time::Duration;

pub(crate) enum UnitVerb {
    Start,
    Stop,
    Restart,
    Enable,
    Disable,
    EnableNow,
    DisableNow,
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
        }
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
        .chain(std::iter::once(unit.to_owned()))
        .collect::<Vec<_>>();
    let result = super::run_command::run(program, &args);
    apply(
        authorization,
        invocation,
        Receipt {
            atom: "do".into(),
            ok: result.ok,
            drift: Drift::Current,
            message: format!(
                "program={program}; args={args:?}; code={:?}; stdout={:?}; stderr={:?}",
                result.code, result.stdout, result.stderr
            ),
        },
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
    args.push(unit.to_owned());
    super::run_command::command_with_timeout(
        authorization,
        invocation,
        "/usr/bin/systemctl",
        &args,
        Duration::from_secs(timeout_secs),
    )
}
