use crate::atoms::r#do::{apply, InvocationKey};
use crate::atoms::{CommandObservation, Drift, Receipt};
use crate::tools::comparison::ActionAuthorization;
use std::path::Path;
use std::time::Duration;

pub(crate) fn cargo_build(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    cwd: &Path,
    environment: &[(String, String)],
    bearer: &str,
    _timeout: Duration,
) -> Result<CommandObservation, String> {
    let env = environment
        .iter()
        .cloned()
        .collect::<std::collections::BTreeMap<_, _>>();
    let result = crate::tools::command::capture_with_cwd_as_bearer_and_env(
        "cargo",
        &["build", "--release"],
        cwd.to_str(),
        bearer,
        env,
    );
    apply(
        authorization,
        invocation,
        Receipt {
            atom: "do".into(),
            ok: result.ok,
            drift: Drift::Current,
            message: format!("cargo build code={}", result.code),
        },
    )?;
    Ok(CommandObservation {
        program: "cargo".into(),
        args: vec!["build".into(), "--release".into()],
        ok: result.ok,
        code: Some(result.code),
        stdout: result.stdout,
        stderr: result.stderr,
    })
}
