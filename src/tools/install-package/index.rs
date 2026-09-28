use crate::tools::comparison::{self, DiffDecision};
use crate::{CmdResult, OperationOutcome};
use std::path::Path;

pub(crate) fn run(
    receipt_dir: &Path,
    name: &str,
    packages: &[String],
    apply: bool,
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
    timeout_secs: u64,
    program: &str,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    run_with_ignores(
        receipt_dir,
        name,
        packages,
        apply,
        conflict_policy,
        conflict_paths,
        timeout_secs,
        program,
        invocation,
        &[],
    )
}

pub(crate) fn run_with_ignores(
    receipt_dir: &Path,
    name: &str,
    packages: &[String],
    apply: bool,
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
    timeout_secs: u64,
    program: &str,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
    ignored: &[String],
) -> Result<OperationOutcome, String> {
    let observe_package = || {
        let current = crate::atoms::ask::install_package::pacman(program, timeout_secs);
        Ok::<_, String>(crate::tools::package::PackageObservation {
            observed_state: if current.ok {
                current.stdout.clone()
            } else {
                format!("probe-failed:{:?}", current.code)
            },
            desired_state: format!("packages-present:{}", packages.join(",")),
            current: Some(CmdResult {
                ok: current.ok,
                code: current.code.unwrap_or(-1),
                stdout: current.stdout,
                stderr: current.stderr,
            }),
        })
    };
    let observation = observe_package()?;
    let run = crate::tools::declaration::execute_with_failure_receipt(
        "install-package",
        "update-installed-packages",
        observe_package,
        |current| {
            if packages.iter().any(|package| {
                !current.current.as_ref().is_some_and(|result| {
                    result
                        .stdout
                        .lines()
                        .any(|line| line.split_whitespace().next() == Some(package))
                })
            }) {
                DiffDecision::Different
            } else {
                DiffDecision::Empty
            }
        },
        |authorization, current| {
            let Some(result) = current.current.as_ref() else {
                return Ok(OperationOutcome {
                    ok: false,
                    changed: false,
                    skipped: false,
                    message: "first_missing_signal=package-observation-unavailable".into(),
                    command: None,
                });
            };
            if !result.ok {
                return Ok(OperationOutcome {
                    ok: false,
                    changed: false,
                    skipped: false,
                    message: format!(
                        "first_missing_signal=package-observation-failed code={} stderr={}",
                        result.code, result.stderr
                    ),
                    command: Some(result.clone()),
                });
            }
            if apply {
                let invocation = invocation
                    .ok_or_else(|| "package-install-invocation-key-missing".to_string())?;
                let result = crate::atoms::r#do::install_package::package_install_with_ignores(
                    &authorization,
                    invocation,
                    receipt_dir,
                    packages,
                    ignored,
                    conflict_policy,
                    conflict_paths,
                    timeout_secs,
                )?;
                let cmd = CmdResult {
                    ok: result.ok,
                    code: result.code.unwrap_or(-1),
                    stdout: result.stdout,
                    stderr: result.stderr,
                };
                Ok(OperationOutcome {
                    ok: cmd.ok,
                    changed: cmd.ok
                        && crate::tools::package::pacman_stdout_indicates_change(&cmd.stdout),
                    skipped: false,
                    message: "update installed packages".into(),
                    command: Some(cmd),
                })
            } else {
                Ok(OperationOutcome {
                    ok: true,
                    changed: false,
                    skipped: false,
                    message: "update installed packages".into(),
                    command: observation.current.clone(),
                })
            }
        },
        |before, movement, after| {
            crate::atoms::attest::install_package::write_guard_receipt(
                receipt_dir,
                name,
                before,
                movement,
                after,
            )
        },
    )?;
    let final_observation = run.observation().clone();
    let (decision, movement) = match run {
        comparison::ComparisonRun::Current { decision, .. } => (decision, None),
        comparison::ComparisonRun::Moved {
            decision, movement, ..
        } => (decision, Some(movement)),
    };
    let mut outcome = movement.clone().unwrap_or(OperationOutcome {
        ok: true,
        changed: false,
        skipped: true,
        message: "installed packages already current".into(),
        command: observation.current.clone(),
    });
    let missing = packages.iter().find(|spec| {
        let package = spec.split_once('=').map_or(spec.as_str(), |(name, _)| name);
        final_observation.current.as_ref().is_some_and(|current| {
            current.ok
                && !current
                    .stdout
                    .lines()
                    .any(|line| line.split_whitespace().next() == Some(package))
        })
    });
    if let Some(package) = missing {
        outcome.ok = false;
        outcome.message = format!("first_missing_signal=package-absent:{package}");
    }
    crate::atoms::attest::install_package::write_receipts(
        receipt_dir,
        name,
        &final_observation,
        decision,
        movement.as_ref(),
        &outcome,
    )?;
    Ok(outcome)
}

pub fn declaration() -> Result<Option<&'static crate::tools::declaration::Declaration>, String> {
    crate::tools::declaration::get("install-package")
}
