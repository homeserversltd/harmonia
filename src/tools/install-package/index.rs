use crate::tools::comparison::{self, DiffDecision};
use crate::{atoms, CmdResult, OperationOutcome};
use std::path::Path;

#[path = "act/index.rs"]
mod act;
#[path = "observe/index.rs"]
mod observe;
#[path = "report-home/index.rs"]
mod report_home;

pub(crate) fn run(
    receipt_dir: &Path,
    name: &str,
    packages: &[String],
    apply: bool,
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
    timeout_secs: u64,
    program: &str,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    if !crate::tools::package::pacman_available(program) {
        return crate::tools::package::non_arch_install(receipt_dir, name, packages);
    }
    let current = observe::pacman(program, timeout_secs);
    let differs = packages.iter().any(|package| {
        !current
            .stdout
            .lines()
            .any(|line| line.split_whitespace().next() == Some(package))
    });
    let observation = crate::tools::package::PackageObservation {
        observed_state: if current.ok {
            current.stdout.clone()
        } else {
            format!("probe-failed:{:?}", current.code)
        },
        desired_state: format!("packages-present:{}", packages.join(",")),
        current: Some(CmdResult {
            ok: current.ok,
            code: current.code.unwrap_or(-1),
            stdout: current.stdout.clone(),
            stderr: current.stderr.clone(),
        }),
    };
    let run = comparison::execute(
        || Ok::<_, String>(observation.clone()),
        |_| {
            if differs {
                DiffDecision::Different
            } else {
                DiffDecision::Empty
            }
        },
        |authorization, _| {
            if apply {
                let invocation = invocation
                    .ok_or_else(|| "package-install-invocation-key-missing".to_string())?;
                let result = act::install(
                    authorization,
                    invocation,
                    receipt_dir,
                    packages,
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
                    message: "package install".into(),
                    command: Some(cmd),
                })
            } else {
                crate::tools::package::reclaim_pacman_database_lock(receipt_dir, program, false)?;
                Ok(OperationOutcome {
                    ok: true,
                    changed: false,
                    skipped: false,
                    message: "package install".into(),
                    command: observation.current.clone(),
                })
            }
        },
    )?;
    let (decision, movement) = match run {
        comparison::ComparisonRun::Current { decision, .. } => (decision, None),
        comparison::ComparisonRun::Moved {
            decision, movement, ..
        } => (decision, Some(movement)),
    };
    let outcome = movement.clone().unwrap_or(OperationOutcome {
        ok: true,
        changed: false,
        skipped: true,
        message: "package install already current".into(),
        command: observation.current.clone(),
    });
    crate::write_json(
        &receipt_dir.join(format!("{name}.comparison.json")),
        &crate::tools::package::package_receipt_fields(
            &observation,
            decision,
            movement.as_ref(),
            outcome.changed,
        ),
    )?;
    crate::tools::package::write_package_receipt(receipt_dir, name, "install", &outcome)?;
    report_home::attest(
        &receipt_dir.join(format!("{name}.attest.jsonl")),
        &outcome.message,
        outcome.ok,
    )?;
    Ok(outcome)
}
