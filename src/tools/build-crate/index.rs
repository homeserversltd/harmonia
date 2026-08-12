#[path = "act/index.rs"]
mod act;
#[path = "observe/index.rs"]
mod observe;
#[path = "report-home/index.rs"]
mod report_home;

use crate::atoms;
use crate::tools::comparison;
use crate::tools::comparison::ActionAuthorization;
use std::path::Path;

pub(crate) fn build(
    auth: ActionAuthorization,
    key: atoms::r#do::InvocationKey,
    cwd: &Path,
    environment: &[(String, String)],
    timeout_secs: u64,
    bearer: &str,
) -> Result<crate::atoms::CommandObservation, String> {
    act::build(auth, key, cwd, environment, timeout_secs, bearer)
}

pub(crate) fn run_build(
    cwd: &Path,
    source_build_sha: &str,
    installed_build_sha: Option<&str>,
    installed_binary: &Path,
    apply: bool,
    environment: &[(String, String)],
    timeout_secs: u64,
    log: &Path,
    bearer: &str,
) -> Result<Option<crate::atoms::CommandObservation>, String> {
    let run = comparison::execute(
        || observe::build_identity(source_build_sha, installed_build_sha, installed_binary),
        |observation| {
            if apply && !observation.identity_matches() {
                comparison::DiffDecision::Different
            } else {
                comparison::DiffDecision::Empty
            }
        },
        |auth, _observation| {
            let key = atoms::r#do::InvocationKey::from_apply_or_timer(apply)
                .ok_or("build-crate-invocation-key-missing")?;
            act::build(auth, key, cwd, environment, timeout_secs, bearer)
        },
    )?;
    match run {
        comparison::ComparisonRun::Moved { observation, movement, .. } => {
            report_home::attest(
                log,
                Some(&movement),
                source_build_sha,
                installed_build_sha,
                observation.installed_binary_present,
                cwd,
                bearer,
                environment,
            )?;
            Ok(Some(movement))
        }
        comparison::ComparisonRun::Current { observation, .. } => {
            report_home::attest(
                log,
                None,
                source_build_sha,
                installed_build_sha,
                observation.installed_binary_present,
                cwd,
                bearer,
                environment,
            )?;
            Ok(None)
        }
    }
}

pub(crate) fn run(
    cwd: &Path,
    source_build_sha: &str,
    installed_build_sha: Option<&str>,
    installed_binary: &Path,
    apply: bool,
    timeout_secs: u64,
    log: &Path,
    bearer: &str,
) -> Result<bool, String> {
    Ok(run_build(
        cwd,
        source_build_sha,
        installed_build_sha,
        installed_binary,
        apply,
        &[],
        timeout_secs,
        log,
        bearer,
    )?
    .is_none_or(|result| result.ok))
}
