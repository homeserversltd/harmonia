pub(crate) use crate::atoms::ask::build_crate::IdentityMode;

use crate::atoms;
use crate::tools::comparison;
use crate::tools::comparison::ActionAuthorization;
use std::path::Path;

pub(crate) fn build(
    auth: &ActionAuthorization,
    key: &atoms::r#do::InvocationKey,
    cwd: &Path,
    environment: &[(String, String)],
    timeout_secs: u64,
    bearer: &str,
) -> Result<crate::atoms::CommandObservation, String> {
    crate::atoms::r#do::build_crate::cargo_build(
        auth,
        key,
        cwd,
        environment,
        bearer,
        std::time::Duration::from_secs(timeout_secs),
    )
}

pub(crate) fn cargo_build(
    auth: &ActionAuthorization,
    key: &atoms::r#do::InvocationKey,
    cwd: &Path,
    environment: &[(String, String)],
    bearer: &str,
    timeout: std::time::Duration,
) -> Result<crate::atoms::CommandObservation, String> {
    crate::atoms::r#do::build_crate::cargo_build(auth, key, cwd, environment, bearer, timeout)
}

pub(crate) fn run_build(
    cwd: &Path,
    source_build_sha: &str,
    installed_build_sha: Option<&str>,
    installed_binary: &Path,
    artifact: &Path,
    apply: bool,
    environment: &[(String, String)],
    timeout_secs: u64,
    log: &Path,
    bearer: &str,
    invocation: Option<&atoms::r#do::InvocationKey>,
) -> Result<Option<crate::atoms::CommandObservation>, String> {
    run_build_with_mode(
        cwd,
        source_build_sha,
        installed_build_sha,
        installed_binary,
        artifact,
        apply,
        environment,
        timeout_secs,
        log,
        bearer,
        invocation,
        IdentityMode::EmbeddedSourceSha,
    )
}

pub(crate) fn run_build_with_mode(
    cwd: &Path,
    source_build_sha: &str,
    installed_build_sha: Option<&str>,
    installed_binary: &Path,
    artifact: &Path,
    apply: bool,
    environment: &[(String, String)],
    timeout_secs: u64,
    log: &Path,
    bearer: &str,
    invocation: Option<&atoms::r#do::InvocationKey>,
    identity_mode: IdentityMode,
) -> Result<Option<crate::atoms::CommandObservation>, String> {
    let run = crate::tools::declaration::execute_with_failure_receipt(
        "build-crate",
        "build-crate",
        || {
            crate::atoms::ask::build_crate::build_identity_with_environment(
                source_build_sha,
                installed_build_sha,
                artifact,
                identity_mode,
                environment,
            )
        },
        |observation| {
            if apply && !observation.identity_matches() {
                comparison::DiffDecision::Different
            } else {
                comparison::DiffDecision::Empty
            }
        },
        |auth, _observation| {
            let key = invocation.ok_or("build-crate-invocation-key-missing")?;
            if identity_mode == IdentityMode::RegularExecutable {
                crate::atoms::r#do::build_crate::cargo_build_and_stamp(
                    &auth,
                    key,
                    cwd,
                    environment,
                    bearer,
                    std::time::Duration::from_secs(timeout_secs),
                    artifact,
                    source_build_sha,
                    &crate::atoms::ask::build_crate::environment_sha(environment),
                )
            } else {
                crate::atoms::r#do::build_crate::cargo_build(
                    &auth,
                    key,
                    cwd,
                    environment,
                    bearer,
                    std::time::Duration::from_secs(timeout_secs),
                )
            }
        },
        |before, movement, after| {
            crate::atoms::attest::build_crate::attest(
                log,
                Some(movement),
                source_build_sha,
                installed_build_sha,
                after.artifact_present,
                cwd,
                bearer,
                environment,
            )?;
            crate::atoms::r#do::build_crate::failure(
                log,
                artifact,
                source_build_sha,
                before,
                after,
                movement.ok,
            )
        },
    )?;
    match run {
        comparison::ComparisonRun::Moved {
            observation,
            movement,
            ..
        } => {
            crate::atoms::attest::build_crate::attest(
                log,
                Some(&movement),
                source_build_sha,
                installed_build_sha,
                observation.artifact_present,
                cwd,
                bearer,
                environment,
            )?;
            Ok(Some(movement))
        }
        comparison::ComparisonRun::Current { observation, .. } => {
            crate::atoms::attest::build_crate::attest(
                log,
                None,
                source_build_sha,
                installed_build_sha,
                observation.artifact_present,
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
        installed_binary,
        apply,
        &[],
        timeout_secs,
        log,
        bearer,
        None,
    )?
    .is_none_or(|result| result.ok))
}

pub fn declaration() -> Result<Option<&'static crate::tools::declaration::Declaration>, String> {
    crate::tools::declaration::get("build-crate")
}
