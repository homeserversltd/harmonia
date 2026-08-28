use crate::atoms::comparison::{self, ActionAuthorization};
use crate::atoms::r#do::InvocationKey;
use crate::atoms::{CommandObservation, Drift, Receipt};
use std::path::Path;
use std::time::Duration;

pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 3600;

pub(crate) fn cargo_build(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    cwd: &Path,
    environment: &[(String, String)],
    bearer: &str,
    timeout: Duration,
) -> Result<CommandObservation, String> {
    let env = environment
        .iter()
        .cloned()
        .collect::<std::collections::BTreeMap<_, _>>();
    let result = crate::atoms::command::capture_with_cwd_as_bearer_and_env_and_timeout(
        "cargo",
        &["build", "--release"],
        cwd.to_str(),
        bearer,
        env,
        timeout.as_secs(),
    );
    let _ = (authorization, invocation);
    Ok(CommandObservation {
        program: "cargo".into(),
        args: vec!["build".into(), "--release".into()],
        ok: result.ok,
        code: Some(result.code),
        stdout: result.stdout,
        stderr: result.stderr,
    })
}

pub(crate) fn cargo_build_and_stamp(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    cwd: &Path,
    environment: &[(String, String)],
    bearer: &str,
    timeout: Duration,
    artifact: &Path,
    source_build_sha: &str,
    environment_sha: &str,
) -> Result<CommandObservation, String> {
    let observation = cargo_build(authorization, invocation, cwd, environment, bearer, timeout)?;
    if observation.ok {
        let artifact_name = artifact
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("artifact");
        let built = cwd.join("target/release").join(artifact_name);
        if built != artifact {
            std::fs::create_dir_all(
                artifact
                    .parent()
                    .ok_or("build-crate-staged-artifact-parent-missing")?,
            )
            .map_err(|error| {
                format!("build-crate-staged-artifact-parent-create-failed: {error}")
            })?;
            std::fs::copy(&built, artifact).map_err(|error| {
                format!(
                    "build-crate-staged-artifact-copy-failed {} -> {}: {error}",
                    built.display(),
                    artifact.display()
                )
            })?;
        }
        let stamp = artifact.with_file_name(format!("{artifact_name}.source-build-sha"));
        std::fs::write(stamp, format!("{source_build_sha}\n"))
            .map_err(|error| format!("build-crate-source-head-stamp-write-failed: {error}"))?;
        let environment_stamp =
            artifact.with_file_name(format!("{artifact_name}.build-environment-sha"));
        std::fs::write(environment_stamp, format!("{environment_sha}\n"))
            .map_err(|error| format!("build-crate-environment-stamp-write-failed: {error}"))?;
    }
    Ok(observation)
}

pub(crate) fn failure(
    log: &Path,
    artifact: &Path,
    source_build_sha: &str,
    before: &crate::atoms::ask::build_crate::Observation,
    after: &crate::atoms::ask::build_crate::Observation,
    movement_ok: bool,
) -> Result<(), String> {
    crate::write_json(
        &log.with_file_name("service-runtime-build-failure.json"),
        &serde_json::json!({"signal":"service-runtime-act-did-not-converge","artifact":artifact,"source_build_sha":source_build_sha,"before":before.artifact_build_sha,"after":after.artifact_build_sha,"movement_ok":movement_ok}),
    )
}
