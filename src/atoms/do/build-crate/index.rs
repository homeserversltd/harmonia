use crate::atoms::comparison::{self, ActionAuthorization};
use crate::atoms::r#do::InvocationKey;
use crate::atoms::{CommandObservation, Drift, Receipt};
use std::path::Path;
use std::time::Duration;

pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 3600;

pub(crate) fn cargo_build_args() -> [&'static str; 3] {
    ["build", "--release", "--locked"]
}

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
    let cargo_args = cargo_build_args();
    let result = crate::atoms::command::capture_with_cwd_as_bearer_and_env_and_timeout(
        "cargo",
        &cargo_args,
        cwd.to_str(),
        bearer,
        env,
        timeout.as_secs(),
    );
    let _ = (authorization, invocation);
    Ok(CommandObservation {
        program: "cargo".into(),
        args: cargo_build_args().into_iter().map(str::to_owned).collect(),
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
    use std::os::unix::fs::MetadataExt;
    use crate::atoms::projectio;
    // Cargo's target directory is the build's staging root, not an installed path.
    let staging_root = cwd.join("target");
    let scratch = artifact.starts_with(&staging_root)
        && !artifact.components().any(|part| matches!(part, std::path::Component::ParentDir));
    if !scratch && !artifact.exists() {
        return Err(format!("build-crate-artifact-absent-refused {}", artifact.display()));
    }
    let observation = cargo_build(authorization, invocation, cwd, environment, bearer, timeout)?;
    if observation.ok {
        let artifact_name = artifact
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("artifact");
        let built = cwd.join("target/release").join(artifact_name);
        if built != artifact {
            if scratch {
                projectio::act_scratch_make_dir(authorization, artifact.parent().ok_or("build-crate-staged-artifact-parent-missing")?)
                    .map_err(|error| format!("build-crate-staged-artifact-parent-create-failed: {error}"))?;
                if artifact.exists() {
                    projectio::act_scratch_remove(authorization, artifact)
                        .map_err(|error| format!("build-crate-staged-artifact-copy-failed: {error}"))?;
                }
            }
            let copied = if scratch {
                projectio::act_scratch_copy(authorization, &built, artifact, None)
            } else {
                projectio::act_copy(authorization, &built, artifact, None, None, None)
            };
            copied.map_err(|error| {
                format!(
                    "build-crate-staged-artifact-copy-failed {} -> {}: {error}",
                    built.display(),
                    artifact.display()
                )
            })?;
        }
        let owner = std::fs::metadata(artifact).map_err(|e| format!("build-crate-artifact-metadata-failed: {e}"))?;
        let stamp = artifact.with_file_name(format!("{artifact_name}.source-build-sha"));
        let environment_stamp =
            artifact.with_file_name(format!("{artifact_name}.build-environment-sha"));
        for (path, value, signal) in [
            (&stamp, source_build_sha, "build-crate-source-head-stamp-write-failed"),
            (&environment_stamp, environment_sha, "build-crate-environment-stamp-write-failed"),
        ] {
            let bytes = format!("{value}\n");
            if scratch {
                match projectio::act_scratch_remove(authorization, path) {
                    Ok(()) => (),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                    Err(error) => return Err(format!("{signal}: {error}")),
                }
                projectio::act_scratch_write_new(authorization, path, bytes.as_bytes(), 0o644)
                    .map_err(|error| format!("{signal}: {error}"))?;
            } else {
                projectio::act_put(authorization, path, bytes.as_bytes(), Some(0o644), Some(owner.uid()), Some(owner.gid()))
                    .map_err(|error| format!("{signal}: {error}"))?;
            }
        }
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

#[cfg(test)]
mod tests {
    #[test]
    fn cargo_build_is_locked_and_release_only() {
        assert_eq!(super::cargo_build_args(), ["build", "--release", "--locked"]);
    }
}
