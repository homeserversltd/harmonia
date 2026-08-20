use crate::atoms::comparison::{self, ActionAuthorization};
use crate::atoms::r#do::{apply, InvocationKey};
use crate::atoms::{CommandObservation, Drift, Receipt};
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
    let result = crate::atoms::command::capture_with_cwd_as_bearer_and_env(
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

pub(crate) fn cargo_build_and_stamp(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
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

pub(crate) fn bench_build_guard(
    root: &Path,
    source_build_sha: &str,
) -> Result<serde_json::Value, String> {
    use std::cell::Cell;
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let artifact = root.join("target/release/caduceus");
    std::fs::create_dir_all(artifact.parent().unwrap()).map_err(|e| e.to_string())?;
    let action_count = Cell::new(0_u32);
    let run_once = |action_count: &Cell<u32>| -> Result<bool, String> {
        let run = crate::atoms::declaration::execute(
            "build-crate",
            "bench-build-crate",
            || crate::atoms::ask::build_crate::build_identity(source_build_sha, None, &artifact),
            |observation| {
                if observation.identity_matches() {
                    comparison::DiffDecision::Empty
                } else {
                    comparison::DiffDecision::Different
                }
            },
            |_, _| {
                action_count.set(action_count.get() + 1);
                std::fs::write(&artifact, format!("bench artifact {source_build_sha}\n"))
                    .map_err(|e| e.to_string())
            },
        )?;
        Ok(matches!(run, comparison::ComparisonRun::Moved { .. }))
    };
    let changed1 = run_once(&action_count)?;
    let ops1 = action_count.get();
    let changed2 = run_once(&action_count)?;
    let ops2 = action_count.get() - ops1;
    if !changed1 || changed2 || ops1 != 1 || ops2 != 0 {
        return Err("build-guard-bench-failed".into());
    }
    Ok(
        serde_json::json!({"run1":{"changed":changed1,"action_count":ops1},"run2":{"changed":changed2,"operations":ops2},"artifact":artifact,"environment":{"CADUCEUS_BUILD_SHA":source_build_sha}}),
    )
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
