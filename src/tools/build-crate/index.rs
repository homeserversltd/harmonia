#[path = "act/index.rs"]
mod act;
#[path = "observe/index.rs"]
mod observe;
pub(crate) use observe::IdentityMode;
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
    artifact: &Path,
    apply: bool,
    environment: &[(String, String)],
    timeout_secs: u64,
    log: &Path,
    bearer: &str,
    invocation: Option<atoms::r#do::InvocationKey>,
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
    invocation: Option<atoms::r#do::InvocationKey>,
    identity_mode: IdentityMode,
) -> Result<Option<crate::atoms::CommandObservation>, String> {
    let run = comparison::execute_with_failure_receipt(
        "build-crate",
        || {
            observe::build_identity_with_mode(
                source_build_sha,
                installed_build_sha,
                artifact,
                identity_mode,
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
            act::build(auth, key, cwd, environment, timeout_secs, bearer)
        },
        |before, movement, after| {
            report_home::attest(
                log,
                Some(movement),
                source_build_sha,
                installed_build_sha,
                after.artifact_present,
                cwd,
                bearer,
                environment,
            )?;
            std::fs::write(
                log.with_file_name("service-runtime-build-failure.json"),
                serde_json::json!({
                    "signal": "service-runtime-act-did-not-converge",
                    "artifact": artifact,
                    "source_build_sha": source_build_sha,
                    "before": before.artifact_build_sha,
                    "after": after.artifact_build_sha,
                    "movement_ok": movement.ok,
                })
                .to_string(),
            )
            .map_err(|error| error.to_string())
        },
    )?;
    match run {
        comparison::ComparisonRun::Moved {
            observation,
            movement,
            ..
        } => {
            report_home::attest(
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
            report_home::attest(
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
        let run = comparison::execute(
            "bench-build-crate",
            || observe::build_identity(source_build_sha, None, &artifact),
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
