use crate::tools::comparison::{self, DiffDecision};
use crate::{OperationOutcome, Profile};
use std::path::Path;

#[path = "act/index.rs"]
mod act;
#[path = "observe/index.rs"]
mod observe;
#[path = "report-home/index.rs"]
mod report_home;

pub(crate) use observe::{ArtifactLockObservation, Observation, Verdict};

pub(crate) fn check(
    package: &str,
    lock_path: &Path,
    upstream_state: Option<&str>,
) -> Result<Observation, String> {
    observe::ratchet(package, lock_path, upstream_state, true)
}

pub(crate) fn install(
    receipt_dir: &Path,
    receipt_name: &str,
    package: &str,
    timeout_secs: u64,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<comparison::ComparisonRun<Option<String>, OperationOutcome>, String> {
    crate::tools::declaration::execute(
        "ratchet-aur-package",
        "ratchet-aur-package",
        || Ok(observe::installed_version(package)),
        |installed| {
            if apply && installed.is_none() {
                DiffDecision::Different
            } else {
                DiffDecision::Empty
            }
        },
        |authorization, _| {
            let invocation = invocation
                .ok_or_else(|| "ratchet-aur-package-install-invocation-key-missing".to_string())?;
            act::install(
                authorization,
                invocation,
                receipt_dir,
                receipt_name,
                package,
                timeout_secs,
                apply,
            )
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_pinned(
    receipt_dir: &Path,
    receipt_name: &str,
    package: &str,
    lock_path: &Path,
    build_root: &Path,
    source_dir: Option<&str>,
    builder_user: Option<&str>,
    timeout_secs: u64,
    install: bool,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<comparison::ComparisonRun<Observation, OperationOutcome>, String> {
    crate::tools::declaration::execute(
        "ratchet-aur-package",
        "ratchet-aur-package",
        || observe::ratchet(package, lock_path, None, install),
        |observation| {
            if apply && observation.verdict == Verdict::BehindPin {
                DiffDecision::Different
            } else {
                DiffDecision::Empty
            }
        },
        |authorization, observation| {
            let invocation = invocation
                .ok_or_else(|| "ratchet-aur-package-build-invocation-key-missing".to_string())?;
            act::build_pinned(
                authorization,
                invocation,
                receipt_dir,
                receipt_name,
                package,
                lock_path,
                build_root,
                source_dir,
                builder_user,
                timeout_secs,
                install,
                apply,
                observation,
            )
        },
    )
}

pub(crate) fn report(
    log: &Path,
    verdict: Verdict,
    outcome: &OperationOutcome,
) -> Result<(), String> {
    report_home::attest(log, verdict, outcome)
}

pub(crate) fn verify_artifact_lock(
    lock_path: &Path,
    profile: Option<&str>,
    receipt_dir: &Path,
) -> Result<OperationOutcome, String> {
    let observation = observe::artifact_lock(lock_path, profile, receipt_dir, false)?;
    let outcome = OperationOutcome {
        ok: observation.ok,
        changed: false,
        skipped: false,
        message: format!("{} artifacts verified", observation.artifact_count),
        command: None,
    };
    report_home::attest_artifact_lock(
        &receipt_dir.join("artifact-lock.attest.jsonl"),
        &observation,
    )?;
    Ok(outcome)
}

pub(crate) fn pinned_artifacts_command(
    action: &str,
    profile: &Profile,
    lock_path: &Path,
    receipt_dir: &Path,
    args: &[String],
) -> Result<(), String> {
    std::fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    match action {
        "check" => observe::pinned_artifacts_check(profile, lock_path, receipt_dir),
        "nudge" => act::pinned_artifacts_nudge(profile, lock_path, receipt_dir, args),
        "bless" => act::pinned_artifacts_bless(profile, lock_path, receipt_dir, args),
        other => Err(format!("unsupported pinned-artifacts action {other}")),
    }
}

pub fn declaration() -> Result<Option<&'static crate::tools::declaration::Declaration>, String> {
    crate::tools::declaration::get("ratchet-aur-package")
}
