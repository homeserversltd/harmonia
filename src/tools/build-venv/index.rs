//! Python virtual-environment convergence organ.
use crate::atoms;
use crate::tools::comparison::{self, DiffDecision};
use crate::OperationOutcome;
use std::path::{Path, PathBuf};
#[path = "act/index.rs"]
mod act;
#[path = "observe/index.rs"]
mod observe;
#[path = "report-home/index.rs"]
mod report_home;
pub(crate) struct Request<'a> {
    pub venv: &'a Path,
    pub source_root: &'a Path,
    pub source_patterns: &'a [String],
    pub python: &'a Path,
    pub receipt_dir: &'a Path,
    pub receipt_name: &'a str,
    pub timeout_secs: u64,
}
pub(crate) fn run(
    request: &Request<'_>,
    apply: bool,
    invocation: Option<atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let run = crate::tools::declaration::execute(
        "build-venv",
        "build-venv",
        || observe::venv(request),
        |o| {
            if apply && o.different() {
                DiffDecision::Different
            } else {
                DiffDecision::Empty
            }
        },
        |authorization, observation| {
            let invocation =
                invocation.ok_or_else(|| "build-venv-invocation-key-missing".to_string())?;
            act::converge(authorization, invocation, request, observation)
        },
    )?;
    let (observation, movement) = match run {
        comparison::ComparisonRun::Current { observation, .. } => (observation, "none"),
        comparison::ComparisonRun::Moved {
            observation,
            movement,
            ..
        } => (observation, movement),
    };
    let changed = apply && movement != "none";
    report_home::receipt(request, &observation, apply, changed, movement)?;
    Ok(OperationOutcome {
        ok: true,
        changed,
        skipped: !apply,
        message: format!("venv converge {movement}"),
        command: None,
    })
}
pub(super) fn state_path(venv: &Path) -> PathBuf {
    venv.join(".harmonia-sbin-dependency-sha256")
}

pub fn declaration() -> Result<Option<&'static crate::tools::declaration::Declaration>, String> {
    crate::tools::declaration::get("build-venv")
}
