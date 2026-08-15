//! Typed adapter for the established build-venv deed.
use crate::OperationOutcome;
use std::path::PathBuf;
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub venv: PathBuf,
    pub source_root: PathBuf,
    pub source_patterns: Vec<String>,
    pub python: PathBuf,
    pub receipt_dir: PathBuf,
    pub receipt_name: String,
    pub timeout_secs: u64,
}
pub(crate) fn run(
    p: &Plan,
    apply: bool,
    i: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    crate::build_venv::run(
        &crate::build_venv::Request {
            venv: &p.venv,
            source_root: &p.source_root,
            source_patterns: &p.source_patterns,
            python: &p.python,
            receipt_dir: &p.receipt_dir,
            receipt_name: &p.receipt_name,
            timeout_secs: p.timeout_secs,
        },
        apply,
        i,
    )
}
