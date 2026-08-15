//! Typed adapter for pinned AUR installation.
use crate::OperationOutcome;
use std::path::PathBuf;
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub receipt_dir: PathBuf,
    pub receipt_name: String,
    pub package: String,
    pub lock_path: PathBuf,
    pub build_root: PathBuf,
    pub source_dir: Option<String>,
    pub builder_user: Option<String>,
    pub timeout_secs: u64,
    pub install: bool,
}
pub(crate) fn run(
    p: &Plan,
    apply: bool,
    i: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    crate::tools::aur::build_pinned(
        &p.receipt_dir,
        &p.receipt_name,
        &p.package,
        &p.lock_path,
        &p.build_root,
        p.source_dir.as_deref(),
        p.builder_user.as_deref(),
        p.timeout_secs,
        p.install,
        apply,
        i,
    )
}
