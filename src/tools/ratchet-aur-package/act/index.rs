use super::{Observation, Verdict};
use crate::atoms;
use crate::tools::comparison::ActionAuthorization;
use crate::OperationOutcome;
use std::path::Path;

#[allow(clippy::too_many_arguments)]
pub(super) fn build_pinned(
    authorization: ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
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
    observation: &Observation,
) -> Result<OperationOutcome, String> {
    if observation.verdict != Verdict::BehindPin {
        return Err("ratchet-aur-package-act-without-behind-pin".into());
    }
    atoms::r#do::aur_build_pinned(authorization, invocation, || {
        crate::tools::aur::build_pinned_action(
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
        )
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn install(
    authorization: ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    receipt_dir: &Path,
    receipt_name: &str,
    package: &str,
    timeout_secs: u64,
    apply: bool,
) -> Result<OperationOutcome, String> {
    atoms::r#do::aur_install(authorization, invocation, || {
        crate::tools::aur::install_action(receipt_dir, receipt_name, package, timeout_secs, apply)
    })
}
