//! Shared compatibility membrane for legacy mutation atom signatures.
use super::{
    build_aur_pinned, build_crate, change_unit, install_aur, install_aur_pinned, install_package,
    make_dir, make_link, pull_repo, remove_file as remove_file_organ, rename as rename_organ,
    run_command, write_file,
};
use crate::atoms::Receipt;
use crate::atoms::comparison::ActionAuthorization;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvocationKey(());

impl InvocationKey {
    pub(crate) fn for_apply() -> Self {
        Self(())
    }

    pub(crate) fn from_apply_or_timer(
        v: bool,
        _mint: crate::invocation_face::Mint,
    ) -> Option<Self> {
        v.then_some(Self(()))
    }
}

pub(crate) fn apply(
    _a: ActionAuthorization,
    _i: InvocationKey,
    r: Receipt,
) -> Result<Receipt, String> {
    Ok(r)
}

pub(crate) use write_file::{FileWriteOptions, FileWriteResult};

pub(crate) fn file_write(
    a: ActionAuthorization,
    i: InvocationKey,
    p: &Path,
    b: &[u8],
    o: FileWriteOptions<'_>,
) -> Result<FileWriteResult, String> {
    write_file::file_write(a, i, p, b, o)
}

pub(crate) fn create_dir_all(
    a: ActionAuthorization,
    i: InvocationKey,
    p: &Path,
) -> Result<(), String> {
    make_dir::create_dir_all(a, i, p)
}

pub(crate) fn remove_file(
    a: ActionAuthorization,
    i: InvocationKey,
    p: &Path,
) -> Result<(), String> {
    remove_file_organ::remove_file(a, i, p)
}

pub(crate) fn rename(
    a: ActionAuthorization,
    i: InvocationKey,
    f: &Path,
    t: &Path,
) -> Result<(), String> {
    rename_organ::rename(a, i, f, t)
}

pub(crate) fn symlink(
    a: ActionAuthorization,
    i: InvocationKey,
    t: &Path,
    l: &Path,
) -> Result<(), String> {
    make_link::symlink(a, i, t, l)
}

pub(crate) fn cargo_build(
    a: ActionAuthorization,
    i: InvocationKey,
    c: &Path,
    e: &[(String, String)],
    b: &str,
    t: Duration,
) -> Result<crate::atoms::CommandObservation, String> {
    build_crate::cargo_build(a, i, c, e, b, t)
}

pub(crate) fn command_with_timeout_in_dir(
    a: ActionAuthorization,
    i: InvocationKey,
    p: &str,
    x: &[String],
    c: Option<&Path>,
    t: Duration,
) -> Result<crate::atoms::CommandObservation, String> {
    run_command::command_with_timeout_in_dir(a, i, p, x, c, t)
}

pub(crate) fn command_with_timeout_in_dir_env(
    a: ActionAuthorization,
    i: InvocationKey,
    p: &str,
    x: &[String],
    c: Option<&Path>,
    e: &[(String, String)],
    t: Duration,
) -> Result<crate::atoms::CommandObservation, String> {
    run_command::command_with_timeout_in_dir_env(a, i, p, x, c, e, t)
}

pub(crate) fn command_with_timeout(
    a: ActionAuthorization,
    i: InvocationKey,
    p: &str,
    x: &[String],
    t: Duration,
) -> Result<crate::atoms::CommandObservation, String> {
    run_command::command_with_timeout(a, i, p, x, t)
}

pub(crate) fn aur_install(
    a: ActionAuthorization,
    i: InvocationKey,
    c: impl FnOnce() -> Result<crate::OperationOutcome, String>,
) -> Result<crate::OperationOutcome, String> {
    install_aur::aur_install(a, i, c)
}

pub(crate) fn aur_install_pinned(
    a: ActionAuthorization,
    i: InvocationKey,
    c: impl FnOnce() -> Result<crate::OperationOutcome, String>,
) -> Result<crate::OperationOutcome, String> {
    install_aur_pinned::aur_install_pinned(a, i, c)
}

pub(crate) fn aur_build_pinned(
    a: ActionAuthorization,
    i: InvocationKey,
    c: impl FnOnce() -> Result<crate::OperationOutcome, String>,
) -> Result<crate::OperationOutcome, String> {
    build_aur_pinned::aur_build_pinned(a, i, c)
}

pub(crate) fn git_pull(
    a: ActionAuthorization,
    i: InvocationKey,
    r: &crate::atoms::git_artifact::Request,
    c: impl FnOnce() -> crate::atoms::git_artifact::Outcome,
) -> crate::atoms::git_artifact::Outcome {
    super::pull_repo::git_pull(a, i, r, c)
}

pub(crate) fn git_acquire(
    a: ActionAuthorization,
    i: InvocationKey,
    p: &crate::atoms::git_artifact::SourcePlan,
    c: impl FnOnce() -> crate::atoms::git_artifact::SourceOutcome,
) -> crate::atoms::git_artifact::SourceOutcome {
    super::pull_repo::git_acquire(a, i, p, c)
}

pub(crate) fn package_install(
    a: ActionAuthorization,
    i: InvocationKey,
    d: &Path,
    p: &[String],
    q: Option<&str>,
    z: &[String],
    s: u64,
) -> Result<crate::atoms::CommandObservation, String> {
    install_package::package_install(a, i, d, p, q, z, s)
}

pub(crate) fn mutating_command(
    a: ActionAuthorization,
    i: InvocationKey,
    p: &str,
    x: &[String],
) -> Result<Receipt, String> {
    run_command::mutating_command(a, i, p, x)
}

pub(crate) use change_unit::UnitVerb;

pub(crate) fn unit_change(
    a: ActionAuthorization,
    i: InvocationKey,
    u: &str,
    v: UnitVerb,
) -> Result<Receipt, String> {
    change_unit::unit_change(a, i, u, v)
}

pub(crate) fn unit_change_scoped(
    a: ActionAuthorization,
    i: InvocationKey,
    u: &str,
    v: UnitVerb,
    b: bool,
    t: Option<&str>,
    s: u64,
) -> Result<crate::atoms::CommandObservation, String> {
    change_unit::unit_change_scoped(a, i, u, v, b, t, s)
}
