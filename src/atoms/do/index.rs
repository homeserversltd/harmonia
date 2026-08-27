//! Authorized mutation atom index.
#![allow(dead_code, unused_imports)]
#[path = "enable_unit.rs"]
pub(crate) mod enable_unit;
#[path = "remove_unit.rs"]
pub(crate) mod remove_unit;
#[path = "aur_package.rs"]
pub(crate) mod aur_package;

#[path = "backfill_file.rs"]
pub(crate) mod backfill_file;
#[path = "make_symlink.rs"]
pub(crate) mod make_symlink;
#[path = "place_file.rs"]
pub(crate) mod place_file;
#[path = "remove_file_organ.rs"]
pub(crate) mod remove_file_organ;
#[path = "build-aur-pinned/index.rs"]
pub(crate) mod build_aur_pinned;
#[path = "build-crate/index.rs"]
pub(crate) mod build_crate;
#[path = "build-venv/index.rs"]
pub(crate) mod build_venv;
#[path = "change-mode/index.rs"]
pub(crate) mod change_mode;
#[path = "change-owner/index.rs"]
pub(crate) mod change_owner;
#[path = "change-unit/index.rs"]
pub(crate) mod change_unit;
#[path = "convergence-lock.rs"]
pub(crate) mod convergence_lock;
#[path = "copy-file/index.rs"]
pub(crate) mod copy_file;
#[path = "install-aur/index.rs"]
pub(crate) mod install_aur;
#[path = "install-aur-pinned/index.rs"]
pub(crate) mod install_aur_pinned;
#[path = "install-package/index.rs"]
pub(crate) mod install_package;
#[path = "make-dir/index.rs"]
pub(crate) mod make_dir;
#[path = "make-link/index.rs"]
pub(crate) mod make_link;
#[path = "pull-repo/index.rs"]
pub(crate) mod pull_repo;
#[path = "remove-dir/index.rs"]
pub(crate) mod remove_dir;
#[path = "remove-file/index.rs"]
pub(crate) mod remove_file;
#[path = "rename/index.rs"]
pub(crate) mod rename;
#[path = "replace-process/index.rs"]
pub(crate) mod replace_process;
#[path = "ritual.rs"]
pub(crate) mod ritual;
#[path = "run-command/index.rs"]
pub(crate) mod run_command;
#[path = "set-clock/index.rs"]
pub(crate) mod set_clock;
#[path = "transaction.rs"]
pub(crate) mod transaction;
#[path = "write-file/index.rs"]
pub(crate) mod write_file;
#[path = "source-shelf.rs"]
pub(crate) mod source_shelf;

#[derive(Debug)]
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

#[path = "symlink-converge.rs"]
pub(crate) mod symlink_converge;
