//! Authorized mutation atom index.
#![allow(dead_code, unused_imports)]
#[path = "enable_unit.rs"]
pub(crate) mod enable_unit;
#[path = "remove_unit.rs"]
pub(crate) mod remove_unit;
#[path = "ratchet_aur.rs"]
pub(crate) mod ratchet_aur;

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
#[path = "compatibility.rs"]
pub(crate) mod compatibility;
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

pub(crate) use compatibility::{
    apply, aur_build_pinned, aur_install, aur_install_pinned, cargo_build, command_with_timeout,
    command_with_timeout_in_dir, command_with_timeout_in_dir_env, create_dir_all, file_write,
    git_acquire, git_pull, mutating_command, package_install, remove_file, rename, symlink,
    unit_change, unit_change_scoped, FileWriteOptions, FileWriteResult, InvocationKey, UnitVerb,
};
