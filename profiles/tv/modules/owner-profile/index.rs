#[path = "../tv-runtime-support.rs"]
mod tv_runtime_support;

use crate::*;
use std::path::Path;
use tv_runtime_support::TvModuleSpec;

pub(crate) const ID: &str = "owner-profile";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    tv_runtime_support::validate(module)
}

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<ModuleExecution, String> {
    tv_runtime_support::execute(
        module,
        receipt_dir,
        apply,
        TvModuleSpec {
            phase: 1,
            schema: "harmonia.tv.owner_profile.v1",
            meaning: "owner account, sudo posture, shell, and TV operator groups are maintained",
        },
    )
}
