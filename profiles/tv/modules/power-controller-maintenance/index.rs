#[path = "../tv-runtime-support.rs"]
mod tv_runtime_support;

use crate::*;
use std::path::Path;
use tv_runtime_support::TvModuleSpec;

pub(crate) const ID: &str = "power-controller-maintenance";

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
            phase: 9,
            schema: "harmonia.tv.power_controller_maintenance.v1",
            meaning: "fstrim and optional Bluetooth/controller support are maintained",
        },
    )
}
