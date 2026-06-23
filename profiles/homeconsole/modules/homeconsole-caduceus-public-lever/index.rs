#[path = "../../../tv/modules/tv-runtime-support.rs"]
mod tv_runtime_support;

use crate::*;
use std::path::Path;
use tv_runtime_support::TvModuleSpec;

pub(crate) const ID: &str = "homeconsole-caduceus-public-lever";

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
            phase: 10,
            schema: "harmonia.homeconsole.caduceus_public_lever.v1",
            meaning: "Caduceus public appliance lever identity, policy, sync/update routes, and binary possession are maintained for HomeConsole",
        },
    )
}
