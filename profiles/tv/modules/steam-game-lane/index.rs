#[path = "../tv-runtime-support.rs"]
mod tv_runtime_support;

use crate::*;
use std::path::Path;
use tv_runtime_support::TvModuleSpec;

pub(crate) const ID: &str = "steam-game-lane";

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
            phase: 8,
            schema: "harmonia.tv.steam_game_lane.v1",
            meaning:
                "Steam and Gamescope exist as optional game lane, not the main Arch TV session",
        },
    )
}
