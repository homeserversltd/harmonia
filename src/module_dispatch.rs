use crate::*;
use std::fs;
use std::path::Path;

#[path = "../profiles/homeconsole/modules/arcadia-gui-runtime/index.rs"]
mod arcadia_gui_runtime;
#[path = "../profiles/homeconsole/modules/arch-keyring-maintenance/index.rs"]
mod arch_keyring_maintenance;
#[path = "../profiles/homeconsole/modules/harmonia-runtime/index.rs"]
mod harmonia_runtime;
#[path = "../profiles/homeconsole/modules/homeconsole-sync-runtime/index.rs"]
mod homeconsole_sync_runtime;
#[path = "../profiles/homeconsole/modules/identity/index.rs"]
mod identity;
#[path = "../profiles/homeconsole/modules/keyman-runtime/index.rs"]
mod keyman_runtime;
#[path = "../profiles/homeconsole/modules/local-ai-runtime/index.rs"]
mod local_ai_runtime;
#[path = "../profiles/homeconsole/modules/pinned-artifacts-runtime/index.rs"]
mod pinned_artifacts_runtime;
#[path = "../profiles/homeconsole/modules/rust-build-toolchain/index.rs"]
mod rust_build_toolchain;
#[path = "../profiles/homeconsole/modules/system-packages/index.rs"]
mod system_packages;
#[path = "../profiles/tv/modules/appliance-proof/index.rs"]
mod tv_appliance_proof;
#[path = "../profiles/tv/modules/console-recovery/index.rs"]
mod tv_console_recovery;
#[path = "../profiles/tv/modules/desktop-config-payload/index.rs"]
mod tv_desktop_config_payload;
#[path = "../profiles/tv/modules/gpu-display-stack/index.rs"]
mod tv_gpu_display_stack;
#[path = "../profiles/tv/modules/hyprland-desktop/index.rs"]
mod tv_hyprland_desktop;
#[path = "../profiles/tv/modules/operator-rc-profile/index.rs"]
mod tv_operator_rc_profile;
#[path = "../profiles/tv/modules/owner-profile/index.rs"]
mod tv_owner_profile;
#[path = "../profiles/tv/modules/power-controller-maintenance/index.rs"]
mod tv_power_controller_maintenance;
#[path = "../profiles/tv/modules/sddm-autologin-hyprland/index.rs"]
mod tv_sddm_autologin_hyprland;
#[path = "../profiles/tv/modules/steam-game-lane/index.rs"]
mod tv_steam_game_lane;
#[path = "../profiles/tv/modules/user-session-services/index.rs"]
mod tv_user_session_services;
pub(crate) use arcadia_gui_runtime::{
    homeconsole_arcadia_check, homeconsole_arcadia_gui_update, homeconsole_arcadia_update,
};
pub(crate) use homeconsole_sync_runtime::homeconsole_sync;
pub(crate) use keyman_runtime::homeconsole_keyman_update;
#[cfg(test)]
pub(crate) use keyman_runtime::{redact_secret_text, sync_directory};
pub(crate) use pinned_artifacts_runtime::pinned_artifacts_command;

pub(crate) struct ModuleExecution {
    pub(crate) ok: bool,
    pub(crate) changed: bool,
    pub(crate) operation_count: usize,
    pub(crate) first_missing_signal: Option<String>,
}

impl ModuleExecution {
    fn from_operations(outcomes: Vec<(&'static str, OperationOutcome)>, module_id: &str) -> Self {
        let mut ok = true;
        let mut changed = false;
        let mut first_missing_signal = None;
        for (operation_id, outcome) in &outcomes {
            if outcome.changed {
                changed = true;
            }
            if !outcome.ok {
                ok = false;
                if first_missing_signal.is_none() {
                    first_missing_signal = Some(format!("{}-{}-failed", module_id, operation_id));
                }
            }
        }
        Self {
            ok,
            changed,
            operation_count: outcomes.len(),
            first_missing_signal,
        }
    }
}

pub(crate) fn execute_profile_module(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<ModuleExecution, String> {
    validate_registered_module(module)?;
    let module_dir = receipt_dir.join("modules").join(&module.id);
    fs::create_dir_all(&module_dir).map_err(|e| e.to_string())?;
    match module.id.as_str() {
        identity::ID => identity::execute(module, &module_dir, apply),
        arch_keyring_maintenance::ID => {
            arch_keyring_maintenance::execute(module, &module_dir, apply)
        }
        system_packages::ID => system_packages::execute(module, &module_dir, apply),
        harmonia_runtime::ID => harmonia_runtime::execute(module, &module_dir, apply),
        keyman_runtime::ID => keyman_runtime::execute(module, &module_dir, apply),
        homeconsole_sync_runtime::ID => {
            homeconsole_sync_runtime::execute(module, &module_dir, apply)
        }
        rust_build_toolchain::ID => rust_build_toolchain::execute(module, &module_dir, apply),
        arcadia_gui_runtime::ID => arcadia_gui_runtime::execute(module, &module_dir, apply),
        local_ai_runtime::ID => local_ai_runtime::execute(module, &module_dir, apply),
        pinned_artifacts_runtime::ID => {
            pinned_artifacts_runtime::execute(module, &module_dir, apply)
        }
        tv_desktop_config_payload::ID => {
            tv_desktop_config_payload::execute(module, &module_dir, apply)
        }
        tv_owner_profile::ID => tv_owner_profile::execute(module, &module_dir, apply),
        tv_gpu_display_stack::ID => tv_gpu_display_stack::execute(module, &module_dir, apply),
        tv_hyprland_desktop::ID => tv_hyprland_desktop::execute(module, &module_dir, apply),
        tv_operator_rc_profile::ID => tv_operator_rc_profile::execute(module, &module_dir, apply),
        tv_user_session_services::ID => {
            tv_user_session_services::execute(module, &module_dir, apply)
        }
        tv_sddm_autologin_hyprland::ID => {
            tv_sddm_autologin_hyprland::execute(module, &module_dir, apply)
        }
        tv_steam_game_lane::ID => tv_steam_game_lane::execute(module, &module_dir, apply),
        tv_power_controller_maintenance::ID => {
            tv_power_controller_maintenance::execute(module, &module_dir, apply)
        }
        tv_console_recovery::ID => tv_console_recovery::execute(module, &module_dir, apply),
        tv_appliance_proof::ID => tv_appliance_proof::execute(module, &module_dir, apply),
        other => Err(format!("module-unregistered-{other}")),
    }
}

pub(crate) fn validate_registered_module(module: &ModuleManifest) -> Result<(), String> {
    match module.id.as_str() {
        identity::ID => identity::validate(module),
        arch_keyring_maintenance::ID => arch_keyring_maintenance::validate(module),
        system_packages::ID => system_packages::validate(module),
        harmonia_runtime::ID => harmonia_runtime::validate(module),
        keyman_runtime::ID => keyman_runtime::validate(module),
        homeconsole_sync_runtime::ID => homeconsole_sync_runtime::validate(module),
        rust_build_toolchain::ID => rust_build_toolchain::validate(module),
        arcadia_gui_runtime::ID => arcadia_gui_runtime::validate(module),
        local_ai_runtime::ID => local_ai_runtime::validate(module),
        pinned_artifacts_runtime::ID => pinned_artifacts_runtime::validate(module),
        tv_desktop_config_payload::ID => tv_desktop_config_payload::validate(module),
        tv_owner_profile::ID => tv_owner_profile::validate(module),
        tv_gpu_display_stack::ID => tv_gpu_display_stack::validate(module),
        tv_hyprland_desktop::ID => tv_hyprland_desktop::validate(module),
        tv_operator_rc_profile::ID => tv_operator_rc_profile::validate(module),
        tv_user_session_services::ID => tv_user_session_services::validate(module),
        tv_sddm_autologin_hyprland::ID => tv_sddm_autologin_hyprland::validate(module),
        tv_steam_game_lane::ID => tv_steam_game_lane::validate(module),
        tv_power_controller_maintenance::ID => tv_power_controller_maintenance::validate(module),
        tv_console_recovery::ID => tv_console_recovery::validate(module),
        tv_appliance_proof::ID => tv_appliance_proof::validate(module),
        other => Err(format!("module-unregistered-{other}")),
    }
}

fn reject_executable_sidecar(module: &ModuleManifest) -> Result<(), String> {
    if module.command.is_some() || !module.args.is_empty() || module.cwd.is_some() {
        return Err(format!("module-executable-sidecar-rejected-{}", module.id));
    }
    Ok(())
}

fn require_path<'a>(
    module: &'a ModuleManifest,
    value: &'a Option<String>,
    name: &str,
) -> Result<&'a str, String> {
    value
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| format!("module-sidecar-missing-{}-{}", module.id, name))
}

fn require_packages(module: &ModuleManifest) -> Result<(), String> {
    if module.packages.is_empty() {
        return Err(format!("module-sidecar-missing-{}-packages", module.id));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn homeconsole_sync_runtime_validate_for_test(
    module: &ModuleManifest,
) -> Result<(), String> {
    homeconsole_sync_runtime::validate(module)
}
