mod atoms;
#[path = "tools/backfill-file/index.rs"]
mod backfill_file;
#[path = "tools/build-crate/index.rs"]
pub(crate) mod build_crate;
#[path = "tools/build-venv/index.rs"]
pub(crate) mod build_venv;
#[path = "tools/check-health/index.rs"]
pub(crate) mod check_health;
#[path = "tools/enable-unit/index.rs"]
pub(crate) mod enable_unit;
pub(crate) use atoms::attest::hyalos;
mod demo_registry;
#[path = "tools/install-package/index.rs"]
pub(crate) mod install_package;
#[path = "tools/place-file/index.rs"]
mod place_file;
#[path = "tools/pull-repo/index.rs"]
pub(crate) mod pull_repo;
#[path = "tools/ratchet-aur-package/index.rs"]
pub(crate) mod ratchet_aur_package;
#[path = "tools/remove-file/index.rs"]
mod remove_file;
#[path = "tools/remove-unit/index.rs"]
pub(crate) mod remove_unit;
#[path = "tools/set-clock/index.rs"]
pub(crate) mod set_clock;
mod stillness_demo;
mod structural_wall_demo;
#[path = "tools/index.rs"]
pub mod tools;

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

const VERSION: &str = env!("CARGO_PKG_VERSION");
pub(crate) const SOURCE_ROOT: &str = "/opt/harmonia/source";

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Profile {
    id: String,
    identity: String,
    #[serde(default)]
    package_authority: Option<PackageAuthority>,
    #[serde(default)]
    modules: Vec<String>,
    /// Raw declarations preserve future additive fields across engine hops.
    #[serde(default)]
    hotfixes: Vec<serde_json::Value>,
    #[serde(skip)]
    syzygy_declaration: Option<SyzygyDeclaration>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct SyzygyDeclaration {
    pub schema: String,
    pub members: Vec<String>,
    pub gui_face: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PackageAuthority {
    os_family: String,
    package_manager: String,
}

impl PackageAuthority {
    fn backend(&self) -> Result<PackageBackend, String> {
        match (self.os_family.as_str(), self.package_manager.as_str()) {
            ("arch", "pacman") => Ok(PackageBackend::Pacman),
            ("debian", "apt") => Ok(PackageBackend::Apt),
            (os_family, package_manager) => Err(format!(
                "profile-package-authority-unsupported-os_family={os_family}-package_manager={package_manager}"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PackageBackend {
    Pacman,
    Apt,
}

impl PackageBackend {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Pacman => "pacman",
            Self::Apt => "apt",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// Hold/Propose/Replace are the drift behaviors of the Presented/Seed/Hotfix categories; full per-file category declaration is a follow-up slice.
pub(crate) enum OnDrift {
    Hold,
    Propose,
    Replace { only_if_exact: String },
}

impl Default for OnDrift {
    fn default() -> Self {
        Self::Hold
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ManagedFileManifest {
    path: String,
    content: String,
    #[serde(default)]
    mode: Option<u32>,
    #[serde(default)]
    on_drift: OnDrift,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CaduceusProfileSourceManifest {
    source: String,
    path: String,
    #[serde(default)]
    mode: Option<u32>,
    #[serde(default)]
    append: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct TemplateFileManifest {
    source: String,
    target: String,
    #[serde(default)]
    mode: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ModuleManifest {
    id: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    install_bin: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    expected_contains: Option<String>,
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    branch: Option<String>,
    #[serde(default)]
    remote: Option<String>,
    #[serde(default)]
    lock: Option<String>,
    #[serde(default)]
    source_dir: Option<String>,
    #[serde(default)]
    install_profile: Option<String>,
    #[serde(default)]
    target_dir: Option<String>,
    #[serde(default)]
    packages: Vec<String>,
    #[serde(default)]
    package_conflict_policy: Option<String>,
    #[serde(default)]
    package_conflict_paths: Vec<String>,
    #[serde(default)]
    expected_files: Vec<String>,
    #[serde(default)]
    binaries: Vec<String>,
    #[serde(default)]
    services: Vec<String>,
    #[serde(default)]
    user_services: Vec<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    managed_files: Vec<ManagedFileManifest>,
    #[serde(default)]
    caduceus_profile_source: Option<CaduceusProfileSourceManifest>,
    #[serde(default)]
    caduceus_commands: Vec<String>,
    #[serde(default)]
    template_files: Vec<TemplateFileManifest>,
    #[serde(default)]
    variables: HashMap<String, String>,
    #[serde(default)]
    optional: bool,
    #[serde(default)]
    optional_warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CmdResult {
    ok: bool,
    code: i32,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PinnedArtifactsLock {
    schema: String,
    profile: String,
    artifacts: HashMap<String, PinnedArtifact>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PinnedArtifact {
    version: String,
    path: String,
    sha256: String,
    #[serde(default = "known_good_policy")]
    policy: String,
    #[serde(default)]
    source: Option<String>,
}

fn known_good_policy() -> String {
    "known-good".to_string()
}

#[derive(Debug, Clone, Serialize)]
struct PinnedArtifactStatus {
    name: String,
    version: String,
    path: String,
    expected_sha256: String,
    actual_sha256: Option<String>,
    exists: bool,
    ok: bool,
    policy: String,
}

#[derive(Debug, Clone)]
struct OperationOutcome {
    ok: bool,
    changed: bool,
    skipped: bool,
    message: String,
    command: Option<CmdResult>,
}

#[path = "bands/index.rs"]
mod bands;

pub(crate) use bands::compare::homeconsole_arcadia_check;
pub(crate) use bands::restart_services::{
    homeconsole_arcadia_gui_update, homeconsole_arcadia_update,
};
pub(crate) use ratchet_aur_package::pinned_artifacts_command;

pub mod device_profile;
mod hotfix;
mod interactables;
mod ladder;
mod module_dispatch;
mod receipts;
mod schedule;
mod subscription;

pub(crate) use atoms::attest::convergence_receipts::*;
pub(crate) use atoms::r#do::convergence_lock::*;
pub(crate) use atoms::r#do::transaction::RunContext;
pub(crate) use bands::stage_profile::capsule::*;
pub(crate) use bands::stage_profile::groups::*;
pub(crate) use bands::stage_profile::molt::*;
pub(crate) use bands::stage_profile::projection::*;
pub(crate) use bands::{
    run_profile_engine, run_profile_engine_with_preflight, run_profile_engine_with_projection,
};
pub(crate) use device_profile::*;
pub(crate) use hotfix::*;
pub(crate) use interactables::*;
pub(crate) use ladder::*;
pub(crate) use module_dispatch::*;
pub(crate) use receipts::*;
pub(crate) use subscription::*;
pub(crate) use tools::command::harmonia_root_from_module_root;
pub(crate) use tools::command::{
    command_capture, command_capture_with_cwd, command_capture_with_timeout,
};

pub struct Invocation(Option<atoms::r#do::InvocationKey>, Option<RunContext>);

mod invocation_face {
    pub(crate) struct Mint(());

    pub(super) fn mint(args: &[String]) -> super::Invocation {
        let applies = args.iter().any(|arg| arg == "--apply")
            || args.first().is_some_and(|arg| {
                matches!(
                    arg.as_str(),
                    "capsule" | "acquire-source" | "demo" | "install-timer" | "uninstall-timer"
                )
            })
            || matches!(args, [command, action, ..] if matches!(command.as_str(), "interactable" | "config-proposal") && matches!(action.as_str(), "run" | "accept"));
        let key = super::atoms::r#do::InvocationKey::from_apply_or_timer(applies, Mint(()));
        let context = key.map(|key| super::RunContext {
            run_id: super::run_id_from_stamp(),
            profile: "production".into(),
            face: args.first().cloned().unwrap_or_else(|| "invoke".into()),
            key,
            carrier: std::rc::Rc::new(std::cell::RefCell::new(
                crate::atoms::r#do::transaction::RunCarrier::default(),
            )),
        });
        super::Invocation(key, context)
    }
}

pub fn invoke(args: Vec<String>) -> Result<(), String> {
    let invocation = invocation_face::mint(&args);
    run(args, invocation)
}

pub(crate) fn run(args: Vec<String>, invocation: Invocation) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("demo") => demo_command(&args[1..], invocation),
        Some("interactable") | Some("config-proposal") => {
            interactable_command(&args[1..], invocation.0)
        }
        Some("install-timer") => schedule::install_timer(
            &args[1..],
            invocation
                .0
                .ok_or_else(|| "schedule-invocation-key-missing".to_string())?,
        ),
        Some("uninstall-timer") => schedule::uninstall_timer(
            &args[1..],
            invocation
                .0
                .ok_or_else(|| "schedule-invocation-key-missing".to_string())?,
        ),
        Some("renew-self") => renew_self_command(&args[1..], invocation),
        Some("update") => update_from_certificate(&args[1..], invocation),
        Some("explain") => explain(),
        Some("toolbelt") | Some("list-tools") => toolbelt(),
        Some("validate-ladder") => {
            let path = args
                .get(1)
                .ok_or("validate-ladder requires <manifest.json>")?;
            let manifest = load_ladder_manifest(Path::new(path))?;
            match validate_ladder(&manifest) {
                Ok(steps) => {
                    println!("schema=harmonia.ladder.validate.v1");
                    hyalos::forward_receipt(
                        "schema=harmonia.ladder.validate.v1",
                        &format!("schema=harmonia.ladder.validate.v1 ok={}", true),
                        Some(
                            serde_json::json!({"schema": "harmonia.ladder.validate.v1", "ok": true}),
                        ),
                        Some(true),
                    );
                    println!("ok=true");
                    println!("module_id={}", manifest.id);
                    println!("version={}", manifest.version);
                    println!("step_count={}", steps.len());
                    println!("first_missing_signal=none");
                    Ok(())
                }
                Err(err) => {
                    println!("schema=harmonia.ladder.validate.v1");
                    hyalos::forward_receipt(
                        "schema=harmonia.ladder.validate.v1",
                        &format!("schema=harmonia.ladder.validate.v1 ok={}", false),
                        Some(
                            serde_json::json!({"schema": "harmonia.ladder.validate.v1", "ok": false}),
                        ),
                        Some(false),
                    );
                    println!("ok=false");
                    println!("module_id={}", manifest.id);
                    println!("version={}", manifest.version);
                    println!("first_missing_signal={}", err.first_missing_signal());
                    Err(format!("module-invalid {}", err.first_missing_signal()))
                }
            }
        }
        Some("resolve-source") => {
            let component = args
                .get(1)
                .ok_or("resolve-source requires <component> --certificate <path>")?;
            let certificate = value_arg(&args, "--certificate")
                .ok_or("resolve-source requires <component> --certificate <path>")?;
            let owning_module = value_arg(&args, "--owner-module")
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_else(|| "engine-plane".to_string());
            let step_id = value_arg(&args, "--step-id")
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_else(|| "source-resolution".to_string());
            let receipt = crate::bands::pull_source::resolve_source_json(
                &certificate,
                component,
                &owning_module,
                &step_id,
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&receipt)
                    .map_err(|err| format!("source-receipt-serialize-failed: {err}"))?
            );
            if receipt["ok"] == false {
                return Err(receipt["blocker"]
                    .as_str()
                    .unwrap_or("source-resolution-failed")
                    .to_string());
            }
            Ok(())
        }
        Some("acquire-source") => {
            let component = args
                .get(1)
                .ok_or("acquire-source requires <component> --certificate <path> --engine-config <path> --destination <path>")?;
            let certificate = value_arg(&args, "--certificate")
                .ok_or("acquire-source requires <component> --certificate <path> --engine-config <path> --destination <path>")?;
            let engine_config = value_arg(&args, "--engine-config")
                .ok_or("acquire-source requires <component> --certificate <path> --engine-config <path> --destination <path>")?;
            let destination = value_arg(&args, "--destination")
                .ok_or("acquire-source requires <component> --certificate <path> --engine-config <path> --destination <path>")?;
            let resolution = crate::bands::pull_source::resolve_source(
                &certificate,
                component,
                "engine-plane",
                "source-acquisition",
            );
            if let Some(ref blocker) = resolution.blocker {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&resolution)
                        .map_err(|err| format!("source-receipt-serialize-failed: {err}"))?
                );
                return Err(blocker.clone());
            }
            let plan = resolution
                .resolution
                .ok_or("source-acquisition-plan-missing")?;
            let config = crate::bands::renew_self::load_engine_plane_config(&engine_config)?
                .ok_or_else(|| format!("engine-config-missing {}", engine_config.display()))?;
            let bearer = value_arg_string(&args, "--bearer").unwrap_or_else(|| "owner".to_string());
            let expected_commit = value_arg_string(&args, "--expected-commit");
            let acquisition = crate::bands::pull_source::bridge_acquisition_plan(
                &plan,
                destination,
                bearer,
                expected_commit,
                std::collections::BTreeMap::new(),
            );
            let outcome = tools::git_artifact::acquire_source(&acquisition, invocation.0);
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schema": "harmonia.engine.source_acquisition.v1",
                    "ok": outcome.ok,
                    "changed": outcome.changed,
                    "component": component,
                    "requested_ref": plan.requested_ref,
                    "attempts": outcome.receipt.attempts.iter().map(|attempt| json!({
                        "index": attempt.index,
                        "kind": format!("{:?}", attempt.kind).to_ascii_lowercase(),
                        "locator": attempt.locator,
                        "credential_selector": attempt.credential_selector,
                        "credential_scope_applied": attempt.credential_selector.as_ref().is_some_and(|selector| acquisition.credentials.contains_key(selector)),
                        "disposition": attempt.disposition,
                        "resolved_commit": attempt.resolved_commit,
                        "external_freshness": attempt.external_freshness,
                        "detail": attempt.detail,
                    })).collect::<Vec<_>>(),
                    "served_index": outcome.receipt.served_index,
                    "resolved_commit": outcome.receipt.resolved_commit,
                    "promotion": outcome.receipt.promotion,
                }))
                .map_err(|err| format!("source-acquisition-receipt-serialize-failed: {err}"))?
            );
            if !outcome.ok {
                return Err("source-acquisition-failed".to_string());
            }
            Ok(())
        }
        Some("inspect-profile") => {
            let path = args
                .get(1)
                .ok_or("inspect-profile requires <profile-index-json>")?;
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            println!("schema=harmonia.profile.inspect.v1");
            hyalos::forward_receipt(
                "schema=harmonia.profile.inspect.v1",
                &format!("schema=harmonia.profile.inspect.v1 ok={}", true),
                Some(serde_json::json!({"schema": "harmonia.profile.inspect.v1", "ok": true})),
                Some(true),
            );
            println!("ok=true");
            println!("profile_id={}", profile.id);
            println!("identity={}", profile.identity);
            println!("module_count={}", profile.modules.len());
            println!("modules={}", profile.modules.join(","));
            Ok(())
        }
        Some("plan-run") => {
            let path = args
                .get(1)
                .ok_or("plan-run requires <profile-index-json>")?;
            let receipt_dir =
                receipt_dir_arg(&args).unwrap_or_else(|| PathBuf::from("target/harmonia-receipts"));
            let profile_path = Path::new(path);
            let profile = load_profile(profile_path).map_err(|e| e.to_string())?;
            let module_root = default_module_root(profile_path);
            write_plan_receipts(&profile, &module_root, &receipt_dir).map_err(|e| e.to_string())?;
            println!("schema=harmonia.plan_run.v1");
            hyalos::forward_receipt(
                "schema=harmonia.plan_run.v1",
                &format!("schema=harmonia.plan_run.v1 ok={}", true),
                Some(serde_json::json!({"schema": "harmonia.plan_run.v1", "ok": true})),
                Some(true),
            );
            println!("ok=true");
            println!("profile_id={}", profile.id);
            println!("receipt_dir={}", receipt_dir.display());
            println!("mutation=false");
            Ok(())
        }
        Some("run-profile") => {
            let path = args
                .get(1)
                .ok_or("run-profile requires <profile-index-json>")?;
            let receipt_dir = receipt_dir_arg(&args)
                .unwrap_or_else(|| PathBuf::from("target/harmonia-run-profile"));
            let mode = UpdateMode::from_apply_flag_with_invocation(
                args.iter().any(|arg| arg == "--apply"),
                invocation.0,
            );
            let module_root = default_module_root(Path::new(path));
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            if profile.id == "homeserver" && profile.identity == "homeserver" {
                homeserver_update(&profile, &module_root, &receipt_dir, mode)
            } else if profile.id == "homeconsole" && profile.identity == "homeconsole" {
                homeconsole_update(&profile, &module_root, &receipt_dir, mode)
            } else if profile.id == "tv" && profile.identity == "arch-tv" {
                tv_update(&profile, &module_root, &receipt_dir, mode)
            } else {
                run_profile_engine(&profile, &module_root, &receipt_dir, mode)
            }
        }
        Some("capsule") => {
            let action = args
                .get(1)
                .ok_or("capsule requires <pack|verify|install>")?;
            match action.as_str() {
                "pack" => {
                    let profile_id = args.get(2).ok_or("capsule pack requires <profile-id>")?;
                    let output_dir =
                        value_arg(&args, "--out").ok_or("capsule pack requires --out <dir>")?;
                    let harmonia_root = value_arg(&args, "--harmonia-root")
                        .unwrap_or_else(|| PathBuf::from(SOURCE_ROOT));
                    capsule_pack_with_invocation(
                        profile_id,
                        &output_dir,
                        &harmonia_root,
                        invocation
                            .0
                            .ok_or_else(|| "capsule-pack-invocation-key-missing".to_string())?,
                    )
                }
                "verify" => {
                    let capsule_dir = args.get(2).ok_or("capsule verify requires <dir>")?;
                    capsule_verify(Path::new(capsule_dir)).map(|_| ())
                }
                "install" => {
                    let capsule_dir = args.get(2).ok_or("capsule install requires <dir>")?;
                    let apply = args.iter().any(|arg| arg == "--apply");
                    let config_dir = value_arg(&args, "--config-dir")
                        .unwrap_or_else(|| PathBuf::from("/etc/harmonia"));
                    capsule_install_with_invocation(
                        Path::new(capsule_dir),
                        &config_dir,
                        apply,
                        invocation.0,
                    )
                }
                other => Err(format!("capsule-action-unsupported-{other}")),
            }
        }
        Some("subscription") => {
            let action = args.get(1).ok_or("subscription requires <show>")?;
            match action.as_str() {
                "show" => subscription_show(&subscription_path()),
                other => Err(format!("subscription-action-unsupported-{other}")),
            }
        }
        Some("molt") => {
            let profile_id = args.get(1).ok_or("molt requires <profile-id>")?;
            let output_dir = value_arg(&args, "--out").ok_or("molt requires --out <path>")?;
            let harmonia_root =
                value_arg(&args, "--harmonia-root").unwrap_or_else(|| PathBuf::from(SOURCE_ROOT));
            let receipt_dir = receipt_dir_arg(&args).unwrap_or_else(|| output_dir.join("receipts"));
            let mode = MoltMode::parse(value_arg_string(&args, "--mode"))?;
            molt(&harmonia_root, profile_id, &output_dir, &receipt_dir, mode)
        }
        Some("pinned-artifacts") => {
            let action = args
                .get(1)
                .ok_or("pinned-artifacts requires <check|nudge|bless>")?;
            let path = args
                .get(2)
                .ok_or("pinned-artifacts requires <profile-index-json>")?;
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            let receipt_dir = receipt_dir_arg(&args)
                .unwrap_or_else(|| PathBuf::from("target/harmonia-pinned-artifacts"));
            let lock_path =
                value_arg(&args, "--lock").unwrap_or_else(|| default_pinned_lock_path(&profile));
            pinned_artifacts_command(action, &profile, &lock_path, &receipt_dir, &args)
        }
        Some("homeserver-update") => {
            let path = args
                .get(1)
                .ok_or("homeserver-update requires <profile-index-json>")?;
            let receipt_dir =
                receipt_dir_arg(&args).unwrap_or_else(homeserver_update_receipt_latest);
            let mode = UpdateMode::from_apply_flag_with_invocation(
                args.iter().any(|arg| arg == "--apply"),
                invocation.0,
            );
            verify_asserted_profile("homeserver")?;
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            let module_root = default_module_root(Path::new(path));
            homeserver_update(&profile, &module_root, &receipt_dir, mode)
        }
        Some("homeconsole-update") => {
            let path = args
                .get(1)
                .ok_or("homeconsole-update requires <profile-index-json>")?;
            let receipt_dir =
                receipt_dir_arg(&args).unwrap_or_else(homeconsole_update_receipt_latest);
            let mode = UpdateMode::from_apply_flag_with_invocation(
                args.iter().any(|arg| arg == "--apply"),
                invocation.0,
            );
            verify_asserted_profile("homeconsole")?;
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            let module_root = default_module_root(Path::new(path));
            homeconsole_update(&profile, &module_root, &receipt_dir, mode)
        }
        Some("tv-update") => {
            let path = args
                .get(1)
                .ok_or("tv-update requires <profile-index-json>")?;
            let receipt_dir = receipt_dir_arg(&args).unwrap_or_else(tv_update_receipt_latest);
            let mode = UpdateMode::from_apply_flag_with_invocation(
                args.iter().any(|arg| arg == "--apply"),
                invocation.0,
            );
            verify_asserted_profile("tv")?;
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            let module_root = default_module_root(Path::new(path));
            tv_update(&profile, &module_root, &receipt_dir, mode)
        }
        Some("homeconsole-local-ai-update") => {
            let path = args
                .get(1)
                .ok_or("homeconsole-local-ai-update requires <profile-index-json>")?;
            let receipt_dir = receipt_dir_arg(&args).unwrap_or_else(|| {
                PathBuf::from("/var/lib/harmonia/receipts/local-ai-runtime-latest")
            });
            let mode = UpdateMode::from_apply_flag_with_invocation(
                args.iter().any(|arg| arg == "--apply"),
                invocation.0,
            );
            let apply = mode.is_software_apply();
            let module_root = default_module_root(Path::new(path));
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            if profile.id != "homeconsole" || profile.identity != "homeconsole" {
                return Err(format!(
                    "homeconsole-local-ai-update requires homeconsole/homeconsole profile, got {}/{}",
                    profile.id, profile.identity
                ));
            }
            let module = load_module(&module_root.join("local-ai-runtime").join("sidecar.json"))?;
            let harmonia_root = harmonia_root_from_module_root(&module_root);
            let run_started = std::time::Instant::now();
            let execution = execute_profile_module(
                &module,
                &module_root,
                &receipt_dir,
                mode.software_authorization(),
                &harmonia_root,
                mode.invocation(),
                None,
            )?;
            write_engine_run_receipt_with_duration(
                &receipt_dir,
                &profile,
                apply,
                execution.ok,
                execution.changed,
                1,
                execution.operation_count,
                execution.first_missing_signal.as_deref().unwrap_or("none"),
                &module_root,
                execution.ok,
                run_started.elapsed().as_millis(),
            )?;
            println!("schema=harmonia.local_ai_runtime.v1");
            hyalos::forward_receipt(
                "schema=harmonia.local_ai_runtime.v1",
                &format!("schema=harmonia.local_ai_runtime.v1 ok={}", execution.ok),
                Some(
                    serde_json::json!({"schema": "harmonia.local_ai_runtime.v1", "ok": execution.ok}),
                ),
                Some(execution.ok),
            );
            println!("ok={}", execution.ok);
            println!("changed={}", execution.changed);
            println!("profile_id={}", profile.id);
            println!("operation_count={}", execution.operation_count);
            println!(
                "first_missing_signal={}",
                execution.first_missing_signal.as_deref().unwrap_or("none")
            );
            println!("receipt_dir={}", receipt_dir.display());
            if execution.ok {
                Ok(())
            } else {
                Err(execution
                    .first_missing_signal
                    .unwrap_or_else(|| "local-ai-runtime-failed".to_string()))
            }
        }
        Some("homeconsole-sync") => {
            let path = args
                .get(1)
                .ok_or("homeconsole-sync requires <profile-index-json>")?;
            let module_path =
                value_arg(&args, "--module").ok_or("homeconsole-sync requires --module <path>")?;
            let receipt_dir = receipt_dir_arg(&args).unwrap_or_else(|| {
                PathBuf::from("/var/lib/harmonia/receipts/homeconsole-sync-latest")
            });
            let mode = UpdateMode::from_apply_flag_with_invocation(
                args.iter().any(|arg| arg == "--apply"),
                invocation.0,
            );
            let apply = mode.is_software_apply();
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            if profile.id != "homeconsole" || profile.identity != "homeconsole" {
                return Err(format!(
                    "homeconsole-sync requires homeconsole/homeconsole profile, got {}/{}",
                    profile.id, profile.identity
                ));
            }
            let module = load_module(Path::new(&module_path))?;
            let module_root = default_module_root(Path::new(path));
            let harmonia_root = harmonia_root_from_module_root(&module_root);
            let run_started = std::time::Instant::now();
            let execution = execute_profile_module(
                &module,
                &module_root,
                &receipt_dir,
                mode.software_authorization(),
                &harmonia_root,
                mode.invocation(),
                Some("homeconsole-sync"),
            )?;
            write_engine_run_receipt_with_duration(
                &receipt_dir,
                &profile,
                apply,
                execution.ok,
                execution.changed,
                1,
                execution.operation_count,
                execution.first_missing_signal.as_deref().unwrap_or("none"),
                &module_root,
                execution.ok,
                run_started.elapsed().as_millis(),
            )?;
            println!("schema=harmonia.homeconsole_sync.v1");
            hyalos::forward_receipt(
                "schema=harmonia.homeconsole_sync.v1",
                &format!("schema=harmonia.homeconsole_sync.v1 ok={}", execution.ok),
                Some(
                    serde_json::json!({"schema": "harmonia.homeconsole_sync.v1", "ok": execution.ok}),
                ),
                Some(execution.ok),
            );
            println!("ok={}", execution.ok);
            println!("changed={}", execution.changed);
            println!("profile_id={}", profile.id);
            println!("operation_count={}", execution.operation_count);
            println!(
                "first_missing_signal={}",
                execution.first_missing_signal.as_deref().unwrap_or("none")
            );
            println!("receipt_dir={}", receipt_dir.display());
            if execution.ok {
                Ok(())
            } else {
                Err(execution
                    .first_missing_signal
                    .unwrap_or_else(|| "homeconsole-sync-failed".to_string()))
            }
        }
        Some("homeconsole-arcadia-check") => {
            let path = args
                .get(1)
                .ok_or("homeconsole-arcadia-check requires <profile-index-json>")?;
            let receipt_dir = receipt_dir_arg(&args).unwrap_or_else(|| {
                PathBuf::from("/var/lib/harmonia/receipts/arcadia-check-latest")
            });
            let repo = value_arg_string(&args, "--repo")
                .unwrap_or_else(|| "https://git.home.arpa/HOMESERVERSLTD/arcadia.git".to_string());
            let branch = value_arg_string(&args, "--branch").unwrap_or_else(|| "main".to_string());
            let current_sha_file = value_arg(&args, "--current-sha-file")
                .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/state/arcadia.sha"));
            let upstream_sha_file = value_arg(&args, "--upstream-sha-file");
            let insecure_tls = args.iter().any(|arg| arg == "--insecure-tls");
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            homeconsole_arcadia_check(
                &profile,
                &receipt_dir,
                &repo,
                &branch,
                &current_sha_file,
                upstream_sha_file.as_deref(),
                insecure_tls,
            )
        }
        Some("homeconsole-arcadia-update") => {
            let path = args
                .get(1)
                .ok_or("homeconsole-arcadia-update requires <profile-index-json>")?;
            let receipt_dir = receipt_dir_arg(&args)
                .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/receipts/arcadia-latest"));
            let artifact = value_arg(&args, "--artifact")
                .ok_or("homeconsole-arcadia-update requires --artifact <path>")?;
            let install_bin = value_arg(&args, "--install-bin")
                .unwrap_or_else(|| PathBuf::from("/usr/local/bin/arcadia"));
            let service = value_arg(&args, "--service")
                .and_then(|p| p.to_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "arcadia.service".to_string());
            let source_sha = value_arg_string(&args, "--source-sha");
            let apply = args.iter().any(|arg| arg == "--apply");
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            homeconsole_arcadia_update(
                &profile,
                &receipt_dir,
                &artifact,
                &install_bin,
                &service,
                apply,
                source_sha.as_deref(),
                invocation.0,
            )
        }
        Some("homeconsole-arcadia-gui-update") => {
            let path = args
                .get(1)
                .ok_or("homeconsole-arcadia-gui-update requires <profile-index-json>")?;
            let receipt_dir = receipt_dir_arg(&args)
                .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/receipts/arcadia-gui-latest"));
            let component =
                value_arg_string(&args, "--component").unwrap_or_else(|| "arcadia".to_string());
            let source_dir = value_arg(&args, "--source-dir")
                .unwrap_or_else(|| PathBuf::from("/opt/arcadia/source"));
            let install_bin = value_arg(&args, "--install-bin")
                .unwrap_or_else(|| PathBuf::from("/usr/local/bin/arcadia"));
            let service = value_arg(&args, "--service")
                .and_then(|p| p.to_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "arcadia.service".to_string());
            let apply = args.iter().any(|arg| arg == "--apply");
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            homeconsole_arcadia_gui_update(
                &profile,
                &receipt_dir,
                &component,
                &source_dir,
                &install_bin,
                &service,
                apply,
                invocation.0,
            )
        }
        _ => usage(),
    }
}

pub(crate) fn toolbelt() -> Result<(), String> {
    println!("schema=harmonia.toolbelt.v1");
    hyalos::forward_receipt(
        "schema=harmonia.toolbelt.v1",
        &format!("schema=harmonia.toolbelt.v1 ok={}", true),
        Some(serde_json::json!({"schema": "harmonia.toolbelt.v1", "ok": true})),
        Some(true),
    );
    println!("ok=true");
    println!("tool_count={}", tools::all().len());
    for declaration in tools::declaration::all()? {
        println!(
            "declaration={} deed={} comparison={:?} attest={:?} inputs={}",
            declaration.tool,
            declaration.deed.map(|d| d.name()).unwrap_or("ask"),
            declaration.comparison,
            declaration.attest,
            declaration.inputs.len()
        );
    }
    for tool in tools::all() {
        let permutations: Vec<&str> = tool.permutations.iter().map(|p| p.name).collect();
        println!(
            "tool={} description={} permutations={}",
            tool.name,
            tool.description,
            permutations.join(",")
        );
        for permutation in tool.permutations {
            let args: Vec<String> = permutation
                .args
                .iter()
                .map(|arg| {
                    format!(
                        "{}:{}:{}",
                        arg.name,
                        arg.kind.name(),
                        if arg.required { "required" } else { "optional" }
                    )
                })
                .collect();
            println!(
                "tool={} permutation={} args={}",
                tool.name,
                permutation.name,
                args.join(",")
            );
        }
    }
    Ok(())
}

pub(crate) fn explain() -> Result<(), String> {
    println!("schema=harmonia.explain.v1");
    hyalos::forward_receipt(
        "schema=harmonia.explain.v1",
        &format!("schema=harmonia.explain.v1 ok={}", true),
        Some(serde_json::json!({"schema": "harmonia.explain.v1", "ok": true})),
        Some(true),
    );
    println!("ok=true");
    println!("name=harmonia");
    println!("version={}", VERSION);
    println!("covenant=Rust update manager and appliance-profile execution engine");
    println!("shell=bootstrap-only");
    println!("python_helper_lane=false");
    println!("profiles=homeserver,homeconsole,tv");
    println!("homeconsole_identity=homeconsole");
    Ok(())
}

fn demo_command(args: &[String], invocation: Invocation) -> Result<(), String> {
    let name = args.first().map(String::as_str);
    if name.is_none() || name == Some("list") {
        println!("schema=harmonia.demo.list.v1");
        println!("ok=true");
        for name in demo_registry::NAMES {
            println!("name={name}");
        }
        return Ok(());
    }
    let name = name.unwrap();
    if !demo_registry::NAMES.contains(&name) {
        return Err(format!("unknown-demo-name={name}"));
    }
    demo_registry::run(name, invocation.0, invocation.1)
}

pub(crate) fn usage() -> Result<(), String> {
    println!("harmonia {}", VERSION);
    println!("usage:");
    println!("  harmonia explain");
    println!("  harmonia inspect-profile <profiles/<id>/index.json>");
    println!("  harmonia toolbelt");
    println!("  harmonia demo [<name>|list]");
    println!("  harmonia config-proposal list [--json]");
    println!("  harmonia config-proposal accept <id>");
    println!("  harmonia install-timer [--systemd-root <path>] [--dry-run]");
    println!("  harmonia uninstall-timer [--systemd-root <path>] [--dry-run]");
    println!("  harmonia validate-ladder <manifest.json>");
    println!("  harmonia resolve-source <component> --certificate <path> [--owner-module <id>] [--step-id <id>]");
    println!("  harmonia acquire-source <component> --certificate <path> --engine-config <path> --destination <path> [--bearer <name>] [--expected-commit <sha>]");
    println!("  harmonia plan-run <profiles/<id>/index.json> [--receipt-dir <path>]");
    println!("  harmonia renew-self (--plan|--apply) --receipt-dir <path> [--module-root <path>]");
    println!("  harmonia update [--apply] [--receipt-dir <path>]");
    println!("  harmonia run-profile <profiles/<id>/index.json> [--apply] [--receipt-dir <path>]");
    println!("  harmonia subscription show");
    println!("  harmonia molt <profile-id> --out <path> [--harmonia-root <path>] [--mode copy|symlink] [--receipt-dir <path>]");
    println!("  harmonia pinned-artifacts check <profiles/<id>/index.json> [--lock <path>] [--receipt-dir <path>]");
    println!("  harmonia pinned-artifacts nudge <profiles/<id>/index.json> --lock <path> --artifact <name> --candidate <path> --version <version> --sha256 <sha256> [--receipt-dir <path>]");
    println!("  harmonia pinned-artifacts bless <profiles/<id>/index.json> --lock <path> --artifact <name> --candidate <path> --version <version> --sha256 <sha256> [--install-path <path>] [--apply] [--receipt-dir <path>]");
    println!("  harmonia homeserver-update <profiles/homeserver/index.json> [--apply] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-update <profiles/homeconsole/index.json> [--apply] [--receipt-dir <path>]");
    println!("  harmonia tv-update <profiles/tv/index.json> [--apply] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-local-ai-update <profiles/homeconsole/index.json> [--apply] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-sync <profiles/homeconsole/index.json> --module <path> [--apply] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-arcadia-check <profiles/homeconsole/index.json> [--repo <url>] [--branch main] [--current-sha-file <path>] [--upstream-sha-file <path>] [--insecure-tls] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-arcadia-update <profiles/homeconsole/index.json> --artifact <path> [--apply] [--install-bin <path>] [--service arcadia.service] [--source-sha <sha>] [--source-sha-file <path>] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-arcadia-gui-update <profiles/homeconsole/index.json> [--repo <url>] [--branch main] [--source-dir /opt/arcadia/source] [--apply] [--install-bin <path>] [--service arcadia.service] [--source-sha-file <path>] [--receipt-dir <path>]");
    Ok(())
}

fn renew_self_command(args: &[String], invocation: Invocation) -> Result<(), String> {
    if args == ["--help"] {
        println!("usage: harmonia renew-self (--plan|--apply) --receipt-dir <path> [--module-root <path>]");
        return Ok(());
    }
    let apply = args.iter().any(|a| a == "--apply");
    let receipt_dir =
        value_arg(args, "--receipt-dir").ok_or("renew-self-requires---receipt-dir-<path>")?;
    let module_root = value_arg(args, "--module-root").unwrap_or_default();
    let execution = bands::renew_self::run(&module_root, &receipt_dir, apply, invocation.0)?;
    let output = json!({"schema": bands::renew_self::PREFLIGHT_SCHEMA, "ok": execution.ok, "apply": apply, "changed": execution.changed, "operation_count": execution.operation_count, "first_missing_signal": execution.first_missing_signal.as_deref().unwrap_or("none"), "receipt_dir": receipt_dir, "module_root": module_root, "authority": "engine-preflight-only", "module_bands": false});
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())?
    );
    if execution.ok {
        Ok(())
    } else {
        Err(execution
            .first_missing_signal
            .unwrap_or_else(|| "engine-preflight-failed".into()))
    }
}

pub(crate) fn receipt_dir_arg(args: &[String]) -> Option<PathBuf> {
    value_arg(args, "--receipt-dir")
}

pub(crate) fn value_arg(args: &[String], name: &str) -> Option<PathBuf> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| PathBuf::from(&pair[1]))
}

pub(crate) fn value_arg_string(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

pub(crate) fn default_module_root(profile_path: &Path) -> PathBuf {
    let profile_dir = profile_path.parent().unwrap_or_else(|| Path::new("."));
    profile_dir.join("modules")
}
