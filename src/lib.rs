pub mod tools;
pub(crate) use tools::module_steps::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{self};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Profile {
    id: String,
    identity: String,
    #[serde(default)]
    modules: Vec<String>,
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
    target_dir: Option<String>,
    #[serde(default)]
    source_sha_file: Option<String>,
    #[serde(default)]
    packages: Vec<String>,
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
}

#[derive(Debug, Clone, Serialize)]
struct CmdResult {
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

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SyncModuleConfig {
    id: String,
    #[serde(default)]
    description: String,
    #[serde(default = "default_sync_adapter_command")]
    adapter_command: String,
    #[serde(default)]
    adapter_args: Vec<String>,
    #[serde(default = "default_sync_provider_env")]
    provider_env: String,
    #[serde(default)]
    providers: Vec<SyncProviderConfig>,
    #[serde(default)]
    shortcut_lanes: Vec<String>,
    #[serde(default)]
    artwork_lanes: Vec<String>,
    #[serde(default = "default_sync_restart_policy")]
    restart_policy: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SyncProviderConfig {
    name: String,
    #[serde(default)]
    env_keys: Vec<String>,
    #[serde(default)]
    required: bool,
}

#[derive(Debug, Clone, Serialize)]
struct SyncProviderReceipt {
    name: String,
    configured: bool,
    required: bool,
    env_keys: Vec<String>,
    missing_env_keys: Vec<String>,
}

fn default_sync_adapter_command() -> String {
    "/usr/local/bin/arch-game-sync".to_string()
}

fn default_sync_provider_env() -> String {
    "/etc/arch-game-sync/providers.env".to_string()
}

fn default_sync_restart_policy() -> String {
    "adapter-owned".to_string()
}

#[derive(Debug, Clone)]
struct OperationOutcome {
    ok: bool,
    changed: bool,
    skipped: bool,
    message: String,
    command: Option<CmdResult>,
}

mod deployable_config;
mod module_dispatch;
mod profile_engine;
mod receipts;

pub(crate) use deployable_config::*;
pub(crate) use module_dispatch::*;
pub(crate) use profile_engine::*;
pub(crate) use receipts::*;

pub fn main_entry() {
    if let Err(err) = run(env::args().skip(1).collect()) {
        eprintln!("harmonia_error={}", err);
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
    }

    #[test]
    fn extracts_profile_identity_fields() {
        let text =
            r#"{"id":"homeconsole","identity":"homeconsole","modules":["identity","packages"]}"#;
        assert_eq!(extract_string(text, "id").unwrap(), "homeconsole");
        assert_eq!(extract_string(text, "identity").unwrap(), "homeconsole");
        assert_eq!(
            extract_string_array(text, "modules"),
            vec!["identity", "packages"]
        );
    }

    #[test]
    fn default_module_root_is_profile_adjacent() {
        assert_eq!(
            default_module_root(Path::new("profiles/homeconsole/index.json")),
            PathBuf::from("profiles/homeconsole/modules")
        );
        assert_eq!(
            default_module_root(Path::new("/etc/harmonia/profiles/homeconsole/index.json")),
            PathBuf::from("/etc/harmonia/profiles/homeconsole/modules")
        );
    }

    #[test]
    fn rejects_old_console_identity_names() {
        let old = Profile {
            id: "homeconsole".into(),
            identity: format!("{}-{}", "arch", "console"),
            modules: module_ids_from_profile_modules(&homeconsole_module_root()).unwrap(),
        };
        assert!(homeconsole_update(
            &old,
            &homeconsole_module_root(),
            &PathBuf::from("target/unused"),
            false,
        )
        .unwrap_err()
        .contains("homeconsole/homeconsole"));
    }

    #[test]
    fn detects_pacman_change_from_stdout() {
        assert!(pacman_stdout_indicates_change("\nupgrading ffmpeg..."));
        assert!(!pacman_stdout_indicates_change(" there is nothing to do"));
    }

    #[test]
    fn redacts_secret_bearing_lines() {
        let redacted = redact_secret_text("ok\npassword=abc\nusername=owner\npublic=yes");
        assert!(redacted.contains("ok"));
        assert!(redacted.contains("public=yes"));
        assert!(!redacted.contains("abc"));
        assert!(!redacted.contains("owner"));
    }

    #[test]
    fn files_convergence_plan_reports_byte_and_mode_drift_without_mutation() {
        let scratch = std::env::temp_dir().join(format!("harmonia-files-plan-{}", process::id()));
        let source = scratch.join("source");
        let target = scratch.join("target");
        let receipts = scratch.join("receipts");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::write(source.join("a.conf"), "new\n").unwrap();
        fs::write(target.join("a.conf"), "old\n").unwrap();
        #[cfg(unix)]
        fs::set_permissions(target.join("a.conf"), fs::Permissions::from_mode(0o600)).unwrap();
        let request = tools::files::FileConvergenceRequest {
            source_root: source.clone(),
            target_root: target.clone(),
            files: vec![tools::files::FileSpec {
                relative_path: PathBuf::from("a.conf"),
                mode: Some(0o644),
            }],
            backup_existing: true,
            receipt_name: "plan".to_string(),
        };
        let outcome = tools::files::converge_files(&request, &receipts, false).unwrap();
        assert!(outcome.ok);
        assert!(outcome.changed);
        assert_eq!(outcome.written, 0);
        assert_eq!(fs::read_to_string(target.join("a.conf")).unwrap(), "old\n");
        let receipt = fs::read_to_string(receipts.join("plan.json")).unwrap();
        assert!(receipt.contains("harmonia.files.converge.v1"));
        assert!(receipt.contains("content_equal_before"));
        assert!(!receipt.contains("sha256"));
        assert!(!receipt.contains("digest"));
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn files_convergence_apply_backs_up_existing_file_and_sets_mode() {
        let scratch = std::env::temp_dir().join(format!("harmonia-files-apply-{}", process::id()));
        let source = scratch.join("source");
        let target = scratch.join("target");
        let receipts = scratch.join("receipts");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::write(source.join("a.conf"), "new\n").unwrap();
        fs::write(target.join("a.conf"), "old\n").unwrap();
        let request = tools::files::FileConvergenceRequest {
            source_root: source.clone(),
            target_root: target.clone(),
            files: vec![tools::files::FileSpec {
                relative_path: PathBuf::from("a.conf"),
                mode: Some(0o640),
            }],
            backup_existing: true,
            receipt_name: "apply".to_string(),
        };
        let outcome = tools::files::converge_files(&request, &receipts, true).unwrap();
        assert!(outcome.ok);
        assert!(outcome.changed);
        assert_eq!(outcome.written, 1);
        assert_eq!(outcome.backed_up, 1);
        assert_eq!(fs::read_to_string(target.join("a.conf")).unwrap(), "new\n");
        assert_eq!(
            fs::read_to_string(receipts.join("backups/a.conf")).unwrap(),
            "old\n"
        );
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(target.join("a.conf"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn files_convergence_apply_is_idempotent_after_byte_equal_mode_equal() {
        let scratch = std::env::temp_dir().join(format!("harmonia-files-idem-{}", process::id()));
        let source = scratch.join("source");
        let target = scratch.join("target");
        let receipts = scratch.join("receipts");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("a.conf"), "same\n").unwrap();
        let request = tools::files::FileConvergenceRequest {
            source_root: source.clone(),
            target_root: target.clone(),
            files: vec![tools::files::FileSpec {
                relative_path: PathBuf::from("a.conf"),
                mode: Some(0o644),
            }],
            backup_existing: true,
            receipt_name: "idem".to_string(),
        };
        tools::files::converge_files(&request, &receipts, true).unwrap();
        let second = tools::files::converge_files(&request, &receipts, true).unwrap();
        assert!(second.ok);
        assert!(!second.changed);
        assert_eq!(second.written, 0);
        assert_eq!(second.backed_up, 0);
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn files_convergence_rejects_absolute_or_parent_relative_paths() {
        for rel in ["/tmp/evil", "../evil", "nested/../../evil"] {
            let request = tools::files::FileConvergenceRequest {
                source_root: PathBuf::from("source"),
                target_root: PathBuf::from("target"),
                files: vec![tools::files::FileSpec {
                    relative_path: PathBuf::from(rel),
                    mode: None,
                }],
                backup_existing: true,
                receipt_name: "reject".to_string(),
            };
            let err = tools::files::converge_files(&request, &PathBuf::from("receipts"), false)
                .unwrap_err();
            assert!(err.contains("files-relative-path-rejected"));
        }
    }

    #[test]
    fn files_convergence_rejects_unsafe_receipt_duplicate_paths_and_modes() {
        let base = tools::files::FileConvergenceRequest {
            source_root: PathBuf::from("source"),
            target_root: PathBuf::from("target"),
            files: vec![tools::files::FileSpec {
                relative_path: PathBuf::from("a.conf"),
                mode: Some(0o644),
            }],
            backup_existing: true,
            receipt_name: "../escape".to_string(),
        };
        let err =
            tools::files::converge_files(&base, &PathBuf::from("receipts"), false).unwrap_err();
        assert!(err.contains("files-receipt-name-rejected"));

        let duplicate = tools::files::FileConvergenceRequest {
            receipt_name: "safe".to_string(),
            files: vec![
                tools::files::FileSpec {
                    relative_path: PathBuf::from("a.conf"),
                    mode: Some(0o644),
                },
                tools::files::FileSpec {
                    relative_path: PathBuf::from("a.conf"),
                    mode: Some(0o644),
                },
            ],
            ..base.clone()
        };
        let err = tools::files::converge_files(&duplicate, &PathBuf::from("receipts"), false)
            .unwrap_err();
        assert!(err.contains("files-duplicate-relative-path-rejected"));

        let invalid_mode = tools::files::FileConvergenceRequest {
            receipt_name: "safe".to_string(),
            files: vec![tools::files::FileSpec {
                relative_path: PathBuf::from("a.conf"),
                mode: Some(0o1000),
            }],
            ..base
        };
        let err = tools::files::converge_files(&invalid_mode, &PathBuf::from("receipts"), false)
            .unwrap_err();
        assert!(err.contains("files-mode-rejected"));
    }

    #[test]
    fn module_sidecar_rejects_legacy_steps_ladder() {
        let receipt_dir =
            std::env::temp_dir().join(format!("harmonia-legacy-steps-{}", process::id()));
        let module_dir = receipt_dir.join("module");
        fs::create_dir_all(&module_dir).unwrap();
        let module_path = module_dir.join("sidecar.json");
        fs::write(&module_path, r#"{"schema":"harmonia.module.sidecar.v1","id":"identity","steps":[{"id":"uname","tool":"command","action":"run"}]}"#).unwrap();
        let err = load_module(&module_path).unwrap_err();
        assert!(err.contains("module-sidecar-behavior-field-rejected"));
        let _ = fs::remove_dir_all(receipt_dir);
    }

    #[test]
    fn module_sidecar_rejects_command_ladder_fields() {
        let receipt_dir =
            std::env::temp_dir().join(format!("harmonia-command-sidecar-{}", process::id()));
        let module_dir = receipt_dir.join("module");
        fs::create_dir_all(&module_dir).unwrap();
        let module_path = module_dir.join("sidecar.json");
        fs::write(
            &module_path,
            r#"{"schema":"harmonia.module.sidecar.v1","id":"identity","command":"/usr/bin/true"}"#,
        )
        .unwrap();
        let err = load_module(&module_path).unwrap_err();
        assert!(err.contains("module-sidecar-behavior-field-rejected"));
        let _ = fs::remove_dir_all(receipt_dir);
    }

    #[test]
    fn unregistered_modules_are_rejected_before_sidecar_can_define_work() {
        let module = ModuleManifest {
            id: "json-invented-module".into(),
            description: "sidecar-only module".into(),
            command: None,
            args: vec![],
            cwd: None,
            service: None,
            install_bin: None,
            url: None,
            expected_contains: None,
            repo: None,
            path: None,
            branch: None,
            remote: None,
            lock: None,
            source_dir: None,
            target_dir: None,
            source_sha_file: None,
            packages: vec![],
            expected_files: vec![],
            binaries: vec![],
            services: vec![],
            user_services: vec![],
            groups: vec![],
        };
        assert_eq!(
            validate_registered_module(&module).unwrap_err(),
            "module-unregistered-json-invented-module"
        );
    }

    #[test]
    fn homeconsole_profile_contains_only_registered_rust_modules_and_adjacent_sidecars() {
        let root = repo_root();
        let profile = load_profile(&root.join("profiles/homeconsole/index.json")).unwrap();
        assert_eq!(profile.id, "homeconsole");
        assert_eq!(profile.identity, "homeconsole");
        assert_eq!(
            profile.modules,
            module_ids_from_profile_modules(&root.join("profiles/homeconsole/modules")).unwrap()
        );
        enforce_homeconsole_update_suite(&profile, &root.join("profiles/homeconsole/modules"))
            .unwrap();
        assert!(
            !root.join("modules").exists(),
            "top-level module execution tree must be absent"
        );
        assert!(
            !root.join("payloads").exists(),
            "top-level payload execution tree must be absent"
        );
        for module in &profile.modules {
            let dir = root.join("profiles/homeconsole/modules").join(module);
            assert!(
                dir.join("index.rs").exists(),
                "{module} needs profile-adjacent Rust marker"
            );
            let manifest = load_module(&dir.join("sidecar.json")).unwrap();
            validate_registered_module(&manifest).unwrap();
        }
    }

    #[test]
    fn tv_profile_owns_deployable_configuration_inside_harmonia_profile() {
        let root = repo_root();
        let profile = load_profile(&root.join("profiles/tv/index.json")).unwrap();
        assert_eq!(profile.id, "tv");
        assert_eq!(profile.identity, "arch-tv");
        assert_eq!(
            profile.modules,
            vec![
                "identity".to_string(),
                "arch-keyring-maintenance".to_string(),
                "system-packages".to_string(),
                "owner-profile".to_string(),
                "gpu-display-stack".to_string(),
                "hyprland-desktop".to_string(),
                "operator-rc-profile".to_string(),
                "desktop-config-payload".to_string(),
                "user-session-services".to_string(),
                "sddm-autologin-hyprland".to_string(),
                "steam-game-lane".to_string(),
                "power-controller-maintenance".to_string(),
                "console-recovery".to_string(),
                "appliance-proof".to_string()
            ]
        );
        assert!(
            !root.join("payloads").exists(),
            "TV config must be profile-adjacent, not a top-level payload execution tree"
        );
        let config_root = root.join("profiles/tv/config/desktop-config");
        assert!(config_root.join(".config/hypr/hyprland.conf").is_file());
        assert!(config_root.join(".config/waybar/waybar.conf").is_file());
        assert!(config_root.join("bin/tv-launcher.sh").is_file());

        for module in &profile.modules {
            let dir = root.join("profiles/tv/modules").join(module);
            assert!(
                dir.join("index.rs").exists(),
                "{module} needs profile-adjacent Rust module logic"
            );
            let manifest = load_module(&dir.join("sidecar.json")).unwrap();
            validate_registered_module(&manifest).unwrap();
        }
    }

    #[test]
    fn tv_profile_runtime_modules_are_constants_only_and_registered() {
        let root = repo_root();
        let profile = load_profile(&root.join("profiles/tv/index.json")).unwrap();
        for module in &profile.modules {
            let manifest = load_module(
                &root
                    .join("profiles/tv/modules")
                    .join(module)
                    .join("sidecar.json"),
            )
            .unwrap();
            assert!(
                manifest.command.is_none(),
                "{module} sidecar must not own a command"
            );
            assert!(
                manifest.args.is_empty(),
                "{module} sidecar must not own args"
            );
            validate_registered_module(&manifest).unwrap();
        }
        for module in [
            "owner-profile",
            "gpu-display-stack",
            "hyprland-desktop",
            "operator-rc-profile",
            "user-session-services",
            "sddm-autologin-hyprland",
            "steam-game-lane",
            "power-controller-maintenance",
            "console-recovery",
            "appliance-proof",
        ] {
            assert!(
                profile.modules.contains(&module.to_string()),
                "missing {module}"
            );
        }
    }

    #[test]
    fn tv_runtime_modules_reject_unsafe_sidecar_values() {
        let root = repo_root();
        let mut manifest =
            load_module(&root.join("profiles/tv/modules/steam-game-lane/sidecar.json")).unwrap();
        manifest.binaries = vec!["steam;touch-/tmp/pwn".to_string()];
        assert!(validate_registered_module(&manifest)
            .unwrap_err()
            .contains("tv-module-binary-value-rejected"));
        manifest.binaries = vec!["steam".to_string()];
        manifest.services = vec!["../../escape.service".to_string()];
        assert!(validate_registered_module(&manifest)
            .unwrap_err()
            .contains("tv-module-service-value-rejected"));
        manifest.services = vec!["power-profiles-daemon.service".to_string()];
        manifest.expected_files = vec!["../escape".to_string()];
        assert!(validate_registered_module(&manifest)
            .unwrap_err()
            .contains("tv-module-expected-path-rejected"));
    }

    #[test]
    fn tv_desktop_config_sidecar_is_constants_only_manifest() {
        let root = repo_root();
        let manifest =
            load_module(&root.join("profiles/tv/modules/desktop-config-payload/sidecar.json"))
                .unwrap();
        assert_eq!(manifest.id, "desktop-config-payload");
        assert_eq!(
            manifest.source_dir.as_deref(),
            Some("profiles/tv/config/desktop-config")
        );
        assert_eq!(manifest.target_dir.as_deref(), Some("/home/owner"));
        assert!(manifest
            .expected_files
            .contains(&".config/hypr/monitors.conf".to_string()));
        assert!(manifest
            .expected_files
            .contains(&"firefox/distribution/policies.json".to_string()));
        assert!(manifest.command.is_none());
        assert!(manifest.args.is_empty());
        validate_registered_module(&manifest).unwrap();
    }

    #[test]
    fn arch_keyring_maintenance_precedes_package_updates_on_arch_profiles() {
        let root = repo_root();
        for profile_path in ["profiles/homeconsole/index.json", "profiles/tv/index.json"] {
            let profile = load_profile(&root.join(profile_path)).unwrap();
            let keyring_pos = profile
                .modules
                .iter()
                .position(|module| module == "arch-keyring-maintenance")
                .expect("profile must include arch-keyring-maintenance");
            let packages_pos = profile
                .modules
                .iter()
                .position(|module| module == "system-packages")
                .expect("profile must include system-packages");
            assert!(keyring_pos < packages_pos);
            let manifest = load_module(
                &root
                    .join(profile_path.replace("index.json", "modules"))
                    .join("arch-keyring-maintenance/sidecar.json"),
            )
            .unwrap();
            assert_eq!(manifest.id, "arch-keyring-maintenance");
            assert!(manifest.packages.contains(&"archlinux-keyring".to_string()));
            assert!(manifest.command.is_none());
            assert!(manifest.args.is_empty());
            validate_registered_module(&manifest).unwrap();
        }
    }

    #[test]
    fn tv_desktop_config_uses_generic_files_convergence_receipt() {
        let root = repo_root();
        let profile = load_profile(&root.join("profiles/tv/index.json")).unwrap();
        let receipts =
            std::env::temp_dir().join(format!("harmonia-tv-files-receipt-{}", process::id()));
        run_profile_engine(
            &profile,
            &root.join("profiles/tv/modules"),
            &receipts,
            false,
        )
        .unwrap();
        let generic = receipts.join("modules/desktop-config-payload/tv-desktop-config-files.json");
        let wrapper =
            receipts.join("modules/desktop-config-payload/tv-desktop-config-install.json");
        assert!(generic.exists());
        assert!(wrapper.exists());
        let generic_text = fs::read_to_string(generic).unwrap();
        assert!(generic_text.contains("harmonia.files.converge.v1"));
        assert!(!generic_text.contains("sha256"));
        assert!(!generic_text.contains("digest"));
        let wrapper_text = fs::read_to_string(wrapper).unwrap();
        assert!(wrapper_text.contains("generic_convergence_receipt"));
        let _ = fs::remove_dir_all(receipts);
    }

    #[test]
    fn deployable_config_export_comes_from_harmonia_profile_tree() {
        let root = repo_root();
        let scratch = std::env::temp_dir().join(format!(
            "harmonia-deployable-config-export-{}",
            process::id()
        ));
        let output = scratch.join("payload");
        let receipts = scratch.join("receipts");
        export_deployable_config(
            &root,
            "homeconsole",
            &output,
            &receipts,
            DeployableConfigMode::Copy,
        )
        .unwrap();
        assert!(output.join("profiles/homeconsole/index.json").exists());
        assert!(output
            .join("profiles/homeconsole/modules/arcadia-gui-runtime/sidecar.json")
            .exists());
        assert!(output
            .join("profiles/homeconsole/modules/pinned-artifacts-runtime/sidecar.json")
            .exists());
        assert!(output
            .join("locks/homeconsole/pinned-artifacts.json")
            .exists());
        assert!(receipts.join("deployable-config-export.json").exists());
        let receipt = fs::read_to_string(receipts.join("deployable-config-export.json")).unwrap();
        assert!(receipt.contains("harmonia.deployable_config_export.v1"));
        assert!(receipt.contains("profile-index"));
        assert!(receipt.contains("module-sidecar"));
        assert!(receipt.contains("profile-lock"));
        assert!(
            !output
                .join("profiles/homeconsole/modules/arcadia-gui-runtime/index.rs")
                .exists(),
            "deployable config export carries constants, not module code"
        );
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn deployable_config_export_rejects_non_harmonia_authority_root() {
        let scratch = std::env::temp_dir().join(format!(
            "harmonia-deployable-config-reject-{}",
            process::id()
        ));
        fs::create_dir_all(scratch.join("profiles/homeconsole")).unwrap();
        fs::write(
            scratch.join("profiles/homeconsole/index.json"),
            r#"{"schema":"harmonia.profile.v1","id":"homeconsole","identity":"homeconsole","modules":[]}"#,
        )
        .unwrap();
        let err = export_deployable_config(
            &scratch,
            "homeconsole",
            &scratch.join("payload"),
            &scratch.join("receipts"),
            DeployableConfigMode::Copy,
        )
        .unwrap_err();
        assert!(err.contains("deployable-config-harmonia-root-rejected"));
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn homeconsole_runtime_modules_require_git_checkout_authority() {
        let root = repo_root();
        for module in [
            "harmonia-runtime",
            "keyman-runtime",
            "homeconsole-sync-runtime",
        ] {
            let manifest = load_module(
                &root
                    .join("profiles/homeconsole/modules")
                    .join(module)
                    .join("sidecar.json"),
            )
            .unwrap();
            assert_eq!(manifest.id, module);
            assert!(
                manifest.repo.is_some(),
                "{module} must carry git checkout source authority"
            );
            if module == "harmonia-runtime" {
                assert_eq!(manifest.source_dir.as_deref(), Some("/opt/harmonia/source"));
                assert_eq!(
                    manifest.install_bin.as_deref(),
                    Some("/usr/local/bin/harmonia")
                );
            } else {
                assert!(manifest.path.is_some());
            }
            validate_registered_module(&manifest).unwrap();
        }
    }

    #[test]
    fn shared_toolbelt_is_callable_by_modules() {
        assert!(tools::get("command").is_some());
        assert!(tools::get("git-artifact").is_some());
        assert!(tools::get("receipt").is_some());
        let root = repo_root();
        let manifest = load_module(
            &root.join("profiles/homeconsole/modules/homeconsole-sync-runtime/sidecar.json"),
        )
        .unwrap();
        assert!(homeconsole_sync_runtime_validate_for_test(&manifest).is_ok());
    }

    #[test]
    fn keyman_store_update_noops_when_checkout_and_store_are_same_path() {
        let root =
            std::env::temp_dir().join(format!("harmonia-keyman-same-path-{}", process::id()));
        fs::create_dir_all(root.join("lib/keyman_installer")).unwrap();
        fs::write(root.join("index.py"), "print('ok')\n").unwrap();
        fs::write(root.join("lib/keyman_installer/index.py"), "print('ok')\n").unwrap();
        fs::write(root.join("keystartup.sh"), "#!/bin/sh\n").unwrap();
        fs::write(root.join("exportkey.sh"), "#!/bin/sh\n").unwrap();
        let changed = sync_directory(&root, &root).unwrap();
        assert!(!changed);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn profile_ledger_is_one_append_only_jsonl_per_profile() {
        let root = std::env::temp_dir().join(format!("harmonia-ledger-{}", process::id()));
        let first_receipt = root.join("runs/first");
        let second_receipt = root.join("runs/second");
        let profile = Profile {
            id: "homeconsole".into(),
            identity: "homeconsole".into(),
            modules: vec!["identity".into()],
        };
        append_profile_ledger_entry(
            &first_receipt,
            &profile,
            ProfileLedgerEntry {
                run_id: "run-one",
                module_id: "identity",
                ok: true,
                changed: false,
                operation_count: 1,
                first_missing_signal: "none",
                receipt_dir: &first_receipt,
            },
        )
        .unwrap();
        append_profile_ledger_entry(
            &second_receipt,
            &profile,
            ProfileLedgerEntry {
                run_id: "run-two",
                module_id: "identity",
                ok: false,
                changed: false,
                operation_count: 0,
                first_missing_signal: "identity-failed",
                receipt_dir: &second_receipt,
            },
        )
        .unwrap();
        let ledger = root.join("runs/homeconsole-ledger.jsonl");
        assert!(ledger.exists());
        let lines = fs::read_to_string(&ledger).unwrap();
        let entries: Vec<serde_json::Value> = lines
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["sequence"], 1);
        assert_eq!(entries[1]["sequence"], 2);
        assert_eq!(entries[0]["run_id"], "run-one");
        assert_eq!(entries[1]["first_missing_signal"], "identity-failed");
        let ledgers: Vec<_> = fs::read_dir(root.join("runs"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().and_then(|e| e.to_str()) == Some("jsonl"))
            .collect();
        assert_eq!(ledgers.len(), 1, "only one profile ledger should exist");
        let _ = fs::remove_dir_all(root);
    }
}

pub(crate) fn run(args: Vec<String>) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("explain") => explain(),
        Some("toolbelt") | Some("list-tools") => toolbelt(),
        Some("inspect-profile") => {
            let path = args
                .get(1)
                .ok_or("inspect-profile requires <profile-index-json>")?;
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            println!("schema=harmonia.profile.inspect.v1");
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
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            write_plan_receipts(&profile, &receipt_dir).map_err(|e| e.to_string())?;
            println!("schema=harmonia.plan_run.v1");
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
            let apply = args.iter().any(|arg| arg == "--apply");
            let module_root = default_module_root(Path::new(path));
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            run_profile_engine(&profile, &module_root, &receipt_dir, apply)
        }
        Some("deployable-config") => {
            let action = args
                .get(1)
                .ok_or("deployable-config requires export <profile-id>")?;
            if action != "export" {
                return Err(format!("deployable-config-action-unsupported-{action}"));
            }
            let profile_id = args
                .get(2)
                .ok_or("deployable-config export requires <profile-id>")?;
            let output_dir = value_arg(&args, "--out")
                .ok_or("deployable-config export requires --out <path>")?;
            let harmonia_root =
                value_arg(&args, "--harmonia-root").unwrap_or_else(|| PathBuf::from("."));
            let receipt_dir = receipt_dir_arg(&args).unwrap_or_else(|| output_dir.join("receipts"));
            let mode = DeployableConfigMode::parse(value_arg_string(&args, "--mode"))?;
            export_deployable_config(&harmonia_root, profile_id, &output_dir, &receipt_dir, mode)
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
        Some("homeconsole-sync") => {
            let path = args
                .get(1)
                .ok_or("homeconsole-sync requires <profile-index-json>")?;
            let receipt_dir = receipt_dir_arg(&args).unwrap_or_else(|| {
                PathBuf::from("/var/lib/harmonia/receipts/homeconsole-sync-latest")
            });
            let apply = args.iter().any(|arg| arg == "--apply");
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            let module_path = value_arg(&args, "--module").unwrap_or_else(|| {
                default_module_root(Path::new(path))
                    .join("sync")
                    .join("index.json")
            });
            let provider_env_override = value_arg(&args, "--provider-env");
            let adapter_override = value_arg_string(&args, "--adapter-command");
            homeconsole_sync(
                &profile,
                &receipt_dir,
                &module_path,
                provider_env_override.as_deref(),
                adapter_override.as_deref(),
                apply,
            )
        }
        Some("homeconsole-update") => {
            let path = args
                .get(1)
                .ok_or("homeconsole-update requires <profile-index-json>")?;
            let receipt_dir = receipt_dir_arg(&args)
                .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/receipts/latest"));
            let apply = args.iter().any(|arg| arg == "--apply");
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            let module_root = default_module_root(Path::new(path));
            homeconsole_update(&profile, &module_root, &receipt_dir, apply)
        }
        Some("homeconsole-keyman-update") => {
            let path = args
                .get(1)
                .ok_or("homeconsole-keyman-update requires <profile-index-json>")?;
            let receipt_dir = receipt_dir_arg(&args)
                .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/receipts/keyman-latest"));
            let source =
                value_arg(&args, "--source").unwrap_or_else(|| PathBuf::from("/opt/keyman/source"));
            let store_dir = value_arg(&args, "--store-dir")
                .unwrap_or_else(|| PathBuf::from("/opt/keyman/source"));
            let runtime_dir =
                value_arg(&args, "--runtime-dir").unwrap_or_else(|| PathBuf::from("/vault/keyman"));
            let vault_dir =
                value_arg(&args, "--vault-dir").unwrap_or_else(|| PathBuf::from("/vault"));
            let key_dir =
                value_arg(&args, "--key-dir").unwrap_or_else(|| PathBuf::from("/root/key"));
            let exchange_dir = value_arg(&args, "--exchange-dir")
                .unwrap_or_else(|| PathBuf::from("/mnt/keyexchange"));
            let apply = args.iter().any(|arg| arg == "--apply");
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            homeconsole_keyman_update(
                &profile,
                &receipt_dir,
                &source,
                &store_dir,
                &runtime_dir,
                &vault_dir,
                &key_dir,
                &exchange_dir,
                apply,
            )
        }
        Some("homeconsole-local-ai-update") => {
            let path = args
                .get(1)
                .ok_or("homeconsole-local-ai-update requires <profile-index-json>")?;
            let receipt_dir = receipt_dir_arg(&args).unwrap_or_else(|| {
                PathBuf::from("/var/lib/harmonia/receipts/local-ai-runtime-latest")
            });
            let apply = args.iter().any(|arg| arg == "--apply");
            let module_root = default_module_root(Path::new(path));
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            if profile.id != "homeconsole" || profile.identity != "homeconsole" {
                return Err(format!(
                    "homeconsole-local-ai-update requires homeconsole/homeconsole profile, got {}/{}",
                    profile.id, profile.identity
                ));
            }
            let module = load_module(&module_root.join("local-ai-runtime").join("sidecar.json"))?;
            let execution = execute_profile_module(&module, &receipt_dir, apply)?;
            write_engine_run_receipt(
                &receipt_dir,
                &profile,
                apply,
                execution.ok,
                execution.changed,
                1,
                execution.operation_count,
                execution.first_missing_signal.as_deref().unwrap_or("none"),
                &module_root,
            )?;
            println!("schema=harmonia.local_ai_runtime.v1");
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
            let source_sha_file = value_arg(&args, "--source-sha-file")
                .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/state/arcadia.sha"));
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
                &source_sha_file,
            )
        }
        Some("homeconsole-arcadia-gui-update") => {
            let path = args
                .get(1)
                .ok_or("homeconsole-arcadia-gui-update requires <profile-index-json>")?;
            let receipt_dir = receipt_dir_arg(&args)
                .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/receipts/arcadia-gui-latest"));
            let repo = value_arg_string(&args, "--repo")
                .unwrap_or_else(|| "https://git.home.arpa/HOMESERVERSLTD/arcadia.git".to_string());
            let branch = value_arg_string(&args, "--branch").unwrap_or_else(|| "main".to_string());
            let source_dir = value_arg(&args, "--source-dir")
                .unwrap_or_else(|| PathBuf::from("/opt/arcadia/source"));
            let install_bin = value_arg(&args, "--install-bin")
                .unwrap_or_else(|| PathBuf::from("/usr/local/bin/arcadia"));
            let service = value_arg(&args, "--service")
                .and_then(|p| p.to_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "arcadia.service".to_string());
            let source_sha_file = value_arg(&args, "--source-sha-file")
                .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/state/arcadia.sha"));
            let apply = args.iter().any(|arg| arg == "--apply");
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            homeconsole_arcadia_gui_update(
                &profile,
                &receipt_dir,
                &repo,
                &branch,
                &source_dir,
                &install_bin,
                &service,
                apply,
                &source_sha_file,
            )
        }
        _ => usage(),
    }
}

pub(crate) fn toolbelt() -> Result<(), String> {
    println!("schema=harmonia.toolbelt.v1");
    println!("ok=true");
    println!("tool_count={}", tools::all().len());
    for tool in tools::all() {
        println!("tool={} description={}", tool.name, tool.description);
    }
    Ok(())
}

pub(crate) fn explain() -> Result<(), String> {
    println!("schema=harmonia.explain.v1");
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

pub(crate) fn usage() -> Result<(), String> {
    println!("harmonia {}", VERSION);
    println!("usage:");
    println!("  harmonia explain");
    println!("  harmonia inspect-profile <profiles/<id>/index.json>");
    println!("  harmonia toolbelt");
    println!("  harmonia plan-run <profiles/<id>/index.json> [--receipt-dir <path>]");
    println!("  harmonia run-profile <profiles/<id>/index.json> [--apply] [--receipt-dir <path>]");
    println!("  harmonia deployable-config export <profile-id> --out <path> [--harmonia-root <path>] [--mode copy|symlink] [--receipt-dir <path>]");
    println!("  harmonia pinned-artifacts check <profiles/<id>/index.json> [--lock <path>] [--receipt-dir <path>]");
    println!("  harmonia pinned-artifacts nudge <profiles/<id>/index.json> --lock <path> --artifact <name> --candidate <path> --version <version> --sha256 <sha256> [--receipt-dir <path>]");
    println!("  harmonia pinned-artifacts bless <profiles/<id>/index.json> --lock <path> --artifact <name> --candidate <path> --version <version> --sha256 <sha256> [--install-path <path>] [--apply] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-update <profiles/homeconsole/index.json> [--apply] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-sync <profiles/homeconsole/index.json> [--module <profiles/homeconsole/modules/sync/sidecar.json>] [--provider-env <path>] [--adapter-command <path>] [--apply] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-keyman-update <profiles/homeconsole/index.json> --source <keyman-source> [--apply] [--store-dir /opt/keyman/source] [--runtime-dir /vault/keyman] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-local-ai-update <profiles/homeconsole/index.json> [--apply] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-arcadia-check <profiles/homeconsole/index.json> [--repo <url>] [--branch main] [--current-sha-file <path>] [--upstream-sha-file <path>] [--insecure-tls] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-arcadia-update <profiles/homeconsole/index.json> --artifact <path> [--apply] [--install-bin <path>] [--service arcadia.service] [--source-sha <sha>] [--source-sha-file <path>] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-arcadia-gui-update <profiles/homeconsole/index.json> [--repo <url>] [--branch main] [--source-dir /opt/arcadia/source] [--apply] [--install-bin <path>] [--service arcadia.service] [--source-sha-file <path>] [--receipt-dir <path>]");
    Ok(())
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
