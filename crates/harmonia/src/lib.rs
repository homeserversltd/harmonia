mod tools;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::process::{self};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Profile {
    id: String,
    family: String,
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
    source_sha_file: Option<String>,
    #[serde(default)]
    packages: Vec<String>,
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

mod arcadia;
mod cli;
mod homeconsole;
mod keyman;
mod modules;
mod pinned_artifacts;
mod profile_engine;
mod receipts;
mod step_tools;
mod sync;

pub(crate) use arcadia::*;
pub(crate) use cli::*;
pub(crate) use homeconsole::*;
pub(crate) use keyman::*;
pub(crate) use modules::*;
pub(crate) use pinned_artifacts::*;
pub(crate) use profile_engine::*;
pub(crate) use receipts::*;
pub(crate) use step_tools::*;
pub(crate) use sync::*;

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
    use std::path::{Path, PathBuf};

    #[test]
    fn extracts_profile_fields() {
        let text =
            r#"{"id":"homeconsole","family":"arch-console","modules":["identity","packages"]}"#;
        assert_eq!(extract_string(text, "id").unwrap(), "homeconsole");
        assert_eq!(extract_string(text, "family").unwrap(), "arch-console");
        assert_eq!(
            extract_string_array(text, "modules"),
            vec!["identity", "packages"]
        );
    }

    #[test]
    fn detects_pacman_change_from_stdout() {
        assert!(pacman_stdout_indicates_change("\nupgrading ffmpeg..."));
        assert!(!pacman_stdout_indicates_change(" there is nothing to do"));
    }

    #[test]
    fn default_module_root_from_profile_path() {
        assert_eq!(
            default_module_root(Path::new("profiles/homeconsole/index.json")),
            PathBuf::from("modules/homeconsole")
        );
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
    fn keyman_source_shape_requires_public_installer_files() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let shape = keyman_source_shape(&root);
        assert!(!shape.0);
        assert!(shape.1.get("index_py_present").is_some());
    }

    #[test]
    fn parses_provider_env_without_exposing_values() {
        let path =
            std::env::temp_dir().join(format!("harmonia-provider-env-{}.env", process::id()));
        fs::write(
            &path,
            "STEAMGRIDDB_API_KEY=secret\nexport TGDB_API_KEY=also-secret\n",
        )
        .unwrap();
        let values = parse_env_file(&path);
        let providers = vec![SyncProviderConfig {
            name: "steamgriddb".to_string(),
            env_keys: vec!["STEAMGRIDDB_API_KEY".to_string()],
            required: false,
        }];
        let receipts = sync_provider_receipts(&providers, &values);
        assert!(receipts[0].configured);
        assert_eq!(receipts[0].env_keys, vec!["STEAMGRIDDB_API_KEY"]);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn module_sidecar_rejects_legacy_steps_ladder() {
        let receipt_dir =
            std::env::temp_dir().join(format!("harmonia-legacy-steps-{}", process::id()));
        let module_dir = receipt_dir.join("module");
        fs::create_dir_all(&module_dir).unwrap();
        let module_path = module_dir.join("index.json");
        fs::write(
            &module_path,
            r#"{"schema":"harmonia.module.v1","id":"identity","steps":[{"id":"uname","tool":"command","action":"run"}]}"#,
        )
        .unwrap();
        let err = load_module(&module_path).unwrap_err();
        assert!(err.contains("module-json-steps-rejected"));
        let _ = fs::remove_dir_all(receipt_dir);
    }

    #[test]
    fn unregistered_modules_are_rejected_before_sidecar_can_define_work() {
        let module = ModuleManifest {
            id: "json-invented-module".into(),
            description: "sidecar-only module".into(),
            command: Some("/usr/bin/true".into()),
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
            source_sha_file: None,
            packages: vec![],
        };
        assert_eq!(
            validate_registered_module(&module).unwrap_err(),
            "module-unregistered-json-invented-module"
        );
    }

    #[test]
    fn homeconsole_profile_contains_only_registered_rust_modules() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let profile = load_profile(&root.join("profiles/homeconsole/index.json")).unwrap();
        assert_eq!(
            profile.modules,
            vec![
                "identity",
                "system-packages",
                "harmonia-runtime",
                "keyman-runtime",
                "homeconsole-sync-runtime",
                "rust-build-toolchain",
                "arcadia-gui-runtime",
                "pinned-artifacts-runtime",
            ]
        );
        enforce_homeconsole_update_suite(&profile).unwrap();
        for module in &profile.modules {
            let manifest = load_module(
                &root
                    .join("modules/homeconsole")
                    .join(module)
                    .join("index.json"),
            )
            .unwrap();
            validate_registered_module(&manifest).unwrap();
        }
        for removed in [
            "desktop-appliance",
            "game-library",
            "pinned-artifacts",
            "receipts",
        ] {
            assert!(
                !root
                    .join("modules/homeconsole")
                    .join(removed)
                    .join("index.json")
                    .exists(),
                "{removed} placeholder module must stay obliterated"
            );
        }
    }

    #[test]
    fn homeconsole_runtime_payload_modules_do_not_require_git_checkouts() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for module in ["keyman-runtime", "homeconsole-sync-runtime"] {
            let manifest = load_module(
                &root
                    .join("modules/homeconsole")
                    .join(module)
                    .join("index.json"),
            )
            .unwrap();
            assert_eq!(manifest.id, module);
            assert!(manifest.path.is_some());
            assert!(
                manifest.repo.is_none(),
                "{module} is a copied/exported runtime payload module, not a git checkout requirement"
            );
            validate_registered_module(&manifest).unwrap();
        }
    }

    #[test]
    fn keyman_payload_sync_noops_when_source_and_store_are_same_path() {
        let root =
            std::env::temp_dir().join(format!("harmonia-keyman-same-path-{}", process::id()));
        fs::create_dir_all(root.join("lib/keyman_installer")).unwrap();
        fs::write(root.join("index.py"), "print('ok')\n").unwrap();
        fs::write(root.join("lib/keyman_installer/index.py"), "print('ok')\n").unwrap();
        fs::write(root.join("keystartup.sh"), "#!/bin/sh\n").unwrap();
        fs::write(root.join("exportkey.sh"), "#!/bin/sh\n").unwrap();

        let changed = sync_directory(&root, &root).unwrap();
        assert!(!changed);
        assert!(root.join("index.py").is_file());
        assert!(root.join("lib/keyman_installer/index.py").is_file());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tv_profile_base_and_payload_authority_are_declared() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let profile = load_profile(&root.join("profiles/tv/index.json")).unwrap();
        assert_eq!(profile.id, "tv");
        assert_eq!(profile.family, "arch-tv");
        assert_eq!(profile.modules, vec!["identity", "system-packages"]);
        assert!(
            !profile.modules.contains(&"arcadia-gui-runtime".to_string()),
            "TV profile must not inherit HomeConsole product runtimes"
        );
        assert!(
            !profile
                .modules
                .contains(&"homeconsole-sync-runtime".to_string()),
            "TV profile must not inherit HomeConsole sync runtime"
        );
        for module in &profile.modules {
            let manifest =
                load_module(&root.join("modules/tv").join(module).join("index.json")).unwrap();
            validate_registered_module(&manifest).unwrap();
        }

        let authority: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(root.join("payloads/tv/index.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(authority["schema"], "harmonia.tv.payload-authority.v1");
        assert_eq!(authority["authority"], "harmonia");
        assert!(authority["make_modern_boundary"]
            .as_str()
            .unwrap()
            .contains("Make Modern owns only"));
        assert!(authority["deployable_consumption"]["allowed_modes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|mode| mode == "declared-export-vendor-with-receipt"));
        assert!(authority["owned_surfaces"]
            .as_array()
            .unwrap()
            .iter()
            .any(|surface| surface == "desktop-config-payload"));
        assert!(authority["desktop_payload_paths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|path| path == ".config/waybar/waybar.conf"));
        assert_eq!(
            authority["deployable_consumption"]["forbidden"],
            "two-hand-maintained-payload-trees"
        );
    }
}
