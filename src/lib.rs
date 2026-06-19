pub mod tools;
pub(crate) use tools::module_steps::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
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

mod cli;
mod homeconsole;
mod modules;
mod profile_engine;
mod receipts;

pub(crate) use cli::*;
pub(crate) use homeconsole::*;
pub(crate) use modules::*;
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
    }

    #[test]
    fn rejects_old_console_identity_names() {
        let old = Profile {
            id: "homeconsole".into(),
            identity: format!("{}-{}", "arch", "console"),
            modules: HOMECONSOLE_UPDATE_SUITE_MODULES
                .iter()
                .map(|m| m.to_string())
                .collect(),
        };
        assert!(
            homeconsole_update(&old, &PathBuf::from("target/unused"), false)
                .unwrap_err()
                .contains("homeconsole/homeconsole")
        );
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
            source_sha_file: None,
            packages: vec![],
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
            HOMECONSOLE_UPDATE_SUITE_MODULES
                .iter()
                .map(|m| m.to_string())
                .collect::<Vec<_>>()
        );
        enforce_homeconsole_update_suite(&profile).unwrap();
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
    fn homeconsole_runtime_modules_require_git_checkout_authority() {
        let root = repo_root();
        for module in ["keyman-runtime", "homeconsole-sync-runtime"] {
            let manifest = load_module(
                &root
                    .join("profiles/homeconsole/modules")
                    .join(module)
                    .join("sidecar.json"),
            )
            .unwrap();
            assert_eq!(manifest.id, module);
            assert!(manifest.path.is_some());
            assert!(
                manifest.repo.is_some(),
                "{module} must carry git checkout source authority"
            );
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
}
