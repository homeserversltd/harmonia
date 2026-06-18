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
    steps: Vec<Step>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Step {
    id: String,
    tool: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    artifact: Option<String>,
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
    apply_only: bool,
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
struct StepOutcome {
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
    fn generic_ack_pseudo_tools_do_not_turn_green() {
        let step = Step {
            id: "fake-contract".into(),
            tool: "config".into(),
            action: "ack".into(),
            command: None,
            args: vec![],
            cwd: None,
            service: None,
            artifact: None,
            install_bin: None,
            url: None,
            expected_contains: None,
            repo: None,
            path: None,
            branch: None,
            remote: None,
            apply_only: false,
        };
        let receipt_dir =
            std::env::temp_dir().join(format!("harmonia-no-pseudo-tool-{}", process::id()));
        let outcome = execute_step(&step, &receipt_dir, false).unwrap();
        assert!(!outcome.ok);
        assert!(outcome.message.contains("unknown tool config"));
        let _ = fs::remove_dir_all(receipt_dir);
    }

    #[test]
    fn unregistered_modules_are_rejected_before_json_can_define_work() {
        let module = ModuleManifest {
            id: "json-invented-module".into(),
            description: "manifest-only module".into(),
            steps: vec![Step {
                id: "fake-step".into(),
                tool: "command".into(),
                action: "run".into(),
                command: Some("/usr/bin/true".into()),
                args: vec![],
                cwd: None,
                service: None,
                artifact: None,
                install_bin: None,
                url: None,
                expected_contains: None,
                repo: None,
                path: None,
                branch: None,
                remote: None,
                apply_only: false,
            }],
        };
        assert_eq!(
            validate_registered_module(&module).unwrap_err(),
            "module-unregistered-json-invented-module"
        );
    }

    #[test]
    fn homeconsole_profile_contains_only_executable_run_profile_modules() {
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
            assert!(
                !manifest.steps.is_empty(),
                "profile module {module} must have executable steps"
            );
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
    fn homeconsole_update_refuses_partial_suite_spine() {
        let profile = Profile {
            id: "homeconsole".into(),
            family: "arch-console".into(),
            modules: vec!["identity".into(), "system-packages".into()],
        };
        let err = enforce_homeconsole_update_suite(&profile).unwrap_err();
        assert!(err.contains("homeconsole-update-suite-spine-mismatch"));
        assert!(err.contains("harmonia-runtime"));
        assert!(err.contains("pinned-artifacts-runtime"));
    }
}
