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
    package_authority: Option<PackageAuthority>,
    #[serde(default)]
    modules: Vec<String>,
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
struct ManagedFileManifest {
    path: String,
    content: String,
    #[serde(default)]
    mode: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CaduceusProfileSourceManifest {
    source: String,
    path: String,
    #[serde(default)]
    mode: Option<u32>,
    #[serde(default)]
    insert_after_profile: String,
    #[serde(default)]
    insert_after_mode: String,
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
    source_sha_file: Option<String>,
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

mod arcadia_gui_runtime;
mod homeconsole_sync_runtime;
mod keyman_runtime;
mod pinned_artifacts_runtime;

pub(crate) use arcadia_gui_runtime::{
    homeconsole_arcadia_check, homeconsole_arcadia_gui_update, homeconsole_arcadia_update,
};
pub(crate) use homeconsole_sync_runtime::homeconsole_sync;
pub(crate) use keyman_runtime::homeconsole_keyman_update;
#[cfg(test)]
pub(crate) use keyman_runtime::{redact_secret_text, sync_directory};
pub(crate) use pinned_artifacts_runtime::pinned_artifacts_command;

mod capsule;
mod convergence_lock;
mod device_profile;
mod deployable_config;
mod ladder;
mod module_dispatch;
mod preflight;
mod profile_engine;
mod receipts;
mod subscription;

pub(crate) use capsule::*;
pub(crate) use convergence_lock::*;
pub(crate) use device_profile::*;
pub(crate) use deployable_config::*;
pub(crate) use ladder::*;
pub(crate) use module_dispatch::*;
pub(crate) use preflight::*;
pub(crate) use profile_engine::*;
pub(crate) use receipts::*;
pub(crate) use subscription::*;

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
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
    }

    fn assert_lawful_profile_module(dir: &Path, module: &str) {
        assert!(
            lawful_module_manifest_exists(dir),
            "{module} needs sidecar+index.rs or ladder manifest"
        );
        let sidecar = dir.join("sidecar.json");
        if sidecar.exists() {
            let manifest = load_module(&sidecar).unwrap();
            validate_registered_module(&manifest).unwrap();
        } else {
            let manifest = load_ladder_manifest(&dir.join("manifest.json")).unwrap();
            assert_eq!(manifest.id, module);
            validate_ladder(&manifest).unwrap();
        }
    }

    #[test]
    fn every_profile_spine_module_resolves_to_valid_ladder_manifest() {
        let profiles_root = repo_root().join("profiles");
        let mut checked = Vec::new();
        for entry in fs::read_dir(&profiles_root).unwrap() {
            let entry = entry.unwrap();
            if !entry.file_type().unwrap().is_dir() {
                continue;
            }
            let profile_path = entry.path().join("index.json");
            if !profile_path.exists() {
                continue;
            }
            let profile = load_profile(&profile_path).unwrap();
            let module_root = entry.path().join("modules");
            for module_id in &profile.modules {
                let module_dir = module_root.join(module_id);
                let manifest_path = module_dir.join("manifest.json");
                assert!(
                    manifest_path.exists(),
                    "profile {} module {} must carry manifest.json at {}",
                    profile.id,
                    module_id,
                    manifest_path.display()
                );
                assert!(
                    is_ladder_manifest(&manifest_path),
                    "profile {} module {} must be a ladder manifest",
                    profile.id,
                    module_id
                );
                let manifest = load_ladder_manifest(&manifest_path).unwrap();
                assert_eq!(manifest.id, *module_id);
                validate_ladder(&manifest).unwrap();
                checked.push(format!("{}/{}", profile.id, module_id));
            }
        }
        assert!(
            !checked.is_empty(),
            "profile spine invariant checked no modules"
        );
    }

    static PACMAN_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn with_fake_pacman<T>(scratch: &Path, f: impl FnOnce() -> T) -> T {
        let _guard = PACMAN_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("pacman env lock");
        let fake = scratch.join("fake-pacman");
        fs::create_dir_all(scratch).unwrap();
        fs::write(
            &fake,
            "#!/usr/bin/env sh\ncase \"$1\" in\n  -Qu) exit 0 ;;\n  -Q) if [ \"$2\" = \"oh-my-posh-bin\" ]; then echo 'oh-my-posh-bin 29.20.1-1'; fi; exit 0 ;;\n  -Syu) echo 'there is nothing to do'; exit 0 ;;\n  -S) echo 'there is nothing to do'; exit 0 ;;\n  -U) echo 'installed local package'; exit 0 ;;\n  *) exit 0 ;;\nesac\n",
        )
        .unwrap();
        #[cfg(unix)]
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        let upstream = scratch.join("aur-upstream.json");
        fs::write(
            &upstream,
            serde_json::json!({
                "schema": "harmonia.aur.upstream_state.v1",
                "package": "oh-my-posh-bin",
                "available_version": "29.20.1-1",
                "pkgbuild_sha": "ed800be1c781d41ce83ce6e693d6e00e868883c9",
                "observed_source": "test-seam"
            })
            .to_string(),
        )
        .unwrap();
        set_test_pacman_path(Some(fake.display().to_string()));
        crate::tools::aur::set_test_upstream_state_path(Some(upstream.display().to_string()));
        let result = f();
        crate::tools::aur::set_test_upstream_state_path(None);
        set_test_pacman_path(None);
        result
    }

    #[test]
    fn corrupt_profile_index_is_loud_parse_error() {
        let scratch =
            std::env::temp_dir().join(format!("harmonia-corrupt-profile-{}", process::id()));
        fs::create_dir_all(&scratch).unwrap();
        let profile_path = scratch.join("index.json");
        fs::write(
            &profile_path,
            r#"{"id":"tv","identity":"arch-tv","modules":["identity",]}"#,
        )
        .unwrap();
        let err = load_profile(&profile_path).unwrap_err().to_string();
        assert!(err.contains("profile-parse-failed"));
        assert!(err.contains(profile_path.to_str().unwrap()));
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn plan_run_accepts_legacy_profile_without_package_authority() {
        let scratch = std::env::temp_dir().join(format!(
            "harmonia-legacy-profile-plan-run-{}",
            process::id()
        ));
        let _ = fs::remove_dir_all(&scratch);
        let profile_path = scratch.join("index.json");
        fs::create_dir_all(scratch.join("modules/identity")).unwrap();
        fs::write(
            &profile_path,
            r#"{"id":"legacy","identity":"legacy","modules":["identity"]}"#,
        )
        .unwrap();
        fs::write(
            scratch.join("modules/identity/sidecar.json"),
            r#"{"id":"identity"}"#,
        )
        .unwrap();

        run(vec![
            "plan-run".into(),
            profile_path.display().to_string(),
            "--receipt-dir".into(),
            scratch.join("receipts").display().to_string(),
        ])
        .unwrap();
        let receipt = fs::read_to_string(scratch.join("receipts/run.json")).unwrap();
        assert!(receipt.contains("\"ok\": true"));
        assert!(receipt.contains("\"profile_id\": \"legacy\""));
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn empty_profile_spine_writes_false_run_receipt() {
        let scratch = std::env::temp_dir().join(format!("harmonia-empty-spine-{}", process::id()));
        let module_root = scratch.join("modules");
        let receipts = scratch.join("receipts");
        fs::create_dir_all(&module_root).unwrap();
        let profile = Profile {
            package_authority: None,
            id: "hollow".into(),
            identity: "hollow".into(),
            modules: vec![],
        };
        let err = run_profile_engine(&profile, &module_root, &receipts, false).unwrap_err();
        assert_eq!(err, "profile-modules-empty");
        let run = fs::read_to_string(receipts.join("run.json")).unwrap();
        assert!(run.contains("\"ok\": false"));
        assert!(run.contains("profile-modules-empty"));
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn plan_receipt_validates_module_sidecars_before_green() {
        let scratch =
            std::env::temp_dir().join(format!("harmonia-plan-validates-{}", process::id()));
        let module_root = scratch.join("modules");
        let receipts = scratch.join("receipts");
        fs::create_dir_all(module_root.join("missing-sidecar")).unwrap();
        let profile = Profile {
            package_authority: None,
            id: "plan".into(),
            identity: "plan".into(),
            modules: vec!["missing-sidecar".into()],
        };
        write_plan_receipts(&profile, &module_root, &receipts).unwrap();
        let run = fs::read_to_string(receipts.join("run.json")).unwrap();
        assert!(run.contains("\"ok\": false"));
        assert!(run.contains("module-missing-missing-sidecar"));
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn command_tool_records_unknown_change_observation() {
        let scratch =
            std::env::temp_dir().join(format!("harmonia-command-unknown-{}", process::id()));
        let outcome = command_tool(&scratch, "true-command", "/usr/bin/true", &[], None).unwrap();
        assert!(outcome.ok);
        assert!(!outcome.changed);
        let receipt = fs::read_to_string(scratch.join("true-command.json")).unwrap();
        assert!(receipt.contains("change_observed"));
        assert!(receipt.contains("unknown"));
        let _ = fs::remove_dir_all(scratch);
    }

    #[cfg(unix)]
    #[test]
    fn machine_id_truncate_zeroes_file_and_receipts_no_reboot() {
        let scratch = std::env::temp_dir().join(format!("harmonia-machine-id-{}", process::id()));
        let etc = scratch.join("etc-machine-id");
        let dbus = scratch.join("dbus-machine-id");
        let receipts = scratch.join("receipts");
        fs::create_dir_all(&scratch).unwrap();
        fs::write(&etc, "0123456789abcdef0123456789abcdef\n").unwrap();
        symlink(&etc, &dbus).unwrap();

        let outcome = tools::machine_id::truncate(
            &receipts,
            "truncate-machine-id",
            Some(etc.to_str().unwrap()),
            Some(dbus.to_str().unwrap()),
            true,
        )
        .unwrap();

        assert!(outcome.ok);
        assert!(outcome.changed);
        assert_eq!(fs::metadata(&etc).unwrap().len(), 0);
        let receipt = fs::read_to_string(receipts.join("truncate-machine-id.json")).unwrap();
        assert!(receipt.contains("harmonia.machine_id_truncate_receipt.v1"));
        assert!(receipt.contains("old machine-id is gone"));
        assert!(receipt.contains("\"reboot_performed\": false"));
        let _ = fs::remove_dir_all(scratch);
    }

    #[cfg(unix)]
    #[test]
    fn machine_id_truncate_is_idempotent_when_already_empty() {
        let scratch =
            std::env::temp_dir().join(format!("harmonia-machine-id-empty-{}", process::id()));
        let etc = scratch.join("etc-machine-id");
        let dbus = scratch.join("dbus-machine-id");
        let receipts = scratch.join("receipts");
        fs::create_dir_all(&scratch).unwrap();
        fs::write(&etc, "").unwrap();
        symlink(&etc, &dbus).unwrap();

        let outcome = tools::machine_id::truncate(
            &receipts,
            "truncate-machine-id",
            Some(etc.to_str().unwrap()),
            Some(dbus.to_str().unwrap()),
            true,
        )
        .unwrap();

        assert!(outcome.ok);
        assert!(!outcome.changed);
        assert_eq!(fs::metadata(&etc).unwrap().len(), 0);
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn parked_machine_id_module_is_valid_and_unreferenced_by_profiles() {
        let root = repo_root();
        let manifest_path = root.join("profiles/_parked/modules/machine-id-truncate/manifest.json");
        let manifest = load_ladder_manifest(&manifest_path).unwrap();
        assert_eq!(manifest.id, "machine-id-truncate");
        validate_ladder(&manifest).unwrap();

        for profile_id in ["homeserver", "homeconsole", "rebis", "tv"] {
            let text =
                fs::read_to_string(root.join("profiles").join(profile_id).join("index.json"))
                    .unwrap();
            let profile: Profile = serde_json::from_str(&text).unwrap();
            assert!(
                !profile
                    .modules
                    .iter()
                    .any(|module| module == "machine-id-truncate"),
                "{profile_id} must not arm machine-id-truncate"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn machine_id_truncate_refuses_divergent_dbus_regular_file() {
        let scratch =
            std::env::temp_dir().join(format!("harmonia-machine-id-diverge-{}", process::id()));
        let etc = scratch.join("etc-machine-id");
        let dbus = scratch.join("dbus-machine-id");
        let receipts = scratch.join("receipts");
        fs::create_dir_all(&scratch).unwrap();
        fs::write(&etc, "0123456789abcdef0123456789abcdef\n").unwrap();
        fs::write(&dbus, "fedcba9876543210fedcba9876543210\n").unwrap();

        let outcome = tools::machine_id::truncate(
            &receipts,
            "truncate-machine-id",
            Some(etc.to_str().unwrap()),
            Some(dbus.to_str().unwrap()),
            true,
        )
        .unwrap();

        assert!(!outcome.ok);
        assert!(!outcome.changed);
        assert!(outcome.message.contains("dbus-machine-id-divergent"));
        assert!(fs::read_to_string(&etc).unwrap().starts_with("012345"));
        let receipt = fs::read_to_string(receipts.join("truncate-machine-id.json")).unwrap();
        assert!(receipt.contains("regular-file"));
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn artifact_promote_detects_equal_length_byte_change_by_sha256() {
        let scratch = std::env::temp_dir().join(format!("harmonia-artifact-sha-{}", process::id()));
        let receipts = scratch.join("receipts");
        let artifact = scratch.join("artifact.bin");
        let install = scratch.join("install.bin");
        fs::create_dir_all(&scratch).unwrap();
        fs::write(&artifact, b"BBBB").unwrap();
        fs::write(&install, b"AAAA").unwrap();
        let outcome =
            artifact_promote_tool(&receipts, "artifact-promote", &artifact, &install, true)
                .unwrap();
        assert!(outcome.ok);
        assert!(outcome.changed);
        assert_eq!(fs::read(&install).unwrap(), b"BBBB");
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn git_artifact_invalid_repo_rev_parse_failure_is_not_changed() {
        let scratch = std::env::temp_dir().join(format!("harmonia-git-invalid-{}", process::id()));
        let target = scratch.join("repo");
        fs::create_dir_all(target.join(".git")).unwrap();
        let request =
            tools::git_artifact::Request::new(None, target, "main".into(), "origin".into());
        let outcome = tools::git_artifact::apply(&request);
        assert!(!outcome.ok);
        assert!(!outcome.changed);
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn files_convergence_error_path_still_writes_partial_receipt() {
        let scratch =
            std::env::temp_dir().join(format!("harmonia-files-error-receipt-{}", process::id()));
        let source = scratch.join("source");
        let target = scratch.join("target");
        let receipts = scratch.join("receipts");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::write(source.join("first.conf"), "first-new\n").unwrap();
        fs::write(source.join("second.conf"), "second-new\n").unwrap();
        fs::write(target.join("first.conf"), "first-old\n").unwrap();
        fs::create_dir_all(target.join("second.conf")).unwrap();
        let request = tools::files::FileConvergenceRequest {
            source_root: source,
            target_root: target,
            files: vec![
                tools::files::FileSpec {
                    relative_path: PathBuf::from("first.conf"),
                    mode: Some(0o644),
                },
                tools::files::FileSpec {
                    relative_path: PathBuf::from("second.conf"),
                    mode: Some(0o644),
                },
            ],
            backup_existing: false,
            receipt_name: "partial".to_string(),
        };
        let err = tools::files::converge_files(&request, &receipts, true).unwrap_err();
        assert!(err.contains("files-converge-target-not-file"));
        let receipt = fs::read_to_string(receipts.join("partial.json")).unwrap();
        assert!(receipt.contains("\"ok\": false"));
        assert!(receipt.contains("\"written\": 1"));
        assert!(receipt.contains("files-converge-target-not-file"));
        let _ = fs::remove_dir_all(scratch);
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
            package_authority: None,
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
    fn homeserver_update_runtime_ladder_registers_convergence_timer() {
        let root = repo_root();
        let manifest = load_ladder_manifest(
            &root.join("profiles/homeserver/modules/homeserver-update-runtime/manifest.json"),
        )
        .unwrap();
        assert_eq!(manifest.id, "homeserver-update-runtime");
        assert!(manifest.ladder.iter().any(|step| {
            step.step_id == "homeserver-update-timer-enable"
                && step.tool == "systemd"
                && step.permutation == "enable-now"
                && step.args["service"].as_str() == Some("harmonia-homeserver.timer")
        }));
        let timer = fs::read_to_string(root.join(
            "profiles/homeserver/modules/homeserver-update-runtime/files_root/etc/systemd/system/harmonia-homeserver.timer",
        ))
        .unwrap();
        assert!(timer.contains("harmonia-homeserver.service"));
        validate_ladder(&manifest).unwrap();
    }

    #[test]
    fn homeserver_update_requires_homeserver_identity() {
        let profile = Profile {
            package_authority: None,
            id: "homeserver".into(),
            identity: "homeconsole".into(),
            modules: homeserver_module_ids_from_profile_modules(&homeserver_module_root()).unwrap(),
        };
        assert!(homeserver_update(
            &profile,
            &homeserver_module_root(),
            &PathBuf::from("target/unused"),
            false,
        )
        .unwrap_err()
        .contains("homeserver/homeserver"));
    }

    #[test]
    fn run_profile_homeserver_delegates_to_rolling_update_suite() {
        let scratch =
            std::env::temp_dir().join(format!("harmonia-run-profile-homeserver-{}", process::id()));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(scratch.join("modules")).unwrap();
        let profile_path = scratch.join("index.json");
        fs::write(
            &profile_path,
            r#"{"id":"homeserver","identity":"homeserver","package_authority":{"os_family":"debian","package_manager":"apt"},"modules":["identity"]}"#,
        )
        .unwrap();
        let err = run(vec![
            "run-profile".into(),
            profile_path.display().to_string(),
            "--receipt-dir".into(),
            scratch.join("receipts").display().to_string(),
        ])
        .unwrap_err();
        assert!(err.contains("homeserver-update-suite-spine-mismatch"));
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn homeserver_profile_registers_homeserver_update_runtime() {
        let root = repo_root();
        let profile = load_profile(&root.join("profiles/homeserver/index.json")).unwrap();
        assert!(profile
            .modules
            .contains(&"homeserver-update-runtime".to_string()));
        enforce_homeserver_update_suite(&profile, &root.join("profiles/homeserver/modules"))
            .unwrap();
    }

    #[test]
    fn homeserver_profile_sync_advances_subscription_module_digest() {
        let root = repo_root();
        let scratch =
            std::env::temp_dir().join(format!("harmonia-homeserver-sync-{}", process::id()));
        let _ = fs::remove_dir_all(&scratch);
        let modules = scratch.join("profiles/homeserver/modules");
        fs::create_dir_all(&modules).unwrap();
        let subscription = scratch.join("subscription.json");
        let previous = std::env::var("HARMONIA_SUBSCRIPTION_PATH").ok();
        std::env::set_var("HARMONIA_SUBSCRIPTION_PATH", &subscription);
        sync_homeserver_profile(&root, &modules, &scratch.join("receipts")).unwrap();
        if let Some(value) = previous {
            std::env::set_var("HARMONIA_SUBSCRIPTION_PATH", value);
        } else {
            std::env::remove_var("HARMONIA_SUBSCRIPTION_PATH");
        }
        let record = read_subscription_record(&subscription).unwrap().unwrap();
        assert_eq!(
            record.ref_name,
            command_capture_with_cwd("git", &["rev-parse", "HEAD"], root.to_str())
                .stdout
                .trim()
        );
        assert_eq!(
            record.modules["homeserver-update-runtime"].tree_sha256,
            module_tree_sha256(&root.join("profiles/homeserver/modules/homeserver-update-runtime"))
                .unwrap()
        );
        let _ = fs::remove_dir_all(&scratch);
    }

    #[test]
    fn tv_update_requires_tv_identity() {
        let profile = Profile {
            package_authority: Some(PackageAuthority { os_family: "arch".into(), package_manager: "pacman".into() }),
            id: "tv".into(),
            identity: "homeconsole".into(),
            modules: tv_module_ids_from_profile_modules(&tv_module_root()).unwrap(),
        };
        assert!(tv_update(
            &profile,
            &tv_module_root(),
            &PathBuf::from("target/unused"),
            false,
        )
        .unwrap_err()
        .contains("tv/arch-tv"));
    }

    #[test]
    fn run_profile_tv_delegates_to_rolling_update_suite() {
        let scratch =
            std::env::temp_dir().join(format!("harmonia-run-profile-tv-{}", process::id()));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(scratch.join("modules")).unwrap();
        let profile_path = scratch.join("index.json");
        fs::write(
            &profile_path,
            r#"{"id":"tv","identity":"arch-tv","package_authority":{"os_family":"arch","package_manager":"pacman"},"modules":["identity"]}"#,
        )
        .unwrap();
        let err = run(vec![
            "run-profile".into(),
            profile_path.display().to_string(),
            "--receipt-dir".into(),
            scratch.join("receipts").display().to_string(),
        ])
        .unwrap_err();
        assert!(err.contains("tv-update-suite-spine-mismatch"));
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn tv_profile_registers_tv_update_runtime() {
        let root = repo_root();
        let profile = load_profile(&root.join("profiles/tv/index.json")).unwrap();
        assert!(profile
            .modules
            .contains(&"tv-update-runtime".to_string()));
        enforce_tv_update_suite(&profile, &root.join("profiles/tv/modules")).unwrap();
    }

    #[test]
    fn tv_profile_sync_advances_subscription_module_digest() {
        let root = repo_root();
        let scratch = std::env::temp_dir().join(format!("harmonia-tv-sync-{}", process::id()));
        let _ = fs::remove_dir_all(&scratch);
        let modules = scratch.join("profiles/tv/modules");
        fs::create_dir_all(&modules).unwrap();
        let subscription = scratch.join("subscription.json");
        let previous = std::env::var("HARMONIA_SUBSCRIPTION_PATH").ok();
        std::env::set_var("HARMONIA_SUBSCRIPTION_PATH", &subscription);
        sync_tv_profile(&root, &modules, &scratch.join("receipts")).unwrap();
        if let Some(value) = previous {
            std::env::set_var("HARMONIA_SUBSCRIPTION_PATH", value);
        } else {
            std::env::remove_var("HARMONIA_SUBSCRIPTION_PATH");
        }
        let record = read_subscription_record(&subscription).unwrap().unwrap();
        assert_eq!(
            record.ref_name,
            command_capture_with_cwd("git", &["rev-parse", "HEAD"], root.to_str())
                .stdout
                .trim()
        );
        assert_eq!(
            record.modules["tv-update-runtime"].tree_sha256,
            module_tree_sha256(&root.join("profiles/tv/modules/tv-update-runtime")).unwrap()
        );
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn tv_update_runtime_ladder_registers_convergence_timer() {
        let root = repo_root();
        let manifest = load_ladder_manifest(
            &root.join("profiles/tv/modules/tv-update-runtime/manifest.json"),
        )
        .unwrap();
        assert_eq!(manifest.id, "tv-update-runtime");
        assert_eq!(manifest.files_root.as_deref(), Some("files_root"));
        assert!(manifest.ladder.iter().any(|step| {
            step.step_id == "tv-update-timer-enable"
                && step.tool == "systemd"
                && step.permutation == "enable-now"
                && step.args["service"].as_str() == Some("harmonia-tv.timer")
        }));
        let timer = fs::read_to_string(root.join(
            "profiles/tv/modules/tv-update-runtime/files_root/etc/systemd/system/harmonia-tv.timer",
        ))
        .unwrap();
        assert!(timer.contains("harmonia-tv.service"));
        validate_ladder(&manifest).unwrap();
    }

    #[test]
    fn homeconsole_update_runtime_ladder_registers_convergence_timer() {
        let root = repo_root();
        let manifest = load_ladder_manifest(
            &root.join("profiles/homeconsole/modules/homeconsole-update-runtime/manifest.json"),
        )
        .unwrap();
        assert_eq!(manifest.id, "homeconsole-update-runtime");
        assert_eq!(manifest.files_root.as_deref(), Some("files_root"));
        assert!(manifest.ladder.iter().any(|step| {
            step.step_id == "homeconsole-update-timer-enable"
                && step.tool == "systemd"
                && step.permutation == "enable-now"
                && step.args["service"].as_str() == Some("harmonia-homeconsole.timer")
        }));
        let timer = fs::read_to_string(root.join(
            "profiles/homeconsole/modules/homeconsole-update-runtime/files_root/etc/systemd/system/harmonia-homeconsole.timer",
        ))
        .unwrap();
        assert!(timer.contains("harmonia-homeconsole.service"));
        validate_ladder(&manifest).unwrap();
    }

    #[test]
    fn materializes_per_run_receipt_dir_for_latest_alias() {
        let scratch =
            std::env::temp_dir().join(format!("harmonia-receipt-alias-{}", process::id()));
        let latest = scratch.join("homeconsole-update-latest");
        let per_run =
            materialize_homeconsole_receipt_dir(&latest, "run-test-1").expect("materialize");
        assert_eq!(per_run, scratch.join("homeconsole-update-run-test-1"));
        assert!(per_run.is_dir());
        #[cfg(unix)]
        {
            let link_target = std::fs::read_link(&latest).expect("latest symlink");
            assert_eq!(link_target, per_run);
        }
        let _ = fs::remove_dir_all(scratch);
    }

    #[cfg(unix)]
    #[test]
    fn homeconsole_update_apply_skips_cleanly_when_convergence_lock_held() {
        let scratch = std::env::temp_dir().join(format!("harmonia-flock-skip-{}", process::id()));
        let lock_path = scratch.join("homeconsole-update.lock");
        let receipt_root = scratch.join("receipts");
        let latest = receipt_root.join("homeconsole-update-latest");
        let profile = Profile {
            package_authority: None,
            id: "homeconsole".into(),
            identity: "homeconsole".into(),
            modules: module_ids_from_profile_modules(&homeconsole_module_root()).unwrap(),
        };
        let _guard = try_acquire_homeconsole_update_lock(&lock_path).expect("hold lock");
        let previous_lock = std::env::var("HARMONIA_HOME_CONSOLE_UPDATE_LOCK").ok();
        std::env::set_var("HARMONIA_HOME_CONSOLE_UPDATE_LOCK", &lock_path);
        let result = homeconsole_update(&profile, &homeconsole_module_root(), &latest, true);
        if let Some(value) = previous_lock {
            std::env::set_var("HARMONIA_HOME_CONSOLE_UPDATE_LOCK", value);
        } else {
            std::env::remove_var("HARMONIA_HOME_CONSOLE_UPDATE_LOCK");
        }
        assert!(
            result.is_ok(),
            "lock-held skip should not fail suite: {result:?}"
        );
        let per_run_dirs: Vec<_> = fs::read_dir(&receipt_root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("homeconsole-update-run-"))
            })
            .collect();
        assert_eq!(per_run_dirs.len(), 1, "expected one per-run receipt dir");
        let skipped = per_run_dirs[0].join("convergence-skipped.json");
        assert!(
            skipped.exists(),
            "missing skipped receipt at {}",
            skipped.display()
        );
        let text = fs::read_to_string(skipped).unwrap();
        assert!(text.contains("harmonia.convergence.skipped.v1"));
        assert!(text.contains("lock-held"));
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn detects_pacman_change_from_stdout() {
        assert!(crate::tools::package::pacman_stdout_indicates_change(
            "\nupgrading ffmpeg..."
        ));
        assert!(!crate::tools::package::pacman_stdout_indicates_change(
            " there is nothing to do"
        ));
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
    fn identity_ladder_shadow_proofs_match_compiled_receipt_family_for_profile_instances() {
        let root = repo_root();
        let scratch =
            std::env::temp_dir().join(format!("harmonia-identity-shadow-{}", process::id()));
        for profile in ["homeconsole", "tv"] {
            let manifest = load_ladder_manifest(
                &root
                    .join("profiles")
                    .join(profile)
                    .join("modules/identity/manifest.json"),
            )
            .unwrap();
            let diff = shadow_proof_receipt_family_diff_for_test(
                &manifest,
                &scratch.join(profile).join("ladder"),
                &scratch.join(profile).join("compiled"),
                |compiled_dir| {
                    let result = CmdResult {
                        ok: true,
                        code: 0,
                        stdout: "planned command /usr/bin/uname".to_string(),
                        stderr: String::new(),
                    };
                    write_command_receipt(compiled_dir, "uname", &result)?;
                    Ok(ModuleExecution {
                        ok: true,
                        changed: false,
                        operation_count: 1,
                        first_missing_signal: None,
                    })
                },
            )
            .unwrap();
            assert!(diff.is_empty(), "{profile} identity shadow diff: {diff:?}");
        }
        let _ = fs::remove_dir_all(scratch);
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
            install_profile: None,
            target_dir: None,
            source_sha_file: None,
            packages: vec![],
            package_conflict_policy: None,
            package_conflict_paths: vec![],
            expected_files: vec![],
            binaries: vec![],
            services: vec![],
            user_services: vec![],
            groups: vec![],
            managed_files: vec![],
            caduceus_profile_source: None,
            template_files: vec![],
            variables: HashMap::new(),
            optional: false,
            optional_warning: None,
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
            assert_lawful_profile_module(&dir, module);
        }
    }

    #[test]
    fn homeserver_profile_registers_coronatio_and_caduceus_runtime_modules() {
        let root = repo_root();
        let profile = load_profile(&root.join("profiles/homeserver/index.json")).unwrap();
        assert_eq!(profile.id, "homeserver");
        assert_eq!(profile.identity, "homeserver");
        assert_eq!(
            profile.modules.first().map(String::as_str),
            Some("rust-build-toolchain")
        );
        assert!(profile
            .modules
            .contains(&"rust-build-toolchain".to_string()));
        assert!(profile.modules.contains(&"coronatio".to_string()));
        assert!(profile.modules.contains(&"caduceus".to_string()));
        assert!(profile.modules.contains(&"forgejo".to_string()));
        assert!(profile.modules.contains(&"gogs".to_string()));
        assert!(profile.modules.contains(&"jellyfin".to_string()));
        assert!(!profile.modules.contains(&"system-files".to_string()));
        assert!(!profile.modules.contains(&"udev".to_string()));
        assert!(!profile.modules.contains(&"systemd".to_string()));
        assert!(root
            .join("profiles/homeserver/modules/udev/99-rapl-permissions.rules.tmpl")
            .is_file());
        assert!(root
            .join("profiles/homeserver/modules/systemd/transmissionPIA.service.tmpl")
            .is_file());
        assert!(!root.join("profiles/homeserver/modules/udev/files").exists());
        assert!(!root
            .join("profiles/homeserver/modules/systemd/files")
            .exists());
        assert!(!root
            .join("profiles/homeserver/modules/system-files")
            .exists());
        for module in &profile.modules {
            let dir = root.join("profiles/homeserver/modules").join(module);
            assert_lawful_profile_module(&dir, module);
            if dir.join("sidecar.json").exists() {
                let manifest = load_module(&dir.join("sidecar.json")).unwrap();
                assert!(
                    manifest.command.is_none(),
                    "{module} sidecar must not own a command"
                );
                assert!(
                    manifest.args.is_empty(),
                    "{module} sidecar must not own args"
                );
            }
        }

        let rust_toolchain = load_ladder_manifest(
            &root.join("profiles/homeserver/modules/rust-build-toolchain/manifest.json"),
        )
        .unwrap();
        assert_eq!(rust_toolchain.id, "rust-build-toolchain");
        assert_eq!(rust_toolchain.files_root.as_deref(), Some("files_root"));
        for wrapper in [
            "usr/local/bin/rustc",
            "usr/local/bin/cargo",
            "usr/local/bin/rustup",
        ] {
            let wrapper_path = root
                .join("profiles/homeserver/modules/rust-build-toolchain/files_root")
                .join(wrapper);
            assert!(wrapper_path.is_file(), "missing wrapper {wrapper}");
            let text = fs::read_to_string(wrapper_path).unwrap();
            assert!(text.contains("RUSTUP_HOME=/opt/rustup"));
            assert!(text.contains("CARGO_HOME=/opt/cargo"));
        }

        for module in ["coronatio", "caduceus"] {
            let manifest = load_ladder_manifest(
                &root
                    .join("profiles/homeserver/modules")
                    .join(module)
                    .join("manifest.json"),
            )
            .unwrap();
            let runtime = manifest
                .ladder
                .iter()
                .find(|step| step.tool == "service-runtime")
                .expect("{module} service-runtime step");
            assert_eq!(runtime.tool, "service-runtime");
            assert!(
                runtime.args["repo"]
                    .as_str()
                    .unwrap_or("")
                    .starts_with("https://git.home.arpa/HOMESERVERSLTD/"),
                "{module} homeserver runtime repo must be root-readable HTTPS"
            );
        }
        let caduceus =
            load_ladder_manifest(&root.join("profiles/homeserver/modules/caduceus/manifest.json"))
                .unwrap();
        let runtime = caduceus
            .ladder
            .iter()
            .find(|step| step.tool == "service-runtime")
            .expect("homeserver caduceus service-runtime step");
        let source_profile: CaduceusProfileSourceManifest = serde_json::from_value(
            runtime.args["caduceus_profile_source"].clone(),
        )
        .unwrap();
        assert_eq!(source_profile.source, "profiles/homeserver/index.yaml");
        assert_eq!(source_profile.path, "/etc/caduceus/profile.yaml");
        for required in [
            "capability:",
            "household_verifying_key:",
            "default_ttl_seconds: 60",
            "harmonia_profile: /etc/harmonia/profiles/homeserver/index.json",
        ] {
            assert!(
                source_profile.insert_after_profile.contains(required)
                    || source_profile.insert_after_mode.contains(required),
                "homeserver Caduceus profile source overlay missing {required}"
            );
        }
        for required in [
            "- staff intent",
            "- update status",
            "- update check",
            "- update now",
            "- receipts latest",
            "- cert status",
            "- cert issue-leaf",
            "- cert bundle create",
            "- cert apply",
            "- cert portal-admit",
            "- config set",
            "- config patch",
        ] {
            assert!(
                !source_profile.append.contains(required),
                "homeserver Caduceus profile command {required} must not be hand-copied into the Harmonia overlay"
            );
        }
        assert!(source_profile.append.contains("harmonia_routes:"));
        assert!(source_profile.append.contains("update_now:"));
        assert!(source_profile.append.contains("homeserver-update"));
        assert!(source_profile.append.contains("/etc/harmonia/profiles/homeserver/index.json"));
        assert!(source_profile.append.contains("/var/lib/harmonia/receipts/homeserver-update-latest/run.json"));
        let managed_files: Vec<ManagedFileManifest> =
            serde_json::from_value(runtime.args["managed_files"].clone()).unwrap();
        assert!(
            managed_files
                .iter()
                .all(|file| file.path != "/etc/caduceus/profile.yaml"),
            "homeserver Caduceus commands must be lifted from caduceus_profile_source, not hand-copied in managed_files"
        );
        let service_text = managed_files
            .iter()
            .find(|file| file.path == "/etc/systemd/system/caduceus.service")
            .expect("homeserver caduceus service managed file")
            .content
            .as_str();
        for forbidden in [
            "NoNewPrivileges=",
            "PrivateTmp=",
            "ProtectSystem=",
            "ProtectHome=",
            "ReadWritePaths=",
        ] {
            assert!(
                !service_text.contains(forbidden),
                "homeserver public Caduceus unit must not carry unjustified hardening {forbidden}"
            );
        }
        assert!(
            !service_text.contains("caduceus-access"),
            "homeserver public Caduceus unit must not depend on retired access service"
        );
        assert!(
            !service_text.contains("access.sock"),
            "homeserver public Caduceus unit must not expose retired socket path"
        );
        assert!(
            !service_text.contains("ExecStartPre="),
            "homeserver public Caduceus unit must not retain retired tmpfiles preflight"
        );
        for installed in [
            "/usr/local/sbin/caduceus_staff/house_ca.py",
            "/usr/local/sbin/caduceus-house-ca",
        ] {
            assert!(
                managed_files.iter().any(|file| file.path == installed),
                "homeserver Caduceus package missing {installed}"
            );
        }
        assert!(root
            .join("profiles/homeserver/modules/caduceus/files_root/usr/local/sbin/caduceus_staff/house_ca.py")
            .is_file());
        assert!(root
            .join("profiles/homeserver/modules/caduceus/files_root/usr/local/sbin/caduceus-house-ca")
            .is_file());
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
                "oh-my-posh-aur-ratchet".to_string(),
                "operator-rc-profile".to_string(),
                "desktop-config-payload".to_string(),
                "user-session-services".to_string(),
                "sddm-autologin-hyprland".to_string(),
                "steam-game-lane".to_string(),
                "power-controller-maintenance".to_string(),
                "console-recovery".to_string(),
                "tv-update-runtime".to_string(),
                "caduceus-public-lever".to_string(),
                "appliance-proof".to_string()
            ]
        );
        assert!(
            !root.join("payloads").exists(),
            "TV config must be profile-adjacent, not a top-level payload execution tree"
        );
        assert!(
            !root.join("profiles/tv/config").exists(),
            "TV files belong inside profiles/tv/modules/<intent>; sibling config folders are rejected"
        );
        let config_root = root.join("profiles/tv/modules/desktop-config-payload/files_root");
        assert!(config_root
            .join("hyprland/.config/hypr/hyprland.conf")
            .is_file());
        assert!(config_root
            .join("waybar/.config/waybar/waybar.conf")
            .is_file());
        assert!(config_root
            .join("launcher-bin/bin/tv-launcher.sh")
            .is_file());

        for module in &profile.modules {
            let dir = root.join("profiles/tv/modules").join(module);
            assert_lawful_profile_module(&dir, module);
        }
    }

    #[test]
    fn tv_profile_runtime_modules_are_ladder_manifests() {
        let root = repo_root();
        let profile = load_profile(&root.join("profiles/tv/index.json")).unwrap();
        let converted = [
            "owner-profile",
            "gpu-display-stack",
            "hyprland-desktop",
            "operator-rc-profile",
            "desktop-config-payload",
            "user-session-services",
            "sddm-autologin-hyprland",
            "steam-game-lane",
            "power-controller-maintenance",
            "console-recovery",
            "tv-update-runtime",
            "caduceus-public-lever",
            "appliance-proof",
        ];
        for module in converted {
            assert!(
                profile.modules.contains(&module.to_string()),
                "missing {module}"
            );
            let dir = root.join("profiles/tv/modules").join(module);
            assert!(
                dir.join("manifest.json").is_file(),
                "{module} manifest missing"
            );
            assert!(
                !dir.join("sidecar.json").exists(),
                "{module} sidecar retired"
            );
            assert!(!dir.join("index.rs").exists(), "{module} wrapper retired");
            let manifest = load_ladder_manifest(&dir.join("manifest.json")).unwrap();
            assert_eq!(manifest.id, module);
            let expected_version = if module == "caduceus-public-lever" {
                "1.1.0"
            } else {
                "1.0.0"
            };
            assert_eq!(manifest.version, expected_version);
            validate_ladder(&manifest).unwrap();
        }
        assert!(
            !root
                .join("profiles/tv/modules/tv-runtime-support.rs")
                .exists(),
            "shared TV runtime support helper retired when last includer converted"
        );
    }

    #[test]
    fn tv_steam_ladder_preserves_optional_continue_semantics() {
        let root = repo_root();
        let steam =
            load_ladder_manifest(&root.join("profiles/tv/modules/steam-game-lane/manifest.json"))
                .unwrap();
        assert!(steam.optional, "steam game lane remains optional");
        assert!(steam
            .optional_warning
            .as_deref()
            .unwrap_or("")
            .contains("customer may have uninstalled Steam"));
        for step in &steam.ladder {
            assert_eq!(step.on_failure, OnFailure::ContinueOptional);
        }
        let steps: Vec<_> = steam
            .ladder
            .iter()
            .map(|step| (step.tool.as_str(), step.permutation.as_str()))
            .collect();
        assert!(
            steps.contains(&("command", "capture")),
            "steam optional checks use command probes"
        );
        assert!(
            steps.contains(&("files", "managed-files")),
            "steam managed files moved to files_root"
        );
    }

    #[test]
    fn tv_ladder_managed_file_payloads_live_in_files_root() {
        let root = repo_root();
        let steam_dir = root.join("profiles/tv/modules/steam-game-lane");
        let steam = load_ladder_manifest(&steam_dir.join("manifest.json")).unwrap();
        assert_eq!(steam.files_root.as_deref(), Some("files_root"));
        assert!(
            steam_dir
                .join("files_root/usr/local/bin/arch-tv-steam-game-lane")
                .is_file()
        );
        assert!(steam
            .ladder
            .iter()
            .any(|step| step.tool == "files" && step.permutation == "managed-files"));

        let caduceus_dir = root.join("profiles/tv/modules/caduceus-public-lever");
        let caduceus =
            load_ladder_manifest(&caduceus_dir.join("manifest.json")).unwrap();
        assert_eq!(caduceus.files_root.as_deref(), Some("files_root"));
        assert!(
            caduceus_dir
                .join("files_root/etc/caduceus/identity.json")
                .is_file()
        );
        let runtime = caduceus
            .ladder
            .iter()
            .find(|step| step.tool == "service-runtime")
            .expect("tv caduceus service-runtime step");
        assert!(runtime.args.get("managed_files").is_some());
        let managed_files: Vec<ManagedFileManifest> =
            serde_json::from_value(runtime.args["managed_files"].clone()).unwrap();
        let service_text = managed_files
            .iter()
            .find(|file| file.path == "/etc/systemd/system/caduceus.service")
            .expect("tv caduceus service managed file")
            .content
            .as_str();
        assert!(!service_text.contains("ReadWritePaths="));
    }

    #[test]
    fn tv_desktop_config_manifest_uses_files_root_tree() {
        let root = repo_root();
        let manifest = load_ladder_manifest(
            &root.join("profiles/tv/modules/desktop-config-payload/manifest.json"),
        )
        .unwrap();
        assert_eq!(manifest.id, "desktop-config-payload");
        assert_eq!(manifest.files_root.as_deref(), Some("files_root"));
        assert!(
            manifest
                .constants
                .get("target_dir")
                .and_then(serde_json::Value::as_str)
                == Some("/home/owner")
        );
        assert!(root
            .join("profiles/tv/modules/desktop-config-payload/files_root/hyprland/.config/hypr/monitors.conf")
            .is_file());
        assert!(root
            .join("profiles/tv/modules/desktop-config-payload/files_root/waybar/.config/waybar/waybar.conf")
            .is_file());
        assert!(root
            .join("profiles/tv/modules/desktop-config-payload/files_root/launcher-bin/bin/tv-launcher.sh")
            .is_file());
        assert!(manifest
            .ladder
            .iter()
            .any(|step| step.tool == "files" && step.permutation == "converge"));
        validate_ladder(&manifest).unwrap();
    }

    #[test]
    fn tv_hyprland_desktop_includes_kcalc_and_launcher_refresh_surface() {
        let root = repo_root();
        let hyprland =
            load_ladder_manifest(&root.join("profiles/tv/modules/hyprland-desktop/manifest.json"))
                .unwrap();
        let packages = hyprland.constants["packages"].as_array().unwrap();
        assert!(
            packages
                .iter()
                .any(|package| package.as_str() == Some("kcalc")),
            "TV hyprland-desktop must install kcalc"
        );

        let config_root = root.join("profiles/tv/modules/desktop-config-payload/files_root");
        let windows =
            fs::read_to_string(config_root.join("hyprland/.config/hypr/windows.conf")).unwrap();
        assert!(windows.contains("org\\.kde\\.kcalc"));
        assert!(windows.contains("windowrule = float 1"));

        let bindings =
            fs::read_to_string(config_root.join("hyprland/.config/hypr/bindings.conf")).unwrap();
        assert!(bindings.contains("bind = SUPER, K, exec, kcalc"));

        let refresh =
            fs::read_to_string(config_root.join("launcher-bin/bin/refresh-launcher-cache.sh"))
                .unwrap();
        assert!(refresh.contains("update-desktop-database"));
        assert!(refresh.contains("kbuildsycoca6"));
        assert!(refresh.contains("wofi-drun-cache"));

        let desktop = load_ladder_manifest(
            &root.join("profiles/tv/modules/desktop-config-payload/manifest.json"),
        )
        .unwrap();
        let expected = desktop.constants["expected_files"].as_array().unwrap();
        assert!(expected
            .iter()
            .any(|value| value.as_str() == Some("bin/refresh-launcher-cache.sh")));
    }

    #[test]
    fn harmonia_runtime_is_engine_preflight_not_profile_artifact_on_arch_profiles() {
        let root = repo_root();
        for profile_path in ["profiles/homeconsole/index.json", "profiles/tv/index.json"] {
            let profile = load_profile(&root.join(profile_path)).unwrap();
            assert!(
                !profile.modules.contains(&"harmonia-runtime".to_string()),
                "harmonia-runtime belongs to engine pre-flight, not the module spine"
            );
            assert!(
                !root
                    .join(profile_path.replace("index.json", "modules"))
                    .join("harmonia-runtime")
                    .exists(),
                "harmonia-runtime profile artifact must be retired"
            );
            assert_eq!(profile.modules[0], "identity");
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

            let keyring_manifest = load_ladder_manifest(
                &root
                    .join(profile_path.replace("index.json", "modules"))
                    .join("arch-keyring-maintenance/manifest.json"),
            )
            .unwrap();
            assert_eq!(keyring_manifest.id, "arch-keyring-maintenance");
            let step_names: Vec<_> = keyring_manifest
                .ladder
                .iter()
                .map(|step| (step.tool.as_str(), step.permutation.as_str()))
                .collect();
            assert_eq!(
                step_names,
                vec![("package", "keyring-repair"), ("package", "install")]
            );
            validate_ladder(&keyring_manifest).unwrap();
        }
    }

    #[test]
    fn missing_harmonia_runtime_preflight_absence_allows_ladder_modules() {
        let root = repo_root();
        let scratch =
            std::env::temp_dir().join(format!("harmonia-terminal-self-modern-{}", process::id()));
        let module_root = scratch.join("modules");
        fs::create_dir_all(module_root.join("identity")).unwrap();
        fs::copy(
            root.join("profiles/tv/modules/identity/manifest.json"),
            module_root.join("identity/manifest.json"),
        )
        .unwrap();
        fs::create_dir_all(module_root.join("system-packages")).unwrap();
        fs::copy(
            root.join("profiles/tv/modules/system-packages/manifest.json"),
            module_root.join("system-packages/manifest.json"),
        )
        .unwrap();
        let receipts = scratch.join("receipts");
        let profile = Profile {
            package_authority: Some(PackageAuthority { os_family: "arch".into(), package_manager: "pacman".into() }),
            id: "tv".into(),
            identity: "arch-tv".into(),
            modules: vec!["identity".into(), "system-packages".into()],
        };
        run_profile_engine(&profile, &module_root, &receipts, false).unwrap();
        assert!(receipts.join("modules/identity").exists());
        assert!(receipts.join("modules/system-packages").exists());
        let events = fs::read_to_string(receipts.join("events.jsonl")).unwrap();
        assert!(!events.contains("module-terminal-stop"));
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn spine_continues_past_failed_module_pro_flow_wall() {
        fn write_command_module(module_root: &Path, module_id: &str, program: &str) {
            let module_dir = module_root.join(module_id);
            fs::create_dir_all(&module_dir).unwrap();
            write_json(
                &module_dir.join("manifest.json"),
                &serde_json::json!({
                    "schema": "harmonia.module.ladder.v1",
                    "id": module_id,
                    "version": "1.0.0",
                    "description": format!("pro-flow wall fixture {module_id}"),
                    "ladder": [{
                        "step_id": "run",
                        "tool": "command",
                        "permutation": "capture",
                        "args": { "program": program },
                        "on_failure": "stop"
                    }]
                }),
            )
            .unwrap();
        }

        for (shape, failing_manifest, expected_signal) in [
            (
                "invalid-ladder",
                serde_json::json!({
                    "schema": "harmonia.module.ladder.v1",
                    "id": "early-failure",
                    "version": "1.0.0",
                    "description": "invalid ladder pro-flow fixture",
                    "ladder": [{
                        "step_id": "fail",
                        "tool": "not-a-registered-tool",
                        "permutation": "capture",
                        "args": {},
                        "on_failure": "stop"
                    }]
                }),
                "module-invalid step_id=fail defect=unknown-tool-not-a-registered-tool",
            ),
            (
                "runtime-execution-failure",
                serde_json::json!({
                    "schema": "harmonia.module.ladder.v1",
                    "id": "early-failure",
                    "version": "1.0.0",
                    "description": "runtime failure pro-flow fixture",
                    "ladder": [{
                        "step_id": "fail",
                        "tool": "command",
                        "permutation": "capture",
                        "args": { "program": "/usr/bin/false" },
                        "on_failure": "stop"
                    }]
                }),
                "step_id=fail defect=tool-step-failed",
            ),
        ] {
            let scratch = std::env::temp_dir()
                .join(format!("harmonia-pro-flow-wall-{shape}-{}", process::id()));
            let module_root = scratch.join("modules");
            let receipts = scratch.join("receipts");
            fs::create_dir_all(module_root.join("early-failure")).unwrap();
            write_json(
                &module_root.join("early-failure/manifest.json"),
                &failing_manifest,
            )
            .unwrap();
            write_command_module(&module_root, "later-one", "/usr/bin/true");
            write_command_module(&module_root, "later-two", "/usr/bin/true");

            let profile = Profile {
                package_authority: None,
                id: format!("pro-flow-{shape}"),
                identity: "pro-flow-wall".into(),
                modules: vec![
                    "early-failure".into(),
                    "later-one".into(),
                    "later-two".into(),
                ],
            };
            let result =
                run_profile_engine_with_preflight(&profile, &module_root, &receipts, true, true);
            assert_eq!(result, Err(expected_signal.to_string()), "shape={shape}");

            let run: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(receipts.join("run.json")).unwrap())
                    .unwrap();
            assert_eq!(run["ok"], false, "shape={shape}");
            assert_eq!(
                run["first_missing_signal"], expected_signal,
                "shape={shape}"
            );

            for later in ["later-one", "later-two"] {
                assert!(
                    receipts
                        .join("modules")
                        .join(later)
                        .join("run.json")
                        .exists(),
                    "shape={shape}: {later} must execute after the early failure"
                );
            }

            let ledger = fs::read_to_string(profile_ledger_path(&receipts, &profile)).unwrap();
            let entries: Vec<serde_json::Value> = ledger
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(entries.len(), 3, "shape={shape}");
            assert_eq!(entries[0]["module_id"], "early-failure", "shape={shape}");
            assert_eq!(entries[0]["ok"], false, "shape={shape}");
            assert_eq!(
                entries[0]["first_missing_signal"], expected_signal,
                "shape={shape}"
            );
            for later in ["later-one", "later-two"] {
                assert!(
                    entries
                        .iter()
                        .any(|entry| entry["module_id"] == later && entry["ok"] == true),
                    "shape={shape}: {later} ledger entry must survive the early failure"
                );
            }
            let events = fs::read_to_string(receipts.join("events.jsonl")).unwrap();
            assert!(!events.contains("module-terminal-stop"), "shape={shape}");
            let _ = fs::remove_dir_all(scratch);
        }
    }

    #[test]
    fn tv_profile_has_no_harmonia_runtime_profile_artifact_before_downstream_modules() {
        let root = repo_root();
        let profile = load_profile(&root.join("profiles/tv/index.json")).unwrap();
        assert_eq!(profile.modules[0], "identity");
        assert!(!profile.modules.contains(&"harmonia-runtime".to_string()));
        assert!(!root.join("profiles/tv/modules/harmonia-runtime").exists());
        let receipts =
            std::env::temp_dir().join(format!("harmonia-tv-self-modern-receipt-{}", process::id()));
        with_fake_pacman(&receipts.join("fixtures"), || {
            run_profile_engine(
                &profile,
                &root.join("profiles/tv/modules"),
                &receipts,
                false,
            )
            .unwrap();
        });
        assert!(
            receipts.join("engine-preflight/run.json").exists(),
            "engine preflight now reports kernel-owned engine-plane state instead of sidecar-gating"
        );
        let preflight = fs::read_to_string(receipts.join("engine-preflight/run.json")).unwrap();
        assert!(preflight.contains("retired_sidecar_gate"));
        assert!(receipts.join("modules/identity").exists());
        let _ = fs::remove_dir_all(receipts);
    }

    #[test]
    fn tv_profile_absolute_path_manifests_config_from_profile_authority() {
        let root = repo_root();
        let scratch =
            std::env::temp_dir().join(format!("harmonia-tv-absolute-profile-{}", process::id()));
        let installed_root = scratch.join("etc/harmonia");
        let profile_root = installed_root.join("profiles/tv");
        fs::create_dir_all(profile_root.parent().unwrap()).unwrap();
        copy_dir_all(&root.join("profiles/tv"), &profile_root).unwrap();
        let previous = std::env::current_dir().unwrap();
        let receipt_dir = scratch.join("receipts");
        std::env::set_current_dir(std::env::temp_dir()).unwrap();
        let profile_path = profile_root.join("index.json");
        let profile = load_profile(&profile_path).unwrap();
        let result = with_fake_pacman(&scratch.join("fixtures"), || {
            run_profile_engine(
                &profile,
                &default_module_root(&profile_path),
                &receipt_dir,
                false,
            )
        });
        std::env::set_current_dir(previous).unwrap();
        assert!(
            result.is_ok(),
            "absolute profile run should not depend on cwd: {result:?}"
        );
        let manifest = fs::read_to_string(
            receipt_dir
                .join("modules/desktop-config-payload/tv-desktop-config-hyprland-summary.json"),
        )
        .unwrap();
        assert!(
            manifest.contains(
                "/etc/harmonia/profiles/tv/modules/desktop-config-payload/files_root/hyprland"
            ) || manifest.contains(
                "etc/harmonia/profiles/tv/modules/desktop-config-payload/files_root/hyprland"
            )
        );
        let _ = fs::remove_dir_all(scratch);
    }

    fn copy_dir_all(source: &Path, target: &Path) -> std::io::Result<()> {
        fs::create_dir_all(target)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let dest = target.join(entry.file_name());
            if file_type.is_dir() {
                copy_dir_all(&entry.path(), &dest)?;
            } else {
                fs::copy(entry.path(), dest)?;
            }
        }
        Ok(())
    }

    #[test]
    fn tv_desktop_config_uses_generic_files_convergence_receipt() {
        let root = repo_root();
        let profile = load_profile(&root.join("profiles/tv/index.json")).unwrap();
        let receipts =
            std::env::temp_dir().join(format!("harmonia-tv-files-receipt-{}", process::id()));
        with_fake_pacman(&receipts.join("fixtures"), || {
            run_profile_engine(
                &profile,
                &root.join("profiles/tv/modules"),
                &receipts,
                false,
            )
            .unwrap();
        });
        let summary =
            receipts.join("modules/desktop-config-payload/tv-desktop-config-hyprland-summary.json");
        assert!(summary.exists());
        let summary_text = fs::read_to_string(summary).unwrap();
        assert!(summary_text.contains("harmonia.tv.desktop_config_install.v1"));
        assert!(summary_text.contains("harmonia-profile-module-owned-files"));
        assert!(summary_text.contains("files_root/hyprland"));
        assert!(!summary_text.contains("sha256"));
        assert!(!summary_text.contains("digest"));
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
            .join("profiles/homeconsole/modules/arcadia-gui-runtime/manifest.json")
            .exists());
        assert!(output
            .join("profiles/homeconsole/modules/pinned-artifacts-runtime/manifest.json")
            .exists());
        assert!(output
            .join("profiles/homeconsole/modules/homeconsole-update-runtime/files_root/etc/systemd/system/harmonia-homeconsole.timer")
            .exists());
        assert!(output
            .join("locks/homeconsole/pinned-artifacts.json")
            .exists());
        assert!(receipts.join("deployable-config-export.json").exists());
        let receipt = fs::read_to_string(receipts.join("deployable-config-export.json")).unwrap();
        assert!(receipt.contains("harmonia.deployable_config_export.v1"));
        assert!(receipt.contains("profile-index"));
        assert!(receipt.contains("module-ladder-manifest"));
        assert!(receipt.contains("module-ladder-files-root"));
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
    fn deployable_config_export_carries_ladder_module_sibling_files() {
        let root = repo_root();
        let scratch = std::env::temp_dir().join(format!(
            "harmonia-deployable-config-tv-ratchet-{}",
            process::id()
        ));
        let output = scratch.join("payload");
        let receipts = scratch.join("receipts");
        export_deployable_config(&root, "tv", &output, &receipts, DeployableConfigMode::Copy)
            .unwrap();
        assert!(output
            .join("profiles/tv/modules/oh-my-posh-aur-ratchet/manifest.json")
            .exists());
        assert!(output
            .join("profiles/tv/modules/oh-my-posh-aur-ratchet/ratchet-lock.json")
            .exists());
        let receipt = fs::read_to_string(receipts.join("deployable-config-export.json")).unwrap();
        assert!(receipt.contains("module-ladder-sibling-file"));
        assert!(receipt.contains("ratchet-lock.json"));
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
        assert!(!root
            .join("profiles/homeconsole/modules/harmonia-runtime")
            .exists());
        for module in ["keyman-runtime", "homeconsole-sync-runtime"] {
            let manifest = load_ladder_manifest(
                &root
                    .join("profiles/homeconsole/modules")
                    .join(module)
                    .join("manifest.json"),
            )
            .unwrap();
            assert_eq!(manifest.id, module);
            assert!(manifest
                .ladder
                .iter()
                .any(|step| step.tool == "git-artifact"));
            validate_ladder(&manifest).unwrap();
        }
    }

    #[test]
    fn homeconsole_caduceus_public_lever_sidecar_stands_up_http_runtime() {
        let root = repo_root();
        let manifest =
            load_ladder_manifest(&root.join(
                "profiles/homeconsole/modules/homeconsole-caduceus-public-lever/manifest.json",
            ))
            .unwrap();
        assert_eq!(manifest.id, "homeconsole-caduceus-public-lever");
        assert_eq!(manifest.ladder[0].tool, "service-runtime");
        assert!(
            manifest.ladder[0].args["repo"]
                .as_str()
                .unwrap_or("")
                .contains("caduceus"),
            "caduceus module must sync caduceus source"
        );
        assert_eq!(
            manifest.ladder[0].args["service"].as_str(),
            Some("caduceus.service")
        );
        assert_eq!(
            manifest.ladder[0].args["url"].as_str(),
            Some("http://127.0.0.1:8787/health")
        );
        let managed_files: Vec<ManagedFileManifest> =
            serde_json::from_value(manifest.ladder[0].args["managed_files"].clone()).unwrap();
        assert!(
            managed_files
                .iter()
                .any(|file| file.path == "/etc/systemd/system/caduceus.service"),
            "caduceus module must install caduceus.service"
        );
        let service_text = managed_files
            .iter()
            .find(|file| file.path == "/etc/systemd/system/caduceus.service")
            .expect("homeconsole caduceus service managed file")
            .content
            .as_str();
        assert!(!service_text.contains("ReadWritePaths="));
        validate_ladder(&manifest).unwrap();
    }

    #[test]
    fn package_family_modules_are_ladder_manifests() {
        let root = repo_root();
        let cases = [
            (
                "homeconsole",
                "arch-keyring-maintenance",
                vec![("package", "keyring-repair"), ("package", "install")],
            ),
            (
                "tv",
                "arch-keyring-maintenance",
                vec![("package", "keyring-repair"), ("package", "install")],
            ),
            (
                "homeconsole",
                "rust-build-toolchain",
                vec![("package", "install")],
            ),
            (
                "homeserver",
                "rust-build-toolchain",
                vec![("package", "install"), ("files", "managed-files")],
            ),
            (
                "homeconsole",
                "system-packages",
                vec![("package", "upgrade")],
            ),
            ("tv", "system-packages", vec![("package", "upgrade")]),
        ];
        for (profile, module, expected) in cases {
            let dir = root
                .join("profiles")
                .join(profile)
                .join("modules")
                .join(module);
            assert!(
                dir.join("manifest.json").is_file(),
                "{profile}/{module} ladder manifest missing"
            );
            assert!(
                !dir.join("sidecar.json").exists(),
                "{profile}/{module} sidecar retired"
            );
            assert!(
                !dir.join("index.rs").exists(),
                "{profile}/{module} compiled module retired"
            );
            let manifest = load_ladder_manifest(&dir.join("manifest.json")).unwrap();
            validate_ladder(&manifest).unwrap();
            let steps: Vec<_> = manifest
                .ladder
                .iter()
                .map(|step| (step.tool.as_str(), step.permutation.as_str()))
                .collect();
            assert_eq!(steps, expected, "{profile}/{module} ladder steps");
        }
    }

    #[test]
    fn tranche_3_c4_runtime_and_rebis_modules_are_ladder_manifests() {
        let root = repo_root();
        let cases = [
            (
                "homeserver",
                "caduceus",
                vec![("command", "capture"), ("service-runtime", "converge")],
            ),
            (
                "homeserver",
                "coronatio",
                vec![("service-runtime", "converge")],
            ),
            (
                "homeconsole",
                "homeconsole-caduceus-public-lever",
                vec![("service-runtime", "converge")],
            ),
            ("rebis", "rebis-waybar-config", vec![("files", "converge")]),
        ];
        for (profile, module, expected) in cases {
            let dir = root
                .join("profiles")
                .join(profile)
                .join("modules")
                .join(module);
            assert!(
                dir.join("manifest.json").is_file(),
                "{profile}/{module} ladder manifest missing"
            );
            assert!(
                !dir.join("sidecar.json").exists(),
                "{profile}/{module} sidecar retired"
            );
            assert!(
                !dir.join("index.rs").exists(),
                "{profile}/{module} compiled wrapper retired"
            );
            let manifest = load_ladder_manifest(&dir.join("manifest.json")).unwrap();
            validate_ladder(&manifest).unwrap();
            let steps: Vec<_> = manifest
                .ladder
                .iter()
                .map(|step| (step.tool.as_str(), step.permutation.as_str()))
                .collect();
            assert_eq!(steps, expected, "{profile}/{module} ladder steps");
        }
    }

    #[test]
    fn systemd_tool_declares_system_and_user_lifecycle_permutations() {
        let systemd = tools::get("systemd").expect("systemd tool registered");
        let names: std::collections::BTreeSet<_> =
            systemd.permutations.iter().map(|p| p.name).collect();
        for required in [
            "daemon-reload",
            "enable-now",
            "restart",
            "is-active-probe",
            "user-daemon-reload",
            "user-enable-now",
            "user-restart",
            "user-is-active-probe",
        ] {
            assert!(
                names.contains(required),
                "missing systemd permutation {required}"
            );
        }
    }

    #[test]
    fn shared_toolbelt_is_callable_by_modules() {
        assert!(tools::get("command").is_some());
        assert!(tools::get("git-artifact").is_some());
        assert!(tools::get("health").is_some());
        assert!(tools::get("files").is_some());
        assert!(tools::get("package").is_some());
        let manifest: ModuleManifest = serde_json::from_value(serde_json::json!({
            "id": "homeconsole-sync-runtime"
        }))
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
            package_authority: None,
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
                module_version: None,
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
                module_version: None,
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

    #[test]
    fn tv_oh_my_posh_aur_ratchet_owns_public_pin_and_spine_position() {
        let root = repo_root();
        let profile = load_profile(&root.join("profiles/tv/index.json")).unwrap();
        let ratchet_pos = profile
            .modules
            .iter()
            .position(|module| module == "oh-my-posh-aur-ratchet")
            .expect("TV spine must include the oh-my-posh AUR ratchet");
        let operator_pos = profile
            .modules
            .iter()
            .position(|module| module == "operator-rc-profile")
            .expect("TV spine must include operator rc profile");
        assert!(ratchet_pos < operator_pos);

        let ratchet = load_ladder_manifest(
            &root.join("profiles/tv/modules/oh-my-posh-aur-ratchet/manifest.json"),
        )
        .unwrap();
        assert_eq!(ratchet.version, "1.0.0");
        assert_eq!(
            ratchet.constants["package"].as_str(),
            Some("oh-my-posh-bin")
        );
        let step_names: Vec<_> = ratchet
            .ladder
            .iter()
            .map(|step| (step.tool.as_str(), step.permutation.as_str()))
            .collect();
        assert_eq!(
            step_names,
            vec![
                ("aur", "check"),
                ("aur", "build-pinned"),
                ("command", "capture")
            ]
        );
        validate_ladder(&ratchet).unwrap();

        let lock: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(
                root.join("profiles/tv/modules/oh-my-posh-aur-ratchet/ratchet-lock.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(lock["schema"], "harmonia.aur.ratchet_lock.v1");
        assert_eq!(lock["package"], "oh-my-posh-bin");
        assert_eq!(lock["pinned_version"], "29.20.1-1");
        assert_eq!(
            lock["pkgbuild_sha"],
            "ed800be1c781d41ce83ce6e693d6e00e868883c9"
        );
    }

    #[test]
    fn operator_rc_profile_no_longer_installs_oh_my_posh() {
        let root = repo_root();
        let operator = load_ladder_manifest(
            &root.join("profiles/tv/modules/operator-rc-profile/manifest.json"),
        )
        .unwrap();
        let packages = operator.constants["packages"].as_array().unwrap();
        assert!(!packages
            .iter()
            .any(|package| package.as_str() == Some("oh-my-posh")));
        assert!(!operator
            .ladder
            .iter()
            .any(|step| step.step_id == "binary-oh-my-posh"));
        validate_ladder(&operator).unwrap();
    }
}

pub(crate) fn run(args: Vec<String>) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("update") => update_from_certificate(&args[1..]),
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
                    println!("ok=true");
                    println!("module_id={}", manifest.id);
                    println!("version={}", manifest.version);
                    println!("step_count={}", steps.len());
                    println!("first_missing_signal=none");
                    Ok(())
                }
                Err(err) => {
                    println!("schema=harmonia.ladder.validate.v1");
                    println!("ok=false");
                    println!("module_id={}", manifest.id);
                    println!("version={}", manifest.version);
                    println!("first_missing_signal={}", err.first_missing_signal());
                    Err(format!("module-invalid {}", err.first_missing_signal()))
                }
            }
        }
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
            let profile_path = Path::new(path);
            let profile = load_profile(profile_path).map_err(|e| e.to_string())?;
            let module_root = default_module_root(profile_path);
            write_plan_receipts(&profile, &module_root, &receipt_dir).map_err(|e| e.to_string())?;
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
            if profile.id == "homeserver" && profile.identity == "homeserver" {
                homeserver_update(&profile, &module_root, &receipt_dir, apply)
            } else if profile.id == "homeconsole" && profile.identity == "homeconsole" {
                homeconsole_update(&profile, &module_root, &receipt_dir, apply)
            } else if profile.id == "tv" && profile.identity == "arch-tv" {
                tv_update(&profile, &module_root, &receipt_dir, apply)
            } else {
                run_profile_engine(&profile, &module_root, &receipt_dir, apply)
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
                    let harmonia_root =
                        value_arg(&args, "--harmonia-root").unwrap_or_else(|| PathBuf::from("."));
                    capsule_pack(profile_id, &output_dir, &harmonia_root)
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
                    capsule_install(Path::new(capsule_dir), &config_dir, apply)
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
        Some("homeserver-update") => {
            let path = args
                .get(1)
                .ok_or("homeserver-update requires <profile-index-json>")?;
            let receipt_dir =
                receipt_dir_arg(&args).unwrap_or_else(homeserver_update_receipt_latest);
            let apply = args.iter().any(|arg| arg == "--apply");
            verify_asserted_profile("homeserver")?;
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            let module_root = default_module_root(Path::new(path));
            homeserver_update(&profile, &module_root, &receipt_dir, apply)
        }
        Some("homeconsole-update") => {
            let path = args
                .get(1)
                .ok_or("homeconsole-update requires <profile-index-json>")?;
            let receipt_dir =
                receipt_dir_arg(&args).unwrap_or_else(homeconsole_update_receipt_latest);
            let apply = args.iter().any(|arg| arg == "--apply");
            verify_asserted_profile("homeconsole")?;
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            let module_root = default_module_root(Path::new(path));
            homeconsole_update(&profile, &module_root, &receipt_dir, apply)
        }
        Some("tv-update") => {
            let path = args.get(1).ok_or("tv-update requires <profile-index-json>")?;
            let receipt_dir = receipt_dir_arg(&args).unwrap_or_else(tv_update_receipt_latest);
            let apply = args.iter().any(|arg| arg == "--apply");
            verify_asserted_profile("tv")?;
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            let module_root = default_module_root(Path::new(path));
            tv_update(&profile, &module_root, &receipt_dir, apply)
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
            let harmonia_root = harmonia_root_from_module_root(&module_root);
            let execution =
                execute_profile_module(&module, &module_root, &receipt_dir, apply, &harmonia_root)?;
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
    println!("  harmonia validate-ladder <manifest.json>");
    println!("  harmonia plan-run <profiles/<id>/index.json> [--receipt-dir <path>]");
    println!("  harmonia update [--apply] [--receipt-dir <path>]");
    println!("  harmonia run-profile <profiles/<id>/index.json> [--apply] [--receipt-dir <path>]");
    println!("  harmonia subscription show");
    println!("  harmonia deployable-config export <profile-id> --out <path> [--harmonia-root <path>] [--mode copy|symlink] [--receipt-dir <path>]");
    println!("  harmonia pinned-artifacts check <profiles/<id>/index.json> [--lock <path>] [--receipt-dir <path>]");
    println!("  harmonia pinned-artifacts nudge <profiles/<id>/index.json> --lock <path> --artifact <name> --candidate <path> --version <version> --sha256 <sha256> [--receipt-dir <path>]");
    println!("  harmonia pinned-artifacts bless <profiles/<id>/index.json> --lock <path> --artifact <name> --candidate <path> --version <version> --sha256 <sha256> [--install-path <path>] [--apply] [--receipt-dir <path>]");
    println!("  harmonia homeserver-update <profiles/homeserver/index.json> [--apply] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-update <profiles/homeconsole/index.json> [--apply] [--receipt-dir <path>]");
    println!("  harmonia tv-update <profiles/tv/index.json> [--apply] [--receipt-dir <path>]");
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
