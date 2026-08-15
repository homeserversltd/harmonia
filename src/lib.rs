mod atoms;
mod stillness_bench;
mod structural_wall_bench;
#[path = "tools/build-venv/index.rs"]
pub(crate) mod build_venv;
#[path = "tools/build-crate/index.rs"]
pub(crate) mod build_crate;
#[path = "tools/install-package/index.rs"]
pub(crate) mod install_package;
#[path = "tools/pull-repo/index.rs"]
pub(crate) mod pull_repo;
#[path = "tools/backfill-file/index.rs"]
mod backfill_file;
#[path = "tools/place-file/index.rs"]
mod place_file;
#[path = "tools/remove-file/index.rs"]
mod remove_file;
#[path = "tools/enable-unit/index.rs"]
pub(crate) mod enable_unit;
#[path = "tools/remove-unit/index.rs"]
pub(crate) mod remove_unit;
#[path = "tools/set-clock/index.rs"]
pub(crate) mod set_clock;
#[path = "tools/check-health/index.rs"]
pub(crate) mod check_health;
#[path = "tools/ratchet-aur-package/index.rs"]
pub(crate) mod ratchet_aur_package;
pub(crate) mod hyalos;
pub mod tools;
mod update_set;

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{self};

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

pub mod application_presets;
#[path = "bands/index.rs"]
mod bands;
mod arcadia_gui_runtime;
mod pinned_artifacts_runtime;

pub(crate) use arcadia_gui_runtime::{
    homeconsole_arcadia_check, homeconsole_arcadia_gui_update, homeconsole_arcadia_update,
};
pub(crate) use pinned_artifacts_runtime::pinned_artifacts_command;

mod capsule;
mod convergence_lock;
pub mod device_profile;
mod interactables;
mod hotfix;
mod ladder;
mod module_dispatch;
mod molt;
mod preflight;
mod profile_engine;
mod receipts;
mod schedule;
mod source_resolver;
mod subscription;

pub(crate) use atoms::r#do::transaction::RunContext;
pub(crate) use capsule::*;
pub(crate) use convergence_lock::*;
pub(crate) use device_profile::*;
pub(crate) use interactables::*;
pub(crate) use hotfix::*;
pub(crate) use ladder::*;
pub(crate) use module_dispatch::*;
pub(crate) use molt::*;
pub(crate) use preflight::*;
pub(crate) use profile_engine::*;
pub(crate) use receipts::*;
pub(crate) use source_resolver::*;
pub(crate) use subscription::*;

pub struct Invocation(Option<atoms::r#do::InvocationKey>, Option<RunContext>);

mod invocation_face {
    pub(crate) struct Mint(());

    pub(super) fn mint(args: &[String]) -> super::Invocation {
        let applies = args.iter().any(|arg| arg == "--apply")
            || args.first().is_some_and(|arg| {
                matches!(
                    arg.as_str(),
                    "acquire-source" | "bench-stillness" | "bench-structural-wall" | "bench-harmonia-foundation"
                )
            })
            || matches!(args, [command, action, ..] if matches!(command.as_str(), "interactable" | "config-proposal") && matches!(action.as_str(), "run" | "accept"));
        let key = super::atoms::r#do::InvocationKey::from_apply_or_timer(applies, Mint(()));
        let context = key.map(|key| super::RunContext {
            run_id: super::run_id_from_stamp(),
            profile: "production".into(),
            face: args.first().cloned().unwrap_or_else(|| "invoke".into()),
            key,
            carrier: std::rc::Rc::new(std::cell::RefCell::new(crate::atoms::r#do::transaction::RunCarrier::default())),
        });
        super::Invocation(key, context)
    }
}

pub fn invoke(args: Vec<String>) {
    let invocation = invocation_face::mint(&args);
    if let Err(err) = run(args, invocation) {
        eprintln!("harmonia_error={}", err);
        process::exit(1);
    }
}

pub fn main_entry() {
    invoke(env::args().skip(1).collect());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::module_steps::{artifact_promote_tool, command_tool, set_test_pacman_path};
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::Command;
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
            owner: None,
            group: None,
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
            modules: vec![],
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
    fn homeserver_update_requires_homeserver_identity() {
        let profile = Profile {
            package_authority: None,
            id: "homeserver".into(),
            identity: "homeconsole".into(),
            modules: vec![],
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
            package_authority: Some(PackageAuthority {
                os_family: "arch".into(),
                package_manager: "pacman".into(),
            }),
            id: "tv".into(),
            identity: "homeconsole".into(),
            modules: vec![],
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
            modules: load_profile(&repo_root().join("profiles/homeconsole/index.json"))
                .unwrap()
                .modules,
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
            owner: None,
            group: None,
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
            owner: None,
            group: None,
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
            owner: None,
            group: None,
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
                owner: None,
                group: None,
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
            owner: None,
            group: None,
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
            caduceus_commands: vec![],
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
            enforce_update_suite(&profile, &root.join("profiles/homeconsole/modules")).unwrap(),
            None
        );
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
        let source_profile: CaduceusProfileSourceManifest =
            serde_json::from_value(runtime.args["caduceus_profile_source"].clone()).unwrap();
        assert_eq!(source_profile.source, "profiles/homeserver/index.yaml");
        assert_eq!(source_profile.path, "/etc/caduceus/profile.yaml");
        for required in [
            "capability:",
            "household_verifying_key:",
            "default_ttl_seconds: 60",
            "harmonia_profile: /etc/harmonia/profiles/homeserver/index.json",
        ] {
            assert!(
                source_profile.append.contains(required),
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
        assert!(source_profile
            .append
            .contains("/etc/harmonia/profiles/homeserver/index.json"));
        assert!(source_profile
            .append
            .contains("/var/lib/harmonia/receipts/update-latest/run.json"));
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
        assert!(
            managed_files
                .iter()
                .all(|file| !file.path.starts_with("/usr/local/sbin/")),
            "homeserver Caduceus staff shelf must come from its synced source tree, not managed files"
        );
        let staff_step = caduceus
            .ladder
            .iter()
            .find(|step| step.step_id == "caduceus-staff-shelf-from-synced-source")
            .expect("homeserver Caduceus source-derived staff shelf step");
        assert_eq!(staff_step.tool, "files");
        assert_eq!(staff_step.permutation, "source-shelf-sweep");
        assert_eq!(
            staff_step.args["source_root"],
            "/opt/caduceus/source/data/staff-actuators"
        );
        assert_eq!(staff_step.args["shelf_source"], "agathodaimon");
        assert_eq!(
            staff_step.args["target_shelf"],
            "/usr/local/sbin/agathodaimon"
        );
        assert_eq!(staff_step.args["launcher_pattern"], "caduceus-*");
        assert_eq!(staff_step.args["shelf_directory_mode"], 0o755);
        assert_eq!(staff_step.args["shelf_file_mode"], 0o644);
        assert_eq!(staff_step.args["launcher_mode"], 0o755);
        assert_eq!(staff_step.args["prune"], true);
        assert!(!staff_step.args.contains_key("program"));
        assert!(root
            .join("profiles/homeserver/modules/caduceus/files_root/etc/sudoers.d/caduceus-keyman")
            .is_file());
        assert!(!root
            .join("profiles/homeserver/modules/caduceus/files_root/usr/local/sbin/agathodaimon")
            .exists());
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
                "xdg-user-settings".to_string(),
                "chromium".to_string(),
                "user-session-services".to_string(),
                "sddm-autologin-hyprland".to_string(),
                "steam-game-lane".to_string(),
                "power-controller-maintenance".to_string(),
                "console-recovery".to_string(),
                "tv-update-runtime".to_string(),
                "household-time".to_string(),
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
        assert!(root
            .join(
                "profiles/tv/modules/xdg-user-settings/files_root/launcher-bin/bin/tv-launcher.sh"
            )
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
    fn homeserver_firewall_carries_terminated_caduceus_child_filter_without_package_or_quiet_restart_drift(
    ) {
        let root = repo_root();
        let module = root.join("profiles/homeserver/modules/firewall");
        let manifest = load_ladder_manifest(&module.join("manifest.json")).unwrap();
        validate_ladder(&manifest).unwrap();
        let baseline = fs::read_to_string(module.join("files_root/etc/nftables.conf")).unwrap();
        let include = "include \"/etc/nftables.d/caduceus-child-filter.nft\"";
        assert!(
            baseline.ends_with('\n'),
            "nftables candidate must end with a newline"
        );
        assert_eq!(baseline.lines().last(), Some(include));
        assert!(module
            .join("files_root/etc/nftables.d/caduceus-child-filter.nft")
            .is_file());
        let seed = manifest
            .ladder
            .iter()
            .find(|step| step.step_id == "caduceus-child-filter-seed-present")
            .unwrap();
        assert_eq!(
            (seed.tool.as_str(), seed.permutation.as_str()),
            ("files", "ensure-present")
        );
        assert_eq!(
            seed.args["files"],
            serde_json::json!(["etc/nftables.d/caduceus-child-filter.nft"])
        );
        let validation = manifest
            .ladder
            .iter()
            .find(|step| step.step_id == "nftables-config-valid")
            .unwrap();
        assert_eq!(
            validation.args["args"],
            serde_json::json!(["-c", "-f", "/etc/nftables.conf"])
        );
        assert!(manifest.ladder.iter().all(|step| step.tool != "package"));
        let seed_index = manifest
            .ladder
            .iter()
            .position(|step| step.step_id == seed.step_id)
            .unwrap();
        let validation_index = manifest
            .ladder
            .iter()
            .position(|step| step.step_id == validation.step_id)
            .unwrap();
        let restart_index = manifest
            .ladder
            .iter()
            .position(|step| step.step_id == "nftables-restart-on-change")
            .unwrap();
        assert!(seed_index < validation_index && validation_index < restart_index);

        let nft = ["/usr/sbin/nft", "nft"]
            .into_iter()
            .find(|candidate| Path::new(candidate).is_file());
        let Some(nft) = nft else {
            eprintln!("nft-parser-proof-unavailable: no nft executable found; structural termination wall retained");
            return;
        };
        let scratch = std::env::temp_dir().join(format!("harmonia-nft-proof-{}", process::id()));
        let _ = fs::remove_dir_all(&scratch);
        let child = scratch.join("nftables.d/caduceus-child-filter.nft");
        fs::create_dir_all(child.parent().unwrap()).unwrap();
        fs::copy(
            module.join("files_root/etc/nftables.d/caduceus-child-filter.nft"),
            &child,
        )
        .unwrap();
        let rendered = baseline
            .replace(
                "flush ruleset",
                "# flush ruleset omitted in isolated parser proof",
            )
            .replace("define lan_if = lan0", "define lan_if = lo")
            .replace("define wan_if = wan0", "define wan_if = lo")
            .replace(
                "/etc/nftables.d/caduceus-child-filter.nft",
                &child.display().to_string(),
            );
        let candidate = scratch.join("nftables.conf");
        fs::write(&candidate, rendered).unwrap();
        let output = Command::new(nft)
            .args(["-c", "-f"])
            .arg(&candidate)
            .output()
            .unwrap();
        let _ = fs::remove_dir_all(&scratch);
        if !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("Operation not permitted")
        {
            eprintln!("nft-parser-proof-unavailable: isolated parser lacks netlink permission; structural termination wall retained");
            return;
        }
        assert!(
            output.status.success(),
            "nft parser rejected isolated candidate: {}",
            String::from_utf8_lossy(&output.stderr)
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
            "steam retains command probes for package and declared-file checks"
        );
        assert_eq!(
            steam
                .ladder
                .iter()
                .filter(|step| step.tool == "files" && step.permutation == "executable-present")
                .count(),
            2,
            "steam executable probes use files/executable-present"
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
        assert!(steam_dir
            .join("files_root/usr/local/bin/arch-tv-steam-game-lane")
            .is_file());
        assert!(steam
            .ladder
            .iter()
            .any(|step| step.tool == "files" && step.permutation == "managed-files"));

        let caduceus_dir = root.join("profiles/tv/modules/caduceus-public-lever");
        let caduceus = load_ladder_manifest(&caduceus_dir.join("manifest.json")).unwrap();
        assert_eq!(caduceus.files_root.as_deref(), Some("files_root"));
        assert!(caduceus_dir
            .join("files_root/etc/caduceus/identity.json")
            .is_file());
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
            .join(
                "profiles/tv/modules/xdg-user-settings/files_root/launcher-bin/bin/tv-launcher.sh"
            )
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

        let xdg_root = root.join("profiles/tv/modules/xdg-user-settings/files_root");
        let refresh =
            fs::read_to_string(xdg_root.join("launcher-bin/bin/refresh-launcher-cache.sh"))
                .unwrap();
        assert!(refresh.contains("update-desktop-database"));
        assert!(refresh.contains("kbuildsycoca6"));
        assert!(refresh.contains("wofi-drun-cache"));

        let desktop =
            load_ladder_manifest(&root.join("profiles/tv/modules/xdg-user-settings/manifest.json"))
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
            package_authority: Some(PackageAuthority {
                os_family: "arch".into(),
                package_manager: "pacman".into(),
            }),
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
            let result = run_profile_engine_with_preflight(
                &profile,
                &module_root,
                &receipts,
                true,
                true,
                None,
                None,
            );
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
    fn missing_module_manifest_debt_runs_the_profile_modules() {
        fn write_command_module(module_root: &Path, module_id: &str) {
            let module_dir = module_root.join(module_id);
            fs::create_dir_all(&module_dir).unwrap();
            write_json(
                &module_dir.join("manifest.json"),
                &serde_json::json!({
                    "schema": "harmonia.module.ladder.v1",
                    "id": module_id,
                    "version": "1.0.0",
                    "description": format!("suite-debt fixture {module_id}"),
                    "ladder": [{
                        "step_id": "run",
                        "tool": "command",
                        "permutation": "capture",
                        "args": { "program": "/usr/bin/true" },
                        "on_failure": "stop"
                    }]
                }),
            )
            .unwrap();
        }

        let scratch =
            std::env::temp_dir().join(format!("harmonia-suite-spine-debt-{}", process::id()));
        let module_root = scratch.join("modules");
        let receipts = scratch.join("receipts");
        write_command_module(&module_root, "first");
        write_command_module(&module_root, "second");
        let profile = Profile {
            package_authority: None,
            id: "homeconsole".into(),
            identity: "homeconsole".into(),
            modules: vec!["first".into(), "second".into(), "missing".into()],
        };
        let suite_debt = enforce_update_suite(&profile, &module_root)
            .unwrap()
            .expect("missing manifest is recorded as debt");
        let result = run_profile_engine_with_preflight(
            &profile,
            &module_root,
            &receipts,
            true,
            true,
            None,
            Some(&suite_debt),
        );
        assert_eq!(result, Err(suite_debt.clone()));

        let run: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(receipts.join("run.json")).unwrap()).unwrap();
        assert_eq!(run["ok"], false);
        assert_eq!(run["suite_ok"], false);
        assert_eq!(run["first_missing_signal"], suite_debt);
        assert_eq!(run["module_count"], 2);
        assert_eq!(run["operation_count"], 2);
        for module in ["first", "second"] {
            assert!(receipts
                .join("modules")
                .join(module)
                .join("run.json")
                .exists());
        }
        let _ = fs::remove_dir_all(scratch);
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

    fn write_molt_fixture(root: &Path) {
        fs::create_dir_all(root.join("src/tools")).unwrap();
        fs::write(root.join("Cargo.toml"), "[package]\nname = \"fixture\"\n").unwrap();
        fs::create_dir_all(root.join("profiles/fixture/modules")).unwrap();
        fs::write(root.join("profiles/fixture/index.json"), r#"{"schema":"harmonia.profile.v1","id":"fixture","identity":"fixture","modules":["alpha","beta"]}"#).unwrap();
        for module in ["alpha", "beta"] {
            let module_root = root.join("profiles/fixture/modules").join(module);
            fs::create_dir_all(module_root.join("files_root")).unwrap();
            fs::write(module_root.join("manifest.json"), format!(r#"{{"schema":"harmonia.module.ladder.v1","id":"{module}","version":"1.0.0","description":"fixture","files_root":"files_root","ladder":[]}}"#)).unwrap();
            fs::write(module_root.join("files_root/payload.txt"), module).unwrap();
        }
    }

    #[test]
    fn molt_comes_from_harmonia_profile_tree() {
        let root = repo_root();
        let scratch = std::env::temp_dir().join(format!("harmonia-molt-{}", process::id()));
        let output = scratch.join("payload");
        let receipts = scratch.join("receipts");
        molt_at_subscription_path(
            &root,
            "homeconsole",
            &output,
            &receipts,
            &scratch.join("subscription.json"),
            MoltMode::Copy,
        )
        .unwrap();
        assert!(output.join("index.json").exists());
        assert!(output
            .join("modules/arcadia-gui-runtime/manifest.json")
            .exists());
        assert!(output
            .join("modules/pinned-artifacts-runtime/manifest.json")
            .exists());
        assert!(!output
            .join("modules/homeconsole-update-runtime/files_root")
            .exists());
        assert!(output
            .join("locks/pinned-artifacts.json")
            .exists());
        assert!(receipts.join("molt.json").exists());
        let receipt = fs::read_to_string(receipts.join("molt.json")).unwrap();
        assert!(receipt.contains("harmonia.molt.v1"));
        assert!(receipt.contains("profile-index"));
        assert!(receipt.contains("module-ladder-manifest"));
        assert!(receipt.contains("profile-lock"));
        assert!(
            !output
                .join("modules/arcadia-gui-runtime/index.rs")
                .exists(),
            "molt carries constants, not module code"
        );
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn molt_uses_the_same_flat_profile_layout_for_absent_and_existing_output_roots() {
        fn relative_file_bytes(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
            fn collect(root: &Path, current: &Path, files: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>) {
                for entry in fs::read_dir(current).unwrap() {
                    let entry = entry.unwrap(); let path = entry.path();
                    if entry.file_type().unwrap().is_dir() { collect(root, &path, files); }
                    else { files.insert(path.strip_prefix(root).unwrap().to_path_buf(), fs::read(path).unwrap()); }
                }
            }
            let mut files = std::collections::BTreeMap::new(); collect(root, root, &mut files); files
        }
        let scratch = std::env::temp_dir().join(format!("harmonia-molt-layout-{}", process::id()));
        let root = scratch.join("root"); let absent_output = scratch.join("absent-output"); let existing_output = scratch.join("existing-output");
        write_molt_fixture(&root);
        molt_at_subscription_path(&root, "fixture", &absent_output, &scratch.join("absent-receipts"), &scratch.join("absent-subscription.json"), MoltMode::Copy).unwrap();
        fs::create_dir_all(&existing_output).unwrap();
        molt_at_subscription_path(&root, "fixture", &existing_output, &scratch.join("existing-receipts"), &scratch.join("existing-subscription.json"), MoltMode::Copy).unwrap();
        assert!(absent_output.join("index.json").is_file()); assert!(absent_output.join("modules/alpha/manifest.json").is_file());
        assert!(!absent_output.join("profiles/fixture").exists());
        assert_eq!(relative_file_bytes(&absent_output), relative_file_bytes(&existing_output));
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn molt_skips_unchanged_modules_and_recopies_only_changed_module() {
        let scratch = std::env::temp_dir().join(format!("harmonia-molt-stale-{}", process::id()));
        let root = scratch.join("root");
        let output = scratch.join("output");
        let receipts = scratch.join("receipts");
        let subscription = scratch.join("subscription.json");
        write_molt_fixture(&root);
        for _ in 0..2 {
            molt_at_subscription_path(
                &root,
                "fixture",
                &output,
                &receipts,
                &subscription,
                MoltMode::Copy,
            )
            .unwrap();
        }
        let receipt: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(receipts.join("molt.json")).unwrap()).unwrap();
        assert_eq!(receipt["untouched_modules"], json!(["alpha", "beta"]));
        assert!(receipt["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| !a["source"].as_str().unwrap().contains("/modules/")));

        fs::write(
            root.join("profiles/fixture/modules/alpha/files_root/payload.txt"),
            "alpha changed",
        )
        .unwrap();
        molt_at_subscription_path(
            &root,
            "fixture",
            &output,
            &receipts,
            &subscription,
            MoltMode::Copy,
        )
        .unwrap();
        let receipt: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(receipts.join("molt.json")).unwrap()).unwrap();
        assert_eq!(receipt["untouched_modules"], json!(["beta"]));
        assert!(receipt["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["source"].as_str().unwrap().contains("/modules/alpha/")));
        assert!(receipt["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| !a["source"].as_str().unwrap().contains("/modules/beta/")));
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn molt_carries_ladder_module_sibling_files() {
        let root = repo_root();
        let scratch =
            std::env::temp_dir().join(format!("harmonia-molt-tv-ratchet-{}", process::id()));
        let output = scratch.join("payload");
        let receipts = scratch.join("receipts");
        molt_at_subscription_path(
            &root,
            "tv",
            &output,
            &receipts,
            &scratch.join("subscription.json"),
            MoltMode::Copy,
        )
        .unwrap();
        assert!(output
            .join("profiles/tv/modules/oh-my-posh-aur-ratchet/manifest.json")
            .exists());
        assert!(output
            .join("profiles/tv/modules/oh-my-posh-aur-ratchet/ratchet-lock.json")
            .exists());
        let receipt = fs::read_to_string(receipts.join("molt.json")).unwrap();
        assert!(receipt.contains("module-ladder-sibling-file"));
        assert!(receipt.contains("ratchet-lock.json"));
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn molt_rejects_non_harmonia_authority_root() {
        let scratch = std::env::temp_dir().join(format!("harmonia-molt-reject-{}", process::id()));
        fs::create_dir_all(scratch.join("profiles/homeconsole")).unwrap();
        fs::write(
            scratch.join("profiles/homeconsole/index.json"),
            r#"{"schema":"harmonia.profile.v1","id":"homeconsole","identity":"homeconsole","modules":[]}"#,
        )
        .unwrap();
        let err = molt_at_subscription_path(
            &scratch,
            "homeconsole",
            &scratch.join("payload"),
            &scratch.join("receipts"),
            &scratch.join("subscription.json"),
            MoltMode::Copy,
        )
        .unwrap_err();
        assert!(err.contains("molt-harmonia-root-rejected"));
        let _ = fs::remove_dir_all(scratch);
    }

    #[test]
    fn keyman_module_requires_git_checkout_authority() {
        let root = repo_root();
        assert!(!root
            .join("profiles/homeconsole/modules/harmonia-runtime")
            .exists());
        let module = "keyman-runtime";
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

    #[test]
    fn homeconsole_caduceus_public_lever_sidecar_stands_up_http_runtime() {
        let root = repo_root();
        let manifest =
            load_ladder_manifest(&root.join(
                "profiles/homeconsole/modules/homeconsole-caduceus-public-lever/manifest.json",
            ))
            .unwrap();
        assert_eq!(manifest.id, "homeconsole-caduceus-public-lever");
        let runtime = manifest
            .ladder
            .iter()
            .find(|step| step.tool == "service-runtime")
            .expect("homeconsole caduceus service-runtime step");
        assert_eq!(runtime.args["component"].as_str(), Some("caduceus"));
        assert_eq!(
            runtime.args["source_dir"].as_str(),
            Some("/opt/caduceus/source")
        );
        assert_eq!(runtime.args["service"].as_str(), Some("caduceus.service"));
        assert_eq!(
            runtime.args["url"].as_str(),
            Some("http://127.0.0.1:8787/health")
        );
        let managed_files: Vec<ManagedFileManifest> =
            serde_json::from_value(runtime.args["managed_files"].clone()).unwrap();
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
                vec![
                    ("files", "managed-directories"),
                    ("command", "capture"),
                    ("command", "capture"),
                    ("command", "capture"),
                    ("service-runtime", "converge"),
                    ("files", "source-shelf-sweep"),
                    ("files", "managed-files"),
                ],
            ),
            (
                "homeserver",
                "coronatio",
                vec![
                    ("service-runtime", "converge"),
                    ("files", "executable-present"),
                    ("command", "capture"),
                    ("command", "capture"),
                    ("files", "converge"),
                    ("command", "capture"),
                ],
            ),
            (
                "homeconsole",
                "homeconsole-caduceus-public-lever",
                vec![
                    ("command", "capture"),
                    ("git-artifact", "sync"),
                    ("files", "source-shelf-sweep"),
                    ("service-runtime", "converge"),
                ],
            ),
            (
                "homeconsole",
                "local-ai-runtime",
                vec![
                    ("package", "install"),
                    ("command", "capture"),
                    ("files", "symlink-converge"),
                    ("files", "symlink-converge"),
                    ("command", "capture"),
                    ("systemd", "is-active-probe"),
                ],
            ),

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

        let coronatio =
            load_ladder_manifest(&root.join("profiles/homeserver/modules/coronatio/manifest.json"))
                .unwrap();
        let coronatio_runtime = coronatio
            .ladder
            .iter()
            .find(|step| step.step_id == "coronatio-service-runtime")
            .unwrap();
        assert_eq!(
            coronatio_runtime.args["identity_environment"],
            json!(["CORONATIO_SOURCE_SHA", "CORONATIO_BUILD_SHA"])
        );

        let local_ai = load_ladder_manifest(
            &root.join("profiles/homeconsole/modules/local-ai-runtime/manifest.json"),
        )
        .unwrap();
        for (step_id, source, target) in [
            (
                "local-ai-server-link",
                "/usr/bin/llama-server",
                "/usr/local/bin/llama-server",
            ),
            (
                "local-ai-cli-link",
                "/usr/bin/llama-cli",
                "/usr/local/bin/llama-cli",
            ),
        ] {
            let step = local_ai
                .ladder
                .iter()
                .find(|step| step.step_id == step_id)
                .unwrap();
            assert_eq!(step.tool, "files");
            assert_eq!(step.permutation, "symlink-converge");
            assert_eq!(step.args["source"], source);
            assert_eq!(step.args["target"], target);
            assert_eq!(step.args["required_source_kind"], "regular-executable");
            assert_eq!(step.args["owner"], "root");
            assert_eq!(step.args["group"], "root");
            assert!(!step.args.contains_key("program"));
            assert!(!step.args.contains_key("args"));
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
                ("files", "executable-present")
            ]
        );
        let executable_step = ratchet
            .ladder
            .iter()
            .find(|step| step.step_id == "binary-oh-my-posh")
            .unwrap();
        assert_eq!(
            executable_step.args["executable"].as_str(),
            Some("oh-my-posh")
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

pub(crate) fn run(args: Vec<String>, invocation: Invocation) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("bench-update-set") => update_set::bench(&args[1..]),
        Some("bench-harmonia-foundation") => atoms::r#do::transaction::bench(
            &args[1..],
            invocation
                .1
                .clone()
                .ok_or_else(|| "foundation-invocation-key-missing".to_string())?,
        ),
        Some("bench-stillness") => stillness_bench::run(invocation.0),
        Some("bench-structural-wall") => structural_wall_bench::run(invocation.0),
        Some("interactable") | Some("config-proposal") => {
            interactable_command(&args[1..], invocation.0)
        }
        Some("install-timer") => schedule::install_timer(&args[1..]),
        Some("uninstall-timer") => schedule::uninstall_timer(&args[1..]),
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
                        Some(serde_json::json!({"schema": "harmonia.ladder.validate.v1", "ok": true})),
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
                        Some(serde_json::json!({"schema": "harmonia.ladder.validate.v1", "ok": false})),
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
            let receipt = resolve_source_json(&certificate, component, &owning_module, &step_id);
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
            let resolution = resolve_source(
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
            let config = load_engine_plane_config(&engine_config)?
                .ok_or_else(|| format!("engine-config-missing {}", engine_config.display()))?;
            let bearer = value_arg_string(&args, "--bearer").unwrap_or(config.git_bearer.clone());
            let expected_commit = value_arg_string(&args, "--expected-commit");
            let acquisition = bridge_acquisition_plan(
                &plan,
                destination,
                bearer,
                expected_commit,
                credential_scopes(&config),
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
            let mode = UpdateMode::from_apply_flag_with_invocation(args.iter().any(|arg| arg == "--apply"), invocation.0);
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
            let mode = UpdateMode::from_apply_flag_with_invocation(args.iter().any(|arg| arg == "--apply"), invocation.0);
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
            let mode = UpdateMode::from_apply_flag_with_invocation(args.iter().any(|arg| arg == "--apply"), invocation.0);
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
            let mode = UpdateMode::from_apply_flag_with_invocation(args.iter().any(|arg| arg == "--apply"), invocation.0);
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
            let mode = UpdateMode::from_apply_flag_with_invocation(args.iter().any(|arg| arg == "--apply"), invocation.0);
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
            let execution =
                execute_profile_module(
                    &module,
                    &module_root,
                    &receipt_dir,
                    mode.software_authorization(),
                    &harmonia_root,
                    mode.invocation(),
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
                Some(serde_json::json!({"schema": "harmonia.local_ai_runtime.v1", "ok": execution.ok})),
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
            let mode = UpdateMode::from_apply_flag_with_invocation(args.iter().any(|arg| arg == "--apply"), invocation.0);
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

pub(crate) fn usage() -> Result<(), String> {
    println!("harmonia {}", VERSION);
    println!("usage:");
    println!("  harmonia explain");
    println!("  harmonia inspect-profile <profiles/<id>/index.json>");
    println!("  harmonia toolbelt");
    println!("  harmonia config-proposal list [--json]");
    println!("  harmonia config-proposal accept <id>");
    println!("  harmonia install-timer [--systemd-root <path>] [--dry-run]");
    println!("  harmonia uninstall-timer [--systemd-root <path>] [--dry-run]");
    println!("  harmonia validate-ladder <manifest.json>");
    println!("  harmonia resolve-source <component> --certificate <path> [--owner-module <id>] [--step-id <id>]");
    println!("  harmonia acquire-source <component> --certificate <path> --engine-config <path> --destination <path> [--bearer <name>] [--expected-commit <sha>]");
    println!("  harmonia plan-run <profiles/<id>/index.json> [--receipt-dir <path>]");
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
