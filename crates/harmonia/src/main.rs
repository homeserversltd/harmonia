use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::time::Instant;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const TOOLBELT: &[(&str, &str)] = &[
    ("archive", "Archive unpack/pack primitive for tar/zip release payloads."),
    ("artifact", "Artifact install/promote/rollback primitive for binaries and release payloads."),
    ("backup", "Backup/snapshot/preserve/restore primitive for mutable runtime state."),
    ("command", "Host command execution primitive with cwd/env/timeout/exit capture; every subprocess produces a command receipt."),
    ("config", "Typed config/JSON/TOML/YAML read/write/validate primitive."),
    ("cron-timer", "Cron/systemd timer install/enable/status primitive."),
    ("download", "HTTP download/version discovery primitive with bounded network calls and receipt evidence."),
    ("files", "Staged file/template/directory/symlink primitive with atomic promotion."),
    ("git-artifact", "Git branch/tag/artifact fetch primitive for source and release payloads."),
    ("health", "Service readiness and health-readback primitive, including HTTP and command checks."),
    ("hotfix", "Emergency one-shot hotfix primitive with explicit receipt and retirement path."),
    ("interactable", "Operator-triggered action primitive for manual buttons that still need receipts."),
    ("migration", "Ordered idempotent migration primitive with applied-state receipts."),
    ("node-build", "Node/npm/pnpm build primitive for web bodies."),
    ("package", "OS package check/update/install primitive; supports pacman first and later apt/dnf adapters."),
    ("permissions", "Owner/group/mode/ACL/sudoers policy primitive with validation before promotion."),
    ("receipt", "Central receipt writer and run ledger primitive."),
    ("rust-build", "Cargo build/test/install primitive for Rust bodies such as Arcadia and Harmonia."),
    ("systemd", "Systemd unit install/enable/disable/start/stop/restart/status primitive."),
    ("venv", "Python virtualenv preservation/update primitive for quarry compatibility surfaces; not a Harmonia authority lane."),
    ("version", "Version detection/compare/channel selection primitive."),
];

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

fn main() {
    if let Err(err) = run(env::args().skip(1).collect()) {
        eprintln!("harmonia_error={}", err);
        process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
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
            println!("profile_family={}", profile.family);
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
            let module_root = value_arg(&args, "--module-root")
                .unwrap_or_else(|| default_module_root(Path::new(path)));
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            run_profile_engine(&profile, &module_root, &receipt_dir, apply)
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
            homeconsole_update(&profile, &receipt_dir, apply)
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
        _ => usage(),
    }
}

fn toolbelt() -> Result<(), String> {
    println!("schema=harmonia.toolbelt.v1");
    println!("ok=true");
    println!("tool_count={}", TOOLBELT.len());
    for (name, description) in TOOLBELT {
        println!("tool={} description={}", name, description);
    }
    Ok(())
}

fn explain() -> Result<(), String> {
    println!("schema=harmonia.explain.v1");
    println!("ok=true");
    println!("name=harmonia");
    println!("version={}", VERSION);
    println!("covenant=Rust update manager and appliance-profile execution engine");
    println!("shell=bootstrap-only");
    println!("python_helper_lane=false");
    println!("profiles=homeserver,homeconsole,tv");
    println!("homeconsole_equals_arch_console=true");
    Ok(())
}

fn usage() -> Result<(), String> {
    println!("harmonia {}", VERSION);
    println!("usage:");
    println!("  harmonia explain");
    println!("  harmonia inspect-profile <profiles/<id>/index.json>");
    println!("  harmonia toolbelt");
    println!("  harmonia plan-run <profiles/<id>/index.json> [--receipt-dir <path>]");
    println!("  harmonia run-profile <profiles/<id>/index.json> [--module-root <path>] [--apply] [--receipt-dir <path>]");
    println!("  harmonia pinned-artifacts check <profiles/<id>/index.json> [--lock <path>] [--receipt-dir <path>]");
    println!("  harmonia pinned-artifacts nudge <profiles/<id>/index.json> --lock <path> --artifact <name> --candidate <path> --version <version> --sha256 <sha256> [--receipt-dir <path>]");
    println!("  harmonia pinned-artifacts bless <profiles/<id>/index.json> --lock <path> --artifact <name> --candidate <path> --version <version> --sha256 <sha256> [--install-path <path>] [--apply] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-update <profiles/homeconsole/index.json> [--apply] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-sync <profiles/homeconsole/index.json> [--module <modules/homeconsole/sync/index.json>] [--provider-env <path>] [--adapter-command <path>] [--apply] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-keyman-update <profiles/homeconsole/index.json> --source <keyman-source> [--apply] [--store-dir /opt/keyman/source] [--runtime-dir /vault/keyman] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-arcadia-check <profiles/homeconsole/index.json> [--repo <url>] [--branch main] [--current-sha-file <path>] [--upstream-sha-file <path>] [--insecure-tls] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-arcadia-update <profiles/homeconsole/index.json> --artifact <path> [--apply] [--install-bin <path>] [--service arcadia.service] [--source-sha <sha>] [--source-sha-file <path>] [--receipt-dir <path>]");
    Ok(())
}

fn receipt_dir_arg(args: &[String]) -> Option<PathBuf> {
    value_arg(args, "--receipt-dir")
}

fn value_arg(args: &[String], name: &str) -> Option<PathBuf> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| PathBuf::from(&pair[1]))
}

fn value_arg_string(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn default_module_root(profile_path: &Path) -> PathBuf {
    let profile_dir = profile_path.parent().unwrap_or_else(|| Path::new("."));
    let profile_id = profile_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");
    profile_dir
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or_else(|| Path::new("."))
        .join("modules")
        .join(profile_id)
}

fn default_pinned_lock_path(profile: &Profile) -> PathBuf {
    PathBuf::from("/etc/harmonia/locks")
        .join(&profile.id)
        .join("pinned-artifacts.json")
}

fn load_profile(path: &Path) -> io::Result<Profile> {
    let text = fs::read_to_string(path)?;
    serde_json::from_str(&text).or_else(|_| {
        Ok(Profile {
            id: extract_string(&text, "id").unwrap_or_else(|| "unknown".to_string()),
            family: extract_string(&text, "family").unwrap_or_else(|| "unknown".to_string()),
            modules: extract_string_array(&text, "modules"),
        })
    })
}

fn load_module(path: &Path) -> Result<ModuleManifest, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("module-read-failed {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("module-parse-failed {}: {e}", path.display()))
}

fn run_profile_engine(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    apply: bool,
) -> Result<(), String> {
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let mut events = File::create(receipt_dir.join("events.jsonl")).map_err(|e| e.to_string())?;
    event(
        &mut events,
        "engine-start",
        true,
        &format!("profile {}", profile.id),
    )?;
    let mut ok = true;
    let mut changed = false;
    let mut first_missing_signal = "none".to_string();
    let mut module_count = 0usize;
    let mut step_count = 0usize;

    for module_id in &profile.modules {
        let module_path = module_root.join(module_id).join("index.json");
        let module = match load_module(&module_path) {
            Ok(m) => m,
            Err(err) => {
                ok = false;
                if first_missing_signal == "none" {
                    first_missing_signal = format!("module-missing-{module_id}");
                }
                event(&mut events, "module-load", false, &err)?;
                continue;
            }
        };
        module_count += 1;
        event(&mut events, "module-start", true, &module.id)?;
        for step in &module.steps {
            step_count += 1;
            let step_dir = receipt_dir.join("steps").join(&module.id);
            fs::create_dir_all(&step_dir).map_err(|e| e.to_string())?;
            let outcome = execute_step(step, &step_dir, apply)?;
            if outcome.changed {
                changed = true;
            }
            if !outcome.ok {
                ok = false;
                if first_missing_signal == "none" {
                    first_missing_signal = format!("{}-{}-failed", module.id, step.id);
                }
            }
            let ev = if outcome.skipped {
                "step-skipped"
            } else {
                "step-complete"
            };
            event(
                &mut events,
                ev,
                outcome.ok,
                &format!("{}:{} {}", module.id, step.id, outcome.message),
            )?;
        }
    }

    write_engine_run_receipt(
        receipt_dir,
        profile,
        apply,
        ok,
        changed,
        module_count,
        step_count,
        &first_missing_signal,
        module_root,
    )?;
    println!("schema=harmonia.run_profile.v1");
    println!("ok={}", ok);
    println!("changed={}", changed);
    println!("profile_id={}", profile.id);
    println!("module_count={}", module_count);
    println!("step_count={}", step_count);
    println!("first_missing_signal={}", first_missing_signal);
    println!("receipt_dir={}", receipt_dir.display());
    if ok {
        Ok(())
    } else {
        Err(first_missing_signal)
    }
}

fn execute_step(step: &Step, receipt_dir: &Path, apply: bool) -> Result<StepOutcome, String> {
    if step.apply_only && !apply {
        write_step_receipt(
            receipt_dir,
            step,
            true,
            false,
            true,
            "apply-only planned",
            None,
        )?;
        return Ok(StepOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "apply-only planned".into(),
            command: None,
        });
    }
    let outcome = match step.tool.as_str() {
        "command" => exec_command_step(step),
        "package" => exec_package_step(step, apply),
        "systemd" => exec_systemd_step(step, apply),
        "artifact" => exec_artifact_step(step, apply),
        "health" => exec_health_step(step),
        "rust-build" => exec_cargo_step(step),
        "node-build" => exec_node_step(step),
        "receipt" | "config" | "version" | "backup" | "files" | "permissions" | "download"
        | "archive" | "git-artifact" | "cron-timer" | "migration" | "hotfix" | "interactable"
        | "venv" => Ok(StepOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: format!("{} contract acknowledged", step.tool),
            command: None,
        }),
        other => Ok(StepOutcome {
            ok: false,
            changed: false,
            skipped: false,
            message: format!("unknown tool {other}"),
            command: None,
        }),
    }?;
    write_step_receipt(
        receipt_dir,
        step,
        outcome.ok,
        outcome.changed,
        outcome.skipped,
        &outcome.message,
        outcome.command.as_ref(),
    )?;
    Ok(outcome)
}

fn exec_command_step(step: &Step) -> Result<StepOutcome, String> {
    let program = step
        .command
        .as_deref()
        .ok_or_else(|| format!("step {} missing command", step.id))?;
    let arg_refs: Vec<&str> = step.args.iter().map(String::as_str).collect();
    let result = command_capture_with_cwd(program, &arg_refs, step.cwd.as_deref());
    Ok(StepOutcome {
        ok: result.ok,
        changed: false,
        skipped: false,
        message: format!("command {}", program),
        command: Some(result),
    })
}

fn exec_package_step(step: &Step, apply: bool) -> Result<StepOutcome, String> {
    let action = if step.action.is_empty() {
        "check"
    } else {
        step.action.as_str()
    };
    if !Path::new("/usr/bin/pacman").exists() {
        return Ok(StepOutcome {
            ok: !apply,
            changed: false,
            skipped: !apply,
            message: if apply {
                "pacman missing for package mutation".to_string()
            } else {
                "package manager absent on scout host; planned only".to_string()
            },
            command: None,
        });
    }
    let result = match action {
        "update" if apply => command_capture("/usr/bin/pacman", &["-Syu", "--noconfirm"]),
        "update" | "check" => command_capture("/usr/bin/pacman", &["-Qu"]),
        "install" if apply => {
            let mut args = vec!["-S", "--noconfirm"];
            args.extend(step.args.iter().map(String::as_str));
            command_capture("/usr/bin/pacman", &args)
        }
        "install" => command_capture("/usr/bin/pacman", &["-Q"]),
        other => {
            return Ok(StepOutcome {
                ok: false,
                changed: false,
                skipped: false,
                message: format!("unsupported package action {other}"),
                command: None,
            })
        }
    };
    let changed =
        action == "update" && apply && result.ok && pacman_stdout_indicates_change(&result.stdout);
    Ok(StepOutcome {
        ok: action != "check" || result.ok || result.code == 1,
        changed,
        skipped: false,
        message: format!("package {action}"),
        command: Some(result),
    })
}

fn exec_systemd_step(step: &Step, apply: bool) -> Result<StepOutcome, String> {
    let action = if step.action.is_empty() {
        "status"
    } else {
        step.action.as_str()
    };
    let service = step.service.as_deref().unwrap_or("");
    let mutating = matches!(
        action,
        "start" | "stop" | "restart" | "enable" | "disable" | "daemon-reload"
    );
    if mutating && !apply {
        return Ok(StepOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: format!("systemd {action} planned"),
            command: None,
        });
    }
    let result = match action {
        "daemon-reload" => command_capture("/usr/bin/systemctl", &["daemon-reload"]),
        "active" | "is-active" => command_capture("/usr/bin/systemctl", &["is-active", service]),
        "status" => command_capture("/usr/bin/systemctl", &["status", service, "--no-pager"]),
        "start" | "stop" | "restart" | "enable" | "disable" => {
            command_capture("/usr/bin/systemctl", &[action, service])
        }
        other => {
            return Ok(StepOutcome {
                ok: false,
                changed: false,
                skipped: false,
                message: format!("unsupported systemd action {other}"),
                command: None,
            })
        }
    };
    Ok(StepOutcome {
        ok: result.ok,
        changed: mutating,
        skipped: false,
        message: format!("systemd {action} {service}"),
        command: Some(result),
    })
}

fn exec_artifact_step(step: &Step, apply: bool) -> Result<StepOutcome, String> {
    let artifact = PathBuf::from(
        step.artifact
            .as_deref()
            .ok_or_else(|| format!("step {} missing artifact", step.id))?,
    );
    let install_bin = PathBuf::from(
        step.install_bin
            .as_deref()
            .ok_or_else(|| format!("step {} missing install_bin", step.id))?,
    );
    let metadata = fs::metadata(&artifact)
        .map_err(|e| format!("artifact-missing {}: {e}", artifact.display()))?;
    if !apply {
        return Ok(StepOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: format!("artifact planned bytes={}", metadata.len()),
            command: None,
        });
    }
    if let Some(parent) = install_bin.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let before_len = fs::metadata(&install_bin).map(|m| m.len()).ok();
    let tmp_install = install_bin.with_extension("harmonia-new");
    fs::copy(&artifact, &tmp_install).map_err(|e| format!("artifact-copy-failed: {e}"))?;
    let mut perms = fs::metadata(&tmp_install)
        .map_err(|e| e.to_string())?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&tmp_install, perms).map_err(|e| e.to_string())?;
    fs::rename(&tmp_install, &install_bin).map_err(|e| format!("artifact-promote-failed: {e}"))?;
    Ok(StepOutcome {
        ok: true,
        changed: before_len != Some(metadata.len()),
        skipped: false,
        message: format!("artifact promoted to {}", install_bin.display()),
        command: None,
    })
}

fn exec_health_step(step: &Step) -> Result<StepOutcome, String> {
    if let Some(url) = &step.url {
        let result = command_capture("/usr/bin/curl", &["-fsS", "--max-time", "3", url]);
        let expected_ok = step
            .expected_contains
            .as_ref()
            .map(|needle| result.stdout.contains(needle))
            .unwrap_or(true);
        return Ok(StepOutcome {
            ok: result.ok && expected_ok,
            changed: false,
            skipped: false,
            message: format!("health {url}"),
            command: Some(result),
        });
    }
    exec_command_step(step)
}

fn exec_cargo_step(step: &Step) -> Result<StepOutcome, String> {
    let args = if step.args.is_empty() {
        vec!["build".to_string(), "--release".to_string()]
    } else {
        step.args.clone()
    };
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = command_capture_with_cwd("/usr/bin/cargo", &arg_refs, step.cwd.as_deref());
    Ok(StepOutcome {
        ok: result.ok,
        changed: false,
        skipped: false,
        message: "cargo".into(),
        command: Some(result),
    })
}

fn exec_node_step(step: &Step) -> Result<StepOutcome, String> {
    let command = step.command.as_deref().unwrap_or("/usr/bin/npm");
    let args = if step.args.is_empty() {
        vec!["run".to_string(), "build".to_string()]
    } else {
        step.args.clone()
    };
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = command_capture_with_cwd(command, &arg_refs, step.cwd.as_deref());
    Ok(StepOutcome {
        ok: result.ok,
        changed: false,
        skipped: false,
        message: "node-build".into(),
        command: Some(result),
    })
}

fn pinned_artifacts_command(
    action: &str,
    profile: &Profile,
    lock_path: &Path,
    receipt_dir: &Path,
    args: &[String],
) -> Result<(), String> {
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    match action {
        "check" => pinned_artifacts_check(profile, lock_path, receipt_dir),
        "nudge" => pinned_artifacts_nudge(profile, lock_path, receipt_dir, args),
        "bless" => pinned_artifacts_bless(profile, lock_path, receipt_dir, args),
        other => Err(format!("unsupported pinned-artifacts action {other}")),
    }
}

fn load_pinned_lock(lock_path: &Path) -> Result<PinnedArtifactsLock, String> {
    let text = fs::read_to_string(lock_path)
        .map_err(|e| format!("pinned-lock-read-failed {}: {e}", lock_path.display()))?;
    serde_json::from_str(&text)
        .map_err(|e| format!("pinned-lock-parse-failed {}: {e}", lock_path.display()))
}

fn write_pinned_lock(lock_path: &Path, lock: &PinnedArtifactsLock) -> Result<(), String> {
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let value = serde_json::to_value(lock).map_err(|e| e.to_string())?;
    write_json(lock_path, &value)
}

fn pinned_artifacts_status(lock: &PinnedArtifactsLock) -> Vec<PinnedArtifactStatus> {
    let mut statuses = Vec::new();
    for (name, artifact) in &lock.artifacts {
        let path = Path::new(&artifact.path);
        let actual = sha256_file(path).ok();
        let exists = path.exists();
        let ok = actual
            .as_deref()
            .map(|sha| sha.eq_ignore_ascii_case(&artifact.sha256))
            .unwrap_or(false);
        statuses.push(PinnedArtifactStatus {
            name: name.clone(),
            version: artifact.version.clone(),
            path: artifact.path.clone(),
            expected_sha256: artifact.sha256.clone(),
            actual_sha256: actual,
            exists,
            ok,
            policy: artifact.policy.clone(),
        });
    }
    statuses.sort_by(|a, b| a.name.cmp(&b.name));
    statuses
}

fn pinned_artifacts_check(
    profile: &Profile,
    lock_path: &Path,
    receipt_dir: &Path,
) -> Result<(), String> {
    let lock = load_pinned_lock(lock_path)?;
    let statuses = pinned_artifacts_status(&lock);
    let ok = lock.profile == profile.id && statuses.iter().all(|status| status.ok);
    let first_missing_signal = if lock.profile != profile.id {
        "pinned-lock-profile-mismatch".to_string()
    } else {
        statuses
            .iter()
            .find(|status| !status.ok)
            .map(|status| format!("pinned-artifact-{}-drift", status.name))
            .unwrap_or_else(|| "none".to_string())
    };
    write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema": "harmonia.pinned_artifacts.check.v1",
            "ok": ok,
            "mutation": false,
            "profile_id": profile.id,
            "lock_path": lock_path,
            "artifact_count": statuses.len(),
            "first_missing_signal": first_missing_signal,
            "artifacts": statuses,
        }),
    )?;
    println!("schema=harmonia.pinned_artifacts.check.v1");
    println!("ok={}", ok);
    println!("profile_id={}", profile.id);
    println!("artifact_count={}", lock.artifacts.len());
    println!("first_missing_signal={}", first_missing_signal);
    println!("receipt_dir={}", receipt_dir.display());
    if ok {
        Ok(())
    } else {
        Err(first_missing_signal)
    }
}

fn pinned_artifacts_nudge(
    profile: &Profile,
    lock_path: &Path,
    receipt_dir: &Path,
    args: &[String],
) -> Result<(), String> {
    let lock = load_pinned_lock(lock_path)?;
    let name = required_value_string(args, "--artifact")?;
    let candidate = required_value(args, "--candidate")?;
    let version = required_value_string(args, "--version")?;
    let expected_sha = required_value_string(args, "--sha256")?;
    let actual_sha = sha256_file(&candidate)?;
    let ok = actual_sha.eq_ignore_ascii_case(&expected_sha);
    let staged_path = receipt_dir
        .join("candidates")
        .join(&name)
        .join(candidate.file_name().unwrap_or_default());
    if ok {
        if let Some(parent) = staged_path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::copy(&candidate, &staged_path)
            .map_err(|e| format!("candidate-stage-failed {}: {e}", staged_path.display()))?;
        let mode = fs::metadata(&candidate)
            .map_err(|e| e.to_string())?
            .permissions()
            .mode();
        fs::set_permissions(&staged_path, fs::Permissions::from_mode(mode))
            .map_err(|e| e.to_string())?;
    }
    let first_missing_signal = if ok {
        "none"
    } else {
        "candidate-sha256-mismatch"
    };
    write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema": "harmonia.pinned_artifacts.nudge.v1",
            "ok": ok,
            "mutation": false,
            "profile_id": profile.id,
            "lock_path": lock_path,
            "artifact": name,
            "candidate": candidate,
            "candidate_version": version,
            "expected_sha256": expected_sha,
            "actual_sha256": actual_sha,
            "staged_path": if ok { Some(staged_path) } else { None },
            "current_lock": lock.artifacts.get(&name),
            "first_missing_signal": first_missing_signal,
            "meaning": "candidate staged for manual proof; blessed known-good lock not advanced",
        }),
    )?;
    println!("schema=harmonia.pinned_artifacts.nudge.v1");
    println!("ok={}", ok);
    println!("artifact={}", name);
    println!("candidate_version={}", version);
    println!("first_missing_signal={}", first_missing_signal);
    println!("receipt_dir={}", receipt_dir.display());
    if ok {
        Ok(())
    } else {
        Err(first_missing_signal.to_string())
    }
}

fn pinned_artifacts_bless(
    profile: &Profile,
    lock_path: &Path,
    receipt_dir: &Path,
    args: &[String],
) -> Result<(), String> {
    let mut lock = load_pinned_lock(lock_path)?;
    if lock.profile != profile.id {
        return Err("pinned-lock-profile-mismatch".to_string());
    }
    let name = required_value_string(args, "--artifact")?;
    let candidate = required_value(args, "--candidate")?;
    let version = required_value_string(args, "--version")?;
    let expected_sha = required_value_string(args, "--sha256")?;
    let actual_sha = sha256_file(&candidate)?;
    if !actual_sha.eq_ignore_ascii_case(&expected_sha) {
        return Err("candidate-sha256-mismatch".to_string());
    }
    let apply = args.iter().any(|arg| arg == "--apply");
    let old = lock.artifacts.get(&name).cloned();
    let install_path = value_arg(args, "--install-path")
        .or_else(|| old.as_ref().map(|artifact| PathBuf::from(&artifact.path)))
        .ok_or("bless requires --install-path for new artifact")?;
    if apply {
        if let Some(parent) = install_path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let backup_path = install_path.with_extension("harmonia-prev");
        if install_path.exists() {
            fs::copy(&install_path, &backup_path)
                .map_err(|e| format!("backup-failed {}: {e}", backup_path.display()))?;
        }
        fs::copy(&candidate, &install_path)
            .map_err(|e| format!("install-failed {}: {e}", install_path.display()))?;
        fs::set_permissions(&install_path, fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
        lock.artifacts.insert(
            name.clone(),
            PinnedArtifact {
                version: version.clone(),
                path: install_path.display().to_string(),
                sha256: expected_sha.clone(),
                policy: "known-good".to_string(),
                source: value_arg_string(args, "--source"),
            },
        );
        write_pinned_lock(lock_path, &lock)?;
    }
    write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema": "harmonia.pinned_artifacts.bless.v1",
            "ok": true,
            "mutation": apply,
            "profile_id": profile.id,
            "lock_path": lock_path,
            "artifact": name,
            "old_lock": old,
            "new_lock": lock.artifacts.get(&name),
            "candidate": candidate,
            "candidate_version": version,
            "sha256": expected_sha,
            "install_path": install_path,
            "first_missing_signal": "none",
            "meaning": if apply { "known-good lock advanced and artifact relocked" } else { "bless planned; rerun with --apply to advance lock" },
        }),
    )?;
    println!("schema=harmonia.pinned_artifacts.bless.v1");
    println!("ok=true");
    println!("mutation={}", apply);
    println!("artifact={}", name);
    println!("candidate_version={}", version);
    println!("first_missing_signal=none");
    println!("receipt_dir={}", receipt_dir.display());
    Ok(())
}

fn required_value(args: &[String], name: &str) -> Result<PathBuf, String> {
    value_arg(args, name).ok_or_else(|| format!("missing required {name} <path>"))
}

fn required_value_string(args: &[String], name: &str) -> Result<String, String> {
    value_arg_string(args, name).ok_or_else(|| format!("missing required {name} <value>"))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file =
        File::open(path).map_err(|e| format!("sha256-open-failed {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn load_sync_module(path: &Path) -> Result<SyncModuleConfig, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("sync-module-read-failed {}: {e}", path.display()))?;
    serde_json::from_str(&text)
        .map_err(|e| format!("sync-module-parse-failed {}: {e}", path.display()))
}

fn parse_env_file(path: &Path) -> HashMap<String, String> {
    let mut envs = HashMap::new();
    let Ok(text) = fs::read_to_string(path) else {
        return envs;
    };
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || key.contains(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            continue;
        }
        let value = value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        envs.insert(key.to_string(), value);
    }
    envs
}

fn sync_provider_receipts(
    providers: &[SyncProviderConfig],
    env_values: &HashMap<String, String>,
) -> Vec<SyncProviderReceipt> {
    providers
        .iter()
        .map(|provider| {
            let missing: Vec<String> = provider
                .env_keys
                .iter()
                .filter(|key| !env_values.get(*key).map(|v| !v.is_empty()).unwrap_or(false))
                .cloned()
                .collect();
            SyncProviderReceipt {
                name: provider.name.clone(),
                configured: missing.is_empty(),
                required: provider.required,
                env_keys: provider.env_keys.clone(),
                missing_env_keys: missing,
            }
        })
        .collect()
}

fn command_capture_with_env(
    program: &str,
    args: &[&str],
    envs: &HashMap<String, String>,
) -> CmdResult {
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    match cmd.output() {
        Ok(output) => CmdResult {
            ok: output.status.success(),
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        },
        Err(err) => CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: err.to_string(),
        },
    }
}

fn homeconsole_sync(
    profile: &Profile,
    receipt_dir: &Path,
    module_path: &Path,
    provider_env_override: Option<&Path>,
    adapter_override: Option<&str>,
    apply: bool,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.family != "arch-console" {
        return Err(format!(
            "homeconsole-sync requires homeconsole/arch-console profile, got {}/{}",
            profile.id, profile.family
        ));
    }
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let mut module = load_sync_module(module_path)?;
    if let Some(adapter) = adapter_override {
        module.adapter_command = adapter.to_string();
    }
    if let Some(provider_env) = provider_env_override {
        module.provider_env = provider_env.display().to_string();
    }
    let provider_env_path = PathBuf::from(&module.provider_env);
    let provider_env_present = provider_env_path.exists();
    let provider_env_values = parse_env_file(&provider_env_path);
    let provider_receipts = sync_provider_receipts(&module.providers, &provider_env_values);
    let missing_required_provider = provider_receipts
        .iter()
        .find(|provider| provider.required && !provider.configured)
        .map(|provider| provider.name.clone());
    let adapter_available = Path::new(&module.adapter_command).exists();
    let mut events = File::create(receipt_dir.join("events.jsonl")).map_err(|e| e.to_string())?;
    event(&mut events, "sync-start", true, "HomeConsole sync started")?;
    event(
        &mut events,
        "sync-module",
        true,
        &format!("module {}", module.id),
    )?;
    let mut ok = missing_required_provider.is_none();
    let mut changed = false;
    let mut adapter_result = None;
    let mut first_missing_signal = missing_required_provider
        .as_ref()
        .map(|name| format!("sync-provider-{name}-missing"))
        .unwrap_or_else(|| "none".to_string());
    if apply {
        if !adapter_available {
            ok = false;
            if first_missing_signal == "none" {
                first_missing_signal = "sync-adapter-missing".to_string();
            }
        } else if ok {
            let arg_refs: Vec<&str> = module.adapter_args.iter().map(String::as_str).collect();
            let result =
                command_capture_with_env(&module.adapter_command, &arg_refs, &provider_env_values);
            changed = result.ok;
            ok = result.ok;
            if !result.ok && first_missing_signal == "none" {
                first_missing_signal = "sync-adapter-failed".to_string();
            }
            write_redacted_command_receipt(receipt_dir, "sync-adapter", &result)?;
            adapter_result = Some(result);
        }
    } else {
        event(
            &mut events,
            "sync-planned",
            true,
            "rerun with --apply to invoke adapter",
        )?;
    }
    write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema": "harmonia.homeconsole_sync.v1",
            "ok": ok,
            "changed": changed,
            "mutation": apply,
            "profile_id": profile.id,
            "profile_family": profile.family,
            "module_path": module_path,
            "module_id": module.id,
            "adapter_command": module.adapter_command,
            "adapter_available": adapter_available,
            "adapter_args": module.adapter_args,
            "provider_env_path": provider_env_path,
            "provider_env_present": provider_env_present,
            "provider_secret_values_recorded": false,
            "providers": provider_receipts,
            "shortcut_lanes": module.shortcut_lanes,
            "artwork_lanes": module.artwork_lanes,
            "restart_policy": module.restart_policy,
            "first_missing_signal": first_missing_signal,
            "meaning": "HomeConsole game library sync is governed by Harmonia; Arcadia may invoke this transition as its sync button target",
            "adapter_exit_code": adapter_result.as_ref().map(|r| r.code),
        }),
    )?;
    println!("schema=harmonia.homeconsole_sync.v1");
    println!("ok={}", ok);
    println!("changed={}", changed);
    println!("mutation={}", apply);
    println!("first_missing_signal={}", first_missing_signal);
    println!("adapter_command={}", module.adapter_command);
    println!("provider_env_path={}", provider_env_path.display());
    println!("receipt_dir={}", receipt_dir.display());
    if ok {
        Ok(())
    } else {
        Err(first_missing_signal)
    }
}

fn homeconsole_keyman_update(
    profile: &Profile,
    receipt_dir: &Path,
    source: &Path,
    store_dir: &Path,
    runtime_dir: &Path,
    vault_dir: &Path,
    key_dir: &Path,
    exchange_dir: &Path,
    apply: bool,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.family != "arch-console" {
        return Err(format!(
            "homeconsole-keyman-update requires homeconsole/arch-console profile, got {}/{}",
            profile.id, profile.family
        ));
    }
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let mut events = File::create(receipt_dir.join("events.jsonl")).map_err(|e| e.to_string())?;
    event(
        &mut events,
        "run-start",
        true,
        "homeconsole keyman update started",
    )?;

    let source_shape = keyman_source_shape(source);
    let source_ok = source_shape.0;
    if !source_ok {
        write_keyman_update_receipt(
            receipt_dir,
            profile,
            apply,
            false,
            false,
            "keyman-source-incomplete",
            source,
            store_dir,
            runtime_dir,
            vault_dir,
            key_dir,
            exchange_dir,
            &source_shape.1,
            None,
        )?;
        println!("schema=harmonia.homeconsole_keyman_update.v1");
        println!("ok=false");
        println!("first_missing_signal=keyman-source-incomplete");
        println!("receipt_dir={}", receipt_dir.display());
        return Err("keyman-source-incomplete".into());
    }

    if !apply {
        event(
            &mut events,
            "plan",
            true,
            "keyman source/runtime update planned",
        )?;
        write_keyman_update_receipt(
            receipt_dir,
            profile,
            false,
            true,
            false,
            "none",
            source,
            store_dir,
            runtime_dir,
            vault_dir,
            key_dir,
            exchange_dir,
            &source_shape.1,
            None,
        )?;
        println!("schema=harmonia.homeconsole_keyman_update.v1");
        println!("ok=true");
        println!("mutation=false");
        println!("first_missing_signal=none");
        println!("receipt_dir={}", receipt_dir.display());
        return Ok(());
    }

    event(
        &mut events,
        "store-start",
        true,
        "copying keyman source to local store",
    )?;
    let changed = sync_directory(source, store_dir)?;
    event(
        &mut events,
        "store-complete",
        true,
        "keyman source stored locally",
    )?;

    let installer_receipt = receipt_dir.join("keyman-installer.json");
    let store_index = store_dir.join("index.py");
    let runtime_s = runtime_dir.to_string_lossy().to_string();
    let vault_s = vault_dir.to_string_lossy().to_string();
    let key_s = key_dir.to_string_lossy().to_string();
    let exchange_s = exchange_dir.to_string_lossy().to_string();
    let receipt_s = installer_receipt.to_string_lossy().to_string();
    let install_args = [
        store_index.to_string_lossy().to_string(),
        "install".to_string(),
        "--profile".to_string(),
        "vault-only".to_string(),
        "--source-dir".to_string(),
        store_dir.to_string_lossy().to_string(),
        "--runtime-dir".to_string(),
        runtime_s,
        "--vault-dir".to_string(),
        vault_s,
        "--key-dir".to_string(),
        key_s,
        "--exchange-dir".to_string(),
        exchange_s,
        "--receipt".to_string(),
        receipt_s,
    ];
    let install_refs: Vec<&str> = install_args.iter().map(String::as_str).collect();
    let installer = command_capture_redacted("/usr/bin/python3", &install_refs);
    write_command_receipt(receipt_dir, "keyman-install", &installer)?;
    event(
        &mut events,
        "installer-complete",
        installer.ok,
        "keyman installer completed with redacted output",
    )?;

    let installed_shape = keyman_install_shape(runtime_dir, vault_dir, key_dir, exchange_dir);
    let ok = installer.ok && installed_shape.0;
    let first_missing_signal = if ok {
        "none"
    } else if !installer.ok {
        "keyman-installer-failed"
    } else {
        "keyman-install-shape-incomplete"
    };
    write_keyman_update_receipt(
        receipt_dir,
        profile,
        true,
        ok,
        changed || installer.ok,
        first_missing_signal,
        source,
        store_dir,
        runtime_dir,
        vault_dir,
        key_dir,
        exchange_dir,
        &installed_shape.1,
        Some(&installer),
    )?;
    println!("schema=harmonia.homeconsole_keyman_update.v1");
    println!("ok={}", ok);
    println!("mutation=true");
    println!("changed={}", changed || installer.ok);
    println!("first_missing_signal={}", first_missing_signal);
    println!("receipt_dir={}", receipt_dir.display());
    if ok {
        Ok(())
    } else {
        Err(first_missing_signal.into())
    }
}

fn keyman_source_shape(source: &Path) -> (bool, serde_json::Value) {
    let index_py = source.join("index.py");
    let installer = source.join("lib/keyman_installer/index.py");
    let startup = source.join("keystartup.sh");
    let export = source.join("exportkey.sh");
    let shape = json!({
        "source_exists": source.is_dir(),
        "index_py_present": index_py.is_file(),
        "installer_present": installer.is_file(),
        "keystartup_present": startup.is_file(),
        "exportkey_present": export.is_file(),
    });
    let ok = source.is_dir()
        && index_py.is_file()
        && installer.is_file()
        && startup.is_file()
        && export.is_file();
    (ok, shape)
}

fn keyman_install_shape(
    runtime_dir: &Path,
    vault_dir: &Path,
    key_dir: &Path,
    exchange_dir: &Path,
) -> (bool, serde_json::Value) {
    let export = runtime_dir.join("exportkey.sh");
    let keys = vault_dir.join(".keys");
    let skeleton = key_dir.join("skeleton.key");
    let service_suite = keys.join("service_suite.key");
    let shape = json!({
        "runtime_dir_present": runtime_dir.is_dir(),
        "exportkey_present": export.is_file(),
        "vault_keys_dir_present": keys.is_dir(),
        "skeleton_key_present": skeleton.is_file(),
        "service_suite_key_present": service_suite.is_file(),
        "exchange_dir_present": exchange_dir.exists(),
        "secret_material": "[REDACTED]",
    });
    let ok = runtime_dir.is_dir()
        && export.is_file()
        && keys.is_dir()
        && skeleton.is_file()
        && service_suite.is_file();
    (ok, shape)
}

fn write_keyman_update_receipt(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
    ok: bool,
    changed: bool,
    first_missing_signal: &str,
    source: &Path,
    store_dir: &Path,
    runtime_dir: &Path,
    vault_dir: &Path,
    key_dir: &Path,
    exchange_dir: &Path,
    shape: &serde_json::Value,
    installer: Option<&CmdResult>,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema": "harmonia.homeconsole_keyman_update.v1",
            "ok": ok,
            "changed": changed,
            "mutation": apply,
            "profile_id": profile.id,
            "profile_family": profile.family,
            "first_missing_signal": first_missing_signal,
            "source": source,
            "store_dir": store_dir,
            "runtime_dir": runtime_dir,
            "vault_dir": vault_dir,
            "key_dir": key_dir,
            "exchange_dir": exchange_dir,
            "shape": shape,
            "installer": installer.map(|cmd| json!({
                "ok": cmd.ok,
                "exit_code": cmd.code,
                "stdout": cmd.stdout,
                "stderr": cmd.stderr,
            })),
            "secret_material": "[REDACTED]",
        }),
    )
}

fn sync_directory(source: &Path, dest: &Path) -> Result<bool, String> {
    if !source.is_dir() {
        return Err(format!("source-not-directory {}", source.display()));
    }
    let before = directory_fingerprint(dest)?;
    if dest.exists() {
        fs::remove_dir_all(dest)
            .map_err(|e| format!("store-clean-failed {}: {e}", dest.display()))?;
    }
    fs::create_dir_all(dest).map_err(|e| format!("store-create-failed {}: {e}", dest.display()))?;
    copy_dir_contents(source, dest)?;
    let after = directory_fingerprint(dest)?;
    Ok(before != after)
}

fn copy_dir_contents(source: &Path, dest: &Path) -> Result<(), String> {
    for entry in
        fs::read_dir(source).map_err(|e| format!("read-dir-failed {}: {e}", source.display()))?
    {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name_s = name.to_string_lossy();
        if matches!(name_s.as_ref(), ".git" | "__pycache__" | ".pytest_cache") {
            continue;
        }
        let src = entry.path();
        let dst = dest.join(&name);
        let meta = entry.metadata().map_err(|e| e.to_string())?;
        if meta.is_dir() {
            fs::create_dir_all(&dst).map_err(|e| e.to_string())?;
            copy_dir_contents(&src, &dst)?;
        } else if meta.is_file() {
            fs::copy(&src, &dst)
                .map_err(|e| format!("copy-failed {} -> {}: {e}", src.display(), dst.display()))?;
            fs::set_permissions(&dst, meta.permissions()).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn directory_fingerprint(path: &Path) -> Result<String, String> {
    if !path.exists() {
        return Ok("absent".into());
    }
    let mut rows = Vec::new();
    collect_fingerprint(path, path, &mut rows)?;
    rows.sort();
    Ok(rows.join("\n"))
}

fn collect_fingerprint(root: &Path, path: &Path, rows: &mut Vec<String>) -> Result<(), String> {
    for entry in
        fs::read_dir(path).map_err(|e| format!("read-dir-failed {}: {e}", path.display()))?
    {
        let entry = entry.map_err(|e| e.to_string())?;
        let p = entry.path();
        let rel = p.strip_prefix(root).unwrap_or(&p).display().to_string();
        let meta = entry.metadata().map_err(|e| e.to_string())?;
        if meta.is_dir() {
            rows.push(format!("dir:{rel}"));
            collect_fingerprint(root, &p, rows)?;
        } else if meta.is_file() {
            rows.push(format!("file:{rel}:{}", meta.len()));
        }
    }
    Ok(())
}

fn command_capture_redacted(program: &str, args: &[&str]) -> CmdResult {
    let mut result = command_capture(program, args);
    result.stdout = redact_secret_text(&result.stdout);
    result.stderr = redact_secret_text(&result.stderr);
    result
}

fn redact_secret_text(text: &str) -> String {
    text.lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if [
                "password",
                "secret",
                "mnemonic",
                "private",
                "token",
                "key=",
                "username=",
            ]
            .iter()
            .any(|needle| lower.contains(needle))
            {
                "[REDACTED]".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn homeconsole_arcadia_check(
    profile: &Profile,
    receipt_dir: &Path,
    repo: &str,
    branch: &str,
    current_sha_file: &Path,
    upstream_sha_file: Option<&Path>,
    insecure_tls: bool,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.family != "arch-console" {
        return Err(format!(
            "homeconsole-arcadia-check requires homeconsole/arch-console profile, got {}/{}",
            profile.id, profile.family
        ));
    }
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let started = Instant::now();
    let current_sha = fs::read_to_string(current_sha_file)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let refspec = format!("refs/heads/{branch}");
    let file_upstream = upstream_sha_file
        .and_then(|path| fs::read_to_string(path).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| is_hex_sha(s));
    let remote = if file_upstream.is_some() {
        CmdResult {
            ok: true,
            code: 0,
            stdout: file_upstream.clone().unwrap_or_default(),
            stderr: String::new(),
        }
    } else {
        git_ls_remote(repo, &refspec, insecure_tls)
    };
    let upstream_sha = if let Some(sha) = file_upstream {
        Some(sha)
    } else {
        remote
            .stdout
            .split_whitespace()
            .next()
            .map(|s| s.to_string())
            .filter(|s| is_hex_sha(s))
    };
    let ok = remote.ok && upstream_sha.is_some() && current_sha.is_some();
    let first_missing_signal = if !remote.ok {
        "upstream-sha-unreadable"
    } else if upstream_sha.is_none() {
        "upstream-sha-missing"
    } else if current_sha.is_none() {
        "current-sha-missing"
    } else {
        "none"
    };
    let update_available = match (&current_sha, &upstream_sha) {
        (Some(current), Some(upstream)) => current != upstream,
        _ => false,
    };
    let elapsed_ms = started.elapsed().as_millis();
    write_command_receipt(receipt_dir, "arcadia-upstream-sha", &remote)?;
    write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema": "harmonia.arcadia_fast_check.v1",
            "ok": ok,
            "mutation": false,
            "profile_id": profile.id,
            "profile_family": profile.family,
            "repo": repo,
            "branch": branch,
            "current_sha_file": current_sha_file,
            "current_sha": current_sha,
            "upstream_sha": upstream_sha,
            "update_available": update_available,
            "first_missing_signal": first_missing_signal,
            "elapsed_ms": elapsed_ms,
        }),
    )?;
    println!("schema=harmonia.arcadia_fast_check.v1");
    println!("ok={}", ok);
    println!("update_available={}", update_available);
    println!(
        "current_sha={}",
        current_sha.as_deref().unwrap_or("unknown")
    );
    println!(
        "upstream_sha={}",
        upstream_sha.as_deref().unwrap_or("unknown")
    );
    println!("first_missing_signal={}", first_missing_signal);
    println!("elapsed_ms={}", elapsed_ms);
    println!("receipt_dir={}", receipt_dir.display());
    if ok {
        Ok(())
    } else {
        Err(first_missing_signal.to_string())
    }
}

fn git_ls_remote(repo: &str, refspec: &str, insecure_tls: bool) -> CmdResult {
    let mut cmd = Command::new("/usr/bin/git");
    if insecure_tls {
        cmd.arg("-c").arg("http.sslVerify=false");
    }
    cmd.arg("ls-remote").arg(repo).arg(refspec);
    match cmd.output() {
        Ok(output) => CmdResult {
            ok: output.status.success(),
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        },
        Err(err) => CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: err.to_string(),
        },
    }
}

fn is_hex_sha(s: &str) -> bool {
    s.len() >= 7 && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn homeconsole_arcadia_update(
    profile: &Profile,
    receipt_dir: &Path,
    artifact: &Path,
    install_bin: &Path,
    service: &str,
    apply: bool,
    source_sha: Option<&str>,
    source_sha_file: &Path,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.family != "arch-console" {
        return Err(format!(
            "homeconsole-arcadia-update requires homeconsole/arch-console profile, got {}/{}",
            profile.id, profile.family
        ));
    }
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let mut events = File::create(receipt_dir.join("events.jsonl")).map_err(|e| e.to_string())?;
    event(&mut events, "arcadia-start", true, "Arcadia update started")?;
    let metadata = fs::metadata(artifact).map_err(|e| format!("artifact-missing: {e}"))?;
    let artifact_len = metadata.len();
    write_artifact_receipt(
        receipt_dir,
        artifact,
        install_bin,
        service,
        apply,
        artifact_len,
    )?;
    event(&mut events, "artifact", true, "Arcadia artifact present")?;
    let mut ok = true;
    let mut changed = false;
    let mut first_missing_signal = "none".to_string();
    if apply {
        if let Some(parent) = install_bin.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let before_len = fs::metadata(install_bin).map(|m| m.len()).ok();
        let stop = command_capture("/usr/bin/systemctl", &["stop", service]);
        write_command_receipt(receipt_dir, "arcadia-service-stop", &stop)?;
        if !stop.ok {
            event(
                &mut events,
                "service-stop-warning",
                false,
                "Arcadia service stop returned nonzero",
            )?;
        }
        let tmp_install = install_bin.with_extension("harmonia-new");
        fs::copy(artifact, &tmp_install).map_err(|e| format!("artifact-copy-failed: {e}"))?;
        let mut perms = fs::metadata(&tmp_install)
            .map_err(|e| e.to_string())?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&tmp_install, perms).map_err(|e| e.to_string())?;
        fs::rename(&tmp_install, install_bin)
            .map_err(|e| format!("artifact-promote-failed: {e}"))?;
        changed = before_len != Some(artifact_len);
        event(
            &mut events,
            "artifact-installed",
            true,
            "Arcadia artifact installed",
        )?;
        if let Some(source_sha) = source_sha {
            if let Some(parent) = source_sha_file.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            fs::write(source_sha_file, format!("{}\n", source_sha.trim()))
                .map_err(|e| format!("source-sha-write-failed: {e}"))?;
            event(
                &mut events,
                "source-sha-recorded",
                true,
                "Arcadia source SHA recorded",
            )?;
        }
        let daemon_reload = command_capture("/usr/bin/systemctl", &["daemon-reload"]);
        write_command_receipt(receipt_dir, "arcadia-daemon-reload", &daemon_reload)?;
        if !daemon_reload.ok {
            ok = false;
            first_missing_signal = "systemd-daemon-reload-failed".to_string();
        }
        let restart = command_capture("/usr/bin/systemctl", &["restart", service]);
        write_command_receipt(receipt_dir, "arcadia-service-restart", &restart)?;
        if !restart.ok {
            ok = false;
            if first_missing_signal == "none" {
                first_missing_signal = "arcadia-service-restart-failed".to_string();
            }
        }
    }
    let status = command_capture("/usr/bin/systemctl", &["is-active", service]);
    write_command_receipt(receipt_dir, "arcadia-service-active", &status)?;
    if apply && !status.ok {
        ok = false;
        if first_missing_signal == "none" {
            first_missing_signal = "arcadia-service-not-active".to_string();
        }
    }
    write_run_receipt(receipt_dir, profile, apply, ok, &first_missing_signal)?;
    println!("schema=harmonia.homeconsole_arcadia_update.v1");
    println!("ok={}", ok);
    println!("changed={}", changed);
    println!("first_missing_signal={}", first_missing_signal);
    println!("artifact={}", artifact.display());
    println!("install_bin={}", install_bin.display());
    println!("service={}", service);
    println!("receipt_dir={}", receipt_dir.display());
    if ok {
        Ok(())
    } else {
        Err(first_missing_signal)
    }
}

fn homeconsole_update(profile: &Profile, receipt_dir: &Path, apply: bool) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.family != "arch-console" {
        return Err(format!(
            "homeconsole-update requires homeconsole/arch-console profile, got {}/{}",
            profile.id, profile.family
        ));
    }
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let mut events = File::create(receipt_dir.join("events.jsonl")).map_err(|e| e.to_string())?;
    event(&mut events, "run-start", true, "homeconsole update started")?;
    let identity = command_capture("/usr/bin/uname", &["-a"]);
    write_command_receipt(receipt_dir, "identity", &identity)?;
    event(&mut events, "identity", identity.ok, "uname identity read")?;
    let pacman_present = Path::new("/usr/bin/pacman").exists();
    if !pacman_present {
        write_run_receipt(receipt_dir, profile, apply, false, "pacman-missing")?;
        return Err("pacman-missing".to_string());
    }
    let games_active = command_capture(
        "/usr/bin/pgrep",
        &["-x", "retroarch|dolphin-emu|pcsx2|PPSSPPQt|dosbox"],
    );
    let game_running = games_active.ok;
    write_command_receipt(receipt_dir, "game-activity", &games_active)?;
    if apply && game_running {
        event(&mut events, "mutation-skipped", true, "game process active")?;
        write_run_receipt(receipt_dir, profile, apply, true, "skipped-game-active")?;
        println!("schema=harmonia.homeconsole_update.v1");
        println!("ok=true");
        println!("changed=false");
        println!("skipped=game-active");
        println!("receipt_dir={}", receipt_dir.display());
        return Ok(());
    }
    let pacman_check = command_capture("/usr/bin/pacman", &["-Qu"]);
    write_command_receipt(receipt_dir, "pacman-check", &pacman_check)?;
    event(&mut events, "pacman-check", true, "pacman -Qu completed")?;
    let mut ok = true;
    let mut changed = false;
    let mut first_missing_signal = "none".to_string();
    if apply {
        let pacman_update = command_capture("/usr/bin/pacman", &["-Syu", "--noconfirm"]);
        changed = pacman_update.ok && pacman_stdout_indicates_change(&pacman_update.stdout);
        ok = pacman_update.ok;
        if !ok {
            first_missing_signal = "pacman-update-failed".to_string();
        }
        write_command_receipt(receipt_dir, "pacman-update", &pacman_update)?;
        event(
            &mut events,
            "pacman-update",
            pacman_update.ok,
            "pacman -Syu --noconfirm",
        )?;
    }
    let appliance = command_capture("/usr/bin/systemctl", &["is-system-running"]);
    write_command_receipt(receipt_dir, "systemd-state", &appliance)?;
    event(&mut events, "systemd-state", true, "systemd state read")?;
    write_run_receipt(receipt_dir, profile, apply, ok, &first_missing_signal)?;
    println!("schema=harmonia.homeconsole_update.v1");
    println!("ok={}", ok);
    println!("changed={}", changed);
    println!("first_missing_signal={}", first_missing_signal);
    println!("receipt_dir={}", receipt_dir.display());
    if ok {
        Ok(())
    } else {
        Err(first_missing_signal)
    }
}

fn command_capture(program: &str, args: &[&str]) -> CmdResult {
    command_capture_with_cwd(program, args, None)
}

fn command_capture_with_cwd(program: &str, args: &[&str], cwd: Option<&str>) -> CmdResult {
    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    match cmd.output() {
        Ok(output) => CmdResult {
            ok: output.status.success(),
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        },
        Err(err) => CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: err.to_string(),
        },
    }
}

fn pacman_stdout_indicates_change(stdout: &str) -> bool {
    stdout.contains("\nupgrading ")
        || stdout.contains("\ninstalling ")
        || stdout.contains("\nreinstalling ")
        || stdout.contains("\nremoving ")
}

fn write_json(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut f = File::create(path).map_err(|e| e.to_string())?;
    serde_json::to_writer_pretty(&mut f, value).map_err(|e| e.to_string())?;
    writeln!(f).map_err(|e| e.to_string())?;
    Ok(())
}

fn write_step_receipt(
    receipt_dir: &Path,
    step: &Step,
    ok: bool,
    changed: bool,
    skipped: bool,
    message: &str,
    command: Option<&CmdResult>,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{}.json", step.id)),
        &json!({
            "schema": "harmonia.step_receipt.v1",
            "step_id": step.id,
            "tool": step.tool,
            "action": step.action,
            "ok": ok,
            "changed": changed,
            "skipped": skipped,
            "message": message,
            "command": command,
        }),
    )
}

fn write_engine_run_receipt(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
    ok: bool,
    changed: bool,
    module_count: usize,
    step_count: usize,
    first_missing_signal: &str,
    module_root: &Path,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema": "harmonia.run_profile.v1",
            "ok": ok,
            "changed": changed,
            "mutation": apply,
            "profile_id": profile.id,
            "profile_family": profile.family,
            "module_count": module_count,
            "step_count": step_count,
            "first_missing_signal": first_missing_signal,
            "module_root": module_root,
        }),
    )
}

fn write_artifact_receipt(
    receipt_dir: &Path,
    artifact: &Path,
    install_bin: &Path,
    service: &str,
    apply: bool,
    artifact_len: u64,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join("arcadia-artifact.json"),
        &json!({
            "schema": "harmonia.arcadia_artifact.v1",
            "ok": true,
            "mutation": apply,
            "artifact": artifact,
            "install_bin": install_bin,
            "service": service,
            "artifact_bytes": artifact_len,
        }),
    )
}

fn write_redacted_command_receipt(
    receipt_dir: &Path,
    name: &str,
    result: &CmdResult,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{}.json", name)),
        &json!({
            "schema": "harmonia.command_receipt.v1",
            "name": name,
            "ok": result.ok,
            "exit_code": result.code,
            "stdout_redacted": true,
            "stderr_redacted": true,
            "stdout_bytes": result.stdout.len(),
            "stderr_bytes": result.stderr.len(),
        }),
    )
}

fn write_command_receipt(receipt_dir: &Path, name: &str, result: &CmdResult) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{}.json", name)),
        &json!({
            "schema": "harmonia.command_receipt.v1",
            "name": name,
            "ok": result.ok,
            "exit_code": result.code,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }),
    )
}

fn write_run_receipt(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
    ok: bool,
    first_missing_signal: &str,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema": "harmonia.run.v1",
            "ok": ok,
            "mutation": apply,
            "profile_id": profile.id,
            "profile_family": profile.family,
            "module_count": profile.modules.len(),
            "first_missing_signal": first_missing_signal,
        }),
    )
}

fn event(events: &mut File, event: &str, ok: bool, message: &str) -> Result<(), String> {
    writeln!(
        events,
        "{}",
        json!({"event": event, "ok": ok, "message": message})
    )
    .map_err(|e| e.to_string())
}

fn extract_string(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let start = text.find(&needle)?;
    let after_key = &text[start + needle.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    let rest = after_colon.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_string_array(text: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{}\"", key);
    let Some(start) = text.find(&needle) else {
        return Vec::new();
    };
    let after_key = &text[start + needle.len()..];
    let Some(colon) = after_key.find(':') else {
        return Vec::new();
    };
    let after_colon = after_key[colon + 1..].trim_start();
    let Some(rest) = after_colon.strip_prefix('[') else {
        return Vec::new();
    };
    let Some(end) = rest.find(']') else {
        return Vec::new();
    };
    rest[..end]
        .split(',')
        .filter_map(|item| {
            let t = item.trim();
            let t = t.strip_prefix('"')?.strip_suffix('"')?;
            Some(t.to_string())
        })
        .collect()
}

fn write_plan_receipts(profile: &Profile, receipt_dir: &Path) -> io::Result<()> {
    fs::create_dir_all(receipt_dir)?;
    let mut events = File::create(receipt_dir.join("events.jsonl"))?;
    writeln!(
        events,
        "{}",
        json!({"event":"plan-start","profile":profile.id,"ok":true})
    )?;
    for module in &profile.modules {
        writeln!(
            events,
            "{}",
            json!({"event":"module-planned","module":module,"ok":true})
        )?;
    }
    let mut run = File::create(receipt_dir.join("run.json"))?;
    serde_json::to_writer_pretty(
        &mut run,
        &json!({
            "schema": "harmonia.run.v1",
            "ok": true,
            "mutation": false,
            "profile_id": profile.id,
            "profile_family": profile.family,
            "module_count": profile.modules.len(),
        }),
    )?;
    writeln!(run)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
