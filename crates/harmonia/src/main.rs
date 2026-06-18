use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

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
            let apply = args.iter().any(|arg| arg == "--apply");
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            homeconsole_arcadia_update(
                &profile,
                &receipt_dir,
                &artifact,
                &install_bin,
                &service,
                apply,
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
    println!("covenant=Rust-only Chrysalis update suite/toolchain");
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
    println!("  harmonia homeconsole-update <profiles/homeconsole/index.json> [--apply] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-arcadia-update <profiles/homeconsole/index.json> --artifact <path> [--apply] [--install-bin <path>] [--service arcadia.service] [--receipt-dir <path>]");
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

fn homeconsole_arcadia_update(
    profile: &Profile,
    receipt_dir: &Path,
    artifact: &Path,
    install_bin: &Path,
    service: &str,
    apply: bool,
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
}
