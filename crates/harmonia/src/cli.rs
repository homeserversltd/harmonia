use crate::*;
use std::path::{Path, PathBuf};

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
    println!("homeconsole_equals_arch_console=true");
    Ok(())
}

pub(crate) fn usage() -> Result<(), String> {
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
