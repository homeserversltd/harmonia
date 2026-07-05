use crate::*;

// Absorbed module-specific runtime helper

// from former src/sync.rs.
use serde_json::json;
use std::collections::HashMap;
use std::fs::{self, File};

pub(crate) fn load_sync_module(path: &Path) -> Result<SyncModuleConfig, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("sync-module-read-failed {}: {e}", path.display()))?;
    serde_json::from_str(&text)
        .map_err(|e| format!("sync-module-parse-failed {}: {e}", path.display()))
}

pub(crate) fn parse_env_file(path: &Path) -> HashMap<String, String> {
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

pub(crate) fn sync_provider_receipts(
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

pub(crate) fn command_capture_with_env(
    program: &str,
    args: &[&str],
    envs: &HashMap<String, String>,
) -> CmdResult {
    let values: Vec<(String, String)> = envs.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    tools::command::capture_with_env(program, args, &values)
}

pub(crate) fn homeconsole_sync(
    profile: &Profile,
    receipt_dir: &Path,
    module_path: &Path,
    provider_env_override: Option<&Path>,
    adapter_override: Option<&str>,
    apply: bool,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.identity != "homeconsole" {
        return Err(format!(
            "homeconsole-sync requires homeconsole/homeconsole profile, got {}/{}",
            profile.id, profile.identity
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
            "profile_family": profile.identity,
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
