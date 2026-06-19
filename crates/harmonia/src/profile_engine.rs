use crate::*;
use std::fs::{self, File};
use std::io::{self};
use std::path::{Path, PathBuf};

pub(crate) fn default_pinned_lock_path(profile: &Profile) -> PathBuf {
    PathBuf::from("/etc/harmonia/locks")
        .join(&profile.id)
        .join("pinned-artifacts.json")
}

pub(crate) fn load_profile(path: &Path) -> io::Result<Profile> {
    let text = fs::read_to_string(path)?;
    serde_json::from_str(&text).or_else(|_| {
        Ok(Profile {
            id: extract_string(&text, "id").unwrap_or_else(|| "unknown".to_string()),
            identity: extract_string(&text, "identity").unwrap_or_else(|| "unknown".to_string()),
            modules: extract_string_array(&text, "modules"),
        })
    })
}

pub(crate) fn load_module(path: &Path) -> Result<ModuleManifest, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("module-read-failed {}: {e}", path.display()))?;
    let raw: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("module-parse-failed {}: {e}", path.display()))?;
    for field in [
        "steps",
        "tool",
        "command",
        "action",
        "actions",
        "args",
        "cwd",
        "apply_only",
    ] {
        if raw.get(field).is_some() {
            return Err(format!(
                "module-sidecar-behavior-field-rejected {} field={}",
                path.display(),
                field
            ));
        }
    }
    serde_json::from_value(raw).map_err(|e| format!("module-parse-failed {}: {e}", path.display()))
}

pub(crate) fn run_profile_engine(
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
    let mut operation_count = 0usize;

    for module_id in &profile.modules {
        let module_path = module_root.join(module_id).join("sidecar.json");
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
        let execution = match execute_profile_module(&module, receipt_dir, apply) {
            Ok(execution) => execution,
            Err(err) => {
                ok = false;
                if first_missing_signal == "none" {
                    first_missing_signal = err.clone();
                }
                event(&mut events, "module-rejected", false, &err)?;
                continue;
            }
        };
        operation_count += execution.operation_count;
        if execution.changed {
            changed = true;
        }
        if !execution.ok {
            ok = false;
            if first_missing_signal == "none" {
                first_missing_signal = execution
                    .first_missing_signal
                    .unwrap_or_else(|| format!("module-failed-{module_id}"));
            }
        }
        event(
            &mut events,
            "module-complete",
            execution.ok,
            &format!("{} operations={}", module.id, execution.operation_count),
        )?;
    }

    write_engine_run_receipt(
        receipt_dir,
        profile,
        apply,
        ok,
        changed,
        module_count,
        operation_count,
        &first_missing_signal,
        module_root,
    )?;
    println!("schema=harmonia.run_profile.v1");
    println!("ok={}", ok);
    println!("changed={}", changed);
    println!("profile_id={}", profile.id);
    println!("module_count={}", module_count);
    println!("operation_count={}", operation_count);
    println!("first_missing_signal={}", first_missing_signal);
    println!("receipt_dir={}", receipt_dir.display());
    if ok {
        Ok(())
    } else {
        Err(first_missing_signal)
    }
}
