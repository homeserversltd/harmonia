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
            family: extract_string(&text, "family").unwrap_or_else(|| "unknown".to_string()),
            modules: extract_string_array(&text, "modules"),
        })
    })
}

pub(crate) fn load_module(path: &Path) -> Result<ModuleManifest, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("module-read-failed {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("module-parse-failed {}: {e}", path.display()))
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
        if module.steps.is_empty() {
            ok = false;
            if first_missing_signal == "none" {
                first_missing_signal = format!("module-empty-{module_id}");
            }
            event(
                &mut events,
                "module-empty",
                false,
                &format!("module {module_id} has no executable steps"),
            )?;
            continue;
        }
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
