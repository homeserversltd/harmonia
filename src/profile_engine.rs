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
    serde_json::from_str(&text).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("profile-parse-failed {}: {err}", path.display()),
        )
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

pub(crate) fn profile_module_failure_is_terminal(module_id: &str) -> bool {
    module_id == "harmonia-runtime"
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
    let run_id = run_id_from_stamp();
    let mut ok = true;
    let mut changed = false;
    let mut first_missing_signal = "none".to_string();
    let mut module_count = 0usize;
    let mut operation_count = 0usize;

    let harmonia_root = harmonia_root_from_module_root(module_root);

    if profile.modules.is_empty() {
        ok = false;
        first_missing_signal = "profile-modules-empty".to_string();
        event(
            &mut events,
            "profile-modules",
            false,
            "profile module spine is empty",
        )?;
    }

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
                append_profile_ledger_entry(
                    receipt_dir,
                    profile,
                    ProfileLedgerEntry {
                        run_id: &run_id,
                        module_id,
                        ok: false,
                        changed: false,
                        operation_count: 0,
                        first_missing_signal: &format!("module-missing-{module_id}"),
                        receipt_dir,
                    },
                )?;
                if profile_module_failure_is_terminal(module_id) {
                    event(&mut events, "module-terminal-stop", false, module_id)?;
                    break;
                }
                continue;
            }
        };
        module_count += 1;
        event(&mut events, "module-start", true, &module.id)?;
        let execution = match execute_profile_module(&module, receipt_dir, apply, &harmonia_root) {
            Ok(execution) => execution,
            Err(err) => {
                ok = false;
                if first_missing_signal == "none" {
                    first_missing_signal = err.clone();
                }
                event(&mut events, "module-rejected", false, &err)?;
                append_profile_ledger_entry(
                    receipt_dir,
                    profile,
                    ProfileLedgerEntry {
                        run_id: &run_id,
                        module_id: &module.id,
                        ok: false,
                        changed: false,
                        operation_count: 0,
                        first_missing_signal: &err,
                        receipt_dir,
                    },
                )?;
                if profile_module_failure_is_terminal(&module.id) {
                    event(&mut events, "module-terminal-stop", false, &module.id)?;
                    break;
                }
                continue;
            }
        };
        operation_count += execution.operation_count;
        if execution.changed {
            changed = true;
        }
        let module_signal = execution.first_missing_signal.as_deref().unwrap_or("none");
        if !execution.ok {
            ok = false;
            if first_missing_signal == "none" {
                first_missing_signal = execution
                    .first_missing_signal
                    .clone()
                    .unwrap_or_else(|| format!("module-failed-{module_id}"));
            }
        }
        append_profile_ledger_entry(
            receipt_dir,
            profile,
            ProfileLedgerEntry {
                run_id: &run_id,
                module_id: &module.id,
                ok: execution.ok,
                changed: execution.changed,
                operation_count: execution.operation_count,
                first_missing_signal: module_signal,
                receipt_dir,
            },
        )?;
        event(
            &mut events,
            "module-complete",
            execution.ok,
            &format!("{} operations={}", module.id, execution.operation_count),
        )?;
        if !execution.ok && profile_module_failure_is_terminal(&module.id) {
            event(&mut events, "module-terminal-stop", false, &module.id)?;
            break;
        }
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

pub(crate) fn homeconsole_update(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    apply: bool,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.identity != "homeconsole" {
        return Err(format!(
            "homeconsole-update requires homeconsole/homeconsole profile, got {}/{}",
            profile.id, profile.identity
        ));
    }
    enforce_homeconsole_update_suite(profile, module_root)?;
    let run_id = run_id_from_stamp();
    let effective_receipt_dir = materialize_homeconsole_receipt_dir(receipt_dir, &run_id)?;
    fs::create_dir_all(&effective_receipt_dir).map_err(|e| e.to_string())?;
    if apply {
        let lock_path = homeconsole_update_lock_path();
        match try_acquire_homeconsole_update_lock(&lock_path) {
            Ok(_guard) => run_profile_engine(profile, module_root, &effective_receipt_dir, apply),
            Err(ConvergenceLockBusy) => {
                write_convergence_skipped_receipt(
                    &effective_receipt_dir,
                    profile,
                    apply,
                    "lock-held",
                    &lock_path,
                    receipt_dir,
                )?;
                emit_convergence_skipped_stdout(&effective_receipt_dir, "lock-held", &profile.id);
                Ok(())
            }
        }
    } else {
        run_profile_engine(profile, module_root, &effective_receipt_dir, apply)
    }
}

pub(crate) fn homeconsole_module_root() -> std::path::PathBuf {
    Path::new("profiles/homeconsole/modules").to_path_buf()
}

pub(crate) fn module_ids_from_profile_modules(module_root: &Path) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    for module_id in [
        "identity",
        "harmonia-runtime",
        "arch-keyring-maintenance",
        "system-packages",
        "keyman-runtime",
        "homeconsole-sync-runtime",
        "rust-build-toolchain",
        "arcadia-gui-runtime",
        "local-ai-runtime",
        "pinned-artifacts-runtime",
        "homeconsole-update-runtime",
        "homeconsole-caduceus-public-lever",
    ] {
        let module_dir = module_root.join(module_id);
        if module_dir.join("index.rs").exists() && module_dir.join("sidecar.json").exists() {
            found.push(module_id.to_string());
        }
    }
    Ok(found)
}

pub(crate) fn enforce_homeconsole_update_suite(
    profile: &Profile,
    module_root: &Path,
) -> Result<(), String> {
    let expected = module_ids_from_profile_modules(module_root)?;
    if profile.modules == expected {
        Ok(())
    } else {
        Err(format!(
            "homeconsole-update-suite-spine-mismatch module_root={} expected={} got={}",
            module_root.display(),
            expected.join(","),
            profile.modules.join(",")
        ))
    }
}

pub(crate) fn command_capture(program: &str, args: &[&str]) -> CmdResult {
    tools::command::capture(program, args)
}

pub(crate) fn command_capture_with_timeout(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
) -> CmdResult {
    tools::command::capture_with_timeout(program, args, timeout_secs)
}

pub(crate) fn command_capture_with_cwd(
    program: &str,
    args: &[&str],
    cwd: Option<&str>,
) -> CmdResult {
    tools::command::capture_with_cwd(program, args, cwd)
}

pub(crate) fn pacman_stdout_indicates_change(stdout: &str) -> bool {
    stdout.contains("\nupgrading ")
        || stdout.contains("\ninstalling ")
        || stdout.contains("\nreinstalling ")
        || stdout.contains("\nremoving ")
}

pub(crate) fn harmonia_root_from_module_root(module_root: &Path) -> PathBuf {
    module_root
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod profile_authority_tests {
    use super::*;

    #[test]
    fn module_root_yields_absolute_installed_harmonia_root() {
        assert_eq!(
            harmonia_root_from_module_root(Path::new("/etc/harmonia/profiles/tv/modules")),
            PathBuf::from("/etc/harmonia")
        );
    }

    #[test]
    fn module_root_yields_relative_repo_harmonia_root() {
        assert_eq!(
            harmonia_root_from_module_root(Path::new("profiles/tv/modules")),
            PathBuf::from("")
        );
    }

    #[test]
    fn command_timeout_kills_sleeping_child() {
        let result = command_capture_with_timeout("/usr/bin/sh", &["-c", "sleep 2"], 1);
        assert!(!result.ok);
        assert!(
            result.stderr.contains("command-timeout-after-1s"),
            "{}",
            result.stderr
        );
        assert!(
            result.stderr.contains("/usr/bin/sh -c sleep 2"),
            "{}",
            result.stderr
        );
    }
}
