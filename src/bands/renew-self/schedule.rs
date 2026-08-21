use crate::atoms::r#do::{run_command, InvocationKey};
use crate::tools::comparison::{self, DiffDecision};
use std::env;
use std::path::{Path, PathBuf};

const INSTALLER_ENV: &str = "HARMONIA_INSTALLER";

fn installer() -> Result<(PathBuf, PathBuf), String> {
    let mut candidates = Vec::new();
    if let Ok(value) = env::var(INSTALLER_ENV) {
        candidates.push(PathBuf::from(value));
    }
    candidates.push(Path::new(crate::SOURCE_ROOT).join("installer/harmonia_installer.py"));
    if let Ok(cwd) = env::current_dir() {
        candidates.push(cwd.join("installer/harmonia_installer.py"));
    }
    for candidate in candidates {
        if candidate.is_file() {
            let cwd = candidate
                .parent()
                .and_then(Path::parent)
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            return Ok((candidate, cwd));
        }
    }
    Err(format!("harmonia-installer-not-found env={INSTALLER_ENV}"))
}

fn invoke(action: &str, args: &[String], invocation: InvocationKey) -> Result<(), String> {
    let (script, cwd) = installer()?;
    let mut child_args = vec![script.to_string_lossy().into_owned(), action.to_string()];
    child_args.extend(args.iter().cloned());
    let systemd_root = args
        .windows(2)
        .find(|pair| pair[0] == "--systemd-root")
        .map(|pair| PathBuf::from(&pair[1]))
        .unwrap_or_else(|| PathBuf::from("/etc/systemd/system"));
    let installing = action == "install-timer";
    let dry_run =
        args.iter().any(|arg| arg == "--dry-run") || !args.iter().any(|arg| arg == "--apply");
    let observe = || {
        Ok::<_, String>((
            systemd_root.join("harmonia.service").is_file(),
            systemd_root.join("harmonia.timer").is_file(),
        ))
    };
    let compare = |observed: &(bool, bool)| {
        let current = if installing {
            observed.0 && observed.1
        } else {
            !observed.0 && !observed.1
        };
        if current {
            DiffDecision::Empty
        } else {
            DiffDecision::Different
        }
    };
    let owned = if dry_run {
        comparison::execute_once("harmonia-schedule", observe, compare, |authorization, _| {
            run_command::command_with_timeout_in_dir(
                authorization,
                invocation,
                "python3",
                &child_args,
                Some(cwd.as_path()),
                std::time::Duration::from_secs(30),
            )
        })?
    } else {
        comparison::execute("harmonia-schedule", observe, compare, |authorization, _| {
            run_command::command_with_timeout_in_dir(
                authorization,
                invocation,
                "python3",
                &child_args,
                Some(cwd.as_path()),
                std::time::Duration::from_secs(30),
            )
        })?
    };
    let result = match owned {
        comparison::ComparisonRun::Moved { movement, .. } => movement,
        comparison::ComparisonRun::Current { .. } => return Ok(()),
    };
    crate::hyalos::forward_receipt(
        "harmonia.schedule.command",
        &format!("action={action} argv={child_args:?} ok={}", result.ok),
        Some(
            serde_json::json!({"action": action, "argv": child_args, "ok": result.ok, "code": result.code, "attest_owner": "hyalos"}),
        ),
        Some(result.ok),
    );
    if !result.stdout.is_empty() {
        print!("{}", result.stdout);
        if !result.stdout.ends_with('\n') {
            println!();
        }
    }
    if !result.stderr.is_empty() {
        eprint!("{}", result.stderr);
        if !result.stderr.ends_with('\n') {
            eprintln!();
        }
    }
    if result.ok {
        Ok(())
    } else {
        Err(format!("installer-exit={:?} action={action}", result.code))
    }
}

pub(crate) fn install_timer(args: &[String], invocation: InvocationKey) -> Result<(), String> {
    invoke("install-timer", args, invocation)
}

pub(crate) fn uninstall_timer(args: &[String], invocation: InvocationKey) -> Result<(), String> {
    invoke("uninstall-timer", args, invocation)
}
