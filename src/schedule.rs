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

fn invoke(action: &str, args: &[String]) -> Result<(), String> {
    let (script, cwd) = installer()?;
    let mut child_args = vec![script.to_string_lossy().into_owned(), action.to_string()];
    child_args.extend(args.iter().cloned());
    let refs: Vec<&str> = child_args.iter().map(String::as_str).collect();
    let result = crate::tools::command::capture_with_cwd("python3", &refs, cwd.to_str());
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
        Err(format!("installer-exit={} action={action}", result.code))
    }
}

pub(crate) fn install_timer(args: &[String]) -> Result<(), String> {
    invoke("install-timer", args)
}

pub(crate) fn uninstall_timer(args: &[String]) -> Result<(), String> {
    invoke("uninstall-timer", args)
}
