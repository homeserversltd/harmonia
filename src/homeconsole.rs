use crate::*;
use std::fs;
use std::path::Path;
use std::process::Command;

pub(crate) fn homeconsole_update(
    profile: &Profile,
    receipt_dir: &Path,
    apply: bool,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.identity != "homeconsole" {
        return Err(format!(
            "homeconsole-update requires homeconsole/homeconsole profile, got {}/{}",
            profile.id, profile.identity
        ));
    }
    enforce_homeconsole_update_suite(profile)?;
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    run_profile_engine(profile, &homeconsole_module_root(), receipt_dir, apply)
}

pub(crate) fn homeconsole_module_root() -> std::path::PathBuf {
    Path::new("profiles/homeconsole/modules").to_path_buf()
}

pub(crate) fn module_ids_from_profile_modules(module_root: &Path) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    for module_id in [
        "identity",
        "system-packages",
        "harmonia-runtime",
        "keyman-runtime",
        "homeconsole-sync-runtime",
        "rust-build-toolchain",
        "arcadia-gui-runtime",
        "pinned-artifacts-runtime",
    ] {
        let module_dir = module_root.join(module_id);
        if module_dir.join("index.rs").exists() && module_dir.join("sidecar.json").exists() {
            found.push(module_id.to_string());
        }
    }
    Ok(found)
}

pub(crate) fn enforce_homeconsole_update_suite(profile: &Profile) -> Result<(), String> {
    let module_root = homeconsole_module_root();
    let expected = module_ids_from_profile_modules(&module_root)?;
    if profile.modules == expected {
        Ok(())
    } else {
        Err(format!(
            "homeconsole-update-suite-spine-mismatch expected={} got={}",
            expected.join(","),
            profile.modules.join(",")
        ))
    }
}

pub(crate) fn command_capture(program: &str, args: &[&str]) -> CmdResult {
    command_capture_with_cwd(program, args, None)
}

pub(crate) fn command_capture_with_cwd(
    program: &str,
    args: &[&str],
    cwd: Option<&str>,
) -> CmdResult {
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

pub(crate) fn pacman_stdout_indicates_change(stdout: &str) -> bool {
    stdout.contains("\nupgrading ")
        || stdout.contains("\ninstalling ")
        || stdout.contains("\nreinstalling ")
        || stdout.contains("\nremoving ")
}
