use crate::*;
use std::fs::{self, File};
use std::path::Path;
use std::process::Command;

pub(crate) fn homeconsole_update(
    profile: &Profile,
    receipt_dir: &Path,
    apply: bool,
) -> Result<(), String> {
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
