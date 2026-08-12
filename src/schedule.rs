use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
const DEFAULT_SYSTEMD_ROOT: &str = "/etc/systemd/system";
const SERVICE_NAME: &str = "harmonia.service";
const TIMER_NAME: &str = "harmonia.timer";
fn options(args: &[String]) -> Result<(PathBuf, bool), String> {
    let mut root = PathBuf::from(DEFAULT_SYSTEMD_ROOT);
    let mut dry_run = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--dry-run" => dry_run = true,
            "--systemd-root" => {
                index += 1;
                root = PathBuf::from(
                    args.get(index)
                        .ok_or("timer command requires a value after --systemd-root")?,
                );
            }
            other => return Err(format!("timer command argument unsupported {other}")),
        }
        index += 1;
    }
    if !root.is_absolute() {
        return Err("timer systemd root must be absolute".to_string());
    }
    Ok((root, dry_run))
}
fn service_bytes() -> &'static [u8] {
    b"[Unit]\nDescription=Run Harmonia convergence for the selected profile\nDocumentation=file:/var/lib/harmonia/receipts/update-latest/run.json\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/harmonia update --apply --receipt-dir /var/lib/harmonia/receipts/update-latest\nNice=10\nIOSchedulingClass=idle\n"
}
fn timer_bytes() -> &'static [u8] {
    b"[Unit]\nDescription=Run Harmonia selected-profile convergence on schedule\n\n[Timer]\nOnBootSec=2min\nOnCalendar=*:0/10\nOnUnitActiveSec=10min\nAccuracySec=30s\nPersistent=true\nUnit=harmonia.service\n\n[Install]\nWantedBy=timers.target\n"
}
fn systemctl(args: &[&str]) -> Result<(), String> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .map_err(|error| format!("systemctl-exec-failed: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "systemctl-failed exit={}",
            status.code().unwrap_or(-1)
        ))
    }
}
fn write_unit(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("unit-parent-missing {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temp, bytes).map_err(|e| e.to_string())?;
    fs::rename(&temp, path).map_err(|e| e.to_string())
}
pub(crate) fn install_timer(args: &[String]) -> Result<(), String> {
    let (root, dry_run) = options(args)?;
    let service = root.join(SERVICE_NAME);
    let timer = root.join(TIMER_NAME);
    if !dry_run {
        write_unit(&service, service_bytes())?;
        write_unit(&timer, timer_bytes())?;
        if root == Path::new(DEFAULT_SYSTEMD_ROOT) {
            systemctl(&["daemon-reload"])?;
            systemctl(&["enable", "--now", TIMER_NAME])?;
        }
    }
    println!("{}",serde_json::to_string_pretty(&json!({"schema":"harmonia.timer.v1","ok":true,"action":"install","dry_run":dry_run,"systemd_root":root,"service":service,"timer":timer,"host_systemd_called":!dry_run&&root==Path::new(DEFAULT_SYSTEMD_ROOT)})).map_err(|e|e.to_string())?);
    Ok(())
}
pub(crate) fn uninstall_timer(args: &[String]) -> Result<(), String> {
    let (root, dry_run) = options(args)?;
    let service = root.join(SERVICE_NAME);
    let timer = root.join(TIMER_NAME);
    if !dry_run {
        if root == Path::new(DEFAULT_SYSTEMD_ROOT) {
            systemctl(&["disable", "--now", TIMER_NAME])?;
        }
        for path in [&timer, &service] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        if root == Path::new(DEFAULT_SYSTEMD_ROOT) {
            systemctl(&["daemon-reload"])?;
        }
    }
    println!("{}",serde_json::to_string_pretty(&json!({"schema":"harmonia.timer.v1","ok":true,"action":"uninstall","dry_run":dry_run,"systemd_root":root,"service":service,"timer":timer,"host_systemd_called":!dry_run&&root==Path::new(DEFAULT_SYSTEMD_ROOT)})).map_err(|e|e.to_string())?);
    Ok(())
}
