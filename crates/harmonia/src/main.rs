use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
struct Profile {
    id: String,
    family: String,
    modules: Vec<String>,
}

#[derive(Debug, Clone)]
struct CmdResult {
    ok: bool,
    code: i32,
    stdout: String,
    stderr: String,
}

fn main() {
    if let Err(err) = run(env::args().skip(1).collect()) {
        eprintln!("harmonia_error={}", err);
        process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("explain") => explain(),
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
            let apply = args.iter().any(|arg| arg == "--apply");
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            homeconsole_arcadia_update(
                &profile,
                &receipt_dir,
                &artifact,
                &install_bin,
                &service,
                apply,
            )
        }
        _ => usage(),
    }
}

fn explain() -> Result<(), String> {
    println!("schema=harmonia.explain.v1");
    println!("ok=true");
    println!("name=harmonia");
    println!("version={}", VERSION);
    println!("covenant=Rust-only Chrysalis update suite/toolchain");
    println!("shell=bootstrap-only");
    println!("python_helper_lane=false");
    println!("profiles=homeserver,homeconsole,tv");
    println!("homeconsole_equals_arch_console=true");
    Ok(())
}

fn usage() -> Result<(), String> {
    println!("harmonia {}", VERSION);
    println!("usage:");
    println!("  harmonia explain");
    println!("  harmonia inspect-profile <profiles/<id>/index.json>");
    println!("  harmonia plan-run <profiles/<id>/index.json> [--receipt-dir <path>]");
    println!("  harmonia homeconsole-update <profiles/homeconsole/index.json> [--apply] [--receipt-dir <path>]");
    println!("  harmonia homeconsole-arcadia-update <profiles/homeconsole/index.json> --artifact <path> [--apply] [--install-bin <path>] [--service arcadia.service] [--receipt-dir <path>]");
    Ok(())
}

fn receipt_dir_arg(args: &[String]) -> Option<PathBuf> {
    value_arg(args, "--receipt-dir")
}

fn value_arg(args: &[String], name: &str) -> Option<PathBuf> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| PathBuf::from(&pair[1]))
}

fn load_profile(path: &Path) -> io::Result<Profile> {
    let text = fs::read_to_string(path)?;
    let id = extract_string(&text, "id").unwrap_or_else(|| "unknown".to_string());
    let family = extract_string(&text, "family").unwrap_or_else(|| id.clone());
    let modules = extract_string_array(&text, "modules");
    Ok(Profile {
        id,
        family,
        modules,
    })
}

fn homeconsole_arcadia_update(
    profile: &Profile,
    receipt_dir: &Path,
    artifact: &Path,
    install_bin: &Path,
    service: &str,
    apply: bool,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.family != "arch-console" {
        return Err(format!(
            "homeconsole-arcadia-update requires homeconsole/arch-console profile, got {}/{}",
            profile.id, profile.family
        ));
    }
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let mut events = File::create(receipt_dir.join("events.jsonl")).map_err(|e| e.to_string())?;
    event(&mut events, "arcadia-start", true, "Arcadia update started")?;

    let metadata = fs::metadata(artifact).map_err(|e| format!("artifact-missing: {e}"))?;
    let artifact_len = metadata.len();
    write_artifact_receipt(
        receipt_dir,
        artifact,
        install_bin,
        service,
        apply,
        artifact_len,
    )?;
    event(&mut events, "artifact", true, "Arcadia artifact present")?;

    let mut ok = true;
    let mut changed = false;
    let mut first_missing_signal = "none".to_string();

    if apply {
        if let Some(parent) = install_bin.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let before_len = fs::metadata(install_bin).map(|m| m.len()).ok();
        let stop = command_capture("/usr/bin/systemctl", &["stop", service]);
        write_command_receipt(receipt_dir, "arcadia-service-stop", &stop)?;
        if !stop.ok {
            event(
                &mut events,
                "service-stop-warning",
                false,
                "Arcadia service stop returned nonzero",
            )?;
        }
        let tmp_install = install_bin.with_extension("harmonia-new");
        fs::copy(artifact, &tmp_install).map_err(|e| format!("artifact-copy-failed: {e}"))?;
        let mut perms = fs::metadata(&tmp_install)
            .map_err(|e| e.to_string())?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&tmp_install, perms).map_err(|e| e.to_string())?;
        fs::rename(&tmp_install, install_bin)
            .map_err(|e| format!("artifact-promote-failed: {e}"))?;
        changed = before_len != Some(artifact_len);
        event(
            &mut events,
            "artifact-installed",
            true,
            "Arcadia artifact installed",
        )?;

        let daemon_reload = command_capture("/usr/bin/systemctl", &["daemon-reload"]);
        write_command_receipt(receipt_dir, "arcadia-daemon-reload", &daemon_reload)?;
        if !daemon_reload.ok {
            ok = false;
            first_missing_signal = "systemd-daemon-reload-failed".to_string();
        }

        let restart = command_capture("/usr/bin/systemctl", &["restart", service]);
        write_command_receipt(receipt_dir, "arcadia-service-restart", &restart)?;
        if !restart.ok {
            ok = false;
            if first_missing_signal == "none" {
                first_missing_signal = "arcadia-service-restart-failed".to_string();
            }
        }
    }

    let status = command_capture("/usr/bin/systemctl", &["is-active", service]);
    write_command_receipt(receipt_dir, "arcadia-service-active", &status)?;
    if apply && !status.ok {
        ok = false;
        if first_missing_signal == "none" {
            first_missing_signal = "arcadia-service-not-active".to_string();
        }
    }

    write_run_receipt(receipt_dir, profile, apply, ok, &first_missing_signal)?;
    println!("schema=harmonia.homeconsole_arcadia_update.v1");
    println!("ok={}", ok);
    println!("changed={}", changed);
    println!("first_missing_signal={}", first_missing_signal);
    println!("artifact={}", artifact.display());
    println!("install_bin={}", install_bin.display());
    println!("service={}", service);
    println!("receipt_dir={}", receipt_dir.display());
    if ok {
        Ok(())
    } else {
        Err(first_missing_signal)
    }
}

fn homeconsole_update(profile: &Profile, receipt_dir: &Path, apply: bool) -> Result<(), String> {
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

fn command_capture(program: &str, args: &[&str]) -> CmdResult {
    match Command::new(program).args(args).output() {
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

fn pacman_stdout_indicates_change(stdout: &str) -> bool {
    stdout.contains("\nupgrading ")
        || stdout.contains("\ninstalling ")
        || stdout.contains("\nreinstalling ")
        || stdout.contains("\nremoving ")
}

fn write_artifact_receipt(
    receipt_dir: &Path,
    artifact: &Path,
    install_bin: &Path,
    service: &str,
    apply: bool,
    artifact_len: u64,
) -> Result<(), String> {
    let mut f =
        File::create(receipt_dir.join("arcadia-artifact.json")).map_err(|e| e.to_string())?;
    writeln!(f, "{{").map_err(|e| e.to_string())?;
    writeln!(f, "  \"schema\": \"harmonia.arcadia_artifact.v1\",").map_err(|e| e.to_string())?;
    writeln!(f, "  \"ok\": true,").map_err(|e| e.to_string())?;
    writeln!(f, "  \"mutation\": {},", apply).map_err(|e| e.to_string())?;
    writeln!(
        f,
        "  \"artifact\": \"{}\",",
        json_escape(&artifact.display().to_string())
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        f,
        "  \"install_bin\": \"{}\",",
        json_escape(&install_bin.display().to_string())
    )
    .map_err(|e| e.to_string())?;
    writeln!(f, "  \"service\": \"{}\",", json_escape(service)).map_err(|e| e.to_string())?;
    writeln!(f, "  \"artifact_bytes\": {}", artifact_len).map_err(|e| e.to_string())?;
    writeln!(f, "}}").map_err(|e| e.to_string())?;
    Ok(())
}

fn write_command_receipt(receipt_dir: &Path, name: &str, result: &CmdResult) -> Result<(), String> {
    let mut f =
        File::create(receipt_dir.join(format!("{}.json", name))).map_err(|e| e.to_string())?;
    writeln!(f, "{{").map_err(|e| e.to_string())?;
    writeln!(f, "  \"schema\": \"harmonia.command_receipt.v1\",").map_err(|e| e.to_string())?;
    writeln!(f, "  \"name\": \"{}\",", json_escape(name)).map_err(|e| e.to_string())?;
    writeln!(f, "  \"ok\": {},", result.ok).map_err(|e| e.to_string())?;
    writeln!(f, "  \"exit_code\": {},", result.code).map_err(|e| e.to_string())?;
    writeln!(f, "  \"stdout\": \"{}\",", json_escape(&result.stdout)).map_err(|e| e.to_string())?;
    writeln!(f, "  \"stderr\": \"{}\"", json_escape(&result.stderr)).map_err(|e| e.to_string())?;
    writeln!(f, "}}").map_err(|e| e.to_string())?;
    Ok(())
}

fn write_run_receipt(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
    ok: bool,
    first_missing_signal: &str,
) -> Result<(), String> {
    let mut run = File::create(receipt_dir.join("run.json")).map_err(|e| e.to_string())?;
    writeln!(run, "{{").map_err(|e| e.to_string())?;
    writeln!(run, "  \"schema\": \"harmonia.run.v1\",").map_err(|e| e.to_string())?;
    writeln!(run, "  \"ok\": {},", ok).map_err(|e| e.to_string())?;
    writeln!(run, "  \"mutation\": {},", apply).map_err(|e| e.to_string())?;
    writeln!(run, "  \"profile_id\": \"{}\",", json_escape(&profile.id))
        .map_err(|e| e.to_string())?;
    writeln!(
        run,
        "  \"profile_family\": \"{}\",",
        json_escape(&profile.family)
    )
    .map_err(|e| e.to_string())?;
    writeln!(run, "  \"module_count\": {},", profile.modules.len()).map_err(|e| e.to_string())?;
    writeln!(
        run,
        "  \"first_missing_signal\": \"{}\"",
        json_escape(first_missing_signal)
    )
    .map_err(|e| e.to_string())?;
    writeln!(run, "}}").map_err(|e| e.to_string())?;
    Ok(())
}

fn event(events: &mut File, event: &str, ok: bool, message: &str) -> Result<(), String> {
    writeln!(
        events,
        "{{\"event\":\"{}\",\"ok\":{},\"message\":\"{}\"}}",
        json_escape(event),
        ok,
        json_escape(message)
    )
    .map_err(|e| e.to_string())
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn extract_string(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let start = text.find(&needle)?;
    let after_key = &text[start + needle.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    let rest = after_colon.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_string_array(text: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{}\"", key);
    let Some(start) = text.find(&needle) else {
        return Vec::new();
    };
    let after_key = &text[start + needle.len()..];
    let Some(colon) = after_key.find(':') else {
        return Vec::new();
    };
    let after_colon = after_key[colon + 1..].trim_start();
    let Some(rest) = after_colon.strip_prefix('[') else {
        return Vec::new();
    };
    let Some(end) = rest.find(']') else {
        return Vec::new();
    };
    rest[..end]
        .split(',')
        .filter_map(|item| {
            let t = item.trim();
            let t = t.strip_prefix('"')?.strip_suffix('"')?;
            Some(t.to_string())
        })
        .collect()
}

fn write_plan_receipts(profile: &Profile, receipt_dir: &Path) -> io::Result<()> {
    fs::create_dir_all(receipt_dir)?;
    let mut events = File::create(receipt_dir.join("events.jsonl"))?;
    writeln!(
        events,
        "{{\"event\":\"plan-start\",\"profile\":\"{}\",\"ok\":true}}",
        json_escape(&profile.id)
    )?;
    for module in &profile.modules {
        writeln!(
            events,
            "{{\"event\":\"module-planned\",\"module\":\"{}\",\"ok\":true}}",
            json_escape(module)
        )?;
    }
    let mut run = File::create(receipt_dir.join("run.json"))?;
    writeln!(run, "{{")?;
    writeln!(run, "  \"schema\": \"harmonia.run.v1\",")?;
    writeln!(run, "  \"ok\": true,")?;
    writeln!(run, "  \"mutation\": false,")?;
    writeln!(run, "  \"profile_id\": \"{}\",", json_escape(&profile.id))?;
    writeln!(
        run,
        "  \"profile_family\": \"{}\",",
        json_escape(&profile.family)
    )?;
    writeln!(run, "  \"module_count\": {}", profile.modules.len())?;
    writeln!(run, "}}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_profile_fields() {
        let text =
            r#"{"id":"homeconsole","family":"arch-console","modules":["identity","packages"]}"#;
        assert_eq!(extract_string(text, "id").unwrap(), "homeconsole");
        assert_eq!(extract_string(text, "family").unwrap(), "arch-console");
        assert_eq!(
            extract_string_array(text, "modules"),
            vec!["identity", "packages"]
        );
    }

    #[test]
    fn json_escape_handles_receipt_strings() {
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
    }

    #[test]
    fn detects_pacman_change_from_stdout() {
        assert!(pacman_stdout_indicates_change("\nupgrading ffmpeg..."));
        assert!(!pacman_stdout_indicates_change(" there is nothing to do"));
    }
}
