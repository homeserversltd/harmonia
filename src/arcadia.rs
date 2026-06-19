use crate::*;
use serde_json::json;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::time::Instant;

const ARCADIA_CONTROL_DROPIN_DIR: &str = "/etc/systemd/system/arcadia.service.d";
const ARCADIA_CONTROL_DROPIN_PATH: &str =
    "/etc/systemd/system/arcadia.service.d/10-control-surface-authority.conf";
const ARCADIA_CONTROL_DROPIN_CONTENT: &str = "[Service]\nUser=\nGroup=\nNoNewPrivileges=false\n";

fn git_artifact_cmd(result: &tools::git_artifact::CommandReceipt) -> CmdResult {
    CmdResult {
        ok: result.ok,
        code: result.code,
        stdout: result.stdout.clone(),
        stderr: result.stderr.clone(),
    }
}

pub(crate) fn homeconsole_arcadia_check(
    profile: &Profile,
    receipt_dir: &Path,
    repo: &str,
    branch: &str,
    current_sha_file: &Path,
    upstream_sha_file: Option<&Path>,
    insecure_tls: bool,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.identity != "homeconsole" {
        return Err(format!(
            "homeconsole-arcadia-check requires homeconsole/homeconsole profile, got {}/{}",
            profile.id, profile.identity
        ));
    }
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let started = Instant::now();
    let current_sha = fs::read_to_string(current_sha_file)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let refspec = format!("refs/heads/{branch}");
    let file_upstream = upstream_sha_file
        .and_then(|path| fs::read_to_string(path).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| is_hex_sha(s));
    let remote = if file_upstream.is_some() {
        CmdResult {
            ok: true,
            code: 0,
            stdout: file_upstream.clone().unwrap_or_default(),
            stderr: String::new(),
        }
    } else {
        git_ls_remote(repo, &refspec, insecure_tls)
    };
    let upstream_sha = if let Some(sha) = file_upstream {
        Some(sha)
    } else {
        remote
            .stdout
            .split_whitespace()
            .next()
            .map(|s| s.to_string())
            .filter(|s| is_hex_sha(s))
    };
    let ok = remote.ok && upstream_sha.is_some() && current_sha.is_some();
    let first_missing_signal = if !remote.ok {
        "upstream-sha-unreadable"
    } else if upstream_sha.is_none() {
        "upstream-sha-missing"
    } else if current_sha.is_none() {
        "current-sha-missing"
    } else {
        "none"
    };
    let update_available = match (&current_sha, &upstream_sha) {
        (Some(current), Some(upstream)) => current != upstream,
        _ => false,
    };
    let elapsed_ms = started.elapsed().as_millis();
    write_command_receipt(receipt_dir, "arcadia-upstream-sha", &remote)?;
    write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema": "harmonia.arcadia_fast_check.v1",
            "ok": ok,
            "mutation": false,
            "profile_id": profile.id,
            "profile_family": profile.identity,
            "repo": repo,
            "branch": branch,
            "current_sha_file": current_sha_file,
            "current_sha": current_sha,
            "upstream_sha": upstream_sha,
            "update_available": update_available,
            "first_missing_signal": first_missing_signal,
            "elapsed_ms": elapsed_ms,
        }),
    )?;
    println!("schema=harmonia.arcadia_fast_check.v1");
    println!("ok={}", ok);
    println!("update_available={}", update_available);
    println!(
        "current_sha={}",
        current_sha.as_deref().unwrap_or("unknown")
    );
    println!(
        "upstream_sha={}",
        upstream_sha.as_deref().unwrap_or("unknown")
    );
    println!("first_missing_signal={}", first_missing_signal);
    println!("elapsed_ms={}", elapsed_ms);
    println!("receipt_dir={}", receipt_dir.display());
    if ok {
        Ok(())
    } else {
        Err(first_missing_signal.to_string())
    }
}

pub(crate) fn git_ls_remote(repo: &str, refspec: &str, insecure_tls: bool) -> CmdResult {
    let mut cmd = Command::new("/usr/bin/git");
    if insecure_tls {
        cmd.arg("-c").arg("http.sslVerify=false");
    }
    cmd.arg("ls-remote").arg(repo).arg(refspec);
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

pub(crate) fn is_hex_sha(s: &str) -> bool {
    s.len() >= 7 && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn ensure_arcadia_control_surface_authority(
    receipt_dir: &Path,
    apply: bool,
) -> Result<bool, String> {
    let existing = fs::read_to_string(ARCADIA_CONTROL_DROPIN_PATH).unwrap_or_default();
    let changed = existing != ARCADIA_CONTROL_DROPIN_CONTENT;
    if apply && changed {
        fs::create_dir_all(ARCADIA_CONTROL_DROPIN_DIR)
            .map_err(|e| format!("arcadia-control-dropin-dir-failed: {e}"))?;
        let tmp = Path::new(ARCADIA_CONTROL_DROPIN_PATH).with_extension("harmonia-new");
        fs::write(&tmp, ARCADIA_CONTROL_DROPIN_CONTENT)
            .map_err(|e| format!("arcadia-control-dropin-write-failed: {e}"))?;
        let mut perms = fs::metadata(&tmp).map_err(|e| e.to_string())?.permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&tmp, perms).map_err(|e| e.to_string())?;
        fs::rename(&tmp, ARCADIA_CONTROL_DROPIN_PATH)
            .map_err(|e| format!("arcadia-control-dropin-promote-failed: {e}"))?;
    }
    write_json(
        &receipt_dir.join("arcadia-control-surface-authority.json"),
        &json!({
            "schema": "harmonia.arcadia_control_surface_authority.v1",
            "ok": !changed || apply,
            "mutation": apply && changed,
            "changed": changed,
            "dropin_path": ARCADIA_CONTROL_DROPIN_PATH,
            "desired": {
                "user": "root",
                "group": "root",
                "no_new_privileges": false,
                "reason": "Arcadia is the HomeConsole front panel and must execute declared local appliance controls through Harmonia/systemd."
            }
        }),
    )?;
    if changed && !apply {
        return Err("arcadia-control-surface-authority-drift".to_string());
    }
    Ok(changed)
}

fn read_arcadia_control_surface_authority(service: &str) -> CmdResult {
    command_capture(
        "/usr/bin/systemctl",
        &[
            "show",
            service,
            "-p",
            "User",
            "-p",
            "Group",
            "-p",
            "NoNewPrivileges",
            "--no-pager",
        ],
    )
}

pub(crate) fn homeconsole_arcadia_update(
    profile: &Profile,
    receipt_dir: &Path,
    artifact: &Path,
    install_bin: &Path,
    service: &str,
    apply: bool,
    source_sha: Option<&str>,
    source_sha_file: &Path,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.identity != "homeconsole" {
        return Err(format!(
            "homeconsole-arcadia-update requires homeconsole/homeconsole profile, got {}/{}",
            profile.id, profile.identity
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
        if let Some(source_sha) = source_sha {
            if let Some(parent) = source_sha_file.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            fs::write(source_sha_file, format!("{}\n", source_sha.trim()))
                .map_err(|e| format!("source-sha-write-failed: {e}"))?;
            event(
                &mut events,
                "source-sha-recorded",
                true,
                "Arcadia source SHA recorded",
            )?;
        }
        let authority_changed = ensure_arcadia_control_surface_authority(receipt_dir, true)?;
        changed = changed || authority_changed;
        event(
            &mut events,
            "control-surface-authority",
            true,
            "Arcadia control-surface authority installed",
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
    if !apply {
        if let Err(signal) = ensure_arcadia_control_surface_authority(receipt_dir, false) {
            ok = false;
            if first_missing_signal == "none" {
                first_missing_signal = signal;
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
    let authority_readback = read_arcadia_control_surface_authority(service);
    write_command_receipt(
        receipt_dir,
        "arcadia-control-surface-authority-readback",
        &authority_readback,
    )?;
    if apply
        && (!authority_readback.ok || !authority_readback.stdout.contains("NoNewPrivileges=no"))
    {
        ok = false;
        if first_missing_signal == "none" {
            first_missing_signal = "arcadia-control-surface-authority-unproven".to_string();
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn homeconsole_arcadia_gui_update(
    profile: &Profile,
    receipt_dir: &Path,
    repo: &str,
    branch: &str,
    source_dir: &Path,
    install_bin: &Path,
    service: &str,
    apply: bool,
    source_sha_file: &Path,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.identity != "homeconsole" {
        return Err(format!(
            "homeconsole-arcadia-gui-update requires homeconsole/homeconsole profile, got {}/{}",
            profile.id, profile.identity
        ));
    }
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;

    let git_request = tools::git_artifact::Request::new(
        Some(repo.to_string()),
        source_dir.to_path_buf(),
        branch.to_string(),
        "origin".to_string(),
    );
    let git_outcome = if apply {
        tools::git_artifact::apply(&git_request)
    } else {
        tools::git_artifact::plan(&git_request)
    };
    let git_cmd = git_artifact_cmd(&git_outcome.command);
    write_command_receipt(receipt_dir, "arcadia-source-git-artifact", &git_cmd)?;
    if !git_outcome.ok {
        write_arcadia_gui_run_receipt(
            receipt_dir,
            profile,
            apply,
            false,
            git_outcome.changed,
            "arcadia-source-git-artifact-failed",
            repo,
            branch,
            source_dir,
            None,
        )?;
        return Err("arcadia-source-git-artifact-failed".to_string());
    }

    let source_sha =
        command_capture_with_cwd("/usr/bin/git", &["rev-parse", "HEAD"], source_dir.to_str());
    write_command_receipt(receipt_dir, "arcadia-source-sha", &source_sha)?;
    let source_sha_value = source_sha.stdout.trim().to_string();
    if !source_sha.ok || !is_hex_sha(&source_sha_value) {
        write_arcadia_gui_run_receipt(
            receipt_dir,
            profile,
            apply,
            false,
            git_outcome.changed,
            "arcadia-source-sha-missing",
            repo,
            branch,
            source_dir,
            None,
        )?;
        return Err("arcadia-source-sha-missing".to_string());
    }

    if !apply {
        write_arcadia_gui_run_receipt(
            receipt_dir,
            profile,
            apply,
            true,
            git_outcome.changed,
            "none",
            repo,
            branch,
            source_dir,
            Some(&source_sha_value),
        )?;
        println!("schema=harmonia.homeconsole_arcadia_gui_update.v1");
        println!("ok=true");
        println!("changed={}", git_outcome.changed);
        println!("first_missing_signal=none");
        println!("source_sha={}", source_sha_value);
        println!("receipt_dir={}", receipt_dir.display());
        return Ok(());
    }

    let build = command_capture_with_cwd(
        "/usr/bin/cargo",
        &["build", "--release"],
        source_dir.to_str(),
    );
    write_command_receipt(receipt_dir, "arcadia-cargo-build", &build)?;
    if !build.ok {
        write_arcadia_gui_run_receipt(
            receipt_dir,
            profile,
            apply,
            false,
            git_outcome.changed,
            "arcadia-cargo-build-failed",
            repo,
            branch,
            source_dir,
            Some(&source_sha_value),
        )?;
        return Err("arcadia-cargo-build-failed".to_string());
    }

    let artifact = source_dir.join("target/release/arcadia");
    homeconsole_arcadia_update(
        profile,
        receipt_dir,
        &artifact,
        install_bin,
        service,
        true,
        Some(&source_sha_value),
        source_sha_file,
    )?;

    let health = arcadia_health_with_retry();
    write_command_receipt(receipt_dir, "arcadia-health", &health)?;
    let ok = health.ok;
    let first_missing_signal = if ok { "none" } else { "arcadia-health-failed" };
    write_arcadia_gui_run_receipt(
        receipt_dir,
        profile,
        apply,
        ok,
        true,
        first_missing_signal,
        repo,
        branch,
        source_dir,
        Some(&source_sha_value),
    )?;
    println!("schema=harmonia.homeconsole_arcadia_gui_update.v1");
    println!("ok={}", ok);
    println!("changed=true");
    println!("first_missing_signal={}", first_missing_signal);
    println!("source_sha={}", source_sha_value);
    println!("receipt_dir={}", receipt_dir.display());
    if ok {
        Ok(())
    } else {
        Err(first_missing_signal.to_string())
    }
}

fn arcadia_health_with_retry() -> CmdResult {
    let mut last = command_capture(
        "/usr/bin/curl",
        &["-fsS", "--max-time", "3", "http://127.0.0.1:8080/health"],
    );
    for _ in 0..5 {
        if last.ok {
            return last;
        }
        thread::sleep(Duration::from_secs(1));
        last = command_capture(
            "/usr/bin/curl",
            &["-fsS", "--max-time", "3", "http://127.0.0.1:8080/health"],
        );
    }
    last
}

#[allow(clippy::too_many_arguments)]
fn write_arcadia_gui_run_receipt(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
    ok: bool,
    changed: bool,
    first_missing_signal: &str,
    repo: &str,
    branch: &str,
    source_dir: &Path,
    source_sha: Option<&str>,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema": "harmonia.homeconsole_arcadia_gui_update.v1",
            "ok": ok,
            "changed": changed,
            "mutation": apply,
            "profile_id": profile.id,
            "profile_family": profile.identity,
            "repo": repo,
            "branch": branch,
            "source_dir": source_dir,
            "source_sha": source_sha,
            "first_missing_signal": first_missing_signal,
        }),
    )
}
