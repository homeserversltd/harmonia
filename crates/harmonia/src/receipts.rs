use crate::*;
use serde_json::json;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

pub(crate) fn write_json(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut f = File::create(path).map_err(|e| e.to_string())?;
    serde_json::to_writer_pretty(&mut f, value).map_err(|e| e.to_string())?;
    writeln!(f).map_err(|e| e.to_string())?;
    Ok(())
}

pub(crate) fn write_step_receipt(
    receipt_dir: &Path,
    step: &Step,
    ok: bool,
    changed: bool,
    skipped: bool,
    message: &str,
    command: Option<&CmdResult>,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{}.json", step.id)),
        &json!({
            "schema": "harmonia.step_receipt.v1",
            "step_id": step.id,
            "tool": step.tool,
            "action": step.action,
            "ok": ok,
            "changed": changed,
            "skipped": skipped,
            "message": message,
            "command": command,
        }),
    )
}

pub(crate) fn write_engine_run_receipt(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
    ok: bool,
    changed: bool,
    module_count: usize,
    step_count: usize,
    first_missing_signal: &str,
    module_root: &Path,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema": "harmonia.run_profile.v1",
            "ok": ok,
            "changed": changed,
            "mutation": apply,
            "profile_id": profile.id,
            "profile_family": profile.family,
            "module_count": module_count,
            "step_count": step_count,
            "first_missing_signal": first_missing_signal,
            "module_root": module_root,
        }),
    )
}

pub(crate) fn write_artifact_receipt(
    receipt_dir: &Path,
    artifact: &Path,
    install_bin: &Path,
    service: &str,
    apply: bool,
    artifact_len: u64,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join("arcadia-artifact.json"),
        &json!({
            "schema": "harmonia.arcadia_artifact.v1",
            "ok": true,
            "mutation": apply,
            "artifact": artifact,
            "install_bin": install_bin,
            "service": service,
            "artifact_bytes": artifact_len,
        }),
    )
}

pub(crate) fn write_redacted_command_receipt(
    receipt_dir: &Path,
    name: &str,
    result: &CmdResult,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{}.json", name)),
        &json!({
            "schema": "harmonia.command_receipt.v1",
            "name": name,
            "ok": result.ok,
            "exit_code": result.code,
            "stdout_redacted": true,
            "stderr_redacted": true,
            "stdout_bytes": result.stdout.len(),
            "stderr_bytes": result.stderr.len(),
        }),
    )
}

pub(crate) fn write_command_receipt(
    receipt_dir: &Path,
    name: &str,
    result: &CmdResult,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{}.json", name)),
        &json!({
            "schema": "harmonia.command_receipt.v1",
            "name": name,
            "ok": result.ok,
            "exit_code": result.code,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }),
    )
}

pub(crate) fn write_run_receipt(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
    ok: bool,
    first_missing_signal: &str,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema": "harmonia.run.v1",
            "ok": ok,
            "mutation": apply,
            "profile_id": profile.id,
            "profile_family": profile.family,
            "module_count": profile.modules.len(),
            "first_missing_signal": first_missing_signal,
        }),
    )
}

pub(crate) fn event(events: &mut File, event: &str, ok: bool, message: &str) -> Result<(), String> {
    writeln!(
        events,
        "{}",
        json!({"event": event, "ok": ok, "message": message})
    )
    .map_err(|e| e.to_string())
}

pub(crate) fn extract_string(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let start = text.find(&needle)?;
    let after_key = &text[start + needle.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    let rest = after_colon.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

pub(crate) fn extract_string_array(text: &str, key: &str) -> Vec<String> {
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

pub(crate) fn write_plan_receipts(profile: &Profile, receipt_dir: &Path) -> io::Result<()> {
    fs::create_dir_all(receipt_dir)?;
    let mut events = File::create(receipt_dir.join("events.jsonl"))?;
    writeln!(
        events,
        "{}",
        json!({"event":"plan-start","profile":profile.id,"ok":true})
    )?;
    for module in &profile.modules {
        writeln!(
            events,
            "{}",
            json!({"event":"module-planned","module":module,"ok":true})
        )?;
    }
    let mut run = File::create(receipt_dir.join("run.json"))?;
    serde_json::to_writer_pretty(
        &mut run,
        &json!({
            "schema": "harmonia.run.v1",
            "ok": true,
            "mutation": false,
            "profile_id": profile.id,
            "profile_family": profile.family,
            "module_count": profile.modules.len(),
        }),
    )?;
    writeln!(run)?;
    Ok(())
}
