use crate::*;
use serde_json::json;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn write_json(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut f = File::create(path).map_err(|e| e.to_string())?;
    serde_json::to_writer_pretty(&mut f, value).map_err(|e| e.to_string())?;
    writeln!(f).map_err(|e| e.to_string())?;
    Ok(())
}

pub(crate) fn run_id_from_stamp() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("run-{nanos}")
}

pub(crate) fn receipt_root_for(receipt_dir: &Path) -> PathBuf {
    receipt_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| receipt_dir.to_path_buf())
}

pub(crate) fn profile_ledger_path(receipt_dir: &Path, profile: &Profile) -> PathBuf {
    receipt_root_for(receipt_dir).join(format!("{}-ledger.jsonl", profile.id))
}

fn next_ledger_sequence(path: &Path) -> Result<u64, String> {
    if !path.exists() {
        return Ok(1);
    }
    let file = File::open(path).map_err(|e| e.to_string())?;
    let count = BufReader::new(file).lines().count() as u64;
    Ok(count + 1)
}

pub(crate) struct ProfileLedgerEntry<'a> {
    pub run_id: &'a str,
    pub module_id: &'a str,
    pub ok: bool,
    pub changed: bool,
    pub operation_count: usize,
    pub first_missing_signal: &'a str,
    pub receipt_dir: &'a Path,
}

pub(crate) fn append_profile_ledger_entry(
    receipt_dir: &Path,
    profile: &Profile,
    entry: ProfileLedgerEntry<'_>,
) -> Result<(), String> {
    let path = profile_ledger_path(receipt_dir, profile);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let sequence = next_ledger_sequence(&path)?;
    let stamped_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let mut ledger = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    writeln!(
        ledger,
        "{}",
        json!({
            "schema": "harmonia.profile_ledger.entry.v1",
            "ledger": "profile-module-ledger",
            "sequence": sequence,
            "stamped_at_unix_ms": stamped_at_unix_ms,
            "run_id": entry.run_id,
            "profile_id": profile.id,
            "identity": profile.identity,
            "module_id": entry.module_id,
            "ok": entry.ok,
            "changed": entry.changed,
            "operation_count": entry.operation_count,
            "first_missing_signal": entry.first_missing_signal,
            "receipt_dir": entry.receipt_dir,
        })
    )
    .map_err(|e| e.to_string())
}

pub(crate) fn write_tool_receipt(
    receipt_dir: &Path,
    name: &str,
    tool: &str,
    action: &str,
    outcome: &OperationOutcome,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{}.json", name)),
        &json!({
            "schema": "harmonia.tool_receipt.v1",
            "operation_id": name,
            "tool": tool,
            "action": action,
            "ok": outcome.ok,
            "changed": outcome.changed,
            "skipped": outcome.skipped,
            "message": outcome.message,
            "command": outcome.command,
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
    operation_count: usize,
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
            "identity": profile.identity,
            "module_count": module_count,
            "operation_count": operation_count,
            "first_missing_signal": first_missing_signal,
            "module_spine_entered": module_root,
            "selected_profile": profile.id,
            "suite_ok": ok,
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
            "identity": profile.identity,
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
            "identity": profile.identity,
            "module_count": profile.modules.len(),
        }),
    )?;
    writeln!(run)?;
    Ok(())
}
