use crate::*;
use serde_json::json;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static RECEIPT_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) fn write_json(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("receipt-parent-missing {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("receipt-parent-create-failed {}: {error}", parent.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("receipt-name-invalid {}", path.display()))?;
    let sequence = RECEIPT_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(
        ".{name}.harmonia-receipt-{}-{sequence}.tmp",
        std::process::id()
    ));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|error| format!("receipt-temp-create-failed {}: {error}", temp.display()))?;
        serde_json::to_writer_pretty(&mut file, value).map_err(|error| {
            format!("receipt-temp-serialize-failed {}: {error}", temp.display())
        })?;
        writeln!(file)
            .map_err(|error| format!("receipt-temp-write-failed {}: {error}", temp.display()))?;
        file.sync_all()
            .map_err(|error| format!("receipt-temp-sync-failed {}: {error}", temp.display()))?;
        drop(file);
        fs::rename(&temp, path).map_err(|error| {
            format!(
                "receipt-atomic-promote-failed {} -> {}: {error}",
                temp.display(),
                path.display()
            )
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("receipt-parent-sync-failed {}: {error}", parent.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
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
    pub module_version: Option<&'a str>,
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
            "module_version": entry.module_version,
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
            "first_missing_signal": outcome.command.as_ref().map(command_first_missing_signal).unwrap_or(if outcome.ok { "none" } else { "operation-failed" }),
        }),
    )
}

pub(crate) fn write_engine_run_receipt_with_duration(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
    hard_selection: Option<&str>,
    ok: bool,
    changed: bool,
    module_count: usize,
    operation_count: usize,
    first_missing_signal: &str,
    module_root: &Path,
    suite_ok: bool,
    run_duration_ms: u128,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema": "harmonia.run_profile.v1",
            "ok": ok,
            "changed": changed,
            "mutation": apply,
            "mode": if apply { "hard" } else { "report-only" },
            "hard_selection": hard_selection,
            "profile_id": profile.id,
            "identity": profile.identity,
            "identity_source": run_identity_source(),
            "module_count": module_count,
            "operation_count": operation_count,
            "run_duration_ms": run_duration_ms,
            "first_missing_signal": first_missing_signal,
            "module_spine_entered": module_root,
            "selected_profile": profile.id,
            "suite_ok": suite_ok,
        }),
    )
}

pub(crate) fn write_artifact_receipt(
    receipt_dir: &Path,
    artifact: &Path,
    install_bin: &Path,
    service: &str,
    apply: bool,
    ok: bool,
    changed: bool,
    first_missing_signal: &str,
    artifact_len: u64,
    artifact_sha256: &str,
    installed_sha256: Option<&str>,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join("arcadia-artifact.json"),
        &json!({
            "schema": "harmonia.arcadia_artifact.v1",
            "ok": ok,
            "changed": changed,
            "mutation": apply,
            "first_missing_signal": first_missing_signal,
            "artifact": artifact,
            "install_bin": install_bin,
            "service": service,
            "artifact_bytes": artifact_len,
            "artifact_sha256": artifact_sha256,
            "installed_sha256": installed_sha256,
        }),
    )
}

fn command_first_missing_signal(result: &CmdResult) -> &'static str {
    if result.ok {
        "none"
    } else if result.stderr.contains("command-timeout-after-") {
        "command-timeout"
    } else if result.stderr.contains("conflicting files")
        || result.stderr.contains("exists in filesystem")
    {
        "pacman-package-file-conflict"
    } else {
        "command-failed"
    }
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
            "first_missing_signal": command_first_missing_signal(result),
        }),
    )
}

pub(crate) fn write_command_receipt_with_request(
    receipt_dir: &Path,
    name: &str,
    program: &str,
    args: &[String],
    cwd: Option<&str>,
    result: &CmdResult,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{}.json", name)),
        &json!({
            "schema": "harmonia.command_receipt.v1",
            "name": name,
            "program": program,
            "args": args,
            "cwd": cwd,
            "ok": result.ok,
            "exit_code": result.code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "first_missing_signal": command_first_missing_signal(result),
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
            "identity_source": run_identity_source(),
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

pub(crate) fn write_plan_receipts(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
) -> io::Result<()> {
    fs::create_dir_all(receipt_dir)?;
    let mut events = File::create(receipt_dir.join("events.jsonl"))?;
    let mut ok = true;
    let mut first_missing_signal = "none".to_string();
    writeln!(
        events,
        "{}",
        json!({"event":"plan-start","profile":profile.id,"ok":true})
    )?;
    if profile.modules.is_empty() {
        ok = false;
        first_missing_signal = "profile-modules-empty".to_string();
        writeln!(
            events,
            "{}",
            json!({"event":"profile-modules","ok":false,"message":"profile module spine is empty"})
        )?;
    }
    for module in &profile.modules {
        let module_dir = module_root.join(module);
        let manifest_path = module_dir.join("manifest.json");
        let planned = if manifest_path.exists() && is_ladder_manifest(&manifest_path) {
            load_ladder_manifest(&manifest_path).and_then(|manifest| {
                if manifest.id != *module {
                    return Err(format!(
                        "module-id-mismatch expected={module} got={}",
                        manifest.id
                    ));
                }
                validate_ladder(&manifest)
                    .map(|_| ())
                    .map_err(|err| err.first_missing_signal())
            })
        } else {
            load_module(&module_dir.join("sidecar.json")).map(|_| ())
        };
        match planned {
            Ok(_) => {
                writeln!(
                    events,
                    "{}",
                    json!({"event":"module-planned","module":module,"ok":true})
                )?;
            }
            Err(err) => {
                ok = false;
                if first_missing_signal == "none" {
                    first_missing_signal = format!("module-missing-{module}");
                }
                writeln!(
                    events,
                    "{}",
                    json!({"event":"module-planned","module":module,"ok":false,"message":err})
                )?;
            }
        }
    }
    let mut run = File::create(receipt_dir.join("run.json"))?;
    serde_json::to_writer_pretty(
        &mut run,
        &json!({
            "schema": "harmonia.run.v1",
            "ok": ok,
            "mutation": false,
            "profile_id": profile.id,
            "identity": profile.identity,
            "identity_source": run_identity_source(),
            "module_count": profile.modules.len(),
            "first_missing_signal": first_missing_signal,
        }),
    )?;
    writeln!(run)?;
    Ok(())
}
