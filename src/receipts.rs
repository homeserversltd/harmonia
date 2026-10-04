use crate::*;
use serde_json::json;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn write_json(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    crate::atoms::attest::write_json_atomic(path, value)
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
    if !crate::atoms::ask::exists(path) {
        return Ok(1);
    }
    let count = crate::atoms::ask::line_count(path)?;
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
    let sequence = next_ledger_sequence(&path)?;
    let stamped_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    crate::atoms::attest::append_jsonl(
        &path,
        &json!({
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
        }),
    )
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

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ConfigSurfaceReceipt { config_state: String, score: f64, reference_id: String, id: String, target: String }

pub(crate) fn clear_config_state_receipts(receipt_dir: &Path) -> Result<(), String> {
    let entries = match fs::read_dir(receipt_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };

    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("config-state-") || !name.ends_with(".json") {
            continue;
        }
        // `file_type` does not follow symlinks, so only direct regular files
        // matching the exact receipt name are eligible for removal.
        if entry.file_type().map_err(|error| error.to_string())?.is_file() {
            fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
        }
    }
    clear_config_plane_witness_receipts(receipt_dir)?;
    Ok(())
}

const CONFIG_PLANE_WITNESS_MAX_DEPTH: usize = 8;
const CONFIG_PLANE_WITNESS_LOG: &str = "config-plane-witnesses.jsonl";

fn sorted_directory_entries(directory: &Path) -> io::Result<Vec<fs::DirEntry>> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}

fn is_direct_directory(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_dir()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

fn clear_config_plane_witnesses_under(directory: &Path, depth: usize) -> Result<(), String> {
    if !is_direct_directory(directory)? {
        return Ok(());
    }
    let entries = match sorted_directory_entries(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    for entry in entries {
        let path = entry.path();
        if entry.file_name().to_str() == Some(CONFIG_PLANE_WITNESS_LOG) {
            // symlink_metadata and file_type do not follow a log symlink.
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_file() => {
                    fs::remove_file(path).map_err(|error| error.to_string())?;
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
        } else if depth < CONFIG_PLANE_WITNESS_MAX_DEPTH
            && entry
                .file_type()
                .map_err(|error| error.to_string())?
                .is_dir()
        {
            clear_config_plane_witnesses_under(&path, depth + 1)?;
        }
    }
    Ok(())
}

fn clear_config_plane_witness_receipts(receipt_dir: &Path) -> Result<(), String> {
    if !is_direct_directory(receipt_dir)? {
        return Ok(());
    }
    let modules_dir = receipt_dir.join("modules");
    if !is_direct_directory(&modules_dir)? {
        return Ok(());
    }
    for module in sorted_directory_entries(&modules_dir).map_err(|error| error.to_string())? {
        if module
            .file_type()
            .map_err(|error| error.to_string())?
            .is_dir()
        {
            clear_config_plane_witnesses_under(&module.path(), 0)?;
        }
    }
    Ok(())
}

fn collect_config_plane_witnesses_under(
    directory: &Path,
    depth: usize,
    seen: &mut std::collections::BTreeSet<(String, String, String, String)>,
    typed: &mut Vec<(String, String, String, String, serde_json::Value)>,
) {
    if !is_direct_directory(directory).is_ok_and(|is_directory| is_directory) {
        return;
    }
    let witness_log = directory.join(CONFIG_PLANE_WITNESS_LOG);
    if fs::symlink_metadata(&witness_log)
        .is_ok_and(|metadata| metadata.file_type().is_file())
    {
        if let Ok(contents) = fs::read_to_string(witness_log) {
            for line in contents.lines() {
                let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if value.get("schema").and_then(serde_json::Value::as_str)
                    != Some(crate::atoms::attest::CONFIG_PLANE_WITNESS_SCHEMA)
                    || serde_json::from_value::<crate::atoms::attest::ConfigPlaneWitness>(
                        value.clone(),
                    )
                    .is_err()
                {
                    continue;
                }
                let Some(module_id) = value.get("module_id").and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                let Some(path) = value.get("path").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                let Some(category) = value.get("category").and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                let Some(disposition) = value
                    .get("disposition")
                    .and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                let key = (
                    module_id.to_string(),
                    path.to_string(),
                    category.to_string(),
                    disposition.to_string(),
                );
                if seen.insert(key.clone()) {
                    typed.push((key.0, key.1, key.2, key.3, value));
                }
            }
        }
    }

    if depth >= CONFIG_PLANE_WITNESS_MAX_DEPTH {
        return;
    }
    let Ok(entries) = sorted_directory_entries(directory) else {
        return;
    };
    for entry in entries {
        if entry
            .file_type()
            .is_ok_and(|file_type| file_type.is_dir())
        {
            collect_config_plane_witnesses_under(&entry.path(), depth + 1, seen, typed);
        }
    }
}

fn collect_config_surfaces(receipt_dir: &Path) -> Vec<serde_json::Value> {
    let mut legacy = fs::read_dir(receipt_dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            if !name.starts_with("config-state-")
                || !name.ends_with(".json")
                || !entry.file_type().ok()?.is_file()
            {
                return None;
            }
            let value = serde_json::from_str::<serde_json::Value>(
                &fs::read_to_string(entry.path()).ok()?,
            )
            .ok()?;
            if value.get("schema").and_then(serde_json::Value::as_str)
                != Some("harmonia.config_state.v1")
            {
                return None;
            }
            let record = serde_json::from_value::<ConfigSurfaceReceipt>(value.clone()).ok()?;
            // Keep legacy fields and any additive sidecar fields verbatim.
            Some((record.id, record.target, value))
        })
        .collect::<Vec<_>>();
    legacy.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.to_string().cmp(&b.2.to_string()))
    });

    let mut typed = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let modules_dir = receipt_dir.join("modules");
    if is_direct_directory(receipt_dir).is_ok_and(|is_directory| is_directory)
        && is_direct_directory(&modules_dir).is_ok_and(|is_directory| is_directory)
    {
        if let Ok(modules) = sorted_directory_entries(&modules_dir) {
            for module in modules {
                if module
                    .file_type()
                    .is_ok_and(|file_type| file_type.is_dir())
                {
                    collect_config_plane_witnesses_under(
                        &module.path(),
                        0,
                        &mut seen,
                        &mut typed,
                    );
                }
            }
        }
    }
    typed.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.cmp(&b.2))
            .then_with(|| a.3.cmp(&b.3))
    });

    let typed_targets = typed
        .iter()
        .map(|(_, path, _, _, _)| path.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let mut sidecars_by_target =
        std::collections::BTreeMap::<String, Vec<serde_json::Value>>::new();
    let mut standalone_legacy = Vec::new();
    for (_, target, value) in legacy {
        if typed_targets.contains(&target) {
            sidecars_by_target.entry(target).or_default().push(value);
        } else {
            standalone_legacy.push(value);
        }
    }

    let mut attached_targets = std::collections::BTreeSet::new();
    let typed_records = typed.into_iter().map(|(_, path, _, _, mut value)| {
        if attached_targets.insert(path.clone()) {
            if let Some(sidecars) = sidecars_by_target.remove(&path) {
                if let Some(object) = value.as_object_mut() {
                    object.insert(
                        "legacy_config_state_evidence".to_string(),
                        serde_json::Value::Array(sidecars),
                    );
                }
            }
        }
        value
    });

    standalone_legacy.into_iter().chain(typed_records).collect()
}

pub(crate) fn write_engine_run_receipt_with_duration(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
    ok: bool,
    changed: bool,
    module_count: usize,
    operation_count: usize,
    first_missing_signal: &str,
    module_root: &Path,
    suite_ok: bool,
    run_duration_ms: u128,
) -> Result<(), String> {
    write_engine_run_receipt_with_duration_and_steps(
        receipt_dir,
        profile,
        apply,
        ok,
        changed,
        module_count,
        operation_count,
        first_missing_signal,
        module_root,
        suite_ok,
        run_duration_ms,
        None,
    )
}

pub(crate) fn write_engine_run_receipt_with_duration_and_steps(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
    ok: bool,
    changed: bool,
    module_count: usize,
    operation_count: usize,
    first_missing_signal: &str,
    module_root: &Path,
    suite_ok: bool,
    run_duration_ms: u128,
    module_steps: Option<&[serde_json::Value]>,
) -> Result<(), String> {
    write_engine_run_receipt_with_duration_and_steps_and_debt(
        receipt_dir,
        profile,
        apply,
        ok,
        changed,
        module_count,
        operation_count,
        first_missing_signal,
        module_root,
        suite_ok,
        run_duration_ms,
        module_steps,
        None,
    )
}

pub(crate) fn write_engine_run_receipt_with_duration_and_steps_and_debt(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
    ok: bool,
    changed: bool,
    module_count: usize,
    operation_count: usize,
    first_missing_signal: &str,
    module_root: &Path,
    suite_ok: bool,
    run_duration_ms: u128,
    module_steps: Option<&[serde_json::Value]>,
    engine_debt: Option<&serde_json::Value>,
) -> Result<(), String> {
    let mut receipt = json!({
            "schema": "harmonia.run_profile.v1",
            "ok": ok,
            "changed": changed,
            "mutation": apply,
            "mode": if apply { "apply" } else { "report-only" },
            "profile_id": profile.id,
            "identity": profile.identity,
            "identity_source": run_identity_source(),
            "module_count": module_count,
            "operation_count": operation_count,
            "config_proposal_count": crate::pending_config_proposal_count(),
            "run_duration_ms": run_duration_ms,
            "first_missing_signal": first_missing_signal,
            "module_spine_entered": module_root,
            "selected_profile": profile.id,
            "suite_ok": suite_ok,
            // Additive closing surface: older readers may ignore this field.
            "steps": module_steps.map_or_else(|| serde_json::Value::Null, |steps| json!(steps)),
        });
    if let Some(engine_debt) = engine_debt {
        receipt["engine_debt"] = engine_debt.clone();
        receipt["degraded"] = json!(true);
        receipt["overall_ok"] = json!(false);
    }
    receipt["config_surfaces"] = json!(collect_config_surfaces(receipt_dir));
    if let Some(base_id) = crate::bands::stage_profile::profile_extends(module_root)? {
        receipt["extends"] = json!(base_id);
        receipt["base_profile_id"] = json!(base_id);
        receipt["union_module_count"] = json!(profile.modules.len());
    }
    write_json(&receipt_dir.join("run.json"), &receipt)
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
    } else if result.stderr.contains("act-did-not-converge") {
        "act-did-not-converge"
    } else if result.stderr.contains("command-timeout-after-") {
        "command-timeout"
    } else if result.stderr.contains("command-spawn-failed") {
        "command-spawn-failed"
    } else if result.stderr.contains("command-wait-failed") {
        "command-wait-failed"
    } else if result.stderr.contains("command-act-observation-failed") {
        "command-act-observation-failed"
    } else if result.stderr.to_ascii_lowercase().contains("birth-debt") || result.stderr.to_ascii_lowercase().contains("birth debt") {
        "birth-debt"
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
    write_command_receipt_with_policy(
        receipt_dir,
        name,
        program,
        args,
        cwd,
        result,
        false,
        None,
        None,
        true,
        false,
    )
}

pub(crate) fn write_command_comparison_receipt(
    receipt_dir: &Path,
    name: &str,
    observed_state: &serde_json::Value,
    desired_state: &serde_json::Value,
    diff_decision: &str,
    executed: bool,
    changed: bool,
    final_observed_state: &serde_json::Value,
    result: Option<&CmdResult>,
) -> Result<(), String> {
    let mut receipt = json!({
        "schema":"harmonia.command_receipt.v1", "name":name,
        "observed_state":observed_state, "desired_state":desired_state,
        "diff_decision":diff_decision, "movement":if executed { "attempted" } else { "none" },
        "changed":changed, "comparison_changed":diff_decision == "Different", "movement_attempted":executed,
        "proof":if diff_decision == "Blocked" { "blocked" } else if executed && result.is_some_and(|r| r.ok) { "command-completed" } else if executed && result.is_some_and(|r| r.stderr.contains("act-did-not-converge")) { "act-did-not-converge" } else if executed { "command-failed" } else if diff_decision == "Different" { "report-only" } else if diff_decision == "Empty" { "current" } else { "not-applicable" },
        "final_observed_state":final_observed_state,
        "blocker":if diff_decision == "Blocked" { result.map(command_first_missing_signal).unwrap_or("command-act-observation-failed") } else if executed && result.is_some_and(|r| !r.ok) { command_first_missing_signal(result.expect("checked result")) } else { "none" },
        "ok":result.is_none_or(|r| r.ok),
    });
    if let Some(result) = result {
        receipt["stdout_bytes"] = json!(result.stdout.len());
        receipt["stderr_bytes"] = json!(result.stderr.len());
        if diff_decision != "Empty" || executed { receipt["exit_code"] = json!(result.code); }
    }
    write_json(&receipt_dir.join(format!("{}.json", name)), &receipt)
}

pub(crate) fn write_command_receipt_with_policy(
    receipt_dir: &Path,
    name: &str,
    program: &str,
    args: &[String],
    cwd: Option<&str>,
    result: &CmdResult,
    advisory: bool,
    lane: Option<&str>,
    active_lane: Option<&str>,
    executed: bool,
    skipped: bool,
) -> Result<(), String> {
    let lane_match = lane.is_none() || lane == active_lane;
    let advisory_triggered = advisory && executed && !result.ok;
    let effective_ok = result.ok || skipped || advisory_triggered;
    write_json(
        &receipt_dir.join(format!("{}.json", name)),
        &json!({
            "schema": "harmonia.command_receipt.v1",
            "name": name,
            "program": program,
            "args": args,
            "cwd": cwd,
            "ok": effective_ok,
            "exit_code": result.code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "advisory": advisory,
            "advisory_triggered": advisory_triggered,
            "advisory_signal": if advisory_triggered { command_first_missing_signal(result) } else { "none" },
            "lane": lane,
            "requested_lane": lane,
            "active_lane": active_lane,
            "lane_match": lane_match,
            "executed": executed,
            "skipped": skipped,
            "first_missing_signal": if effective_ok { "none" } else { command_first_missing_signal(result) },
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
    crate::atoms::attest::append_jsonl_to(
        events,
        &json!({"event": event, "ok": ok, "message": message}),
    )
}

pub(crate) fn write_plan_receipts(
    profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
) -> io::Result<()> {
    let extension = crate::bands::stage_profile::profile_extends(module_root)
        .map_err(io::Error::other)?;
    let projection = if extension.is_some() {
        Some(
            crate::bands::stage_profile::load_profile_projection(
                profile,
                module_root,
                &std::collections::BTreeSet::new(),
            )
            .map_err(io::Error::other)?,
        )
    } else {
        None
    };
    let mut events = Vec::new();
    let mut ok = true;
    let mut first_missing_signal = "none".to_string();
    crate::atoms::attest::append_jsonl_to(
        &mut events,
        &json!({"event":"plan-start","profile":profile.id,"ok":true}),
    )
    .map_err(io::Error::other)?;
    if profile.modules.is_empty() {
        ok = false;
        first_missing_signal = "profile-modules-empty".to_string();
        crate::atoms::attest::append_jsonl_to(
            &mut events,
            &json!({"event":"profile-modules","ok":false,"message":"profile module spine is empty"}),
        ).map_err(io::Error::other)?;
    }
    for module in &profile.modules {
        let module_dir = crate::bands::stage_profile::resolve_module_dir(module_root, module)
            .map_err(io::Error::other)?;
        let manifest_path = module_dir.join("manifest.json");
        let planned = if crate::atoms::ask::exists(&manifest_path)
            && is_ladder_manifest(&manifest_path)
        {
            let projected_manifest = projection
                .as_ref()
                .and_then(|projection| projection.modules.get(module))
                .and_then(|projected| match &projected.loaded {
                    crate::bands::stage_profile::LoadedModule::Ladder(manifest) => {
                        Some(manifest.clone())
                    }
                    crate::bands::stage_profile::LoadedModule::Sidecar(_) => None,
                });
            let loaded = if let Some(manifest) = projected_manifest {
                Ok(manifest)
            } else {
                load_ladder_manifest(&manifest_path)
            };
            loaded.and_then(|manifest| {
                if manifest.id != *module {
                    return Err(format!(
                        "module-id-mismatch expected={module} got={}",
                        manifest.id
                    ));
                }
                // Projection replaces package pins on every module after its
                // initial validation. Revalidate that effective declaration for
                // plan-run instead of reusing the pre-projection step cache.
                let steps = validate_ladder(&manifest).map_err(|err| err.first_missing_signal())?;
                for step in steps {
                    let mut planned = json!({
                        "event":"step-planned", "module":module,
                        "step_id":step.step_id, "tool":step.tool,
                        "permutation":step.permutation, "args":step.args,
                        "ok":true, "mutation":false
                    });
                    if extension.is_some() && step.tool == "package" {
                        let pins = serde_json::to_value(&manifest.package_pins)
                            .map_err(|error| error.to_string())?;
                        let exclusion_set: Vec<&String> = manifest.package_pins.keys().collect();
                        planned["package_pins"] = pins;
                        planned["exclusion_set"] = json!(exclusion_set);
                    }
                    crate::atoms::attest::append_jsonl_to(&mut events, &planned)
                        .map_err(|error| error.to_string())?;
                }
                Ok(())
            })
        } else {
            load_module(&module_dir.join("sidecar.json")).map(|_| ())
        };
        match planned {
            Ok(_) => {
                crate::atoms::attest::append_jsonl_to(
                    &mut events,
                    &json!({"event":"module-planned","module":module,"ok":true}),
                )
                .map_err(io::Error::other)?;
            }
            Err(err) => {
                ok = false;
                if first_missing_signal == "none" {
                    first_missing_signal = format!("module-missing-{module}");
                }
                crate::atoms::attest::append_jsonl_to(
                    &mut events,
                    &json!({"event":"module-planned","module":module,"ok":false,"message":err}),
                )
                .map_err(io::Error::other)?;
            }
        }
    }
    crate::atoms::attest::write_receipt_bytes_atomic(&receipt_dir.join("events.jsonl"), &events)
        .map_err(io::Error::other)?;
    let mut run = json!({
            "schema": "harmonia.run.v1",
            "ok": ok,
            "mutation": false,
            "profile_id": profile.id,
            "identity": profile.identity,
            "identity_source": run_identity_source(),
            "module_count": profile.modules.len(),
            "first_missing_signal": first_missing_signal,
        });
    if let Some(base_id) = crate::bands::stage_profile::profile_extends(module_root).map_err(io::Error::other)? {
        run["extends"] = json!(base_id);
        run["base_profile_id"] = json!(base_id);
        run["union_module_count"] = json!(profile.modules.len());
    }
    crate::atoms::attest::write_json_atomic(&receipt_dir.join("run.json"), &run)
        .map_err(io::Error::other)?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::{clear_config_state_receipts, collect_config_surfaces};
    use std::fs;
    use tempfile::tempdir;
    fn record(schema: &str, state: &str, id: &str, target: &str, score: f64, reference_id: &str) -> String {
        serde_json::json!({"schema":schema,"config_state":state,"id":id,"target":target,"score":score,"reference_id":reference_id}).to_string()
    }
    #[test]
    fn config_surfaces_include_recognized_and_refused_in_id_target_order() {
        let d=tempdir().unwrap();
        fs::write(d.path().join("config-state-z.json"),record("harmonia.config_state.v1","refused-unrecognized","z","/z",0.12,"ref-z")).unwrap();
        fs::write(d.path().join("config-state-a-z.json"),record("harmonia.config_state.v1","interactable","a","/z",1.0,"ref-a-z")).unwrap();
        fs::write(d.path().join("config-state-a-a.json"),record("harmonia.config_state.v1","interactable","a","/a",0.9,"ref-a-a")).unwrap();
        let got=collect_config_surfaces(d.path());
        assert_eq!(got.iter().map(|v|v["id"].as_str().unwrap()).collect::<Vec<_>>(),["a","a","z"]);
        assert_eq!(got.iter().map(|v|v["target"].as_str().unwrap()).collect::<Vec<_>>(),["/a","/z","/z"]);
        assert_eq!(got[2]["config_state"],"refused-unrecognized"); assert_eq!(got[2]["score"],0.12); assert_eq!(got[2]["reference_id"],"ref-z");
    }
    #[test]
    fn config_surfaces_ignore_malformed_unrelated_nested_and_nonregular_files() {
        let d=tempdir().unwrap();
        fs::write(d.path().join("config-state-bad.json"),"not-json").unwrap();
        fs::write(d.path().join("config-state-wrong.json"),record("other.v1","interactable","wrong","/wrong",1.0,"wrong")).unwrap();
        fs::write(d.path().join("notes.json"),record("harmonia.config_state.v1","interactable","unrelated","/unrelated",1.0,"unrelated")).unwrap();
        let nested=d.path().join("nested"); fs::create_dir(&nested).unwrap();
        fs::write(nested.join("config-state-nested.json"),record("harmonia.config_state.v1","interactable","nested","/nested",1.0,"nested")).unwrap();
        fs::create_dir(d.path().join("config-state-directory.json")).unwrap();
        assert!(collect_config_surfaces(d.path()).is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn clear_config_state_receipts_removes_only_direct_regular_matches() {
        use std::os::unix::fs::symlink;

        let d = tempdir().unwrap();
        let stale = d.path().join("config-state-stale.json");
        let unrelated = d.path().join("config-state-stale.txt");
        let nested = d.path().join("nested");
        let directory = d.path().join("config-state-directory.json");
        let symlink_path = d.path().join("config-state-link.json");
        fs::write(&stale, "stale").unwrap();
        fs::write(&unrelated, "keep").unwrap();
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("config-state-nested.json"), "keep").unwrap();
        fs::create_dir(&directory).unwrap();
        symlink(&unrelated, &symlink_path).unwrap();

        clear_config_state_receipts(d.path()).unwrap();

        assert!(!stale.exists());
        assert!(unrelated.exists());
        assert!(nested.join("config-state-nested.json").exists());
        assert!(directory.exists());
        assert!(symlink_path.symlink_metadata().is_ok());
    }

    #[test]
    fn clear_config_state_receipts_succeeds_when_directory_is_absent() {
        let d = tempdir().unwrap();
        assert!(clear_config_state_receipts(&d.path().join("missing")).is_ok());
    }
}
