use crate::*;
use serde_json::json;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

thread_local! {
    static ACTIVE_RUN_ID: RefCell<Option<String>> = const { RefCell::new(None) };
    static ACTIVE_RECEIPT_DIRECTORY: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

pub(crate) struct RunIdGuard(Option<String>);

impl RunIdGuard {
    pub(crate) fn enter(run_id: &str) -> Self {
        let previous = ACTIVE_RUN_ID.with(|active| active.replace(Some(run_id.to_owned())));
        Self(previous)
    }
}

impl Drop for RunIdGuard {
    fn drop(&mut self) {
        let previous = self.0.take();
        ACTIVE_RUN_ID.with(|active| {
            active.replace(previous);
        });
    }
}

pub(crate) fn write_json(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    crate::atoms::attest::write_json_atomic(path, value)
}

pub(crate) fn run_id_from_stamp() -> String {
    if let Some(run_id) = ACTIVE_RUN_ID.with(|active| active.borrow().clone()) {
        return run_id;
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("run-{nanos}")
}

pub(crate) struct ReceiptScopeGuard(Option<PathBuf>);

impl ReceiptScopeGuard {
    pub(crate) fn enter(path: &Path) -> Self {
        let path = absolute_receipt_path(path);
        Self(ACTIVE_RECEIPT_DIRECTORY.with(|active| active.replace(Some(path))))
    }
}

impl Drop for ReceiptScopeGuard {
    fn drop(&mut self) {
        let previous = self.0.take();
        ACTIVE_RECEIPT_DIRECTORY.with(|active| { active.replace(previous); });
    }
}

fn absolute_receipt_path(path: &Path) -> PathBuf {
    if path.is_absolute() { path.to_path_buf() }
    else { std::env::current_dir().unwrap_or_default().join(path) }
}

/// Only receipt files receive the press identity; appliance settings and other
/// JSON documents using the same atomic writer retain their original shape.
pub(crate) fn receipt_run_id(path: &Path) -> Option<String> {
    let path = absolute_receipt_path(path);
    let in_receipts = path.starts_with("/var/lib/harmonia/receipts")
        || ACTIVE_RECEIPT_DIRECTORY.with(|active| active.borrow().as_ref().is_some_and(|root| path.starts_with(root)));
    if !in_receipts { return None; }
    ACTIVE_RUN_ID.with(|active| active.borrow().clone())
}

pub(crate) fn is_current_run_receipt(receipt: &serde_json::Value) -> bool {
    ACTIVE_RUN_ID.with(|active| active.borrow().as_ref().is_none_or(|run_id| {
        receipt.get("run_id").and_then(serde_json::Value::as_str) == Some(run_id.as_str())
    }))
}

pub(crate) fn receipt_root_for(receipt_dir: &Path) -> PathBuf {
    receipt_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| receipt_dir.to_path_buf())
}

pub(crate) struct ProfileLedgerEntry<'a> {
    pub module_id: &'a str,
    pub ok: bool,
    pub changed: bool,
    pub operation_count: usize,
    pub first_missing_signal: &'a str,
    pub receipt_dir: &'a Path,
    pub module_version: Option<&'a str>,
    pub step: Option<&'a str>,
    pub error: Option<&'a str>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ProfileLedgerWriteReport {
    pub(crate) unparsable_lines: usize,
    pub(crate) read_warnings: Vec<String>,
}

pub(crate) fn write_profile_ledger_run(
    _receipt_dir: &Path, _latest_path: Option<&Path>, profile: &Profile,
    run_id: &str, entries: &[ProfileLedgerEntry<'_>],
) -> Result<ProfileLedgerWriteReport, String> {
    match crate::ledger::record(profile, run_id, entries) {
        Ok(()) => Ok(ProfileLedgerWriteReport::default()),
        Err(error) => {
            let signal = crate::deeds::coded_signal(&error);
            crate::deeds::reporting_failure("profile_ledger", &signal);
            let _ = crate::deeds::record("profile-ledger", crate::ledger::DATABASE, false, false,
                None, Some(run_id), None, Some(&signal), None);
            Ok(ProfileLedgerWriteReport { unparsable_lines: 0, read_warnings: vec![signal] })
        }
    }
}

fn update_run_receipt_projection(
    receipt_dir: &Path,
    field: &str,
    projection: serde_json::Value,
) -> Result<(), String> {
    let path = receipt_dir.join("run.json");
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("run-receipt-projection-observe-failed {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("run-receipt-projection-collision {}", path.display()));
    }
    let bytes = fs::read(&path)
        .map_err(|error| format!("run-receipt-projection-read-failed {}: {error}", path.display()))?;
    let mut receipt = serde_json::from_slice::<serde_json::Value>(&bytes)
        .map_err(|error| format!("run-receipt-projection-parse-failed {}: {error}", path.display()))?;
    if receipt.get("schema").and_then(serde_json::Value::as_str)
        != Some("harmonia.run_profile.v1")
    {
        return Err(format!("run-receipt-projection-schema-mismatch {}", path.display()));
    }
    let object = receipt
        .as_object_mut()
        .ok_or_else(|| format!("run-receipt-projection-not-object {}", path.display()))?;
    object.insert(field.to_owned(), projection);
    crate::deeds::annotate_reporting(&mut receipt);
    write_json(&path, &receipt)
}

pub(crate) fn record_profile_ledger_projection(
    receipt_dir: &Path,
    report: &ProfileLedgerWriteReport,
) -> Result<(), String> {
    update_run_receipt_projection(
        receipt_dir,
        "profile_ledger",
        json!({
            "ok": true,
            "signal": null,
            "unparsable_lines": report.unparsable_lines,
            "read_warnings": report.read_warnings,
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

thread_local! {
    // Single-invocation evidence, consumed by the reply's run projection.
    static CONFIG_WITNESSES: RefCell<BTreeMap<(String,String,String,String),serde_json::Value>> = const { RefCell::new(BTreeMap::new()) };
}

pub(crate) fn clear_config_state_receipts(_receipt_dir: &Path) -> Result<(), String> {
    crate::bands::propose_edits::reset_config_state_recognitions();
    CONFIG_WITNESSES.with(|state|state.borrow_mut().clear());
    Ok(())
}

pub(crate) fn retain_config_witness(witness: &crate::atoms::attest::ConfigPlaneWitness) -> Result<(), String> {
    let value=serde_json::to_value(witness).map_err(|error|error.to_string())?;
    CONFIG_WITNESSES.with(|state| {
        state.borrow_mut().entry((witness.module_id.clone(),witness.path.clone(),value["category"].as_str().unwrap_or_default().to_owned(),value["disposition"].as_str().unwrap_or_default().to_owned()))
            .or_insert(value);
    });
    Ok(())
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
            if !is_current_run_receipt(&value) { return None; }
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

    let typed = CONFIG_WITNESSES.with(|state| std::mem::take(&mut *state.borrow_mut()))
        .into_iter().map(|((module,path,category,disposition),value)|(module,path,category,disposition,value))
        .collect::<Vec<_>>();

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
    module_artifact_debt: Option<&[serde_json::Value]>,
) -> Result<(), String> {
    let mut receipt = json!({
            "schema": "harmonia.run_profile.v1",
            "run_id": run_id_from_stamp(),
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
            "steps": module_steps.map_or_else(|| json!([]), |steps| json!(steps)),
            "module_artifact_debt": module_artifact_debt.unwrap_or(&[]),
        });
    if let Some(engine_debt) = engine_debt {
        receipt["engine_debt"] = engine_debt.clone();
    }
    let degraded = engine_debt.is_some()
        || module_artifact_debt.is_some_and(|debts| !debts.is_empty());
    receipt["overall_ok"] = json!(ok && !degraded);
    if degraded {
        receipt["degraded"] = json!(true);
    }
    receipt["config_surfaces"] = json!(collect_config_surfaces(receipt_dir));
    if let Some(base_id) = crate::bands::stage_profile::profile_extends(module_root)? {
        receipt["extends"] = json!(base_id);
        receipt["base_profile_id"] = json!(base_id);
        receipt["union_module_count"] = json!(profile.modules.len());
    }
    if let Some(excluded_module_ids) = crate::bands::stage_profile::profile_excludes(module_root)? {
        receipt["excluded_module_ids"] = json!(excluded_module_ids);
    }
    crate::deeds::annotate_reporting(&mut receipt);
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
    } else if result.stderr.contains("command-bearer-resolution-failed") {
        "command-bearer-resolution-failed"
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
    step_bearer: &str,
    observation_bearer: Option<&str>,
) -> Result<(), String> {
    write_command_comparison_receipt_inner(
        receipt_dir,
        name,
        observed_state,
        desired_state,
        diff_decision,
        executed,
        changed,
        final_observed_state,
        result,
        Some(step_bearer),
        observation_bearer,
        true,
    )
}

fn write_command_comparison_receipt_inner(
    receipt_dir: &Path,
    name: &str,
    observed_state: &serde_json::Value,
    desired_state: &serde_json::Value,
    diff_decision: &str,
    executed: bool,
    changed: bool,
    final_observed_state: &serde_json::Value,
    result: Option<&CmdResult>,
    step_bearer: Option<&str>,
    observation_bearer: Option<&str>,
    include_result_stdout: bool,
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
    if let Some(bearer) = step_bearer {
        receipt["bearer"] = json!(bearer);
    }
    if let Some(bearer) = observation_bearer {
        receipt["observation_bearer"] = json!(bearer);
    }
    if let Some(result) = result {
        receipt["stdout_bytes"] = json!(result.stdout.len());
        receipt["stderr_bytes"] = json!(result.stderr.len());
        if include_result_stdout {
            receipt["stdout"] = json!(result.stdout);
        }
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
    write_command_receipt_with_policy_inner(
        receipt_dir, name, program, args, cwd, result, advisory, lane, active_lane, executed,
        skipped, None,
    )
}

pub(crate) fn write_command_receipt_with_policy_and_bearer(
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
    bearer: &str,
) -> Result<(), String> {
    write_command_receipt_with_policy_inner(
        receipt_dir, name, program, args, cwd, result, advisory, lane, active_lane, executed,
        skipped, Some(bearer),
    )
}

fn write_command_receipt_with_policy_inner(
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
    bearer: Option<&str>,
) -> Result<(), String> {
    let lane_match = lane.is_none() || lane == active_lane;
    let advisory_triggered = advisory && executed && !result.ok;
    let effective_ok = result.ok || skipped || advisory_triggered;
    let mut receipt = json!({
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
        });
    if let Some(bearer) = bearer {
        receipt["bearer"] = json!(bearer);
    }
    write_json(&receipt_dir.join(format!("{}.json", name)), &receipt)
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

pub(crate) struct EventSink;

pub(crate) fn event(_events: &mut EventSink, _event: &str, _ok: bool, _message: &str) -> Result<(), String> {
    // These are walk/plan/observation summaries. The native run receipt carries
    // failures; actual mutation attempts are recorded by their owning atom or
    // transaction, once, rather than again at every summary layer.
    Ok(())
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
    let mut ok = true;
    let mut first_missing_signal = "none".to_string();

    if profile.modules.is_empty() {
        ok = false;
        first_missing_signal = "profile-modules-empty".to_string();
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
            let selected_profile_index = module_root
                .parent()
                .map(|profile_root| profile_root.join("index.json"))
                .filter(|path| path.is_file());
            let loaded = if let Some(manifest) = projected_manifest {
                Ok(manifest)
            } else {
                crate::tools::ladder::load_ladder_manifest_with_context(
                    &manifest_path,
                    false,
                    selected_profile_index.as_deref(),
                )
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
                crate::tools::routine::project_manifest_routines(&manifest, &steps)?;
                for step in steps {
                    if step.tool == "command" && step.permutation == "act" {
                        crate::tools::routine::command_skip_if_absent(&step.args)?;
                    }
                }
                Ok(())
            })
        } else {
            load_module(&module_dir.join("sidecar.json")).map(|_| ())
        };
        match planned {
            Ok(_) => {}
            Err(_err) => {
                ok = false;
                if first_missing_signal == "none" {
                    first_missing_signal = format!("module-missing-{module}");
                }
            }
        }
    }

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
    if let Some(excluded_module_ids) =
        crate::bands::stage_profile::profile_excludes(module_root).map_err(io::Error::other)?
    {
        run["excluded_module_ids"] = json!(excluded_module_ids);
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
