use serde_json::Value;
use std::path::Path;

const EXHAUSTION_SCHEMA: &str = "harmonia.module_artifact_exhaustion.v1";

pub(crate) fn read_exhaustion_receipt(directory: &Path) -> Result<Value, String> {
    let path = directory.join("module-artifact-exhaustion.json");
    let bytes = std::fs::read(&path).map_err(|error| {
        format!(
            "module-artifact-exhaustion-receipt-read-failed path={} error={error}",
            path.display()
        )
    })?;
    let mut receipt: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("module-artifact-exhaustion-receipt-invalid: {error}"))?;
    validate_exhaustion_receipt(&receipt)?;
    if let Some(object) = receipt.as_object_mut() {
        object.insert(
            "receipt_path".into(),
            Value::String(path.display().to_string()),
        );
    }
    Ok(receipt)
}

pub(crate) fn collect_exhaustion_receipts(receipt_dir: &Path) -> Result<Vec<Value>, String> {
    let root = receipt_dir.join("modules");
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut pending = vec![root];
    let mut receipts = Vec::new();
    while let Some(directory) = pending.pop() {
        let mut entries = std::fs::read_dir(&directory)
            .map_err(|error| {
                format!(
                    "module-artifact-exhaustion-tree-read-failed path={} error={error}",
                    directory.display()
                )
            })?
            .map(|entry| {
                entry.map_err(|error| {
                    format!("module-artifact-exhaustion-tree-entry-failed: {error}")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries.into_iter().rev() {
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
                format!(
                    "module-artifact-exhaustion-tree-stat-failed path={} error={error}",
                    path.display()
                )
            })?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                pending.push(path);
                continue;
            }
            if metadata.is_file()
                && path.file_name().and_then(|name| name.to_str())
                    == Some("module-artifact-exhaustion.json")
            {
                let parent = path.parent().ok_or_else(|| {
                    format!(
                        "module-artifact-exhaustion-receipt-parent-missing path={}",
                        path.display()
                    )
                })?;
                receipts.push(read_exhaustion_receipt(parent)?);
            }
        }
    }
    receipts.sort_by(|left, right| {
        left.get("receipt_path")
            .and_then(Value::as_str)
            .cmp(&right.get("receipt_path").and_then(Value::as_str))
    });
    Ok(receipts)
}

fn validate_exhaustion_receipt(receipt: &Value) -> Result<(), String> {
    match receipt.get("schema").and_then(Value::as_str) {
        Some(EXHAUSTION_SCHEMA)
            if receipt.get("tool").and_then(Value::as_str) == Some("release-binary") =>
        {
            validate_release_binary_exhaustion(receipt)
        }
        Some(EXHAUSTION_SCHEMA) => validate_fetch_artifact_exhaustion(receipt),
        _ => Err("module-artifact-exhaustion-receipt-invalid: schema".into()),
    }
}

fn validate_fetch_artifact_exhaustion(receipt: &Value) -> Result<(), String> {
    let invalid = |reason: &str| format!("module-artifact-exhaustion-receipt-invalid: {reason}");
    if receipt.get("ok").and_then(Value::as_bool) != Some(false)
        || receipt.get("changed").and_then(Value::as_bool) != Some(false)
        || receipt
            .get("installed_artifact_preserved")
            .and_then(Value::as_bool)
            != Some(true)
        || !nonempty_string(receipt.get("module_id"))
        || !nonempty_string(receipt.get("component"))
        || !nonempty_string(receipt.get("routine_id"))
        || !nonempty_string(receipt.get("step_id"))
        || !receipt
            .get("first_missing_signal")
            .and_then(Value::as_str)
            .is_some_and(|signal| signal.starts_with("module-artifact-candidates-exhausted"))
    {
        return Err(invalid("kernel-or-module-identity"));
    }
    let candidates = receipt
        .get("candidates")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("candidate-list-missing"))?;
    let count = receipt
        .get("candidate_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("candidate-count-missing"))? as usize;
    if count == 0 || count != candidates.len() {
        return Err(invalid("candidate-count-mismatch"));
    }
    for (index, candidate) in candidates.iter().enumerate() {
        let final_state = candidate.get("final-state");
        let attempt = candidate.get("attempt");
        let requested_assets = candidate
            .get("requested_assets")
            .and_then(Value::as_array);
        if candidate.get("candidate_index").and_then(Value::as_u64)
            != Some((index + 1) as u64)
            || !nonempty_string(candidate.get("candidate_name"))
            || !requested_assets.is_some_and(|assets| {
                !assets.is_empty()
                    && assets.iter().all(|asset| {
                        nonempty_string(asset.get("asset_name"))
                            && nonempty_string(asset.get("sidecar_name"))
                    })
            })
            || candidate.get("observed").and_then(|value| value.get("configured"))
                .and_then(Value::as_bool)
                != Some(true)
            || candidate.get("could-change").and_then(Value::as_bool) != Some(false)
            || attempt.and_then(|value| value.get("operation")).and_then(Value::as_str)
                != Some("inspect-and-validate-module-release")
            || attempt.and_then(|value| value.get("state")).and_then(Value::as_str)
                != Some("candidate-refused")
            || final_state
                .and_then(|value| value.get("disposition"))
                .and_then(Value::as_str)
                != Some("refused")
            || final_state
                .and_then(|value| value.get("selected"))
                .and_then(Value::as_bool)
                != Some(false)
            || !nonempty_string(final_state.and_then(|value| value.get("blocker")))
            || !nonempty_string(candidate.get("candidate_locator"))
        {
            return Err(invalid("candidate-refusal-not-proven"));
        }
    }
    let witness = receipt
        .get("standing_artifact")
        .ok_or_else(|| invalid("standing-artifact-witness-missing"))?;
    let size = witness.get("size").and_then(Value::as_u64).unwrap_or(0);
    let mode = witness.get("mode").and_then(Value::as_u64).unwrap_or(0);
    let digest = witness.get("sha256").and_then(Value::as_str).unwrap_or("");
    if witness.get("observed").and_then(Value::as_bool) != Some(true)
        || witness.get("regular").and_then(Value::as_bool) != Some(true)
        || witness.get("executable").and_then(Value::as_bool) != Some(true)
        || witness.get("readable").and_then(Value::as_bool) != Some(true)
        || witness.get("nonempty").and_then(Value::as_bool) != Some(true)
        || witness.get("unchanged").and_then(Value::as_bool) != Some(true)
        || !nonempty_string(witness.get("path"))
        || size == 0
        || mode & 0o111 == 0
        || !is_sha256(digest)
    {
        return Err(invalid("standing-artifact-witness-incomplete"));
    }
    Ok(())
}

fn validate_release_binary_exhaustion(receipt: &Value) -> Result<(), String> {
    let invalid = |reason: &str| format!("module-artifact-exhaustion-receipt-invalid: {reason}");
    if receipt.get("ok").and_then(Value::as_bool) != Some(false)
        || receipt.get("changed").and_then(Value::as_bool) != Some(false)
        || !nonempty_string(receipt.get("module_id"))
        || !nonempty_string(receipt.get("component"))
        || !receipt.get("routine_id").is_some_and(|routine_id| {
            routine_id.is_null() || nonempty_string(Some(routine_id))
        })
        || !nonempty_string(receipt.get("step_id"))
        || receipt.get("could-change").and_then(Value::as_bool) != Some(false)
        || !receipt
            .get("first_missing_signal")
            .and_then(Value::as_str)
            .is_some_and(|signal| signal.starts_with("module-artifact-candidates-exhausted"))
    {
        return Err(invalid("release-binary-identity-or-signal"));
    }
    let candidates = receipt
        .get("candidates")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("candidate-list-missing"))?;
    let count = receipt
        .get("candidate_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("candidate-count-missing"))? as usize;
    if count == 0 || count != candidates.len() {
        return Err(invalid("candidate-count-mismatch"));
    }
    for (index, candidate) in candidates.iter().enumerate() {
        let attempt = candidate.get("attempt");
        let final_state = candidate.get("final-state");
        if candidate.get("candidate_index").and_then(Value::as_u64)
            != Some((index + 1) as u64)
            || !nonempty_string(candidate.get("candidate_locator"))
            || candidate.get("observed").and_then(|value| value.get("configured"))
                .and_then(Value::as_bool)
                != Some(true)
            || candidate.get("could-change").and_then(Value::as_bool) != Some(false)
            || attempt.and_then(|value| value.get("operation")).and_then(Value::as_str)
                != Some("inspect-flag-and-digest-verified-binary")
            || !matches!(
                attempt.and_then(|value| value.get("state")).and_then(Value::as_str),
                Some("candidate-refused" | "completed")
            )
            || !matches!(
                final_state.and_then(|value| value.get("disposition"))
                    .and_then(Value::as_str),
                Some("refused" | "unavailable")
            )
            || final_state.and_then(|value| value.get("selected"))
                .and_then(Value::as_bool)
                != Some(false)
            || !nonempty_string(final_state.and_then(|value| value.get("blocker")))
            || !matches!(
                (
                    attempt.and_then(|value| value.get("state")).and_then(Value::as_str),
                    final_state
                        .and_then(|value| value.get("disposition"))
                        .and_then(Value::as_str)
                ),
                (Some("candidate-refused"), Some("refused"))
                    | (Some("completed"), Some("unavailable"))
            )
        {
            return Err(invalid("release-binary-candidate-outcome-not-proven"));
        }
    }
    let witness = receipt
        .get("standing_artifact")
        .ok_or_else(|| invalid("standing-artifact-witness-missing"))?;
    if witness.get("observed").and_then(Value::as_bool) != Some(true)
        || witness.get("unchanged").and_then(Value::as_bool) != Some(true)
        || !nonempty_string(witness.get("path"))
    {
        return Err(invalid("standing-artifact-observation-incomplete"));
    }
    match witness.get("state").and_then(Value::as_str) {
        Some("present") => {
            if receipt.get("installed_artifact_state").and_then(Value::as_str) != Some("present")
                || receipt.get("installed_artifact_preserved").and_then(Value::as_bool) != Some(true)
                || witness.get("regular").and_then(Value::as_bool) != Some(true)
                || witness.get("readable").and_then(Value::as_bool) != Some(true)
                || !is_sha256(witness.get("sha256").and_then(Value::as_str).unwrap_or(""))
                || witness.get("mode").and_then(Value::as_u64).is_none()
                || witness.get("uid").and_then(Value::as_u64).is_none()
                || witness.get("gid").and_then(Value::as_u64).is_none()
            {
                return Err(invalid("standing-artifact-present-observation-incomplete"));
            }
        }
        Some("absent") => {
            if receipt.get("installed_artifact_state").and_then(Value::as_str) != Some("absent")
                || receipt.get("installed_artifact_preserved").and_then(Value::as_bool) != Some(false)
                || witness.get("regular").and_then(Value::as_bool) != Some(false)
                || witness.get("readable").and_then(Value::as_bool) != Some(false)
                || !witness.get("sha256").is_some_and(Value::is_null)
                || !witness.get("mode").is_some_and(Value::is_null)
                || !witness.get("uid").is_some_and(Value::is_null)
                || !witness.get("gid").is_some_and(Value::is_null)
            {
                return Err(invalid("standing-artifact-absence-not-proven"));
            }
        }
        _ => return Err(invalid("standing-artifact-state-unknown")),
    }
    Ok(())
}

fn nonempty_string(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|text| !text.trim().is_empty())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
