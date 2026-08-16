use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const SUBSCRIPTION_SCHEMA: &str = "harmonia.subscription.v1";
const DEFAULT_SUBSCRIPTION_PATH: &str = "/var/lib/harmonia/subscription.json";
const DECLARED_SUBSCRIPTION_MODE: u32 = 0o644;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SubscriptionModuleReceived {
    pub version: String,
    pub tree_sha256: String,
    pub received_at_run_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SubscriptionRecord {
    pub schema: String,
    pub lane: String,
    pub source: String,
    #[serde(rename = "ref")]
    pub ref_name: String,
    pub selected_profile: String,
    pub engine_version_received: String,
    #[serde(default)]
    pub modules: BTreeMap<String, SubscriptionModuleReceived>,
    pub updated_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SubscriptionModuleUpdate {
    pub id: String,
    pub version: String,
    pub tree_sha256: String,
    pub received_at_run_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SubscriptionUpdate {
    pub lane: String,
    pub source: String,
    pub ref_name: String,
    pub selected_profile: String,
    pub engine_version_received: String,
    pub modules: Vec<SubscriptionModuleUpdate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SubscriptionModuleStatus {
    pub id: String,
    pub status: String,
    pub record_version: Option<String>,
    pub capsule_version: String,
    pub record_tree_sha256: Option<String>,
    pub capsule_tree_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct SubscriptionShowReceipt {
    schema: &'static str,
    ok: bool,
    path: String,
    record: Option<Value>,
    first_missing_signal: String,
}

pub(crate) fn subscription_path() -> PathBuf {
    std::env::var_os("HARMONIA_SUBSCRIPTION_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SUBSCRIPTION_PATH))
}

pub(crate) fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

pub(crate) fn read_subscription_record(path: &Path) -> Result<Option<SubscriptionRecord>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path)
        .map_err(|e| format!("subscription-read-failed {}: {e}", path.display()))?;
    let record: SubscriptionRecord = serde_json::from_str(&text)
        .map_err(|e| format!("subscription-parse-failed {}: {e}", path.display()))?;
    if record.schema != SUBSCRIPTION_SCHEMA {
        return Err(format!("subscription-schema-unsupported {}", record.schema));
    }
    Ok(Some(record))
}

pub(crate) fn diff_subscription_modules(
    path: &Path,
    modules: &[SubscriptionModuleUpdate],
) -> Result<Vec<SubscriptionModuleStatus>, String> {
    let record = read_subscription_record(path)?;
    let mut statuses = Vec::new();
    for module in modules {
        let existing = record
            .as_ref()
            .and_then(|record| record.modules.get(&module.id));
        let status = match existing {
            None => "new",
            Some(existing) if existing.tree_sha256 == module.tree_sha256 => "current",
            Some(_) => "stale",
        };
        statuses.push(SubscriptionModuleStatus {
            id: module.id.clone(),
            status: status.to_string(),
            record_version: existing.map(|m| m.version.clone()),
            capsule_version: module.version.clone(),
            record_tree_sha256: existing.map(|m| m.tree_sha256.clone()),
            capsule_tree_sha256: module.tree_sha256.clone(),
        });
    }
    Ok(statuses)
}

#[cfg(test)]
pub(crate) fn update_subscription_record(
    path: &Path,
    update: SubscriptionUpdate,
) -> Result<SubscriptionRecord, String> {
    update_subscription_record_with_invocation(path, update, crate::atoms::r#do::InvocationKey::for_apply())
}

pub(crate) fn update_subscription_record_with_invocation(
    path: &Path,
    update: SubscriptionUpdate,
    key: crate::atoms::r#do::InvocationKey,
) -> Result<SubscriptionRecord, String> {
    let existing_value = if path.exists() {
        let text = fs::read_to_string(path)
            .map_err(|e| format!("subscription-read-failed {}: {e}", path.display()))?;
        serde_json::from_str::<Value>(&text)
            .map_err(|e| format!("subscription-parse-failed {}: {e}", path.display()))?
    } else {
        Value::Object(Map::new())
    };
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.is_dir() || meta.file_type().is_symlink() {
            return Err(format!(
                "subscription-output-kind-collision {}",
                path.display()
            ));
        }
    }
    let mut object = existing_value.as_object().cloned().unwrap_or_default();
    let mut modules_object = object
        .get("modules")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for module in update.modules {
        let unchanged = modules_object
            .get(&module.id)
            .and_then(Value::as_object)
            .map(|old| {
                old.get("version").and_then(Value::as_str) == Some(module.version.as_str())
                    && old.get("tree_sha256").and_then(Value::as_str)
                        == Some(module.tree_sha256.as_str())
            })
            .unwrap_or(false);
        if !unchanged {
            modules_object.insert(
                module.id,
                json!({
                    "version": module.version,
                    "tree_sha256": module.tree_sha256,
                    "received_at_run_id": module.received_at_run_id,
                }),
            );
        }
    }
    object.insert("schema".to_string(), json!(SUBSCRIPTION_SCHEMA));
    object.insert("lane".to_string(), json!(update.lane));
    object.insert("source".to_string(), json!(update.source));
    object.insert("ref".to_string(), json!(update.ref_name));
    object.insert(
        "selected_profile".to_string(),
        json!(update.selected_profile),
    );
    object.insert(
        "engine_version_received".to_string(),
        json!(update.engine_version_received),
    );
    object.insert("modules".to_string(), Value::Object(modules_object));
    let mut current_without_time = object.clone();
    current_without_time.remove("updated_at_unix_ms");
    let existing_without_time = existing_value.as_object().map(|old| {
        let mut old = old.clone();
        old.remove("updated_at_unix_ms");
        old
    });
    if existing_without_time.as_ref() == Some(&current_without_time) {
        return read_subscription_record(path)?
            .ok_or_else(|| "subscription-write-missing-after-promote".to_string());
    }
    object.insert("updated_at_unix_ms".to_string(), json!(now_unix_ms()));
    let value = Value::Object(object);
    let bytes = serde_json::to_vec_pretty(&value)
        .map_err(|e| e.to_string())
        .map(|mut b| {
            b.push(b'\n');
            b
        })?;
    let parent = path
        .parent()
        .ok_or_else(|| "subscription-parent-missing".to_string())?;
    ensure_subscription_parent(key, parent)?;
    let parent_meta = fs::symlink_metadata(parent).map_err(|e| {
        format!(
            "subscription-parent-authority-missing {}: {e}",
            parent.display()
        )
    })?;
    let target_tail = fs::symlink_metadata(path)
        .ok()
        .map(|meta| (meta.mode() & 0o7777, meta.uid(), meta.gid()))
        .unwrap_or((
            DECLARED_SUBSCRIPTION_MODE,
            parent_meta.uid(),
            parent_meta.gid(),
        ));
    crate::tools::comparison::execute(
        "subscription-promote",
        || Ok(fs::read(path).ok().as_deref() == Some(bytes.as_slice())),
        |same| {
            if *same {
                crate::tools::comparison::DiffDecision::Empty
            } else {
                crate::tools::comparison::DiffDecision::Different
            }
        },
        |authorization, _| {
            crate::atoms::r#do::write_file::file_write(
                authorization,
                key,
                path,
                &bytes,
                crate::atoms::r#do::write_file::FileWriteOptions {
                    write_bytes: true,
                    mode: Some(target_tail.0),
                    uid: Some(target_tail.1),
                    gid: Some(target_tail.2),
                    backup_to: None,
                },
            )
            .map(|_| ())
        },
    )?;
    let post_meta = fs::symlink_metadata(path).map_err(|e| {
        format!(
            "subscription-postimage-metadata-missing {}: {e}",
            path.display()
        )
    })?;
    if (post_meta.mode() & 0o7777, post_meta.uid(), post_meta.gid()) != target_tail {
        return Err(format!(
            "subscription-postimage-metadata-mismatch {}",
            path.display()
        ));
    }
    if fs::read(path).ok().as_deref() != Some(bytes.as_slice()) {
        return Err(format!(
            "subscription-postimage-mismatch {}",
            path.display()
        ));
    }
    read_subscription_record(path)?
        .ok_or_else(|| "subscription-write-missing-after-promote".to_string())
}

pub(crate) fn subscription_show(path: &Path) -> Result<(), String> {
    let record_value = if path.exists() {
        let text = fs::read_to_string(path)
            .map_err(|e| format!("subscription-read-failed {}: {e}", path.display()))?;
        Some(
            serde_json::from_str::<Value>(&text)
                .map_err(|e| format!("subscription-parse-failed {}: {e}", path.display()))?,
        )
    } else {
        None
    };
    let receipt = SubscriptionShowReceipt {
        schema: SUBSCRIPTION_SCHEMA,
        ok: record_value.is_some(),
        path: path.display().to_string(),
        record: record_value,
        first_missing_signal: if path.exists() {
            "none".to_string()
        } else {
            "subscription-record-absent".to_string()
        },
    };
    let text = serde_json::to_string_pretty(&receipt).map_err(|e| e.to_string())?;
    println!("{text}");
    if receipt.ok {
        Ok(())
    } else {
        Err("subscription-record-absent".to_string())
    }
}

pub(crate) fn update_engine_plane(
    path: &Path,
    engine_version: &str,
    engine_lane: &str,
    lock_sha256: Option<&str>,
    key: crate::atoms::r#do::InvocationKey,
) -> Result<(), String> {
    let existing_value = if path.exists() {
        let text = fs::read_to_string(path)
            .map_err(|e| format!("subscription-read-failed {}: {e}", path.display()))?;
        serde_json::from_str::<Value>(&text)
            .map_err(|e| format!("subscription-parse-failed {}: {e}", path.display()))?
    } else {
        Value::Object(Map::new())
    };
    let mut object = existing_value.as_object().cloned().unwrap_or_default();
    object.insert("schema".to_string(), json!(SUBSCRIPTION_SCHEMA));
    object.insert("engine_version_received".to_string(), json!(engine_version));
    object.insert(
        "engine_plane".to_string(),
        json!({
            "version": engine_version,
            "lane": engine_lane,
            "lock_sha256": lock_sha256,
            "updated_at_unix_ms": now_unix_ms(),
        }),
    );
    object.insert("updated_at_unix_ms".to_string(), json!(now_unix_ms()));
    write_json_value_atomic_with_invocation(path, &Value::Object(object), key)
}

pub(crate) fn hotfix_ledger_entry(path: &Path, hotfix_id: &str) -> Result<Option<Value>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path)
        .map_err(|error| format!("subscription-read-failed {}: {error}", path.display()))?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|error| format!("subscription-parse-failed {}: {error}", path.display()))?;
    Ok(value
        .get("hotfix_ledger")
        .and_then(Value::as_object)
        .and_then(|ledger| ledger.get(hotfix_id))
        .cloned())
}
pub(crate) fn close_hotfix_ledger(
    path: &Path,
    hotfix_id: &str,
    body_identity: &str,
    closing_reason: &str,
    receipt_reference: &Path,
    key: crate::atoms::r#do::InvocationKey,
) -> Result<(), String> {
    let existing = if path.exists() {
        let text = fs::read_to_string(path)
            .map_err(|error| format!("subscription-read-failed {}: {error}", path.display()))?;
        serde_json::from_str::<Value>(&text)
            .map_err(|error| format!("subscription-parse-failed {}: {error}", path.display()))?
    } else {
        Value::Object(Map::new())
    };
    let mut root = existing.as_object().cloned().unwrap_or_default();
    let mut ledger = root
        .get("hotfix_ledger")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    ledger.entry(hotfix_id.to_string()).or_insert_with(|| json!({"hotfix_id": hotfix_id, "body_identity": body_identity, "closing_reason": closing_reason, "receipt_reference": receipt_reference}));
    root.insert("hotfix_ledger".to_string(), Value::Object(ledger));
    root.insert("schema".to_string(), json!(SUBSCRIPTION_SCHEMA));
    root.insert("updated_at_unix_ms".to_string(), json!(now_unix_ms()));
    write_json_value_atomic_with_invocation(path, &Value::Object(root), key)
}

#[cfg(test)]
pub(crate) fn write_json_value_atomic(path: &Path, value: &Value) -> Result<(), String> {
    write_json_value_atomic_with_invocation(path, value, crate::atoms::r#do::InvocationKey::for_apply())
}

pub(crate) fn write_json_value_atomic_with_invocation(path: &Path, value: &Value, key: crate::atoms::r#do::InvocationKey) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())? + "
";
    let parent = path.parent().ok_or_else(|| "subscription-parent-missing".to_string())?;
    crate::tools::comparison::execute("subscription-json-parent", || Ok(fs::symlink_metadata(parent).is_ok()), |present| if *present { crate::tools::comparison::DiffDecision::Empty } else { crate::tools::comparison::DiffDecision::Different }, |authorization, _| crate::atoms::r#do::make_dir::create_dir_all(authorization, key, parent))?;
    crate::tools::comparison::execute("subscription-json-write", || Ok(fs::read(path).ok().as_deref() == Some(text.as_bytes())), |same| if *same { crate::tools::comparison::DiffDecision::Empty } else { crate::tools::comparison::DiffDecision::Different }, |authorization, _| crate::atoms::r#do::write_file::file_write(authorization, key, path, text.as_bytes(), crate::atoms::r#do::write_file::FileWriteOptions { write_bytes: true, mode: None, uid: None, gid: None, backup_to: None }).map(|_| ()))?;
    Ok(())
}

fn ensure_subscription_parent(
    key: crate::atoms::r#do::InvocationKey,
    parent: &Path,
) -> Result<(), String> {
    if let Ok(meta) = fs::symlink_metadata(parent) {
        if meta.is_dir() && !meta.file_type().is_symlink() {
            return Ok(());
        }
        return Err(format!(
            "subscription-parent-kind-collision {}",
            parent.display()
        ));
    }
    crate::tools::comparison::execute(
        "subscription-parent-create",
        || {
            Ok(fs::symlink_metadata(parent)
                .map(|meta| meta.is_dir() && !meta.file_type().is_symlink())
                .unwrap_or(false))
        },
        |present| {
            if *present {
                crate::tools::comparison::DiffDecision::Empty
            } else {
                crate::tools::comparison::DiffDecision::Different
            }
        },
        |authorization, _| crate::atoms::r#do::make_dir::create_dir_all(authorization, key, parent),
    )?;
    Ok(())
}

pub(crate) fn preserve_existing_lane_or_default(path: &Path) -> String {
    read_subscription_record(path)
        .ok()
        .flatten()
        .map(|record| record.lane)
        .filter(|lane| !lane.trim().is_empty())
        .unwrap_or_else(|| "upstream".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process;

    fn scratch(name: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("harmonia-subscription-{name}-{}", process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn subscription_seed_and_atomic_update_preserve_machine_local_fields() {
        let root = scratch("seed");
        let path = root.join("subscription.json");
        update_subscription_record(
            &path,
            SubscriptionUpdate {
                lane: "owner".into(),
                source: "fixture://first".into(),
                ref_name: "ref-a".into(),
                selected_profile: "tv".into(),
                engine_version_received: "0.1.0".into(),
                modules: vec![SubscriptionModuleUpdate {
                    id: "alpha".into(),
                    version: "1".into(),
                    tree_sha256: "aaa".into(),
                    received_at_run_id: "run-a".into(),
                }],
            },
        )
        .unwrap();
        let mut value: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("machine_note".into(), json!("keep-me"));
        write_json_value_atomic(&path, &value).unwrap();
        update_subscription_record(
            &path,
            SubscriptionUpdate {
                lane: "owner".into(),
                source: "fixture://second".into(),
                ref_name: "ref-b".into(),
                selected_profile: "tv".into(),
                engine_version_received: "0.1.1".into(),
                modules: vec![SubscriptionModuleUpdate {
                    id: "beta".into(),
                    version: "2".into(),
                    tree_sha256: "bbb".into(),
                    received_at_run_id: "run-b".into(),
                }],
            },
        )
        .unwrap();
        let updated: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(updated["schema"], SUBSCRIPTION_SCHEMA);
        assert_eq!(updated["machine_note"], "keep-me");
        assert_eq!(updated["modules"]["alpha"]["version"], "1");
        assert_eq!(updated["modules"]["beta"]["tree_sha256"], "bbb");
        assert!(!path.with_extension("harmonia-new").exists());
        let _ = fs::remove_dir_all(root);
    }
}
