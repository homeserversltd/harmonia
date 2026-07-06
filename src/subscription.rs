use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const SUBSCRIPTION_SCHEMA: &str = "harmonia.subscription.v1";
const DEFAULT_SUBSCRIPTION_PATH: &str = "/var/lib/harmonia/subscription.json";

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
            Some(existing)
                if existing.version == module.version
                    && existing.tree_sha256 == module.tree_sha256 =>
            {
                "current"
            }
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

pub(crate) fn update_subscription_record(
    path: &Path,
    update: SubscriptionUpdate,
) -> Result<SubscriptionRecord, String> {
    let existing_value = if path.exists() {
        let text = fs::read_to_string(path)
            .map_err(|e| format!("subscription-read-failed {}: {e}", path.display()))?;
        serde_json::from_str::<Value>(&text)
            .map_err(|e| format!("subscription-parse-failed {}: {e}", path.display()))?
    } else {
        Value::Object(Map::new())
    };
    let mut object = existing_value.as_object().cloned().unwrap_or_default();
    let mut modules_object = object
        .get("modules")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for module in update.modules {
        modules_object.insert(
            module.id,
            json!({
                "version": module.version,
                "tree_sha256": module.tree_sha256,
                "received_at_run_id": module.received_at_run_id,
            }),
        );
    }
    let updated_at_unix_ms = now_unix_ms();
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
    object.insert("updated_at_unix_ms".to_string(), json!(updated_at_unix_ms));
    write_json_value_atomic(path, &Value::Object(object))?;
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
    write_json_value_atomic(path, &Value::Object(object))
}

pub(crate) fn write_json_value_atomic(path: &Path, value: &Value) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())? + "\n";
    write_bytes_atomic(path, text.as_bytes())
}

pub(crate) fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("harmonia-new");
    fs::write(&tmp, bytes)
        .map_err(|e| format!("subscription-write-failed {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| {
        format!(
            "subscription-promote-failed {} -> {}: {e}",
            tmp.display(),
            path.display()
        )
    })
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
