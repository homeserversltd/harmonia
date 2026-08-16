use crate::{subscription_path, tools, write_json, Profile};
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

const SCHEMA: &str = "harmonia.hotfix.v1";
const RECEIPT_SCHEMA: &str = "harmonia.hotfix.receipt.v1";

#[derive(Debug)]
struct Scope {
    profiles: Vec<String>,
    bodies: Vec<String>,
}

#[derive(Debug)]
struct Payload {
    file_bytes: Vec<u8>,
    target_path: PathBuf,
    mode: Option<u32>,
    owner: Option<String>,
}

pub(crate) fn run_profile_hotfixes(
    profile: &Profile,
    receipt_dir: &Path,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) {
    for (ordinal, declaration) in profile.hotfixes.iter().enumerate() {
        if let Err(blocker) = run_one(profile, receipt_dir, declaration, invocation) {
            // A Hotfix failure is terminal for that declaration, never for the
            // profile engine.  Receipt persistence is attempted independently
            // so a broken receipt destination cannot suppress sibling hotfixes.
            let _ = write_blocked_receipt(profile, receipt_dir, declaration, ordinal, &blocker);
        }
    }
}

fn run_one(
    profile: &Profile,
    receipt_dir: &Path,
    declaration: &Value,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<(), String> {
    let object = declaration
        .as_object()
        .ok_or_else(|| "hotfix-declaration-not-object".to_string())?;
    // Schema is additive declaration metadata, not a behavior gate. Field
    // presence selects this primitive and the full declaration is preserved.
    let schema = optional_string(object, "schema").unwrap_or(SCHEMA);
    let id = required_string(object, "id", "hotfix-id-missing")?;
    let description = optional_string(object, "description").unwrap_or_default();
    let scope = parse_scope(object.get("scope"))?;
    let in_scope = (scope.profiles.is_empty()
        || scope.profiles.iter().any(|value| value == &profile.id))
        && (scope.bodies.is_empty() || scope.bodies.iter().any(|value| value == &profile.identity));
    if !in_scope {
        // Scope is evaluated before every other phase. No target observation,
        // file action, or subscription-ledger write occurs for excluded bodies.
        return Ok(());
    }

    let hotfix_receipt_dir = receipt_dir.join("hotfixes");
    let receipt_path = hotfix_receipt_dir.join(format!("{id}.json"));
    let predicate = observe_predicate(object.get("predicate"), object.get("payload"))?;
    let ledger = crate::hotfix_ledger_entry(&subscription_path(), id)?;
    let ledger_open = ledger.is_none();
    let payload = parse_payload(object.get("payload"))?;
    let eligible = predicate.0 && ledger_open && payload.is_some();
    let decision = if eligible {
        tools::comparison::DiffDecision::Different
    } else {
        tools::comparison::DiffDecision::Empty
    };
    let run = tools::comparison::execute(
        "hotfix",
        || Ok::<_, String>(()),
        |_| decision,
        |_, _| {
            let payload = payload.as_ref().expect("nonempty eligibility has payload");
            let backup = payload.target_path.with_extension("harmonia-hotfix.bak");
            let ownership = crate::backfill_file::resolve_ownership(payload.owner.as_deref())?;
            let backup_policy = crate::backfill_file::BackupPolicy::Observed(&backup);
            let outcome =
                crate::backfill_file::execute(crate::backfill_file::BackfillFileRequest {
                    path: &payload.target_path,
                    declared_bytes: &payload.file_bytes,
                    mode: payload.mode,
                    ownership,
                    backup: backup_policy,
                    invocation: invocation,
                })?;
            Ok(outcome.hotfix_receipt)
        },
    )?;

    let (movement, changed, tool_receipt) = match run {
        tools::comparison::ComparisonRun::Current { .. } => ("none", false, Value::Null),
        tools::comparison::ComparisonRun::Moved { movement, .. } => (
            "comparison-gated-file-backfill",
            movement.changed,
            serde_json::to_value(&movement).map_err(|error| error.to_string())?,
        ),
    };
    let closing_reason = if !predicate.0 {
        Some("predicate-false")
    } else if ledger.is_some() {
        Some("ledger-closed")
    } else if payload.is_none() {
        Some("payload-absent")
    } else {
        None
    };

    // The file-tool receipt is durable before the machine-local completion fact.
    let mut receipt = prior_receipt(&receipt_path)?;
    receipt.insert("schema".into(), json!(RECEIPT_SCHEMA));
    receipt.insert("hotfix_schema".into(), json!(schema));
    receipt.insert("hotfix_id".into(), json!(id));
    receipt.insert("description".into(), json!(description));
    receipt.insert("profile_id".into(), json!(profile.id));
    receipt.insert("body_identity".into(), json!(profile.identity));
    receipt.insert("scope_observation".into(), json!("in-scope"));
    receipt.insert("predicate_observation".into(), predicate.1);
    receipt.insert(
        "ledger_state".into(),
        json!(if ledger_open { "open" } else { "closed" }),
    );
    receipt.insert(
        "eligibility_comparison".into(),
        json!(if eligible { "nonempty" } else { "empty" }),
    );
    receipt.insert("movement".into(), json!(movement));
    receipt.insert("changed".into(), json!(changed));
    receipt.insert("file_tool_receipt".into(), tool_receipt);
    receipt.insert("retirement".into(), json!(closing_reason));
    receipt.insert(
        "source_cure_debt".into(),
        json!(format!("source-cure-required:hotfix:{id}")),
    );
    receipt.insert("declaration".into(), declaration.clone());
    receipt.insert(
        "receipt_stamps".into(),
        append_stamp(receipt.get("receipt_stamps"), "hotfix-proved"),
    );
    write_json(&receipt_path, &Value::Object(receipt))?;

    if eligible {
        crate::close_hotfix_ledger(
            &subscription_path(),
            id,
            &profile.identity,
            "file-tool-proved",
            &receipt_path,
            invocation.ok_or_else(|| "hotfix-ledger-invocation-missing".to_string())?,
        )?;
    }
    Ok(())
}

fn write_blocked_receipt(
    profile: &Profile,
    receipt_dir: &Path,
    declaration: &Value,
    ordinal: usize,
    blocker: &str,
) -> Result<(), String> {
    let id = declaration
        .as_object()
        .and_then(|object| optional_string(object, "id"))
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("invalid-{ordinal}"));
    let receipt_path = receipt_dir.join("hotfixes").join(format!("{id}.json"));
    let mut receipt = prior_receipt(&receipt_path)?;
    receipt.insert("schema".into(), json!(RECEIPT_SCHEMA));
    receipt.insert(
        "hotfix_schema".into(),
        json!(declaration
            .as_object()
            .and_then(|object| optional_string(object, "schema"))
            .unwrap_or(SCHEMA)),
    );
    receipt.insert("hotfix_id".into(), json!(id));
    receipt.insert(
        "description".into(),
        json!(declaration
            .as_object()
            .and_then(|object| optional_string(object, "description"))
            .unwrap_or_default()),
    );
    receipt.insert("profile_id".into(), json!(profile.id));
    receipt.insert("body_identity".into(), json!(profile.identity));
    receipt.insert("scope_observation".into(), json!("in-scope-or-unreadable"));
    receipt.insert("lifecycle".into(), json!("blocked"));
    receipt.insert("blocker".into(), json!(blocker));
    receipt.insert("movement".into(), json!("none"));
    receipt.insert("changed".into(), json!(false));
    receipt.insert("file_tool_receipt".into(), Value::Null);
    receipt.insert(
        "source_cure_debt".into(),
        json!(format!("source-cure-required:hotfix:{id}")),
    );
    receipt.insert("declaration".into(), declaration.clone());
    receipt.insert(
        "receipt_stamps".into(),
        append_stamp(receipt.get("receipt_stamps"), "hotfix-blocked"),
    );
    write_json(&receipt_path, &Value::Object(receipt))
}

fn prior_receipt(path: &Path) -> Result<Map<String, Value>, String> {
    if !crate::atoms::ask::exists(path) {
        return Ok(Map::new());
    }
    let text = crate::atoms::ask::text(path)
        .map_err(|error| format!("hotfix-receipt-read-failed {}: {error}", path.display()))?;
    Ok(serde_json::from_str::<Value>(&text)
        .map_err(|error| format!("hotfix-receipt-parse-failed {}: {error}", path.display()))?
        .as_object()
        .cloned()
        .unwrap_or_default())
}

fn append_stamp(prior: Option<&Value>, stamp: &str) -> Value {
    let mut stamps = prior.and_then(Value::as_array).cloned().unwrap_or_default();
    stamps.push(json!(stamp));
    Value::Array(stamps)
}

fn parse_scope(value: Option<&Value>) -> Result<Scope, String> {
    let Some(value) = value else {
        return Ok(Scope {
            profiles: Vec::new(),
            bodies: Vec::new(),
        });
    };
    if value.is_null() {
        return Ok(Scope {
            profiles: Vec::new(),
            bodies: Vec::new(),
        });
    }
    let object = value
        .as_object()
        .ok_or_else(|| "hotfix-scope-invalid".to_string())?;
    Ok(Scope {
        profiles: string_array(object.get("profiles"), "hotfix-scope-profiles-invalid")?,
        bodies: string_array(object.get("bodies"), "hotfix-scope-bodies-invalid")?,
    })
}

fn parse_payload(value: Option<&Value>) -> Result<Option<Payload>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let object = value
        .as_object()
        .ok_or_else(|| "hotfix-payload-invalid".to_string())?;
    let file_bytes = object
        .get("file_bytes")
        .and_then(Value::as_array)
        .ok_or_else(|| "hotfix-payload-file-bytes-missing".to_string())?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .filter(|byte| *byte <= u8::MAX as u64)
                .map(|byte| byte as u8)
                .ok_or_else(|| "hotfix-payload-file-bytes-invalid".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let target_path = PathBuf::from(required_string(
        object,
        "target_path",
        "hotfix-payload-target-path-missing",
    )?);
    let mode = object
        .get("mode")
        .map(|value| {
            value
                .as_u64()
                .filter(|mode| *mode <= 0o777)
                .map(|mode| mode as u32)
                .ok_or_else(|| "hotfix-payload-mode-invalid".to_string())
        })
        .transpose()?;
    let owner = object
        .get("owner")
        .map(|value| {
            value
                .as_str()
                .filter(|owner| !owner.trim().is_empty())
                .map(ToString::to_string)
                .ok_or_else(|| "hotfix-payload-owner-invalid".to_string())
        })
        .transpose()?;
    Ok(Some(Payload {
        file_bytes,
        target_path,
        mode,
        owner,
    }))
}

fn observe_predicate(
    predicate: Option<&Value>,
    payload: Option<&Value>,
) -> Result<(bool, Value), String> {
    crate::backfill_file::observe_predicate(predicate, payload)
}

fn optional_string<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    signal: &str,
) -> Result<&'a str, String> {
    optional_string(object, name).ok_or_else(|| signal.to_string())
}

fn string_array(value: Option<&Value>, signal: &str) -> Result<Vec<String>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value
        .as_array()
        .ok_or_else(|| signal.to_string())?
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|item| !item.trim().is_empty())
                .map(ToString::to_string)
                .ok_or_else(|| signal.to_string())
        })
        .collect()
}
