use crate::{subscription_path, tools, write_json, Profile};
use serde_json::{json, Map, Value};
use std::fs;
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

pub(crate) fn run_profile_hotfixes(profile: &Profile, receipt_dir: &Path) -> Result<(), String> {
    for declaration in &profile.hotfixes {
        run_one(profile, receipt_dir, declaration)?;
    }
    Ok(())
}

fn run_one(profile: &Profile, receipt_dir: &Path, declaration: &Value) -> Result<(), String> {
    let object = declaration
        .as_object()
        .ok_or_else(|| "hotfix-declaration-not-object".to_string())?;
    let schema = optional_string(object, "schema").unwrap_or(SCHEMA);
    if schema != SCHEMA {
        return Err(format!("hotfix-schema-unsupported {schema}"));
    }
    let id = required_string(object, "id", "hotfix-id-missing")?;
    let description = required_string(object, "description", "hotfix-description-missing")?;
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
        || Ok::<_, String>(()),
        |_| decision,
        |_, _| {
            let payload = payload.as_ref().expect("nonempty eligibility has payload");
            tools::files::comparison_gated_hotfix_backfill(
                &tools::files::HotfixFileBackfillRequest {
                    target: payload.target_path.clone(),
                    file_bytes: payload.file_bytes.clone(),
                    mode: payload.mode,
                    owner: payload.owner.clone(),
                },
            )
        },
    )?;

    let (movement, changed, tool_receipt) = match run {
        tools::comparison::ComparisonRun::Current { .. } => ("none", false, Value::Null),
        tools::comparison::ComparisonRun::Moved { movement, .. } => (
            "comparison-gated-file-backfill",
            movement.changed,
            serde_json::to_value(movement).map_err(|error| error.to_string())?,
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
    receipt.insert("hotfix_schema".into(), json!(SCHEMA));
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
        )?;
    }
    Ok(())
}

fn prior_receipt(path: &Path) -> Result<Map<String, Value>, String> {
    if !path.exists() {
        return Ok(Map::new());
    }
    let text = fs::read_to_string(path)
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
    let family = predicate
        .and_then(Value::as_object)
        .and_then(|object| object.get("family"))
        .and_then(Value::as_str)
        .unwrap_or("Always");
    let args = predicate
        .and_then(Value::as_object)
        .and_then(|object| object.get("args"))
        .and_then(Value::as_object);
    match family {
        "Always" => Ok((true, json!({"family":"Always", "condition":"always"}))),
        "FileAbsent" => {
            let path = args
                .and_then(|args| args.get("target_path"))
                .and_then(Value::as_str)
                .or_else(|| {
                    payload
                        .and_then(Value::as_object)
                        .and_then(|item| item.get("target_path"))
                        .and_then(Value::as_str)
                })
                .ok_or_else(|| "hotfix-file-absent-target-path-missing".to_string())?;
            let absent = !Path::new(path).exists();
            Ok((
                absent,
                json!({"family":"FileAbsent", "target_path":path, "condition": if absent {"absent"} else {"present"}}),
            ))
        }
        "VersionBelow" => {
            let args = args.ok_or_else(|| "hotfix-version-below-args-missing".to_string())?;
            let witness_path =
                required_string(args, "version_path", "hotfix-version-below-witness-missing")?;
            let minimum = required_string(args, "minimum", "hotfix-version-below-minimum-missing")?;
            let observed = fs::read_to_string(witness_path)
                .unwrap_or_default()
                .trim()
                .to_string();
            let below = version_below(&observed, minimum);
            Ok((
                below,
                json!({"family":"VersionBelow", "version_path":witness_path, "observed_version":observed, "minimum":minimum, "condition":if below {"below"} else {"current-or-newer"}}),
            ))
        }
        other => Err(format!("hotfix-predicate-unsupported {other}")),
    }
}

fn version_below(observed: &str, minimum: &str) -> bool {
    let parse = |value: &str| {
        value
            .split('.')
            .map(|part| part.parse::<u64>().ok())
            .collect::<Option<Vec<_>>>()
    };
    match (parse(observed), parse(minimum)) {
        (Some(observed), Some(minimum)) => {
            let count = observed.len().max(minimum.len());
            (0..count)
                .map(|index| {
                    (
                        *observed.get(index).unwrap_or(&0),
                        *minimum.get(index).unwrap_or(&0),
                    )
                })
                .find_map(|(left, right)| (left != right).then_some(left < right))
                .unwrap_or(false)
        }
        _ => observed < minimum,
    }
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
