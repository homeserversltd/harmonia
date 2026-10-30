//! Pure notification row composition; execution belongs to run-command.
use serde_json::{json, Value};

pub(super) fn rows(
    profile: &str,
    identity: &crate::atoms::ask::ruyi::LocalIdentity,
    final_receipt: &Value,
) -> Vec<(&'static str, Value)> {
    let Some(promoted) = final_receipt.get("promoted").and_then(Value::as_array) else { return Vec::new(); };
    if promoted.is_empty() { return Vec::new(); }
    let Some(digest) = final_receipt.get("set_digest").and_then(Value::as_str)
        .filter(|s| s.len() == 12 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) else { return Vec::new(); };
    let Some(mut set) = promoted.iter().map(Value::as_str).collect::<Option<Vec<_>>>() else { return Vec::new(); };
    set.sort();
    let short_set: Vec<String> = set.iter().map(|rung| {
        match rung.rsplit_once('-') {
            Some((prefix, sha)) if sha.len() > 12 && sha.bytes().all(|b| b.is_ascii_hexdigit()) => format!("{prefix}-{}", &sha[..12]),
            _ => (*rung).to_owned(),
        }
    }).collect();
    let key = identity.mac.as_str();
    let from = json!({"body":profile,"hostname":identity.hostname,"mac":identity.mac});
    vec![("updated", json!({
        "id":format!("update:{key}:{digest}"), "kind":"update", "color":"blue",
        "title":"Updated", "body":format!("caduceus, sbin, coronatio moved to {}", short_set.join(", ")),
        "from":from, "state":"pending", "ttl":"7d",
        "actions":[{"verb":"dismiss","label":"Dismiss"}], "max_rows":10
    }))]
}
