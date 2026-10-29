//! Pure notification row composition; execution belongs to run-command.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(super) fn rows(
    profile: &str,
    identity: &crate::atoms::ask::ruyi::LocalIdentity,
    pending: usize,
    promoted: &[String],
) -> Vec<(&'static str, Value)> {
    let key = identity.mac.as_str();
    let from = json!({"body":profile,"hostname":identity.hostname,"mac":identity.mac});
    let mut rows = Vec::new();
    if pending > 0 {
        rows.push(("proposals", json!({
            "id":format!("update:{key}:proposals"), "kind":"update", "color":"blue",
            "title":"Updates waiting for you", "body":format!("{pending} proposals wait in Updates"),
            "from":from, "state":"pending", "ttl":"until-acted",
            "actions":[{"verb":"open-updates","label":"Open Updates"},{"verb":"dismiss","label":"Dismiss"}],
            "max_rows":10
        })));
    }
    if !promoted.is_empty() {
        let mut set = promoted.to_vec();
        set.sort();
        let digest = format!("{:x}", Sha256::digest(set.join("\n").as_bytes()));
        let short_set: Vec<String> = set.iter().map(|rung| {
            match rung.rsplit_once('-') {
                Some((prefix, sha)) if sha.len() > 12 && sha.bytes().all(|b| b.is_ascii_hexdigit()) => format!("{prefix}-{}", &sha[..12]),
                _ => rung.clone(),
            }
        }).collect();
        rows.push(("updated", json!({
            "id":format!("update:{key}:{}", &digest[..12]), "kind":"update", "color":"blue",
            "title":"Updated", "body":format!("caduceus, sbin, coronatio moved to {}", short_set.join(", ")),
            "from":from, "state":"pending", "ttl":"7d",
            "actions":[{"verb":"dismiss","label":"Dismiss"}], "max_rows":10
        })));
    }
    rows
}
