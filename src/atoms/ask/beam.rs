use serde::{Deserialize, Serialize};
use std::time::Duration;

pub(crate) const LOCK_SCHEMA: &str = "harmonia.beam-lock.v1";
pub(crate) const DOOR_SCHEMA: &str = "caduceus.beam.v1";
pub(crate) const DEFAULT_DOOR_URL: &str = "http://127.0.0.1:3014/api/v1/beam";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct BeamLock {
    pub schema: String,
    pub caduceus_sha: String,
    pub env_sha: String,
    pub minted_from: MintedFrom,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MintedFrom {
    pub harmonia_sha: String,
    pub caduceus_release_tag: String,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct BeamDoor {
    pub schema: String,
    pub ok: bool,
    pub service: String,
    pub caduceus_sha: String,
    pub env_sha: String,
    pub profile: String,
    pub gui_face: Option<String>,
    pub syzygy_sha: Option<String>,
}

pub(crate) fn parse_lock(raw: &str) -> Result<BeamLock, String> {
    let lock = serde_json::from_str(raw).map_err(|_| "beam-lock-malformed".to_string())?;
    validate_lock(lock)
}
pub(crate) fn parse_lock_optional(raw: Option<&str>) -> Result<Option<BeamLock>, String> {
    raw.map(parse_lock).transpose()
}
pub(crate) fn parse_door(raw: &str) -> Result<BeamDoor, String> {
    let door = serde_json::from_str(raw).map_err(|_| "beam-door-malformed".to_string())?;
    validate_door(door)
}
pub(crate) fn read_embedded_lock() -> Result<BeamLock, String> {
    parse_lock(include_str!("../../../locks/beam.json"))
}
pub(crate) fn read_lock_path(path: &std::path::Path) -> Result<Option<BeamLock>, String> {
    match std::fs::read_to_string(path) {
        Ok(raw) => parse_lock(&raw).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("beam-lock-malformed".to_string()),
    }
}
pub(crate) fn fetch_door(url: &str) -> Result<BeamDoor, String> {
    let args = vec!["-fsS".into(), "--max-time".into(), "3".into(), url.into()];
    let result = crate::atoms::ask::read_only_command_with_timeout(
        "/usr/bin/curl",
        &args,
        Duration::from_secs(4),
    );
    if !result.ok {
        return Err("beam-door-unreachable".into());
    }
    parse_door(&result.stdout)
}
pub(crate) fn validate_lock(lock: BeamLock) -> Result<BeamLock, String> {
    if lock.schema != LOCK_SCHEMA
        || !hex_len(&lock.caduceus_sha, 40)
        || !hex_len(&lock.env_sha, 64)
        || !hex_len(&lock.minted_from.harmonia_sha, 40)
        || !hex_len(&lock.minted_from.caduceus_release_tag, 40)
    {
        Err("beam-lock-malformed".into())
    } else {
        Ok(lock)
    }
}
pub(crate) fn validate_door(door: BeamDoor) -> Result<BeamDoor, String> {
    if door.schema != DOOR_SCHEMA
        || !door.ok
        || door.service != "caduceus"
        || !hex_len(&door.caduceus_sha, 40)
        || !hex_len(&door.env_sha, 64)
        || door.profile.is_empty()
        || door.syzygy_sha.as_deref().is_some_and(|s| !hex_len(s, 40))
    {
        Err("beam-door-malformed".into())
    } else {
        Ok(door)
    }
}
fn hex_len(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lock() -> BeamLock {
        BeamLock {
            schema: LOCK_SCHEMA.into(),
            caduceus_sha: "a".repeat(40),
            env_sha: "b".repeat(64),
            minted_from: MintedFrom {
                harmonia_sha: "c".repeat(40),
                caduceus_release_tag: "d".repeat(40),
            },
        }
    }
    fn door() -> BeamDoor {
        BeamDoor {
            schema: DOOR_SCHEMA.into(),
            ok: true,
            service: "caduceus".into(),
            caduceus_sha: "a".repeat(40),
            env_sha: "b".repeat(64),
            profile: "p".into(),
            gui_face: Some("g".into()),
            syzygy_sha: None,
        }
    }
    #[test]
    fn valid_lock() {
        assert!(validate_lock(lock()).is_ok());
    }
    #[test]
    fn malformed_lock() {
        assert!(parse_lock("{}").is_err());
    }
    #[test]
    fn absent_lock() {
        assert_eq!(parse_lock_optional(None).unwrap(), None);
    }
    #[test]
    fn valid_door() {
        assert!(validate_door(door()).is_ok());
    }
    #[test]
    fn foreign_door() {
        let mut d = door();
        d.schema = "foreign.v1".into();
        assert!(validate_door(d).is_err());
    }
    #[test]
    fn false_ok_door() { let mut d = door(); d.ok = false; assert!(validate_door(d).is_err()); }
    #[test]
    fn foreign_service_door() { let mut d = door(); d.service = "foreign".into(); assert!(validate_door(d).is_err()); }
    #[test]
    fn nullable_gui_face() { let mut d = door(); d.gui_face = None; assert!(validate_door(d).is_ok()); }
    #[test]
    fn malformed_door() {
        assert!(parse_door("{}").is_err());
    }
}
