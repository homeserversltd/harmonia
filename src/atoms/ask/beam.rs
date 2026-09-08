use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

pub(crate) const LOCK_SCHEMA: &str = "harmonia.beam-lock.v1";
pub(crate) const SLOT_SCHEMA: &str = "harmonia.beam-slot.v1";
pub(crate) const DOOR_SCHEMA: &str = "caduceus.beam.v1";
pub(crate) fn door_url() -> Result<String, &'static str> {
    super::caduceus_door::base_url().map(|base| format!("{base}/api/v1/beam"))
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged, deny_unknown_fields)]
pub(crate) enum BeamLock {
    Legacy {
        schema: String,
        caduceus_sha: String,
        env_sha: String,
        minted_from: MintedFrom,
    },
    Slot {
        schema: String,
        component: String,
        resolve: String,
        registry_base: String,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedBeamLock {
    pub lock: BeamLock,
    pub version: String,
    pub flagged_at: String,
    pub credential: &'static str,
    pub malformed_flags: usize,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SlotResolutionError {
    pub signal: String,
    pub credential: &'static str,
    pub malformed_flags: usize,
}
impl SlotResolutionError {
    fn new(signal: impl Into<String>, credential: &'static str) -> Self {
        Self {
            signal: signal.into(),
            credential,
            malformed_flags: 0,
        }
    }
    fn with_malformed_flags(
        signal: impl Into<String>,
        credential: &'static str,
        malformed_flags: usize,
    ) -> Self {
        Self {
            signal: signal.into(),
            credential,
            malformed_flags,
        }
    }
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseFlag {
    schema: String,
    component: String,
    source_sha: String,
    env_sha: String,
    sha256: String,
    flagged_at: String,
    pipeline_url: String,
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

/// Capability minted only by the beam comparison owner for the exact locked
/// Caduceus release. Callers can carry it, but cannot construct one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BeamConvergenceAuthorization {
    caduceus_sha: String,
    refetch: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingBeamFinalization {
    pub authorization: BeamConvergenceAuthorization,
    pub receipt_dir: PathBuf,
    pub door_url: String,
}
impl BeamLock {
    pub(crate) fn caduceus_sha(&self) -> Option<&str> {
        match self {
            Self::Legacy { caduceus_sha, .. } => Some(caduceus_sha),
            Self::Slot { .. } => None,
        }
    }

    pub(crate) fn env_sha(&self) -> Option<&str> {
        match self {
            Self::Legacy { env_sha, .. } => Some(env_sha),
            Self::Slot { .. } => None,
        }
    }
}

impl BeamConvergenceAuthorization {
    pub(crate) fn caduceus_sha(&self) -> &str {
        &self.caduceus_sha
    }
    pub(crate) fn refetch(&self) -> bool {
        self.refetch
    }
    pub(crate) fn receipt_authorization(&self) -> crate::bands::compare::BeamAuthorizationReceipt {
        crate::bands::compare::BeamAuthorizationReceipt::TripleLadder
    }
}

pub(crate) fn authorize_convergence(
    caduceus_sha: &str,
    divergent_member: Option<&str>,
    divergent: bool,
    apply: bool,
    developer_mode: bool,
) -> Option<BeamConvergenceAuthorization> {
    (divergent && apply && !developer_mode).then(|| BeamConvergenceAuthorization {
        caduceus_sha: caduceus_sha.to_owned(),
        refetch: divergent_member == Some("env_sha"),
    })
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
/// One bounded Ruyi PUT; curl owns the three-second transport deadline.
pub(crate) fn put_json(url: &str, bytes: &[u8]) -> Result<String, String> {
    let mut child = Command::new("/usr/bin/curl")
        .args(["-fsS", "--max-time", "3", "-X", "PUT", "-H",
            "content-type: application/json", "--data-binary", "@-", "-w", "\n%{http_code}", url])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().map_err(|_| "ruyi-gateway-unreachable".to_string())?;
    let sent = child.stdin.take().ok_or_else(|| "ruyi-put-stdin-unavailable".to_string())?
        .write_all(bytes);
    let output = child.wait_with_output()
        .map_err(|_| "ruyi-gateway-unreachable".to_string())?;
    if output.status.code() == Some(22) {
        return Err("ruyi-put-refused".into());
    }
    if !output.status.success() || sent.is_err() {
        return Err("ruyi-gateway-unreachable".into());
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| "ruyi-put-response-malformed".to_string())?;
    let (body, status) = text.rsplit_once('\n')
        .ok_or_else(|| "ruyi-put-response-malformed".to_string())?;
    if !status.parse::<u16>().is_ok_and(|status| (200..300).contains(&status)) {
        return Err("ruyi-put-refused".into());
    }
    Ok(body.to_owned())
}

/// One bounded Ruyi DELETE; curl owns the three-second transport deadline.
pub(crate) fn delete(url: &str) -> Result<(String, u16), String> {
    let output = Command::new("/usr/bin/curl")
        .args([
            "-sS",
            "--max-time",
            "3",
            "-X",
            "DELETE",
            "-w",
            "\n%{http_code}",
            url,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|_| "ruyi-bump-transport-failed".to_string())?;
    if !output.status.success() {
        return Err("ruyi-bump-transport-failed".into());
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| "ruyi-bump-seat-reply-malformed".to_string())?;
    let (body, status) = text
        .rsplit_once('\n')
        .ok_or_else(|| "ruyi-bump-seat-reply-malformed".to_string())?;
    let status = status
        .trim()
        .parse::<u16>()
        .map_err(|_| "ruyi-bump-seat-reply-malformed".to_string())?;
    Ok((body.to_owned(), status))
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
    match &lock {
        BeamLock::Legacy {
            schema,
            caduceus_sha,
            env_sha,
            minted_from,
        } if schema == LOCK_SCHEMA
            && hex_len(caduceus_sha, 40)
            && hex_len(env_sha, 64)
            && hex_len(&minted_from.harmonia_sha, 40)
            && hex_len(&minted_from.caduceus_release_tag, 40) =>
        {
            Ok(lock)
        }
        BeamLock::Slot {
            schema,
            component,
            resolve,
            registry_base,
        } if schema == SLOT_SCHEMA
            && component == "caduceus"
            && resolve == "latest-flagged-release"
            && !registry_base.trim().is_empty() =>
        {
            Ok(lock)
        }
        _ => Err("beam-lock-malformed".into()),
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

fn flag_request(
    url: &str,
    destination: &std::path::Path,
    token: Option<&str>,
) -> Result<u16, String> {
    let mut command = Command::new("curl");
    command.args([
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--max-time",
        "3",
        "--output",
    ]);
    command
        .arg(destination)
        .args(["--write-out", "%{http_code}"]);
    if let Some(token) = token {
        let escaped = token.replace('\\', "\\\\").replace('"', "\\\"");
        command
            .arg("--config")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut child = command
            .arg(url)
            .spawn()
            .map_err(|_| "beam-flag-unresolvable".to_string())?;
        child
            .stdin
            .take()
            .ok_or_else(|| "beam-flag-unresolvable".to_string())?
            .write_all(format!("header = \"Authorization: token {escaped}\"\n").as_bytes())
            .map_err(|_| "beam-flag-unresolvable".to_string())?;
        let output = child
            .wait_with_output()
            .map_err(|_| "beam-flag-unresolvable".to_string())?;
        return Ok(String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .unwrap_or(0));
    }
    let output = command
        .arg(url)
        .output()
        .map_err(|_| "beam-flag-unresolvable".to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap_or(0))
}
fn fetch_flag(
    url: &str,
    destination: &std::path::Path,
    token: Option<&str>,
) -> Result<u16, String> {
    let status = flag_request(url, destination, token)?;
    if status == 401 || status == 403 {
        return Err("beam-flag-unresolvable".into());
    }
    Ok(status)
}

#[derive(Debug, Deserialize)]
struct RegistryVersion {
    name: String,
    version: String,
    created_at: String,
}

pub(crate) fn resolve_slot(slot: &BeamLock) -> Result<ResolvedBeamLock, SlotResolutionError> {
    resolve_slot_with_credential_source(slot, |listing_url| {
        crate::atoms::forge_credential::credential_for_url(listing_url)
    })
}

#[cfg(test)]
pub(crate) fn resolve_slot_with_credential_path(
    slot: &BeamLock,
    credential_path: &std::path::Path,
    estate_host: &str,
) -> Result<ResolvedBeamLock, SlotResolutionError> {
    resolve_slot_with_credential_source(slot, |listing_url| {
        match crate::atoms::forge_credential::resolve_for_url_at(
            listing_url,
            credential_path,
            estate_host,
        ) {
            crate::atoms::forge_credential::Outcome::Present { username, token } => {
                Ok(Some(crate::atoms::forge_credential::Credential {
                    username,
                    token,
                }))
            }
            crate::atoms::forge_credential::Outcome::Absent => Ok(None),
            crate::atoms::forge_credential::Outcome::Err(reason) => Err(reason),
        }
    })
}

fn resolve_slot_with_credential_source(
    slot: &BeamLock,
    resolve_credential: impl FnOnce(
        &str,
    ) -> Result<
        Option<crate::atoms::forge_credential::Credential>,
        String,
    >,
) -> Result<ResolvedBeamLock, SlotResolutionError> {
    let BeamLock::Slot {
        component,
        registry_base,
        ..
    } = slot
    else {
        return Err(SlotResolutionError::new("beam-flag-unresolvable", "absent"));
    };
    let api = if let Some((authority, _)) = registry_base.split_once("/api/packages/") {
        format!("{authority}/api/v1/packages/HOMESERVERSLTD?type=generic&q={component}")
    } else {
        format!(
            "{}/api/v1/packages/HOMESERVERSLTD?type=generic&q={component}",
            registry_base.trim_end_matches('/')
        )
    };
    let dir = std::env::temp_dir().join(format!(
        "harmonia-beam-slot-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&dir)
        .map_err(|_| SlotResolutionError::new("beam-flag-unresolvable", "absent"))?;
    let listing_path = dir.join("listing");
    let listing_url = format!("{api}&limit=50&page=1");
    let credential = resolve_credential(&listing_url)
        .map_err(|signal| SlotResolutionError::new(signal, "absent"))?;
    let credential_state = if credential.is_some() {
        "present"
    } else {
        "absent"
    };
    let token = credential
        .as_ref()
        .map(|credential| credential.token.as_str());
    let mut versions = Vec::new();
    // Forgejo listing pagination is capped at five pages.
    for page in 1..=5 {
        let listing_url = format!("{api}&limit=50&page={page}");
        let status = fetch_flag(&listing_url, &listing_path, token)
            .map_err(|signal| SlotResolutionError::new(signal, credential_state))?;
        if !(200..300).contains(&status) {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(SlotResolutionError::new(
                "beam-flag-unresolvable",
                credential_state,
            ));
        }
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&listing_path).map_err(|_| {
                SlotResolutionError::new("beam-flag-unresolvable", credential_state)
            })?)
            .map_err(|_| SlotResolutionError::new("beam-flag-unresolvable", credential_state))?;
        let raw_items = value
            .as_array()
            .ok_or_else(|| SlotResolutionError::new("beam-flag-unresolvable", credential_state))?;
        for item in raw_items {
            let parsed: RegistryVersion = serde_json::from_value(item.clone()).map_err(|_| {
                SlotResolutionError::new("beam-flag-unresolvable", credential_state)
            })?;
            if parsed.name != component.as_str() || !hex_len(&parsed.version, 40) {
                continue;
            }
            versions.push(parsed);
        }
        if raw_items.len() < 50 {
            break;
        }
    }
    versions.sort_by(|left, right| right.created_at.cmp(&left.created_at));
    let mut selected = None;
    let mut malformed_flags = 0;
    for item in versions.into_iter().take(20) {
        let flag_path = dir.join("flag");
        let url = format!(
            "{}/{}/{}/release.flag",
            registry_base.trim_end_matches('/'),
            component,
            item.version
        );
        let status = fetch_flag(&url, &flag_path, token).map_err(|signal| {
            SlotResolutionError::with_malformed_flags(signal, credential_state, malformed_flags)
        })?;
        if status == 404 {
            continue;
        }
        if !(200..300).contains(&status) {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(SlotResolutionError::with_malformed_flags(
                "beam-flag-unresolvable",
                credential_state,
                malformed_flags,
            ));
        }
        let flag: ReleaseFlag =
            serde_json::from_slice(&std::fs::read(&flag_path).map_err(|_| {
                SlotResolutionError::with_malformed_flags(
                    "beam-flag-unresolvable",
                    credential_state,
                    malformed_flags,
                )
            })?)
            .map_err(|_| {
                SlotResolutionError::with_malformed_flags(
                    "beam-flag-unresolvable",
                    credential_state,
                    malformed_flags,
                )
            })?;
        if flag.schema != "estate.release-flag.v1"
            || flag.component != component.as_str()
            || flag.source_sha != item.version
            || !hex_len(&flag.env_sha, 64)
            || !hex_len(&flag.sha256, 64)
            || flag.flagged_at.trim().is_empty()
            || flag.pipeline_url.trim().is_empty()
        {
            malformed_flags += 1;
            continue;
        }
        if selected
            .as_ref()
            .is_none_or(|(_, at, _)| flag.flagged_at > *at)
        {
            selected = Some((item.version, flag.flagged_at, flag.env_sha));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    let Some((version, flagged_at, env_sha)) = selected else {
        return Err(SlotResolutionError::with_malformed_flags(
            "beam-flag-absent",
            credential_state,
            malformed_flags,
        ));
    };
    Ok(ResolvedBeamLock {
        lock: BeamLock::Legacy {
            schema: LOCK_SCHEMA.into(),
            caduceus_sha: version.clone(),
            env_sha,
            minted_from: MintedFrom {
                harmonia_sha: "0".repeat(40),
                caduceus_release_tag: version.clone(),
            },
        },
        version,
        flagged_at,
        credential: credential_state,
        malformed_flags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lock() -> BeamLock {
        BeamLock::Legacy {
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
    fn legacy_and_slot_locks_parse() {
        let legacy = format!(
            r#"{{"schema":"harmonia.beam-lock.v1","caduceus_sha":"{}","env_sha":"{}","minted_from":{{"harmonia_sha":"{}","caduceus_release_tag":"{}"}}}}"#,
            "a".repeat(40),
            "b".repeat(64),
            "c".repeat(40),
            "d".repeat(40)
        );
        assert!(parse_lock(&legacy).is_ok());
        assert!(parse_lock(r#"{"schema":"harmonia.beam-slot.v1","component":"caduceus","resolve":"latest-flagged-release","registry_base":"https://git.home.arpa/api/packages/HOMESERVERSLTD/generic"}"#).is_ok());
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
    fn false_ok_door() {
        let mut d = door();
        d.ok = false;
        assert!(validate_door(d).is_err());
    }
    #[test]
    fn foreign_service_door() {
        let mut d = door();
        d.service = "foreign".into();
        assert!(validate_door(d).is_err());
    }
    #[test]
    fn nullable_gui_face() {
        let mut d = door();
        d.gui_face = None;
        assert!(validate_door(d).is_ok());
    }
    #[test]
    fn malformed_door() {
        assert!(parse_door("{}").is_err());
    }
    #[test]
    fn env_divergence_authorizes_beam_refetch() {
        let authorization =
            authorize_convergence(&"a".repeat(40), Some("env_sha"), true, true, false).unwrap();
        assert!(authorization.refetch());
    }

    #[test]
    fn caduceus_divergence_does_not_refetch() {
        let authorization =
            authorize_convergence(&"a".repeat(40), Some("caduceus_sha"), true, true, false)
                .unwrap();
        assert!(!authorization.refetch());
    }
}
