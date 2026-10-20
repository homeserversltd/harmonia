//! Offline reader for the public Wukong Staff collective stamp.
//! Network observations are optional evidence: failures never gate the legacy path.
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

const MEMBERS: [&str; 6] = [
    "harmonia",
    "caduceus",
    "sbin",
    "coronatio",
    "arcadia",
    "documentation",
];
const MAX_HTTP_BODY: usize = 2 * 1024 * 1024;
const MAX_STAMP_BYTES: usize = 16 * 1024;
const MAX_KEY_LINE_BYTES: usize = 4096;
const MAX_CANDIDATES: usize = 32;
const MAX_KEY_CANDIDATES: usize = 32;
const MAX_RELEASE_PAGES: usize = 5;
const RELEASES_PER_PAGE: usize = 50;

#[derive(Clone, Debug, Default)]
pub(crate) struct FireSealObservation {
    pub(crate) profile: String,
    pub(crate) status: String,
    pub(crate) band: Option<String>,
    pub(crate) licensee: Option<String>,
    pub(crate) issued: Option<String>,
    pub(crate) source: Option<String>,
    pub(crate) signal: String,
    pub(crate) terms: std::collections::BTreeMap<String, String>,
}

impl FireSealObservation {
    pub(crate) fn as_json(&self) -> Value {
        json!({
            "profile": self.profile,
            "status": self.status,
            "band": self.band,
            "licensee": self.licensee,
            "issued": self.issued,
            "source": self.source,
            "signal": self.signal,
            "reason": if self.signal == "none" { Value::Null } else { json!(self.signal) },
        })
    }

    pub(crate) fn ruyi_value(&self) -> Value {
        if self.status != "VALID" {
            return Value::Null;
        }
        json!({
            "band": self.band,
            "licensee": self.licensee,
            "issued": self.issued,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct StampObservation {
    pub(crate) declared: bool,
    pub(crate) verdict: Option<String>,
    pub(crate) signal: String,
    pub(crate) stamp_sha: Option<String>,
    pub(crate) stamp_source: Option<String>,
    pub(crate) key_id: Option<String>,
    pub(crate) terms: std::collections::BTreeMap<String, String>,
    pub(crate) declared_members: Vec<String>,
    pub(crate) attempts: Vec<Value>,
    pub(crate) fire_seal: Option<FireSealObservation>,
}

impl StampObservation {
    pub(crate) fn stamp_target(&self, member: &str) -> Option<&str> {
        if self.verdict.as_deref() != Some("VALID")
            || !self
                .declared_members
                .iter()
                .any(|declared| declared == member)
        {
            return None;
        }
        self.terms.get(member).map(String::as_str)
    }

    pub(crate) fn target(&self, member: &str) -> Option<&str> {
        self.seal_target(member).or_else(|| self.stamp_target(member))
    }

    pub(crate) fn seal_target(&self, member: &str) -> Option<&str> {
        let seal = self.fire_seal.as_ref()?;
        if seal.status != "VALID"
            || !self
                .declared_members
                .iter()
                .any(|declared| declared == member)
        {
            return None;
        }
        seal.terms.get(member).map(String::as_str)
    }

    pub(crate) fn as_json(&self) -> Value {
        let source_declaration = if self.signal == "wukong-staff-config-unreachable"
            || self.signal == "wukong-staff-config-malformed"
        {
            "unknown"
        } else if self.declared {
            "declared"
        } else if self.signal == "wukong-staff-source-undeclared" {
            "undeclared"
        } else {
            "unknown"
        };
        let disposition = self.verdict.as_deref().unwrap_or(if self.declared {
            "UNAVAILABLE"
        } else if self.signal == "wukong-staff-source-undeclared" {
            "UNDECLARED"
        } else {
            "UNAVAILABLE"
        });
        let mut value = json!({
            "declared": self.declared,
            "verdict": self.verdict,
            "signal": self.signal,
            "stamp_sha": self.stamp_sha,
            "stamp_source": self.stamp_source.as_deref().map(safe_source_label),
            "key_id": self.key_id,
            "terms": self.terms,
            "declared_members": self.declared_members,
            "candidate_attempts": self.attempts,
            "observed": {
                "source_declaration": source_declaration,
                "stamp_source": self.stamp_source.as_deref().map(safe_source_label),
                "key_id": self.key_id,
                "verdict": self.verdict,
                "signal": self.signal,
            },
            "could_change": false,
            "attempt": {
                "operation": "read-and-verify-collective-stamp",
                "performed": true,
                "candidate_attempts": self.attempts.len(),
            },
            "final_state": {
                "disposition": disposition,
                "selected_target": self.verdict.as_deref() == Some("VALID"),
            },
        });
        if let Some(fire_seal) = self.fire_seal.as_ref() {
            value["wukong_fire_seal"] = fire_seal.as_json();
        }
        value
    }
}

struct CachedSourceObservation {
    stamp: StampObservation,
    own_profile: Option<String>,
    verified_candidates: Vec<FetchedStamp>,
    fire_seal: OnceLock<FireSealObservation>,
}

static OBSERVATION: OnceLock<CachedSourceObservation> = OnceLock::new();

fn source_observation() -> &'static CachedSourceObservation {
    OBSERVATION.get_or_init(|| {
        let own_profile = crate::device_profile::own_sold_profile();
        let mut verified_candidates = Vec::new();
        let stamp = observe_uncached(&mut verified_candidates);
        CachedSourceObservation {
            stamp,
            own_profile,
            verified_candidates,
            fire_seal: OnceLock::new(),
        }
    })
}

/// All public observation/target consumers share the same immutable own-profile observation; specula kernel resolves no seal.
pub(crate) fn current() -> StampObservation {
    current_with_fire_seal()
}

/// Resolve the optional fire seal lazily, sharing the already-read stamp candidates.
pub(crate) fn current_with_fire_seal() -> StampObservation {
    let cached = source_observation();
    let mut observation = cached.stamp.clone();
    if let Some(profile) = cached.own_profile.as_deref() {
        observation.fire_seal = Some(
            cached
                .fire_seal
                .get_or_init(|| {
                    observe_fire_seal_for_profile(
                        profile,
                        cached.stamp.stamp_source.as_deref(),
                        &cached.verified_candidates,
                    )
                })
                .clone(),
        );
    }
    observation
}

pub(crate) fn target_sha(member: &str) -> Option<String> {
    current_with_fire_seal().target(member).map(str::to_owned)
}

pub(crate) fn write_receipt(receipt_dir: &std::path::Path) -> Result<(), String> {
    let observation = current();
    if !observation.declared {
        return Ok(());
    }
    crate::write_json(
        &receipt_dir.join("wukong-staff-stamp.json"),
        &observation.as_json(),
    )
}

fn observe_uncached(verified_candidates: &mut Vec<FetchedStamp>) -> StampObservation {
    let config_path = crate::bands::pull_source::appliance_config_path();
    let config_bytes = match std::fs::read(&config_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return StampObservation {
                signal: "wukong-staff-source-undeclared".into(),
                ..StampObservation::default()
            }
        }
        Err(_) => return unavailable("wukong-staff-config-unreachable"),
    };
    let config: Value = match serde_json::from_slice(&config_bytes) {
        Ok(config) => config,
        Err(_) => return unavailable("wukong-staff-config-malformed"),
    };
    let source = config
        .get("sources")
        .and_then(|sources| sources.get("wukong-staff"));
    let Some(source) = source else {
        return StampObservation {
            signal: "wukong-staff-source-undeclared".into(),
            ..StampObservation::default()
        };
    };

    let members = declared_members(&config);
    let mut candidates = Vec::new();
    if let Some(configured) = source.get("candidates") {
        expand_candidates(configured, &mut candidates);
    }
    let key_candidates = source
        .get("key_line")
        .into_iter()
        .chain(source.get("key_line_candidates"))
        .flat_map(candidate_strings)
        .take(MAX_KEY_CANDIDATES)
        .collect::<Vec<_>>();
    let mut observation = StampObservation {
        declared: true,
        signal: if candidates.is_empty() {
            "wukong-staff-source-candidates-invalid".into()
        } else {
            "wukong-staff-stamp-absent".into()
        },
        declared_members: members,
        ..StampObservation::default()
    };
    let mut best_failure: Option<CandidateFailure> = None;

    for (index, candidate) in candidates.iter().enumerate() {
        let locator = candidate_locator(candidate);
        let mut receipt = json!({
            "candidate_index": index + 1,
            "candidate_locator": locator.as_deref().map(safe_source_label),
            "observed": {"configured": true},
            "could_change": false,
            "attempt": {"operation":"inspect-newest-verified-release-stamp"},
            "final_state": {"disposition":"unavailable"},
        });
        let configured_key_candidates = candidate
            .get("key_line")
            .into_iter()
            .chain(candidate.get("key_line_candidates"))
            .flat_map(candidate_strings)
            .chain(key_candidates.iter().cloned())
            .take(MAX_KEY_CANDIDATES)
            .collect::<Vec<_>>();
        let Some(locator) = locator else {
            let failure = CandidateFailure {
                verdict: "UNKNOWN".into(),
                signal: "wukong-staff-source-candidate-invalid".into(),
                selected_release: "unknown".into(),
                http_status: None,
            };
            receipt["final_state"] = json!({
                "disposition":"unknown",
                "verdict":failure.verdict,
                "signal":failure.signal,
            });
            if best_failure.as_ref().is_none_or(|current| {
                candidate_failure_rank(&failure) > candidate_failure_rank(current)
            }) {
                best_failure = Some(failure);
            }
            observation.attempts.push(receipt);
            continue;
        };

        match fetch_candidate_stamp(&locator, &configured_key_candidates) {
            Ok(fetched) => {
                let parsed = &fetched.parsed;
                receipt["key_attempts"] = json!(fetched.key_attempts);
                receipt["final_state"] = json!({
                    "disposition":"selected",
                    "verdict":"VALID",
                    "stamp_sha":parsed.stamp_sha,
                    "selected_release":fetched.selected_release,
                    "stamp_source":safe_source_label(&fetched.stamp_source),
                    "key_id":parsed.key_id,
                });
                if observation.verdict.as_deref() != Some("VALID") {
                    observation.signal = "none".into();
                    observation.verdict = Some("VALID".into());
                    observation.stamp_sha = Some(parsed.stamp_sha.clone());
                    observation.key_id = Some(parsed.key_id.clone());
                    observation.terms = parsed.terms.clone();
                    observation.stamp_source = Some(fetched.stamp_source.clone());
                }
                verified_candidates.push(fetched);
            }
            Err(failure) => {
                let disposition = failure.verdict.to_ascii_lowercase();
                receipt["final_state"] = json!({
                    "disposition":disposition,
                    "verdict":failure.verdict,
                    "signal":failure.signal,
                    "selected_release":failure.selected_release,
                    "http_status":failure.http_status,
                });
                if best_failure.as_ref().is_none_or(|current| {
                    candidate_failure_rank(&failure) > candidate_failure_rank(current)
                }) {
                    best_failure = Some(failure);
                }
            }
        }
        observation.attempts.push(receipt);
    }

    if verified_candidates.is_empty() {
        if let Some(failure) = best_failure {
            observation.signal = failure.signal;
            observation.verdict = Some(failure.verdict);
        }
        if observation.attempts.is_empty() && !candidates.is_empty() {
            observation.signal = "wukong-staff-stamp-unreachable".into();
        }
    }
    observation
}

fn unavailable(signal: &str) -> StampObservation {
    StampObservation {
        declared: true,
        signal: signal.into(),
        ..StampObservation::default()
    }
}

fn declared_members(config: &Value) -> Vec<String> {
    let Some(members) = config
        .get("syzygy")
        .filter(|value| value.get("schema").and_then(Value::as_str) == Some("appliance.syzygy.v1"))
        .and_then(|value| value.get("members"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    members
        .iter()
        .filter_map(Value::as_str)
        .filter(|member| MEMBERS.contains(member))
        .map(str::to_owned)
        .collect()
}

fn expand_candidates(value: &Value, output: &mut Vec<Value>) {
    if output.len() >= MAX_CANDIDATES {
        return;
    }
    match value {
        Value::Array(values) => {
            for value in values {
                expand_candidates(value, output);
                if output.len() >= MAX_CANDIDATES {
                    break;
                }
            }
        }
        Value::Object(object) if object.contains_key("candidates") => {
            if let Some(candidates) = object.get("candidates") {
                expand_candidates(candidates, output);
            }
        }
        Value::String(_) | Value::Object(_) => output.push(value.clone()),
        _ => {}
    }
}

fn candidate_locator(candidate: &Value) -> Option<String> {
    let url = candidate.as_str().or_else(|| {
        ["url", "base_url", "release_url", "file_url", "locator"]
            .iter()
            .find_map(|name| candidate.get(*name).and_then(Value::as_str))
    })?;
    #[cfg(all(feature = "test-facade", unix))]
    if fixture_stamp_file_path(url).is_some() {
        return Some(url.to_owned());
    }
    safe_https_url(url).or_else(|| {
        safe_local_directory_root(url).map(|_| url.trim().to_owned())
    })
}

fn key_candidate_locator(candidate: &Value) -> Option<String> {
    let url = candidate.as_str().or_else(|| {
        ["url", "base_url", "release_url", "file_url", "locator"]
            .iter()
            .find_map(|name| candidate.get(*name).and_then(Value::as_str))
    })?;
    safe_locator(url)
}

#[cfg(all(feature = "test-facade", unix))]
const TEST_STAMP_FILE_ENV: &str = "HARMONIA_TEST_COLLECTIVE_STAMP_FILE";

/// The fixture seam accepts only one explicit regular file beneath this
/// ground's receipts tree. Production file:// candidates remain directory roots.
#[cfg(all(feature = "test-facade", unix))]
fn fixture_stamp_file_path(locator: &str) -> Option<std::path::PathBuf> {
    let path_text = locator.strip_prefix("file://")?;
    if !path_text.starts_with('/')
        || path_text
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || path_text.contains(['?', '#', '\\', '%'])
    {
        return None;
    }
    let path = std::path::PathBuf::from(path_text);
    if !path.is_absolute() || path.to_str().is_none() {
        return None;
    }
    let configured = std::env::var_os(TEST_STAMP_FILE_ENV)?;
    if std::path::PathBuf::from(configured) != path {
        return None;
    }

    let receipts_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("receipts");
    validate_local_path_components(&receipts_root).ok()?;
    let root_metadata = std::fs::symlink_metadata(&receipts_root).ok()?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return None;
    }
    let relative = path.strip_prefix(&receipts_root).ok()?;
    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return None;
    }
    let mut current = receipts_root;
    for (index, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&current).ok()?;
        if metadata.file_type().is_symlink() {
            return None;
        }
        let is_file = index + 1 == components.len();
        if (is_file && !metadata.is_file()) || (!is_file && !metadata.is_dir()) {
            return None;
        }
    }
    (current.canonicalize().ok()? == path).then_some(path)
}

#[cfg(all(feature = "test-facade", unix))]
fn fetch_fixture_stamp_file(
    locator: &str,
    configured_key_candidates: &[String],
) -> Result<FetchedStamp, CandidateFailure> {
    let path = fixture_stamp_file_path(locator).ok_or_else(|| CandidateFailure {
        verdict: "UNKNOWN".into(),
        signal: "wukong-staff-source-candidate-invalid".into(),
        selected_release: "unknown".into(),
        http_status: None,
    })?;
    let selected_release = "test-facade-file".to_owned();
    let mut file = crate::atoms::attest::open_nofollow_read(&path).map_err(|_| CandidateFailure {
        verdict: "UNAVAILABLE".into(),
        signal: "wukong-staff-stamp-unreachable".into(),
        selected_release: selected_release.clone(),
        http_status: None,
    })?;
    let mut bytes = Vec::with_capacity(MAX_STAMP_BYTES.min(1024));
    file.take((MAX_STAMP_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| CandidateFailure {
            verdict: "UNAVAILABLE".into(),
            signal: "wukong-staff-stamp-unreachable".into(),
            selected_release: selected_release.clone(),
            http_status: None,
        })?;
    if bytes.len() > MAX_STAMP_BYTES {
        return Err(CandidateFailure {
            verdict: "INVALID".into(),
            signal: "wukong-staff-stamp-response-oversized".into(),
            selected_release,
            http_status: None,
        });
    }
    let parsed = parse_collective_stamp(&bytes).map_err(|(verdict, signal)| CandidateFailure {
        verdict,
        signal,
        selected_release: selected_release.clone(),
        http_status: None,
    })?;
    let mirror_base = MirrorBase::None;
    let key_attempts = verify_parsed_stamp(
        &parsed,
        configured_key_candidates,
        None,
        &mirror_base,
    )
    .map_err(|failure| CandidateFailure {
        selected_release: selected_release.clone(),
        ..failure
    })?;
    Ok(FetchedStamp {
        parsed,
        stamp_source: locator.to_owned(),
        selected_release,
        key_attempts,
        key_candidates: configured_key_candidates.to_vec(),
        fire_asset_urls: std::collections::BTreeMap::new(),
        mirror_base,
    })
}

fn safe_locator(locator: &str) -> Option<String> {
    let locator = locator.trim();
    safe_https_url(locator)
        .or_else(|| local_file_url_path(locator).map(|_| locator.to_owned()))
}

fn local_file_url_path(locator: &str) -> Option<std::path::PathBuf> {
    let path = locator.strip_prefix("file://")?;
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.bytes().any(|byte| {
            byte.is_ascii_control() || matches!(byte, b'%' | b'?' | b'#' | b'\\')
        })
    {
        return None;
    }
    let path = std::path::PathBuf::from(path);
    if !path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, std::path::Component::RootDir | std::path::Component::Normal(_))
        })
        || path.file_name().is_none()
    {
        return None;
    }
    Some(path)
}

fn safe_local_directory_root(locator: &str) -> Option<std::path::PathBuf> {
    let path = local_file_url_path(locator)?;
    validate_local_path_components(&path).ok()?;
    let metadata = std::fs::symlink_metadata(&path).ok()?;
    (!metadata.file_type().is_symlink() && metadata.is_dir()).then_some(path)
}


fn safe_https_url(url: &str) -> Option<String> {
    let url = url.trim();
    let rest = url.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty()
        || authority.contains('@')
        || authority
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || url.bytes().any(|byte| byte.is_ascii_control())
        || url.contains(['\\', '#'])
    {
        return None;
    }
    Some(url.to_owned())
}

fn candidate_strings(value: &Value) -> Vec<String> {
    fn collect(value: &Value, output: &mut Vec<String>) {
        if output.len() >= MAX_KEY_CANDIDATES {
            return;
        }
        match value {
            Value::String(text) => output.push(text.clone()),
            Value::Array(values) => {
                for value in values {
                    collect(value, output);
                    if output.len() >= MAX_KEY_CANDIDATES {
                        break;
                    }
                }
            }
            Value::Object(object) if object.contains_key("candidates") => {
                if let Some(candidates) = object.get("candidates") {
                    collect(candidates, output);
                }
            }
            Value::Object(object) => {
                if let Some(line) = object.get("line").or_else(|| object.get("key_line")) {
                    collect(line, output);
                } else if let Some(locator) = key_candidate_locator(value) {
                    output.push(locator);
                }
            }
            _ => {}
        }
    }
    let mut output = Vec::new();
    collect(value, &mut output);
    output
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
    oversized: bool,
}

fn request(url: &str, max_bytes: usize) -> Result<HttpResponse, String> {
    let url =
        safe_https_url(url).ok_or_else(|| "wukong-staff-source-candidate-invalid".to_string())?;
    let credential = match crate::atoms::forge_credential::resolve_for_url(&url) {
        crate::atoms::forge_credential::Outcome::Present { token, .. } => Some(token),
        crate::atoms::forge_credential::Outcome::Absent => None,
        crate::atoms::forge_credential::Outcome::Err(_) => {
            return Err("wukong-staff-forge-credential-unavailable".into())
        }
    };
    let mut command = Command::new("/usr/bin/curl");
    command.args([
        "--silent",
        "--show-error",
        "--location",
        "--max-redirs",
        "5",
        "--connect-timeout",
        "5",
        "--max-time",
        "15",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--write-out",
        "%{stderr}\n%{http_code}\n",
    ]);
    if credential.is_some() {
        command.args(["--config", "-"]).stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command
        .arg(&url)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "wukong-staff-stamp-unreachable".to_string())?;
    if let Some(token) = credential.as_deref() {
        let Some(mut stdin) = child.stdin.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("wukong-staff-stamp-unreachable".into());
        };
        let Some(config_line) = curl_authorization_config(token) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("wukong-staff-forge-credential-invalid".into());
        };
        if stdin.write_all(config_line.as_bytes()).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err("wukong-staff-stamp-unreachable".into());
        }
    }

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "wukong-staff-stamp-unreachable".to_string())?;
    let mut body = Vec::with_capacity(max_bytes.min(MAX_HTTP_BODY));
    let mut oversized = false;
    let mut buffer = [0u8; 8192];
    loop {
        let count = match stdout.read(&mut buffer) {
            Ok(count) => count,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("wukong-staff-stamp-unreachable".into());
            }
        };
        if count == 0 {
            break;
        }
        if !oversized {
            let retained = count.min(max_bytes.saturating_sub(body.len()));
            body.extend_from_slice(&buffer[..retained]);
            oversized = retained < count;
        }
    }
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| "wukong-staff-stamp-unreachable".to_string())?;
    let mut status_tail = [0u8; 5];
    let mut status_tail_len = 0;
    loop {
        let count = match stderr.read(&mut buffer) {
            Ok(count) => count,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("wukong-staff-stamp-unreachable".into());
            }
        };
        if count == 0 {
            break;
        }
        for byte in &buffer[..count] {
            if status_tail_len < status_tail.len() {
                status_tail[status_tail_len] = *byte;
                status_tail_len += 1;
            } else {
                status_tail.copy_within(1.., 0);
                status_tail[status_tail.len() - 1] = *byte;
            }
        }
    }
    let status = child
        .wait()
        .map_err(|_| "wukong-staff-stamp-unreachable".to_string())?;
    if !status.success() {
        return Err("wukong-staff-stamp-unreachable".into());
    }
    let status_code = (status_tail_len == status_tail.len()
        && status_tail[0] == b'\n'
        && status_tail[4] == b'\n')
        .then(|| std::str::from_utf8(&status_tail[1..4]).ok())
        .flatten()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| "wukong-staff-stamp-http-status-invalid".to_string())?;
    Ok(HttpResponse {
        status: status_code,
        body,
        oversized,
    })
}

fn validate_local_path_components(path: &std::path::Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("wukong-staff-local-file-invalid".into());
    }
    let mut current = std::path::PathBuf::from("/");
    let components = path.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        match component {
            std::path::Component::RootDir => continue,
            std::path::Component::Normal(name) => current.push(name),
            _ => return Err("wukong-staff-local-file-invalid".into()),
        }
        let metadata = std::fs::symlink_metadata(&current)
            .map_err(|_| "wukong-staff-local-file-unavailable".to_string())?;
        if metadata.file_type().is_symlink()
            || (index + 1 < components.len() && !metadata.is_dir())
        {
            return Err("wukong-staff-local-file-invalid".into());
        }
    }
    Ok(())
}

fn read_locator(locator: &str, max_bytes: usize) -> Result<HttpResponse, String> {
    if let Some(path) = local_file_url_path(locator) {
        validate_local_path_components(&path)?;
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|_| "wukong-staff-local-file-unavailable".to_string())?;
        if !metadata.file_type().is_file() {
            return Err("wukong-staff-local-file-invalid".into());
        }
        #[cfg(unix)]
        let mut file = crate::atoms::attest::open_nofollow_read(&path)
            .map_err(|_| "wukong-staff-local-file-unavailable".to_string())?;
        #[cfg(not(unix))]
        let mut file = std::fs::File::open(&path)
            .map_err(|_| "wukong-staff-local-file-unavailable".to_string())?;
        if !file
            .metadata()
            .map_err(|_| "wukong-staff-local-file-unavailable".to_string())?
            .is_file()
        {
            return Err("wukong-staff-local-file-invalid".into());
        }
        let mut body = Vec::with_capacity(max_bytes.min(MAX_HTTP_BODY));
        file.take(max_bytes.saturating_add(1) as u64)
            .read_to_end(&mut body)
            .map_err(|_| "wukong-staff-local-file-unavailable".to_string())?;
        let oversized = body.len() > max_bytes;
        body.truncate(max_bytes);
        return Ok(HttpResponse {
            status: 200,
            body,
            oversized,
        });
    }
    request(locator, max_bytes)
}

fn curl_authorization_config(token: &str) -> Option<String> {
    if token.bytes().any(|byte| byte.is_ascii_control()) {
        return None;
    }
    let escaped = token.replace('\\', "\\\\").replace('"', "\\\"");
    Some(format!("header = \"Authorization: token {escaped}\"\n"))
}

struct FetchedStamp {
    parsed: ParsedStamp,
    stamp_source: String,
    selected_release: String,
    key_attempts: Vec<Value>,
    key_candidates: Vec<String>,
    fire_asset_urls: std::collections::BTreeMap<String, String>,
    mirror_base: MirrorBase,
}

enum MirrorBase {
    None,
    HttpsFile(String),
    LocalRoot(std::path::PathBuf),
    Forgejo {
        authority: String,
        repo_path: String,
        commit: String,
    },
}

struct CandidateFailure {
    verdict: String,
    signal: String,
    selected_release: String,
    http_status: Option<u16>,
}

fn candidate_failure_rank(failure: &CandidateFailure) -> u8 {
    match failure.verdict.as_str() {
        "INVALID" => 3,
        "UNKNOWN" => 2,
        _ => 1,
    }
}

fn fire_failure_rank(seal: &FireSealObservation) -> u8 {
    match seal.status.as_str() {
        "INVALID" => 4,
        "UNKNOWN" => 3,
        _ => 1,
    }
}

impl FetchedStamp {
    fn mirror_key_url(&self, key_id: &str) -> Option<String> {
        if !lower_hex(key_id, 16) {
            return None;
        }
        match &self.mirror_base {
            MirrorBase::None => None,
            MirrorBase::HttpsFile(stamp_url) => {
                let rest = stamp_url.strip_prefix("https://")?;
                let (authority, path) = rest.split_once('/')?;
                let path = path.split(['?', '#']).next()?;
                let root = https_stamp_root(path);
                Some(format!("https://{authority}{root}/keys/{key_id}.txt"))
            }
            MirrorBase::LocalRoot(root) => {
                Some(local_file_url(&root.join("keys").join(format!("{key_id}.txt"))))
            }
            MirrorBase::Forgejo {
                authority,
                repo_path,
                commit,
            } => Some(format!(
                "https://{authority}/{repo_path}/raw/commit/{commit}/keys/{key_id}.txt"
            )),
        }
    }

    fn fire_seal_locator(&self, profile: &str) -> Option<String> {
        let asset = format!("fire-{profile}.mgla");
        match &self.mirror_base {
            MirrorBase::None => None,
            MirrorBase::HttpsFile(stamp_url) => https_sibling(stamp_url, &asset),
            MirrorBase::LocalRoot(root) => Some(local_file_url(
                &root.join("fire").join(profile).join("latest.mgla"),
            )),
            MirrorBase::Forgejo { .. } => self.fire_asset_urls.get(&asset).cloned(),
        }
    }
}

fn unavailable_fire_seal(
    profile: &str,
    signal: &str,
    source: Option<String>,
) -> FireSealObservation {
    FireSealObservation {
        profile: profile.to_owned(),
        status: "UNAVAILABLE".into(),
        source: source.map(|locator| safe_source_label(&locator)),
        signal: signal.to_owned(),
        ..FireSealObservation::default()

    }
}

fn observe_fire_seal_for_profile(
    profile: &str,
    stamp_source: Option<&str>,
    verified_candidates: &[FetchedStamp],
) -> FireSealObservation {
    if verified_candidates.is_empty() {
        return unavailable_fire_seal(
            profile,
            "wukong-fire-stamp-unavailable",
            stamp_source.map(str::to_owned),
        );
    }
    let readable_bands = verified_candidates
        .iter()
        .map(|candidate| candidate.parsed.stamp_sha.clone())
        .collect::<Vec<_>>();
    let mut seen = std::collections::BTreeSet::new();
    let mut best_seal: Option<FireSealObservation> = None;
    for candidate in verified_candidates {
        let Some(locator) = candidate.fire_seal_locator(profile) else {
            let absent = unavailable_fire_seal(
                profile,
                "wukong-fire-seal-absent",
                Some(candidate.stamp_source.clone()),
            );
            if best_seal.as_ref().is_none_or(|current| {
                fire_failure_rank(&absent) > fire_failure_rank(current)
            }) {
                best_seal = Some(absent);
            }
            continue;
        };
        if !seen.insert(locator) {
            continue;
        }
        let seal = observe_fire_seal(candidate, profile, &readable_bands);
        if seal.status == "VALID" {
            return seal;
        }
        if best_seal.as_ref().is_none_or(|current| {
            fire_failure_rank(&seal) > fire_failure_rank(current)
        }) {
            best_seal = Some(seal);
        }
    }
    best_seal.unwrap_or_else(|| {
        unavailable_fire_seal(
            profile,
            "wukong-fire-seal-absent",
            stamp_source.map(str::to_owned),
        )
    })
}

fn observe_fire_seal(
    fetched: &FetchedStamp,
    profile: &str,
    readable_stamp_bands: &[String],
) -> FireSealObservation {
    let Some(locator) = fetched.fire_seal_locator(profile) else {
        return unavailable_fire_seal(
            profile,
            "wukong-fire-seal-absent",
            Some(fetched.stamp_source.clone()),
        );
    };
    let response = match read_locator(&locator, MAX_STAMP_BYTES) {
        Ok(response) => response,
        Err(_) => {
            return unavailable_fire_seal(
                profile,
                "wukong-fire-seal-unreachable",
                Some(locator),
            );
        }
    };
    if response.oversized {
        return FireSealObservation {
            profile: profile.to_owned(),
            status: "INVALID".into(),
            source: Some(safe_source_label(&locator)),
            signal: "wukong-fire-seal-response-oversized".into(),
            ..FireSealObservation::default()
        };
    }
    if !(200..300).contains(&response.status) {
        return unavailable_fire_seal(
            profile,
            if response.status == 404 {
                "wukong-fire-seal-absent"
            } else {
                "wukong-fire-seal-unreachable"
            },
            Some(locator),
        );
    }
    let parsed = match parse_mgla(&response.body) {
        Ok(parsed) => parsed,
        Err((status, signal)) => {
            return FireSealObservation {
                profile: profile.to_owned(),
                status,
                source: Some(safe_source_label(&locator)),
                signal,
                ..FireSealObservation::default()
            };
        }
    };
    let expected_product = format!("wukong-fire-{profile}");
    if parsed.product != expected_product {
        return FireSealObservation {
            profile: profile.to_owned(),
            status: "INVALID".into(),
            band: Some(parsed.stamp_sha),
            licensee: Some(parsed.licensee),
            issued: Some(parsed.issued),
            source: Some(safe_source_label(&locator)),
            signal: "wukong-fire-product-invalid".into(),
            ..FireSealObservation::default()
        };
    }

    let mut key_inputs = fetched
        .key_candidates
        .iter()
        .cloned()
        .map(|candidate| (candidate, "declared-key-line"))
        .collect::<Vec<_>>();
    if let Some(mirror) = fetched.mirror_key_url(&parsed.key_id) {
        key_inputs.push((mirror, "source-mirror-key"));
    }
    let mut seen = Vec::<String>::new();
    key_inputs.retain(|(candidate, _)| {
        if seen.iter().any(|previous| previous == candidate) {
            false
        } else {
            seen.push(candidate.clone());
            true
        }
    });
    let mut last_invalid = None;
    let mut last_unknown = None;
    let mut last_unavailable = "wukong-fire-key-line-unavailable".to_string();
    for (key_candidate, _) in key_inputs.into_iter().take(MAX_KEY_CANDIDATES + 1) {
        match read_key_candidate(&key_candidate) {
            Ok(key_line) => match verify_collective_stamp(&parsed, &key_line) {
                Ok((_, _, _)) => {
                    if !readable_stamp_bands.iter().any(|band| band == &parsed.stamp_sha) {
                        return FireSealObservation {
                            profile: profile.to_owned(),
                            status: "INVALID".into(),
                            band: Some(parsed.stamp_sha.clone()),
                            licensee: Some(parsed.licensee),
                            issued: Some(parsed.issued),
                            source: Some(safe_source_label(&locator)),
                            signal: format!(
                                "wukong-fire-band-mismatch {profile} fire_band={}",
                                parsed.stamp_sha
                            ),
                            ..FireSealObservation::default()
                        };
                    }
                    return FireSealObservation {
                        profile: profile.to_owned(),
                        status: "VALID".into(),
                        band: Some(parsed.stamp_sha),
                        licensee: Some(parsed.licensee),
                        issued: Some(parsed.issued),
                        source: Some(safe_source_label(&locator)),
                        signal: "none".into(),
                        terms: parsed.terms,
                    };
                }
                Err((verdict, signal)) if verdict == "INVALID" => last_invalid = Some(signal),
                Err((_, signal)) => last_unknown = Some(signal),
            },
            Err(KeyReadFailure::Unavailable(signal)) => last_unavailable = signal,
            Err(KeyReadFailure::Unknown(signal)) | Err(KeyReadFailure::Invalid(signal)) => {
                last_unknown = Some(signal)
            }
        }
    }
    FireSealObservation {
        profile: profile.to_owned(),
        status: if last_invalid.is_some() {
            "INVALID".into()
        } else if last_unknown.is_some() {
            "UNKNOWN".into()
        } else {
            "UNAVAILABLE".into()
        },
        band: Some(parsed.stamp_sha),
        licensee: Some(parsed.licensee),
        issued: Some(parsed.issued),
        source: Some(safe_source_label(&locator)),
        signal: last_invalid
            .or(last_unknown)
            .unwrap_or(last_unavailable),
        ..FireSealObservation::default()
    }
}

pub(crate) fn safe_source_label(locator: &str) -> String {
    locator
        .split(['?', '#'])
        .next()
        .unwrap_or(locator)
        .to_owned()
}

fn local_file_url(path: &std::path::Path) -> String {
    format!("file://{}", path.display())
}

fn https_stamp_root(path: &str) -> String {
    let root = path
        .strip_suffix("/stamps/latest.mgla")
        .unwrap_or_else(|| path.rsplit_once('/').map(|(parent, _)| parent).unwrap_or_default())
        .trim_matches('/');
    if root.is_empty() {
        String::new()
    } else {
        format!("/{root}")
    }
}

fn https_sibling(locator: &str, filename: &str) -> Option<String> {
    let locator = safe_https_url(locator)?;
    let rest = locator.strip_prefix("https://")?;
    let (authority, path_and_query) = rest.split_once('/')?;
    let path = path_and_query.split(['?', '#']).next()?;
    if path.rsplit('/').next()? != "latest.mgla" {
        return None;
    }
    let parent = path.rsplit_once('/').map(|(parent, _)| parent).unwrap_or_default();
    Some(if parent.is_empty() {
        format!("https://{authority}/{filename}")
    } else {
        format!("https://{authority}/{parent}/{filename}")
    })
}

fn fetch_candidate_stamp(
    locator: &str,
    configured_key_candidates: &[String],
) -> Result<FetchedStamp, CandidateFailure> {
    #[cfg(all(feature = "test-facade", unix))]
    if fixture_stamp_file_path(locator).is_some() {
        return fetch_fixture_stamp_file(locator, configured_key_candidates);
    }
    if let Some((api, authority, repo_path)) = release_endpoint(locator) {
        return fetch_release_stamp(&api, &authority, &repo_path, configured_key_candidates);
    }
    let safe_locator = safe_locator(locator).ok_or_else(|| CandidateFailure {
        verdict: "UNKNOWN".into(),
        signal: "wukong-staff-source-candidate-invalid".into(),
        selected_release: "unknown".into(),
        http_status: None,
    })?;
    let local_path = local_file_url_path(&safe_locator);
    let (stamp_locator, mirror_base, selected_release): (String, MirrorBase, String) =
        if let Some(path) = local_path.as_ref() {
            validate_local_path_components(path).map_err(|_| CandidateFailure {
                verdict: "UNKNOWN".into(),
                signal: "wukong-staff-local-file-invalid".into(),
                selected_release: "local-file".into(),
                http_status: None,
            })?;
            let metadata = std::fs::symlink_metadata(path).map_err(|_| CandidateFailure {
                verdict: "UNAVAILABLE".into(),
                signal: "wukong-staff-stamp-unreachable".into(),
                selected_release: "local-file".into(),
                http_status: None,
            })?;
            if !metadata.is_dir() {
                return Err(CandidateFailure {
                    verdict: "UNKNOWN".into(),
                    signal: "wukong-staff-local-file-invalid".into(),
                    selected_release: "local-file".into(),
                    http_status: None,
                });
            }
            (
                local_file_url(&path.join("stamps").join("latest.mgla")),
                MirrorBase::LocalRoot(path.clone()),
                "local-file".into(),
            )
        } else {
            if !is_file_url(&safe_locator) {
                return Err(CandidateFailure {
                    verdict: "UNKNOWN".into(),
                    signal: "wukong-staff-source-candidate-invalid".into(),
                    selected_release: "unknown".into(),
                    http_status: None,
                });
            }
            (
                safe_locator.clone(),
                MirrorBase::HttpsFile(safe_locator.clone()),
                "plain-https-file".into(),
            )
        };
    let response = read_locator(&stamp_locator, MAX_STAMP_BYTES).map_err(|_| CandidateFailure {
        verdict: "UNAVAILABLE".into(),
        signal: "wukong-staff-stamp-unreachable".into(),
        selected_release: selected_release.clone(),
        http_status: None,
    })?;
    if !(200..300).contains(&response.status) {
        return Err(CandidateFailure {
            verdict: "UNAVAILABLE".into(),
            signal: "wukong-staff-stamp-http-unavailable".into(),
            selected_release,
            http_status: Some(response.status),
        });
    }
    if response.oversized {
        return Err(CandidateFailure {
            verdict: "INVALID".into(),
            signal: "wukong-staff-stamp-response-oversized".into(),
            selected_release,
            http_status: None,
        });
    }
    let parsed = parse_collective_stamp(&response.body).map_err(|(verdict, signal)| CandidateFailure {
        verdict,
        signal,
        selected_release: selected_release.clone(),
        http_status: None,
    })?;
    let key_attempts = verify_parsed_stamp(
        &parsed,
        configured_key_candidates,
        None,
        &mirror_base,
    )
    .map_err(|failure| CandidateFailure {
        selected_release: selected_release.clone(),
        ..failure
    })?;
    Ok(FetchedStamp {
        parsed,
        stamp_source: stamp_locator,
        selected_release,
        key_attempts,
        key_candidates: configured_key_candidates.to_vec(),
        fire_asset_urls: std::collections::BTreeMap::new(),
        mirror_base,
    })
}

fn fetch_release_stamp(
    api: &str,
    authority: &str,
    repo_path: &str,
    configured_key_candidates: &[String],
) -> Result<FetchedStamp, CandidateFailure> {
    let mut releases = Vec::<Value>::new();
    for page_number in 1..=MAX_RELEASE_PAGES {
        let url = format!("{api}?limit={RELEASES_PER_PAGE}&page={page_number}");
        let response = request(&url, MAX_HTTP_BODY).map_err(|reason| CandidateFailure {
            verdict: "UNAVAILABLE".into(),
            signal: reason,
            selected_release: "release-listing".into(),
            http_status: None,
        })?;
        if response.oversized {
            return Err(CandidateFailure {
                verdict: "UNAVAILABLE".into(),
                signal: "wukong-staff-release-list-oversized".into(),
                selected_release: "release-listing".into(),
                http_status: None,
            });
        }
        if !(200..300).contains(&response.status) {
            return Err(CandidateFailure {
                verdict: "UNAVAILABLE".into(),
                signal: "wukong-staff-release-list-unavailable".into(),
                selected_release: "release-listing".into(),
                http_status: Some(response.status),
            });
        }
        let page: Vec<Value> = serde_json::from_slice(&response.body).map_err(|_| CandidateFailure {
            verdict: "UNKNOWN".into(),
            signal: "wukong-staff-release-list-malformed".into(),
            selected_release: "release-listing".into(),
            http_status: None,
        })?;
        let count = page.len();
        releases.extend(page);
        if count < RELEASES_PER_PAGE {
            break;
        }
    }
    releases.retain(|release| eligible_release(release).is_some());
    releases.sort_by(|left, right| {
        published_at(right)
            .cmp(published_at(left))
            .then_with(|| release_tag(right).cmp(&release_tag(left)))
    });
    if releases.is_empty() {
        return Err(CandidateFailure {
            verdict: "UNAVAILABLE".into(),
            signal: "wukong-staff-stamp-absent".into(),
            selected_release: "no-eligible-release".into(),
            http_status: None,
        });
    }

    let mut last_failure = CandidateFailure {
        verdict: "UNAVAILABLE".into(),
        signal: "wukong-staff-stamp-absent".into(),
        selected_release: "no-release-stamp".into(),
        http_status: None,
    };
    for release in &releases {
        let selected_release = release_tag(release).unwrap_or("unknown-tag").to_owned();
        let commit = eligible_release(release).unwrap_or_default().to_owned();
        let assets = release.get("assets").and_then(Value::as_array);
        let Some(stamp_asset) = assets.and_then(|assets| {
            assets.iter().find(|asset| {
                asset.get("name").and_then(Value::as_str) == Some("stamp.mgla")
            })
        }) else {
            last_failure = CandidateFailure {
                verdict: "UNAVAILABLE".into(),
                signal: "wukong-staff-stamp-absent".into(),
                selected_release,
                http_status: None,
            };
            continue;
        };
        let Some(stamp_url) = release_asset_url(stamp_asset) else {
            last_failure = CandidateFailure {
                verdict: "UNAVAILABLE".into(),
                signal: "wukong-staff-stamp-asset-url-missing".into(),
                selected_release,
                http_status: None,
            };
            continue;
        };
        let response = match request(&stamp_url, MAX_STAMP_BYTES) {
            Ok(response) => response,
            Err(signal) => {
                last_failure = CandidateFailure {
                    verdict: "UNAVAILABLE".into(),
                    signal,
                    selected_release,
                    http_status: None,
                };
                continue;
            }
        };
        if response.oversized {
            last_failure = CandidateFailure {
                verdict: "INVALID".into(),
                signal: "wukong-staff-stamp-response-oversized".into(),
                selected_release,
                http_status: None,
            };
            continue;
        }
        if !(200..300).contains(&response.status) {
            last_failure = CandidateFailure {
                verdict: "UNAVAILABLE".into(),
                signal: "wukong-staff-stamp-http-unavailable".into(),
                selected_release,
                http_status: Some(response.status),
            };
            continue;
        }
        let parsed = match parse_collective_stamp(&response.body) {
            Ok(parsed) => parsed,
            Err((verdict, signal)) => {
                last_failure = CandidateFailure {
                    verdict,
                    signal,
                    selected_release,
                    http_status: None,
                };
                continue;
            }
        };
        let key_asset_name = format!("keys/{}.txt", parsed.key_id);
        let key_asset_url = assets.and_then(|assets| {
            assets.iter().find(|asset| {
                asset.get("name").and_then(Value::as_str) == Some(key_asset_name.as_str())
            })
        }).and_then(release_asset_url);
        let mirror_base = MirrorBase::Forgejo {
            authority: authority.to_owned(),
            repo_path: repo_path.to_owned(),
            commit,
        };
        let key_attempts = match verify_parsed_stamp(
            &parsed,
            configured_key_candidates,
            key_asset_url.as_deref(),
            &mirror_base,
        ) {
            Ok(attempts) => attempts,
            Err(failure) => {
                last_failure = CandidateFailure {
                    selected_release,
                    ..failure
                };
                continue;
            }
        };
        let fire_asset_urls = assets
            .into_iter()
            .flatten()
            .filter_map(|asset| {
                let name = asset.get("name").and_then(Value::as_str)?;
                (name.starts_with("fire-") && name.ends_with(".mgla"))
                    .then(|| release_asset_url(asset).map(|url| (name.to_owned(), url)))
                    .flatten()
            })
            .collect();
        return Ok(FetchedStamp {
            parsed,
            stamp_source: stamp_url,
            selected_release,
            key_attempts,
            key_candidates: configured_key_candidates.to_vec(),
            fire_asset_urls,
            mirror_base,
        });
    }
    Err(last_failure)
}

fn verify_parsed_stamp(
    parsed: &ParsedStamp,
    configured_key_candidates: &[String],
    release_key_asset: Option<&str>,
    mirror_base: &MirrorBase,
) -> Result<Vec<Value>, CandidateFailure> {
    let mut key_inputs = Vec::<(String, &'static str)>::new();
    if let Some(asset_url) = release_key_asset {
        key_inputs.push((asset_url.to_owned(), "release-key-asset"));
    }
    key_inputs.extend(
        configured_key_candidates
            .iter()
            .cloned()
            .map(|candidate| (candidate, "declared-key-line")),
    );
    if let Some(mirror_url) = mirror_base_key_url(mirror_base, &parsed.key_id) {
        key_inputs.push((mirror_url, "source-mirror-key"));
    }
    let mut seen = Vec::new();
    key_inputs.retain(|(candidate, _)| {
        if seen.iter().any(|previous| previous == candidate) {
            false
        } else {
            seen.push(candidate.clone());
            true
        }
    });
    let mut key_attempts = Vec::new();
    let mut last_invalid = None;
    let mut last_unknown = None;
    let mut last_unavailable = "wukong-staff-key-line-unavailable".to_string();
    for (key_candidate, source_kind) in key_inputs.into_iter().take(MAX_KEY_CANDIDATES + 2) {
        match read_key_candidate(&key_candidate) {
            Ok(key_line) => match verify_collective_stamp(parsed, &key_line) {
                Ok(_) => {
                    key_attempts.push(json!({
                        "source":source_kind,
                        "disposition":"verified",
                    }));
                    return Ok(key_attempts);
                }
                Err((verdict, signal)) if verdict == "INVALID" => {
                    key_attempts.push(json!({
                        "source":source_kind,
                        "disposition":"invalid",
                        "signal":signal,
                    }));
                    last_invalid = Some(signal);
                }
                Err((_, signal)) => {
                    key_attempts.push(json!({
                        "source":source_kind,
                        "disposition":"unknown",
                        "signal":signal,
                    }));
                    last_unknown = Some(signal);
                }
            },
            Err(KeyReadFailure::Unavailable(signal)) => {
                key_attempts.push(json!({
                    "source":source_kind,
                    "disposition":"unavailable",
                    "signal":signal,
                }));
                last_unavailable = signal;
            }
            Err(KeyReadFailure::Unknown(signal)) | Err(KeyReadFailure::Invalid(signal)) => {
                key_attempts.push(json!({
                    "source":source_kind,
                    "disposition":"unknown",
                    "signal":signal,
                }));
                last_unknown = Some(signal);
            }
        }
    }
    let (verdict, signal) = if let Some(signal) = last_invalid {
        ("INVALID", signal)
    } else if let Some(signal) = last_unknown {
        ("UNKNOWN", signal)
    } else {
        ("UNAVAILABLE", last_unavailable)
    };
    Err(CandidateFailure {
        verdict: verdict.into(),
        signal,
        selected_release: "stamp".into(),
        http_status: None,
    })
}

fn mirror_base_key_url(mirror_base: &MirrorBase, key_id: &str) -> Option<String> {
    if !lower_hex(key_id, 16) {
        return None;
    }
    match mirror_base {
        MirrorBase::None => None,
        MirrorBase::HttpsFile(stamp_url) => {
            let rest = stamp_url.strip_prefix("https://")?;
            let (authority, path) = rest.split_once('/')?;
            let path = path.split(['?', '#']).next()?;
            let root = https_stamp_root(path);
            Some(format!("https://{authority}{root}/keys/{key_id}.txt"))
        }
        MirrorBase::LocalRoot(root) => {
            Some(local_file_url(&root.join("keys").join(format!("{key_id}.txt"))))
        }
        MirrorBase::Forgejo {
            authority,
            repo_path,
            commit,
        } => Some(format!(
            "https://{authority}/{repo_path}/raw/commit/{commit}/keys/{key_id}.txt"
        )),
    }
}

fn release_asset_url(asset: &Value) -> Option<String> {
    asset
        .get("browser_download_url")
        .or_else(|| asset.get("url"))
        .and_then(Value::as_str)
        .and_then(safe_https_url)
}

fn eligible_release(release: &Value) -> Option<&str> {
    if release.get("draft").and_then(Value::as_bool) != Some(false)
        || published_at(release).is_empty()
    {
        return None;
    }
    let tag = release_tag(release)?;
    tag.strip_prefix("sha-")
        .filter(|commit| lower_hex(commit, 40))
}

fn release_tag(release: &Value) -> Option<&str> {
    release.get("tag_name").and_then(Value::as_str)
}

fn published_at(release: &Value) -> &str {
    release
        .get("published_at")
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn release_endpoint(locator: &str) -> Option<(String, String, String)> {
    let rest = locator.strip_prefix("https://")?;
    let (authority, path_and_query) = rest.split_once('/')?;
    let path = path_and_query.split(['?', '#']).next()?;
    let api_marker = "/api/v1/repos/";
    if let Some(index) = path.find(api_marker) {
        let prefix = &path[..index];
        let repo_and_suffix = &path[index + api_marker.len()..];
        let parts = repo_and_suffix.split('/').collect::<Vec<_>>();
        if parts.len() != 2 && !(parts.len() == 3 && parts[2] == "releases") {
            return None;
        }
        if !safe_repo_segment(parts[0]) || !safe_repo_segment(parts[1]) {
            return None;
        }
        let repo_name = parts[1].trim_end_matches(".git");
        let repo_path = format!("{}/{repo_name}", parts[0]);
        let api = format!("https://{authority}{prefix}/api/v1/repos/{repo_path}/releases");
        return Some((api, authority.to_owned(), repo_path));
    }

    let host = crate::atoms::forge_credential::url_host(locator)?;
    let clean_path = path.trim_end_matches('/');
    let parts = clean_path.split('/').collect::<Vec<_>>();
    if host != crate::atoms::forge_credential::ESTATE_FORGEJO_HOST || parts.len() != 2 {
        return None;
    }
    if !safe_repo_segment(parts[0]) || !safe_repo_segment(parts[1]) {
        return None;
    }
    let repo_name = parts[1].trim_end_matches(".git");
    let repo_path = format!("{}/{repo_name}", parts[0]);
    let api = format!("https://{authority}/api/v1/repos/{repo_path}/releases");
    Some((api, authority.to_owned(), repo_path))
}

fn safe_repo_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn is_file_url(locator: &str) -> bool {
    let Some(rest) = locator.strip_prefix("https://") else {
        return false;
    };
    let Some((_, path_and_query)) = rest.split_once('/') else {
        return false;
    };
    let path = path_and_query.split(['?', '#']).next().unwrap_or_default();
    !path.is_empty()
        && !path.ends_with('/')
        && path.rsplit('/').next().is_some_and(|name| !name.is_empty())
}

fn stamp_key_id_hint_from_bytes(bytes: &[u8]) -> Option<String> {
    let line = trim_extraction_padding(bytes)?;
    stamp_key_id_hint(line)
}

fn stamp_key_id_hint(line: &str) -> Option<String> {
    if !line.starts_with("MGLA1|") {
        return None;
    }
    let body = line.split_once("|sig=").map_or(line, |(body, _)| body);
    let fields = body.split('|').collect::<Vec<_>>();
    if fields.len() != 8 || fields[0] != "MGLA1" {
        return None;
    }
    let (name, key_id) = fields[7].split_once('=')?;
    (name == "key" && lower_hex(key_id, 16)).then(|| key_id.to_owned())
}

fn trim_extraction_padding(bytes: &[u8]) -> Option<&str> {
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && (bytes[start].is_ascii_whitespace() || bytes[start] == 0) {
        start += 1;
    }
    while end > start && (bytes[end - 1].is_ascii_whitespace() || bytes[end - 1] == 0) {
        end -= 1;
    }
    std::str::from_utf8(&bytes[start..end]).ok()
}

fn parse_collective_stamp(bytes: &[u8]) -> Result<ParsedStamp, (String, String)> {
    let parsed = parse_mgla(bytes)?;
    if parsed.product != "wukong-staff" {
        return Err(("INVALID".into(), "wukong-staff-stamp-terms-invalid".into()));
    }
    let concatenated = MEMBERS
        .iter()
        .map(|member| parsed.terms.get(*member).expect("fixed grant order").as_str())
        .collect::<String>();
    let expected_band = format!("{:x}", Sha256::digest(concatenated.as_bytes()));
    if parsed.stamp_sha != expected_band {
        return Err(("INVALID".into(), "wukong-staff-stamp-band-invalid".into()));
    }
    Ok(parsed)
}

struct ParsedStamp {
    body: String,
    signature: Signature,
    key_id: String,
    stamp_sha: String,
    terms: std::collections::BTreeMap<String, String>,
    licensee: String,
    issued: String,
    product: String,
}

fn parse_mgla(bytes: &[u8]) -> Result<ParsedStamp, (String, String)> {
    let line = trim_extraction_padding(bytes)
        .ok_or_else(|| ("INVALID".into(), "wukong-staff-stamp-encoding-invalid".into()))?;
    if !line.starts_with("MGLA1|") {
        if line.starts_with("MGLA") {
            return Err(("UNKNOWN".into(), "wukong-staff-stamp-unknown".into()));
        }
        return Err(("INVALID".into(), "wukong-staff-stamp-invalid".into()));
    }
    let Some((body, encoded_signature)) = line.rsplit_once("|sig=") else {
        return Err(("INVALID".into(), "wukong-staff-stamp-invalid".into()));
    };
    if body
        .as_bytes()
        .last()
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        return Err(("INVALID".into(), "wukong-staff-stamp-invalid".into()));
    }
    let names = [
        "product", "band", "licensee", "grant", "issued", "expiry", "key",
    ];
    let fields = body.split('|').collect::<Vec<_>>();
    if fields.len() != names.len() + 1 || fields[0] != "MGLA1" {
        return Err(("INVALID".into(), "wukong-staff-stamp-invalid".into()));
    }
    let mut values = std::collections::BTreeMap::new();
    for (field, expected) in fields.iter().skip(1).zip(names) {
        let Some((name, value)) = field.split_once('=') else {
            return Err(("INVALID".into(), "wukong-staff-stamp-invalid".into()));
        };
        if name != expected
            || value.is_empty()
            || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        {
            return Err(("INVALID".into(), "wukong-staff-stamp-invalid".into()));
        }
        values.insert(name.to_owned(), value.to_owned());
    }
    let grant = values.get("grant").map(String::as_str).unwrap_or_default();
    let parsed_terms = grant.split(',').collect::<Vec<_>>();
    if parsed_terms.len() != MEMBERS.len() {
        return Err((
            "UNKNOWN".into(),
            "stamp-grant-term-count-foreign".into(),
        ));
    }

    let key_id = values.get("key").cloned().unwrap_or_default();
    if !lower_hex(&key_id, 16) {
        return Err(("INVALID".into(), "wukong-staff-key-id-invalid".into()));
    }
    let signature_bytes = decode_base64url(encoded_signature)
        .filter(|bytes| bytes.len() == 64)
        .ok_or_else(|| ("INVALID".into(), "wukong-staff-signature-invalid".into()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| ("INVALID".into(), "wukong-staff-signature-invalid".into()))?;

    let mut terms = std::collections::BTreeMap::new();
    for (item, member) in parsed_terms.iter().zip(MEMBERS) {
        let Some((name, sha)) = item.split_once(':') else {
            return Err(("INVALID".into(), "wukong-staff-stamp-terms-invalid".into()));
        };
        if name != member || !lower_hex(sha, 40) {
            return Err(("INVALID".into(), "wukong-staff-stamp-terms-invalid".into()));
        }
        terms.insert(member.to_owned(), sha.to_owned());
    }
    if values.get("expiry").map(String::as_str) != Some("never") {
        return Err(("INVALID".into(), "wukong-staff-stamp-terms-invalid".into()));
    }
    Ok(ParsedStamp {
        body: body.to_owned(),
        signature,
        key_id,
        stamp_sha: values.get("band").cloned().unwrap_or_default(),
        terms,
        licensee: values.get("licensee").cloned().unwrap_or_default(),
        issued: values.get("issued").cloned().unwrap_or_default(),
        product: values.get("product").cloned().unwrap_or_default(),
    })
}

fn verify_collective_stamp(
    stamp: &ParsedStamp,
    key_line: &str,
) -> Result<(String, std::collections::BTreeMap<String, String>, String), (String, String)> {
    let (key_id, public_key) = parse_key_line(key_line)
        .map_err(|_| ("UNKNOWN".into(), "wukong-staff-key-line-foreign".into()))?;
    if stamp.key_id != key_id {
        return Err(("UNKNOWN".into(), "wukong-staff-key-id-unavailable".into()));
    }
    let verifier = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| ("UNKNOWN".into(), "wukong-staff-key-line-foreign".into()))?;
    verifier
        .verify_strict(stamp.body.as_bytes(), &stamp.signature)
        .map_err(|_| ("INVALID".into(), "wukong-staff-signature-invalid".into()))?;
    Ok((stamp.stamp_sha.clone(), stamp.terms.clone(), key_id))
}

enum KeyReadFailure {
    Unavailable(String),
    Unknown(String),
    Invalid(String),
}

fn read_key_candidate(candidate: &str) -> Result<String, KeyReadFailure> {
    if let Some(line) = trim_extraction_padding(candidate.as_bytes()) {
        if line.starts_with("MGLA-KEY1|") {
            return Ok(line.to_owned());
        }
    }
    let locator = safe_locator(candidate)
        .ok_or_else(|| KeyReadFailure::Unknown("wukong-staff-key-candidate-foreign".into()))?;
    if let Some(path) = local_file_url_path(&locator) {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(KeyReadFailure::Unknown("wukong-staff-key-line-absent".into()));
            }
            Err(_) => {
                return Err(KeyReadFailure::Unavailable(
                    "wukong-staff-key-line-unavailable".into(),
                ));
            }
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(KeyReadFailure::Unknown("wukong-staff-key-line-foreign".into()));
            }
            Ok(_) => {}
        }
    }
    let response = match read_locator(&locator, MAX_KEY_LINE_BYTES) {
        Ok(response) => response,
        Err(_) => {
            return Err(KeyReadFailure::Unavailable(
                "wukong-staff-key-line-unavailable".into(),
            ));
        }
    };
    if response.oversized {
        return Err(KeyReadFailure::Unavailable(
            "wukong-staff-key-line-oversized".into(),
        ));
    }
    if response.status == 404 {
        return Err(KeyReadFailure::Unknown("wukong-staff-key-line-absent".into()));
    }
    if !(200..300).contains(&response.status) {
        return Err(KeyReadFailure::Unavailable(
            "wukong-staff-key-line-unavailable".into(),
        ));
    }
    let line = trim_extraction_padding(&response.body)
        .ok_or_else(|| KeyReadFailure::Unknown("wukong-staff-key-line-foreign".into()))?;
    if line.is_empty() {
        return Err(KeyReadFailure::Unknown("wukong-staff-key-line-foreign".into()));
    }
    Ok(line.to_owned())
}

fn parse_key_line(line: &str) -> Result<(String, [u8; 32]), ()> {
    let line = trim_extraction_padding(line.as_bytes()).ok_or(())?;
    let fields = line.split('|').collect::<Vec<_>>();
    if fields.len() != 3 || fields[0] != "MGLA-KEY1" {
        return Err(());
    }
    let key_id = fields[1].strip_prefix("key=").ok_or(())?;
    let encoded = fields[2].strip_prefix("pub=").ok_or(())?;
    if !lower_hex(key_id, 16) {
        return Err(());
    }
    let public = decode_base64url(encoded).ok_or(())?;
    let public: [u8; 32] = public.try_into().map_err(|_| ())?;
    let derived = format!("{:x}", Sha256::digest(public));
    if &derived[..16] != key_id {
        return Err(());
    }
    Ok((key_id.to_owned(), public))
}

fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    if value.is_empty()
        || value.contains('=')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return None;
    }
    let padded = format!("{}{}", value, "=".repeat((4 - value.len() % 4) % 4));
    base64::engine::general_purpose::URL_SAFE
        .decode(padded)
        .ok()
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
