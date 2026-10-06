//! Offline reader for the public Wukong Staff collective stamp.
//! Network observations are optional evidence: failures never gate the legacy path.
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

const MEMBERS: [&str; 5] = ["harmonia", "caduceus", "sbin", "coronatio", "arcadia"];
const MAX_HTTP_BODY: usize = 2 * 1024 * 1024;
const MAX_STAMP_BYTES: usize = 16 * 1024;
const MAX_KEY_LINE_BYTES: usize = 4096;
const MAX_CANDIDATES: usize = 32;
const MAX_KEY_CANDIDATES: usize = 32;
const MAX_RELEASE_PAGES: usize = 5;
const RELEASES_PER_PAGE: usize = 50;

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
}

impl StampObservation {
    pub(crate) fn target(&self, member: &str) -> Option<&str> {
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
        json!({
            "declared": self.declared,
            "verdict": self.verdict,
            "signal": self.signal,
            "stamp_sha": self.stamp_sha,
            "stamp_source": self.stamp_source,
            "key_id": self.key_id,
            "terms": self.terms,
            "declared_members": self.declared_members,
            "candidate_attempts": self.attempts,
            "observed": {
                "source_declaration": source_declaration,
                "stamp_source": self.stamp_source,
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
        })
    }
}

static OBSERVATION: OnceLock<StampObservation> = OnceLock::new();

/// One process observes the declared source once; callers share that immutable
/// result so no member hot path repeats the external door.
pub(crate) fn current() -> StampObservation {
    OBSERVATION.get_or_init(observe_uncached).clone()
}

pub(crate) fn target_sha(member: &str) -> Option<String> {
    current().target(member).map(str::to_owned)
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

fn observe_uncached() -> StampObservation {
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

    for (index, candidate) in candidates.iter().enumerate() {
        let locator = candidate_locator(candidate);
        let mut receipt = json!({
            "candidate_index": index + 1,
            "candidate_locator": locator,
            "observed": {"configured": true},
            "could_change": false,
            "attempt": {"operation":"inspect-newest-release-stamp"},
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
            receipt["final_state"] = json!({
                "disposition":"invalid-candidate",
                "signal":"wukong-staff-source-candidate-invalid"
            });
            observation.attempts.push(receipt);
            continue;
        };

        match fetch_candidate_stamp(&locator) {
            Ok(fetched) => {
                observation.stamp_source = Some(fetched.stamp_source.clone());
                if fetched.bytes.len() > MAX_STAMP_BYTES {
                    receipt["final_state"] = json!({
                        "disposition":"invalid",
                        "signal":"wukong-staff-stamp-oversized",
                        "selected_release":fetched.selected_release,
                        "stamp_source":fetched.stamp_source,
                    });
                    observation.signal = "wukong-staff-stamp-invalid".into();
                    observation.verdict = Some("INVALID".into());
                    observation.attempts.push(receipt);
                    return observation;
                }
                let Some(stamp_line) = trim_extraction_padding(&fetched.bytes) else {
                    receipt["final_state"] = json!({
                        "disposition":"invalid",
                        "signal":"wukong-staff-stamp-encoding-invalid",
                        "selected_release":fetched.selected_release,
                        "stamp_source":fetched.stamp_source,
                    });
                    observation.signal = "wukong-staff-stamp-invalid".into();
                    observation.verdict = Some("INVALID".into());
                    observation.attempts.push(receipt);
                    return observation;
                };

                match parse_collective_stamp(stamp_line) {
                    Err((verdict, signal)) => {
                        observation.key_id = stamp_key_id_hint(stamp_line);
                        receipt["final_state"] = json!({
                            "disposition":"selected",
                            "verdict":verdict,
                            "signal":signal,
                            "selected_release":fetched.selected_release,
                            "stamp_source":fetched.stamp_source,
                            "key_id":observation.key_id,
                        });
                        observation.signal = signal;
                        observation.verdict = Some(verdict);
                        observation.attempts.push(receipt);
                        return observation;
                    }
                    Ok(parsed) => {
                        observation.key_id = Some(parsed.key_id.clone());
                        let mut key_inputs = Vec::<(String, &'static str)>::new();
                        if let Some(asset_url) = fetched.key_asset_url.as_ref() {
                            key_inputs.push((asset_url.clone(), "release-key-asset"));
                        }
                        for key_candidate in &configured_key_candidates {
                            key_inputs.push((key_candidate.clone(), "declared-key-line"));
                        }
                        if let Some(mirror_url) = fetched.mirror_key_url(&parsed.key_id) {
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
                        let mut last_unavailable = "wukong-staff-key-line-unavailable".to_string();
                        for (key_candidate, source_kind) in
                            key_inputs.into_iter().take(MAX_KEY_CANDIDATES + 2)
                        {
                            match read_key_candidate(&key_candidate) {
                                Ok(key_line) => match verify_collective_stamp(&parsed, &key_line) {
                                    Ok((sha, terms, key_id)) => {
                                        key_attempts.push(json!({
                                            "source":source_kind,
                                            "disposition":"verified",
                                        }));
                                        receipt["key_attempts"] = json!(key_attempts);
                                        receipt["final_state"] = json!({
                                            "disposition":"selected",
                                            "verdict":"VALID",
                                            "stamp_sha":sha,
                                            "selected_release":fetched.selected_release,
                                            "stamp_source":fetched.stamp_source,
                                            "key_id":key_id,
                                        });
                                        observation.signal = "none".into();
                                        observation.verdict = Some("VALID".into());
                                        observation.stamp_sha = Some(sha);
                                        observation.key_id = Some(key_id);
                                        observation.terms = terms;
                                        observation.attempts.push(receipt);
                                        return observation;
                                    }
                                    Err((verdict, signal)) => {
                                        key_attempts.push(json!({
                                            "source":source_kind,
                                            "disposition":"invalid",
                                            "signal":signal,
                                        }));
                                        if verdict == "INVALID" {
                                            last_invalid = Some(signal);
                                        }
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
                                Err(KeyReadFailure::Invalid(signal)) => {
                                    key_attempts.push(json!({
                                        "source":source_kind,
                                        "disposition":"invalid",
                                        "signal":signal,
                                    }));
                                    last_invalid = Some(signal);
                                }
                            }
                        }
                        receipt["key_attempts"] = json!(key_attempts);
                        if let Some(signal) = last_invalid {
                            receipt["final_state"] = json!({
                                "disposition":"selected",
                                "verdict":"INVALID",
                                "signal":signal,
                                "selected_release":fetched.selected_release,
                                "stamp_source":fetched.stamp_source,
                                "key_id":observation.key_id,
                            });
                            observation.signal = signal;
                            observation.verdict = Some("INVALID".into());
                            observation.attempts.push(receipt);
                            return observation;
                        }
                        receipt["final_state"] = json!({
                            "disposition":"unavailable",
                            "signal":last_unavailable,
                            "selected_release":fetched.selected_release,
                            "stamp_source":fetched.stamp_source,
                            "key_id":observation.key_id,
                        });
                        observation.signal = last_unavailable;
                        observation.attempts.push(receipt);
                    }
                }
            }
            Err((reason, selected_release)) => {
                if reason == "wukong-staff-stamp-response-oversized" {
                    observation.stamp_source = Some(locator.clone());
                    observation.signal = "wukong-staff-stamp-invalid".into();
                    observation.verdict = Some("INVALID".into());
                    receipt["final_state"] = json!({
                        "disposition":"invalid",
                        "signal":reason,
                        "selected_release":selected_release,
                        "stamp_source":locator,
                    });
                    observation.attempts.push(receipt);
                    return observation;
                }
                receipt["final_state"] = json!({
                    "disposition":"unavailable",
                    "signal":reason,
                    "selected_release":selected_release,
                });
                observation.signal = reason;
                observation.attempts.push(receipt);
            }
        }
    }
    if observation.attempts.is_empty() {
        observation.signal = "wukong-staff-stamp-unreachable".into();
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
    safe_https_url(url)
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
                } else if let Some(locator) = candidate_locator(value) {
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

fn request(url: &str, max_bytes: usize) -> Result<(u16, Vec<u8>), String> {
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
        "\n%{http_code}",
    ]);
    if credential.is_some() {
        command.args(["--config", "-"]).stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command
        .arg(&url)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
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
    let max_output = max_bytes.saturating_add(32);
    let mut output = Vec::with_capacity(max_output.min(MAX_HTTP_BODY + 32));
    let read_result = stdout
        .by_ref()
        .take(max_output as u64)
        .read_to_end(&mut output);
    if read_result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err("wukong-staff-stamp-unreachable".into());
    }
    if output.len() >= max_output {
        let _ = child.kill();
        let _ = child.wait();
        return Err("wukong-staff-stamp-response-oversized".into());
    }
    let status = child
        .wait()
        .map_err(|_| "wukong-staff-stamp-unreachable".to_string())?;
    if !status.success() {
        return Err("wukong-staff-stamp-unreachable".into());
    }
    let split = output
        .iter()
        .rposition(|byte| *byte == b'\n')
        .ok_or_else(|| "wukong-staff-stamp-http-status-invalid".to_string())?;
    let status_code = std::str::from_utf8(&output[split + 1..])
        .ok()
        .and_then(|value| value.trim().parse::<u16>().ok())
        .ok_or_else(|| "wukong-staff-stamp-http-status-invalid".to_string())?;
    let body = output[..split].to_vec();
    if body.len() > max_bytes {
        return Err("wukong-staff-stamp-response-oversized".into());
    }
    Ok((status_code, body))
}

fn curl_authorization_config(token: &str) -> Option<String> {
    if token.bytes().any(|byte| byte.is_ascii_control()) {
        return None;
    }
    let escaped = token.replace('\\', "\\\\").replace('"', "\\\"");
    Some(format!("header = \"Authorization: token {escaped}\"\n"))
}

struct FetchedStamp {
    bytes: Vec<u8>,
    stamp_source: String,
    selected_release: String,
    key_asset_url: Option<String>,
    mirror_base: MirrorBase,
}

enum MirrorBase {
    File(String),
    Forgejo {
        authority: String,
        repo_path: String,
        commit: String,
    },
}

impl FetchedStamp {
    fn mirror_key_url(&self, key_id: &str) -> Option<String> {
        if !lower_hex(key_id, 16) {
            return None;
        }
        match &self.mirror_base {
            MirrorBase::File(stamp_url) => {
                let rest = stamp_url.strip_prefix("https://")?;
                let (authority, path) = rest.split_once('/')?;
                let path = path.split(['?', '#']).next()?;
                let parent = path.rsplit_once('/')?.0.trim_end_matches('/');
                Some(if parent.is_empty() {
                    format!("https://{authority}/keys/{key_id}.txt")
                } else {
                    format!("https://{authority}/{parent}/keys/{key_id}.txt")
                })
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
}

fn fetch_candidate_stamp(locator: &str) -> Result<FetchedStamp, (String, String)> {
    if let Some((api, authority, repo_path)) = release_endpoint(locator) {
        return fetch_release_stamp(&api, &authority, &repo_path);
    }
    let safe_locator = safe_https_url(locator).ok_or_else(|| {
        (
            "wukong-staff-source-candidate-invalid".into(),
            "unknown".into(),
        )
    })?;
    if !is_file_url(&safe_locator) {
        return Err((
            "wukong-staff-source-candidate-invalid".into(),
            "unknown".into(),
        ));
    }
    let (status, bytes) = request(&safe_locator, MAX_STAMP_BYTES)
        .map_err(|reason| (reason, "plain-https-file".into()))?;
    if !(200..300).contains(&status) {
        return Err((
            "wukong-staff-stamp-http-unavailable".into(),
            "plain-https-file".into(),
        ));
    }
    Ok(FetchedStamp {
        bytes,
        stamp_source: safe_locator.clone(),
        selected_release: "plain-https-file".into(),
        key_asset_url: None,
        mirror_base: MirrorBase::File(safe_locator),
    })
}

fn fetch_release_stamp(
    api: &str,
    authority: &str,
    repo_path: &str,
) -> Result<FetchedStamp, (String, String)> {
    let mut releases = Vec::<Value>::new();
    for page_number in 1..=MAX_RELEASE_PAGES {
        let url = format!("{api}?limit={RELEASES_PER_PAGE}&page={page_number}");
        let (status, bytes) = request(&url, MAX_HTTP_BODY).map_err(|reason| {
            let signal = if reason == "wukong-staff-stamp-response-oversized" {
                "wukong-staff-release-list-oversized".to_string()
            } else {
                reason
            };
            (signal, "release-listing".into())
        })?;
        if !(200..300).contains(&status) {
            return Err((
                "wukong-staff-release-list-unavailable".into(),
                "release-listing".into(),
            ));
        }
        let page: Vec<Value> = serde_json::from_slice(&bytes).map_err(|_| {
            (
                "wukong-staff-release-list-malformed".into(),
                "release-listing".into(),
            )
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
    let Some(newest) = releases.first() else {
        return Err((
            "wukong-staff-stamp-absent".into(),
            "no-eligible-release".into(),
        ));
    };
    let tag = release_tag(newest).unwrap_or("unknown-tag");
    let commit = eligible_release(newest)
        .expect("filtered eligible releases")
        .to_owned();
    let selected_release = tag.to_owned();
    let assets = newest.get("assets").and_then(Value::as_array);
    let Some(stamp_asset) = assets.and_then(|assets| {
        assets
            .iter()
            .find(|asset| asset.get("name").and_then(Value::as_str) == Some("stamp.mgla"))
    }) else {
        return Err(("wukong-staff-stamp-absent".into(), selected_release));
    };
    let Some(stamp_url) = release_asset_url(stamp_asset) else {
        return Err((
            "wukong-staff-stamp-asset-url-missing".into(),
            selected_release,
        ));
    };
    let (status, bytes) = request(&stamp_url, MAX_STAMP_BYTES)
        .map_err(|reason| (reason, selected_release.clone()))?;
    if !(200..300).contains(&status) {
        return Err((
            "wukong-staff-stamp-http-unavailable".into(),
            selected_release,
        ));
    }
    let key_asset_name = format!(
        "keys/{}.txt",
        stamp_key_id_hint_from_bytes(&bytes).unwrap_or_default()
    );
    let key_asset_url = assets
        .and_then(|assets| {
            assets.iter().find(|asset| {
                asset.get("name").and_then(Value::as_str) == Some(key_asset_name.as_str())
            })
        })
        .and_then(release_asset_url);
    Ok(FetchedStamp {
        bytes,
        stamp_source: stamp_url,
        selected_release,
        key_asset_url,
        mirror_base: MirrorBase::Forgejo {
            authority: authority.to_owned(),
            repo_path: repo_path.to_owned(),
            commit,
        },
    })
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

struct ParsedStamp {
    body: String,
    signature: Signature,
    key_id: String,
    stamp_sha: String,
    terms: std::collections::BTreeMap<String, String>,
}

fn parse_collective_stamp(line: &str) -> Result<ParsedStamp, (String, String)> {
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
    let key_id = values.get("key").cloned().unwrap_or_default();
    if !lower_hex(&key_id, 16) {
        return Err(("INVALID".into(), "wukong-staff-key-id-invalid".into()));
    }
    let signature_bytes = decode_base64url(encoded_signature)
        .filter(|bytes| bytes.len() == 64)
        .ok_or_else(|| ("INVALID".into(), "wukong-staff-signature-invalid".into()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| ("INVALID".into(), "wukong-staff-signature-invalid".into()))?;

    let grant = values.get("grant").map(String::as_str).unwrap_or_default();
    let parsed_terms = grant.split(',').collect::<Vec<_>>();
    if parsed_terms.len() != MEMBERS.len() {
        return Err(("INVALID".into(), "wukong-staff-stamp-terms-invalid".into()));
    }
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
    if values.get("product").map(String::as_str) != Some("wukong-staff")
        || values.get("expiry").map(String::as_str) != Some("never")
    {
        return Err(("INVALID".into(), "wukong-staff-stamp-terms-invalid".into()));
    }
    let concatenated = MEMBERS
        .iter()
        .map(|member| terms.get(*member).expect("fixed grant order").as_str())
        .collect::<String>();
    let expected_band = format!("{:x}", Sha256::digest(concatenated.as_bytes()));
    if values.get("band") != Some(&expected_band) {
        return Err(("INVALID".into(), "wukong-staff-stamp-band-invalid".into()));
    }
    Ok(ParsedStamp {
        body: body.to_owned(),
        signature,
        key_id,
        stamp_sha: expected_band,
        terms,
    })
}

fn verify_collective_stamp(
    stamp: &ParsedStamp,
    key_line: &str,
) -> Result<(String, std::collections::BTreeMap<String, String>, String), (String, String)> {
    let (key_id, public_key) = parse_key_line(key_line)
        .map_err(|_| ("INVALID".into(), "wukong-staff-key-line-invalid".into()))?;
    if stamp.key_id != key_id {
        return Err(("INVALID".into(), "wukong-staff-key-id-mismatch".into()));
    }
    let verifier = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| ("INVALID".into(), "wukong-staff-key-line-invalid".into()))?;
    verifier
        .verify_strict(stamp.body.as_bytes(), &stamp.signature)
        .map_err(|_| ("INVALID".into(), "wukong-staff-signature-invalid".into()))?;
    Ok((stamp.stamp_sha.clone(), stamp.terms.clone(), key_id))
}

enum KeyReadFailure {
    Unavailable(String),
    Invalid(String),
}

fn read_key_candidate(candidate: &str) -> Result<String, KeyReadFailure> {
    if let Some(line) = trim_extraction_padding(candidate.as_bytes()) {
        if line.starts_with("MGLA-KEY1|") {
            return Ok(line.to_owned());
        }
    }
    let locator = safe_https_url(candidate)
        .ok_or_else(|| KeyReadFailure::Invalid("wukong-staff-key-candidate-invalid".into()))?;
    let (status, bytes) = match request(&locator, MAX_KEY_LINE_BYTES) {
        Ok(response) => response,
        Err(reason) if reason == "wukong-staff-stamp-response-oversized" => {
            return Err(KeyReadFailure::Invalid(
                "wukong-staff-key-line-oversized".into(),
            ));
        }
        Err(_) => {
            return Err(KeyReadFailure::Unavailable(
                "wukong-staff-key-line-unavailable".into(),
            ));
        }
    };
    if !(200..300).contains(&status) {
        return Err(KeyReadFailure::Unavailable(
            "wukong-staff-key-line-unavailable".into(),
        ));
    }
    let line = trim_extraction_padding(&bytes)
        .ok_or_else(|| KeyReadFailure::Invalid("wukong-staff-key-line-invalid".into()))?;
    if line.is_empty() {
        return Err(KeyReadFailure::Invalid(
            "wukong-staff-key-line-invalid".into(),
        ));
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
