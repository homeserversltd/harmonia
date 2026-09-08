//! Interpreted sbin release evidence, separate from compiled beam acceptance.
use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};

const SBIN_RELEASES: &str = "https://git.home.arpa/api/v1/repos/HOMESERVERSLTD/sbin/releases";

#[derive(Debug, Clone)]
pub(crate) struct Observation {
    pub(crate) selected: Option<Value>,
    pub(crate) signal: String,
    pub(crate) malformed_flags: usize,
    pub(crate) credential: &'static str,
    pub(crate) refusals: Vec<Value>,
}

impl Observation {
    pub(crate) fn evidence(&self) -> Value {
        json!({"selected": self.selected, "signal": self.signal,
            "malformed_flags": self.malformed_flags, "credential": self.credential,
            "refusals": self.refusals})
    }
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Keep body and transport outcome separate: malformed JSON is evidence to
/// skip, while a truncated curl transfer is never a valid flag.
fn get(url: &str, token: Option<&str>) -> Result<(u16, Vec<u8>), ()> {
    let mut command = Command::new("/usr/bin/curl");
    command
        .args([
            "--silent",
            "--show-error",
            "--location",
            "--max-time",
            "3",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--write-out",
            "\n%{http_code}",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let token = token.filter(|_| {
        crate::atoms::forge_credential::url_host(url).as_deref()
            == Some(crate::atoms::forge_credential::ESTATE_FORGEJO_HOST)
    });
    if token.is_some() {
        command.args(["--config", "-"]).stdin(Stdio::piped());
    }
    let mut child = command.arg(url).spawn().map_err(|_| ())?;
    if let Some(token) = token {
        let escaped = token.replace('\\', "\\\\").replace('"', "\\\"");
        let write = child
            .stdin
            .take()
            .ok_or(())?
            .write_all(format!("header = \"Authorization: token {escaped}\"\n").as_bytes());
        if write.is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(());
        }
    }
    let output = child.wait_with_output().map_err(|_| ())?;
    if !output.status.success() {
        return Err(());
    }
    let split = output
        .stdout
        .iter()
        .rposition(|byte| *byte == b'\n')
        .ok_or(())?;
    let status = std::str::from_utf8(&output.stdout[split + 1..])
        .map_err(|_| ())?
        .trim()
        .parse::<u16>()
        .map_err(|_| ())?;
    Ok((status, output.stdout[..split].to_vec()))
}

fn validate(flag: &Value, tag: &str, seat: &super::mint_seats::Seat) -> Result<(), String> {
    seat.validate(flag)?;
    if flag
        .get("component")
        .is_some_and(|value| value.as_str() != Some("sbin"))
    {
        return Err("syzygy-flag-component-invalid sbin".into());
    }
    if flag
        .get("source_sha")
        .is_some_and(|value| value.as_str() != Some(tag))
    {
        return Err("syzygy-flag-source-sha-invalid sbin".into());
    }
    for name in ["flagged_at", "pipeline_url"] {
        if flag
            .get(name)
            .is_some_and(|value| value.as_str().is_none_or(|s| s.trim().is_empty()))
        {
            return Err(format!("syzygy-flag-{name}-invalid sbin"));
        }
    }
    for name in ["env_sha", "sha256"] {
        if flag
            .get(name)
            .is_some_and(|value| value.as_str().is_none_or(|s| !hex(s, 64)))
        {
            return Err(format!("syzygy-flag-{name}-invalid sbin"));
        }
    }
    Ok(())
}

pub(crate) fn resolve_sbin(seat: &super::mint_seats::Seat) -> Observation {
    let mut observed = Observation {
        selected: None,
        signal: "syzygy-flag-absent sbin".into(),
        malformed_flags: 0,
        credential: "absent",
        refusals: Vec::new(),
    };
    let credential = match crate::atoms::forge_credential::credential_for_url(SBIN_RELEASES) {
        Ok(value) => value,
        Err(reason) => {
            observed.signal = "syzygy-flag-unresolvable sbin".into();
            observed.refusals.push(json!({"signal": reason}));
            return observed;
        }
    };
    observed.credential = if credential.is_some() {
        "present"
    } else {
        "absent"
    };
    let token = credential
        .as_ref()
        .map(|credential| credential.token.as_str());
    let mut releases = Vec::new();
    // Same bounded listing observation as the beam: five pages, fifty rows.
    for page in 1..=5 {
        let response = get(&format!("{SBIN_RELEASES}?limit=50&page={page}"), token);
        let bytes = match response {
            Ok((404, _)) => break,
            Ok((200..=299, bytes)) => bytes,
            _ => {
                observed.signal = "syzygy-flag-unresolvable sbin".into();
                return observed;
            }
        };
        let listing = match serde_json::from_slice::<Value>(&bytes) {
            Ok(Value::Array(listing)) => listing,
            _ => {
                observed.signal = "syzygy-flag-unresolvable sbin".into();
                return observed;
            }
        };
        let count = listing.len();
        releases.extend(listing.into_iter().filter(|release| {
            release
                .get("tag_name")
                .and_then(Value::as_str)
                .is_some_and(|tag| hex(tag, 40))
        }));
        if count < 50 {
            break;
        }
    }
    let created = |release: &Value| {
        release
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    releases.sort_by_key(|release| std::cmp::Reverse(created(release)));
    let mut seen = std::collections::BTreeSet::new();
    for release in releases
        .into_iter()
        .filter(|release| seen.insert(release["tag_name"].as_str().unwrap_or_default().to_owned()))
        .take(20)
    {
        let tag = release["tag_name"].as_str().unwrap_or_default();
        let assets = release.get("assets").and_then(Value::as_array);
        for asset in assets
            .into_iter()
            .flatten()
            .filter(|asset| asset.get("name").and_then(Value::as_str) == Some("release.flag"))
        {
            let Some(url) = asset
                .get("browser_download_url")
                .and_then(Value::as_str)
                .filter(|url| !url.trim().is_empty())
            else {
                observed.malformed_flags += 1;
                observed.refusals.push(
                    json!({"tag":tag,"signal":"syzygy-flag-asset-url-missing sbin","asset":asset}),
                );
                continue;
            };
            let bytes = match get(url, token) {
                Ok((404, _)) => continue,
                Ok((200..=299, bytes)) => bytes,
                _ => {
                    observed.signal = "syzygy-flag-unresolvable sbin".into();
                    return observed;
                }
            };
            let flag = match serde_json::from_slice::<Value>(&bytes) {
                Ok(flag) => flag,
                Err(_) => {
                    observed.malformed_flags += 1;
                    observed
                        .refusals
                        .push(json!({"tag":tag,"signal":"syzygy-flag-json-malformed sbin"}));
                    continue;
                }
            };
            if let Err(signal) = validate(&flag, tag, seat) {
                observed.malformed_flags += 1;
                observed
                    .refusals
                    .push(json!({"tag":tag,"signal":signal,"flag":flag}));
                continue;
            }
            if observed.selected.as_ref().is_none_or(|previous| {
                flag.get("flagged_at").and_then(Value::as_str)
                    > previous.get("flagged_at").and_then(Value::as_str)
            }) {
                observed.selected = Some(flag);
            }
        }
    }
    if observed.selected.is_some() {
        observed.signal = "none".into();
    }
    observed
}
