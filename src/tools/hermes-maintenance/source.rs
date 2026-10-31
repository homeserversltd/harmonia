//! Ordered declared source selection for the native Hermes updater.
use super::{official_url, run_owner_command, OFFICIAL_URL};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub(super) struct Candidate {
    pub url: String,
    pub selector: Option<String>,
    pub refused: bool,
}

#[derive(Clone, Debug)]
pub(super) struct Catalog {
    pub candidates: Vec<Candidate>,
    pub declared: bool,
}

#[derive(Clone, Debug)]
pub(super) struct Selection {
    pub candidate: Candidate,
    pub target_sha: String,
    pub skipped: Vec<String>,
    pub catalog: Catalog,
}

fn safe_url(value: &str) -> bool {
    if value.is_empty() || value.starts_with('-') || value.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        || value.contains('?') || value.contains('#') || value.contains('\\') {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if ["token=", "secret=", "password=", "private_key", "access_key"].iter().any(|marker| lower.contains(marker)) {
        return false;
    }
    if let Some(rest) = value.strip_prefix("https://") {
        let authority = rest.split('/').next().unwrap_or("");
        return !authority.is_empty() && !authority.contains('@') && rest.contains('/');
    }
    if let Some(rest) = value.strip_prefix("ssh://") {
        let authority = rest.split('/').next().unwrap_or("");
        return !authority.is_empty() && (!authority.contains('@') || authority.strip_prefix("git@").is_some_and(|host| !host.is_empty() && !host.contains('@'))) && rest.contains('/');
    }
    value.starts_with("git@") && value.contains(':') && value.contains('/')
}

fn normalized(value: &str) -> &str {
    value.trim_end_matches('/').strip_suffix(".git").unwrap_or(value.trim_end_matches('/'))
}

impl Catalog {
    pub fn load() -> Result<Self, String> {
        let path = crate::bands::pull_source::appliance_config_path();
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::fallback()),
            Err(_) => return Err("source-declaration-unreadable".into()),
        };
        let config: Value = serde_json::from_slice(&bytes).map_err(|_| "source-declaration-invalid")?;
        if !config.is_object() {
            return Err("source-declaration-invalid".into());
        }
        let sources = match config.get("sources") {
            None | Some(Value::Null) => return Ok(Self::fallback()),
            Some(Value::Object(sources)) => sources,
            _ => return Err("source-declaration-invalid".into()),
        };
        let Some(declaration) = sources.get("hermes-agent") else {
            return Ok(Self::fallback());
        };
        match declaration.get("ref") {
            None | Some(Value::Null) => {}
            Some(Value::String(value)) if value == "main" => {}
            _ => return Err("upstream-branch-must-be-main".into()),
        }
        let entries = declaration.get("candidates").and_then(Value::as_array).ok_or("source-candidates-invalid")?;
        if entries.is_empty() {
            return Err("upstream-main-resolution-failed".into());
        }
        let mut candidates = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            let url = entry.get("url").and_then(Value::as_str).filter(|url| safe_url(url));
            let selector = entry.get("credential_selector").and_then(Value::as_str);
            let selector_valid = entry.get("credential_selector").is_none_or(|value| value.is_null() || value.as_str() == Some("owner-forge-ssh"));
            let refused = entry.get("kind").and_then(Value::as_str) != Some("git") || url.is_none() || !selector_valid;
            candidates.push(Candidate {
                url: url.map(str::to_owned).unwrap_or_else(|| format!("candidate-{}", index + 1)),
                selector: selector.map(str::to_owned),
                refused,
            });
        }
        Ok(Self { candidates, declared: true })
    }

    fn fallback() -> Self {
        Self { candidates: vec![Candidate { url: OFFICIAL_URL.into(), selector: None, refused: false }], declared: false }
    }

    pub fn allows(&self, url: &str) -> bool {
        official_url(url) || self.candidates.iter().any(|candidate| !candidate.refused && normalized(&candidate.url) == normalized(url))
    }

    pub fn select(&self, skipped: &mut Vec<String>) -> Result<Selection, String> {
        skipped.clear();
        for candidate in &self.candidates {
            if candidate.refused {
                skipped.push(format!("{}: refused", candidate.url));
                continue;
            }
            let env = match git_environment(candidate) {
                Ok(env) => env,
                Err(_) => { skipped.push(format!("{}: refused", candidate.url)); continue; }
            };
            let output = run_owner_command("git", &["ls-remote", "--refs", &candidate.url, "refs/heads/main"], None, env, 30);
            match output {
                Ok(output) if output.status.success() => {
                    let text = std::str::from_utf8(&output.stdout).unwrap_or("");
                    if let Some(sha) = crate::atoms::git_artifact::parse_declared_remote_head(text, "refs/heads/main") {
                        return Ok(Selection { candidate: candidate.clone(), target_sha: sha, skipped: skipped.clone(), catalog: self.clone() });
                    }
                    skipped.push(format!("{}: no main", candidate.url));
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
                    let refused = ["authentication failed", "access denied", "permission denied", "authorization failed", "http 401", "http 403", "error: 401", "error: 403", "returned error: 401", "returned error: 403"]
                        .iter().any(|signal| stderr.contains(signal));
                    skipped.push(format!("{}: {}", candidate.url, if refused { "refused" } else { "unreachable" }));
                }
                Err(_) => skipped.push(format!("{}: unreachable", candidate.url)),
            }
        }
        Err("upstream-main-resolution-failed".into())
    }
}

pub(super) fn git_environment(candidate: &Candidate) -> Result<BTreeMap<String, String>, String> {
    let host = crate::atoms::git_artifact::git_source_host(&candidate.url);
    let is_forge = host.as_deref() == Some(crate::atoms::forge_credential::ESTATE_FORGEJO_HOST);
    if candidate.selector.is_some() && !is_forge {
        return Err("source-candidate-selector-host-mismatch".into());
    }
    let mut env = BTreeMap::from([
        ("GIT_TERMINAL_PROMPT".into(), "0".into()),
        ("GIT_OPTIONAL_LOCKS".into(), "0".into()),
        ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
        ("GIT_CONFIG_GLOBAL".into(), "/dev/null".into()),
        ("GIT_SSH_COMMAND".into(), "ssh -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none -o IdentityFile=none".into()),
        ("GIT_CONFIG_COUNT".into(), "1".into()),
        ("GIT_CONFIG_KEY_0".into(), "credential.helper".into()),
        ("GIT_CONFIG_VALUE_0".into(), "".into()),
    ]);
    if is_forge && candidate.selector.is_some() {
        let request = crate::atoms::git_artifact::Request::new(Some(candidate.url.clone()), PathBuf::new(), "main".into(), "origin".into())
            .with_credential_selector(candidate.selector.clone());
        let context = crate::atoms::git_artifact::git_command_context(&request)?;
        if !context.env.contains_key("HARMONIA_FORGEJO_TOKEN") {
            return Err("source-candidate-credential-unavailable".into());
        }
        env.extend(context.env);
        let configs = context.config_args.chunks_exact(2).map(|pair| pair[1].split_once('=').ok_or("git-config-invalid")).collect::<Result<Vec<_>, _>>()?;
        env.insert("GIT_CONFIG_COUNT".into(), configs.len().to_string());
        for (index, (key, value)) in configs.iter().enumerate() {
            env.insert(format!("GIT_CONFIG_KEY_{index}"), (*key).to_owned());
            env.insert(format!("GIT_CONFIG_VALUE_{index}"), (*value).to_owned());
        }
    }
    Ok(env)
}
