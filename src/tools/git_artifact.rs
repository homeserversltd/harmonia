pub(crate) use crate::atoms::git_artifact::scoped_request;
pub use crate::atoms::git_artifact::*;
pub(crate) use crate::pull_repo::acquire_source;

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleaseRequest {
    pub kind: String,
    pub base_url: String,
    pub owner: String,
    pub repo: String,
    pub credential_token_path: Option<PathBuf>,
    pub credential_scope_found: bool,
    pub cache_dir: PathBuf,
}

pub(crate) fn fetch_release_asset(
    request: &ReleaseRequest,
    tag: &str,
    asset_name: &str,
    apply: bool,
) -> Result<crate::CmdResult, String> {
    if !matches!(request.kind.as_str(), "forgejo-release" | "github-release")
        || !safe_release_segment(tag)
        || !safe_release_segment(&request.owner)
        || !safe_release_segment(&request.repo)
        || !safe_asset_name(asset_name)
    {
        return Ok(miss("release-declaration-incomplete"));
    }
    if !apply {
        return Ok(crate::CmdResult {
            ok: true,
            code: 0,
            stdout: format!("release-asset-planned tag={tag} asset={asset_name}"),
            stderr: String::new(),
        });
    }
    if request.kind == "forgejo-release" && !request.credential_scope_found {
        return Ok(miss("release-credential-scope-missing"));
    }
    let base = request.base_url.trim_end_matches('/');
    let api = if request.kind == "forgejo-release" && !base.ends_with("/api/v1") {
        format!("{base}/api/v1")
    } else {
        base.to_string()
    };
    let metadata_url = release_metadata_url(&api, &request.owner, &request.repo, tag);
    fs::create_dir_all(&request.cache_dir)
        .map_err(|e| format!("release-cache-create-failed: {e}"))?;
    let metadata = run_curl(
        &curl_args(&metadata_url, "/dev/stdout"),
        request.credential_token_path.as_deref(),
    )?;
    if !metadata.ok {
        return Ok(metadata);
    }
    let asset_url = serde_json::from_str::<serde_json::Value>(&metadata.stdout)
        .ok()
        .and_then(|v| {
            v.get("assets")?
                .as_array()?
                .iter()
                .find(|a| a.get("name").and_then(serde_json::Value::as_str) == Some(asset_name))
                .and_then(|a| a.get("browser_download_url").or_else(|| a.get("url")))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        });
    let Some(asset_url) = asset_url else {
        return Ok(miss(format!(
            "release-asset-missing tag={tag} asset={asset_name}"
        )));
    };
    let destination = request.cache_dir.join(asset_name);
    let temp = request
        .cache_dir
        .join(format!(".{asset_name}.download-{}", std::process::id()));
    let download = match run_curl(
        &curl_args(&asset_url, &temp.to_string_lossy()),
        request.credential_token_path.as_deref(),
    ) {
        Ok(result) => result,
        Err(error) => {
            let _ = fs::remove_file(&temp);
            return Ok(miss(error));
        }
    };
    if !download.ok {
        let _ = fs::remove_file(&temp);
        return Ok(download);
    }
    if let Err(e) = fs::rename(&temp, &destination) {
        let _ = fs::remove_file(&temp);
        return Ok(miss(format!("release-asset-promote-failed: {e}")));
    }
    Ok(download)
}
fn release_metadata_url(api: &str, owner: &str, repo: &str, tag: &str) -> String {
    format!("{api}/repos/{owner}/{repo}/releases/tags/{tag}")
}

fn curl_args(url: &str, output: &str) -> Vec<String> {
    vec![
        "-fsSL".into(),
        "--max-time".into(),
        "120".into(),
        "-o".into(),
        output.into(),
        url.into(),
    ]
}
fn miss(message: impl Into<String>) -> crate::CmdResult {
    crate::CmdResult {
        ok: false,
        code: 22,
        stdout: String::new(),
        stderr: message.into(),
    }
}

fn safe_release_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .chars()
            .all(|character| !character.is_control() && character != '/' && character != '\\')
}

fn safe_asset_name(value: &str) -> bool {
    safe_release_segment(value) && !value.contains('/') && !value.contains('\\')
}

pub(crate) fn parse_forgejo_token(contents: &str) -> Result<String, String> {
    contents
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("FORGEJO_TOKEN=")
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
        })
        .ok_or_else(|| "forgejo-token-empty".into())
}

fn run_curl(
    args: &[String],
    token_path: Option<&std::path::Path>,
) -> Result<crate::CmdResult, String> {
    let header = if let Some(path) = token_path {
        let contents = fs::read_to_string(path)
            .map_err(|e| format!("release-token-unavailable {}: {e}", path.display()))?;
        let token = parse_forgejo_token(&contents)
            .map_err(|e| format!("release-token-invalid {}: {e}", path.display()))?;
        Some(format!("Authorization: token {token}\n"))
    } else {
        None
    };
    let mut command = Command::new("/usr/bin/curl");
    command.args(args);
    if header.is_some() {
        command.args(["-H", "@-"]);
        command.stdin(Stdio::piped());
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| format!("release-curl-start-failed: {e}"))?;
    if let Some(header) = header {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "release-curl-stdin-unavailable".to_string())?;
        stdin
            .write_all(header.as_bytes())
            .map_err(|e| format!("release-token-delivery-failed: {e}"))?;
    }
    let o = child
        .wait_with_output()
        .map_err(|e| format!("release-curl-wait-failed: {e}"))?;
    Ok(crate::CmdResult {
        ok: o.status.success(),
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&o.stderr).trim().to_string(),
    })
}

pub fn plan(request: &Request) -> Outcome {
    crate::pull_repo::plan(request)
}
pub fn stdout_changed(stdout: &str) -> bool {
    stdout.lines().any(|line| line.trim() == "changed=true")
}

#[cfg(test)]
mod tests {
    use super::{parse_forgejo_token, release_metadata_url, safe_asset_name, safe_release_segment};

    #[test]
    fn token_parser_ignores_username() {
        assert_eq!(
            parse_forgejo_token("username=owner\nFORGEJO_TOKEN=secret\n").unwrap(),
            "secret"
        );
    }

    #[test]
    fn release_url_uses_safe_segments() {
        assert_eq!(
            release_metadata_url(
                "https://git.home.arpa/api/v1",
                "HOMESERVERSLTD",
                "harmonia",
                "0.1.1"
            ),
            "https://git.home.arpa/api/v1/repos/HOMESERVERSLTD/harmonia/releases/tags/0.1.1"
        );
        assert!(!safe_release_segment("../escape"));
        assert!(!safe_asset_name("nested/file"));
        assert!(safe_asset_name("harmonia-0.1.1-x86_64"));
    }
}
