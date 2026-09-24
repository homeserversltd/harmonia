pub(crate) use crate::atoms::git_artifact::scoped_request;
pub use crate::atoms::git_artifact::*;
pub(crate) use crate::pull_repo::acquire_source;

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const INSPECTION_MAX_BODY_BYTES: &str = "67108864";
const INSPECTION_OVERSIZE_BLOCKER: &str = "release-inspection-fetch-oversize max_bytes=67108864";

pub(crate) fn unique_temp_suffix() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleaseRequest {
    pub kind: String,
    pub base_url: String,
    pub owner: String,
    pub repo: String,
    pub credential: Option<crate::atoms::forge_credential::Credential>,
    pub credential_host: Option<String>,
    pub credential_scope_found: bool,
    pub cache_dir: PathBuf,
}

impl ReleaseRequest {
    fn credential_for_url<'a>(
        &'a self,
        url: &str,
    ) -> Option<&'a crate::atoms::forge_credential::Credential> {
        let host = crate::atoms::forge_credential::url_host(url)?;
        (self.credential_host.as_deref() == Some(host.as_str()))
            .then_some(self.credential.as_ref())
            .flatten()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ReleaseAssets {
    pub artifact: Vec<u8>,
    pub sidecar: Vec<u8>,
    pub release_flag: Option<Vec<u8>>,
    pub metadata_url: String,
    pub target_commitish: String,
}
struct ReleaseMetadata {
    url: String,
    target_commitish: String,
    assets: serde_json::Value,
}
fn release_api(r: &ReleaseRequest) -> String {
    let b = r.base_url.trim_end_matches('/');
    if r.kind == "forgejo-release" && !b.ends_with("/api/v1") {
        format!("{b}/api/v1")
    } else {
        b.to_string()
    }
}
fn lookup_release_metadata(
    r: &ReleaseRequest,
    tag: &str,
) -> Result<Option<ReleaseMetadata>, String> {
    lookup_release_metadata_inner(r, tag, false)
}
fn lookup_release_metadata_inner(
    r: &ReleaseRequest,
    tag: &str,
    inspection_bounds: bool,
) -> Result<Option<ReleaseMetadata>, String> {
    if let Some(source_sha) = source_sha_from_release_tag(tag) {
        let sha_tag = release_tag_for_source_sha(source_sha).expect("validated source SHA");
        if let Some(release) = lookup_release_metadata_single(r, &sha_tag, inspection_bounds)? {
            return Ok(Some(release));
        }
        return lookup_release_metadata_single(r, source_sha, inspection_bounds);
    }
    lookup_release_metadata_single(r, tag, inspection_bounds)
}

fn lookup_release_metadata_single(
    r: &ReleaseRequest,
    tag: &str,
    inspection_bounds: bool,
) -> Result<Option<ReleaseMetadata>, String> {
    let url = release_metadata_url(&release_api(r), &r.owner, &r.repo, tag);
    fs::create_dir_all(&r.cache_dir).map_err(|e| format!("release-cache-create-failed: {e}"))?;
    let path = r
        .cache_dir
        .join(format!(".metadata-{}", unique_temp_suffix()));
    let mut args = if inspection_bounds {
        inspection_curl_args(&url, &path.to_string_lossy())
    } else {
        curl_args(&url, &path.to_string_lossy())
    };
    args.extend(["-w".into(), "%{http_code}".into()]);
    let result = run_curl(&args, r.credential_for_url(&url))?;
    if result.stdout.trim() == "404" {
        let _ = fs::remove_file(&path);
        return Ok(None);
    }
    if inspection_bounds && result.code == 63 {
        let _ = fs::remove_file(&path);
        return Err(INSPECTION_OVERSIZE_BLOCKER.into());
    }
    if !result.ok {
        let _ = fs::remove_file(&path);
        let error = format!("release-metadata-fetch-failed: {}", result.stderr);
        let error_with_status = format!("{error} http_status={}", result.stdout.trim());
        return Err(if r.credential_for_url(&url).is_none() {
            crate::atoms::ask::fetch_artifact::normalize_auth_required_error(
                &error_with_status,
                &url,
            )
            .unwrap_or(error)
        } else {
            error
        });
    }
    let text =
        fs::read_to_string(&path).map_err(|e| format!("release-metadata-read-failed: {e}"))?;
    let _ = fs::remove_file(&path);
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("release-metadata-malformed: {e}"))?;
    let target_commitish = value
        .get("target_commitish")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_owned();
    let assets = value
        .get("assets")
        .cloned()
        .ok_or_else(|| "release-assets-missing".to_string())?;
    Ok(Some(ReleaseMetadata {
        url,
        target_commitish,
        assets,
    }))
}
fn release_asset_url(m: &ReleaseMetadata, tag: &str, name: &str) -> Result<String, String> {
    m.assets
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|x| x.get("name").and_then(serde_json::Value::as_str) == Some(name))
        })
        .and_then(|x| x.get("browser_download_url").or_else(|| x.get("url")))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("release-asset-missing tag={tag} asset={name}"))
}
fn optional_release_asset_url(m: &ReleaseMetadata, name: &str) -> Option<String> {
    let asset = m
        .assets
        .as_array()?
        .iter()
        .find(|asset| asset.get("name").and_then(serde_json::Value::as_str) == Some(name))?;
    asset
        .get("browser_download_url")
        .or_else(|| asset.get("url"))?
        .as_str()
        .map(str::to_owned)
}
fn download_release_asset(
    r: &ReleaseRequest,
    url: &str,
    name: &str,
    inspection_bounds: bool,
) -> Result<Vec<u8>, String> {
    let p = r
        .cache_dir
        .join(format!(".{name}-{}", unique_temp_suffix()));
    let args = if inspection_bounds {
        inspection_curl_args(url, &p.to_string_lossy())
    } else {
        curl_args(url, &p.to_string_lossy())
    };
    let x = run_curl(&args, r.credential_for_url(url))?;
    if inspection_bounds && x.code == 63 {
        let _ = fs::remove_file(&p);
        return Err(INSPECTION_OVERSIZE_BLOCKER.into());
    }
    if !x.ok {
        let _ = fs::remove_file(&p);
        let error = format!("release-asset-fetch-failed: {}", x.stderr);
        return Err(if r.credential_for_url(&url).is_none() {
            crate::atoms::ask::fetch_artifact::normalize_auth_required_error(&error, url)
                .unwrap_or(error)
        } else {
            error
        });
    }
    let b = fs::read(&p).map_err(|e| format!("release-asset-read-failed: {e}"))?;
    let _ = fs::remove_file(&p);
    Ok(b)
}
pub(crate) fn fetch_release_assets(
    r: &ReleaseRequest,
    tag: &str,
    asset_name: &str,
    sidecar_name: &str,
) -> Result<Option<ReleaseAssets>, String> {
    fetch_release_assets_inner(r, tag, asset_name, sidecar_name, false, true)
}
pub(crate) fn fetch_release_assets_for_inspection(
    r: &ReleaseRequest,
    tag: &str,
    asset_name: &str,
    sidecar_name: &str,
) -> Result<Option<ReleaseAssets>, String> {
    fetch_release_assets_inner(r, tag, asset_name, sidecar_name, true, false)
}
fn fetch_release_assets_inner(
    r: &ReleaseRequest,
    tag: &str,
    asset_name: &str,
    sidecar_name: &str,
    inspect_release_flag: bool,
    require_tag_commitish_match: bool,
) -> Result<Option<ReleaseAssets>, String> {
    if r.kind != "forgejo-release"
        || !safe_release_segment(tag)
        || !safe_release_segment(&r.owner)
        || !safe_release_segment(&r.repo)
        || !safe_asset_name(asset_name)
        || !safe_asset_name(sidecar_name)
    {
        return Err("release-declaration-incomplete".into());
    }
    let Some(m) = lookup_release_metadata_inner(r, tag, inspect_release_flag)? else {
        return Ok(None);
    };
    let expected_commit = source_sha_from_release_tag(tag);
    if expected_commit.is_some_and(|source_sha| m.target_commitish != source_sha)
        || (require_tag_commitish_match
            && expected_commit.is_none()
            && m.target_commitish != tag)
    {
        return Err("fetch-artifact-release-commit-mismatch".into());
    }
    let au = release_asset_url(&m, tag, asset_name)?;
    let su = release_asset_url(&m, tag, sidecar_name)?;
    let release_flag = inspect_release_flag
        .then(|| optional_release_asset_url(&m, "release.flag"))
        .flatten()
        .map(|url| download_release_asset(r, &url, "release.flag", inspect_release_flag))
        .transpose()?;
    Ok(Some(ReleaseAssets {
        artifact: download_release_asset(r, &au, asset_name, inspect_release_flag)?,
        sidecar: download_release_asset(r, &su, sidecar_name, inspect_release_flag)?,
        release_flag,
        metadata_url: m.url,
        target_commitish: m.target_commitish,
    }))
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
    let Some(metadata) = (match lookup_release_metadata(request, tag) {
        Ok(v) => v,
        Err(e) => return Ok(miss(e)),
    }) else {
        return Ok(miss(format!("release-absent tag={tag}")));
    };
    if metadata.target_commitish != source_sha_from_release_tag(tag).unwrap_or(tag) {
        return Ok(miss("fetch-artifact-release-commit-mismatch"));
    }
    let url = match release_asset_url(&metadata, tag, asset_name) {
        Ok(v) => v,
        Err(e) => return Ok(miss(e)),
    };
    let destination = request.cache_dir.join(asset_name);
    let temp = request
        .cache_dir
        .join(format!(".{asset_name}.download-{}", unique_temp_suffix()));
    let bytes = match download_release_asset(request, &url, asset_name, false) {
        Ok(v) => v,
        Err(e) => return Ok(miss(e)),
    };
    if let Err(e) = fs::write(&temp, bytes).and_then(|_| fs::rename(&temp, &destination)) {
        let _ = fs::remove_file(&temp);
        return Ok(miss(format!("release-asset-promote-failed: {e}")));
    }
    Ok(crate::CmdResult {
        ok: true,
        code: 0,
        stdout: String::new(),
        stderr: String::new(),
    })
}
fn release_metadata_url(api: &str, owner: &str, repo: &str, tag: &str) -> String {
    format!("{api}/repos/{owner}/{repo}/releases/tags/{tag}")
}

pub(crate) fn release_tag_for_source_sha(source_sha: &str) -> Option<String> {
    (source_sha.len() == 40
        && source_sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| format!("sha-{source_sha}"))
}

pub(crate) fn source_sha_from_release_tag(tag: &str) -> Option<&str> {
    let source_sha = tag.strip_prefix("sha-").unwrap_or(tag);
    (source_sha.len() == 40
        && source_sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(source_sha)
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
fn inspection_curl_args(url: &str, output: &str) -> Vec<String> {
    vec![
        "-fsSL".into(),
        "--connect-timeout".into(),
        "5".into(),
        "--max-time".into(),
        "120".into(),
        "--max-filesize".into(),
        INSPECTION_MAX_BODY_BYTES.into(),
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

fn run_curl(
    args: &[String],
    credential: Option<&crate::atoms::forge_credential::Credential>,
) -> Result<crate::CmdResult, String> {
    let header = credential.map(|credential| {
        format!("Authorization: token {}\n", credential.token)
    });
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
    use super::{release_metadata_url, safe_asset_name, safe_release_segment};

    #[test]
    fn release_metadata_request_carries_configured_authorization() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let length = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..length]);
            assert!(request.contains("Authorization: token test-token"));
            let body = r#"{"target_commitish":"tag","assets":[]}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let root =
            std::env::temp_dir().join(format!("harmonia-release-auth-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let request = super::ReleaseRequest {
            kind: "forgejo-release".into(),
            base_url: format!("http://{address}/api/v1"),
            owner: "OWNER".into(),
            repo: "REPO".into(),
            credential: Some(crate::atoms::forge_credential::Credential {
                username: "owner".into(),
                token: "test-token".into(),
            }),
            credential_host: Some(address.ip().to_string()),
            credential_scope_found: true,
            cache_dir: root.join("cache"),
        };
        let metadata = super::lookup_release_metadata(&request, "tag").unwrap();
        println!("trace release credential=present header=present token=redacted");
        assert!(metadata.is_some());
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn sha_release_lookup_falls_back_to_bare_source_tag_after_404() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let source_sha = "0123456789abcdef0123456789abcdef01234567";
        let server = thread::spawn(move || {
            for (expected, status, body) in [
                (
                    format!("GET /api/v1/repos/OWNER/REPO/releases/tags/sha-{source_sha} "),
                    404,
                    String::new(),
                ),
                (
                    format!("GET /api/v1/repos/OWNER/REPO/releases/tags/{source_sha} "),
                    200,
                    format!(r#"{{"target_commitish":"{source_sha}","assets":[]}}"#),
                ),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 4096];
                let length = stream.read(&mut request).unwrap();
                assert!(String::from_utf8_lossy(&request[..length]).starts_with(&expected));
                let reason = if status == 404 { "Not Found" } else { "OK" };
                write!(
                    stream,
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        let root = std::env::temp_dir().join(format!("harmonia-release-fallback-{}", std::process::id()));
        let request = super::ReleaseRequest {
            kind: "forgejo-release".into(),
            base_url: format!("http://{address}/api/v1"),
            owner: "OWNER".into(),
            repo: "REPO".into(),
            credential: None,
            credential_host: None,
            credential_scope_found: false,
            cache_dir: root,
        };
        let metadata = super::lookup_release_metadata(&request, &format!("sha-{source_sha}"))
            .unwrap()
            .expect("bare-tag fallback should resolve");
        server.join().unwrap();
        assert_eq!(metadata.target_commitish, source_sha);
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
