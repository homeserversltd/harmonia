//! Observation and bounded acquisition for Forgejo generic artifacts.
use crate::atoms::git_artifact::{ReleaseAssets, ReleaseRequest};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::process::{Command, Stdio};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command as ReleaseCommand, Stdio as ReleaseStdio};
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

struct ReleaseMetadata {
    url: String,
    target_commitish: String,
    created_at: Option<String>,
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
    let url = release_metadata_url_for_request(&release_api(r), &r.owner, &r.repo, tag);
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
        created_at: value
            .get("created_at")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
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
    fetch_release_assets_inner(r, tag, asset_name, sidecar_name, false, true, false)
}
pub(crate) fn fetch_release_assets_for_inspection(
    r: &ReleaseRequest,
    tag: &str,
    asset_name: &str,
    sidecar_name: &str,
) -> Result<Option<ReleaseAssets>, String> {
    fetch_release_assets_inner(r, tag, asset_name, sidecar_name, true, false, false)
}
fn fetch_release_assets_for_pinned_inspection(
    r: &ReleaseRequest,
    tag: &str,
    asset_name: &str,
    sidecar_name: &str,
) -> Result<Option<ReleaseAssets>, String> {
    fetch_release_assets_inner(r, tag, asset_name, sidecar_name, true, false, true)
}
fn fetch_release_assets_inner(
    r: &ReleaseRequest,
    tag: &str,
    asset_name: &str,
    sidecar_name: &str,
    inspect_release_flag: bool,
    require_tag_commitish_match: bool,
    pin_to_target_commitish: bool,
) -> Result<Option<ReleaseAssets>, String> {
    Ok(fetch_release_assets_inner_with_created_at(
        r,
        tag,
        asset_name,
        sidecar_name,
        inspect_release_flag,
        require_tag_commitish_match,
        pin_to_target_commitish,
    )?
    .map(|(assets, _created_at)| assets))
}

fn fetch_release_assets_inner_with_created_at(
    r: &ReleaseRequest,
    tag: &str,
    asset_name: &str,
    sidecar_name: &str,
    inspect_release_flag: bool,
    require_tag_commitish_match: bool,
    pin_to_target_commitish: bool,
) -> Result<Option<(ReleaseAssets, Option<String>)>, String> {
    if !matches!(r.kind.as_str(), "forgejo-release" | "github-release")
        || !safe_release_segment(tag)
        || !safe_release_segment(&r.owner)
        || !safe_release_segment(&r.repo)
        || !safe_asset_name(asset_name)
        || !safe_asset_name(sidecar_name)
    {
        return Err("release-declaration-incomplete".into());
    }
    // Pinned discovery uses the listed tag only as an exact metadata locator.
    let metadata = if pin_to_target_commitish {
        lookup_release_metadata_single(r, tag, inspect_release_flag)?
    } else {
        lookup_release_metadata_inner(r, tag, inspect_release_flag)?
    };
    let Some(m) = metadata else {
        return Ok(None);
    };
    let created_at = m.created_at.clone();
    let expected_commit = source_sha_from_release_tag(tag);
    if !pin_to_target_commitish
        && (expected_commit.is_some_and(|source_sha| m.target_commitish != source_sha)
            || (require_tag_commitish_match
                && expected_commit.is_none()
                && m.target_commitish != tag))
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
    Ok(Some((
        ReleaseAssets {
            artifact: download_release_asset(r, &au, asset_name, inspect_release_flag)?,
            sidecar: download_release_asset(r, &su, sidecar_name, inspect_release_flag)?,
            release_flag,
            metadata_url: m.url,
            target_commitish: m.target_commitish,
        },
        created_at,
    )))
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
fn release_metadata_url_for_request(api: &str, owner: &str, repo: &str, tag: &str) -> String {
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
    let mut command = ReleaseCommand::new("/usr/bin/curl");
    command.args(args);
    if header.is_some() {
        command.args(["-H", "@-"]);
        command.stdin(ReleaseStdio::piped());
    }
    command.stdout(ReleaseStdio::piped()).stderr(ReleaseStdio::piped());
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


pub(crate) const MANIFEST_SCHEMA: &str = "estate.artifact.manifest.v1";
pub(crate) const DEFAULT_FORGE_API_ROOT: &str = "https://git.home.arpa/api/v1";
pub(crate) const DEFAULT_PROFILE_SOURCE: &str = "/etc/appliance/profile.json";
pub(crate) const PROFILE_AXIS: &str = "profile";
pub(crate) const BUILD_TARGET: &str = "x86_64-unknown-linux-gnu";
const MAX_STDERR_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: &str = "67108864";

fn trim_trailing_crlf(value: &str) -> &str {
    value.trim_end_matches(|character: char| character == '\r' || character == '\n')
}

fn release_api_root(api_root: &str) -> String {
    let base = api_root.trim_end_matches('/');
    if base.ends_with("/api/v1") {
        base.to_owned()
    } else {
        format!("{base}/api/v1")
    }
}

pub(crate) fn release_metadata_url(api_root: &str, release_repo: &str, tag: &str) -> String {
    let (owner, repo) = release_repo.split_once('/').unwrap_or((release_repo, ""));
    let tag = crate::atoms::ask::fetch_artifact::source_sha_from_release_tag(tag)
        .and_then(crate::atoms::ask::fetch_artifact::release_tag_for_source_sha)
        .unwrap_or_else(|| tag.to_owned());
    format!(
        "{}/repos/{owner}/{repo}/releases/tags/{tag}",
        release_api_root(api_root)
    )
}

pub(crate) fn is_http_status(error: &str, status: &str) -> bool {
    error
        .split(|character: char| !character.is_ascii_digit())
        .any(|part| part == status)
}

fn has_optional_detail(error: &str, prefix: &str) -> bool {
    error == prefix
        || error
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with(':') || rest.starts_with(' '))
}

pub(crate) fn auth_required_url(error: &str, fallback_url: &str) -> Option<String> {
    for prefix in [
        "fetch-artifact-auth-required url=",
        "fetch-artifact-auth-required-non-estate-registry url=",
    ] {
        if let Some(url) = error.strip_prefix(prefix) {
            return Some(if url.is_empty() {
                fallback_url.to_owned()
            } else {
                url.to_owned()
            });
        }
    }
    if error == "fetch-artifact-auth-required"
        || error == "fetch-artifact-auth-required-non-estate-registry"
    {
        return Some(fallback_url.to_owned());
    }
    if has_optional_detail(error, "fetch-artifact-registry-refused-401")
        || has_optional_detail(error, "fetch-artifact-registry-refused-403")
    {
        return Some(fallback_url.to_owned());
    }
    if (has_optional_detail(error, "release-metadata-fetch-failed")
        || has_optional_detail(error, "release-asset-fetch-failed")
        || has_optional_detail(error, "release-asset-download-failed"))
        && (is_http_status(error, "401") || is_http_status(error, "403"))
    {
        return Some(fallback_url.to_owned());
    }
    None
}

pub(crate) fn normalize_auth_required_error(error: &str, fallback_url: &str) -> Option<String> {
    auth_required_url(error, fallback_url)
        .map(|url| format!("fetch-artifact-auth-required url={url}"))
}

pub(crate) fn build_environment_prefix(component: &str) -> String {
    let mut prefix = component
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    prefix.push('_');
    prefix
}

pub(crate) fn build_environment_variables(
    component: &str,
    source_build_sha: &str,
    environment_sha: &str,
) -> Vec<(String, String)> {
    let prefix = build_environment_prefix(component);
    vec![
        (format!("{prefix}BUILD_SHA"), source_build_sha.into()),
        (format!("{prefix}SOURCE_SHA"), source_build_sha.into()),
        (format!("{prefix}BUILD_ENV_SHA"), environment_sha.into()),
    ]
}

pub(crate) fn build_environment(
    component: &str,
    source_build_sha: &str,
) -> Result<(Vec<(String, String)>, String), String> {
    let rustc = crate::atoms::command::capture("rustc", &["-Vv"]);
    if !rustc.ok {
        return Err(format!(
            "fetch-artifact-build-rustc-version-failed: {}",
            rustc.stderr
        ));
    }
    let cargo = crate::atoms::command::capture("cargo", &["-V"]);
    if !cargo.ok {
        return Err(format!(
            "fetch-artifact-build-cargo-version-failed: {}",
            cargo.stderr
        ));
    }
    let material = format!(
        "{}
{}
{}
",
        trim_trailing_crlf(&rustc.stdout),
        trim_trailing_crlf(&cargo.stdout),
        BUILD_TARGET
    );
    let environment_sha = crate::atoms::file_sha256(material.as_bytes());
    Ok((
        build_environment_variables(component, source_build_sha, &environment_sha),
        environment_sha,
    ))
}

pub(crate) fn profile_axis_declared(args: &BTreeMap<String, Value>) -> Result<bool, String> {
    match args.get("profile_axis") {
        None => Ok(false),
        Some(value) if value.as_str() == Some(PROFILE_AXIS) => Ok(true),
        Some(_) => Err("fetch-artifact-profile-axis-invalid".into()),
    }
}

pub(crate) fn read_profile_source(path: &Path) -> Result<String, String> {
    let text = fs::read_to_string(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => "fetch-artifact-profile-source-missing",
        _ => "fetch-artifact-profile-source-unreadable",
    })?;
    let value: Value =
        serde_json::from_str(&text).map_err(|_| "fetch-artifact-profile-source-malformed")?;
    let profile = value
        .get("profile")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|profile| !profile.is_empty())
        .ok_or("fetch-artifact-profile-source-profile-missing")?;
    Ok(profile.to_owned())
}

pub(crate) fn resolved_profile_segment(profile: &str) -> Result<String, String> {
    validate_segment(profile, "profile")?;
    Ok(
        if ["homeserver", "homeconsole", "tv"]
            .iter()
            .any(|sold_profile| profile.eq_ignore_ascii_case(sold_profile))
        {
            profile.to_ascii_lowercase()
        } else {
            "probe".to_owned()
        },
    )
}

pub(crate) fn profile_release_names(
    artifact_name: &str,
    profile: &str,
    asset_name: Option<&str>,
    sidecar_name: Option<&str>,
) -> Result<(String, String), String> {
    validate_segment(profile, "profile")?;
    profile_release_names_for_segment(artifact_name, profile, asset_name, sidecar_name)
}

pub(crate) fn profile_release_names_for_segment(
    artifact_name: &str,
    resolved_profile_segment: &str,
    asset_name: Option<&str>,
    sidecar_name: Option<&str>,
) -> Result<(String, String), String> {
    let expected_asset = format!("{artifact_name}-{resolved_profile_segment}-x86_64");
    let expected_sidecar = format!("{expected_asset}.sha256");
    if asset_name.is_some_and(|name| name != expected_asset.as_str()) {
        return Err("fetch-artifact-profile-asset-name-mismatch".into());
    }
    if sidecar_name.is_some_and(|name| name != expected_sidecar.as_str()) {
        return Err("fetch-artifact-profile-sidecar-name-mismatch".into());
    }
    Ok((
        asset_name.unwrap_or(&expected_asset).to_owned(),
        sidecar_name.unwrap_or(&expected_sidecar).to_owned(),
    ))
}

fn hex_boundary(bytes: &[u8], start: usize, sha: &[u8]) -> bool {
    bytes.get(start..start + sha.len()) == Some(sha)
        && !bytes
            .get(start.wrapping_sub(1))
            .is_some_and(|b| b.is_ascii_hexdigit())
        && !bytes
            .get(start + sha.len())
            .is_some_and(|b| b.is_ascii_hexdigit())
}

pub(crate) fn identity_matches_bytes(
    bytes: &[u8],
    source_sha: &str,
    identity: &str,
    component: &str,
) -> bool {
    let marker = if identity == "embedded-sha" {
        None
    } else {
        Some(format!("{component}.liveness.v1").into_bytes())
    };
    if let Some(marker) = marker {
        // The marker anchors the compiled build-sha constant; the exact 40-hex
        // match is the identity (pali:harmonia-component-release-identity-law).
        // rustc packs string literals back to back, so the byte after the sha is
        // whatever literal follows (a real caduceus binary carries "caduceus-p...",
        // a hex digit) and is never a boundary signal here.
        return bytes.windows(marker.len()).enumerate().any(|(i, w)| {
            if w != marker {
                return false;
            }
            let start = i + marker.len();
            bytes.get(start..start + source_sha.len()) == Some(source_sha.as_bytes())
        });
    }
    bytes
        .windows(source_sha.len())
        .enumerate()
        .any(|(i, _)| hex_boundary(bytes, i, source_sha.as_bytes()))
}

pub(crate) fn identity_matches(
    destination: &Path,
    source_sha: &str,
    identity: &str,
    component: &str,
) -> bool {
    fs::read(destination)
        .is_ok_and(|bytes| identity_matches_bytes(&bytes, source_sha, identity, component))
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub(crate) struct Manifest {
    pub schema: String,
    pub component: String,
    pub source_sha: String,
    pub target: String,
    pub sha256: String,
    pub built_at: String,
    pub pipeline_url: String,
    /// BeamPair toolchain identity minted by CI (pali:harmonia-beam-syzygy-law):
    /// sha256(rustc -Vv || cargo -V || target triple). Optional so manifests
    /// published before 2026-09-02 still parse; when present it SHALL be 64-hex.
    #[serde(default)]
    pub env_sha: Option<String>,
    #[serde(default)]
    pub rustc_version: Option<String>,
}
#[derive(Debug, Clone)]
pub(crate) struct Download {
    pub manifest: Manifest,
    pub bytes: Vec<u8>,
    pub identity: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ReleaseInspection {
    pub resolved_revision: String,
    pub digest: String,
    pub version: Option<Value>,
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_hexdigit())
}
pub(crate) fn validate_source_sha(value: &str) -> bool {
    is_hex(value, 40)
}
fn validate_segment(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.contains('\0')
    {
        return Err(format!("fetch-artifact-{field}-invalid"));
    }
    Ok(())
}

pub(crate) fn validate_manifest(
    manifest: &Manifest,
    expected_component: &str,
    expected_source_sha: &str,
) -> Result<(), String> {
    if manifest.schema != MANIFEST_SCHEMA {
        return Err("fetch-artifact-manifest-schema-mismatch".into());
    }
    if manifest.component != expected_component {
        return Err("fetch-artifact-manifest-component-mismatch".into());
    }
    if manifest.source_sha != expected_source_sha || !validate_source_sha(&manifest.source_sha) {
        return Err("fetch-artifact-manifest-source-sha-mismatch".into());
    }
    if !is_hex(&manifest.sha256, 64) {
        return Err("fetch-artifact-manifest-sha256-malformed".into());
    }
    if let Some(env_sha) = manifest.env_sha.as_deref() {
        if !is_hex(env_sha, 64) {
            return Err("fetch-artifact-manifest-env-sha-malformed".into());
        }
    }
    for (value, field) in [
        (&manifest.target, "target"),
        (&manifest.built_at, "built-at"),
        (&manifest.pipeline_url, "pipeline-url"),
    ] {
        if value.trim().is_empty() {
            return Err(format!("fetch-artifact-manifest-{field}-missing"));
        }
    }
    Ok(())
}
pub(crate) fn artifact_url(base: &str, component: &str, source_sha: &str, name: &str) -> String {
    format!(
        "{}/{}/{}/{}",
        base.trim_end_matches('/'),
        component,
        source_sha,
        name
    )
}
fn curl_to_file(
    url: &str,
    destination: &Path,
    stderr_path: &Path,
    token: Option<&str>,
) -> Result<u16, String> {
    let mut command = Command::new("curl");
    command.args([
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--connect-timeout",
        "5",
        "--max-time",
        "30",
        "--max-filesize",
        MAX_BODY_BYTES,
        "--output",
        destination.to_str().ok_or("fetch-artifact-path-invalid")?,
        "--stderr",
        stderr_path.to_str().ok_or("fetch-artifact-path-invalid")?,
        "--write-out",
        "%{http_code}",
        url,
    ]);
    let output = if let Some(token) = token {
        let escaped = token.replace('\\', "\\\\").replace('"', "\\\"");
        command
            .arg("--config")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|e| format!("fetch-artifact-registry-unreachable: {e}"))?;
        child
            .stdin
            .take()
            .ok_or_else(|| "fetch-artifact-auth-config-failed".to_string())?
            .write_all(format!("header = \"Authorization: token {escaped}\"\n").as_bytes())
            .map_err(|e| format!("fetch-artifact-auth-config-failed: {e}"))?;
        child.wait_with_output()
    } else {
        command.output()
    };
    let output = output.map_err(|e| format!("fetch-artifact-registry-unreachable: {e}"))?;
    let status = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u16>()
        .unwrap_or(0);
    if token.is_none() && (status == 401 || status == 403) {
        return Err(format!("fetch-artifact-auth-required url={url}"));
    }
    if !(200..300).contains(&status) || !output.status.success() {
        let stderr = fs::read(stderr_path).unwrap_or_default();
        let detail = String::from_utf8_lossy(&stderr[..stderr.len().min(MAX_STDERR_BYTES)])
            .trim()
            .to_string();
        return if detail.is_empty() {
            Err(format!("fetch-artifact-registry-refused-{status}"))
        } else {
            Err(format!(
                "fetch-artifact-registry-refused-{status}: {detail}"
            ))
        };
    }
    Ok(status)
}

fn curl_with_resolved_credential(
    url: &str,
    destination: &Path,
    credential_path: &Path,
    estate_host: &str,
) -> Result<u16, String> {
    // Credential placement and resolution obey pali:keyman-forgejo-token-one-place-law.
    let credential =
        match crate::atoms::forge_credential::resolve_for_url_at(url, credential_path, estate_host)
        {
            crate::atoms::forge_credential::Outcome::Present { token, .. } => Some(token),
            crate::atoms::forge_credential::Outcome::Absent => None,
            crate::atoms::forge_credential::Outcome::Err(reason) => return Err(reason),
        };
    let stderr_path = destination.with_extension("stderr");
    let result = curl_to_file(url, destination, &stderr_path, credential.as_deref());
    let _ = fs::remove_file(&stderr_path);
    result.map_err(|error| normalize_auth_required_error(&error, url).unwrap_or(error))
}

pub(crate) fn credential_state_for_url(url: &str) -> Result<&'static str, String> {
    match crate::atoms::forge_credential::resolve_for_url(url) {
        crate::atoms::forge_credential::Outcome::Present { .. } => Ok("present"),
        crate::atoms::forge_credential::Outcome::Absent => Ok("absent"),
        crate::atoms::forge_credential::Outcome::Err(reason) => Err(reason),
    }
}

pub(crate) fn download(
    component: &str,
    registry_base: &str,
    source_sha: &str,
    artifact_name: &str,
) -> Result<Download, String> {
    download_with_credential_source(
        component,
        registry_base,
        source_sha,
        artifact_name,
        Path::new(crate::atoms::forge_credential::ROOT_PLANE_FORGEJO_CREDENTIAL),
        crate::atoms::forge_credential::ESTATE_FORGEJO_HOST,
    )
}

#[cfg(test)]
pub(crate) fn download_with_credential_path(
    component: &str,
    registry_base: &str,
    source_sha: &str,
    artifact_name: &str,
    credential_path: &Path,
    estate_host: &str,
) -> Result<Download, String> {
    download_with_credential_source(
        component,
        registry_base,
        source_sha,
        artifact_name,
        credential_path,
        estate_host,
    )
}

fn download_with_credential_source(
    component: &str,
    registry_base: &str,
    source_sha: &str,
    artifact_name: &str,
    credential_path: &Path,
    estate_host: &str,
) -> Result<Download, String> {
    validate_segment(component, "component")?;
    validate_segment(artifact_name, "artifact-name")?;
    if !validate_source_sha(source_sha) {
        return Err("fetch-artifact-source-sha-invalid".into());
    }
    if registry_base.trim().is_empty() {
        return Err("fetch-artifact-registry-base-missing".into());
    }
    let directory = std::env::temp_dir().join(format!(
        "harmonia-fetch-{source_sha}-{}",
        unique_temp_suffix()
    ));
    fs::create_dir_all(&directory)
        .map_err(|e| format!("fetch-artifact-temp-create-failed: {e}"))?;
    let result = (|| {
        let manifest_path = directory.join("manifest.json");
        let artifact_path = directory.join("artifact");
        curl_with_resolved_credential(
            &artifact_url(registry_base, component, source_sha, "manifest.json"),
            &manifest_path,
            credential_path,
            estate_host,
        )?;
        let manifest: Manifest = serde_json::from_slice(
            &fs::read(&manifest_path)
                .map_err(|e| format!("fetch-artifact-manifest-read-failed: {e}"))?,
        )
        .map_err(|e| format!("fetch-artifact-manifest-malformed: {e}"))?;
        validate_manifest(&manifest, component, source_sha)?;
        curl_with_resolved_credential(
            &artifact_url(registry_base, component, source_sha, artifact_name),
            &artifact_path,
            credential_path,
            estate_host,
        )?;
        let bytes = fs::read(&artifact_path)
            .map_err(|e| format!("fetch-artifact-download-read-failed: {e}"))?;
        if bytes.len()
            > MAX_BODY_BYTES
                .parse::<usize>()
                .expect("constant is numeric")
        {
            return Err("fetch-artifact-download-too-large".into());
        }
        Ok(Download {
            manifest,
            bytes,
            identity: "liveness-marker".into(),
        })
    })();
    let _ = fs::remove_dir_all(&directory);
    result
}
fn release_source_revision(
    release: &ReleaseAssets,
    component: &str,
    schema_base: Option<&str>,
) -> Result<(String, Option<Value>), String> {
    let Some(flag_bytes) = release.release_flag.as_deref() else {
        return Ok((release.target_commitish.clone(), None));
    };
    let (source_sha, version) = release_flag_source_revision(flag_bytes, component, schema_base)?;
    if release.target_commitish != source_sha {
        return Err("fetch-artifact-release-commit-mismatch".into());
    }
    Ok((source_sha, version))
}

fn release_flag_source_revision(
    flag_bytes: &[u8],
    component: &str,
    schema_base: Option<&str>,
) -> Result<(String, Option<Value>), String> {
    let flag: Value = serde_json::from_slice(flag_bytes)
        .map_err(|_| "fetch-artifact-release-flag-malformed".to_string())?;
    if let Some(base) = schema_base {
        let seat = crate::atoms::ask::mint_seats::Seat::load(
            crate::atoms::ask::mint_seats::RELEASE_FLAG,
            base,
        )?;
        seat.validate(&flag)?;
    } else {
        let seat = crate::atoms::ask::mint_seats::at_start()
            .release_flag
            .as_ref()
            .map_err(|reason| reason.clone())?;
        seat.validate(&flag)?;
    }
    if flag.get("component").and_then(Value::as_str) != Some(component) {
        return Err("fetch-artifact-release-flag-component-mismatch".into());
    }
    let source_sha = flag
        .get("source_sha")
        .and_then(Value::as_str)
        .ok_or("fetch-artifact-release-flag-source-sha-missing")?;
    if !validate_source_sha(source_sha) {
        return Err("fetch-artifact-release-flag-source-sha-invalid".into());
    }
    Ok((
        source_sha.to_owned(),
        flag.pointer("/lineage/version").cloned(),
    ))
}

pub(crate) fn inspect_release(
    component: &str,
    release_repo: &str,
    tag: &str,
    api_root: &str,
    asset: &str,
    sidecar: &str,
    release_schema_base: Option<&str>,
) -> Result<Option<ReleaseInspection>, String> {
    let (owner, repo) = release_repo
        .split_once('/')
        .ok_or_else(|| "fetch-artifact-release-repo-invalid".to_string())?;
    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        return Err("fetch-artifact-release-repo-invalid".into());
    }
    let credential = crate::atoms::forge_credential::credential_for_url(api_root)?;
    let credential_scope_found = credential.is_some();
    let request = ReleaseRequest {
        kind: "forgejo-release".into(),
        base_url: api_root.into(),
        owner: owner.into(),
        repo: repo.into(),
        credential,
        credential_host: crate::atoms::forge_credential::url_host(api_root),
        credential_scope_found,
        cache_dir: std::env::temp_dir().join(format!("harmonia-release-{}", unique_temp_suffix())),
    };
    let result: Result<Option<ReleaseInspection>, String> = (|| {
        let Some(release) = fetch_release_assets_for_inspection(&request, tag, asset, sidecar)?
        else {
            return Ok(None);
        };
        let digest = crate::atoms::file_sha256(&release.artifact);
        // A release.flag is stamped with the repository's release component
        // segment (workflow-coronatio-xenia-add-xenos-hodos), which is distinct
        // from the xenos id `component` names; bind the flag to the repo segment.
        let (resolved_revision, version) =
            release_source_revision(&release, repo, release_schema_base)?;
        let sidecar_text = String::from_utf8(release.sidecar)
            .map_err(|_| "fetch-artifact-release-sidecar-malformed".to_string())?;
        if !is_hex(&digest, 64) || sidecar_text != format!("{digest}  {asset}\n") {
            return Err("fetch-artifact-release-sidecar-mismatch".into());
        }
        if !validate_source_sha(&resolved_revision) {
            return Err("fetch-artifact-release-revision-unavailable".into());
        }
        Ok(Some(ReleaseInspection {
            resolved_revision,
            digest,
            version,
        }))
    })();
    let _ = std::fs::remove_dir_all(&request.cache_dir);
    match result {
        Err(error) if !credential_scope_found => {
            let metadata_url = release_metadata_url(api_root, release_repo, tag);
            Err(normalize_auth_required_error(&error, &metadata_url).unwrap_or(error))
        }
        other => other,
    }
}

/// Read the public engine release with the stricter contract used by the
/// self-update lane. A flagless exact-SHA release is deliberately reported as
/// absent so the caller can use its pinned source fallback; a present flag
/// must be complete and bound to the exact admitted source SHA.
pub(crate) fn download_engine_release(
    component: &str,
    release_repo: &str,
    api_root: &str,
    source_sha: &str,
    release_schema_base: Option<&str>,
) -> Result<Option<Download>, String> {
    if !validate_source_sha(source_sha) {
        return Err("fetch-artifact-engine-source-sha-invalid".into());
    }
    let (owner, repo) = release_repo
        .split_once('/')
        .ok_or_else(|| "fetch-artifact-release-repo-invalid".to_string())?;
    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        return Err("fetch-artifact-release-repo-invalid".into());
    }
    let credential = crate::atoms::forge_credential::credential_for_url(api_root)?;
    let credential_scope_found = credential.is_some();
    let request = ReleaseRequest {
        kind: "forgejo-release".into(),
        base_url: api_root.into(),
        owner: owner.into(),
        repo: repo.into(),
        credential,
        credential_host: crate::atoms::forge_credential::url_host(api_root),
        credential_scope_found,
        cache_dir: std::env::temp_dir()
            .join(format!("harmonia-engine-release-{}", unique_temp_suffix())),
    };
    let result: Result<Option<Download>, String> = (|| {
        let Some(release) = fetch_release_assets_for_inspection(
            &request,
            source_sha,
            "harmonia-x86_64",
            "harmonia-x86_64.sha256",
        )?
        else {
            return Ok(None);
        };
        if release.target_commitish != source_sha {
            return Err("fetch-artifact-engine-release-target-mismatch".into());
        }
        let digest = crate::atoms::file_sha256(&release.artifact);
        let (resolved_revision, _version) =
            release_source_revision(&release, component, release_schema_base)?;
        if resolved_revision != source_sha {
            return Err("fetch-artifact-engine-release-source-mismatch".into());
        }
        if release.release_flag.is_none() {
            return Ok(None);
        }
        let sidecar_text = String::from_utf8(release.sidecar)
            .map_err(|_| "fetch-artifact-release-sidecar-malformed".to_string())?;
        if sidecar_text != format!("{digest}  harmonia-x86_64\n") {
            return Err("fetch-artifact-release-sidecar-mismatch".into());
        }
        let flag_bytes = release.release_flag.as_deref().expect("checked above");
        let flag: Value = serde_json::from_slice(flag_bytes)
            .map_err(|_| "fetch-artifact-release-flag-malformed".to_string())?;
        if flag.get("component").and_then(Value::as_str) != Some(component)
            || flag.get("source_sha").and_then(Value::as_str) != Some(source_sha)
            || flag.get("sha256").and_then(Value::as_str) != Some(digest.as_str())
            || !flag
                .get("env_sha")
                .and_then(Value::as_str)
                .is_some_and(|value| is_hex(value, 64))
            || !flag
                .get("pipeline_url")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
        {
            return Err("fetch-artifact-release-flag-binding-mismatch".into());
        }
        Ok(Some(Download {
            manifest: Manifest {
                schema: MANIFEST_SCHEMA.into(),
                component: component.into(),
                source_sha: resolved_revision,
                target: BUILD_TARGET.into(),
                sha256: digest,
                built_at: source_sha.into(),
                pipeline_url: release.metadata_url,
                env_sha: flag
                    .get("env_sha")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                rustc_version: flag
                    .get("rustc_version")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            },
            bytes: release.artifact,
            identity: "engine-release".into(),
        }))
    })();
    let _ = std::fs::remove_dir_all(&request.cache_dir);
    match result {
        Err(error) if !credential_scope_found => {
            let metadata_url = release_metadata_url(api_root, release_repo, source_sha);
            Err(normalize_auth_required_error(&error, &metadata_url).unwrap_or(error))
        }
        other => other,
    }
}

/// Observe a release's digest without acquiring the artifact bytes. The release
/// metadata and checksum sidecar are the bounded currentness witness; binary
/// acquisition remains unreachable until the caller compares this digest.
pub(crate) fn probe_release_digest(
    binary_name: &str,
    release_repo: &str,
    tag: &str,
    api_root: &str,
    asset_name: Option<&str>,
    sidecar_name: Option<&str>,
    source_build_sha: &str,
) -> Result<Option<String>, String> {
    let (owner, repo) = release_repo
        .split_once('/')
        .ok_or_else(|| "fetch-artifact-release-repo-invalid".to_string())?;
    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        return Err("fetch-artifact-release-repo-invalid".into());
    }
    let asset = asset_name.map(str::to_owned).unwrap_or_else(|| format!("{binary_name}-x86_64"));
    let sidecar = sidecar_name.map(str::to_owned).unwrap_or_else(|| format!("{asset}.sha256"));
    let credential = crate::atoms::forge_credential::credential_for_url(api_root)?;
    let request = ReleaseRequest {
        kind: "forgejo-release".into(), base_url: api_root.into(), owner: owner.into(), repo: repo.into(),
        credential_host: crate::atoms::forge_credential::url_host(api_root),
        credential_scope_found: credential.is_some(), credential,
        cache_dir: std::env::temp_dir().join(format!("harmonia-release-probe-{}", unique_temp_suffix())),
    };
    let result = (|| {
        let Some(metadata) = lookup_release_metadata(&request, tag)? else { return Ok(None); };
        let expected_commit = source_sha_from_release_tag(tag).unwrap_or(source_build_sha);
        if metadata.target_commitish != expected_commit {
            return Err("fetch-artifact-release-commit-mismatch".into());
        }
        let url = release_asset_url(&metadata, tag, &sidecar)?;
        let bytes = download_release_asset(&request, &url, &sidecar, true)?;
        let text = String::from_utf8(bytes).map_err(|_| "fetch-artifact-release-sidecar-malformed".to_string())?;
        let line = text.trim_end_matches(['\r', '\n']);
        if line.contains('\n') || line.contains('\r') {
            return Err("fetch-artifact-release-sidecar-malformed".into());
        }
        let (digest, named_asset) = line.split_once("  ").ok_or_else(|| "fetch-artifact-release-sidecar-malformed".to_string())?;
        if !is_hex(digest, 64) || named_asset != asset {
            return Err("fetch-artifact-release-sidecar-malformed".into());
        }
        Ok(Some(digest.to_owned()))
    })();
    let _ = std::fs::remove_dir_all(&request.cache_dir);
    result
}

pub(crate) fn download_release(
    component: &str,
    binary_name: &str,
    _source_dir: &Path,
    release_repo: &str,
    tag: Option<&str>,
    api_root: &str,
    asset_name: Option<&str>,
    sidecar_name: Option<&str>,
    identity: &str,
    source_build_sha: &str,
) -> Result<Option<Download>, String> {
    let (owner, repo) = release_repo
        .split_once('/')
        .ok_or_else(|| "fetch-artifact-release-repo-invalid".to_string())?;
    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        return Err("fetch-artifact-release-repo-invalid".into());
    }
    let tag = match tag.filter(|value| !value.trim().is_empty()) {
        Some(value) => value.to_owned(),
        None => source_build_sha.to_owned(),
    };
    let asset = asset_name
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{binary_name}-x86_64"));
    let sidecar = sidecar_name
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{asset}.sha256"));
    let credential = crate::atoms::forge_credential::credential_for_url(api_root)?;
    let credential_scope_found = credential.is_some();
    let credential_host = crate::atoms::forge_credential::url_host(api_root);
    let request = ReleaseRequest {
        kind: "forgejo-release".into(),
        base_url: api_root.into(),
        owner: owner.into(),
        repo: repo.into(),
        credential,
        credential_host,
        credential_scope_found,
        cache_dir: std::env::temp_dir().join(format!("harmonia-release-{}", unique_temp_suffix())),
    };
    let result: Result<Option<Download>, String> = (|| {
        let Some(release) = fetch_release_assets(&request, &tag, &asset, &sidecar)? else {
            return Ok(None);
        };
        let digest = crate::atoms::file_sha256(&release.artifact);
        let (resolved_revision, _version) = release_source_revision(&release, repo, None)?;
        let sidecar_text = String::from_utf8(release.sidecar)
            .map_err(|_| "fetch-artifact-release-sidecar-malformed".to_string())?;
        let expected = format!("{digest}  {asset}");
        if !is_hex(&digest, 64) || sidecar_text.trim_end_matches(['\r', '\n']) != expected {
            return Err("fetch-artifact-release-sidecar-mismatch".into());
        }
        let manifest = Manifest {
            schema: MANIFEST_SCHEMA.into(),
            component: component.into(),
            source_sha: resolved_revision,
            target: std::env::consts::ARCH.into(),
            sha256: digest,
            built_at: crate::atoms::ask::fetch_artifact::source_sha_from_release_tag(&tag)
                .unwrap_or(&tag)
                .to_owned(),
            pipeline_url: release.metadata_url,
            env_sha: None,
            rustc_version: None,
        };
        Ok(Some(Download {
            manifest,
            bytes: release.artifact,
            identity: identity.into(),
        }))
    })();
    let _ = std::fs::remove_dir_all(&request.cache_dir);
    match result {
        Err(error) if !credential_scope_found => {
            let metadata_url = release_metadata_url(api_root, release_repo, &tag);
            Err(normalize_auth_required_error(&error, &metadata_url).unwrap_or(error))
        }
        other => other,
    }
}
pub(crate) fn download_latest_release(
    component: &str,
    release_repo: &str,
    api_root: &str,
    asset_name: &str,
    sidecar_name: &str,
    identity: &str,
    release_schema_base: Option<&str>,
) -> Result<Option<Download>, String> {
    download_release_with_pin(
        component,
        release_repo,
        api_root,
        asset_name,
        sidecar_name,
        identity,
        release_schema_base,
        None,
    )
}

pub(crate) fn download_pinned_release(
    component: &str,
    release_repo: &str,
    api_root: &str,
    asset_name: &str,
    sidecar_name: &str,
    identity: &str,
    pinned_release_sha: &str,
    release_schema_base: Option<&str>,
) -> Result<Download, String> {
    if !validate_source_sha(pinned_release_sha) {
        return Err("fetch-artifact-pinned-release-sha-invalid".into());
    }
    let pinned_release_sha = pinned_release_sha.to_ascii_lowercase();
    download_release_with_pin(
        component,
        release_repo,
        api_root,
        asset_name,
        sidecar_name,
        identity,
        release_schema_base,
        Some(&pinned_release_sha),
    )?
    .ok_or_else(|| "fetch-artifact-pinned-release-missing".into())
}

fn download_release_with_pin(
    component: &str,
    release_repo: &str,
    api_root: &str,
    asset_name: &str,
    sidecar_name: &str,
    identity: &str,
    release_schema_base: Option<&str>,
    pinned_release_sha: Option<&str>,
) -> Result<Option<Download>, String> {
    let (owner, repo) = release_repo
        .split_once('/')
        .ok_or_else(|| "fetch-artifact-release-repo-invalid".to_string())?;
    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        return Err("fetch-artifact-release-repo-invalid".into());
    }
    validate_segment(component, "component")?;
    validate_segment(asset_name, "asset-name")?;
    validate_segment(sidecar_name, "sidecar-name")?;
    let credential = crate::atoms::forge_credential::credential_for_url(api_root)?;
    let credential_scope_found = credential.is_some();
    let request = ReleaseRequest {
        kind: "forgejo-release".into(),
        base_url: api_root.into(),
        owner: owner.into(),
        repo: repo.into(),
        credential,
        credential_host: crate::atoms::forge_credential::url_host(api_root),
        credential_scope_found,
        cache_dir: std::env::temp_dir().join(format!(
            "harmonia-latest-release-{}",
            unique_temp_suffix()
        )),
    };
    let result = (|| {
        let mut releases = lookup_published_releases(&request)?;
        releases.sort_by(|left, right| {
            right
                .created_at_order
                .cmp(&left.created_at_order)
                .then_with(|| right.id.cmp(&left.id))
        });
        let mut saw_pinned_target = false;
        for candidate in releases {
            if let Some(pinned_release_sha) = pinned_release_sha {
                if candidate.target_commitish.as_deref() != Some(pinned_release_sha) {
                    continue;
                }
                saw_pinned_target = true;
            }
            if candidate.draft
                || !candidate.has_asset(asset_name)
                || !candidate.has_asset(sidecar_name)
                || !candidate.has_asset("release.flag")
            {
                continue;
            }
            let expected_source_sha = if let Some(pinned_release_sha) = pinned_release_sha {
                pinned_release_sha
            } else {
                let Some(tagged_source_sha) = source_sha_from_release_tag(&candidate.tag_name)
                else {
                    continue;
                };
                tagged_source_sha
            };
            let release_result = if pinned_release_sha.is_some() {
                fetch_release_assets_for_pinned_inspection(
                    &request,
                    &candidate.tag_name,
                    asset_name,
                    sidecar_name,
                )
            } else {
                fetch_release_assets_for_inspection(
                    &request,
                    &candidate.tag_name,
                    asset_name,
                    sidecar_name,
                )
            };
            let release = match release_result {
                Ok(Some(release)) => release,
                Ok(None) => continue,
                Err(error) if ineligible_release_error(&error) => continue,
                Err(error) => return Err(error),
            };
            if release.target_commitish != expected_source_sha {
                continue;
            }
            let Some(flag_bytes) = release.release_flag.as_deref() else {
                continue;
            };
            let (source_sha, _version) =
                match release_source_revision(&release, repo, release_schema_base) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
            if source_sha != expected_source_sha {
                continue;
            }
            let digest = crate::atoms::file_sha256(&release.artifact);
            let Ok(sidecar_text) = String::from_utf8(release.sidecar) else {
                continue;
            };
            if sidecar_text.trim_end_matches(['\r', '\n']) != format!("{digest}  {asset_name}") {
                continue;
            }
            let flag: Value = match serde_json::from_slice(flag_bytes) {
                Ok(flag) => flag,
                Err(_) => continue,
            };
            let flag_digest_matches = if pinned_release_sha.is_some() {
                flag.get("sha256")
                    .map_or(true, |value| value.as_str() == Some(digest.as_str()))
            } else {
                flag.get("sha256")
                    .and_then(Value::as_str)
                    .is_some_and(|value| is_hex(value, 64))
            };
            let flag_environment_is_valid = if pinned_release_sha.is_some() {
                flag.get("env_sha").map_or(true, |value| {
                    value.as_str().is_some_and(|value| is_hex(value, 64))
                })
            } else {
                flag.get("env_sha")
                    .and_then(Value::as_str)
                    .is_some_and(|value| is_hex(value, 64))
            };
            if !flag_digest_matches
                || !flag_environment_is_valid
                || !flag
                    .get("pipeline_url")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty())
            {
                continue;
            }
            return Ok(Some(Download {
                manifest: Manifest {
                    schema: MANIFEST_SCHEMA.into(),
                    component: component.into(),
                    source_sha,
                    target: BUILD_TARGET.into(),
                    sha256: digest,
                    built_at: candidate.created_at,
                    pipeline_url: release.metadata_url,
                    env_sha: flag
                        .get("env_sha")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    rustc_version: flag
                        .get("rustc_version")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                },
                bytes: release.artifact,
                identity: identity.into(),
            }));
        }
        if pinned_release_sha.is_some() && saw_pinned_target {
            return Err("fetch-artifact-pinned-release-mismatch".into());
        }
        if pinned_release_sha.is_some() {
            return Err("fetch-artifact-pinned-release-missing".into());
        }
        Ok(None)
    })();
    let _ = std::fs::remove_dir_all(&request.cache_dir);
    match result {
        Err(error) if !credential_scope_found => {
            let metadata_url = format!(
                "{}/repos/{release_repo}/releases",
                release_api_root(api_root)
            );
            Err(normalize_auth_required_error(&error, &metadata_url).unwrap_or(error))
        }
        other => other,
    }
}

pub(crate) fn download_latest_engine_release(
    component: &str,
    release_repo: &str,
    api_root: &str,
    release_schema_base: Option<&str>,
) -> Result<Option<Download>, String> {
    download_latest_release(
        component,
        release_repo,
        api_root,
        "harmonia-x86_64",
        "harmonia-x86_64.sha256",
        "engine-release",
        release_schema_base,
    )
}

/// Read the explicitly configured GitHub rolling release as a public fallback.
/// Its fixed `latest` tag is resolved exactly, never by selecting an arbitrary
/// newest release from the repository's history.
pub(crate) fn download_github_latest_engine_release(
    component: &str,
    release_repo: &str,
    api_root: &str,
    release_schema_base: Option<&str>,
) -> Result<Option<Download>, String> {
    let (owner, repo) = release_repo
        .split_once('/')
        .ok_or_else(|| "fetch-artifact-release-repo-invalid".to_string())?;
    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        return Err("fetch-artifact-release-repo-invalid".into());
    }
    validate_segment(component, "component")?;
    validate_segment(owner, "release-owner")?;
    validate_segment(repo, "release-repo")?;
    let request = ReleaseRequest {
        kind: "github-release".into(),
        base_url: api_root.into(),
        owner: owner.into(),
        repo: repo.into(),
        credential: None,
        credential_host: None,
        credential_scope_found: false,
        cache_dir: std::env::temp_dir().join(format!(
            "harmonia-github-engine-release-{}",
            unique_temp_suffix()
        )),
    };
    let result = (|| {
        let Some((release, created_at)) = fetch_release_assets_inner_with_created_at(
            &request,
            "latest",
            "harmonia-x86_64",
            "harmonia-x86_64.sha256",
            true,
            false,
            false,
        )?
        else {
            return Ok(None);
        };
        let Some(flag_bytes) = release.release_flag.as_deref() else {
            return Err("fetch-artifact-release-flag-missing".into());
        };
        let created_at = created_at
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| "fetch-artifact-github-release-created-at-missing".to_string())?;
        let (source_sha, _) = release_source_revision(&release, component, release_schema_base)?;
        if !validate_source_sha(&source_sha) {
            return Err("fetch-artifact-github-engine-release-source-mismatch".into());
        }
        let digest = crate::atoms::file_sha256(&release.artifact);
        let sidecar_text = String::from_utf8(release.sidecar)
            .map_err(|_| "fetch-artifact-release-sidecar-malformed".to_string())?;
        if sidecar_text != format!("{digest}  harmonia-x86_64\n") {
            return Err("fetch-artifact-release-sidecar-mismatch".into());
        }
        let flag: Value = serde_json::from_slice(flag_bytes)
            .map_err(|_| "fetch-artifact-release-flag-malformed".to_string())?;
        if flag.get("sha256").and_then(Value::as_str) != Some(digest.as_str()) {
            return Err("fetch-artifact-release-flag-digest-mismatch".into());
        }
        let env_sha = flag
            .get("env_sha")
            .and_then(Value::as_str)
            .filter(|value| is_hex(value, 64))
            .ok_or_else(|| "fetch-artifact-release-flag-env-sha-invalid".to_string())?;
        let pipeline_url = flag
            .get("pipeline_url")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| "fetch-artifact-release-flag-pipeline-url-missing".to_string())?;
        Ok(Some(Download {
            manifest: Manifest {
                schema: MANIFEST_SCHEMA.into(),
                component: component.into(),
                source_sha,
                target: BUILD_TARGET.into(),
                sha256: digest,
                built_at: created_at,
                pipeline_url: pipeline_url.into(),
                env_sha: Some(env_sha.into()),
                rustc_version: flag
                    .get("rustc_version")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            },
            bytes: release.artifact,
            identity: "engine-release".into(),
        }))
    })();
    let _ = fs::remove_dir_all(&request.cache_dir);
    result
}

#[derive(Debug)]
struct PublishedRelease {
    id: u64,
    created_at: String,
    created_at_order: i128,
    tag_name: String,
    target_commitish: Option<String>,
    draft: bool,
    assets: Value,
}

impl PublishedRelease {
    fn has_asset(&self, name: &str) -> bool {
        self.assets.as_array().is_some_and(|assets| {
            assets.iter().any(|asset| {
                asset.get("name").and_then(Value::as_str) == Some(name)
                    && asset
                        .get("browser_download_url")
                        .or_else(|| asset.get("url"))
                        .and_then(Value::as_str)
                        .is_some_and(|url| !url.trim().is_empty())
            })
        })
    }
}

const RELEASE_LIST_PAGE_SIZE: usize = 50;
const RELEASE_LIST_MAX_PAGES: usize = 100;

fn lookup_published_releases(request: &ReleaseRequest) -> Result<Vec<PublishedRelease>, String> {
    let api = release_api(request);
    let url = format!(
        "{api}/repos/{}/{}/releases",
        request.owner, request.repo
    );
    fs::create_dir_all(&request.cache_dir)
        .map_err(|error| format!("release-cache-create-failed: {error}"))?;
    let mut releases = Vec::new();
    for page in 1..=RELEASE_LIST_MAX_PAGES {
        let page_url = format!("{url}?limit={RELEASE_LIST_PAGE_SIZE}&page={page}");
        let path = request
            .cache_dir
            .join(format!(".release-list-{}", unique_temp_suffix()));
        let args = inspection_curl_args(&page_url, &path.to_string_lossy());
        let mut args = args;
        args.extend(["-w".into(), "%{http_code}".into()]);
        let response = run_curl(&args, request.credential_for_url(&page_url))?;
        if response.code == 63 {
            let _ = fs::remove_file(&path);
            return Err(INSPECTION_OVERSIZE_BLOCKER.into());
        }
        if !response.ok {
            let _ = fs::remove_file(&path);
            let error = format!(
                "release-list-fetch-failed: {} http_status={}",
                response.stderr,
                response.stdout.trim()
            );
            return Err(if request.credential_for_url(&page_url).is_none() {
                normalize_auth_required_error(&error, &page_url).unwrap_or(error)
            } else {
                error
            });
        }
        let bytes = fs::read(&path)
            .map_err(|error| format!("release-list-read-failed: {error}"))?;
        let _ = fs::remove_file(&path);
        let page_releases: Vec<Value> = serde_json::from_slice(&bytes)
            .map_err(|error| format!("release-list-malformed: {error}"))?;
        if page_releases.len() > RELEASE_LIST_PAGE_SIZE {
            return Err("release-list-page-over-limit".into());
        }
        for release in &page_releases {
            let id = release
                .get("id")
                .and_then(Value::as_u64)
                .ok_or("release-list-id-missing-or-invalid")?;
            let created_at = release
                .get("created_at")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or("release-list-created-at-missing")?;
            let created_at_order = rfc3339_order_key(created_at)
                .ok_or("release-list-created-at-invalid")?;
            let tag_name = release
                .get("tag_name")
                .and_then(Value::as_str)
                .filter(|value| safe_release_segment(value))
                .ok_or("release-list-tag-invalid")?;
            let assets = release
                .get("assets")
                .cloned()
                .filter(Value::is_array)
                .ok_or("release-list-assets-missing")?;
            let target_commitish = release
                .get("target_commitish")
                .and_then(Value::as_str)
                .map(str::to_owned);
            releases.push(PublishedRelease {
                id,
                created_at: created_at.to_owned(),
                created_at_order,
                tag_name: tag_name.to_owned(),
                target_commitish,
                draft: release.get("draft").and_then(Value::as_bool).unwrap_or(false),
                assets,
            });
        }
        if page_releases.len() < RELEASE_LIST_PAGE_SIZE {
            return Ok(releases);
        }
    }
    Err("release-list-page-limit-exceeded".into())
}

fn rfc3339_order_key(value: &str) -> Option<i128> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }
    let parse = |start: usize, end: usize| -> Option<i64> {
        value.get(start..end)?.parse::<i64>().ok()
    };
    let year = parse(0, 4)?;
    let month = parse(5, 7)?;
    let day = parse(8, 10)?;
    let hour = parse(11, 13)?;
    let minute = parse(14, 16)?;
    let second = parse(17, 19)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut index = 19;
    let mut nanos = 0_i64;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let fraction_start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == fraction_start {
            return None;
        }
        let fraction = value.get(fraction_start..index)?;
        let first_nine = &fraction[..fraction.len().min(9)];
        nanos = first_nine.parse::<i64>().ok()?;
        for _ in first_nine.len()..9 {
            nanos *= 10;
        }
    }
    let offset_seconds = match bytes.get(index).copied()? {
        b'Z' if index + 1 == bytes.len() => 0_i64,
        sign @ (b'+' | b'-') if index + 6 == bytes.len() && bytes.get(index + 3) == Some(&b':') => {
            let hours = value.get(index + 1..index + 3)?.parse::<i64>().ok()?;
            let minutes = value.get(index + 4..index + 6)?.parse::<i64>().ok()?;
            if hours > 23 || minutes > 59 {
                return None;
            }
            let offset = hours * 3600 + minutes * 60;
            if sign == b'+' { offset } else { -offset }
        }
        _ => return None,
    };
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second - offset_seconds;
    Some(i128::from(seconds) * 1_000_000_000 + i128::from(nanos))
}

fn ineligible_release_error(error: &str) -> bool {
    [
        "fetch-artifact-release-commit-mismatch",
        "release-asset-missing",
        "release-assets-missing",
        "release-metadata-malformed",
        "fetch-artifact-release-flag-",
        "fetch-artifact-release-sidecar-",
    ]
    .iter()
    .any(|prefix| error.starts_with(prefix))
}

pub(crate) fn destination_identity(destination: &Path, source_sha: &str) -> bool {
    identity_matches(destination, source_sha, "liveness-marker", "caduceus")
}

#[cfg(test)]
mod tests {
    use super::*;
    const RELEASE_SOURCE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn native_release_fixture(identity: &str) -> Result<crate::OperationOutcome, String> {
        let source_dir = tempfile::tempdir().unwrap();
        fs::write(
            source_dir.path().join("Cargo.toml"),
            "[package]\nname=\"fixture\"\nversion=\"1.2.3\"\n",
        )
        .unwrap();
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let artifact =
            format!("caduceus.liveness.v1{RELEASE_SOURCE_SHA}caduceus-profile").into_bytes();
        let digest = crate::atoms::file_sha256(&artifact);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let release_body = serde_json::json!({
            "target_commitish": RELEASE_SOURCE_SHA,
            "assets": [
                {"name": "fixture-x86_64", "browser_download_url": format!("http://{address}/artifact")},
                {"name": "fixture-x86_64.sha256", "browser_download_url": format!("http://{address}/sidecar")},
            ],
        }).to_string().into_bytes();
        let served_artifact = artifact.clone();
        let server = thread::spawn(move || {
            let release_path =
                format!("/api/v1/repos/OWNER/REPO/releases/tags/sha-{RELEASE_SOURCE_SHA}");
            for (path, body) in [
                (release_path, release_body),
                ("/artifact".into(), served_artifact.clone()),
                (
                    "/sidecar".into(),
                    format!("{digest}  fixture-x86_64\n").into_bytes(),
                ),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 4096];
                let n = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..n]);
                assert!(request.starts_with(&format!("GET {path} ")));
                assert!(!request
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("authorization:")));
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        let destination = source_dir.path().join("target/harmonia-release/fixture");
        let installed = source_dir.path().join("installed");
        let receipt_dir = source_dir.path().join("receipts");
        let args = [
            ("component", serde_json::json!("caduceus")),
            ("release_repo", serde_json::json!("OWNER/REPO")),
            (
                "api_root",
                serde_json::json!(format!("http://{address}/api/v1")),
            ),
            ("source_build_sha", serde_json::json!(RELEASE_SOURCE_SHA)),
            ("artifact_name", serde_json::json!("fixture")),
            ("identity", serde_json::json!(identity)),
            ("source_dir", serde_json::json!(source_dir.path())),
            ("destination", serde_json::json!(&destination)),
            ("installed_binary", serde_json::json!(&installed)),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome =
            crate::tools::fetch_artifact::execute(&args, &receipt_dir, true, Some(&invocation));
        server.join().unwrap();
        if outcome.is_ok() {
            assert_eq!(fs::read(&destination).unwrap(), artifact);
        }
        outcome
    }

    #[test]
    fn engine_release_fixture_requires_full_sha_assets_sidecar_and_loaded_flag_seat() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let artifact = b"native-harmonia-engine-artifact".to_vec();
        let digest = crate::atoms::file_sha256(&artifact);
        let env_sha = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let flag = serde_json::json!({
            "schema": "estate.release-flag.v1",
            "component": "harmonia",
            "source_sha": RELEASE_SOURCE_SHA,
            "env_sha": env_sha,
            "sha256": digest,
            "flagged_at": "2026-09-21T00:00:00Z",
            "pipeline_url": "https://ci.home.arpa/harmonia/1"
        });
        let schema = serde_json::json!({
            "schema": "estate.release-flag.v1",
            "required": [
                "schema", "component", "source_sha", "env_sha", "sha256",
                "flagged_at", "pipeline_url"
            ],
            "fields": {}
        });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let release_path = format!("/api/v1/repos/OWNER/REPO/releases/tags/sha-{RELEASE_SOURCE_SHA}");
        let responses = vec![
            (
                release_path,
                serde_json::json!({
                    "tag_name": format!("sha-{RELEASE_SOURCE_SHA}"),
                    "name": RELEASE_SOURCE_SHA,
                    "target_commitish": RELEASE_SOURCE_SHA,
                    "assets": [
                        {"name": "harmonia-x86_64", "browser_download_url": format!("http://{address}/artifact")},
                        {"name": "harmonia-x86_64.sha256", "browser_download_url": format!("http://{address}/sidecar")},
                        {"name": "release.flag", "browser_download_url": format!("http://{address}/flag")}
                    ]
                }).to_string().into_bytes(),
            ),
            ("/flag".into(), serde_json::to_vec(&flag).unwrap()),
            ("/artifact".into(), artifact.clone()),
            (
                "/sidecar".into(),
                format!("{digest}  harmonia-x86_64\n").into_bytes(),
            ),
            (
                format!("/api/v1/schema/estate.release-flag.v1"),
                serde_json::to_vec(&schema).unwrap(),
            ),
        ];
        let server = thread::spawn(move || {
            for (path, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 4096];
                let length = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..length]);
                assert!(request.starts_with(&format!("GET {path} ")));
                assert!(!request
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("authorization:")));
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        let api_root = format!("http://{address}/api/v1");
        let download = download_engine_release(
            "harmonia",
            "OWNER/REPO",
            &api_root,
            RELEASE_SOURCE_SHA,
            Some(&format!("http://{address}")),
        )
        .unwrap()
        .expect("strict engine release fixture should be present");
        server.join().unwrap();
        assert_eq!(download.bytes, artifact);
        assert_eq!(download.manifest.source_sha, RELEASE_SOURCE_SHA);
        assert_eq!(download.manifest.sha256, digest);
        assert_eq!(download.manifest.env_sha.as_deref(), Some(env_sha));
    }

    #[test]
    fn flagless_exact_sha_release_selects_pinned_source_lane() {
        let release = ReleaseAssets {
            artifact: b"native-harmonia-engine-artifact".to_vec(),
            sidecar: Vec::new(),
            release_flag: None,
            metadata_url: "https://git.home.arpa/release".into(),
            target_commitish: RELEASE_SOURCE_SHA.into(),
        };
        let (resolved, flag) = release_source_revision(&release, "harmonia", None).unwrap();
        assert_eq!(resolved, RELEASE_SOURCE_SHA);
        assert!(flag.is_none());
    }

    #[test]
    fn foreign_component_release_flag_is_refused_after_schema_validation() {
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
            assert!(request.starts_with("GET /api/v1/schema/estate.release-flag.v1 "));
            let schema = serde_json::json!({
                "schema": "estate.release-flag.v1",
                "required": [
                    "schema", "component", "source_sha", "env_sha", "sha256",
                    "flagged_at", "pipeline_url"
                ],
                "fields": {}
            });
            let body = serde_json::to_vec(&schema).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        });
        let release = ReleaseAssets {
            artifact: Vec::new(),
            sidecar: Vec::new(),
            release_flag: Some(
                serde_json::to_vec(&serde_json::json!({
                    "schema": "estate.release-flag.v1",
                    "component": "harmonia-monad",
                    "source_sha": RELEASE_SOURCE_SHA,
                    "env_sha": "a".repeat(64),
                    "sha256": "b".repeat(64),
                    "flagged_at": "2026-09-21T00:00:00Z",
                    "pipeline_url": "https://ci.home.arpa/harmonia/1"
                }))
                .unwrap(),
            ),
            metadata_url: "https://git.home.arpa/release".into(),
            target_commitish: RELEASE_SOURCE_SHA.into(),
        };
        let error =
            release_source_revision(&release, "harmonia", Some(&format!("http://{address}")))
                .unwrap_err();
        server.join().unwrap();
        assert_eq!(error, "fetch-artifact-release-flag-component-mismatch");
    }

    #[test]
    fn native_release_fixture_http_server_stages_binary_and_verifies_sidecar() {
        let outcome = native_release_fixture("liveness-marker").unwrap();
        assert!(outcome.ok);
        assert!(outcome.changed);
        assert_eq!(outcome.message, "fetch-artifact-installed");
    }

    #[test]
    fn native_release_fixture_http_server_rejects_embedded_identity() {
        let error = native_release_fixture("embedded-sha").unwrap_err();
        assert_eq!(error, "fetch-artifact-source-identity-missing");
    }

    #[test]
    fn authenticated_curl_captures_status_and_uses_forgejo_token_header() {
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
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });
        let directory =
            std::env::temp_dir().join(format!("harmonia-fetch-auth-test-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let destination = directory.join("artifact");
        let stderr_path = directory.join("stderr");
        let result = curl_to_file(
            &format!("http://{address}/artifact"),
            &destination,
            &stderr_path,
            Some("test-token"),
        );
        server.join().unwrap();
        let _ = fs::remove_dir_all(&directory);
        assert_eq!(result.unwrap(), 200);
    }

    #[test]
    fn forgejo_credential_contract_registry_present_header_and_absent_anonymous() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::os::unix::fs::PermissionsExt;
        use std::thread;

        let source_sha = "0123456789abcdef0123456789abcdef01234567";
        let artifact = b"registry-artifact";
        let digest = crate::atoms::file_sha256(artifact);
        for (credential_contents, expected_header, trace) in [
            (Some("FORGEJO_TOKEN=test-token\n"), true, "present"),
            (None, false, "absent"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let digest = digest.clone();
            let server = thread::spawn(move || {
                for (path, body) in [
                    (
                        format!("/caduceus/{source_sha}/manifest.json"),
                        format!(
                            r#"{{"schema":"estate.artifact.manifest.v1","component":"caduceus","source_sha":"{source_sha}","target":"x86_64","sha256":"{digest}","built_at":"now","pipeline_url":"https://ci"}}"#
                        )
                        .into_bytes(),
                    ),
                    (format!("/caduceus/{source_sha}/artifact"), artifact.to_vec()),
                ] {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut request = [0_u8; 4096];
                    let length = stream.read(&mut request).unwrap();
                    let request = String::from_utf8_lossy(&request[..length]);
                    assert!(request.starts_with(&format!("GET {path} ")));
                    assert_eq!(request.contains("Authorization: token test-token"), expected_header);
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .unwrap();
                    stream.write_all(&body).unwrap();
                }
            });
            let credential = tempfile::NamedTempFile::new().unwrap();
            if let Some(contents) = credential_contents {
                std::fs::write(credential.path(), contents).unwrap();
                let mut permissions = std::fs::metadata(credential.path()).unwrap().permissions();
                permissions.set_mode(0o600);
                std::fs::set_permissions(credential.path(), permissions).unwrap();
            }
            let missing = credential.path().with_extension("missing");
            let credential_path = if credential_contents.is_some() {
                credential.path()
            } else {
                missing.as_path()
            };
            let result = download_with_credential_path(
                "caduceus",
                &format!("http://{address}"),
                source_sha,
                "artifact",
                credential_path,
                &address.ip().to_string(),
            );
            server.join().unwrap();
            assert!(result.is_ok(), "registry fixture failed for {trace}");
            println!(
                "trace registry credential={trace} header={}",
                if expected_header { "present" } else { "absent" }
            );
        }
    }

    #[test]
    fn fetch_artifact_manifest_mismatch() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(pair) => break pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(5))
                    }
                    Err(error) => panic!("{error}"),
                }
            };
            let mut request = [0_u8; 2048];
            let length = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..length]);
            assert!(request.starts_with(
                "GET /caduceus/0123456789abcdef0123456789abcdef01234567/manifest.json"
            ));
            let body = format!(
                r#"{{"schema":"{}","component":"other","source_sha":"{}","target":"x86_64","sha256":"{}","built_at":"now","pipeline_url":"https://ci"}}"#,
                MANIFEST_SCHEMA,
                sha,
                "a".repeat(64)
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            thread::sleep(std::time::Duration::from_millis(100));
            assert!(
                listener.accept().is_err(),
                "artifact endpoint was contacted"
            );
        });
        let result = download("caduceus", &format!("http://{address}"), sha, "artifact");
        server.join().unwrap();
        assert_eq!(
            result.expect_err("manifest mismatch should reject before artifact fetch"),
            "fetch-artifact-manifest-component-mismatch"
        );
    }

    #[test]
    fn caduceus_build_environment_prefix_exports_source_and_build_sha() {
        let environment = build_environment_variables("caduceus", "source-sha", "environment-sha");
        assert_eq!(build_environment_prefix("caduceus"), "CADUCEUS_");
        assert_eq!(
            environment,
            vec![
                ("CADUCEUS_BUILD_SHA".into(), "source-sha".into()),
                ("CADUCEUS_SOURCE_SHA".into(), "source-sha".into()),
                ("CADUCEUS_BUILD_ENV_SHA".into(), "environment-sha".into()),
            ]
        );
    }

    #[test]
    fn coronatio_build_environment_prefix_exports_source_and_build_sha() {
        let environment = build_environment_variables("coronatio", "source-sha", "environment-sha");
        assert_eq!(build_environment_prefix("coronatio"), "CORONATIO_");
        assert_eq!(
            environment,
            vec![
                ("CORONATIO_BUILD_SHA".into(), "source-sha".into()),
                ("CORONATIO_SOURCE_SHA".into(), "source-sha".into()),
                ("CORONATIO_BUILD_ENV_SHA".into(), "environment-sha".into()),
            ]
        );
    }

    #[test]
    fn dashed_component_build_environment_prefix_replaces_separator() {
        let environment = build_environment_variables("foo-bar", "source-sha", "environment-sha");
        assert_eq!(build_environment_prefix("foo-bar"), "FOO_BAR_");
        assert_eq!(
            environment,
            vec![
                ("FOO_BAR_BUILD_SHA".into(), "source-sha".into()),
                ("FOO_BAR_SOURCE_SHA".into(), "source-sha".into()),
                ("FOO_BAR_BUILD_ENV_SHA".into(), "environment-sha".into()),
            ]
        );
    }

    #[test]
    fn build_environment_normalizes_only_trailing_crlf() {
        assert_eq!(trim_trailing_crlf(" \trustc -Vv\r\n"), " \trustc -Vv");
        assert_eq!(trim_trailing_crlf("\nrustc -Vv"), "\nrustc -Vv");
        assert_eq!(trim_trailing_crlf("rustc -Vv \t\r\n"), "rustc -Vv \t");
    }

    #[test]
    fn bare_auth_required_fixture_normalizes_with_fallback_url() {
        let url = "https://git.home.arpa/api/v1/refusing";
        assert_eq!(
            normalize_auth_required_error("fetch-artifact-auth-required", url),
            Some(format!("fetch-artifact-auth-required url={url}"))
        );
    }

    #[test]
    fn release_metadata_403_fixture_normalizes_with_fallback_url() {
        let url = "https://git.home.arpa/api/v1/refusing";
        assert_eq!(
            normalize_auth_required_error(
                "release-metadata-fetch-failed: curl: (22) The requested URL returned error: 403",
                url,
            ),
            Some(format!("fetch-artifact-auth-required url={url}"))
        );
    }
}
