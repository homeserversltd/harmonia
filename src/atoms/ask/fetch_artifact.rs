//! Observation and bounded acquisition for Forgejo generic artifacts.
use crate::tools::git_artifact::{
    fetch_release_assets, fetch_release_assets_for_inspection, unique_temp_suffix, ReleaseAssets,
    ReleaseRequest,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

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

pub(crate) fn profile_release_names(
    artifact_name: &str,
    profile: &str,
    asset_name: Option<&str>,
    sidecar_name: Option<&str>,
) -> Result<(String, String), String> {
    validate_segment(profile, "profile")?;
    let expected_asset = format!("{artifact_name}-{profile}-x86_64");
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
#[serde(deny_unknown_fields)]
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
    if release.target_commitish != source_sha {
        return Err("fetch-artifact-release-commit-mismatch".into());
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
            built_at: tag.clone(),
            pipeline_url: release.metadata_url,
            env_sha: None,
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
                format!("/api/v1/repos/OWNER/REPO/releases/tags/{RELEASE_SOURCE_SHA}");
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
