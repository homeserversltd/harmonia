//! Observation and bounded acquisition for Forgejo generic artifacts.
use serde::Deserialize;
use crate::tools::git_artifact::{fetch_release_assets, ReleaseRequest};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

pub(crate) const MANIFEST_SCHEMA: &str = "estate.artifact.manifest.v1";
const MAX_STDERR_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: &str = "67108864";

fn hex_boundary(bytes: &[u8], start: usize, sha: &[u8]) -> bool {
    bytes.get(start..start + sha.len()) == Some(sha)
        && !bytes.get(start.wrapping_sub(1)).is_some_and(|b| b.is_ascii_hexdigit())
        && !bytes.get(start + sha.len()).is_some_and(|b| b.is_ascii_hexdigit())
}

pub(crate) fn identity_matches_bytes(bytes: &[u8], source_sha: &str, identity: &str, component: &str) -> bool {
    let marker = if identity == "embedded-sha" { None } else { Some(format!("{component}.liveness.v1").into_bytes()) };
    if let Some(marker) = marker {
        return bytes.windows(marker.len()).enumerate().any(|(i, w)| {
            if w != marker {
                return false;
            }
            let start = i + marker.len();
            bytes.get(start..start + source_sha.len()) == Some(source_sha.as_bytes())
                && !bytes
                    .get(start + source_sha.len())
                    .is_some_and(|b| b.is_ascii_hexdigit())
        });
    }
    bytes.windows(source_sha.len()).enumerate().any(|(i, _)| hex_boundary(bytes, i, source_sha.as_bytes()))
}

pub(crate) fn identity_matches(destination: &Path, source_sha: &str, identity: &str, component: &str) -> bool {
    fs::read(destination).is_ok_and(|bytes| identity_matches_bytes(&bytes, source_sha, identity, component))
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
}
#[derive(Debug, Clone)]
pub(crate) struct Download {
    pub manifest: Manifest,
    pub bytes: Vec<u8>,
    pub identity: String,
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
fn artifact_url(base: &str, component: &str, source_sha: &str, name: &str) -> String {
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
        "--fail", "--silent", "--show-error", "--location",
        "--connect-timeout", "5", "--max-time", "30",
        "--max-filesize", MAX_BODY_BYTES,
        "--output", destination.to_str().ok_or("fetch-artifact-path-invalid")?,
        "--stderr", stderr_path.to_str().ok_or("fetch-artifact-path-invalid")?,
        "--write-out", "%{http_code}", url,
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
    let output = output
        .map_err(|e| format!("fetch-artifact-registry-unreachable: {e}"))?;
    let status = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u16>()
        .unwrap_or(0);
    if status == 401 || status == 403 {
        return Err("fetch-artifact-auth-required".into());
    }
    if !(200..300).contains(&status) || !output.status.success() {
        let stderr = fs::read(stderr_path).unwrap_or_default();
        let detail = String::from_utf8_lossy(&stderr[..stderr.len().min(MAX_STDERR_BYTES)])
            .trim()
            .to_string();
        return if detail.is_empty() {
            Err(format!("fetch-artifact-registry-refused-{status}"))
        } else {
            Err(format!("fetch-artifact-registry-refused-{status}: {detail}"))
        };
    }
    Ok(status)
}

fn registry_is_estate_host(base: &str) -> bool {
    base.trim()
        .split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
        .is_some_and(|authority| authority == "git.home.arpa")
}

fn configured_estate_token() -> Result<String, String> {
    let path = crate::bands::renew_self::engine_config_path();
    let config = crate::bands::renew_self::load_engine_plane_config(&path)?;
    let token_path = config
        .into_iter()
        .flat_map(|config| config.credential_scopes.into_values())
        .find_map(|scope| {
            (scope.https_host.as_deref() == Some("git.home.arpa"))
                .then_some(scope.https_token_path)
                .flatten()
        })
        .ok_or_else(|| "fetch-artifact-auth-required-configured-scope-missing".to_string())?;
    crate::atoms::git_artifact::read_token(&token_path)
}

fn curl_with_anonymous_first(url: &str, destination: &Path) -> Result<u16, String> {
    let stderr_path = destination.with_extension("stderr");
    let anonymous = curl_to_file(url, destination, &stderr_path, None);
    if let Err(error) = &anonymous {
        if error != "fetch-artifact-auth-required" {
            let _ = fs::remove_file(&stderr_path);
            return anonymous;
        }
    } else {
        let _ = fs::remove_file(&stderr_path);
        return anonymous;
    }
    if !registry_is_estate_host(url) {
        let _ = fs::remove_file(&stderr_path);
        return Err("fetch-artifact-auth-required-non-estate-registry".into());
    }
    let token = configured_estate_token()?;
    let result = curl_to_file(url, destination, &stderr_path, Some(&token));
    let _ = fs::remove_file(&stderr_path);
    result
}

pub(crate) fn download(
    component: &str,
    registry_base: &str,
    source_sha: &str,
    artifact_name: &str,
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
        "harmonia-fetch-{}-{}",
        std::process::id(),
        source_sha
    ));
    fs::create_dir_all(&directory)
        .map_err(|e| format!("fetch-artifact-temp-create-failed: {e}"))?;
    let result = (|| {
        let manifest_path = directory.join("manifest.json");
        let artifact_path = directory.join("artifact");
        curl_with_anonymous_first(
            &artifact_url(registry_base, component, source_sha, "manifest.json"),
            &manifest_path,
        )?;
        let manifest: Manifest = serde_json::from_slice(
            &fs::read(&manifest_path)
                .map_err(|e| format!("fetch-artifact-manifest-read-failed: {e}"))?,
        )
        .map_err(|e| format!("fetch-artifact-manifest-malformed: {e}"))?;
        validate_manifest(&manifest, component, source_sha)?;
        curl_with_anonymous_first(
            &artifact_url(registry_base, component, source_sha, artifact_name),
            &artifact_path,
        )?;
        let bytes = fs::read(&artifact_path)
            .map_err(|e| format!("fetch-artifact-download-read-failed: {e}"))?;
        if bytes.len() > MAX_BODY_BYTES.parse::<usize>().expect("constant is numeric") {
            return Err("fetch-artifact-download-too-large".into());
        }
        Ok(Download { manifest, bytes, identity: "liveness-marker".into() })
    })();
    let _ = fs::remove_dir_all(&directory);
    result
}
pub(crate) fn download_release(component:&str,source_dir:&Path,release_repo:&str,tag:Option<&str>,api_root:&str,asset_name:Option<&str>,sidecar_name:Option<&str>)->Result<Option<Download>,String>{
 let (owner,repo)=release_repo.split_once('/').ok_or_else(||"fetch-artifact-release-repo-invalid".to_string())?; if owner.is_empty()||repo.is_empty()||repo.contains('/') {return Err("fetch-artifact-release-repo-invalid".into())}
 let tag=match tag {Some(v) if !v.trim().is_empty()=>v.to_owned(),_=>release_version(source_dir)?}; let arch=std::env::consts::ARCH;
 let asset=asset_name.map(str::to_owned).unwrap_or_else(||format!("{component}-{tag}-x86_64")); let sidecar=sidecar_name.map(str::to_owned).unwrap_or_else(||format!("{asset}.sha256"));
 let request=ReleaseRequest{kind:"forgejo-release".into(),base_url:api_root.into(),owner:owner.into(),repo:repo.into(),credential_token_path:None,credential_scope_found:false,cache_dir:std::env::temp_dir().join(format!("harmonia-release-{}",std::process::id()))};
 let Some(release)=fetch_release_assets(&request,&tag,&asset,&sidecar)? else{return Ok(None)};
 if !validate_source_sha(&release.target_commitish){return Err("fetch-artifact-release-target-commitish-invalid".into())}
 let digest=crate::atoms::file_sha256(&release.artifact); let sidecar_text=String::from_utf8(release.sidecar).map_err(|_|"fetch-artifact-release-sidecar-malformed".to_string())?; let expected=format!("{digest}  {asset}");
 if !is_hex(&digest,64)||sidecar_text.trim_end_matches(['\r','\n'])!=expected{return Err("fetch-artifact-release-sidecar-mismatch".into())}
 let manifest=Manifest{schema:MANIFEST_SCHEMA.into(),component:component.into(),source_sha:release.target_commitish,target:arch.into(),sha256:digest,built_at:tag,pipeline_url:release.metadata_url};
 Ok(Some(Download{manifest,bytes:release.artifact,identity:"embedded-sha".into()}))
}

pub(crate) fn destination_identity(destination: &Path, source_sha: &str) -> bool {
    identity_matches(destination, source_sha, "liveness-marker", "caduceus")
}

pub(crate) fn release_version(source_dir: &Path) -> Result<String, String> {
    let text = fs::read_to_string(source_dir.join("Cargo.toml"))
        .map_err(|e| format!("fetch-artifact-release-source-read-failed: {e}"))?;
    let mut package = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') { package = trimmed == "[package]"; continue; }
        if package {
            let Some((key, value)) = trimmed.split_once('=') else { continue };
            if key.trim() != "version" {
                continue;
            }
            let Some(value) = value.trim().strip_prefix('"').and_then(|v| v.strip_suffix('"')) else {
                continue;
            };
            if !value.is_empty() {
                return Ok(value.to_owned());
            }
        }
    }
    Err("fetch-artifact-release-version-missing".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_release_fixture_http_server_stages_binary_and_verifies_sidecar() {
        let source = std::env::temp_dir().join(format!("harmonia-release-source-{}", std::process::id()));
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("Cargo.toml"), "[package]\nname=\"fixture\"\nversion=\"1.2.3\"\n").unwrap();
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        assert_eq!(release_version(&source).unwrap(), "1.2.3");
        let artifact = b"release-artifact-0123456789abcdef0123456789abcdef01234567";
        let digest = crate::atoms::file_sha256(artifact);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let release_body = serde_json::json!({
            "target_commitish": "0123456789abcdef0123456789abcdef01234567",
            "assets": [
                {"name": "fixture-1.2.3-x86_64", "browser_download_url": format!("http://{address}/artifact")},
                {"name": "fixture-1.2.3-x86_64.sha256", "browser_download_url": format!("http://{address}/sidecar")},
            ],
        }).to_string().into_bytes();
        let server = thread::spawn(move || {
            for (path, body) in [
                ("/api/v1/repos/OWNER/REPO/releases/tags/1.2.3", release_body),
                ("/artifact", artifact.to_vec()),
                ("/sidecar", format!("{digest}  fixture-1.2.3-x86_64\n").into_bytes()),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 4096];
                let n = stream.read(&mut request).unwrap();
                assert!(String::from_utf8_lossy(&request[..n]).starts_with(&format!("GET {path} ")));
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        let destination = source.join("target/harmonia-release/fixture");
        let installed = source.join("installed");
        let receipt_dir = source.join("receipts");
        let args = [
            ("component", serde_json::json!("fixture")),
            ("release_repo", serde_json::json!("OWNER/REPO")),
            ("api_root", serde_json::json!(format!("http://{address}/api/v1"))),
            ("source_build_sha", serde_json::json!("0123456789abcdef0123456789abcdef01234567")),
            ("source_dir", serde_json::json!(source)),
            ("destination", serde_json::json!(destination)),
            ("installed_binary", serde_json::json!(installed)),
        ].into_iter().map(|(key, value)| (key.into(), value)).collect();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome = crate::tools::fetch_artifact::execute(&args, &receipt_dir, true, Some(&invocation)).unwrap();
        server.join().unwrap();
        assert!(outcome.ok);
        assert!(outcome.changed);
        assert_eq!(fs::read(destination).unwrap(), artifact);
        let _ = fs::remove_dir_all(source);
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
        let directory = std::env::temp_dir().join(format!(
            "harmonia-fetch-auth-test-{}",
            std::process::id()
        ));
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
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(std::time::Duration::from_millis(5)),
                    Err(error) => panic!("{error}"),
                }
            };
            let mut request = [0_u8; 2048];
            let length = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..length]);
            assert!(request.starts_with("GET /caduceus/0123456789abcdef0123456789abcdef01234567/manifest.json"));
            let body = format!(r#"{{"schema":"{}","component":"other","source_sha":"{}","target":"x86_64","sha256":"{}","built_at":"now","pipeline_url":"https://ci"}}"#, MANIFEST_SCHEMA, sha, "a".repeat(64));
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
            thread::sleep(std::time::Duration::from_millis(100));
            assert!(listener.accept().is_err(), "artifact endpoint was contacted");
        });
        let result = download("caduceus", &format!("http://{address}"), sha, "artifact");
        server.join().unwrap();
        assert_eq!(
            result.expect_err("manifest mismatch should reject before artifact fetch"),
            "fetch-artifact-manifest-component-mismatch"
        );
    }
}
