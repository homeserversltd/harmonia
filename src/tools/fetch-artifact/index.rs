use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) fn execute(
    args: &BTreeMap<String, Value>,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<crate::OperationOutcome, String> {
    let required = |name: &str| {
        args.get(name)
            .and_then(Value::as_str)
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| format!("fetch-artifact-missing-{name}"))
    };
    let component = required("component")?;
    let registry_base = args
        .get("registry_base")
        .and_then(Value::as_str)
        .unwrap_or("");
    let release_repo = args
        .get("release_repo")
        .and_then(Value::as_str)
        .unwrap_or("");
    let identity = args
        .get("identity")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            if release_repo.trim().is_empty() {
                "liveness-marker"
            } else {
                "embedded-sha"
            }
        });
    let source_sha = required("source_build_sha")?;
    let beam_refetch = args
        .get("beam_refetch")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let artifact_name = args
        .get("artifact_name")
        .and_then(Value::as_str)
        .unwrap_or(component);
    let destination = Path::new(required("destination")?);
    let installed_binary = Path::new(required("installed_binary")?);
    if !crate::atoms::ask::fetch_artifact::validate_source_sha(source_sha) {
        return Err("fetch-artifact-source-sha-invalid".into());
    }

    let profile_axis = crate::atoms::ask::fetch_artifact::profile_axis_declared(args)?;
    let profile = if profile_axis {
        let profile_source = args
            .get("profile_source")
            .and_then(Value::as_str)
            .unwrap_or(crate::atoms::ask::fetch_artifact::DEFAULT_PROFILE_SOURCE);
        Some(crate::atoms::ask::fetch_artifact::read_profile_source(
            Path::new(profile_source),
        )?)
    } else {
        None
    };
    let (release_asset_name, release_sidecar_name) = match profile.as_deref() {
        Some(profile) => {
            let (asset, sidecar) = crate::atoms::ask::fetch_artifact::profile_release_names(
                artifact_name,
                profile,
                args.get("asset_name").and_then(Value::as_str),
                args.get("sidecar_name").and_then(Value::as_str),
            )?;
            (Some(asset), Some(sidecar))
        }
        None => (
            args.get("asset_name")
                .and_then(Value::as_str)
                .map(str::to_owned),
            args.get("sidecar_name")
                .and_then(Value::as_str)
                .map(str::to_owned),
        ),
    };

    let source_dir = args
        .get("source_dir")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(Path::new);
    let native_release = !release_repo.trim().is_empty();
    let mut release_fallback: Option<(String, String)> = None;
    let native_download = if native_release {
        let release_source_dir = source_dir.unwrap_or(Path::new(""));
        let tag = args
            .get("release_tag")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| source_sha.to_owned());
        let api_root = args
            .get("api_root")
            .and_then(Value::as_str)
            .unwrap_or("https://git.home.arpa/api/v1");
        match crate::atoms::ask::fetch_artifact::download_release(
            component,
            artifact_name,
            release_source_dir,
            release_repo,
            (!tag.is_empty()).then_some(tag.as_str()),
            api_root,
            release_asset_name.as_deref(),
            release_sidecar_name.as_deref(),
            source_sha,
        ) {
            Ok(Some(download)) => Some(download),
            Ok(None) => {
                release_fallback = Some((
                    "release-miss".into(),
                    crate::atoms::ask::fetch_artifact::release_metadata_url(
                        api_root,
                        release_repo,
                        &tag,
                    ),
                ));
                None
            }
            Err(error) if crate::atoms::ask::fetch_artifact::is_http_status(&error, "404") => {
                release_fallback = Some((
                    "release-miss".into(),
                    crate::atoms::ask::fetch_artifact::release_metadata_url(
                        api_root,
                        release_repo,
                        &tag,
                    ),
                ));
                None
            }
            Err(error) => {
                let metadata_url = crate::atoms::ask::fetch_artifact::release_metadata_url(
                    api_root,
                    release_repo,
                    &tag,
                );
                if let Some(artifact_url) =
                    crate::atoms::ask::fetch_artifact::auth_required_url(&error, &metadata_url)
                {
                    release_fallback = Some(("auth-required".into(), artifact_url));
                    None
                } else {
                    let _ = crate::atoms::attest::fetch_artifact::attest(
                        &receipt_dir.join("harmonia-atoms.log"),
                        false,
                        false,
                        &format!(
                            "state=Drift; care=artifact acquisition refused; after=Drift; error={error}"
                        ),
                    );
                    return Err(error);
                }
            }
        }
    } else {
        None
    };
    let effective_source_sha = native_download
        .as_ref()
        .map(|d| d.manifest.source_sha.clone())
        .unwrap_or_else(|| source_sha.to_owned());
    let current = crate::atoms::ask::fetch_artifact::identity_matches(
        installed_binary,
        &effective_source_sha,
        identity,
        component,
    );
    if current && !beam_refetch {
        crate::atoms::attest::fetch_artifact::attest(
            &receipt_dir.join("harmonia-atoms.log"),
            true,
            false,
            "state=Current; care=verified embedded source SHA; after=Current",
        )?;
        return Ok(crate::OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "fetch-artifact-current".into(),
            command: None,
        });
    }
    if current && beam_refetch {
        crate::atoms::attest::fetch_artifact::attest(
            &receipt_dir.join("harmonia-atoms.log"),
            true,
            false,
            "state=Drift; care=beam env SHA divergence requires artifact refetch; after=Drift; reason=fetch-artifact-refetch-beam-env-sha",
        )?;
    }
    let registry_download = if native_download.is_none() && release_fallback.is_none() {
        let registry_artifact_name = release_asset_name.as_deref().unwrap_or(artifact_name);
        let manifest_url = crate::atoms::ask::fetch_artifact::artifact_url(
            registry_base,
            component,
            source_sha,
            "manifest.json",
        );
        match crate::atoms::ask::fetch_artifact::download(
            component,
            registry_base,
            source_sha,
            registry_artifact_name,
        ) {
            Ok(download) => Some(download),
            Err(error) => {
                if let Some(artifact_url) =
                    crate::atoms::ask::fetch_artifact::auth_required_url(&error, &manifest_url)
                {
                    release_fallback = Some(("auth-required".into(), artifact_url));
                    None
                } else {
                    let _ = crate::atoms::attest::fetch_artifact::attest(
                        &receipt_dir.join("harmonia-atoms.log"),
                        false,
                        false,
                        &format!(
                            "state=Drift; care=artifact acquisition refused; after=Drift; error={error}"
                        ),
                    );
                    return Err(error);
                }
            }
        }
    } else {
        None
    };
    let download = if let Some(download) = native_download {
        download
    } else if let Some((fallback_reason, artifact_url)) = release_fallback {
        let source_dir = source_dir.ok_or("fetch-artifact-source-dir-missing")?;
        let source_dir_text = source_dir.display().to_string();
        let artifact = source_dir.join("target/release").join(artifact_name);
        let (environment, build_environment_sha) =
            crate::atoms::ask::fetch_artifact::build_environment(source_sha)?;
        crate::write_json(
            &receipt_dir.join("fallback.json"),
            &serde_json::json!({
                "schema": "harmonia.fetch-artifact.fallback.v1",
                "fallback_reason": fallback_reason,
                "artifact_url": artifact_url,
                "source_build_sha": source_sha,
                "source_dir": source_dir_text,
                "build_environment_sha": build_environment_sha,
            }),
        )?;
        if !apply {
            crate::atoms::attest::fetch_artifact::attest(
                &receipt_dir.join("harmonia-atoms.log"),
                true,
                false,
                "state=Drift; care=release miss requires source build; after=Drift (planned)",
            )?;
            return Ok(crate::OperationOutcome {
                ok: true,
                changed: false,
                skipped: true,
                message: "fetch-artifact-planned".into(),
                command: None,
            });
        }
        let build = crate::build_crate::run_build_with_mode(
            source_dir,
            source_sha,
            None,
            installed_binary,
            &artifact,
            apply,
            &environment,
            args.get("timeout_secs")
                .and_then(Value::as_u64)
                .unwrap_or(crate::atoms::r#do::build_crate::DEFAULT_TIMEOUT_SECS),
            &receipt_dir.join("harmonia-atoms.log"),
            args.get("bearer")
                .and_then(Value::as_str)
                .unwrap_or("owner"),
            invocation,
            crate::build_crate::IdentityMode::EmbeddedSourceSha,
        )?;
        if let Some(build) = build.filter(|build| !build.ok) {
            return Err(format!(
                "fetch-artifact-source-build-failed: {}",
                build.stderr
            ));
        }
        let bytes = std::fs::read(&artifact)
            .map_err(|error| format!("fetch-artifact-source-build-read-failed: {error}"))?;
        let manifest = crate::atoms::ask::fetch_artifact::Manifest {
            schema: crate::atoms::ask::fetch_artifact::MANIFEST_SCHEMA.into(),
            component: component.into(),
            source_sha: source_sha.into(),
            target: crate::atoms::ask::fetch_artifact::BUILD_TARGET.into(),
            sha256: crate::atoms::file_sha256(&bytes),
            built_at: "fallback".into(),
            pipeline_url: artifact_url,
            env_sha: Some(build_environment_sha),
        };
        crate::atoms::ask::fetch_artifact::Download {
            manifest,
            bytes,
            identity: "embedded-sha".into(),
        }
    } else {
        registry_download.ok_or("fetch-artifact-registry-download-missing")?
    };
    if !apply {
        crate::atoms::attest::fetch_artifact::attest(
            &receipt_dir.join("harmonia-atoms.log"),
            true,
            false,
            "state=Drift; care=manifest and digest verified; after=Drift (planned)",
        )?;
        return Ok(crate::OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "fetch-artifact-planned".into(),
            command: None,
        });
    }
    let invocation = invocation.ok_or("fetch-artifact-invocation-key-missing")?;
    // Force Drift only for the pre-act observation; allow convergence afterward.
    let mut force_stage_pre_act = true;
    let result = crate::atoms::comparison::execute(
        "fetch-artifact",
        || {
            if std::mem::take(&mut force_stage_pre_act) {
                Ok(false)
            } else {
                Ok(crate::atoms::ask::fetch_artifact::identity_matches(
                    destination,
                    &effective_source_sha,
                    identity,
                    component,
                ))
            }
        },
        |seen| {
            if *seen {
                crate::atoms::comparison::DiffDecision::Empty
            } else {
                crate::atoms::comparison::DiffDecision::Different
            }
        },
        |authorization, _| {
            crate::atoms::r#do::fetch_artifact::install(
                &authorization,
                invocation,
                destination,
                &download,
            )
        },
    );
    let run = match result {
        Ok(run) => run,
        Err(error) => {
            let _ = crate::atoms::attest::fetch_artifact::attest(
                &receipt_dir.join("harmonia-atoms.log"),
                false,
                false,
                &format!("state=Drift; care=atomic install failed; after=Drift; error={error}"),
            );
            return Err(error);
        }
    };
    match run {
        crate::atoms::comparison::ComparisonRun::Current { .. } => {
            crate::atoms::attest::fetch_artifact::attest(
                &receipt_dir.join("harmonia-atoms.log"),
                true,
                false,
                "state=Current; care=verified embedded source SHA; after=Current",
            )?;
            Ok(crate::OperationOutcome {
                ok: true,
                changed: false,
                skipped: true,
                message: "fetch-artifact-current".into(),
                command: None,
            })
        }
        crate::atoms::comparison::ComparisonRun::Moved { movement: (), .. } => {
            crate::atoms::attest::fetch_artifact::attest(
                &receipt_dir.join("harmonia-atoms.log"),
                true,
                true,
                if beam_refetch {
                    "state=Drift; care=verified digest and atomic install; after=Current; reason=fetch-artifact-refetch-beam-env-sha"
                } else {
                    "state=Drift; care=verified digest and atomic install; after=Current"
                },
            )?;
            Ok(crate::OperationOutcome {
                ok: true,
                changed: true,
                skipped: false,
                message: "fetch-artifact-installed".into(),
                command: None,
            })
        }
    }
}

pub(crate) fn declaration(
) -> Result<Option<&'static crate::tools::declaration::Declaration>, String> {
    crate::tools::declaration::get("fetch-artifact")
}

#[cfg(test)]
mod tests {
    use super::execute;
    use serde_json::json;
    use std::{
        collections::BTreeMap,
        fs,
        io::{Read, Write},
        net::TcpListener,
        path::PathBuf,
        thread,
    };

    const SOURCE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
    const ARTIFACT_NAME: &str = "fallback-fixture";

    fn source_fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("src")).unwrap();
        fs::write(
            root.path().join("Cargo.toml"),
            "[package]\nname = \"fallback-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(
            root.path().join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\nversion = 3\n\n[[package]]\nname = \"fallback-fixture\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(
            root.path().join("src/main.rs"),
            "fn main() { println!(\"{}\", env!(\"CADUCEUS_BUILD_SHA\")); }\n",
        )
        .unwrap();
        root
    }

    fn release_fallback_args(
        root: &std::path::Path,
        api_root: String,
        destination: &std::path::Path,
        installed_binary: &std::path::Path,
    ) -> BTreeMap<String, serde_json::Value> {
        [
            ("component", json!("caduceus")),
            ("release_repo", json!("OWNER/REPO")),
            ("api_root", json!(api_root)),
            ("source_build_sha", json!(SOURCE_SHA)),
            ("artifact_name", json!(ARTIFACT_NAME)),
            ("source_dir", json!(root)),
            ("destination", json!(destination)),
            ("installed_binary", json!(installed_binary)),
            ("bearer", json!("owner")),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect()
    }

    fn one_response_server(status: u16) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            let length = stream.read(&mut request).unwrap();
            assert!(String::from_utf8_lossy(&request[..length]).starts_with(
                "GET /api/v1/repos/OWNER/REPO/releases/tags/0123456789abcdef0123456789abcdef01234567 "
            ));
            let reason = match status {
                401 => "Unauthorized",
                404 => "Not Found",
                500 => "Internal Server Error",
                _ => "Unexpected",
            };
            write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });
        (format!("http://{address}/api/v1"), server)
    }

    #[test]
    fn release_404_builds_source_fallback_and_installs_destination() {
        let root = source_fixture();
        let destination = root.path().join("destination");
        let installed_binary = root.path().join("installed");
        let receipts = root.path().join("receipts");
        let (api_root, server) = one_response_server(404);
        let args = release_fallback_args(root.path(), api_root, &destination, &installed_binary);
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome = execute(&args, &receipts, true, Some(&invocation)).unwrap();
        server.join().unwrap();
        assert!(outcome.ok);
        assert!(outcome.changed);
        assert!(!outcome.skipped);
        assert!(destination.exists());
        assert!(crate::atoms::ask::fetch_artifact::identity_matches(
            &destination,
            SOURCE_SHA,
            "embedded-sha",
            "caduceus"
        ));
    }

    #[test]
    fn release_401_writes_fallback_schema_and_installs_destination() {
        let root = source_fixture();
        let destination = root.path().join("destination");
        let installed_binary = root.path().join("installed");
        let receipts = root.path().join("receipts");
        let (api_root, server) = one_response_server(401);
        let expected_artifact_url =
            format!("{api_root}/repos/OWNER/REPO/releases/tags/{SOURCE_SHA}");
        let args = release_fallback_args(root.path(), api_root, &destination, &installed_binary);
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome = execute(&args, &receipts, true, Some(&invocation)).unwrap();
        server.join().unwrap();
        assert!(outcome.ok);
        assert!(outcome.changed);
        let fallback: serde_json::Value =
            serde_json::from_slice(&fs::read(receipts.join("fallback.json")).unwrap()).unwrap();
        assert_eq!(fallback["schema"], "harmonia.fetch-artifact.fallback.v1");
        assert_eq!(fallback["fallback_reason"], "auth-required");
        assert_eq!(fallback["artifact_url"], expected_artifact_url);
        assert_eq!(fallback["source_build_sha"], SOURCE_SHA);
        assert!(destination.exists());
    }

    #[test]
    fn registry_403_builds_source_fallback_and_records_refusing_manifest_url() {
        let root = source_fixture();
        let destination = root.path().join("destination");
        let installed_binary = root.path().join("installed");
        let receipts = root.path().join("receipts");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            let length = stream.read(&mut request).unwrap();
            assert!(String::from_utf8_lossy(&request[..length]).starts_with(
                "GET /caduceus/0123456789abcdef0123456789abcdef01234567/manifest.json "
            ));
            write!(
                stream,
                "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });
        let registry_base = format!("http://{address}");
        let expected_manifest_url = format!("{registry_base}/caduceus/{SOURCE_SHA}/manifest.json");
        let args: BTreeMap<String, serde_json::Value> = [
            ("component", json!("caduceus")),
            ("registry_base", json!(&registry_base)),
            ("source_build_sha", json!(SOURCE_SHA)),
            ("artifact_name", json!(ARTIFACT_NAME)),
            ("source_dir", json!(root.path())),
            ("destination", json!(&destination)),
            ("installed_binary", json!(&installed_binary)),
            ("bearer", json!("owner")),
            ("identity", json!("embedded-sha")),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome = execute(&args, &receipts, true, Some(&invocation)).unwrap();
        server.join().unwrap();
        assert!(outcome.ok);
        assert!(outcome.changed);
        let fallback: serde_json::Value =
            serde_json::from_slice(&fs::read(receipts.join("fallback.json")).unwrap()).unwrap();
        assert_eq!(fallback["fallback_reason"], "auth-required");
        assert_eq!(fallback["artifact_url"], expected_manifest_url);
        assert_eq!(fallback["source_build_sha"], SOURCE_SHA);
        assert!(destination.exists());
    }

    #[test]
    fn release_500_refuses_without_invoking_source_fallback_build() {
        let root = source_fixture();
        let destination = root.path().join("destination");
        let installed_binary = root.path().join("installed");
        let receipts = root.path().join("receipts");
        let (api_root, server) = one_response_server(500);
        let args = release_fallback_args(root.path(), api_root, &destination, &installed_binary);
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let error = execute(&args, &receipts, true, Some(&invocation))
            .expect_err("server failure must not invoke source fallback");
        server.join().unwrap();
        assert!(error.contains("500"), "unexpected error: {error}");
        assert!(!root
            .path()
            .join("target/release")
            .join(ARTIFACT_NAME)
            .exists());
        assert!(!destination.exists());
    }

    #[test]
    fn staged_present_stale_installed_identity_is_drift_and_downloads_fresh_artifact() {
        let old = "0123456789abcdef0123456789abcdef01234567";
        let new = "fedcba9876543210fedcba9876543210fedcba98";
        let root =
            std::env::temp_dir().join(format!("harmonia-fetch-identity-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let installed = root.join("installed");
        let destination = root.join("destination");
        let receipts = root.join("receipts");
        fs::write(&installed, format!("caduceus.liveness.v1{old}")).unwrap();
        fs::write(
            &destination,
            format!("caduceus.liveness.v1{new}:staged-by-earlier-run"),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for path in [
                format!("/caduceus/{new}/manifest.json"),
                format!("/caduceus/{new}/artifact"),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 4096];
                let n = stream.read(&mut request).unwrap();
                assert!(String::from_utf8_lossy(&request[..n]).starts_with(&format!("GET {path} ")));
                let body = if path.ends_with("manifest.json") {
                    format!(
                        r#"{{"schema":"estate.artifact.manifest.v1","component":"caduceus","source_sha":"{new}","target":"x86_64","sha256":"9dd6c95a5644c1d55a1f7ac5302dad5564637d79f55924c9949427a0efca1ec1","built_at":"now","pipeline_url":"https://ci"}}"#
                    )
                } else {
                    format!("caduceus.liveness.v1{new}")
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });
        let args: BTreeMap<String, serde_json::Value> = [
            ("component", json!("caduceus")),
            ("registry_base", json!(format!("http://{address}"))),
            ("source_build_sha", json!(new)),
            ("artifact_name", json!("artifact")),
            ("destination", json!(PathBuf::from(&destination))),
            ("installed_binary", json!(PathBuf::from(&installed))),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome = execute(&args, &receipts, true, Some(&invocation)).unwrap();
        server.join().unwrap();
        assert_eq!(outcome.message, "fetch-artifact-installed");
        assert!(outcome.ok);
        assert!(!outcome.skipped);
        assert!(outcome.changed);
        assert_eq!(
            fs::read(&destination).unwrap(),
            format!("caduceus.liveness.v1{new}").as_bytes()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn profile_source_refusal_preserves_installed_bytes_before_download() {
        let root = tempfile::tempdir().unwrap();
        let installed = root.path().join("installed");
        let before = b"installed-before-profile-blocker";
        fs::write(&installed, before).unwrap();
        let cases = [
            (
                "missing",
                root.path().join("missing"),
                "fetch-artifact-profile-source-missing",
            ),
            (
                "unreadable",
                root.path().join("unreadable"),
                "fetch-artifact-profile-source-unreadable",
            ),
            (
                "malformed",
                root.path().join("malformed.json"),
                "fetch-artifact-profile-source-malformed",
            ),
            (
                "profile-less",
                root.path().join("profile-less.json"),
                "fetch-artifact-profile-source-profile-missing",
            ),
        ];
        fs::create_dir(cases[1].1.clone()).unwrap();
        fs::write(&cases[2].1, "{").unwrap();
        fs::write(&cases[3].1, "{}").unwrap();

        for (name, profile_source, expected) in cases {
            let destination = root.path().join(format!("destination-{name}"));
            let args: BTreeMap<String, serde_json::Value> = [
                ("component", json!("fixture")),
                ("release_repo", json!("OWNER/REPO")),
                ("api_root", json!("http://127.0.0.1:1/api/v1")),
                (
                    "source_build_sha",
                    json!("0123456789abcdef0123456789abcdef01234567"),
                ),
                ("artifact_name", json!("fixture")),
                ("profile_axis", json!("profile")),
                ("profile_source", json!(profile_source)),
                ("destination", json!(&destination)),
                ("installed_binary", json!(&installed)),
            ]
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect();
            let error = execute(&args, &root.path().join("receipts"), true, None)
                .expect_err("profile source blocker");
            assert_eq!(error, expected, "case={name}");
            assert_eq!(fs::read(&installed).unwrap(), before, "case={name}");
            assert!(!destination.exists(), "case={name}");
        }
    }

    #[test]
    fn profile_axis_rejects_invalid_axis_before_profile_source_read() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("destination");
        let installed = root.path().join("installed");
        let args: BTreeMap<String, serde_json::Value> = [
            ("component", json!("fixture")),
            ("release_repo", json!("OWNER/REPO")),
            (
                "source_build_sha",
                json!("0123456789abcdef0123456789abcdef01234567"),
            ),
            ("profile_axis", json!("unsupported")),
            ("destination", json!(&destination)),
            ("installed_binary", json!(&installed)),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect();

        let error = execute(&args, &root.path().join("receipts"), true, None)
            .expect_err("invalid profile axis");
        assert_eq!(error, "fetch-artifact-profile-axis-invalid");
    }

    #[test]
    fn profile_axis_rejects_unsafe_profile_and_name_overrides() {
        let root = tempfile::tempdir().unwrap();
        let profile_source = root.path().join("profile.json");
        fs::write(&profile_source, r#"{"profile":"../homeserver"}"#).unwrap();
        let destination = root.path().join("destination");
        let installed = root.path().join("installed");
        let base_args: BTreeMap<String, serde_json::Value> = [
            ("component", json!("fixture")),
            ("release_repo", json!("OWNER/REPO")),
            (
                "source_build_sha",
                json!("0123456789abcdef0123456789abcdef01234567"),
            ),
            ("artifact_name", json!("fixture")),
            ("profile_axis", json!("profile")),
            ("profile_source", json!(&profile_source)),
            ("destination", json!(&destination)),
            ("installed_binary", json!(&installed)),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect();
        let error = execute(&base_args, &root.path().join("receipts"), true, None)
            .expect_err("unsafe profile");
        assert_eq!(error, "fetch-artifact-profile-invalid");

        fs::write(&profile_source, r#"{"profile":"homeserver"}"#).unwrap();
        for (key, value, expected) in [
            (
                "asset_name",
                "fixture-x86_64",
                "fetch-artifact-profile-asset-name-mismatch",
            ),
            (
                "sidecar_name",
                "fixture-homeserver-x86_64.digest",
                "fetch-artifact-profile-sidecar-name-mismatch",
            ),
        ] {
            let mut args = base_args.clone();
            args.insert(key.into(), json!(value));
            let error = execute(&args, &root.path().join("receipts"), true, None)
                .expect_err("profile name override");
            assert_eq!(error, expected, "override={key}");
        }
    }

    #[test]
    fn profile_axis_native_release_uses_profile_specific_asset_and_sidecar() {
        let root = tempfile::tempdir().unwrap();
        let profile_source = root.path().join("profile.json");
        fs::write(&profile_source, r#"{"profile":"homeserver"}"#).unwrap();
        let source_sha = "0123456789abcdef0123456789abcdef01234567";
        let artifact = format!("profile-specific-release-artifact-{source_sha}").into_bytes();
        let digest = crate::atoms::file_sha256(&artifact);
        let asset_name = "caduceus-homeserver-x86_64";
        let sidecar_name = "caduceus-homeserver-x86_64.sha256";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let release_body = json!({
            "target_commitish": source_sha,
            "assets": [
                {
                    "name": asset_name,
                    "browser_download_url": format!("http://{address}/artifact"),
                },
                {
                    "name": sidecar_name,
                    "browser_download_url": format!("http://{address}/sidecar"),
                },
            ],
        })
        .to_string()
        .into_bytes();
        let artifact_for_server = artifact.clone();
        let server = thread::spawn(move || {
            for (path, body) in [
                (
                    format!("/api/v1/repos/OWNER/REPO/releases/tags/{source_sha}"),
                    release_body,
                ),
                ("/artifact".into(), artifact_for_server),
                (
                    "/sidecar".into(),
                    format!("{digest}  {asset_name}\n").into_bytes(),
                ),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 4096];
                let n = stream.read(&mut request).unwrap();
                assert!(
                    String::from_utf8_lossy(&request[..n]).starts_with(&format!("GET {path} ")),
                    "unexpected request for {path}"
                );
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        let destination = root.path().join("destination");
        let installed = root.path().join("installed");
        let args: BTreeMap<String, serde_json::Value> = [
            ("component", json!("caduceus")),
            ("release_repo", json!("OWNER/REPO")),
            ("api_root", json!(format!("http://{address}/api/v1"))),
            ("source_build_sha", json!(source_sha)),
            ("artifact_name", json!("caduceus")),
            ("profile_axis", json!("profile")),
            ("profile_source", json!(&profile_source)),
            ("destination", json!(&destination)),
            ("installed_binary", json!(&installed)),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome = execute(
            &args,
            &root.path().join("receipts"),
            true,
            Some(&invocation),
        )
        .unwrap();
        server.join().unwrap();
        assert!(outcome.ok);
        assert!(outcome.changed);
        assert_eq!(fs::read(destination).unwrap(), artifact);
    }

    #[test]
    fn beam_refetches_current_embedded_identity() {
        let new = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        let installed = root.join("installed");
        let destination = root.join("destination");
        let receipts = root.join("receipts");
        fs::write(&installed, format!("caduceus.liveness.v1{new}")).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for path in [
                format!("/caduceus/{new}/manifest.json"),
                format!("/caduceus/{new}/artifact"),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 4096];
                let n = stream.read(&mut request).unwrap();
                assert!(String::from_utf8_lossy(&request[..n]).starts_with(&format!("GET {path} ")));
                let body = if path.ends_with("manifest.json") {
                    format!(
                        r#"{{"schema":"estate.artifact.manifest.v1","component":"caduceus","source_sha":"{new}","target":"x86_64","sha256":"32f70da4e10cc86076da0e00a3b783ed3c2731302adc851d9e32fad57cbb7c20","built_at":"now","pipeline_url":"https://ci"}}"#
                    )
                } else {
                    format!("caduceus.liveness.v1{new}")
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });
        let args: BTreeMap<String, serde_json::Value> = [
            ("component", json!("caduceus")),
            ("registry_base", json!(format!("http://{address}"))),
            ("source_build_sha", json!(new)),
            ("beam_refetch", json!(true)),
            ("artifact_name", json!("artifact")),
            ("destination", json!(PathBuf::from(&destination))),
            ("installed_binary", json!(PathBuf::from(&installed))),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome = execute(&args, &receipts, true, Some(&invocation)).unwrap();
        server.join().unwrap();
        assert_eq!(outcome.message, "fetch-artifact-installed");
        let atom_log = fs::read_to_string(receipts.join("harmonia-atoms.log")).unwrap();
        assert!(atom_log.contains("fetch-artifact-refetch-beam-env-sha"));
        assert!(outcome.ok);
        assert!(!outcome.skipped);
        assert!(outcome.changed);
        assert_eq!(
            fs::read(&destination).unwrap(),
            format!("caduceus.liveness.v1{new}").as_bytes()
        );
    }
}
