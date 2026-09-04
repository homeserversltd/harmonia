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

    let native_release = !release_repo.trim().is_empty();
    let native_download = if native_release {
        let source_dir = Path::new(args.get("source_dir").and_then(Value::as_str).unwrap_or(""));
        let tag = args
            .get("release_tag")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| source_sha.to_owned());
        match crate::atoms::ask::fetch_artifact::download_release(
            component,
            artifact_name,
            source_dir,
            release_repo,
            (!tag.is_empty()).then_some(tag.as_str()),
            args.get("api_root")
                .and_then(Value::as_str)
                .unwrap_or("https://git.home.arpa/api/v1"),
            release_asset_name.as_deref(),
            release_sidecar_name.as_deref(),
            source_sha,
        ) {
            Ok(Some(download)) => Some(download),
            Ok(None) => {
                let api = args
                    .get("api_root")
                    .and_then(Value::as_str)
                    .unwrap_or("https://git.home.arpa/api/v1")
                    .trim_end_matches('/');
                let message = format!(
                    "fetch-artifact-release-absent tag={tag} url={api}/repos/{release_repo}/releases/tags/{tag}"
                );
                crate::atoms::attest::fetch_artifact::attest(
                    &receipt_dir.join("harmonia-atoms.log"),
                    false,
                    false,
                    &format!(
                        "state=Drift; care=artifact acquisition refused; after=Drift; error={message}"
                    ),
                )?;
                return Ok(crate::OperationOutcome {
                    ok: false,
                    changed: false,
                    skipped: true,
                    message,
                    command: None,
                });
            }
            Err(error) => {
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
    let download = if let Some(download) = native_download {
        download
    } else {
        let registry_artifact_name = release_asset_name.as_deref().unwrap_or(artifact_name);
        match crate::atoms::ask::fetch_artifact::download(
            component,
            registry_base,
            source_sha,
            registry_artifact_name,
        ) {
            Ok(download) => download,
            Err(error) => {
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
    let mut beam_refetch_pre_act = beam_refetch;
    let result = crate::atoms::comparison::execute(
        "fetch-artifact",
        || {
            if std::mem::take(&mut beam_refetch_pre_act) {
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
    #[test]
    fn absent_release_tag_refuses_without_staging() {
        let root =
            std::env::temp_dir().join(format!("harmonia-fetch-absent-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("Cargo.toml"), "[package]\nversion=\"1.2.3\"\n").unwrap();
        let installed = root.join("installed");
        let destination = root.join("destination");
        let installed_before = b"installed-before-sentinel";
        fs::write(&installed, installed_before).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            let n = stream.read(&mut request).unwrap();
            assert!(String::from_utf8_lossy(&request[..n])
                .starts_with("GET /api/v1/repos/OWNER/REPO/releases/tags/0123456789abcdef0123456789abcdef01234567 "));
            write!(
                stream,
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });
        let args = [
            ("component", json!("fixture")),
            ("release_repo", json!("OWNER/REPO")),
            (
                "source_build_sha",
                json!("0123456789abcdef0123456789abcdef01234567"),
            ),
            ("source_dir", json!(root)),
            ("api_root", json!(format!("http://{address}/api/v1"))),
            ("destination", json!(destination)),
            ("installed_binary", json!(installed)),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome = execute(&args, &root.join("receipts"), true, Some(&invocation)).unwrap();
        server.join().unwrap();
        assert!(!outcome.ok);
        assert!(!outcome.changed);
        assert!(outcome.skipped);
        assert_eq!(outcome.command, None);
        assert_eq!(outcome.message, format!("fetch-artifact-release-absent tag=0123456789abcdef0123456789abcdef01234567 url=http://{address}/api/v1/repos/OWNER/REPO/releases/tags/0123456789abcdef0123456789abcdef01234567"));
        assert_eq!(fs::read(&installed).unwrap(), installed_before);
        assert!(!destination.exists());
        let _ = fs::remove_dir_all(root);
    }

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

    #[test]
    fn stale_installed_identity_applies_fresh_artifact() {
        let old = "0123456789abcdef0123456789abcdef01234567";
        let new = "fedcba9876543210fedcba9876543210fedcba98";
        let root =
            std::env::temp_dir().join(format!("harmonia-fetch-identity-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let installed = root.join("installed");
        let destination = root.join("destination");
        let receipts = root.join("receipts");
        fs::write(
            &installed,
            format!("caduceus.liveness.v1{old}; unrelated={new}"),
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
