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
    let registry_base = args.get("registry_base").and_then(Value::as_str).unwrap_or("");
    let release_repo = args.get("release_repo").and_then(Value::as_str).unwrap_or("");
    let identity = args.get("identity").and_then(Value::as_str).unwrap_or_else(|| {
        if release_repo.trim().is_empty() { "liveness-marker" } else { "embedded-sha" }
    });
    let source_sha = required("source_build_sha")?;
    let artifact_name = args.get("artifact_name").and_then(Value::as_str).unwrap_or(component);
    let destination = Path::new(required("destination")?);
    let installed_binary = Path::new(required("installed_binary")?);
    if !crate::atoms::ask::fetch_artifact::validate_source_sha(source_sha) {
        return Err("fetch-artifact-source-sha-invalid".into());
    }

    let native_release = !release_repo.trim().is_empty();
    let native_download = if native_release {
        let source_dir = Path::new(args.get("source_dir").and_then(Value::as_str).unwrap_or(""));
        let tag = args.get("release_tag").and_then(Value::as_str).map(str::to_owned).or_else(|| crate::atoms::ask::fetch_artifact::release_version(source_dir).ok()).unwrap_or_default();
        match crate::atoms::ask::fetch_artifact::download_release(component, source_dir, release_repo, (!tag.is_empty()).then_some(tag.as_str()), args.get("api_root").and_then(Value::as_str).unwrap_or("https://git.home.arpa/api/v1"), args.get("asset_name").and_then(Value::as_str), args.get("sidecar_name").and_then(Value::as_str)) {
            Ok(Some(download)) => Some(download),
            Ok(None) => { let api=args.get("api_root").and_then(Value::as_str).unwrap_or("https://git.home.arpa/api/v1").trim_end_matches('/'); let message=format!("fetch-artifact-release-absent tag={tag} url={api}/repos/{release_repo}/releases/tags/{tag}"); crate::atoms::attest::fetch_artifact::attest(&receipt_dir.join("harmonia-atoms.log"),false,false,&format!("state=Drift; care=artifact acquisition refused; after=Drift; error={message}"))?; return Ok(crate::OperationOutcome{ok:false,changed:false,skipped:true,message,command:None}); }
            Err(error) => { let _=crate::atoms::attest::fetch_artifact::attest(&receipt_dir.join("harmonia-atoms.log"),false,false,&format!("state=Drift; care=artifact acquisition refused; after=Drift; error={error}")); return Err(error); }
        }
    } else { None };
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
    if current {
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
    let download = if let Some(download)=native_download { download } else { match crate::atoms::ask::fetch_artifact::download(component, registry_base, source_sha, artifact_name) { Ok(download)=>download, Err(error)=>{ let _=crate::atoms::attest::fetch_artifact::attest(&receipt_dir.join("harmonia-atoms.log"),false,false,&format!("state=Drift; care=artifact acquisition refused; after=Drift; error={error}")); return Err(error); } } };
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
    let result = crate::atoms::comparison::execute(
        "fetch-artifact",
        || {
            Ok(crate::atoms::ask::fetch_artifact::identity_matches(
                destination,
                &effective_source_sha,
                identity,
                component
            ))
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
                "state=Drift; care=verified digest and atomic install; after=Current",
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
        let root = std::env::temp_dir().join(format!("harmonia-fetch-absent-{}", std::process::id()));
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
            assert!(String::from_utf8_lossy(&request[..n]).starts_with("GET /api/v1/repos/OWNER/REPO/releases/tags/1.2.3 "));
            write!(stream, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });
        let args = [
            ("component", json!("fixture")),
            ("release_repo", json!("OWNER/REPO")),
            ("source_build_sha", json!("0123456789abcdef0123456789abcdef01234567")),
            ("source_dir", json!(root)),
            ("api_root", json!(format!("http://{address}/api/v1"))),
            ("destination", json!(destination)),
            ("installed_binary", json!(installed)),
        ].into_iter().map(|(key, value)| (key.into(), value)).collect();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome = execute(&args, &root.join("receipts"), true, Some(&invocation)).unwrap();
        server.join().unwrap();
        assert!(!outcome.ok); assert!(!outcome.changed); assert!(outcome.skipped); assert_eq!(outcome.command, None); assert_eq!(outcome.message, format!("fetch-artifact-release-absent tag=1.2.3 url=http://{address}/api/v1/repos/OWNER/REPO/releases/tags/1.2.3"));
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
        let root = std::env::temp_dir().join(format!("harmonia-fetch-identity-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let installed = root.join("installed");
        let destination = root.join("destination");
        let receipts = root.join("receipts");
        fs::write(&installed, format!("caduceus.liveness.v1{old}; unrelated={new}")).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for path in [format!("/caduceus/{new}/manifest.json"), format!("/caduceus/{new}/artifact")] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 4096];
                let n = stream.read(&mut request).unwrap();
                assert!(String::from_utf8_lossy(&request[..n]).starts_with(&format!("GET {path} ")));
                let body = if path.ends_with("manifest.json") {
                    format!(r#"{{"schema":"estate.artifact.manifest.v1","component":"caduceus","source_sha":"{new}","target":"x86_64","sha256":"9dd6c95a5644c1d55a1f7ac5302dad5564637d79f55924c9949427a0efca1ec1","built_at":"now","pipeline_url":"https://ci"}}"#)
                } else {
                    format!("caduceus.liveness.v1{new}")
                };
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
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
        assert_eq!(fs::read(&destination).unwrap(), format!("caduceus.liveness.v1{new}").as_bytes());
        let _ = fs::remove_dir_all(root);
    }
}
