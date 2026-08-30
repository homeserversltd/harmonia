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
    let registry_base = required("registry_base")?;
    let source_sha = required("source_build_sha")?;
    let artifact_name = required("artifact_name")?;
    let destination = Path::new(required("destination")?);
    let installed_binary = Path::new(required("installed_binary")?);
    if !crate::atoms::ask::fetch_artifact::validate_source_sha(source_sha) {
        return Err("fetch-artifact-source-sha-invalid".into());
    }

    // Current is decided by the installed binary; the registry path is staging.
    let current = crate::atoms::ask::fetch_artifact::destination_identity(installed_binary, source_sha);
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
    let download = match crate::atoms::ask::fetch_artifact::download(
        component,
        registry_base,
        source_sha,
        artifact_name,
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
    let result = crate::atoms::comparison::execute(
        "fetch-artifact",
        || {
            Ok(crate::atoms::ask::fetch_artifact::destination_identity(
                destination,
                source_sha,
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
