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
