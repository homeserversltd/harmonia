pub(crate) const DEFAULT_BEARER: &str = "owner";
use serde_json::Value;
use std::collections::BTreeMap;

fn string_arg<'a>(args: &'a BTreeMap<String, Value>, name: &str) -> Result<&'a str, String> {
    args.get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("service-runtime-missing-{name}"))
}

fn validate_build_environment(args: &BTreeMap<String, Value>) -> Result<(), String> {
    let Some(value) = args.get("build_environment") else {
        return Ok(());
    };
    let Some(values) = value.as_object() else {
        return Err("service-runtime-build-environment-invalid".into());
    };
    for (key, value) in values {
        if !matches!(key.as_str(), "RUSTUP_HOME" | "CARGO_HOME") {
            return Err(format!("service-runtime-build-environment-refused-{key}"));
        }
        if value.as_str().is_none_or(|text| text.trim().is_empty()) {
            return Err(format!("service-runtime-build-environment-invalid-{key}"));
        }
    }
    Ok(())
}

/// Validate the declaration retained long enough for ladder lowering.
/// No execution state or service-runtime actuator is constructed here.
pub(crate) fn validate_ladder_args(args: &BTreeMap<String, Value>) -> Result<(), String> {
    validate_build_environment(args)?;
    for name in [
        "component",
        "source_dir",
        "install_bin",
        "service",
        "url",
        "binary_name",
        "op_prefix",
        "run_schema",
        "managed_files_schema",
    ] {
        string_arg(args, name)?;
    }
    if let Some(value) = args.get("source_sha_file") {
        if value.as_str().is_none_or(|path| path.trim().is_empty()) {
            return Err("service-runtime-source-sha-file-invalid".into());
        }
    }
    if let Some(files) = args.get("managed_files") {
        if !files.is_array() {
            return Err("service-runtime-managed-files-invalid".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_ladder_args;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn base_args() -> BTreeMap<String, serde_json::Value> {
        [
            ("component", json!("fixture")),
            ("source_dir", json!("/src")),
            ("install_bin", json!("/bin/fixture")),
            ("service", json!("fixture.service")),
            ("url", json!("http://127.0.0.1/health")),
            ("binary_name", json!("fixture")),
            ("op_prefix", json!("fixture")),
            ("run_schema", json!("demo.v1")),
            ("managed_files_schema", json!("demo.v1")),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect()
    }

    #[test]
    fn source_sha_file_is_optional_but_nonempty_when_present() {
        let mut args = base_args();
        assert!(validate_ladder_args(&args).is_ok());
        args.insert("source_sha_file".into(), json!("/state/source.sha"));
        assert!(validate_ladder_args(&args).is_ok());
        args.insert("source_sha_file".into(), json!("  "));
        assert_eq!(
            validate_ladder_args(&args),
            Err("service-runtime-source-sha-file-invalid".into())
        );
        args.insert("source_sha_file".into(), json!(42));
        assert_eq!(
            validate_ladder_args(&args),
            Err("service-runtime-source-sha-file-invalid".into())
        );
    }
}
