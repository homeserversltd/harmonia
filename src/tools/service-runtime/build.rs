const BUILD_ENV_ALLOWLIST: &[&str] = &["RUSTUP_HOME", "CARGO_HOME"];
fn build_identity_name(component: &str) -> String {
    let component = component
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("{component}_BUILD_SHA")
}

fn build_environment(
    args: &BTreeMap<String, Value>,
    acquired_source_sha: Option<&str>,
) -> Result<BTreeMap<String, String>, String> {
    let mut environment = match args.get("build_environment") {
        None => BTreeMap::new(),
        Some(Value::Object(values)) => values
            .iter()
            .map(|(key, value)| {
                if !BUILD_ENV_ALLOWLIST.contains(&key.as_str()) {
                    return Err(format!("service-runtime-build-environment-refused-{key}"));
                }
                let value = value
                    .as_str()
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| format!("service-runtime-build-environment-invalid-{key}"))?;
                Ok((key.clone(), value.to_string()))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?,
        Some(_) => return Err("service-runtime-build-environment-invalid".to_string()),
    };
    if let Some(source_sha) = acquired_source_sha {
        if !is_hex_sha(source_sha) {
            return Err("service-runtime-identity-source-sha-invalid".to_string());
        }
        let component = string_arg(args, "component")?;
        environment.insert(build_identity_name(&component), source_sha.to_string());
    }
    Ok(environment)
}
fn write_skipped_build_receipt(
    receipt_dir: &Path,
    spec: &ServiceRuntimeSpec,
    promoted_source_sha: &str,
    remote_sha: &str,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{}.json", spec.build_op)),
        &json!({
            "schema": "harmonia.service-runtime.cargo-build.v1",
            "state": "converged-quiet",
            "ok": true,
            "changed": false,
            "invoked": false,
            "reason": "source-sha-matches-promoted-source-and-installed-binary",
            "remote_sha": remote_sha,
            "promoted_source_sha": promoted_source_sha,
        }),
    )
}
