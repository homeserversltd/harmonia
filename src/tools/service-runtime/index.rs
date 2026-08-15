use crate::tools::{ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use serde_json::Value;
use std::collections::BTreeMap;

pub const NAME: &str = "service-runtime";
pub const DESCRIPTION: &str =
    "declaration-only service runtime lowered to owning primitive tools before execution.";
pub(crate) const DEFAULT_BEARER: &str = "owner";

const SERVICE_RUNTIME_ARGS: &[ToolArg] = &[
    ToolArg::optional("module_id", ToolArgKind::String),
    ToolArg::required("component", ToolArgKind::String),
    ToolArg::optional("bearer", ToolArgKind::String),
    ToolArg::required("source_dir", ToolArgKind::String),
    ToolArg::required("install_bin", ToolArgKind::String),
    ToolArg::required("service", ToolArgKind::String),
    ToolArg::required("url", ToolArgKind::String),
    ToolArg::required("binary_name", ToolArgKind::String),
    ToolArg::required("op_prefix", ToolArgKind::String),
    ToolArg::required("run_schema", ToolArgKind::String),
    ToolArg::required("managed_files_schema", ToolArgKind::String),
    ToolArg::optional("managed_files", ToolArgKind::Json),
    ToolArg::optional("caduceus_profile_source", ToolArgKind::Json),
    ToolArg::optional("caduceus_commands", ToolArgKind::Json),
    ToolArg::optional("build_environment", ToolArgKind::Json),
];

pub const PERMUTATIONS: &[ToolPermutation] = &[ToolPermutation::new(
    "converge",
    "declare a Rust service runtime for pre-execution primitive lowering",
    SERVICE_RUNTIME_ARGS,
)];
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION, PERMUTATIONS);

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
    if let Some(files) = args.get("managed_files") {
        if !files.is_array() {
            return Err("service-runtime-managed-files-invalid".into());
        }
    }
    Ok(())
}
