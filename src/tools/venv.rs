use crate::OperationOutcome;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Component, Path};

fn safe_absolute_path(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        && !path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
}

pub(crate) fn validate_ladder_args(args: &BTreeMap<String, Value>) -> Result<(), String> {
    for name in ["venv", "source_root"] {
        let value = args.get(name).and_then(Value::as_str).unwrap_or_default();
        if !safe_absolute_path(value) {
            return Err(format!("venv-{name}-path-rejected"));
        }
    }
    let patterns = args
        .get("source_patterns")
        .and_then(Value::as_array)
        .ok_or("venv-source-patterns-missing")?;
    if patterns.is_empty()
        || patterns.iter().any(|value| {
            !matches!(
                value.as_str(),
                Some("requirements*.txt") | Some("pyproject.toml")
            )
        })
    {
        return Err("venv-source-patterns-rejected".into());
    }
    if let Some(python) = args.get("python").and_then(Value::as_str) {
        if !safe_absolute_path(python) {
            return Err("venv-python-path-rejected".into());
        }
    }
    Ok(())
}

pub(crate) fn execute_step(
    args: &BTreeMap<String, Value>,
    receipt_dir: &Path,
    receipt_name: &str,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    validate_ladder_args(args)?;
    let venv = std::path::PathBuf::from(args.get("venv").and_then(Value::as_str).unwrap());
    let source_root =
        std::path::PathBuf::from(args.get("source_root").and_then(Value::as_str).unwrap());
    let patterns = args
        .get("source_patterns")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect::<Vec<_>>();
    let python = std::path::PathBuf::from(
        args.get("python")
            .and_then(Value::as_str)
            .unwrap_or("/usr/bin/python3"),
    );
    crate::build_venv::run(
        &crate::build_venv::Request {
            venv: &venv,
            source_root: &source_root,
            source_patterns: &patterns,
            python: &python,
            receipt_dir,
            receipt_name,
            timeout_secs: crate::tools::command::DEFAULT_TIMEOUT_SECS,
        },
        apply,
        invocation,
    )
}
