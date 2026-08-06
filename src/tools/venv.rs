use super::{ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::OperationOutcome;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

pub const NAME: &str = "venv";
pub const DESCRIPTION: &str = "Change-gated Python virtual-environment convergence primitive.";
pub const PERMUTATIONS: &[ToolPermutation] = &[ToolPermutation::new(
    "converge",
    "ensure a declared virtual environment and refresh declared dependencies only on content change",
    &[
        ToolArg::required("venv", ToolArgKind::String),
        ToolArg::required("source_root", ToolArgKind::String),
        ToolArg::required("source_patterns", ToolArgKind::StringArray),
        ToolArg::optional("python", ToolArgKind::String),
    ],
)];
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION, PERMUTATIONS);

fn safe_absolute_path(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute() && !path.components().any(|part| matches!(part, Component::ParentDir))
}

pub(crate) fn validate_ladder_args(args: &BTreeMap<String, Value>) -> Result<(), String> {
    for name in ["venv", "source_root"] {
        let value = args.get(name).and_then(Value::as_str).unwrap_or_default();
        if !safe_absolute_path(value) {
            return Err(format!("venv-{name}-path-rejected"));
        }
    }
    let patterns = args.get("source_patterns").and_then(Value::as_array).ok_or("venv-source-patterns-missing")?;
    if patterns.is_empty() || patterns.iter().any(|value| !matches!(value.as_str(), Some("requirements*.txt") | Some("pyproject.toml"))) {
        return Err("venv-source-patterns-rejected".into());
    }
    if let Some(python) = args.get("python").and_then(Value::as_str) {
        if !safe_absolute_path(python) { return Err("venv-python-path-rejected".into()); }
    }
    Ok(())
}

fn declaration_files(source_root: &Path, patterns: &[String]) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for entry in fs::read_dir(source_root).map_err(|error| format!("venv-source-read-failed {}: {error}", source_root.display()))? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if (!patterns.iter().any(|pattern| pattern == "requirements*.txt") || !(name.starts_with("requirements") && name.ends_with(".txt")))
            && (!patterns.iter().any(|pattern| pattern == "pyproject.toml") || name != "pyproject.toml") { continue; }
        if entry.file_type().map_err(|error| error.to_string())?.is_file() { files.push(entry.path()); }
    }
    files.sort();
    Ok(files)
}

fn aggregate_digest(source_root: &Path, files: &[PathBuf]) -> Result<String, String> {
    let mut digest = Sha256::new();
    for path in files {
        let relative = path.strip_prefix(source_root).map_err(|error| error.to_string())?;
        digest.update(relative.to_string_lossy().as_bytes());
        digest.update([0]);
        digest.update(Sha256::digest(fs::read(path).map_err(|error| format!("venv-declaration-read-failed {}: {error}", path.display()))?));
        digest.update([0]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn command_ok(program: &Path, args: &[&str], cwd: Option<&Path>) -> Result<(), String> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(cwd) = cwd { command.current_dir(cwd); }
    let output = command.output().map_err(|error| format!("venv-command-start-failed {}: {error}", program.display()))?;
    if output.status.success() { Ok(()) } else { Err(format!("venv-command-failed {} exit={}", program.display(), output.status)) }
}

pub(crate) fn execute_ladder_step(
    args: &BTreeMap<String, Value>, receipt_dir: &Path, receipt_name: &str, apply: bool,
) -> Result<OperationOutcome, String> {
    validate_ladder_args(args)?;
    let venv = PathBuf::from(args.get("venv").and_then(Value::as_str).unwrap());
    let source_root = PathBuf::from(args.get("source_root").and_then(Value::as_str).unwrap());
    let patterns: Vec<String> = args.get("source_patterns").and_then(Value::as_array).unwrap().iter().filter_map(Value::as_str).map(str::to_string).collect();
    let python = PathBuf::from(args.get("python").and_then(Value::as_str).unwrap_or("/usr/bin/python3"));
    let files = declaration_files(&source_root, &patterns)?;
    let hash = if files.is_empty() { None } else { Some(aggregate_digest(&source_root, &files)?) };
    let state = venv.join(".harmonia-sbin-dependency-sha256");
    let prior = fs::read_to_string(&state).ok().map(|value| value.trim().to_string());
    let venv_python = venv.join("bin/python");
    let valid = venv_python.is_file();
    let different = !valid || hash.as_ref() != prior.as_ref();
    let mut changed = false;
    let mut movement = "none";
    if apply && different {
        if !valid {
            command_ok(&python, &["-m", "venv", venv.to_str().ok_or("venv-path-utf8")?], None)?;
            movement = "create-venv";
        }
        if let Some(hash) = &hash {
            for file in &files {
                if file.file_name().and_then(|name| name.to_str()) == Some("pyproject.toml") {
                    command_ok(&venv_python, &["-m", "pip", "install", "."], Some(&source_root))?;
                } else {
                    command_ok(&venv_python, &["-m", "pip", "install", "-r", file.to_str().ok_or("venv-file-utf8")?], None)?;
                }
            }
            fs::write(&state, format!("{hash}\n")).map_err(|error| format!("venv-state-write-failed {}: {error}", state.display()))?;
            movement = "refresh-dependencies";
        }
        changed = true;
    }
    fs::create_dir_all(receipt_dir).map_err(|error| error.to_string())?;
    crate::write_json(&receipt_dir.join(format!("{receipt_name}.json")), &json!({
        "schema":"harmonia.venv.converge.v1", "ok":true, "apply":apply, "changed":changed,
        "venv":venv, "source_root":source_root, "dependency_files":files,
        "dependency_sha256":hash, "previous_dependency_sha256":prior,
        "diff_decision":if different {"different"} else {"empty"}, "movement":movement,
        "first_missing_signal":"none"
    }))?;
    Ok(OperationOutcome { ok: true, changed, skipped: !apply, message: format!("venv converge {movement}"), command: None })
}
