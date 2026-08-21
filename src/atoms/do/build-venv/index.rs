//! Build-venv atom: owns venv creation, dependency installation, and state custody.
use crate::atoms::r#do::InvocationKey;
use crate::atoms::comparison::ActionAuthorization;
use crate::OperationOutcome;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub venv: PathBuf,
    pub source_root: PathBuf,
    pub source_patterns: Vec<String>,
    pub python: PathBuf,
    pub receipt_dir: PathBuf,
    pub receipt_name: String,
    pub timeout_secs: u64,
}

pub(crate) fn converge(
    authorization: ActionAuthorization,
    invocation: InvocationKey,
    request: &crate::build_venv::Request<'_>,
    observation: &crate::atoms::ask::build_venv::Observation,
) -> Result<&'static str, String> {
    let mut movement = "none";
    if !observation.venv_valid {
        let result = crate::atoms::r#do::run_command::command_with_timeout(
            authorization,
            invocation,
            request.python.to_str().ok_or("venv-python-path-utf8")?,
            &[
                "-m".into(),
                "venv".into(),
                request.venv.to_str().ok_or("venv-path-utf8")?.into(),
            ],
            Duration::from_secs(request.timeout_secs),
        )?;
        ensure_ok(&result, request.python.to_string_lossy().as_ref())?;
        movement = "create-venv";
    }
    if observation.dependency_sha256 != observation.previous_dependency_sha256 {
        if let Some(hash) = observation.dependency_sha256.as_deref() {
            let python = request.venv.join("bin/python");
            for file in &observation.dependency_files {
                let (args, cwd) =
                    if file.file_name().and_then(|n| n.to_str()) == Some("pyproject.toml") {
                        (
                            vec!["-m".into(), "pip".into(), "install".into(), ".".into()],
                            Some(request.source_root),
                        )
                    } else {
                        (
                            vec![
                                "-m".into(),
                                "pip".into(),
                                "install".into(),
                                "-r".into(),
                                file.to_string_lossy().into_owned(),
                            ],
                            None,
                        )
                    };
                let result = crate::atoms::r#do::run_command::command_with_timeout_in_dir(
                    authorization,
                    invocation,
                    python.to_str().ok_or("venv-python-path-utf8")?,
                    &args,
                    cwd,
                    Duration::from_secs(request.timeout_secs),
                )?;
                ensure_ok(&result, python.to_string_lossy().as_ref())?;
            }
            crate::atoms::r#do::write_file::file_write(
                authorization,
                invocation,
                &request.venv.join(".harmonia-sbin-dependency-sha256"),
                format!("{hash}\n").as_bytes(),
                crate::atoms::r#do::write_file::FileWriteOptions {
                    write_bytes: true,
                    mode: Some(0o600),
                    uid: Some(unsafe { libc::geteuid() }),
                    gid: Some(unsafe { libc::getegid() }),
                    backup_to: None,
                },
            )?;
            movement = "refresh-dependencies";
        }
    }
    Ok(movement)
}
fn ensure_ok(result: &crate::atoms::CommandObservation, program: &str) -> Result<(), String> {
    if result.ok {
        Ok(())
    } else if result.code.is_none() {
        Err(format!(
            "venv-command-start-failed {program}: {}",
            result.stderr
        ))
    } else {
        Err(format!(
            "venv-command-failed {program} exit={:?}",
            result.code
        ))
    }
}
