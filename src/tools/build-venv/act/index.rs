use crate::atoms;
use crate::tools::comparison::ActionAuthorization;
use std::time::Duration;
pub(super) fn converge(
    authorization: ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    request: &super::Request<'_>,
    observation: &super::observe::Observation,
) -> Result<&'static str, String> {
    let mut movement = "none";
    if !observation.venv_valid {
        let result = atoms::r#do::command_with_timeout(
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
            let (args, cwd) = if file.file_name().and_then(|n| n.to_str()) == Some("pyproject.toml")
            {
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
            let result = atoms::r#do::command_with_timeout_in_dir(
                authorization,
                invocation,
                python.to_str().ok_or("venv-python-path-utf8")?,
                &args,
                cwd,
                Duration::from_secs(request.timeout_secs),
            )?;
            ensure_ok(&result, python.to_string_lossy().as_ref())?;
        }
        atoms::r#do::file_write(
            authorization,
            invocation,
            &super::state_path(request.venv),
            format!("{hash}\n").as_bytes(),
            atoms::r#do::FileWriteOptions {
                write_bytes: true,
                mode: None,
                uid: None,
                gid: None,
                backup_to: None,
            },
        )?;
        movement = "refresh-dependencies";
        }
    }
    Ok(movement)
}
fn ensure_ok(result: &atoms::CommandObservation, program: &str) -> Result<(), String> {
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
