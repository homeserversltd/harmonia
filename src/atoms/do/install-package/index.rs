use crate::atoms::r#do::InvocationKey;
use crate::atoms::CommandObservation;
use crate::atoms::command;
use crate::CmdResult;

#[allow(clippy::too_many_arguments)]
pub(crate) fn pacman_mutate_packages_with_options(
    receipt_dir: &Path,
    sync: bool,
    packages: &[String],
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
    timeout_secs: u64,
) -> Result<CmdResult, String> {
    let program = crate::atoms::package::pacman_program();
    crate::atoms::package::reclaim_pacman_database_lock(receipt_dir, &program, true)?;
    let mut args = crate::atoms::package::pacman_base_args(sync);
    args.extend(packages.iter().map(String::as_str));
    crate::atoms::package::capture_overwrite_preimage(receipt_dir, conflict_paths)?;
    let result = command::capture_with_timeout(&program, &args, timeout_secs);
    if result.ok || !crate::atoms::package::pacman_needs_overwrite_retry(&result) {
        return Ok(result);
    }
    let Some(policy) = conflict_policy else {
        return Ok(result);
    };
    if policy != "overwrite-declared-paths" {
        return Ok(CmdResult {
            ok: false,
            code: result.code,
            stdout: result.stdout,
            stderr: format!(
                "{}\npacman-package-file-conflict-policy-unsupported:{policy}",
                result.stderr
            )
            .trim()
            .to_string(),
        });
    }
    let Some(mut overwrite_args) = crate::atoms::package::overwrite_allowed_args(
        &crate::atoms::package::pacman_base_args(sync),
        conflict_paths,
    ) else {
        return Ok(CmdResult {
            ok: false,
            code: result.code,
            stdout: result.stdout,
            stderr: format!(
                "{}\npacman-package-file-conflict-overwrite-paths-missing-or-wildcard",
                result.stderr
            )
            .trim()
            .to_string(),
        });
    };
    overwrite_args.extend(packages.iter().map(String::as_str));
    let second = command::capture_with_timeout(&program, &overwrite_args, timeout_secs);
    crate::write_json(&receipt_dir.join("pacman-package-transaction.json"), &serde_json::json!({"schema":"harmonia.pacman_package_transaction.v1", "first_ok": result.ok, "second_ok": second.ok, "overwrite_paths": conflict_paths}))?;
    Ok(CmdResult {
        ok: second.ok,
        code: second.code,
        stdout: format!(
            "first_command={} {}\nfirst_ok={}\nsecond_command={} {}\n{}",
            program,
            args.join(" "),
            result.ok,
            program,
            overwrite_args.join(" "),
            second.stdout
        )
        .trim()
        .to_string(),
        stderr: format!(
            "first_stderr={}\nsecond_stderr={}",
            result.stderr, second.stderr
        )
        .trim()
        .to_string(),
    })
}
use crate::atoms::comparison::ActionAuthorization;
use std::path::Path;

pub(crate) fn package_install(
    _authorization: ActionAuthorization,
    _invocation: InvocationKey,
    receipt_dir: &Path,
    packages: &[String],
    conflict_policy: Option<&str>,
    conflict_paths: &[String],
    timeout_secs: u64,
) -> Result<CommandObservation, String> {
    let result = pacman_mutate_packages_with_options(
        receipt_dir,
        false,
        packages,
        conflict_policy,
        conflict_paths,
        timeout_secs,
    )?;
    Ok(CommandObservation {
        program: crate::atoms::package::pacman_program(),
        args: vec!["-S".into(), "--noconfirm".into(), "--needed".into()],
        ok: result.ok,
        code: Some(result.code),
        stdout: result.stdout,
        stderr: result.stderr,
    })
}
