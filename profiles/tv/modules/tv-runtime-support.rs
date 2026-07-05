use crate::*;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::symlink;

#[derive(Clone, Copy)]
pub(crate) struct TvModuleSpec {
    pub(crate) phase: u8,
    pub(crate) schema: &'static str,
    pub(crate) meaning: &'static str,
}

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    if module.command.is_some() || !module.args.is_empty() || module.cwd.is_some() {
        return Err(format!("module-executable-sidecar-rejected-{}", module.id));
    }
    if module.packages.is_empty()
        && module.expected_files.is_empty()
        && module.binaries.is_empty()
        && module.services.is_empty()
        && module.user_services.is_empty()
        && module.groups.is_empty()
        && module.managed_files.is_empty()
    {
        return Err(format!("tv-module-empty-proof-surface-{}", module.id));
    }
    validate_values("package", &module.packages, valid_package_name)?;
    validate_values("binary", &module.binaries, valid_binary_name)?;
    validate_values("service", &module.services, valid_systemd_unit_name)?;
    validate_values(
        "user-service",
        &module.user_services,
        valid_systemd_unit_name,
    )?;
    validate_values("group", &module.groups, valid_group_name)?;
    for path in &module.expected_files {
        validate_expected_path(path)?;
    }
    for file in &module.managed_files {
        validate_managed_file(file)?;
    }
    Ok(())
}

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
    spec: TvModuleSpec,
) -> Result<ModuleExecution, String> {
    validate(module)?;
    let mut operations: Vec<(&'static str, OperationOutcome)> = Vec::new();
    if !module.groups.is_empty() {
        operations.push(("owner-groups", owner_groups(module, receipt_dir, apply)?));
    }
    if !module.managed_files.is_empty() {
        operations.push(("managed-files", managed_files(module, receipt_dir, apply)?));
    }
    if !module.packages.is_empty() {
        operations.push((
            "packages",
            packages(module, receipt_dir, apply, module.optional)?,
        ));
    }
    if !module.binaries.is_empty() {
        operations.push((
            "binaries",
            binaries(module, receipt_dir, apply, module.optional)?,
        ));
    }
    if !module.services.is_empty() {
        operations.push((
            "services",
            services(module, receipt_dir, apply, module.optional)?,
        ));
    }
    if !module.user_services.is_empty() {
        operations.push((
            "user-services",
            user_services(module, receipt_dir, apply, module.optional)?,
        ));
    }
    if !module.expected_files.is_empty() {
        operations.push((
            "expected-files",
            expected_files(module, receipt_dir, apply, module.optional)?,
        ));
    }
    let outcomes: Vec<OperationOutcome> = operations
        .iter()
        .map(|(_, outcome)| outcome.clone())
        .collect();
    write_tv_receipt(module, receipt_dir, apply, spec, &outcomes)?;
    if module.optional {
        let changed = outcomes.iter().any(|outcome| outcome.changed);
        return Ok(ModuleExecution {
            ok: true,
            changed,
            operation_count: operations.len(),
            first_missing_signal: None,
        });
    }
    Ok(ModuleExecution::from_operations(operations, &module.id))
}

fn planned_outcome(message: impl Into<String>, ok: bool) -> OperationOutcome {
    OperationOutcome {
        ok,
        changed: false,
        skipped: true,
        message: message.into(),
        command: None,
    }
}

fn managed_files(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    tools::files::converge_managed_files(
        &tools::files::ManagedFilesRequest {
            module_id: &module.id,
            files: &module.managed_files,
            receipt_name: "tv-managed-files",
            schema: "harmonia.tv.managed_files.v1",
            first_missing_signal: "tv-managed-file-missing",
        },
        receipt_dir,
        apply,
    )
}

fn pacman_command_path() -> String {
    crate::tools::module_steps::pacman_program()
}

fn packages(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
    optional: bool,
) -> Result<OperationOutcome, String> {
    let pacman = pacman_command_path();
    if !Path::new(&pacman).exists() {
        let outcome = planned_outcome(
            if apply && !optional {
                "pacman missing for TV package mutation"
            } else if optional {
                "optional TV package set cannot be checked here; warning only"
            } else {
                "pacman absent on scout host; TV packages planned only"
            },
            !apply || optional,
        );
        write_tool_receipt(
            receipt_dir,
            "tv-packages",
            "package",
            "tv-package-set",
            &outcome,
        )?;
        return Ok(outcome);
    }
    let checking_only = !apply || optional;
    let mut args: Vec<String> = if checking_only {
        vec!["-Q".into()]
    } else {
        vec!["-S".into(), "--needed".into(), "--noconfirm".into()]
    };
    args.extend(module.packages.iter().cloned());
    let result = command_tool(receipt_dir, "tv-packages", &pacman, &args, None)?;
    if optional {
        write_json(
            &receipt_dir.join("tv-packages.json"),
            &json!({"schema":"harmonia.tv.packages.v1","ok":true,"module":module.id,"operation":"packages","tool":"package","action":"tv-package-set","apply":apply,"optional":true,"warning":"optional package set is customer-owned; Harmonia checked only and did not reinstall","packages":module.packages,"command":result.command,"first_missing_signal":"none"}),
        )?;
        write_json(
            &receipt_dir.join("tv-packages-warning.json"),
            &json!({"schema":"harmonia.tv.optional_warning.v1","ok":true,"module":module.id,"operation":"packages","warning":"optional package set is customer-owned; Harmonia checked only and did not reinstall","packages":module.packages,"apply":apply,"command_ok":result.ok,"first_missing_signal":"none"}),
        )?;
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: !result.ok,
            message: "optional TV package set checked; missing packages are warnings".to_string(),
            command: result.command,
        });
    }
    Ok(OperationOutcome {
        changed: apply
            && result.ok
            && pacman_stdout_indicates_change(
                result
                    .command
                    .as_ref()
                    .map(|c| c.stdout.as_str())
                    .unwrap_or(""),
            ),
        ..result
    })
}

fn binaries(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
    optional: bool,
) -> Result<OperationOutcome, String> {
    let missing: Vec<String> = module
        .binaries
        .iter()
        .filter(|binary| resolve_binary(binary).is_none())
        .cloned()
        .collect();
    let ok = missing.is_empty();
    let outcome_ok = ok || !apply || optional;
    let outcome = OperationOutcome {
        ok: outcome_ok,
        changed: false,
        skipped: !ok,
        message: format!("{} binaries checked", module.binaries.len()),
        command: None,
    };
    write_json(
        &receipt_dir.join("tv-binaries.json"),
        &json!({"schema":"harmonia.tv.binaries.v1","ok":outcome_ok,"module":module.id,"checked":module.binaries,"missing":missing,"apply":apply,"optional":optional,"warning": if optional && !missing.is_empty() { module.optional_warning.as_deref().unwrap_or("optional customer-owned binaries missing") } else { "" },"first_missing_signal": if outcome_ok {"none"} else {"tv-binary-missing"}}),
    )?;
    Ok(outcome)
}

fn services(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
    optional: bool,
) -> Result<OperationOutcome, String> {
    if !Path::new("/usr/bin/systemctl").exists() {
        let outcome = planned_outcome(
            "systemctl absent on scout host; TV services planned only",
            !apply,
        );
        write_tool_receipt(
            receipt_dir,
            "tv-services",
            "systemd",
            "tv-service-set",
            &outcome,
        )?;
        return Ok(outcome);
    }
    let mut ok = true;
    let mut changed = false;
    for service in &module.services {
        let before_enabled = if apply && !optional {
            Some(command_capture(
                "/usr/bin/systemctl",
                &["is-enabled", service],
            ))
        } else {
            None
        };
        let before_active = if apply && !optional {
            Some(command_capture(
                "/usr/bin/systemctl",
                &["is-active", service],
            ))
        } else {
            None
        };
        let args: Vec<String> = if apply && !optional {
            vec!["enable".into(), "--now".into(), service.clone()]
        } else {
            vec!["is-enabled".into(), service.clone()]
        };
        let outcome = command_tool(
            receipt_dir,
            &format!("service-{}", receipt_slug(service)?),
            "/usr/bin/systemctl",
            &args,
            None,
        )?;
        if apply && !optional && outcome.ok {
            let was_enabled = before_enabled.as_ref().map(|r| r.ok).unwrap_or(false);
            let was_active = before_active
                .as_ref()
                .map(|r| r.stdout.trim() == "active")
                .unwrap_or(false);
            changed |= !was_enabled || !was_active;
        }
        ok &= outcome.ok;
    }
    let outcome_ok = ok || !apply || optional;
    let outcome = OperationOutcome {
        ok: outcome_ok,
        changed,
        skipped: !apply && !ok,
        message: format!("{} services checked", module.services.len()),
        command: None,
    };
    write_json(
        &receipt_dir.join("tv-services.json"),
        &json!({"schema":"harmonia.tv.services.v1","ok":outcome_ok,"module":module.id,"services":module.services,"apply":apply,"optional":optional,"warning": if optional && !ok { module.optional_warning.as_deref().unwrap_or("optional customer-owned service missing") } else { "" },"first_missing_signal": if outcome_ok {"none"} else {"tv-service-proof-missing"}}),
    )?;
    Ok(outcome)
}

fn user_services(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
    optional: bool,
) -> Result<OperationOutcome, String> {
    let target_root = module.target_dir.as_deref().unwrap_or("/home/owner");
    let mut missing = Vec::new();
    let mut linked = Vec::new();
    for service in &module.user_services {
        let unit = Path::new(target_root)
            .join(".config/systemd/user")
            .join(service);
        let wants = Path::new(target_root)
            .join(".config/systemd/user/graphical-session.target.wants")
            .join(service);
        if !unit.exists() {
            missing.push(unit.display().to_string());
            continue;
        }
        if apply && !wants.exists() {
            if let Some(parent) = wants.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    format!(
                        "tv-user-service-wants-parent-failed {}: {e}",
                        parent.display()
                    )
                })?;
            }
            create_symlink(&unit, &wants)?;
            linked.push(wants.display().to_string());
        }
    }
    let ok = missing.is_empty() || !apply || optional;
    let outcome = OperationOutcome {
        ok,
        changed: !linked.is_empty(),
        skipped: !apply,
        message: format!("{} user services checked", module.user_services.len()),
        command: None,
    };
    write_json(
        &receipt_dir.join("tv-user-services.json"),
        &json!({"schema":"harmonia.tv.user_services.v1","ok":ok,"module":module.id,"user_services":module.user_services,"missing":missing,"linked":linked,"apply":apply,"optional":optional,"warning": if optional && !missing.is_empty() { module.optional_warning.as_deref().unwrap_or("optional customer-owned user service missing") } else { "" },"first_missing_signal": if ok {"none"} else {"tv-user-service-proof-missing"}}),
    )?;
    Ok(outcome)
}

fn owner_groups(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    if !Path::new("/usr/bin/id").exists() {
        let outcome = planned_outcome("id absent on scout host; owner groups planned only", !apply);
        write_tool_receipt(
            receipt_dir,
            "owner-groups",
            "command",
            "owner-groups",
            &outcome,
        )?;
        return Ok(outcome);
    }
    let result = command_capture("/usr/bin/id", &["-nG", "owner"]);
    if !result.ok && !apply {
        let outcome = planned_outcome(
            "owner user absent on scout host; owner profile planned only",
            true,
        );
        write_tool_receipt(
            receipt_dir,
            "owner-groups",
            "command",
            "owner-groups",
            &outcome,
        )?;
        return Ok(outcome);
    }
    let stdout = result.stdout.clone();
    let mut missing: Vec<String> = module
        .groups
        .iter()
        .filter(|g| !stdout.split_whitespace().any(|have| have == g.as_str()))
        .cloned()
        .collect();
    let mut changed = false;
    let mut command = Some(result);
    if apply && !missing.is_empty() {
        let groups = missing.join(",");
        let args = vec!["-aG".to_string(), groups, "owner".to_string()];
        let usermod = command_tool(
            receipt_dir,
            "owner-groups-apply",
            "/usr/bin/usermod",
            &args,
            None,
        )?;
        changed = usermod.ok;
        if usermod.ok {
            let refreshed = command_capture("/usr/bin/id", &["-nG", "owner"]);
            missing = module
                .groups
                .iter()
                .filter(|g| {
                    !refreshed
                        .stdout
                        .split_whitespace()
                        .any(|have| have == g.as_str())
                })
                .cloned()
                .collect();
            command = Some(refreshed);
        } else {
            command = usermod.command;
        }
    }
    let ok = missing.is_empty();
    let outcome = OperationOutcome {
        ok: ok || !apply,
        changed,
        skipped: !apply && !ok,
        message: format!("owner groups checked; missing={}", missing.len()),
        command,
    };
    write_json(
        &receipt_dir.join("owner-groups.json"),
        &json!({"schema":"harmonia.tv.owner_groups.v1","ok":outcome.ok,"module":module.id,"expected":module.groups,"missing":missing,"apply":apply,"changed":changed,"first_missing_signal": if outcome.ok {"none"} else {"owner-group-missing"}}),
    )?;
    Ok(outcome)
}

fn expected_files(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
    optional: bool,
) -> Result<OperationOutcome, String> {
    let target_root = module.target_dir.as_deref().unwrap_or("/");
    let root = PathBuf::from(target_root);
    let mut missing = Vec::new();
    for expected in &module.expected_files {
        let path = if Path::new(expected).is_absolute() {
            PathBuf::from(expected)
        } else {
            root.join(expected)
        };
        if !path.exists() {
            missing.push(path.display().to_string());
        }
    }
    let ok = missing.is_empty() || !apply || optional;
    let outcome = OperationOutcome {
        ok,
        changed: false,
        skipped: (!apply || optional) && !missing.is_empty(),
        message: format!("{} expected files checked", module.expected_files.len()),
        command: None,
    };
    write_json(
        &receipt_dir.join("tv-expected-files.json"),
        &json!({"schema":"harmonia.tv.expected_files.v1","ok":ok,"module":module.id,"target_root":target_root,"checked":module.expected_files.len(),"missing":missing,"apply":apply,"optional":optional,"warning": if optional && !missing.is_empty() { module.optional_warning.as_deref().unwrap_or("optional customer-owned files missing") } else { "" },"first_missing_signal": if ok {"none"} else {"tv-expected-file-missing"}}),
    )?;
    Ok(outcome)
}

fn write_tv_receipt(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
    spec: TvModuleSpec,
    outcomes: &[OperationOutcome],
) -> Result<(), String> {
    let raw_ok = outcomes.iter().all(|outcome| outcome.ok);
    let ok = raw_ok || module.optional;
    let changed = outcomes.iter().any(|outcome| outcome.changed);
    let warning_signals: Vec<String> = outcomes
        .iter()
        .enumerate()
        .filter(|(_, outcome)| !outcome.ok || outcome.skipped)
        .map(|(index, outcome)| format!("optional-warning-{}-{}", index + 1, outcome.message))
        .collect();
    let first_missing_signal = if ok {
        "none".to_string()
    } else {
        format!("{}-proof-missing", module.id)
    };
    write_json(
        &receipt_dir.join(format!("{}.json", module.id)),
        &json!({
            "schema": spec.schema,
            "ok": ok,
            "raw_ok": raw_ok,
            "optional": module.optional,
            "module": module.id,
            "phase": spec.phase,
            "apply": apply,
            "changed": changed,
            "operation_count": outcomes.len(),
            "package_count": module.packages.len(),
            "binary_count": module.binaries.len(),
            "service_count": module.services.len(),
            "user_service_count": module.user_services.len(),
            "expected_file_count": module.expected_files.len(),
            "managed_file_count": module.managed_files.len(),
            "warning_count": if module.optional { warning_signals.len() } else { 0 },
            "warning_signals": if module.optional { warning_signals } else { Vec::<String>::new() },
            "optional_missing_warning": if module.optional { module.optional_warning.as_deref().unwrap_or("optional customer-owned surface missing") } else { "" },
            "first_missing_signal": first_missing_signal,
            "meaning": spec.meaning,
        }),
    )
}

fn validate_values(kind: &str, values: &[String], valid: fn(&str) -> bool) -> Result<(), String> {
    for value in values {
        if !valid(value) {
            return Err(format!("tv-module-{kind}-value-rejected {value}"));
        }
    }
    Ok(())
}

fn valid_package_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '+' | '-'))
}

fn valid_binary_name(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('/')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

fn valid_systemd_unit_name(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('/')
        && !value.contains("..")
        && (value.ends_with(".service") || value.ends_with(".timer"))
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '-'))
}

fn valid_group_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

fn validate_expected_path(value: &str) -> Result<(), String> {
    if value.is_empty() || value.contains('\0') || value.contains("..") {
        return Err(format!("tv-module-expected-path-rejected {value}"));
    }
    Ok(())
}

fn validate_managed_file(file: &ManagedFileManifest) -> Result<(), String> {
    let path = Path::new(&file.path);
    if !path.is_absolute() || file.path.contains('\0') || file.path.contains("..") {
        return Err(format!(
            "tv-module-managed-file-path-rejected {}",
            file.path
        ));
    }
    if let Some(mode) = file.mode {
        if !(0o400..=0o777).contains(&mode) {
            return Err(format!(
                "tv-module-managed-file-mode-rejected {}",
                file.path
            ));
        }
    }
    Ok(())
}

fn receipt_slug(value: &str) -> Result<String, String> {
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '-'))
    {
        return Err(format!("tv-module-receipt-name-rejected {value}"));
    }
    Ok(value.replace('.', "-"))
}

fn resolve_binary(binary: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn create_symlink(source: &Path, target: &Path) -> Result<(), String> {
    if target.exists() {
        return Ok(());
    }
    symlink(source, target).map_err(|e| {
        format!(
            "tv-user-service-symlink-failed {} -> {}: {e}",
            target.display(),
            source.display()
        )
    })
}

#[cfg(not(unix))]
fn create_symlink(_source: &Path, _target: &Path) -> Result<(), String> {
    Ok(())
}
