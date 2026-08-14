use crate::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[cfg(test)]
pub(crate) use crate::tools::package::set_test_pacman_path;

pub(crate) fn package_tool(
    receipt_dir: &Path,
    name: &str,
    action: &str,
    packages: &[String],
    apply: bool,
) -> Result<OperationOutcome, String> {
    crate::tools::package::package_tool(receipt_dir, name, action, packages, apply)
}

pub(crate) fn command_tool(
    receipt_dir: &Path,
    name: &str,
    program: &str,
    args: &[String],
    cwd: Option<&str>,
) -> Result<OperationOutcome, String> {
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = command_capture_with_cwd(program, &arg_refs, cwd);
    write_command_receipt_with_change_observed(receipt_dir, name, &result, "unknown")?;
    Ok(OperationOutcome {
        ok: result.ok,
        changed: false,
        skipped: false,
        message: format!("command {program}; change_observed=unknown"),
        command: Some(result),
    })
}

#[allow(dead_code)]
pub(crate) fn artifact_promote_tool(
    receipt_dir: &Path,
    name: &str,
    artifact: &Path,
    install_bin: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let metadata = fs::metadata(artifact)
        .map_err(|e| format!("artifact-missing {}: {e}", artifact.display()))?;
    if !apply {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: format!("artifact planned bytes={}", metadata.len()),
            command: None,
        };
        write_tool_receipt(receipt_dir, name, "artifact", "promote", &outcome)?;
        return Ok(outcome);
    }
    if let Some(parent) = install_bin.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let before_sha = sha256_file(install_bin).ok();
    let artifact_sha = sha256_file(artifact)?;
    let tmp_install = install_bin.with_extension("harmonia-new");
    fs::copy(artifact, &tmp_install).map_err(|e| format!("artifact-copy-failed: {e}"))?;
    let mut perms = fs::metadata(&tmp_install)
        .map_err(|e| e.to_string())?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&tmp_install, perms).map_err(|e| e.to_string())?;
    fs::rename(&tmp_install, install_bin).map_err(|e| format!("artifact-promote-failed: {e}"))?;
    let outcome = OperationOutcome {
        ok: true,
        changed: before_sha.as_deref() != Some(artifact_sha.as_str()),
        skipped: false,
        message: format!("artifact promoted to {}", install_bin.display()),
        command: None,
    };
    write_tool_receipt(receipt_dir, name, "artifact", "promote", &outcome)?;
    Ok(outcome)
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|e| format!("sha256-read-failed {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

fn write_command_receipt_with_change_observed(
    receipt_dir: &Path,
    name: &str,
    result: &CmdResult,
    change_observed: &str,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{}.json", name)),
        &serde_json::json!({
            "schema": "harmonia.command_receipt.v1",
            "name": name,
            "ok": result.ok,
            "exit_code": result.code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "change_observed": change_observed,
        }),
    )
}

#[allow(dead_code)]
pub(crate) fn health_tool(
    receipt_dir: &Path,
    name: &str,
    url: Option<&str>,
    expected_contains: Option<&str>,
    command: Option<&str>,
    args: &[String],
    cwd: Option<&str>,
) -> Result<OperationOutcome, String> {
    if let Some(url) = url {
        let result = crate::tools::health::curl_probe(&crate::tools::health::ProbeRequest {
            url,
            retries: 0,
            timeout_secs: 3,
            expected_contains,
        });
        write_command_receipt(receipt_dir, name, &result)?;
        return Ok(OperationOutcome {
            ok: result.ok,
            changed: false,
            skipped: false,
            message: format!("health {url}"),
            command: Some(result),
        });
    }
    let program = command.ok_or_else(|| format!("health {name} missing command or url"))?;
    command_tool(receipt_dir, name, program, args, cwd)
}

#[allow(dead_code)]
pub(crate) fn cargo_tool(
    receipt_dir: &Path,
    name: &str,
    args: &[String],
    cwd: Option<&str>,
) -> Result<OperationOutcome, String> {
    let args = if args.is_empty() {
        vec!["build".to_string(), "--release".to_string()]
    } else {
        args.to_vec()
    };
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = command_capture_with_cwd("/usr/bin/cargo", &arg_refs, cwd);
    write_command_receipt(receipt_dir, name, &result)?;
    Ok(OperationOutcome {
        ok: result.ok,
        changed: false,
        skipped: false,
        message: "cargo".into(),
        command: Some(result),
    })
}

#[cfg(test)]
mod pacman_safety_tests {
    use super::*;

    #[test]
    fn sync_package_mutation_uses_full_upgrade_semantics() {
        let args = crate::tools::package::pacman_base_args(true);
        assert_eq!(args, vec!["-Syu", "--noconfirm"]);
    }

    #[test]
    fn overwrite_without_sidecar_allowance_remains_conflict_failure() {
        let result = CmdResult {
            ok: false,
            code: 1,
            stdout: String::new(),
            stderr: "error: failed to commit transaction (conflicting files)\nfoo: /usr/bin/foo exists in filesystem".to_string(),
        };
        assert!(!result.ok);
        assert_eq!(
            crate::tools::package::pacman_conflict_signal(&result).as_deref(),
            Some("pacman-package-file-conflict")
        );
        assert!(result.stderr.contains("exists in filesystem"));
    }

    #[test]
    fn overwrite_policy_rejects_wildcard_paths() {
        assert!(crate::tools::package::overwrite_allowed_args(
            &crate::tools::package::pacman_base_args(false),
            &["*".to_string()]
        )
        .is_none());
    }
}

pub(crate) fn execute_routine_tool(
    tool: &str,
    requested_permutation: Option<&str>,
    args: &std::collections::BTreeMap<String, serde_json::Value>,
    manifest: &crate::ladder::LadderManifest,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
    service_runtime: &mut Option<crate::tools::service_runtime::ServiceRuntimeState>,
) -> Result<
    (
        OperationOutcome,
        std::collections::BTreeMap<String, serde_json::Value>,
    ),
    String,
> {
    if !crate::tools::routine_summonable(tool) {
        return Err(format!("routine-tool-not-summonable-{tool}"));
    }
    let contract =
        crate::tools::get(tool).ok_or_else(|| format!("routine-tool-not-found-{tool}"))?;
    let permutation = requested_permutation
        .and_then(|name| contract.permutation(name))
        .or_else(|| contract.permutations.first())
        .ok_or_else(|| format!("routine-tool-no-permutation-{tool}"))?;
    for arg in permutation.args {
        if arg.required && !args.contains_key(arg.name) {
            return Err(format!("routine-arg-missing-{tool}-{}", arg.name));
        }
        if let Some(value) = args.get(arg.name) {
            if !arg.kind.matches(value) {
                return Err(format!("routine-arg-type-{tool}-{}", arg.name));
            }
        }
    }
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let name = tool.to_string();
    match tool {
        "service-runtime" => crate::tools::service_runtime::execute_routine_stage(
            permutation.name,
            args,
            manifest,
            receipt_dir,
            apply,
            invocation,
            service_runtime,
        ),
        "pull-repo" => {
            let step = crate::ladder::ValidatedStep {
                step_id: name.clone(),
                tool: tool.into(),
                permutation: permutation.name.into(),
                args: args.clone(),
                on_failure: crate::ladder::OnFailure::Stop,
            };
            let plan = crate::ladder::routine_source_plan(&step, manifest)?;
            let o = crate::bands::pull_source::execute_source(&plan, apply, invocation);
            let mut out: std::collections::BTreeMap<String, serde_json::Value> = [
                ("path".into(), serde_json::json!(plan.destination)),
                ("changed".into(), serde_json::json!(o.changed)),
                ("source_reference".into(), serde_json::json!(plan.reference)),
                ("source_remote".into(), serde_json::json!(plan.reference)),
            ]
            .into_iter()
            .collect();
            if let Some(commit) = o.receipt.resolved_commit.clone() {
                out.insert("resolved_commit".into(), serde_json::json!(commit));
            }
            let result = OperationOutcome {
                ok: o.ok,
                changed: o.changed,
                skipped: !apply,
                message: o.receipt.promotion.clone(),
                command: None,
            };
            write_json(
                &receipt_dir.join(format!("{name}.json")),
                &serde_json::json!({"schema":"harmonia.routine_tool.receipt.v1","ok":o.ok,"changed":o.changed,"skipped":!apply,"promotion":o.receipt.promotion}),
            )?;
            crate::pull_repo::attest_source(&receipt_dir.join("pull-repo.attest.jsonl"), &o)?;
            Ok((result, out))
        }
        "build-crate" => {
            let cwd = Path::new(
                args.get("cwd")
                    .and_then(|v| v.as_str())
                    .ok_or("build-crate-cwd-missing")?,
            );
            let source_sha = args
                .get("source_build_sha")
                .and_then(|v| v.as_str())
                .ok_or("build-crate-source-build-sha-missing")?;
            let installed_sha = args.get("installed_build_sha").and_then(|v| v.as_str());
            let binary_path = args
                .get("installed_binary")
                .and_then(|v| v.as_str())
                .ok_or("build-crate-installed-binary-missing")?;
            let binary = Path::new(binary_path);
            let artifact_path = args
                .get("artifact")
                .and_then(Value::as_str)
                .map(PathBuf::from)
                .or_else(|| {
                    args.get("artifact_name")
                        .and_then(Value::as_str)
                        .map(|name| cwd.join("target/release").join(name))
                })
                .unwrap_or_else(|| binary.to_path_buf());
            let env_value = args.get("environment");
            let env: Vec<(String, String)> = match env_value {
                None => Vec::new(),
                Some(Value::Object(m)) => m
                    .iter()
                    .map(|(k, v)| {
                        v.as_str()
                            .map(|x| (k.clone(), x.to_string()))
                            .ok_or_else(|| format!("build-crate-environment-nonstring-{k}"))
                            .map_err(|e| e)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                Some(_) => return Err("build-crate-environment-not-object".into()),
            };
            let timeout = args
                .get("timeout_secs")
                .and_then(Value::as_u64)
                .unwrap_or(crate::tools::command::DEFAULT_TIMEOUT_SECS);
            let bearer = args
                .get("bearer")
                .and_then(Value::as_str)
                .unwrap_or("owner");
            let moved = crate::build_crate::run_build(
                cwd,
                source_sha,
                installed_sha,
                binary,
                &artifact_path,
                apply,
                &env,
                timeout,
                &receipt_dir.join("harmonia-atoms.log"),
                bearer,
                invocation,
            )?;
            if let Some(legacy_name) = args.get("legacy_build_receipt").and_then(Value::as_str) {
                if let Some(observation) = &moved {
                    let command = CmdResult {
                        ok: observation.ok,
                        code: observation.code.unwrap_or(-1),
                        stdout: observation.stdout.clone(),
                        stderr: observation.stderr.clone(),
                    };
                    crate::write_command_receipt(receipt_dir, legacy_name, &command)?;
                } else {
                    crate::write_json(
                        &receipt_dir.join(format!("{legacy_name}.json")),
                        &serde_json::json!({"schema":"harmonia.service-runtime.cargo-build.v1","state":"converged-quiet","ok":true,"changed":false,"invoked":false,"reason":"source-sha-matches-promoted-source-and-installed-binary","remote_sha":"","promoted_source_sha":source_sha}),
                    )?;
                }
            }
            let result = OperationOutcome {
                ok: moved.as_ref().map_or(true, |x| x.ok),
                changed: apply && moved.is_some(),
                skipped: !apply,
                message: "build-crate".into(),
                command: None,
            };
            let result_changed = result.changed;
            // Legacy cargo-build receipt is authoritative; avoid a duplicate routine-tool writer.
            Ok((
                result,
                [
                    ("artifact".into(), serde_json::json!(artifact_path)),
                    ("source_build_sha".into(), serde_json::json!(source_sha)),
                    ("changed".into(), serde_json::json!(result_changed)),
                ]
                .into_iter()
                .collect(),
            ))
        }
        "place-file" => {
            let path = Path::new(
                args.get("path")
                    .and_then(Value::as_str)
                    .ok_or("place-file-path-missing")?,
            );
            let source = args.get("source_path").and_then(Value::as_str);
            let declared = args.get("declared_bytes").and_then(Value::as_str);
            if source.is_some() == declared.is_some() {
                return Err("place-file-requires-exactly-one-source".into());
            }
            let bytes = if let Some(source) = source {
                fs::read(source).map_err(|e| format!("place-file-source-read:{e}"))?
            } else {
                declared.unwrap().as_bytes().to_vec()
            };
            let default_backup = receipt_dir.join("backups/prior-binary");
            let request = crate::place_file::PlaceFileRequest {
                path,
                declared_bytes: &bytes,
                mode: args.get("mode").and_then(Value::as_u64).map(|x| x as u32),
                ownership: crate::place_file::DeclaredOwnership {
                    uid: args.get("uid").and_then(Value::as_u64).map(|x| x as u32),
                    gid: args.get("gid").and_then(Value::as_u64).map(|x| x as u32),
                },
                backup: args
                    .get("backup_path")
                    .and_then(Value::as_str)
                    .map(Path::new)
                    .map(crate::place_file::BackupPolicy::To)
                    .unwrap_or(crate::place_file::BackupPolicy::To(&default_backup)),
                invocation: invocation,
            };
            let placed = crate::place_file::execute(request)?;
            let changed = apply && placed.movement.changed();
            if permutation.name == "binary-promotion" {
                if let Some(legacy_name) = args
                    .get("legacy_binary_install_receipt")
                    .and_then(Value::as_str)
                {
                    let mut legacy = serde_json::json!({"schema":"harmonia.service-runtime.binary-install.v1","artifact":source.unwrap_or(""),"install_bin":path,"apply":apply,"ok":placed.receipt.ok,"changed":changed,"state":if changed { "binary-swapped" } else { "converged-quiet" }});
                    if !changed {
                        if let Some(object) = legacy.as_object_mut() {
                            object.remove("artifact");
                            object.insert(
                                "reason".into(),
                                serde_json::json!("source-sha-gate-preserved-installed-binary"),
                            );
                        }
                    }
                    crate::write_json(&receipt_dir.join(format!("{legacy_name}.json")), &legacy)?;
                }
            }
            write_json(
                &receipt_dir.join(format!("{name}.json")),
                &serde_json::json!({"schema":"harmonia.routine_tool.receipt.v1","ok":placed.receipt.ok,"changed":changed,"skipped":!apply,"effect":placed.receipt,"movement":{"bytes":placed.movement.bytes,"mode":placed.movement.mode,"owner":placed.movement.owner,"created":placed.movement.created,"backed_up":placed.movement.backed_up}}),
            )?;
            Ok((
                OperationOutcome {
                    ok: true,
                    changed,
                    skipped: !apply,
                    message: "place-file".into(),
                    command: None,
                },
                [
                    ("path".into(), serde_json::json!(path)),
                    ("changed".into(), serde_json::json!(changed)),
                    (
                        "sha256".into(),
                        serde_json::json!(crate::atoms::file_sha256(&bytes)),
                    ),
                ]
                .into_iter()
                .collect(),
            ))
        }
        "backfill-file" => {
            let path = Path::new(
                args.get("path")
                    .and_then(Value::as_str)
                    .ok_or("backfill-file-path-missing")?,
            );
            let bytes = args
                .get("declared_bytes")
                .and_then(Value::as_str)
                .ok_or("backfill-file-bytes-missing")?
                .as_bytes();
            let request = crate::backfill_file::BackfillFileRequest {
                path,
                declared_bytes: bytes,
                mode: args.get("mode").and_then(Value::as_u64).map(|v| v as u32),
                ownership: crate::backfill_file::DeclaredOwnership {
                    uid: args.get("uid").and_then(Value::as_u64).map(|v| v as u32),
                    gid: args.get("gid").and_then(Value::as_u64).map(|v| v as u32),
                },
                backup: crate::backfill_file::BackupPolicy::None,
                invocation,
            };
            let out = crate::backfill_file::execute(request)?;
            write_json(
                &receipt_dir.join(format!("{name}.json")),
                &serde_json::json!({"schema":"harmonia.routine_tool.receipt.v1","ok":out.receipt.ok,"changed":out.movement.changed(),"skipped":!apply}),
            )?;
            Ok((
                OperationOutcome {
                    ok: out.receipt.ok,
                    changed: apply && out.movement.changed(),
                    skipped: !apply,
                    message: "backfill-file".into(),
                    command: None,
                },
                [
                    ("path".into(), serde_json::json!(path)),
                    (
                        "sha256".into(),
                        serde_json::json!(crate::atoms::file_sha256(bytes)),
                    ),
                ]
                .into_iter()
                .collect(),
            ))
        }
        "check-health" => {
            let url = args
                .get("url")
                .and_then(Value::as_str)
                .ok_or("check-health-url-missing")?;
            let request = crate::tools::health::ProbeRequest {
                url,
                retries: args.get("retries").and_then(Value::as_u64).unwrap_or(0) as usize,
                timeout_secs: args
                    .get("timeout_secs")
                    .and_then(Value::as_u64)
                    .unwrap_or(3),
                expected_contains: args.get("expected_contains").and_then(Value::as_str),
            };
            let result = crate::check_health::probe(&request);
            if let Some(legacy) = args.get("legacy_receipt").and_then(Value::as_str) {
                crate::write_command_receipt(receipt_dir, legacy, &result)?;
            }
            write_json(
                &receipt_dir.join(format!("{name}.json")),
                &serde_json::json!({"schema":"harmonia.routine_tool.receipt.v1","ok":result.ok,"changed":false,"skipped":!apply,"stdout":result.stdout,"stderr":result.stderr}),
            )?;
            Ok((
                OperationOutcome {
                    ok: result.ok,
                    changed: false,
                    skipped: !apply,
                    message: "check-health".into(),
                    command: Some(result),
                },
                [("url".into(), serde_json::json!(url))]
                    .into_iter()
                    .collect(),
            ))
        }
        "systemd" => {
            let service = args.get("service").and_then(Value::as_str);
            let user = args.get("user").and_then(Value::as_bool).unwrap_or(false);
            let target = args.get("target_user").and_then(Value::as_str);
            let timeout = args
                .get("timeout_secs")
                .and_then(Value::as_u64)
                .unwrap_or(30);
            let binary_changed = args
                .get("binary_changed")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let managed_files_changed = args
                .get("managed_files_changed")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let material_changed = match permutation.name {
                "daemon-reload" => managed_files_changed,
                "restart" => binary_changed || managed_files_changed,
                _ => false,
            };
            let restart_policy = args.get("restart_policy").and_then(Value::as_str);
            let effective = if user {
                format!("user-{}", permutation.name)
            } else {
                permutation.name.to_string()
            };
            let observation_only = matches!(permutation.name, "is-active-probe");
            let o = crate::tools::systemd::run_permutation_with_policy(
                receipt_dir,
                &name,
                &effective,
                service,
                &[],
                target,
                timeout,
                if observation_only { false } else { apply },
                material_changed,
                restart_policy,
                invocation,
            )?;
            if let Some(legacy) = args.get("legacy_receipt").and_then(Value::as_str) {
                fs::copy(
                    receipt_dir.join(format!("{name}.json")),
                    receipt_dir.join(format!("{legacy}.json")),
                )
                .map_err(|e| e.to_string())?;
            }
            Ok((
                o,
                [("service".into(), serde_json::json!(service.unwrap_or("")))]
                    .into_iter()
                    .collect(),
            ))
        }
        "enable-unit" => {
            let service = args
                .get("service")
                .and_then(Value::as_str)
                .ok_or("enable-unit-service-missing")?;
            let user = args.get("user").and_then(Value::as_bool).unwrap_or(false);
            let target = args.get("target_user").and_then(Value::as_str);
            let timeout = args
                .get("timeout_secs")
                .and_then(Value::as_u64)
                .unwrap_or(30);
            let o = crate::tools::systemd::run_action(
                receipt_dir,
                &name,
                "enable",
                Some(service),
                user,
                target,
                timeout,
                apply,
                false,
                invocation,
            )?;
            if let Some(legacy) = args.get("legacy_receipt").and_then(Value::as_str) {
                fs::copy(
                    receipt_dir.join(format!("{name}.json")),
                    receipt_dir.join(format!("{legacy}.json")),
                )
                .map_err(|e| e.to_string())?;
            }
            Ok((
                o,
                [
                    ("service".into(), serde_json::json!(service)),
                    ("enabled".into(), serde_json::json!(true)),
                ]
                .into_iter()
                .collect(),
            ))
        }
        _ => Err(format!("routine-tool-not-summonable-{tool}")),
    }
}
