use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) struct FetchArtifactExecution {
    pub outcome: crate::OperationOutcome,
    pub source_sha: String,
    pub artifact_path: std::path::PathBuf,
}

#[derive(serde::Deserialize)]
struct FetchArtifactApplianceConfig {
    #[serde(default)]
    sources: BTreeMap<String, Value>,
}

fn appliance_source_declared(config_path: &Path, component: &str) -> Result<bool, String> {
    let text = std::fs::read_to_string(config_path).map_err(|error| {
        format!(
            "appliance-config-read-failed {}: {error}",
            config_path.display()
        )
    })?;
    let config: FetchArtifactApplianceConfig = serde_json::from_str(&text).map_err(|error| {
        format!(
            "appliance-config-parse-failed {}: {error}",
            config_path.display()
        )
    })?;
    Ok(config.sources.contains_key(component))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn same_source_sha(left: &str, right: &str) -> bool {
    left.strip_prefix("sha-")
        .unwrap_or(left)
        .eq_ignore_ascii_case(right.strip_prefix("sha-").unwrap_or(right))
}

pub(crate) fn execute(
    args: &BTreeMap<String, Value>,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<crate::OperationOutcome, String> {
    execute_with_provenance(args, receipt_dir, apply, invocation).map(|result| result.outcome)
}

pub(crate) fn execute_with_provenance(
    args: &BTreeMap<String, Value>,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<FetchArtifactExecution, String> {
    execute_with_module_provenance(args, receipt_dir, apply, invocation, None)
}

pub(crate) fn execute_with_provenance_for_module(
    args: &BTreeMap<String, Value>,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
    module_id: &str,
) -> Result<FetchArtifactExecution, String> {
    execute_with_module_provenance(args, receipt_dir, apply, invocation, Some(module_id))
}

fn execute_with_module_provenance(
    args: &BTreeMap<String, Value>,
    receipt_dir: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
    module_id: Option<&str>,
) -> Result<FetchArtifactExecution, String> {
    let required = |name: &str| {
        args.get(name)
            .and_then(Value::as_str)
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| format!("fetch-artifact-missing-{name}"))
    };
    let component = required("component")?;
    let registry_base = args
        .get("registry_base")
        .and_then(Value::as_str)
        .unwrap_or("");
    let release_repo = args
        .get("release_repo")
        .and_then(Value::as_str)
        .unwrap_or("");
    let identity = args
        .get("identity")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            if release_repo.trim().is_empty() {
                "liveness-marker"
            } else {
                "embedded-sha"
            }
        });
    let source_policy = args
        .get("source_policy")
        .and_then(Value::as_str)
        .unwrap_or("artifact");
    if !matches!(source_policy, "artifact" | "developer" | "source") {
        return Err(format!("fetch-artifact-source-policy-invalid policy={source_policy}"));
    }
    let source_sha = args
        .get("source_build_sha")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("");
    if source_policy != "artifact" && source_sha.is_empty() {
        return Err("fetch-artifact-missing-source_build_sha".into());
    }
    let beam_refetch = args
        .get("beam_refetch")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let artifact_name = args
        .get("artifact_name")
        .and_then(Value::as_str)
        .unwrap_or(component);
    let destination = Path::new(required("destination")?);
    let installed_binary = Path::new(required("installed_binary")?);
    if source_policy != "artifact" && !crate::atoms::ask::fetch_artifact::validate_source_sha(source_sha) {
        return Err("fetch-artifact-source-sha-invalid".into());
    }
    let stamped_release_sha = if source_policy == "artifact" {
        crate::atoms::ask::collective_stamp::target_sha(component)
    } else {
        None
    };
    let explicit_pinned_release_sha = if source_policy == "artifact"
        && stamped_release_sha.is_none()
    {
        match args.get("pinned_release_sha") {
            None | Some(Value::Null) => None,
            Some(Value::String(value))
                if crate::atoms::ask::fetch_artifact::validate_source_sha(value) =>
            {
                Some(value.to_ascii_lowercase())
            }
            Some(_) => return Err("fetch-artifact-pinned-release-sha-invalid".into()),
        }
    } else {
        None
    };
    let pinned_release_sha = stamped_release_sha
        .as_deref()
        .or(explicit_pinned_release_sha.as_deref())
        .map(str::to_owned);

    let profile_axis = crate::atoms::ask::fetch_artifact::profile_axis_declared(args)?;
    let profile = if profile_axis {
        let profile_source = args
            .get("profile_source")
            .and_then(Value::as_str)
            .unwrap_or(crate::atoms::ask::fetch_artifact::DEFAULT_PROFILE_SOURCE);
        Some(crate::atoms::ask::fetch_artifact::read_profile_source(
            Path::new(profile_source),
        )?)
    } else {
        None
    };
    let (release_asset_name, release_sidecar_name, resolved_profile_segment) =
        match profile.as_deref() {
            Some(profile) => {
                let resolved_segment =
                    crate::atoms::ask::fetch_artifact::resolved_profile_segment(profile)?;
                let (asset, sidecar) =
                    crate::atoms::ask::fetch_artifact::profile_release_names_for_segment(
                        artifact_name,
                        &resolved_segment,
                        args.get("asset_name").and_then(Value::as_str),
                        args.get("sidecar_name").and_then(Value::as_str),
                    )?;
                (Some(asset), Some(sidecar), Some(resolved_segment))
            }
            None => (
                args.get("asset_name")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                args.get("sidecar_name")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                None,
            ),
        };
    let profile_receipt_fields = profile
        .as_deref()
        .zip(resolved_profile_segment.as_deref())
        .map(|(declared, resolved)| {
            format!("; declared_profile={declared}; resolved_profile_segment={resolved}")
        })
        .unwrap_or_default();

    let source_dir = args
        .get("source_dir")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(Path::new);
    let native_release = !release_repo.trim().is_empty();
    let xenia_artifact = source_policy == "artifact" && module_id == Some("xenia");
    let xenia_source_undeclared = if xenia_artifact {
        let config_path = crate::bands::pull_source::appliance_config_path();
        !appliance_source_declared(&config_path, component)?
    } else {
        false
    };
    let xenia_expected_digest = if xenia_artifact {
        match args.get("expected_digest") {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) if valid_sha256(value) => Some(value.as_str()),
            Some(_) => return Err("fetch-artifact-expected-digest-invalid".into()),
        }
    } else {
        None
    };
    let pull_repo_source_sha = ["source_build_sha", "resolved_revision", "resolved_commit"]
        .iter()
        .find_map(|name| {
            args.get(*name)
                .and_then(Value::as_str)
                .filter(|value| crate::atoms::ask::fetch_artifact::validate_source_sha(value))
        })
        .map(str::to_owned);
    if xenia_source_undeclared
        && native_release
        && !beam_refetch
        && xenia_expected_digest.is_some()
        && pull_repo_source_sha.as_deref().is_some_and(|source_identity| {
            pinned_release_sha
                .as_deref()
                .is_none_or(|pin| same_source_sha(source_identity, pin))
        })
        && crate::known_good_ledger::sha256_file(installed_binary)
            .is_ok_and(|installed_digest| Some(installed_digest.as_str()) == xenia_expected_digest)
    {
        let source_identity = pull_repo_source_sha.unwrap();
        let installed_digest = xenia_expected_digest.unwrap();
        crate::atoms::attest::fetch_artifact::attest(
            &receipt_dir.join("harmonia-atoms.log"),
            true,
            false,
            &format!(
                "state=Current; care=pull-repo digest and source identity match installed bytes; after=Current; road=artifact; digest_supplier=pull-repo; observed={installed_digest}; desired={installed_digest}; source_sha={source_identity}; diff=empty; movement=none{profile_receipt_fields}"
            ),
        )?;
        return Ok(FetchArtifactExecution {
            outcome: crate::OperationOutcome {
                ok: true,
                changed: false,
                skipped: true,
                message: "fetch-artifact-current".into(),
                command: None,
            },
            source_sha: source_identity,
            artifact_path: installed_binary.to_path_buf(),
        });
    }
    if source_policy == "developer" {
        let source_reference = args
            .get("source_reference")
            .and_then(Value::as_str)
            .ok_or("fetch-artifact-developer-source-reference-missing")?;
        if !matches!(source_reference, "main" | "refs/heads/main") {
            return Err("fetch-artifact-developer-source-not-main".into());
        }
    }
    let mut release_fallback: Option<(String, String)> = (source_policy == "developer")
        .then(|| ("developer-main".into(), "source://main".into()));
    let mut credential_state = "absent";
    let mut release_digest = None;
    let mut native_download = None;
    let mut effective_source_sha = source_sha.to_owned();
    let mut stamped_source_plan: Option<crate::tools::git_artifact::SourcePlan> = None;
    let mut module_release_candidates: Option<Vec<Value>> = None;
    if source_policy == "artifact" && xenia_source_undeclared {
        if !native_release {
            return Err("fetch-artifact-xenia-release-repo-missing".into());
        }
        let selected_source_sha = pinned_release_sha
            .as_deref()
            .or(pull_repo_source_sha.as_deref())
            .ok_or("fetch-artifact-xenia-release-source-sha-missing")?
            .to_ascii_lowercase();
        if pull_repo_source_sha
            .as_deref()
            .is_some_and(|observed| !same_source_sha(observed, &selected_source_sha))
        {
            return Err("fetch-artifact-xenia-release-source-sha-mismatch".into());
        }
        let release_tag = crate::atoms::ask::fetch_artifact::release_tag_for_source_sha(
            &selected_source_sha,
        )
        .ok_or("fetch-artifact-xenia-release-source-sha-invalid")?;
        let api_root = args
            .get("api_root")
            .and_then(Value::as_str)
            .unwrap_or("https://git.home.arpa/api/v1");
        credential_state =
            crate::atoms::ask::fetch_artifact::credential_state_for_url(api_root)?;
        let mut download = crate::atoms::ask::fetch_artifact::download_release(
            component,
            artifact_name,
            source_dir.unwrap_or(Path::new("")),
            release_repo,
            Some(&release_tag),
            api_root,
            release_asset_name.as_deref(),
            release_sidecar_name.as_deref(),
            identity,
            &selected_source_sha,
        )?
        .ok_or("fetch-artifact-xenia-release-absent")?;
        if !crate::atoms::ask::fetch_artifact::validate_source_sha(&download.manifest.source_sha)
            || !same_source_sha(&download.manifest.source_sha, &selected_source_sha)
        {
            return Err("fetch-artifact-xenia-release-source-sha-mismatch".into());
        }
        if xenia_expected_digest
            .is_some_and(|expected| download.manifest.sha256 != expected)
        {
            return Err("fetch-artifact-xenia-pull-repo-digest-mismatch".into());
        }
        effective_source_sha = download.manifest.source_sha.clone();
        release_digest = Some(download.manifest.sha256.clone());
        download.identity = identity.to_owned();
        native_download = Some(download);
    } else if source_policy == "artifact" {
        let config_path = crate::bands::pull_source::appliance_config_path();
        let certificate_path = crate::device_profile::device_profile_certificate_path();
        let source_receipt = crate::bands::pull_source::resolve_source(
            crate::bands::pull_source::SourceAuthority::ApplianceConfig {
                config_path: &config_path,
                profile_path: &certificate_path,
            },
            component,
            module_id.unwrap_or(component),
            "module-release-artifact",
            None,
            None,
        );
        if !source_receipt.ok {
            return Err(format!(
                "fetch-artifact-source-resolution-refused component={component} blocker={}",
                source_receipt
                    .blocker
                    .as_deref()
                    .unwrap_or("source-resolution-not-ok")
            ));
        }
        let resolution = source_receipt
            .resolution
            .as_ref()
            .ok_or("fetch-artifact-source-resolution-missing")?;
        if resolution.source_policy != "artifact" {
            return Err(format!(
                "fetch-artifact-source-policy-mismatch component={component} configured={}",
                resolution.source_policy
            ));
        }
        if resolution.candidates.is_empty() {
            return Err(format!(
                "fetch-artifact-source-candidates-empty component={component}"
            ));
        }
        let asset_name = release_asset_name
            .as_deref()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{artifact_name}-x86_64"));
        let sidecar_name = release_sidecar_name
            .as_deref()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{asset_name}.sha256"));
        credential_state = "managed-by-configured-release-provider";
        let (download, candidate_receipts) =
            crate::bands::renew_self::download_module_release_candidates(
                component,
                resolution,
                &asset_name,
                &sidecar_name,
                resolved_profile_segment.as_deref(),
                pinned_release_sha.as_deref(),
                None,
            );
        std::fs::create_dir_all(receipt_dir)
            .map_err(|error| format!("fetch-artifact-receipt-dir-create: {error}"))?;
        crate::write_json(
            &receipt_dir.join("module-release-candidates.json"),
            &serde_json::json!({
                "schema": "harmonia.module_release_candidates.v1",
                "module_id": module_id.unwrap_or(component),
                "component": component,
                "candidate_count": candidate_receipts.len(),
                "candidates": candidate_receipts,
            }),
        )
        .map_err(|error| format!("fetch-artifact-candidate-receipt-write: {error}"))?;
        module_release_candidates = Some(candidate_receipts);
        if let Some(mut download) = download {
            if !crate::atoms::ask::fetch_artifact::validate_source_sha(
                &download.manifest.source_sha,
            ) {
                return Err("fetch-artifact-release-source-sha-invalid".into());
            }
            if pinned_release_sha
                .as_deref()
                .is_some_and(|pinned| download.manifest.source_sha != pinned)
            {
                return Err("fetch-artifact-pinned-release-mismatch".into());
            }
            effective_source_sha = download.manifest.source_sha.clone();
            release_digest = Some(download.manifest.sha256.clone());
            download.identity = identity.to_owned();
            native_download = Some(download);
        } else {
            let candidate_count = module_release_candidates
                .as_ref()
                .map_or(0, Vec::len);
            let exhaustion_signal = format!(
                "module-artifact-candidates-exhausted module={} component={} candidate_count={candidate_count}",
                module_id.unwrap_or(component),
                component
            );
            if candidate_count == 0 {
                return Err(format!(
                    "module-artifact-release-candidates-absent module={} component={}",
                    module_id.unwrap_or(component),
                    component
                ));
            }
            let stamped_pruned_target = stamped_release_sha.as_deref().filter(|_| {
                candidate_count > 0
                    && module_release_candidates.as_ref().is_some_and(|candidates| {
                        candidates.len() == candidate_count
                            && candidates.iter().all(|candidate| {
                                candidate
                                    .pointer("/final-state/blocker")
                                    .and_then(Value::as_str)
                                    == Some("fetch-artifact-pinned-release-missing")
                            })
                    })
            });
            if let Some(target_sha) = stamped_pruned_target {
                let declared_source_dir = source_dir.ok_or("fetch-artifact-source-dir-missing")?;
                let mut pinned_resolution = resolution.clone();
                pinned_resolution.requested_ref = target_sha.to_owned();
                stamped_source_plan = Some(crate::bands::pull_source::bridge_acquisition_plan(
                    &pinned_resolution,
                    declared_source_dir.to_path_buf(),
                    Some(target_sha.to_owned()),
                ));
                effective_source_sha = target_sha.to_owned();
                release_fallback = Some((
                    "stamped-release-pruned".into(),
                    format!("source://{target_sha}"),
                ));
            } else {
                if !apply {
                    return Err(exhaustion_signal);
                }
                let before = read_standing_artifact_snapshot(installed_binary)?;
                let after = read_standing_artifact_snapshot(installed_binary)?;
                if before != after {
                    return Err(format!(
                        "fetch-artifact-standing-artifact-changed-during-observation path={}",
                        installed_binary.display()
                    ));
                }
                let mut witness = after;
                witness["unchanged"] = Value::Bool(true);
                let routine_id = receipt_dir
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|value| value.to_str())
                    .unwrap_or("unknown-routine");
                let debt = serde_json::json!({
                    "schema": "harmonia.module_artifact_exhaustion.v1",
                    "ok": false,
                    "module_id": module_id.unwrap_or(component),
                    "component": component,
                    "routine_id": routine_id,
                    "step_id": "fetch-artifact",
                    "first_missing_signal": exhaustion_signal,
                    "candidate_count": candidate_count,
                    "candidates": module_release_candidates.as_ref().unwrap(),
                    "standing_artifact": witness,
                    "changed": false,
                    "installed_artifact_preserved": true,
                });
                crate::write_json(
                    &receipt_dir.join("module-artifact-exhaustion.json"),
                    &debt,
                )
                .map_err(|error| format!("fetch-artifact-exhaustion-receipt-write: {error}"))?;
                crate::atoms::attest::fetch_artifact::attest(
                    &receipt_dir.join("harmonia-atoms.log"),
                    true,
                    false,
                    &format!(
                        "state=Drift; care=all configured Release candidates refused; after=Drift; reason={exhaustion_signal}; installed_artifact_preserved=true"
                    ),
                )?;
                return Ok(FetchArtifactExecution {
                    outcome: crate::OperationOutcome {
                        ok: true,
                        changed: false,
                        skipped: true,
                        message: exhaustion_signal,
                        command: None,
                    },
                    source_sha: String::new(),
                    artifact_path: installed_binary.to_path_buf(),
                });
            }
        }
    } else if source_policy == "source" && native_release {
        let tag = args
            .get("release_tag")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| source_sha.to_owned());
        let api_root = args
            .get("api_root")
            .and_then(Value::as_str)
            .unwrap_or("https://git.home.arpa/api/v1");
        credential_state = crate::atoms::ask::fetch_artifact::credential_state_for_url(api_root)?;
        match crate::atoms::ask::fetch_artifact::probe_release_digest(
            artifact_name,
            release_repo,
            &tag,
            api_root,
            release_asset_name.as_deref(),
            release_sidecar_name.as_deref(),
            source_sha,
        ) {
            Ok(digest) => release_digest = digest,
            Err(error) if crate::atoms::ask::fetch_artifact::is_http_status(&error, "404") => {
                release_fallback = Some((
                    "release-miss".into(),
                    crate::atoms::ask::fetch_artifact::release_metadata_url(
                        api_root,
                        release_repo,
                        &tag,
                    ),
                ));
            }
            Err(error)
                if crate::atoms::ask::fetch_artifact::auth_required_url(
                    &error,
                    &crate::atoms::ask::fetch_artifact::release_metadata_url(
                        api_root,
                        release_repo,
                        &tag,
                    ),
                )
                .is_some() =>
            {
                let url = crate::atoms::ask::fetch_artifact::release_metadata_url(
                    api_root,
                    release_repo,
                    &tag,
                );
                release_fallback = Some((
                    "auth-required".into(),
                    crate::atoms::ask::fetch_artifact::auth_required_url(&error, &url)
                        .unwrap_or(url),
                ));
            }
            Err(error) => return Err(error),
        }
    }
    let release_known = release_digest.is_some();
    let road = if source_policy == "artifact" {
        "artifact"
    } else {
        "clone"
    };
    let current = if let Some(expected_digest) = release_digest.as_deref() {
        crate::known_good_ledger::sha256_file(installed_binary)
            .is_ok_and(|installed_digest| installed_digest == expected_digest)
    } else {
        crate::atoms::ask::fetch_artifact::identity_matches(
            installed_binary,
            &effective_source_sha,
            identity,
            component,
        )
    };
    let observed_identity = if release_digest.is_some() {
        crate::known_good_ledger::sha256_file(installed_binary)
            .ok()
            .unwrap_or_else(|| "unreadable-or-absent".into())
    } else if crate::atoms::ask::fetch_artifact::identity_matches(
        installed_binary,
        &effective_source_sha,
        identity,
        component,
    ) {
        effective_source_sha.clone()
    } else {
        "marker-mismatch-or-absent".into()
    };
    if current && !beam_refetch && source_policy != "developer" {
        let supplier = if release_digest.is_some() {
            "release"
        } else {
            "marker-fallback"
        };
        crate::atoms::attest::fetch_artifact::attest(
            &receipt_dir.join("harmonia-atoms.log"),
            true,
            false,
            &format!(
                "state=Current; care=bytes-true currentness; after=Current; road={road}; digest_supplier={supplier}; observed={}; desired={}; diff=empty; movement=none{profile_receipt_fields}",
                observed_identity,
                release_digest.as_deref().unwrap_or(&effective_source_sha)
            ),
        )?;
        return Ok(FetchArtifactExecution {
            outcome: crate::OperationOutcome {
                ok: true,
                changed: false,
                skipped: true,
                message: "fetch-artifact-current".into(),
                command: None,
            },
            source_sha: effective_source_sha,
            artifact_path: installed_binary.to_path_buf(),
        });
    }
    if current && beam_refetch && apply {
        crate::atoms::attest::fetch_artifact::attest(
            &receipt_dir.join("harmonia-atoms.log"),
            true,
            false,
            &format!("state=Drift; care=beam env SHA divergence requires artifact refetch; after=Drift; reason=fetch-artifact-refetch-beam-env-sha; observed={}; desired={}; diff=nonempty; movement=authorized{profile_receipt_fields}", observed_identity, release_digest.as_deref().unwrap_or(&effective_source_sha)),
        )?;
    }
    if !apply {
        let desired_identity = release_digest.as_deref().unwrap_or(&effective_source_sha);
        crate::atoms::attest::fetch_artifact::attest(
            &receipt_dir.join("harmonia-atoms.log"),
            true,
            false,
            &format!("state=Drift; care=release digest/marker comparison only; after=Drift (planned); observed={observed_identity}; desired={desired_identity}; diff=nonempty; movement=none{profile_receipt_fields}"),
        )?;
        return Ok(FetchArtifactExecution {
            outcome: crate::OperationOutcome {
                ok: true,
                changed: false,
                skipped: true,
                message: "fetch-artifact-planned".into(),
                command: None,
            },
            source_sha: effective_source_sha,
            artifact_path: installed_binary.to_path_buf(),
        });
    }
    if source_policy == "source" && native_release && release_fallback.is_none() {
        let tag = args.get("release_tag").and_then(Value::as_str).map(str::to_owned).unwrap_or_else(|| source_sha.to_owned());
        let api_root = args.get("api_root").and_then(Value::as_str).unwrap_or("https://git.home.arpa/api/v1");
        native_download = crate::atoms::ask::fetch_artifact::download_release(
            component, artifact_name, source_dir.unwrap_or(Path::new("")), release_repo,
            (!tag.is_empty()).then_some(tag.as_str()), api_root, release_asset_name.as_deref(),
            release_sidecar_name.as_deref(), identity, source_sha,
        )?;
        if let (Some(expected), Some(download)) = (release_digest.as_deref(), native_download.as_ref()) {
            if download.manifest.sha256 != expected {
                return Err("fetch-artifact-release-digest-changed-after-observation".into());
            }
        }
        if native_download.is_none() {
            release_fallback = Some(("release-miss".into(), crate::atoms::ask::fetch_artifact::release_metadata_url(api_root, release_repo, &tag)));
        }
    }
    let registry_download = if native_download.is_none() && release_fallback.is_none() {
        let registry_artifact_name = release_asset_name.as_deref().unwrap_or(artifact_name);
        let manifest_url = crate::atoms::ask::fetch_artifact::artifact_url(
            registry_base,
            component,
            source_sha,
            "manifest.json",
        );
        credential_state = crate::atoms::ask::fetch_artifact::credential_state_for_url(&manifest_url)?;
        match crate::atoms::ask::fetch_artifact::download(
            component,
            registry_base,
            source_sha,
            registry_artifact_name,
        ) {
            Ok(download) => Some(download),
            Err(error) => {
                if let Some(artifact_url) =
                    crate::atoms::ask::fetch_artifact::auth_required_url(&error, &manifest_url)
                {
                    if source_policy == "artifact" {
                        return Err(error);
                    }
                    release_fallback = Some(("auth-required".into(), artifact_url));
                    None
                } else {
                    let _ = crate::atoms::attest::fetch_artifact::attest(
                        &receipt_dir.join("harmonia-atoms.log"),
                        false,
                        false,
                        &format!(
                            "state=Drift; care=artifact acquisition refused; after=Drift; error={error}"
                        ),
                    );
                    return Err(error);
                }
            }
        }
    } else {
        None
    };
    let download = if let Some(download) = native_download {
        download
    } else if let Some((fallback_reason, artifact_url)) = release_fallback {
        let source_dir = source_dir.ok_or("fetch-artifact-source-dir-missing")?;
        let source_dir_text = source_dir.display().to_string();
        let artifact = source_dir.join("target/release").join(artifact_name);
        let (environment, build_environment_sha) = crate::atoms::ask::fetch_artifact::build_environment(
            component,
            &effective_source_sha,
        )?;
        let mut environment = environment;
        if source_policy == "source" {
            environment.push(("CARTRIDGE_SOURCE_SHA".into(), effective_source_sha.clone()));
        }
        let mut fallback_receipt = serde_json::json!({
            "schema": "harmonia.fetch-artifact.fallback.v1",
            "fallback_reason": fallback_reason,
            "artifact_url": artifact_url,
            "credential": credential_state,
            "source_build_sha": effective_source_sha,
            "source_dir": source_dir_text,
            "build_environment_sha": build_environment_sha,
        });
        if let (Some(declared), Some(resolved)) =
            (profile.as_deref(), resolved_profile_segment.as_deref())
        {
            let fields = fallback_receipt
                .as_object_mut()
                .ok_or("fetch-artifact-fallback-receipt-invalid")?;
            fields.insert("declared_profile".into(), Value::String(declared.into()));
            fields.insert(
                "resolved_profile_segment".into(),
                Value::String(resolved.into()),
            );
        }
        crate::write_json(&receipt_dir.join("fallback.json"), &fallback_receipt)?;
        if let Some(plan) = stamped_source_plan.as_ref() {
            let acquisition = crate::bands::pull_source::execute_source(plan, apply, invocation);
            let observed_source_head = if apply {
                let head = crate::atoms::ask::pull_repo::source_head(source_dir, "owner");
                head.ok.then(|| head.stdout.trim().to_owned())
            } else {
                None
            };
            let acquisition_record = serde_json::json!({
                "requested_ref": plan.reference,
                "expected_commit": plan.expected_commit,
                "destination": plan.destination.display().to_string(),
                "apply": apply,
                "ok": acquisition.ok,
                "changed": acquisition.changed,
                "resolved_commit": acquisition.receipt.resolved_commit,
                "owner_checkout_head": observed_source_head,
                "source_receipt": acquisition.receipt,
            });
            crate::write_json(
                &receipt_dir.join("fallback-acquisition.json"),
                &acquisition_record,
            )?;
            if apply {
                if !acquisition.ok {
                    return Err(format!(
                        "fetch-artifact-stamped-source-acquisition-failed: {}",
                        acquisition.receipt.promotion
                    ));
                }
                if acquisition.receipt.resolved_commit.as_deref()
                    != Some(effective_source_sha.as_str())
                {
                    return Err("fetch-artifact-stamped-source-acquisition-commit-mismatch".into());
                }
                if observed_source_head.as_deref() != Some(effective_source_sha.as_str()) {
                    return Err("fetch-artifact-stamped-source-checkout-head-mismatch".into());
                }
            }
        }
        if !apply {
            crate::atoms::attest::fetch_artifact::attest(
                &receipt_dir.join("harmonia-atoms.log"),
                true,
                false,
                &format!("state=Drift; care=release miss requires source build; after=Drift (planned){profile_receipt_fields}"),
            )?;
            return Ok(FetchArtifactExecution {
                outcome: crate::OperationOutcome {
                    ok: true,
                    changed: false,
                    skipped: true,
                    message: "fetch-artifact-planned".into(),
                    command: None,
                },
                source_sha: effective_source_sha,
                artifact_path: installed_binary.to_path_buf(),
            });
        }
        let build = crate::build_crate::run_build_with_mode_for_component(
            source_dir,
            &effective_source_sha,
            None,
            installed_binary,
            &artifact,
            apply,
            &environment,
            args.get("timeout_secs")
                .and_then(Value::as_u64)
                .unwrap_or(crate::atoms::r#do::build_crate::DEFAULT_TIMEOUT_SECS),
            &receipt_dir.join("harmonia-atoms.log"),
            args.get("bearer")
                .and_then(Value::as_str)
                .unwrap_or("owner"),
            invocation,
            component,
            crate::build_crate::IdentityMode::EmbeddedSourceSha,
        )?;
        if let Some(build) = build.filter(|build| !build.ok) {
            return Err(format!(
                "fetch-artifact-source-build-failed: {}",
                build.stderr
            ));
        }
        let bytes = std::fs::read(&artifact)
            .map_err(|error| format!("fetch-artifact-source-build-read-failed: {error}"))?;
        let manifest = crate::atoms::ask::fetch_artifact::Manifest {
            schema: crate::atoms::ask::fetch_artifact::MANIFEST_SCHEMA.into(),
            component: component.into(),
            source_sha: effective_source_sha.clone(),
            target: crate::atoms::ask::fetch_artifact::BUILD_TARGET.into(),
            sha256: crate::atoms::file_sha256(&bytes),
            built_at: "fallback".into(),
            pipeline_url: artifact_url,
            env_sha: Some(build_environment_sha),
            rustc_version: None,
        };
        crate::atoms::ask::fetch_artifact::Download {
            manifest,
            bytes,
            identity: identity.into(),
        }
    } else {
        registry_download.ok_or("fetch-artifact-registry-download-missing")?
    };
    if !apply {
        crate::atoms::attest::fetch_artifact::attest(
            &receipt_dir.join("harmonia-atoms.log"),
            true,
            false,
            &format!("state=Drift; care=manifest and digest verified; after=Drift (planned){profile_receipt_fields}"),
        )?;
        return Ok(FetchArtifactExecution {
            outcome: crate::OperationOutcome {
                ok: true,
                changed: false,
                skipped: true,
                message: "fetch-artifact-planned".into(),
                command: None,
            },
            source_sha: effective_source_sha,
            artifact_path: installed_binary.to_path_buf(),
        });
    }
    let invocation = invocation.ok_or("fetch-artifact-invocation-key-missing")?;
    // Force Drift only for the pre-act observation; allow convergence afterward.
    let mut force_stage_pre_act = true;
    let result = crate::atoms::comparison::execute(
        "fetch-artifact",
        || {
            if std::mem::take(&mut force_stage_pre_act) {
                Ok(false)
            } else {
                Ok(crate::known_good_ledger::sha256_file(destination)
                    .is_ok_and(|digest| digest == download.manifest.sha256)
                    || crate::atoms::ask::fetch_artifact::identity_matches(
                        destination, &effective_source_sha, &download.identity, component,
                    ))
            }
        },
        |seen| {
            if *seen {
                crate::atoms::comparison::DiffDecision::Empty
            } else {
                crate::atoms::comparison::DiffDecision::Different
            }
        },
        |authorization, _| {
            crate::atoms::r#do::fetch_artifact::install(
                &authorization,
                invocation,
                destination,
                &download,
            )
        },
    );
    let run = match result {
        Ok(run) => run,
        Err(error) => {
            let _ = crate::atoms::attest::fetch_artifact::attest(
                &receipt_dir.join("harmonia-atoms.log"),
                false,
                false,
                &format!("state=Drift; care=atomic install failed; after=Drift; error={error}"),
            );
            return Err(error);
        }
    };
    match run {
        crate::atoms::comparison::ComparisonRun::Current { .. } => {
            crate::atoms::attest::fetch_artifact::attest(
                &receipt_dir.join("harmonia-atoms.log"),
                true,
                false,
                &format!("state=Current; care=verified embedded source SHA; after=Current{profile_receipt_fields}"),
            )?;
            Ok(FetchArtifactExecution {
                outcome: crate::OperationOutcome {
                    ok: true,
                    changed: false,
                    skipped: true,
                    message: "fetch-artifact-current".into(),
                    command: None,
                },
                source_sha: effective_source_sha,
                artifact_path: destination.to_path_buf(),
            })
        }
        crate::atoms::comparison::ComparisonRun::Moved { movement: (), .. } => {
            let supplier = if release_known {
                "release"
            } else if matches!(source_policy, "source" | "developer") {
                "build"
            } else {
                "artifact"
            };
            let detail = if beam_refetch {
                format!("state=Drift; care=verified digest and atomic install; after=Current; road={road}; digest_supplier={supplier}; reason=fetch-artifact-refetch-beam-env-sha; observed={}; desired={}; diff=nonempty; movement=completed", observed_identity, download.manifest.sha256)
            } else {
                format!("state=Drift; care=verified digest and atomic install; after=Current; road={road}; digest_supplier={supplier}; observed={}; desired={}; diff=nonempty; movement=completed", observed_identity, download.manifest.sha256)
            };
            let detail = format!("{detail}{profile_receipt_fields}");
            crate::atoms::attest::fetch_artifact::attest(
                &receipt_dir.join("harmonia-atoms.log"),
                true,
                true,
                &detail,
            )?;
            Ok(FetchArtifactExecution {
                outcome: crate::OperationOutcome {
                    ok: true,
                    changed: true,
                    skipped: false,
                    message: "fetch-artifact-installed".into(),
                    command: None,
                },
                source_sha: effective_source_sha,
                artifact_path: destination.to_path_buf(),
            })
        }
    }
}

pub(crate) fn declaration(
) -> Result<Option<&'static crate::tools::declaration::Declaration>, String> {
    crate::tools::declaration::get("fetch-artifact")
}

fn read_standing_artifact_snapshot(path: &Path) -> Result<Value, String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        format!(
            "fetch-artifact-standing-artifact-unobservable path={} error={error}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "fetch-artifact-standing-artifact-not-regular path={}",
            path.display()
        ));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o111 == 0 {
        return Err(format!(
            "fetch-artifact-standing-artifact-not-executable path={}",
            path.display()
        ));
    }
    if metadata.len() == 0 {
        return Err(format!(
            "fetch-artifact-standing-artifact-empty path={}",
            path.display()
        ));
    }
    let bytes = std::fs::read(path).map_err(|error| {
        format!(
            "fetch-artifact-standing-artifact-unreadable path={} error={error}",
            path.display()
        )
    })?;
    if bytes.is_empty() || bytes.len() as u64 != metadata.len() {
        return Err(format!(
            "fetch-artifact-standing-artifact-read-mismatch path={}",
            path.display()
        ));
    }
    Ok(serde_json::json!({
        "path": path,
        "observed": true,
        "regular": true,
        "executable": true,
        "readable": true,
        "nonempty": true,
        "size": bytes.len(),
        "sha256": crate::atoms::file_sha256(&bytes),
        "device": metadata.dev(),
        "inode": metadata.ino(),
        "mode": mode,
        "mtime_seconds": metadata.mtime(),
        "mtime_nanoseconds": metadata.mtime_nsec(),
        "ctime_seconds": metadata.ctime(),
        "ctime_nanoseconds": metadata.ctime_nsec(),
    }))
}

#[cfg(test)]
mod tests {
    use super::execute;
    use serde_json::json;
    use std::{
        collections::BTreeMap,
        fs,
        io::{Read, Write},
        net::TcpListener,
        path::PathBuf,
        thread,
    };

    const SOURCE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
    const ARTIFACT_NAME: &str = "fallback-fixture";

    fn source_fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("src")).unwrap();
        fs::write(
            root.path().join("Cargo.toml"),
            "[package]\nname = \"fallback-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(
            root.path().join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\nversion = 3\n\n[[package]]\nname = \"fallback-fixture\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(
            root.path().join("src/main.rs"),
            "fn main() { println!(\"{}\", concat!(\"caduceus.liveness.v1\", env!(\"CADUCEUS_BUILD_SHA\"))); }\n",
        )
        .unwrap();
        root
    }

    fn embedded_source_fixture() -> tempfile::TempDir {
        let root = source_fixture();
        fs::write(
            root.path().join("src/main.rs"),
            "fn main() { print!(\"caduceus.liveness.v1{}x{}y\", env!(\"CADUCEUS_BUILD_SHA\"), env!(\"CARTRIDGE_SOURCE_SHA\")); }\n",
        )
        .unwrap();
        root
    }

    fn release_fallback_args(
        root: &std::path::Path,
        api_root: String,
        destination: &std::path::Path,
        installed_binary: &std::path::Path,
    ) -> BTreeMap<String, serde_json::Value> {
        [
            ("component", json!("caduceus")),
            ("release_repo", json!("OWNER/REPO")),
            ("api_root", json!(api_root)),
            ("source_build_sha", json!(SOURCE_SHA)),
            ("artifact_name", json!(ARTIFACT_NAME)),
            ("source_dir", json!(root)),
            ("destination", json!(destination)),
            ("installed_binary", json!(installed_binary)),
            ("bearer", json!("owner")),
            ("identity", json!("liveness-marker")),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect()
    }

    fn one_response_server(status: u16) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            let length = stream.read(&mut request).unwrap();
            let expected = format!(
                "GET /api/v1/repos/OWNER/REPO/releases/tags/sha-{SOURCE_SHA} "
            );
            assert!(String::from_utf8_lossy(&request[..length]).starts_with(&expected));
            let reason = match status {
                401 => "Unauthorized",
                404 => "Not Found",
                500 => "Internal Server Error",
                _ => "Unexpected",
            };
            write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            if status == 404 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 4096];
                let length = stream.read(&mut request).unwrap();
                assert!(String::from_utf8_lossy(&request[..length]).starts_with(&format!(
                    "GET /api/v1/repos/OWNER/REPO/releases/tags/{SOURCE_SHA} "
                )));
                write!(
                    stream,
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
            }
        });
        (format!("http://{address}/api/v1"), server)
    }

    #[test]
    fn release_404_builds_source_fallback_and_installs_destination() {
        #[cfg(feature = "test-facade")]
        let _bearer_guard = crate::atoms::command::install_test_current_effective_user();
        let root = source_fixture();
        let destination = root.path().join("destination");
        let installed_binary = root.path().join("installed");
        let receipts = root.path().join("receipts");
        let (api_root, server) = one_response_server(404);
        let args = release_fallback_args(root.path(), api_root, &destination, &installed_binary);
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome = execute(&args, &receipts, true, Some(&invocation)).unwrap();
        server.join().unwrap();
        assert!(outcome.ok);
        assert!(outcome.changed);
        assert!(!outcome.skipped);
        assert!(destination.exists());
        assert!(crate::atoms::ask::fetch_artifact::identity_matches(
            &destination,
            SOURCE_SHA,
            "liveness-marker",
            "caduceus"
        ));
    }

    #[test]
    fn release_404_source_policy_builds_and_installs_embedded_sha_artifact() {
        let root = embedded_source_fixture();
        let destination = root.path().join("destination");
        let installed_binary = root.path().join("installed");
        let receipts = root.path().join("receipts");
        let (api_root, server) = one_response_server(404);
        let mut args = release_fallback_args(
            root.path(),
            api_root,
            &destination,
            &installed_binary,
        );
        args.insert("identity".into(), json!("embedded-sha"));
        args.insert("source_policy".into(), json!("source"));
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome = execute(&args, &receipts, true, Some(&invocation)).unwrap();
        server.join().unwrap();
        assert!(outcome.ok);
        assert!(outcome.changed);
        let staged = root.path().join("target/release").join(ARTIFACT_NAME);
        assert!(staged.is_file());
        let bytes = fs::read(&destination).unwrap();
        let offset = bytes
            .windows(SOURCE_SHA.len())
            .enumerate()
            .find_map(|(offset, window)| {
                (window == SOURCE_SHA.as_bytes()
                    && offset > 0
                    && offset + SOURCE_SHA.len() < bytes.len()
                    && !bytes[offset - 1].is_ascii_hexdigit()
                    && !bytes[offset + SOURCE_SHA.len()].is_ascii_hexdigit())
                    .then_some(offset)
            })
            .expect("CARTRIDGE_SOURCE_SHA must be embedded at a hex boundary");
        assert!(offset > 0);
        assert!(!bytes[offset - 1].is_ascii_hexdigit());
        assert!(offset + SOURCE_SHA.len() < bytes.len());
        assert!(!bytes[offset + SOURCE_SHA.len()].is_ascii_hexdigit());
        assert!(crate::atoms::ask::fetch_artifact::identity_matches(
            &destination,
            SOURCE_SHA,
            "embedded-sha",
            "caduceus"
        ));
    }

    #[test]
    fn release_401_writes_fallback_schema_and_installs_destination() {
        #[cfg(feature = "test-facade")]
        let _bearer_guard = crate::atoms::command::install_test_current_effective_user();
        let root = source_fixture();
        let destination = root.path().join("destination");
        let installed_binary = root.path().join("installed");
        let receipts = root.path().join("receipts");
        let (api_root, server) = one_response_server(401);
        let expected_artifact_url =
            format!("{api_root}/repos/OWNER/REPO/releases/tags/sha-{SOURCE_SHA}");
        let args = release_fallback_args(root.path(), api_root, &destination, &installed_binary);
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome = execute(&args, &receipts, true, Some(&invocation)).unwrap();
        server.join().unwrap();
        assert!(outcome.ok);
        assert!(outcome.changed);
        let fallback: serde_json::Value =
            serde_json::from_slice(&fs::read(receipts.join("fallback.json")).unwrap()).unwrap();
        assert_eq!(fallback["schema"], "harmonia.fetch-artifact.fallback.v1");
        assert_eq!(fallback["fallback_reason"], "auth-required");
        assert_eq!(fallback["artifact_url"], expected_artifact_url);
        assert_eq!(fallback["source_build_sha"], SOURCE_SHA);
        assert!(destination.exists());
    }

    #[test]
    fn registry_403_builds_source_fallback_and_records_refusing_manifest_url() {
        #[cfg(feature = "test-facade")]
        let _bearer_guard = crate::atoms::command::install_test_current_effective_user();
        let root = source_fixture();
        let destination = root.path().join("destination");
        let installed_binary = root.path().join("installed");
        let receipts = root.path().join("receipts");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            let length = stream.read(&mut request).unwrap();
            assert!(String::from_utf8_lossy(&request[..length]).starts_with(
                "GET /caduceus/0123456789abcdef0123456789abcdef01234567/manifest.json "
            ));
            write!(
                stream,
                "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });
        let registry_base = format!("http://{address}");
        let expected_manifest_url = format!("{registry_base}/caduceus/{SOURCE_SHA}/manifest.json");
        let args: BTreeMap<String, serde_json::Value> = [
            ("component", json!("caduceus")),
            ("registry_base", json!(&registry_base)),
            ("source_build_sha", json!(SOURCE_SHA)),
            ("artifact_name", json!(ARTIFACT_NAME)),
            ("source_dir", json!(root.path())),
            ("destination", json!(&destination)),
            ("installed_binary", json!(&installed_binary)),
            ("bearer", json!("owner")),
            ("identity", json!("liveness-marker")),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome = execute(&args, &receipts, true, Some(&invocation)).unwrap();
        server.join().unwrap();
        assert!(outcome.ok);
        assert!(outcome.changed);
        let fallback: serde_json::Value =
            serde_json::from_slice(&fs::read(receipts.join("fallback.json")).unwrap()).unwrap();
        assert_eq!(fallback["fallback_reason"], "auth-required");
        assert_eq!(fallback["artifact_url"], expected_manifest_url);
        assert_eq!(fallback["source_build_sha"], SOURCE_SHA);
        assert!(destination.exists());
    }

    #[test]
    fn release_500_refuses_without_invoking_source_fallback_build() {
        let root = source_fixture();
        let destination = root.path().join("destination");
        let installed_binary = root.path().join("installed");
        let receipts = root.path().join("receipts");
        let (api_root, server) = one_response_server(500);
        let args = release_fallback_args(root.path(), api_root, &destination, &installed_binary);
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let error = execute(&args, &receipts, true, Some(&invocation))
            .expect_err("server failure must not invoke source fallback");
        server.join().unwrap();
        assert!(error.contains("500"), "unexpected error: {error}");
        assert!(!root
            .path()
            .join("target/release")
            .join(ARTIFACT_NAME)
            .exists());
        assert!(!destination.exists());
    }

    #[test]
    fn staged_present_stale_installed_identity_is_drift_and_downloads_fresh_artifact() {
        let old = "0123456789abcdef0123456789abcdef01234567";
        let new = "fedcba9876543210fedcba9876543210fedcba98";
        let root =
            std::env::temp_dir().join(format!("harmonia-fetch-identity-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let installed = root.join("installed");
        let destination = root.join("destination");
        let receipts = root.join("receipts");
        fs::write(&installed, format!("caduceus.liveness.v1{old}")).unwrap();
        fs::write(
            &destination,
            format!("caduceus.liveness.v1{new}:staged-by-earlier-run"),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for path in [
                format!("/caduceus/{new}/manifest.json"),
                format!("/caduceus/{new}/artifact"),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 4096];
                let n = stream.read(&mut request).unwrap();
                assert!(String::from_utf8_lossy(&request[..n]).starts_with(&format!("GET {path} ")));
                let body = if path.ends_with("manifest.json") {
                    format!(
                        r#"{{"schema":"estate.artifact.manifest.v1","component":"caduceus","source_sha":"{new}","target":"x86_64","sha256":"9dd6c95a5644c1d55a1f7ac5302dad5564637d79f55924c9949427a0efca1ec1","built_at":"now","pipeline_url":"https://ci"}}"#
                    )
                } else {
                    format!("caduceus.liveness.v1{new}")
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });
        let args: BTreeMap<String, serde_json::Value> = [
            ("component", json!("caduceus")),
            ("registry_base", json!(format!("http://{address}"))),
            ("source_build_sha", json!(new)),
            ("artifact_name", json!("artifact")),
            ("destination", json!(PathBuf::from(&destination))),
            ("installed_binary", json!(PathBuf::from(&installed))),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome = execute(&args, &receipts, true, Some(&invocation)).unwrap();
        server.join().unwrap();
        assert_eq!(outcome.message, "fetch-artifact-installed");
        assert!(outcome.ok);
        assert!(!outcome.skipped);
        assert!(outcome.changed);
        assert_eq!(
            fs::read(&destination).unwrap(),
            format!("caduceus.liveness.v1{new}").as_bytes()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn profile_source_refusal_preserves_installed_bytes_before_download() {
        let root = tempfile::tempdir().unwrap();
        let installed = root.path().join("installed");
        let before = b"installed-before-profile-blocker";
        fs::write(&installed, before).unwrap();
        let cases = [
            (
                "missing",
                root.path().join("missing"),
                "fetch-artifact-profile-source-missing",
            ),
            (
                "unreadable",
                root.path().join("unreadable"),
                "fetch-artifact-profile-source-unreadable",
            ),
            (
                "malformed",
                root.path().join("malformed.json"),
                "fetch-artifact-profile-source-malformed",
            ),
            (
                "profile-less",
                root.path().join("profile-less.json"),
                "fetch-artifact-profile-source-profile-missing",
            ),
        ];
        fs::create_dir(cases[1].1.clone()).unwrap();
        fs::write(&cases[2].1, "{").unwrap();
        fs::write(&cases[3].1, "{}").unwrap();

        for (name, profile_source, expected) in cases {
            let destination = root.path().join(format!("destination-{name}"));
            let args: BTreeMap<String, serde_json::Value> = [
                ("component", json!("fixture")),
                ("release_repo", json!("OWNER/REPO")),
                ("api_root", json!("http://127.0.0.1:1/api/v1")),
                (
                    "source_build_sha",
                    json!("0123456789abcdef0123456789abcdef01234567"),
                ),
                ("artifact_name", json!("fixture")),
                ("profile_axis", json!("profile")),
                ("profile_source", json!(profile_source)),
                ("destination", json!(&destination)),
                ("installed_binary", json!(&installed)),
            ]
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect();
            let error = execute(&args, &root.path().join("receipts"), true, None)
                .expect_err("profile source blocker");
            assert_eq!(error, expected, "case={name}");
            assert_eq!(fs::read(&installed).unwrap(), before, "case={name}");
            assert!(!destination.exists(), "case={name}");
        }
    }

    #[test]
    fn profile_axis_rejects_invalid_axis_before_profile_source_read() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("destination");
        let installed = root.path().join("installed");
        let args: BTreeMap<String, serde_json::Value> = [
            ("component", json!("fixture")),
            ("release_repo", json!("OWNER/REPO")),
            (
                "source_build_sha",
                json!("0123456789abcdef0123456789abcdef01234567"),
            ),
            ("profile_axis", json!("unsupported")),
            ("destination", json!(&destination)),
            ("installed_binary", json!(&installed)),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect();

        let error = execute(&args, &root.path().join("receipts"), true, None)
            .expect_err("invalid profile axis");
        assert_eq!(error, "fetch-artifact-profile-axis-invalid");
    }

    #[test]
    fn profile_axis_rejects_unsafe_profile_and_name_overrides() {
        let root = tempfile::tempdir().unwrap();
        let profile_source = root.path().join("profile.json");
        fs::write(&profile_source, r#"{"profile":"../homeserver"}"#).unwrap();
        let destination = root.path().join("destination");
        let installed = root.path().join("installed");
        let base_args: BTreeMap<String, serde_json::Value> = [
            ("component", json!("fixture")),
            ("release_repo", json!("OWNER/REPO")),
            (
                "source_build_sha",
                json!("0123456789abcdef0123456789abcdef01234567"),
            ),
            ("artifact_name", json!("fixture")),
            ("profile_axis", json!("profile")),
            ("profile_source", json!(&profile_source)),
            ("destination", json!(&destination)),
            ("installed_binary", json!(&installed)),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect();
        let error = execute(&base_args, &root.path().join("receipts"), true, None)
            .expect_err("unsafe profile");
        assert_eq!(error, "fetch-artifact-profile-invalid");

        fs::write(&profile_source, r#"{"profile":"homeserver"}"#).unwrap();
        for (key, value, expected) in [
            (
                "asset_name",
                "fixture-x86_64",
                "fetch-artifact-profile-asset-name-mismatch",
            ),
            (
                "sidecar_name",
                "fixture-homeserver-x86_64.digest",
                "fetch-artifact-profile-sidecar-name-mismatch",
            ),
        ] {
            let mut args = base_args.clone();
            args.insert(key.into(), json!(value));
            let error = execute(&args, &root.path().join("receipts"), true, None)
                .expect_err("profile name override");
            assert_eq!(error, expected, "override={key}");
        }
    }

    #[test]
    fn profile_axis_native_release_uses_profile_specific_asset_and_sidecar() {
        let root = tempfile::tempdir().unwrap();
        let profile_source = root.path().join("profile.json");
        fs::write(&profile_source, r#"{"profile":"homeserver"}"#).unwrap();
        let source_sha = "0123456789abcdef0123456789abcdef01234567";
        let artifact = format!("profile-specific-release-artifact-{source_sha}").into_bytes();
        let digest = crate::atoms::file_sha256(&artifact);
        let asset_name = "caduceus-homeserver-x86_64";
        let sidecar_name = "caduceus-homeserver-x86_64.sha256";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let release_body = json!({
            "target_commitish": source_sha,
            "assets": [
                {
                    "name": asset_name,
                    "browser_download_url": format!("http://{address}/artifact"),
                },
                {
                    "name": sidecar_name,
                    "browser_download_url": format!("http://{address}/sidecar"),
                },
            ],
        })
        .to_string()
        .into_bytes();
        let artifact_for_server = artifact.clone();
        let server = thread::spawn(move || {
            for (path, body) in [
                (
                    format!("/api/v1/repos/OWNER/REPO/releases/tags/sha-{source_sha}"),
                    release_body,
                ),
                ("/artifact".into(), artifact_for_server),
                (
                    "/sidecar".into(),
                    format!("{digest}  {asset_name}\n").into_bytes(),
                ),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 4096];
                let n = stream.read(&mut request).unwrap();
                assert!(
                    String::from_utf8_lossy(&request[..n]).starts_with(&format!("GET {path} ")),
                    "unexpected request for {path}"
                );
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        let destination = root.path().join("destination");
        let installed = root.path().join("installed");
        let args: BTreeMap<String, serde_json::Value> = [
            ("component", json!("caduceus")),
            ("release_repo", json!("OWNER/REPO")),
            ("api_root", json!(format!("http://{address}/api/v1"))),
            ("source_build_sha", json!(source_sha)),
            ("artifact_name", json!("caduceus")),
            ("profile_axis", json!("profile")),
            ("profile_source", json!(&profile_source)),
            ("destination", json!(&destination)),
            ("installed_binary", json!(&installed)),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome = execute(
            &args,
            &root.path().join("receipts"),
            true,
            Some(&invocation),
        )
        .unwrap();
        server.join().unwrap();
        assert!(outcome.ok);
        assert!(outcome.changed);
        assert_eq!(fs::read(destination).unwrap(), artifact);
    }

    #[test]
    fn native_release_refetches_marker_current_but_byte_drifted_install() {
        let root = tempfile::tempdir().unwrap();
        let source_sha = "0123456789abcdef0123456789abcdef01234567";
        let artifact = format!("release-bytes-{source_sha}").into_bytes();
        let digest = crate::atoms::file_sha256(&artifact);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let release_body = json!({
            "target_commitish": source_sha,
            "assets": [
                {"name":"fixture-x86_64","browser_download_url":format!("http://{address}/artifact")},
                {"name":"fixture-x86_64.sha256","browser_download_url":format!("http://{address}/sidecar")}
            ]
        })
        .to_string()
        .into_bytes();
        let artifact_for_server = artifact.clone();
        let server = thread::spawn(move || {
            for (path, body) in [
                (
                    format!("/api/v1/repos/OWNER/REPO/releases/tags/sha-{source_sha}"),
                    release_body,
                ),
                ("/artifact".into(), artifact_for_server),
                (
                    "/sidecar".into(),
                    format!("{digest}  fixture-x86_64\n").into_bytes(),
                ),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 4096];
                let n = stream.read(&mut request).unwrap();
                assert!(String::from_utf8_lossy(&request[..n]).starts_with(&format!("GET {path} ")));
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        let installed = root.path().join("installed");
        let destination = root.path().join("destination");
        let receipts = root.path().join("receipts");
        fs::write(&installed, format!("hand-restored-{source_sha}-different")).unwrap();
        let args: BTreeMap<String, serde_json::Value> = [
            ("component", json!("fixture")),
            ("release_repo", json!("OWNER/REPO")),
            ("api_root", json!(format!("http://{address}/api/v1"))),
            ("source_build_sha", json!(source_sha)),
            ("artifact_name", json!("fixture")),
            ("identity", json!("embedded-sha")),
            ("destination", json!(&destination)),
            ("installed_binary", json!(&installed)),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome = execute(&args, &receipts, true, Some(&invocation)).unwrap();
        server.join().unwrap();
        assert!(outcome.ok);
        assert!(outcome.changed);
        assert_eq!(fs::read(destination).unwrap(), artifact);
    }

    #[test]
    fn beam_refetches_current_embedded_identity() {
        let new = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        let installed = root.join("installed");
        let destination = root.join("destination");
        let receipts = root.join("receipts");
        fs::write(&installed, format!("caduceus.liveness.v1{new}")).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for path in [
                format!("/caduceus/{new}/manifest.json"),
                format!("/caduceus/{new}/artifact"),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 4096];
                let n = stream.read(&mut request).unwrap();
                assert!(String::from_utf8_lossy(&request[..n]).starts_with(&format!("GET {path} ")));
                let body = if path.ends_with("manifest.json") {
                    format!(
                        r#"{{"schema":"estate.artifact.manifest.v1","component":"caduceus","source_sha":"{new}","target":"x86_64","sha256":"32f70da4e10cc86076da0e00a3b783ed3c2731302adc851d9e32fad57cbb7c20","built_at":"now","pipeline_url":"https://ci"}}"#
                    )
                } else {
                    format!("caduceus.liveness.v1{new}")
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });
        let args: BTreeMap<String, serde_json::Value> = [
            ("component", json!("caduceus")),
            ("registry_base", json!(format!("http://{address}"))),
            ("source_build_sha", json!(new)),
            ("beam_refetch", json!(true)),
            ("artifact_name", json!("artifact")),
            ("destination", json!(PathBuf::from(&destination))),
            ("installed_binary", json!(PathBuf::from(&installed))),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let outcome = execute(&args, &receipts, true, Some(&invocation)).unwrap();
        server.join().unwrap();
        assert_eq!(outcome.message, "fetch-artifact-installed");
        let atom_log = fs::read_to_string(receipts.join("harmonia-atoms.log")).unwrap();
        assert!(atom_log.contains("fetch-artifact-refetch-beam-env-sha"));
        assert!(outcome.ok);
        assert!(!outcome.skipped);
        assert!(outcome.changed);
        assert_eq!(
            fs::read(&destination).unwrap(),
            format!("caduceus.liveness.v1{new}").as_bytes()
        );
    }
}
