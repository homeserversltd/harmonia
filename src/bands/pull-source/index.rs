use crate::OperationOutcome;
use super::Band;
use crate::ladder::{LadderManifest, ProjectedRoutineChild, ValidatedStep};
use crate::tools;
use crate::ModuleExecution;
use crate::CmdResult;
use crate::{
    LoadedModule, PackageAuthority, Profile, ProfileProjection, SoftwareApplyAuthorization,
    UpdateMode,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::path::Path;

pub(crate) fn enter(enter: &mut impl FnMut(Band) -> Result<(), String>) -> Result<(), String> {
    enter(Band::PullSource)
}

// Pure engine-plane source policy resolution.
//
// This module reads an explicitly supplied device certificate and returns data
// only.  It never opens a transport, probes a candidate, reads credentials, or
// writes a receipt to disk.  The caller owns persistence and execution.

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;

pub(crate) const SOURCE_PLAN_SCHEMA: &str = "harmonia.engine.source_plan.v1";
pub(crate) const SOURCE_RECEIPT_SCHEMA: &str = "harmonia.engine.source_resolution.v1";
pub(crate) const DEVICE_PROFILE_SCHEMA: &str = "homeserver.device-profile.v1";

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SourceCandidatePlan {
    pub kind: String,
    pub locator: String,
    pub credential_selector: Option<String>,
    pub freshness_authority: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SourceResolution {
    pub schema: &'static str,
    pub component: String,
    pub requested_ref: String,
    pub candidates: Vec<SourceCandidatePlan>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SourceResolutionReceipt {
    pub schema: &'static str,
    pub ok: bool,
    pub mutation: bool,
    pub network_access: bool,
    pub certificate_path: String,
    pub certificate_schema: Option<String>,
    pub component: String,
    pub owning_module: String,
    pub step_id: String,
    pub requested_ref: Option<String>,
    pub ordered_candidate_identities: Vec<String>,
    pub credential_selectors: Vec<String>,
    pub blocker: Option<String>,
    pub resolution: Option<SourceResolution>,
}

#[derive(Debug, Deserialize)]
struct Certificate {
    schema: String,
    #[serde(default)]
    sources: BTreeMap<String, SourceDeclaration>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceDeclaration {
    #[serde(rename = "ref")]
    reference: String,
    candidates: Vec<SourceCandidate>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceCandidate {
    kind: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    credential_selector: Option<String>,
}

fn receipt(
    certificate_path: &Path,
    certificate_schema: Option<String>,
    component: &str,
    owning_module: &str,
    step_id: &str,
    requested_ref: Option<String>,
    candidates: Vec<String>,
    selectors: Vec<String>,
    blocker: Option<String>,
    resolution: Option<SourceResolution>,
) -> SourceResolutionReceipt {
    SourceResolutionReceipt {
        schema: SOURCE_RECEIPT_SCHEMA,
        ok: blocker.is_none(),
        mutation: false,
        network_access: false,
        certificate_path: certificate_path.display().to_string(),
        certificate_schema,
        component: component.to_string(),
        owning_module: owning_module.to_string(),
        step_id: step_id.to_string(),
        requested_ref,
        ordered_candidate_identities: candidates,
        credential_selectors: selectors,
        blocker,
        resolution,
    }
}

fn blocker_receipt(
    certificate_path: &Path,
    certificate_schema: Option<String>,
    component: &str,
    owning_module: &str,
    step_id: &str,
    blocker: String,
) -> SourceResolutionReceipt {
    receipt(
        certificate_path,
        certificate_schema,
        component,
        owning_module,
        step_id,
        None,
        Vec::new(),
        Vec::new(),
        Some(blocker),
        None,
    )
}

fn parse_certificate(path: &Path) -> Result<Certificate, String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("source-certificate-read-failed {}: {err}", path.display()))?;
    let certificate: Certificate = serde_json::from_str(&text)
        .map_err(|err| format!("source-certificate-parse-failed {}: {err}", path.display()))?;
    if certificate.schema != DEVICE_PROFILE_SCHEMA {
        return Err(format!(
            "source-certificate-schema-foreign expected={DEVICE_PROFILE_SCHEMA} got={}",
            certificate.schema
        ));
    }
    Ok(certificate)
}

fn locator_is_safe(locator: &str) -> bool {
    let lower = locator.to_ascii_lowercase();
    if [
        "token=",
        "secret=",
        "password=",
        "private_key",
        "access_key",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        return false;
    }
    let Some((_, after_scheme)) = locator.split_once("://") else {
        return true;
    };
    let authority = after_scheme.split('/').next().unwrap_or_default();
    !authority.contains('@')
}

pub(crate) fn selector_is_safe(selector: &str) -> bool {
    let selector = selector.trim();
    !selector.is_empty()
        && selector.chars().enumerate().all(|(index, ch)| match index {
            0 => ch.is_ascii_alphabetic(),
            _ => ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'),
        })
        && !selector.contains("..")
        && !selector.contains('/')
        && !selector.contains('\\')
        && !["token", "secret", "password", "private", "key-path"]
            .iter()
            .any(|forbidden| selector.to_ascii_lowercase().contains(forbidden))
}

/// Bridge certificate policy and body-local material without merging their
/// authorities. The certificate supplies candidates and opaque selectors; the
/// supplied map supplies only selector-keyed CredentialScope material. Missing
/// named scopes remain unresolved so `acquire_source` produces its established
/// hard-red receipt instead of falling back anonymously.
pub(crate) fn bridge_acquisition_plan(
    resolution: &SourceResolution,
    destination: PathBuf,
    bearer: String,
    expected_commit: Option<String>,
    credentials: BTreeMap<String, crate::tools::git_artifact::CredentialScope>,
) -> crate::tools::git_artifact::SourcePlan {
    crate::tools::git_artifact::SourcePlan {
        candidates: resolution
            .candidates
            .iter()
            .map(|candidate| crate::tools::git_artifact::SourceCandidate {
                kind: match candidate.kind.as_str() {
                    "git" => crate::tools::git_artifact::SourceCandidateKind::Git,
                    "local-checkout" => {
                        crate::tools::git_artifact::SourceCandidateKind::LocalCheckout
                    }
                    _ => unreachable!("source resolution admits only supported candidate kinds"),
                },
                locator: candidate.locator.clone(),
                credential_selector: candidate.credential_selector.clone(),
            })
            .collect(),
        reference: resolution.requested_ref.clone(),
        destination,
        expected_commit,
        bearer,
        credentials,
    }
}

fn candidate_plan(
    candidate: &SourceCandidate,
    ordinal: usize,
) -> Result<(SourceCandidatePlan, String, Option<String>), String> {
    let (locator, freshness_authority) = match candidate.kind.as_str() {
        "git" => {
            if candidate
                .url
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none()
                || candidate.path.is_some()
            {
                return Err(format!(
                    "source-candidate-invalid component-candidate={ordinal} kind=git"
                ));
            }
            (candidate.url.as_ref().unwrap().trim().to_string(), None)
        }
        "local-checkout" => {
            if candidate
                .path
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none()
                || candidate.url.is_some()
            {
                return Err(format!(
                    "source-candidate-invalid component-candidate={ordinal} kind=local-checkout"
                ));
            }
            (
                candidate.path.as_ref().unwrap().trim().to_string(),
                Some("external-owner-plane-freshness-not-verified-by-harmonia".to_string()),
            )
        }
        other => {
            return Err(format!(
                "source-candidate-kind-unsupported component-candidate={ordinal} kind={other}"
            ));
        }
    };
    if !locator_is_safe(&locator) {
        return Err(format!(
            "source-candidate-locator-secret-like component-candidate={ordinal}"
        ));
    }
    if let Some(selector) = candidate.credential_selector.as_deref() {
        if !selector_is_safe(selector) {
            return Err(format!(
                "source-credential-selector-invalid component-candidate={ordinal}"
            ));
        }
    }
    Ok((
        SourceCandidatePlan {
            kind: candidate.kind.clone(),
            locator,
            credential_selector: candidate.credential_selector.clone(),
            freshness_authority,
        },
        format!("{}:{ordinal}", candidate.kind),
        candidate.credential_selector.clone(),
    ))
}

/// Resolve one component without executing transport or mutating local state.
pub(crate) fn resolve_source(
    certificate_path: &Path,
    component: &str,
    owning_module: &str,
    step_id: &str,
) -> SourceResolutionReceipt {
    let certificate = match parse_certificate(certificate_path) {
        Ok(certificate) => certificate,
        Err(blocker) => {
            return blocker_receipt(
                certificate_path,
                None,
                component,
                owning_module,
                step_id,
                blocker,
            );
        }
    };
    let schema = Some(certificate.schema.clone());
    let Some(declaration) = certificate.sources.get(component) else {
        return blocker_receipt(
            certificate_path,
            schema,
            component,
            owning_module,
            step_id,
            format!("source-component-undeclared component={component}"),
        );
    };
    let requested_ref = declaration.reference.trim();
    if requested_ref.is_empty() {
        return blocker_receipt(
            certificate_path,
            schema,
            component,
            owning_module,
            step_id,
            format!("source-ref-empty component={component}"),
        );
    }
    if declaration.candidates.is_empty() {
        return receipt(
            certificate_path,
            schema,
            component,
            owning_module,
            step_id,
            Some(requested_ref.to_string()),
            Vec::new(),
            Vec::new(),
            Some(format!("source-candidates-empty component={component}")),
            None,
        );
    }

    let mut candidates = Vec::new();
    let mut identities = Vec::new();
    let mut selectors = Vec::new();
    for (index, candidate) in declaration.candidates.iter().enumerate() {
        match candidate_plan(candidate, index + 1) {
            Ok((plan, identity, selector)) => {
                candidates.push(plan);
                identities.push(identity);
                if let Some(selector) = selector {
                    selectors.push(selector);
                }
            }
            Err(blocker) => {
                identities.push(format!("{}:{}", candidate.kind, index + 1));
                return receipt(
                    certificate_path,
                    schema,
                    component,
                    owning_module,
                    step_id,
                    Some(requested_ref.to_string()),
                    identities,
                    selectors,
                    Some(blocker),
                    None,
                );
            }
        }
    }
    let resolution = SourceResolution {
        schema: SOURCE_PLAN_SCHEMA,
        component: component.to_string(),
        requested_ref: requested_ref.to_string(),
        candidates,
    };
    receipt(
        certificate_path,
        schema,
        component,
        owning_module,
        step_id,
        Some(requested_ref.to_string()),
        identities,
        selectors,
        None,
        Some(resolution),
    )
}

/// Validate every declared source entry before any profile or module execution.
/// An omitted `sources` object is deliberately an empty declaration set, allowing
/// source certificates to remain valid until a later slice names consumers.
pub(crate) fn validate_declared_sources(
    certificate_path: &Path,
) -> Result<Vec<SourceResolutionReceipt>, String> {
    let certificate = parse_certificate(certificate_path)?;
    let components: Vec<String> = certificate.sources.keys().cloned().collect();
    let mut receipts = Vec::new();
    for component in components {
        let resolution = resolve_source(
            certificate_path,
            &component,
            "engine-plane",
            "certificate-source-validation",
        );
        if let Some(blocker) = resolution.blocker.clone() {
            return Err(format!(
                "source-validation-blocker component={} certificate={} owner_module={} step_id={} blocker={blocker}",
                resolution.component,
                resolution.certificate_path,
                resolution.owning_module,
                resolution.step_id,
            ));
        }
        receipts.push(resolution);
    }
    Ok(receipts)
}

pub(crate) fn resolve_source_json(
    certificate_path: &Path,
    component: &str,
    owning_module: &str,
    step_id: &str,
) -> Value {
    serde_json::to_value(resolve_source(
        certificate_path,
        component,
        owning_module,
        step_id,
    ))
    .unwrap_or_else(|err| {
        json!({
            "schema": SOURCE_RECEIPT_SCHEMA,
            "ok": false,
            "mutation": false,
            "network_access": false,
            "component": component,
            "owning_module": owning_module,
            "step_id": step_id,
            "blocker": format!("source-receipt-serialize-failed: {err}"),
        })
    })
}

fn string_arg<'a>(args: &'a BTreeMap<String, Value>, name: &str) -> &'a str {
    args.get(name).and_then(Value::as_str).unwrap_or("")
}
fn optional_string_arg<'a>(args: &'a BTreeMap<String, Value>, name: &str) -> Option<&'a str> {
    args.get(name).and_then(Value::as_str)
}

pub(crate) fn execute_git_artifact_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let source_plan = routine_source_plan(step, manifest)?;
    let outcome = if apply {
        tools::git_artifact::acquire_source(&source_plan, invocation)
    } else {
        tools::git_artifact::SourceOutcome {
            ok: true,
            changed: false,
            receipt: tools::git_artifact::SourceReceipt {
                attempts: Vec::new(),
                served_index: None,
                resolved_commit: None,
                promotion: "planned source acquisition".to_string(),
            },
        }
    };
    let command = source_outcome_command(&outcome);
    crate::write_tool_receipt(
        module_dir,
        &step.step_id,
        "git-artifact",
        "sync",
        &OperationOutcome {
            ok: outcome.ok,
            changed: outcome.changed,
            skipped: !apply,
            message: outcome.receipt.promotion.clone(),
            command: Some(command.clone()),
        },
    )?;
    let receipt_path = module_dir.join(format!("{}.json", step.step_id));
    let mut receipt: Value = serde_json::from_slice(
        &fs::read(&receipt_path)
            .map_err(|error| format!("git-artifact-receipt-read-failed: {error}"))?,
    )
    .map_err(|error| format!("git-artifact-receipt-parse-failed: {error}"))?;
    let object = receipt
        .as_object_mut()
        .ok_or_else(|| "git-artifact-receipt-not-object".to_string())?;
    object.insert(
        "attempts".into(),
        json!(outcome
            .receipt
            .attempts
            .iter()
            .map(|attempt| json!({
                "index": attempt.index,
                "kind": format!("{:?}", attempt.kind).to_ascii_lowercase(),
                "locator": attempt.locator,
                "credential_selector": attempt.credential_selector,
                "disposition": attempt.disposition,
                "resolved_commit": attempt.resolved_commit,
                "external_freshness": attempt.external_freshness,
                "detail": attempt.detail,
            }))
            .collect::<Vec<_>>()),
    );
    object.insert("served_index".into(), json!(outcome.receipt.served_index));
    if let Some(commit) = &outcome.receipt.resolved_commit {
        object.insert("resolved_commit".into(), json!(commit));
    }
    object.insert("promotion".into(), json!(outcome.receipt.promotion));
    crate::write_json(&receipt_path, &receipt)?;
    Ok(OperationOutcome {
        ok: outcome.ok,
        changed: outcome.changed,
        skipped: !apply,
        message: outcome.receipt.promotion,
        command: Some(command),
    })
}

pub(crate) fn routine_source_plan(
    step: &ValidatedStep,
    manifest: &LadderManifest,
) -> Result<tools::git_artifact::SourcePlan, String> {
    let component = string_arg(&step.args, "component");
    if component.trim().is_empty() {
        return Err(format!(
            "source-component-missing module={} step_id={}",
            manifest.id, step.step_id
        ));
    }
    let destination = optional_string_arg(&step.args, "path")
        .or_else(|| optional_string_arg(&step.args, "source_dir"))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            format!(
                "source-destination-missing module={} step_id={}",
                manifest.id, step.step_id
            )
        })?;
    let config = crate::bands::renew_self::load_engine_plane_config(&crate::bands::renew_self::engine_config_path())?;
    let certificate = crate::device_profile_certificate_path();
    let certificate_resolution =
        crate::bands::pull_source::resolve_source(&certificate, component, &manifest.id, &step.step_id);
    let resolution = match certificate_resolution.resolution {
        Some(resolution) => resolution,
        None if certificate_resolution
            .blocker
            .as_deref()
            .is_some_and(|blocker| {
                blocker == format!("source-component-undeclared component={component}")
            }) =>
        {
            let config = config.as_ref().ok_or_else(|| {
                format!("source-resolution-blocked module={} step_id={} component={} blocker=engine-config-missing", manifest.id, step.step_id, component)
            })?;
            engine_source_resolution(component, config)?
        }
        None => {
            let blocker = certificate_resolution
                .blocker
                .unwrap_or_else(|| "source-resolution-plan-missing".to_string());
            return Err(format!(
                "source-resolution-blocked module={} step_id={} component={} blocker={blocker}",
                manifest.id, step.step_id, component
            ));
        }
    };
    let credentials = config
        .as_ref()
        .map(crate::bands::renew_self::credential_scopes)
        .unwrap_or_default();
    let expected_commit = (resolution.requested_ref.len() == 40
        && resolution
            .requested_ref
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()))
    .then(|| resolution.requested_ref.clone());
    Ok(crate::bands::pull_source::bridge_acquisition_plan(
        &resolution,
        PathBuf::from(destination),
        optional_string_arg(&step.args, "bearer")
            .unwrap_or("owner")
            .to_string(),
        expected_commit,
        credentials,
    ))
}

pub(crate) fn execute_source(
    plan: &tools::git_artifact::SourcePlan,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> tools::git_artifact::SourceOutcome {
    if apply {
        return crate::pull_repo::acquire_source(plan, invocation);
    }
    if let Some(outcome) = crate::pull_repo::observe_source(plan) {
        return outcome;
    }
    let local = tools::git_artifact::source_head(&plan.destination, &plan.bearer);
    let resolved_commit = local
        .ok
        .then(|| local.stdout.trim().to_string())
        .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()));
    tools::git_artifact::SourceOutcome {
        ok: true,
        changed: false,
        receipt: tools::git_artifact::SourceReceipt {
            attempts: Vec::new(),
            served_index: None,
            resolved_commit,
            promotion: "planned source acquisition".into(),
        },
    }
}

fn engine_source_resolution(
    component: &str,
    config: &crate::bands::renew_self::EnginePlaneConfig,
) -> Result<SourceResolution, String> {
    let declared = config.source_components.get(component);
    let (source_repo_url, branch) = if let Some(declared) = declared {
        (&declared.repo_url, &declared.branch)
    } else {
        (&config.source_repo_url, &config.branch)
    };
    let source_component = config
        .source_components
        .get(component)
        .map(|_| component)
        .unwrap_or_else(|| {
            config
                .source_repo_url
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .and_then(|segment| segment.rsplit(':').next())
                .unwrap_or_default()
                .trim_end_matches(".git")
        });
    if source_component != component {
        return Err(format!(
            "source-component-undeclared component={component}; engine-source-component={source_component}"
        ));
    }
    let requested_ref = branch.trim();
    if requested_ref.is_empty() {
        return Err(format!("source-ref-empty component={component}"));
    }
    let credential_selector = match config.credential_scopes.len() {
        0 => None,
        1 => config.credential_scopes.keys().next().cloned(),
        _ => {
            return Err(format!(
                "engine-source-credential-selector-ambiguous component={component} scopes={}",
                config.credential_scopes.len()
            ));
        }
    };
    let candidate = SourceCandidate {
        kind: "git".to_string(),
        url: Some(source_repo_url.trim().to_string()),
        path: None,
        credential_selector,
    };
    let (candidate, _, _) = candidate_plan(&candidate, 1).map_err(|blocker| {
        format!("engine-source-candidate-invalid component={component} blocker={blocker}")
    })?;
    Ok(SourceResolution {
        schema: SOURCE_PLAN_SCHEMA,
        component: component.to_string(),
        requested_ref: requested_ref.to_string(),
        candidates: vec![candidate],
    })
}

/// Execute the complete PullSource band lifecycle for one projected module.
/// Selection, preconditions, authority gating, failure policy, and accumulation
/// intentionally live here rather than in the ladder compatibility executor.
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_manifest_band(
    manifest: &LadderManifest,
    module_dir: &Path,
    auth: Option<&SoftwareApplyAuthorization>,
    pa: Option<&PackageAuthority>,
    key: Option<crate::atoms::r#do::InvocationKey>,
    mode_apply: bool,
    routine_states: &mut BTreeMap<String, crate::ModuleWalkState>,
    projected_steps: &[ValidatedStep],
    projected_routines: &BTreeMap<String, Vec<ProjectedRoutineChild>>,
) -> Result<ModuleExecution, String> {
    crate::atoms::attest::prepare_receipt_parent(module_dir)?;
    let mut result = ModuleExecution {
        ok: true,
        changed: false,
        operation_count: 0,
        first_missing_signal: None,
        placements: Vec::new(),
    };
    for step in projected_steps {
        if step.tool == "routine" {
            let children = projected_routines
                .get(&step.step_id)
                .ok_or_else(|| "routine-step-missing".to_string())?;
            if !children
                .iter()
                .any(|child| child.band == crate::bands::Band::PullSource)
            {
                continue;
            }
        } else if crate::tools::routine::placement_for_step(step)? != crate::bands::Band::PullSource
        {
            continue;
        }
        if let Some(precondition) = if step.tool == "routine" {
            None
        } else {
            crate::tools::routine::command_precondition(&step.args)?
        } {
            result.operation_count += 1;
            let probe = crate::bands::compare::execute_command_precondition(
                step,
                &precondition,
                manifest,
                module_dir,
            )?;
            if !probe.ok {
                result.ok = false;
                let detail = probe
                    .command
                    .as_ref()
                    .map(|r| format!("exit_code={} stderr={}", r.code, r.stderr))
                    .unwrap_or_else(|| probe.message.clone());
                let signal = format!(
                    "step_id={} state=blocked probe_error={detail}",
                    step.step_id
                );
                result.first_missing_signal.get_or_insert(signal);
                result.placements.push(serde_json::json!({"step_id":step.step_id,"tool":step.tool,"permutation":step.permutation,"band":"PullSource","status":"blocked","module":manifest.id}));
                break;
            }
        }
        result.operation_count += 1;
        let outcome = if step.tool == "routine" {
            crate::tools::routine::execute_routine(
                step,
                manifest,
                module_dir,
                auth,
                pa,
                mode_apply,
                key,
                Some(routine_states),
                crate::bands::Band::PullSource,
                projected_routines
                    .get(&step.step_id)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            )?
        } else {
            crate::tools::routine::execute_validated_step(
                step, manifest, module_dir, auth, pa, false, key, None,
            )?
        };
        if step.tool == "routine" {
            let routine = routine_states
                .get(&step.step_id)
                .ok_or_else(|| "routine-state-missing".to_string())?;
            for child in projected_routines
                .get(&step.step_id)
                .map(Vec::as_slice)
                .unwrap_or(&[])
            {
                if child.band != crate::bands::Band::PullSource {
                    continue;
                }
                let receipt = routine
                    .children
                    .iter()
                    .find(|r| r.get("name").and_then(Value::as_str) == Some(child.name.as_str()))
                    .ok_or_else(|| format!("routine-child-receipt-missing-{}", child.name))?;
                result.placements.push(serde_json::json!({"step_id":child.name,"tool":child.tool,"permutation":child.permutation,"band":"PullSource","status":receipt.get("state").and_then(Value::as_str).unwrap_or("failed"),"ok":receipt.get("ok").and_then(Value::as_bool).unwrap_or(false),"changed":receipt.get("changed").and_then(Value::as_bool).unwrap_or(false),"module":manifest.id,"routine":step.step_id}));
            }
        } else {
            result.placements.push(serde_json::json!({"step_id":step.step_id,"tool":step.tool,"permutation":step.permutation,"band":"PullSource","status":if outcome.ok {"completed"} else {"failed"},"module":manifest.id}));
        }
        result.changed |= outcome.changed;
        if !outcome.ok {
            result.ok = false;
            result.first_missing_signal.get_or_insert_with(|| {
                format!("step_id={} defect={}", step.step_id, outcome.message)
            });
            if step.on_failure == crate::ladder::OnFailure::Stop {
                break;
            }
        }
    }
    Ok(result)
}

use crate::receipts::event;
pub(crate) fn execute_manifest_modules(
    profile: &Profile,
    receipt_dir: &Path,
    mode: UpdateMode,
    mode_apply: bool,
    disabled_modules: &BTreeSet<String>,
    projection: &ProfileProjection,
    states: &mut BTreeMap<String, ModuleExecution>,
    routines: &mut BTreeMap<String, BTreeMap<String, crate::ModuleWalkState>>,
    halted: &mut BTreeSet<String>,
    module_count: &mut usize,
    operation_count: &mut usize,
    changed: &mut bool,
    ok: &mut bool,
    first_missing_signal: &mut String,
    events: &mut File,
) -> Result<(), String> {
    for module_id in &profile.modules {
        if disabled_modules.contains(module_id) || halted.contains(module_id) {
            continue;
        }
        let Some(projected) = projection.modules.get(module_id) else {
            let err = projection
                .errors
                .get(module_id)
                .cloned()
                .unwrap_or_else(|| format!("module-not-in-projection-{module_id}"));
            let state = states.entry(module_id.clone()).or_insert(ModuleExecution {
                ok: true,
                changed: false,
                operation_count: 0,
                first_missing_signal: None,
                placements: Vec::new(),
            });
            state.ok = false;
            state.first_missing_signal.get_or_insert(err.clone());
            halted.insert(module_id.clone());
            *ok = false;
            if *first_missing_signal == "none" {
                *first_missing_signal = err.clone();
            }
            event(events, "module-rejected", false, &err)?;
            continue;
        };
        *module_count = profile.modules.len();
        let result = match &projected.loaded {
            LoadedModule::Ladder(manifest) => execute_manifest_band(
                manifest,
                &receipt_dir.join("modules").join(module_id),
                mode.software_authorization(),
                profile.package_authority.as_ref(),
                mode.invocation(),
                mode_apply,
                routines.entry(module_id.clone()).or_default(),
                &projected.steps,
                &projected.routines,
            ),
            LoadedModule::Sidecar(_) => Err("module-sidecar-not-band-executable".to_string()),
        };
        let state = states.entry(module_id.clone()).or_insert(ModuleExecution {
            ok: true,
            changed: false,
            operation_count: 0,
            first_missing_signal: None,
            placements: Vec::new(),
        });
        match result {
            Ok(part) => {
                state.operation_count += part.operation_count;
                state.changed |= part.changed;
                state.placements.extend(part.placements);
                *operation_count += part.operation_count;
                *changed |= part.changed;
                if !part.ok {
                    state.ok = false;
                    state.first_missing_signal = state
                        .first_missing_signal
                        .take()
                        .or(part.first_missing_signal);
                    *ok = false;
                    halted.insert(module_id.clone());
                    if *first_missing_signal == "none" {
                        *first_missing_signal = state
                            .first_missing_signal
                            .clone()
                            .unwrap_or_else(|| format!("module-failed-{module_id}"));
                    }
                }
                event(
                    events,
                    "module-band",
                    part.ok,
                    &format!(
                        "{} band=PullSource steps={}",
                        module_id, part.operation_count
                    ),
                )?;
            }
            Err(err) => {
                state.ok = false;
                state.first_missing_signal.get_or_insert(err.clone());
                halted.insert(module_id.clone());
                *ok = false;
                if *first_missing_signal == "none" {
                    *first_missing_signal = err.clone();
                }
                event(events, "module-rejected", false, &err)?;
            }
        }
    }
    Ok(())
}

fn source_outcome_command(outcome: &tools::git_artifact::SourceOutcome) -> CmdResult {
    CmdResult {
        ok: outcome.ok,
        code: if outcome.ok { 0 } else { 1 },
        stdout: outcome.receipt.promotion.clone(),
        stderr: if outcome.ok {
            String::new()
        } else {
            outcome.receipt.promotion.clone()
        },
    }
}


pub(crate) fn execute_routine_child(
    tool: &str,
    requested_permutation: Option<&str>,
    args: &std::collections::BTreeMap<String, serde_json::Value>,
    manifest: &crate::ladder::LadderManifest,
    receipt_dir: &std::path::Path,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<(crate::OperationOutcome, std::collections::BTreeMap<String, serde_json::Value>), String> {
    let contract = crate::tools::get(tool).ok_or_else(|| format!("routine-tool-not-found-{tool}"))?;
    let permutation = requested_permutation.and_then(|name| contract.permutation(name)).or_else(|| contract.permutations.first()).ok_or_else(|| format!("routine-tool-no-permutation-{tool}"))?;
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
    let name = tool.to_string();
    match tool {
        "pull-repo" => {
            let step = crate::ladder::ValidatedStep {
                step_id: name.clone(),
                tool: tool.into(),
                permutation: permutation.name.into(),
                args: args.clone(),
                on_failure: crate::ladder::OnFailure::Stop,
            };
            let plan = crate::bands::pull_source::routine_source_plan(&step, manifest)?;
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
            crate::write_json(
                &receipt_dir.join(format!("{name}.json")),
                &serde_json::json!({"schema":"harmonia.routine_tool.receipt.v1","ok":o.ok,"changed":o.changed,"skipped":!apply,"promotion":o.receipt.promotion}),
            )?;
            crate::pull_repo::attest_source(&receipt_dir.join("pull-repo.attest.jsonl"), &o)?;
            Ok((result, out))
        }
        _ => Err(format!("routine-tool-not-summonable-{tool}")),
    }
}
