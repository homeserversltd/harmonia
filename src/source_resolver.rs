//! Pure engine-plane source policy resolution.
//!
//! This module reads an explicitly supplied device certificate and returns data
//! only.  It never opens a transport, probes a candidate, reads credentials, or
//! writes a receipt to disk.  The caller owns persistence and execution.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

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
pub(crate) struct SourcePlan {
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
    pub plan: Option<SourcePlan>,
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
    plan: Option<SourcePlan>,
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
        plan,
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

fn selector_is_safe(selector: &str) -> bool {
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
    let plan = SourcePlan {
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
        Some(plan),
    )
}

/// Validate every declared source entry before any profile or module execution.
/// An omitted `sources` object is deliberately an empty declaration set, allowing
/// slice-1 certificates to remain valid until a later slice names consumers.
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
