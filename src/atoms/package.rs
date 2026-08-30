use crate::CmdResult;
use std::env;
use std::path::Path;

pub(crate) const PACKAGE_PIN_SCOPE_LIMITATION: &str =
    "Harmonia's pin excludes names only from Harmonia-owned package transactions; it cannot stop the operator's own hand or a bare pacman/apt command run outside Harmonia (for example, `pacman -Syu`).";

const HARMONIA_PACMAN_PATH_ENV: &str = "HARMONIA_PACMAN_PATH";
const HARMONIA_PACMAN_CONF_PATH_ENV: &str = "HARMONIA_PACMAN_CONF_PATH";
const HARMONIA_PACMAN_KEY_PATH_ENV: &str = "HARMONIA_PACMAN_KEY_PATH";

pub(crate) fn pacman_program() -> String {
    env::var(HARMONIA_PACMAN_PATH_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "/usr/bin/pacman".to_string())
}

pub(crate) fn pacman_conf_program() -> String {
    env::var(HARMONIA_PACMAN_CONF_PATH_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "/usr/bin/pacman-conf".to_string())
}

pub(crate) fn pacman_key_program() -> String {
    env::var(HARMONIA_PACMAN_KEY_PATH_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "/usr/bin/pacman-key".to_string())
}

pub(crate) fn pacman_available(program: &str) -> bool {
    Path::new(program).exists()
}

pub(crate) fn pacman_conflict_signal(result: &CmdResult) -> Option<String> {
    if result.ok {
        return None;
    }
    let combined = format!("{}\n{}", result.stdout, result.stderr);
    if combined.contains("conflicting files") || combined.contains("exists in filesystem") {
        Some("pacman-package-file-conflict".to_string())
    } else {
        None
    }
}

pub(crate) fn pacman_needs_overwrite_retry(result: &CmdResult) -> bool {
    pacman_conflict_signal(result).is_some()
}

pub(crate) fn pacman_base_args(sync: bool) -> Vec<&'static str> {
    if sync {
        vec!["-Syu", "--noconfirm"]
    } else {
        vec!["-S", "--noconfirm", "--needed"]
    }
}

pub(crate) fn overwrite_allowed_args<'a>(
    base: &[&'a str],
    paths: &'a [String],
) -> Option<Vec<&'a str>> {
    if paths.is_empty() || paths.iter().any(|path| path == "*") {
        return None;
    }
    let mut args = base.to_vec();
    for path in paths {
        args.push("--overwrite");
        args.push(path.as_str());
    }
    Some(args)
}

pub(crate) fn pacman_stdout_indicates_change(stdout: &str) -> bool {
    let lower = stdout.to_ascii_lowercase();
    lower.contains("upgrading")
        || lower.contains("installing")
        || lower.contains("reinstalling")
        || lower.contains("removing")
}



pub(crate) use crate::atoms::ask::install_package::PackageObservation;
pub(crate) use crate::atoms::r#do::install_package::{
    keyring_repair_tool, package_tool_for_backend,
    package_tool_with_policy_for_backend_and_pins,
    package_tool_with_policy_for_backend_and_ceilings,
};


#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct DeclaredCeiling {
    pub package: String,
    pub desired: String,
    pub ceiling: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct CeilingCommandEvidence {
    pub program: String,
    pub args: Vec<String>,
    pub ok: bool,
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timeout_secs: u64,
    pub timeout: bool,
    pub timeout_effect: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct CeilingEntry {
    pub package: String,
    pub desired_version: String,
    pub ceiling: String,
    pub live_version: Option<String>,
    pub comparison: String,
    pub witness_state: String,
    pub identity_change: IdentityChange,
    pub currentness_witness: CurrentnessWitness,
    pub posture: String,
    pub command_evidence: Vec<CeilingCommandEvidence>,
    pub first_blocker: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct CurrentnessWitness {
    pub before: Option<String>,
    pub after: Option<String>,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum IdentityChange {
    Unchanged,
    Ordered { before: String, after: String },
    Incomparable { before: String, after: String, first_blocker: String },
}

pub(crate) fn identity_change(before: &str, after: &str) -> IdentityChange {
    if before == after { return IdentityChange::Unchanged; }
    if before.trim().is_empty() || after.trim().is_empty() {
        return IdentityChange::Incomparable { before: before.into(), after: after.into(), first_blocker: "identity-empty".into() };
    }
    if before.starts_with("sha256:") || after.starts_with("sha256:") {
        return IdentityChange::Incomparable { before: before.into(), after: after.into(), first_blocker: "identity-nonorderable-digest".into() };
    }
    match crate::atoms::ask::package_ceiling::compare_debian_versions(before, after, std::time::Duration::from_secs(12)) {
        Ok(result) => match result.order {
            crate::atoms::ask::package_ceiling::DebianVersionOrder::Less | crate::atoms::ask::package_ceiling::DebianVersionOrder::Greater => IdentityChange::Ordered { before: before.into(), after: after.into() },
            crate::atoms::ask::package_ceiling::DebianVersionOrder::Equal => IdentityChange::Unchanged,
        },
        Err(_) => IdentityChange::Incomparable { before: before.into(), after: after.into(), first_blocker: "identity-version-order-unavailable".into() },
    }
}


#[cfg(test)]
mod package_ceiling_tests {
    use super::*;
    #[test]
    fn package_ceiling_equal_identity_is_unchanged() { assert_eq!(identity_change("sha256:a", "sha256:a"), IdentityChange::Unchanged); }
    #[test]
    fn package_ceiling_distinct_debian_versions_are_ordered() { assert!(matches!(identity_change("1.0", "2.0"), IdentityChange::Ordered { .. })); }
    #[test]
    fn package_ceiling_unequal_digest_is_incomparable() { assert!(matches!(identity_change("sha256:a", "sha256:b"), IdentityChange::Incomparable { .. })); }
    #[test]
    fn package_ceiling_witness_preserves_unchanged_identity() { let w=CurrentnessWitness { before:Some("1".into()), after:Some("1".into()), state:"current".into() }; assert_eq!(w.before,w.after); assert_eq!(w.state,"current"); }
    #[test]
    fn package_ceiling_declared_receipt_fields_are_typed() { let c=DeclaredCeiling { package:"pkg".into(), desired:"1".into(), ceiling:"2".into() }; assert_eq!(c.package,"pkg"); assert_eq!(c.ceiling,"2"); }
}
