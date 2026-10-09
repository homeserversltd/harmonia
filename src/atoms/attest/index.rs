//! One-call receipt custody: redact, serialize locally, then forward the same redacted value.
#![allow(dead_code)]
#[path = "change_unit.rs"]
pub(crate) mod change_unit;
#[path = "build_crate.rs"]
pub(crate) mod build_crate;
#[path = "fetch_artifact.rs"]
pub(crate) mod fetch_artifact;
#[path = "build_venv.rs"]
pub(crate) mod build_venv;
#[path = "hermes_maintenance.rs"]
pub(crate) mod hermes_maintenance;
#[path = "check_health.rs"]
pub(crate) mod check_health;
#[path = "copy_file.rs"]
pub(crate) mod copy_file;
#[path = "config_plane.rs"]
pub(crate) mod config_plane;
#[path = "convergence-receipts.rs"]
pub(crate) mod convergence_receipts;
#[path = "pull_repo.rs"]
pub(crate) mod pull_repo;
#[path = "hyalos.rs"]
pub(crate) mod hyalos;
pub(crate) use config_plane::{
    ConfigPlaneCategory, ConfigPlaneDisposition, ConfigPlaneWitness, CONFIG_PLANE_WITNESS_SCHEMA,
};
#[path = "install_package.rs"]
pub(crate) mod install_package;
#[path = "make_dir.rs"]
pub(crate) mod make_dir;
#[path = "make_link.rs"]
pub(crate) mod make_link;
#[path = "remove_dir.rs"]
pub(crate) mod remove_dir;
#[path = "remove_file.rs"]
pub(crate) mod remove_file;
#[path = "rename.rs"]
pub(crate) mod rename;
#[path = "build_aur_pinned.rs"]
pub(crate) mod build_aur_pinned;
#[path = "install_aur.rs"]
pub(crate) mod install_aur;
#[path = "install_aur_pinned.rs"]
pub(crate) mod install_aur_pinned;
#[path = "run_command.rs"]
pub(crate) mod run_command;
#[path = "replace_process.rs"]
pub(crate) mod replace_process;
#[path = "set_clock.rs"]
pub(crate) mod set_clock;
#[path = "write_file.rs"]
pub(crate) mod write_file;
use super::Receipt;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use sha2::{Digest, Sha256};

static JSON_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static PROPOSAL_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct StalePreimage {
    path: std::path::PathBuf,
    bytes: Vec<u8>,
    mode: u32,
    uid: u32,
    gid: u32,
}


/// Attestation-owned no-follow read handle for source observation.
#[cfg(unix)]
pub(crate) fn open_nofollow_read(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| error.to_string())
}

/// Test fixture permission helper owned by the attestation filesystem seam.
pub(crate) fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        return fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| error.to_string());
    }
    #[cfg(not(unix))]
    { let _ = (path, mode); Ok(()) }
}


#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SyzygyMint {
    pub(crate) caduceus_sha: String,
    pub(crate) partner_sha: String,
    pub(crate) keyman_sha: Option<String>,
    pub(crate) gui_sha: Option<String>,
    pub(crate) syzygy_sha: Option<String>,
    pub(crate) env_sha: String,
    pub(crate) signal: String,
}

impl SyzygyMint {
    fn failed(signal: String) -> Self {
        Self {
            caduceus_sha: String::new(),
            partner_sha: String::new(),
            keyman_sha: None,
            gui_sha: None,
            syzygy_sha: None,
            env_sha: String::new(),
            signal,
        }
    }
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Raw member observations accompany the typed mint without becoming its identity.
#[derive(Debug, Clone)]
pub(crate) struct SyzygyEvidence {
    pub(crate) mint: SyzygyMint,
    pub(crate) member_flags: serde_json::Value,
    pub(crate) observations: serde_json::Value,
    pub(crate) stamp_verdict: Option<String>,
    pub(crate) stamp_sha: Option<String>,
    pub(crate) stamp_signal: String,
}

impl SyzygyEvidence {
    pub(crate) fn matched_stamp_sha(&self) -> Option<&str> {
        if self.stamp_verdict.as_deref() == Some("VALID") && self.stamp_signal == "none" {
            self.stamp_sha
                .as_deref()
                .filter(|sha| valid_lower_hex(sha, 64))
        } else {
            None
        }
    }
}

impl std::ops::Deref for SyzygyEvidence {
    type Target = SyzygyMint;
    fn deref(&self) -> &Self::Target { &self.mint }
}

fn committed_beam(dir: &Path) -> Result<serde_json::Value, String> {
    let bytes = fs::read(dir.join("beam.json")).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            "syzygy-beam-receipt-absent".to_string()
        } else {
            "syzygy-beam-receipt-malformed".to_string()
        }
    })?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| "syzygy-beam-receipt-malformed".to_string())?;
    if value.get("schema").and_then(serde_json::Value::as_str) != Some("harmonia.beam-compare.v1") {
        return Err("syzygy-beam-receipt-malformed".into());
    }
    Ok(value)
}

fn committed_routine_source_sha(
    dir: &Path,
    receipt: &crate::atoms::r#do::transaction::TransactionReceipt,
    member: &str,
    tools: &[&str],
    output_name: &str,
) -> Option<String> {
    let modules = receipt.member_modules.get(member)?;
    let mut observed = BTreeSet::new();
    for module in modules {
        let mut components = Path::new(module).components();
        if !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
        {
            return None;
        }
        let module_dir = dir.join("modules").join(module);
        let routines = fs::read_dir(&module_dir).ok()?;
        for routine in routines {
            let routine = routine.ok()?;
            if !routine.file_type().ok()?.is_dir() {
                continue;
            }
            let children = fs::read_dir(routine.path()).ok()?;
            for child in children {
                let child = child.ok()?;
                if !child.file_type().ok()?.is_dir() {
                    continue;
                }
                let path = child.path().join("routine-child.json");
                let bytes = match fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(_) => return None,
                };
                let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
                if value.get("schema").and_then(serde_json::Value::as_str)
                    != Some("harmonia.routine.child-receipt.v1")
                    || value.get("state").and_then(serde_json::Value::as_str) != Some("completed")
                    || value.get("ok").and_then(serde_json::Value::as_bool) != Some(true)
                    || !value
                        .get("tool")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|tool| tools.contains(&tool))
                {
                    continue;
                }
                if let Some(source_sha) = value
                    .pointer(&format!("/outputs/{output_name}"))
                    .and_then(serde_json::Value::as_str)
                    .filter(|sha| valid_lower_hex(sha, 40))
                {
                    observed.insert(source_sha.to_owned());
                }
            }
        }
    }
    if observed.len() == 1 {
        observed.into_iter().next()
    } else {
        None
    }
}

/// Resolve each available member independently, then mint only from a complete
/// known-good set. Stamp comparisons use this run's committed source receipts,
/// never a latest remote flag as the member's worn identity.
pub(crate) fn committed_syzygy_mint(
    dir: &Path,
    receipt: &crate::atoms::r#do::transaction::TransactionReceipt,
) -> SyzygyEvidence {
    committed_syzygy_mint_with_sudoers(dir, receipt, &BTreeMap::new(), &[])
}

pub(crate) fn committed_syzygy_mint_with_sudoers(
    dir: &Path,
    receipt: &crate::atoms::r#do::transaction::TransactionReceipt,
    declared_fragments: &BTreeMap<String, Vec<String>>,
    committed_targets: &[crate::atoms::r#do::transaction::Target],
) -> SyzygyEvidence {
    use serde_json::{json, Value};
    let mut evidence = SyzygyEvidence {
        mint: SyzygyMint::failed("none".into()),
        member_flags: json!({}),
        observations: json!({}),
        stamp_verdict: None,
        stamp_sha: None,
        stamp_signal: "wukong-staff-stamp-not-observed".into(),
    };
    for child in &receipt.children {
        evidence.member_flags[&child.member] = json!(format!("syzygy-flag-absent {}", child.member));
    }
    if receipt.state != crate::atoms::r#do::transaction::TransactionState::Committed {
        evidence.mint.signal = "syzygy-transaction-not-committed".into();
        return evidence;
    }
    let seats = crate::atoms::ask::mint_seats::at_start();
    evidence.observations["schema_seats"] = json!({
        "estate.release-flag.v1": seats.release_flag.as_ref().err().map(String::as_str).unwrap_or("loaded"),
        "harmonia.update-set.v1": seats.update_set.as_ref().err().map(String::as_str).unwrap_or("loaded")
    });
    let mut signals = Vec::<String>::new();
    if let Some(signal) = seats.signal() { signals.push(signal.to_owned()); }
    let members = receipt.children.iter().map(|child| child.member.as_str()).collect::<BTreeSet<_>>();
    evidence.member_flags["harmonia"] = json!({"source_sha": receipt.source_head});
    match committed_beam(dir) {
        Ok(beam) => {
            evidence.observations["caduceus"] = beam.clone();
            for (name, length) in [("caduceus_sha", 40), ("env_sha", 64)] {
                match beam.get("lock").and_then(|lock| lock.get(name)) {
                    None | Some(Value::Null) => signals.push(format!("syzygy-beam-{name}-absent")),
                    Some(value) => match value.as_str() {
                        Some(sha) if valid_lower_hex(sha, length) => {
                            if name == "caduceus_sha" { evidence.mint.caduceus_sha = sha.to_owned(); }
                            else { evidence.mint.env_sha = sha.to_owned(); }
                        }
                        _ => signals.push(format!("syzygy-beam-{name}-invalid")),
                    }
                }
            }
            if !evidence.mint.caduceus_sha.is_empty() {
                evidence.member_flags["caduceus"] = json!({
                    "source_sha": evidence.mint.caduceus_sha,
                    "flagged_at": beam.pointer("/resolved_from/flagged_at"),
                    "malformed_flags": beam.get("malformed_flags").and_then(Value::as_u64).unwrap_or(0)
                });
            } else {
                evidence.member_flags["caduceus"] = json!(signals.last());
            }
            // Preserve the selected public release flag independently of the
            // beam-worn SHA so consumers can use its rustc_version watermark.
            if members.contains("caduceus") {
                if let Ok(seat) = &seats.release_flag {
                    let observed = crate::atoms::ask::member_flag::resolve_component("caduceus", seat);
                    evidence.observations["caduceus_release_flag"] = observed.evidence();
                    if observed.signal == "none" {
                        if let Some(flag) = observed.selected {
                            if !evidence.member_flags["caduceus"].is_object() {
                                evidence.member_flags["caduceus"] = json!({
                                    "source_sha": if evidence.mint.caduceus_sha.is_empty() { Value::Null } else { json!(evidence.mint.caduceus_sha) },
                                    "flagged_at": Value::Null,
                                    "malformed_flags": observed.malformed_flags
                                });
                            }
                            evidence.member_flags["caduceus"]["release_flag"] = flag;
                        }
                    }
                }
            }
        }
        Err(signal) => {
            evidence.member_flags["caduceus"] = json!(signal);
            signals.push(signal);
        }
    }
    if !members.contains("caduceus") { signals.push("syzygy-caduceus-member-missing".into()); }
    if members.contains("sbin") {
        match &seats.release_flag {
            Ok(seat) => {
                let observed = crate::atoms::ask::member_flag::resolve_sbin(seat);
                evidence.observations["sbin"] = observed.evidence();
                if observed.signal == "none" {
                    if let Some(flag) = &observed.selected {
                        evidence.mint.partner_sha = flag.get("source_sha").and_then(Value::as_str).unwrap_or_default().to_owned();
                        evidence.member_flags["sbin"] = json!({
                            "source_sha": evidence.mint.partner_sha,
                            "flagged_at": flag.get("flagged_at"),
                            "malformed_flags": observed.malformed_flags,
                            "release_flag": flag
                        });
                    }
                } else {
                    evidence.member_flags["sbin"] = json!(observed.signal);
                    signals.push(observed.signal);
                }
            }
            Err(signal) => {
                evidence.member_flags["sbin"] = json!(signal);
            }
        }
    } else {
        signals.push("syzygy-required-partner-missing".into());
    }
    // Hyprland is a package, not a repository vertex. Every other declared
    // GUI member resolves its own repository flag on the known-good axis.
    if receipt.gui.as_deref() != Some("Hyprland") {
        let gui_member = receipt.gui_member.as_deref().or(match receipt.gui.as_deref() {
            Some("Arcadia") => Some("arcadia"),
            Some("Coronatio") => Some("coronatio"),
            _ => None,
        });
        if let Some(member) = gui_member {
            let component = if member.eq_ignore_ascii_case("arcadia") {
                "arcadia"
            } else if member.eq_ignore_ascii_case("coronatio") {
                "coronatio"
            } else {
                member
            };
            match &seats.release_flag {
                Ok(seat) => {
                    let observed =
                        crate::atoms::ask::member_flag::resolve_component(component, seat);
                    evidence.observations[member] = observed.evidence();
                    if observed.signal == "none" {
                        if let Some(flag) = &observed.selected {
                            evidence.mint.gui_sha = Some(
                                flag.get("source_sha")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                            );
                            evidence.member_flags[member] = json!({
                                "source_sha": evidence.mint.gui_sha,
                                "flagged_at": flag.get("flagged_at"),
                                "malformed_flags": observed.malformed_flags,
                                "release_flag": flag
                            });
                        }
                    } else {
                        evidence.member_flags[member] = json!(observed.signal);
                        signals.push(observed.signal);
                    }
                }
                Err(signal) => {
                    evidence.member_flags[member] = json!(signal);
                }
            }
        }
    }
    if members.contains("keyman") {
        match &seats.release_flag {
            Ok(seat) => {
                let observed = crate::atoms::ask::member_flag::resolve_component("keyman", seat);
                evidence.observations["keyman"] = observed.evidence();
                if observed.signal == "none" {
                    if let Some(flag) = &observed.selected {
                        evidence.mint.keyman_sha = Some(
                            flag.get("source_sha")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_owned(),
                        );
                        evidence.member_flags["keyman"] = json!({
                            "source_sha": evidence.mint.keyman_sha,
                            "flagged_at": flag.get("flagged_at"),
                            "malformed_flags": observed.malformed_flags,
                            "release_flag": flag
                        });
                    } else {
                        let signal = "syzygy-flag-absent keyman";
                        evidence.member_flags["keyman"] = json!(signal);
                        signals.push(signal.into());
                    }
                } else {
                    evidence.member_flags["keyman"] = json!(observed.signal);
                    signals.push(observed.signal);
                }
            }
            Err(seat_signal) => {
                let signal = format!("syzygy-flag-unresolvable keyman ({seat_signal})");
                evidence.member_flags["keyman"] = json!(signal);
                signals.push(signal);
            }
        }
    }
    if members.contains("sudoers") {
        let mut fragments = declared_fragments
            .values()
            .flat_map(|names| names.iter().cloned())
            .collect::<Vec<_>>();
        fragments.sort();
        fragments.dedup();
        if !receipt.member_modules.contains_key("sudoers") {
            let signal = "sudoers-module-absent";
            evidence.member_flags["sudoers"] = json!(signal);
        } else if fragments.is_empty() {
            let signal = "sudoers-fragments-absent";
            evidence.member_flags["sudoers"] = json!(signal);
        } else {
            let mut digest = Sha256::new();
            let mut failure = None;
            for name in &fragments {
                let target = committed_targets.iter().find(|target| {
                    target.member == "sudoers"
                        && target.path.parent() == Some(Path::new("/etc/sudoers.d"))
                        && target.path.file_name().and_then(|value| value.to_str())
                            == Some(name.as_str())
                });
                let Some(target) = target else {
                    failure = Some(format!("sudoers-fragment-target-absent {name}"));
                    break;
                };
                let bytes = match fs::read(&target.path) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        failure = Some(format!("sudoers-fragment-target-unreadable {name}"));
                        break;
                    }
                };
                digest.update(name.as_bytes());
                digest.update([0]);
                digest.update(&bytes);
                digest.update([0]);
            }
            if let Some(signal) = failure {
                evidence.member_flags["sudoers"] = json!(signal);
            } else {
                evidence.member_flags["sudoers"] = json!({
                    "source_sha": receipt.source_head,
                    "pinned_by": receipt.source_head,
                    "fragments": fragments,
                    "fragments_sha256": format!("{:x}", digest.finalize())
                });
            }
        }
    }
    if signals.is_empty() {
        match crate::atoms::r#do::transaction::compute_syzygy_sha(
            &evidence.mint.caduceus_sha,
            &evidence.mint.partner_sha,
            evidence.mint.gui_sha.as_deref(),
            evidence.mint.keyman_sha.as_deref(),
        ) {
            Ok(sha) => evidence.mint.syzygy_sha = Some(sha),
            Err(signal) => signals.push(signal),
        }
    }
    evidence.mint.signal = signals.first().cloned().unwrap_or_else(|| "none".into());
    evidence.observations["signals"] = json!(signals);
    let stamp = crate::atoms::ask::collective_stamp::current();
    evidence.stamp_verdict = stamp.verdict.clone();
    evidence.stamp_sha = if stamp.verdict.as_deref() == Some("VALID") {
        stamp
            .stamp_sha
            .as_deref()
            .filter(|sha| valid_lower_hex(sha, 64))
            .map(str::to_owned)
    } else {
        None
    };
    evidence.stamp_signal = stamp.signal.clone();
    evidence.observations["wukong_staff_stamp"] = stamp.as_json();
    if stamp.verdict.as_deref() == Some("VALID") {
        let mut actual_sources = serde_json::Map::new();
        let mut first_stamp_signal = None;
        for member in &stamp.declared_members {
            let (actual_sha, provenance) = match member.as_str() {
                // The committed beam is the worn Caduceus proof; the resolver's
                // selected release flag is only the desired source watermark.
                "caduceus" => (
                    (!evidence.mint.caduceus_sha.is_empty())
                        .then(|| evidence.mint.caduceus_sha.clone()),
                    "beam.lock.caduceus_sha",
                ),
                "harmonia" => (
                    valid_lower_hex(&receipt.source_head, 40)
                        .then(|| receipt.source_head.clone()),
                    "transaction.source_head",
                ),
                "sbin" => (
                    committed_routine_source_sha(
                        dir,
                        receipt,
                        member,
                        &["pull-repo"],
                        "resolved_commit",
                    ),
                    "routine-child.outputs.resolved_commit",
                ),
                "coronatio" | "arcadia" => (
                    committed_routine_source_sha(
                        dir,
                        receipt,
                        member,
                        &["fetch-artifact", "build-crate", "build"],
                        "source_build_sha",
                    ),
                    "routine-child.outputs.source_build_sha",
                ),
                _ => (None, "unsupported-member"),
            };
            let expected_sha = stamp.target(member);
            let matches = actual_sha
                .as_deref()
                .zip(expected_sha)
                .map(|(actual, expected)| actual == expected);
            actual_sources.insert(
                member.clone(),
                json!({
                    "source_sha": actual_sha,
                    "stamp_sha": expected_sha,
                    "matches": matches,
                    "provenance": provenance,
                }),
            );
            match (actual_sha.as_deref(), expected_sha) {
                (Some(actual), Some(expected)) if actual == expected => {}
                (Some(_), _) => {
                    first_stamp_signal
                        .get_or_insert_with(|| format!("wukong-staff-unstamped {member}"));
                }
                (None, _) => {
                    first_stamp_signal.get_or_insert_with(|| {
                        format!("wukong-staff-committed-source-unavailable {member}")
                    });
                }
            }
        }
        evidence.observations["wukong_staff_member_sources"] = Value::Object(actual_sources);
        evidence.stamp_signal = first_stamp_signal.unwrap_or_else(|| "none".into());
    }
    // Validate before any consumer can persist the mint. A desync refuses the
    // digest, never the already committed module transaction or its receipt.
    let value = transaction_value(receipt, &evidence, None);
    if let Ok(seat) = &seats.update_set {
        if let Err(signal) = seat.validate(&value) {
            evidence.mint.syzygy_sha = None;
            evidence.mint.signal = signal.clone();
            evidence.observations["update_set_seat"] = json!(signal);
        }
    }
    evidence
}

fn transaction_value(
    receipt: &crate::atoms::r#do::transaction::TransactionReceipt,
    evidence: &SyzygyEvidence,
    failed_step: Option<&str>,
) -> serde_json::Value {
    use serde_json::{json, Value};
    let mut enriched = receipt.clone();
    enriched.syzygy_sha = evidence.mint.syzygy_sha.clone();
    enriched.syzygy_signal = evidence.mint.signal.clone();
    let mut value = crate::atoms::r#do::transaction::project_update_set_v1(&enriched);
    value["event"] = json!("new-artifact");
    value["held_back_by"] = json!([]);
    value["member_flags"] = evidence.member_flags.clone();
    value["member_flag_observations"] = evidence.observations.clone();
    value["stamp_verdict"] = evidence
        .stamp_verdict
        .clone()
        .map(Value::String)
        .unwrap_or(Value::Null);
    value["stamp_sha"] = evidence
        .stamp_sha
        .clone()
        .map(Value::String)
        .unwrap_or(Value::Null);
    value["stamp_signal"] = json!(evidence.stamp_signal);
    value["wukong_staff_stamp"] = evidence
        .observations
        .get("wukong_staff_stamp")
        .cloned()
        .unwrap_or(Value::Null);
    value["wukong_staff_member_sources"] = evidence
        .observations
        .get("wukong_staff_member_sources")
        .cloned()
        .unwrap_or(Value::Null);
    if let Some(members) = value.get_mut("members").and_then(Value::as_array_mut) {
        for member in members {
            let source = member.get("member").and_then(Value::as_str)
                .and_then(|name| {
                    evidence.member_flags.get(name).and_then(|flag| flag.get("source_sha"))
                        .or_else(|| evidence.observations.get(name)
                            .and_then(|observed| observed.pointer("/selected/source_sha")))
                }).cloned().unwrap_or(Value::Null);
            member["source_sha"] = source;
        }
    }
    if let Some(step) = failed_step { value["failed_step"] = json!(step); }
    value
}

pub(crate) fn augment_run_json_with_stamp(
    dir: &Path,
    evidence: &SyzygyEvidence,
) -> Result<(), String> {
    let path = dir.join("run.json");
    let bytes = fs::read(&path).map_err(|error| {
        format!(
            "transaction-run-json-read-failed {}: {error}",
            path.display()
        )
    })?;
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "transaction-run-json-parse-failed {}: {error}",
            path.display()
        )
    })?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| format!("transaction-run-json-not-object {}", path.display()))?;
    object.insert(
        "stamp_verdict".into(),
        evidence
            .stamp_verdict
            .clone()
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null),
    );
    object.insert(
        "stamp_sha".into(),
        evidence
            .stamp_sha
            .clone()
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null),
    );
    object.insert(
        "stamp_signal".into(),
        serde_json::Value::String(evidence.stamp_signal.clone()),
    );
    object.insert(
        "wukong_staff_stamp".into(),
        evidence
            .observations
            .get("wukong_staff_stamp")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    );
    object.insert(
        "wukong_staff_member_sources".into(),
        evidence
            .observations
            .get("wukong_staff_member_sources")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    );
    object.insert(
        "syzygy_sha".into(),
        evidence
            .mint
            .syzygy_sha
            .clone()
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null),
    );
    object.insert(
        "syzygy_signal".into(),
        serde_json::Value::String(evidence.mint.signal.clone()),
    );
    write_json_atomic(&path, &value)
}

pub(crate) fn write_transaction_receipt(
    dir: &Path,
    receipt: &crate::atoms::r#do::transaction::TransactionReceipt,
    evidence: &SyzygyEvidence,
    failed_step: Option<&str>,
) -> Result<(), String> {
    let value = transaction_value(receipt, evidence, failed_step);
    write_json_atomic(&dir.join("update-set.json"), &value)
}

pub(crate) fn write_transaction_rollback_receipt(
    dir: &Path,
    receipt: &crate::atoms::r#do::transaction::TransactionReceipt,
    evidence: &SyzygyEvidence,
    failed_step: Option<&str>,
    restored_paths: &[String],
    pointer_restores: &[crate::known_good_ledger::KnownGoodPointerRestore],
    rollback_errors: &[String],
) -> Result<(), String> {
    let mut value = transaction_value(receipt, evidence, failed_step);
    value["transaction_state"] = serde_json::to_value(&receipt.state)
        .map_err(|error| format!("transaction-state-serialize-failed: {error}"))?;
    value["restored_paths"] = serde_json::json!(restored_paths);
    value["known_good_pointer_restores"] = serde_json::json!(pointer_restores);
    value["rollback_errors"] = serde_json::json!(rollback_errors);
    write_json_atomic(&dir.join("update-set.json"), &value)
}

#[cfg(test)]
mod syzygy_mint_tests {
    use super::*;
    use std::{collections::BTreeMap, fs, path::Path};

    fn transaction(state: crate::atoms::r#do::transaction::TransactionState) -> crate::atoms::r#do::transaction::TransactionReceipt {
        crate::atoms::r#do::transaction::TransactionReceipt {
            schema: "harmonia.transaction.v1",
            state,
            profile_id: "test".into(),
            profile_identity: "test".into(),
            source_head: "test".into(),
            gui: None,
            gui_member: None,
            syzygy_sha: None,
            syzygy_signal: "none".into(),
            member_modules: BTreeMap::new(),
            children: Vec::new(),
            target_count: 0,
            service_count: 0,
            caduceus_count: 0,
        }
    }

    #[test]
    fn non_committed_transaction_preserves_failure_signal() {
        let receipt = transaction(crate::atoms::r#do::transaction::TransactionState::Open);
        let mint = committed_syzygy_mint(Path::new("/does/not/exist"), &receipt);
        assert_eq!(mint.caduceus_sha, "");
        assert_eq!(mint.partner_sha, "");
        assert_eq!(mint.gui_sha, None);
        assert_eq!(mint.syzygy_sha, None);
        assert_eq!(mint.env_sha, "");
        assert_eq!(mint.signal, "syzygy-transaction-not-committed");
    }

    #[test]
    fn committed_mint_carries_env_sha_from_current_beam_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let env_sha = "b".repeat(64);
        fs::write(
            dir.path().join("beam.json"),
            serde_json::json!({
                "schema": "harmonia.beam-compare.v1",
                "state": "aligned",
                "converged": true,
                "lock": {"caduceus_sha": "a".repeat(40), "env_sha": env_sha},
                "lock_source": "literal",
                "door": null,
                "first_divergent_member": null,
                "first_missing_signal": "none",
                "authorization": "none"
            })
            .to_string(),
        )
        .unwrap();
        let mut receipt = transaction(crate::atoms::r#do::transaction::TransactionState::Committed);
        // No sbin child: this beam-provenance test must not query the forge.
        receipt.member_modules = BTreeMap::from([
            ("caduceus".into(), vec!["module-caduceus".into()]),
        ]);
        receipt.children = vec![
            crate::atoms::r#do::transaction::ProjectionChild {
                ordinal: 0,
                member: "caduceus".into(),
                target_indices: Vec::new(),
                service_indices: Vec::new(),
                source_sha: None,
            },
        ];

        let mint = committed_syzygy_mint(dir.path(), &receipt);
        assert_eq!(mint.env_sha, "b".repeat(64));
        assert_eq!(mint.caduceus_sha, "a".repeat(40));
        assert_eq!(mint.member_flags["caduceus"]["source_sha"], "a".repeat(40));
        assert_eq!(mint.syzygy_sha, None);
        let seats = crate::atoms::ask::mint_seats::at_start();
        assert_eq!(mint.signal, seats.signal().unwrap_or("syzygy-required-partner-missing"));
        let mut signals = seats.signal().into_iter().collect::<Vec<_>>();
        signals.push("syzygy-required-partner-missing");
        assert_eq!(mint.observations["signals"], serde_json::json!(signals));
    }

    #[test]
    fn missing_or_malformed_beam_evidence_fails_the_mint() {
        let dir = tempfile::tempdir().unwrap();
        let receipt = transaction(crate::atoms::r#do::transaction::TransactionState::Committed);
        let seats = crate::atoms::ask::mint_seats::at_start();
        let assert_failed = |mint: &SyzygyEvidence, beam_signal: &str| {
            assert_eq!(mint.signal, seats.signal().unwrap_or(beam_signal));
            assert_eq!(mint.syzygy_sha, None);
            let mut signals = seats.signal().into_iter().collect::<Vec<_>>();
            signals.extend([
                beam_signal,
                "syzygy-caduceus-member-missing",
                "syzygy-required-partner-missing",
            ]);
            assert_eq!(mint.observations["signals"], serde_json::json!(signals));
        };
        let mint = committed_syzygy_mint(dir.path(), &receipt);
        assert_failed(&mint, "syzygy-beam-receipt-absent");
        assert_eq!(mint.member_flags["caduceus"], "syzygy-beam-receipt-absent");
        assert_eq!(mint.env_sha, "");

        fs::write(dir.path().join("beam.json"), "{}").unwrap();
        let mint = committed_syzygy_mint(dir.path(), &receipt);
        assert_failed(&mint, "syzygy-beam-receipt-malformed");
        assert_eq!(mint.member_flags["caduceus"], "syzygy-beam-receipt-malformed");
        assert_eq!(mint.env_sha, "");

        fs::write(
            dir.path().join("beam.json"),
            serde_json::json!({
                "schema": "harmonia.beam-compare.v1",
                "lock": {"caduceus_sha": "a".repeat(40), "env_sha": "A".repeat(64)}
            })
            .to_string(),
        )
        .unwrap();
        let mint = committed_syzygy_mint(dir.path(), &receipt);
        assert_failed(&mint, "syzygy-beam-env_sha-invalid");
        assert_eq!(mint.caduceus_sha, "a".repeat(40));
        assert_eq!(mint.env_sha, "");
    }
}

/// Persist a JSON receipt through the attest durability membrane.
fn is_backup_path(path: &Path) -> bool {
    path.components().any(|c| c.as_os_str() == "backups")
}

fn make_receipt_tree_readable(path: &Path) -> Result<(), String> {
    let root = Path::new("/var/lib/harmonia/receipts");
    let Ok(relative) = path.strip_prefix(root) else {
        return Ok(());
    };
    if is_backup_path(relative) {
        return Ok(());
    }
    let mut current = root.to_path_buf();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&current, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("receipt-directory-mode-failed {}: {e}", current.display()))?;
        for component in relative.components() {
            current.push(component);
            fs::set_permissions(&current, fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("receipt-directory-mode-failed {}: {e}", current.display()))?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ProposalOwnerPolicy {
    CurrentProcess,
}

#[cfg(unix)]
fn proposal_owner(policy: ProposalOwnerPolicy) -> (u32, u32) {
    match policy {
        ProposalOwnerPolicy::CurrentProcess => {
            (unsafe { libc::geteuid() }, unsafe { libc::getegid() })
        }
    }
}

#[cfg(not(unix))]
fn proposal_owner(_policy: ProposalOwnerPolicy) -> (u32, u32) {
    (0, 0)
}

fn proposal_target_kind(path: &Path) -> Result<Option<std::fs::Metadata>, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "proposal-projection-observe-failed {}: {error}",
            path.display()
        )),
    }
}

fn verify_proposal_owner(path: &Path, policy: ProposalOwnerPolicy) -> Result<(), String> {
    let metadata = fs::metadata(path).map_err(|error| {
        format!(
            "proposal-projection-owner-observe-failed {}: {error}",
            path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let (uid, gid) = proposal_owner(policy);
        if (metadata.uid(), metadata.gid()) != (uid, gid) {
            return Err(format!(
                "proposal-projection-owner-mismatch {} expected_uid={} expected_gid={} actual_uid={} actual_gid={}",
                path.display(),
                uid,
                gid,
                metadata.uid(),
                metadata.gid()
            ));
        }
    }
    Ok(())
}

fn capture_stale_preimage(
    path: &Path,
    policy: ProposalOwnerPolicy,
) -> Result<StalePreimage, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.file_type().is_file() {
        return Err(format!("proposal-projection-collision {}", path.display()));
    }
    verify_proposal_owner(path, policy)?;
    if metadata.permissions().mode() & 0o7777 != 0o644 {
        return Err(format!(
            "proposal-projection-mode-mismatch {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        return Ok(StalePreimage {
            path: path.to_path_buf(),
            bytes: fs::read(path).map_err(|e| e.to_string())?,
            mode: metadata.mode() & 0o7777,
            uid: metadata.uid(),
            gid: metadata.gid(),
        });
    }
    #[cfg(not(unix))]
    Ok(StalePreimage {
        path: path.to_path_buf(),
        bytes: fs::read(path).map_err(|e| e.to_string())?,
        mode: 0o644,
        uid: 0,
        gid: 0,
    })
}

fn write_proposal_bytes(
    path: &Path,
    bytes: &[u8],
    policy: ProposalOwnerPolicy,
) -> Result<bool, String> {
    let observed = proposal_target_kind(path)?;
    if let Some(metadata) = &observed {
        if !metadata.file_type().is_file() {
            return Err(format!("proposal-projection-collision {}", path.display()));
        }
        verify_proposal_owner(path, policy)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o7777 != 0o644 {
                return Err(format!(
                    "proposal-projection-mode-mismatch {}",
                    path.display()
                ));
            }
        }
        if fs::read(path).map_err(|error| error.to_string())? == bytes {
            return Ok(false);
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("proposal-projection-parent-missing {}", path.display()))?;
    prepare_receipt_parent(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("proposal-projection-name-invalid {}", path.display()))?;
    let sequence = PROPOSAL_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(
        ".{name}.harmonia-attest-projection-{}-{sequence}",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|error| {
            format!(
                "proposal-projection-temp-create-failed {}: {error}",
                temp.display()
            )
        })?;
    let result = (|| -> Result<(), String> {
        file.write_all(bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        drop(file);
        #[cfg(unix)]
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o644))
            .map_err(|error| error.to_string())?;
        fs::rename(&temp, path).map_err(|error| error.to_string())?;
        verify_proposal_owner(path, policy)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map(|()| true)
}

pub(crate) fn refresh_proposal_projection(
    feed_path: &Path,
    feed_bytes: &[u8],
    records: &[(String, Vec<u8>)],
    policy: ProposalOwnerPolicy,
) -> Result<usize, String> {
    with_proposal_projection_lock(feed_path, || {
        refresh_proposal_projection_locked(feed_path, feed_bytes, records, policy)
    })
}

pub(crate) fn with_proposal_projection_lock<T, F>(
    feed_path: &Path,
    operation: F,
) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String>,
{
    let parent = feed_path
        .parent()
        .ok_or_else(|| format!("proposal-projection-parent-missing {}", feed_path.display()))?;
    prepare_receipt_parent(parent)?;
    let name = feed_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("proposal-projection-name-invalid {}", feed_path.display()))?;
    let lock_path = parent.join(format!(".{name}.lock"));
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|error| {
            format!(
                "proposal-projection-lock-open-failed {}: {error}",
                lock_path.display()
            )
        })?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == -1 {
        return Err(format!(
            "proposal-projection-lock-acquire-failed {}: {}",
            lock_path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let result = operation();
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) } == -1 {
        return Err(format!(
            "proposal-projection-lock-release-failed {}: {}",
            lock_path.display(),
            std::io::Error::last_os_error()
        ));
    }
    result
}

pub(crate) fn refresh_proposal_projection_locked(
    feed_path: &Path,
    feed_bytes: &[u8],
    records: &[(String, Vec<u8>)],
    policy: ProposalOwnerPolicy,
) -> Result<usize, String> {
    let parent = feed_path
        .parent()
        .ok_or_else(|| format!("proposal-projection-parent-missing {}", feed_path.display()))?;
    prepare_receipt_parent(parent)?;
    let proposal_root = parent.join("proposals");
    if let Some(metadata) = proposal_target_kind(&proposal_root)? {
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(format!(
                "proposal-projection-collision {}",
                proposal_root.display()
            ));
        }
    }
    if let Some(metadata) = proposal_target_kind(feed_path)? {
        if !metadata.file_type().is_file() {
            return Err(format!(
                "proposal-projection-collision {}",
                feed_path.display()
            ));
        }
    }
    prepare_receipt_parent(&proposal_root)?;
    let live = records
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut stale = Vec::new();
    for path in fs::read_dir(&proposal_root)
        .map_err(|error| error.to_string())?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?
    {
        let Some(metadata) = proposal_target_kind(&path)? else {
            continue;
        };
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        if name.starts_with("config-proposal-") && name.ends_with(".json") && !live.contains(name) {
            if !metadata.file_type().is_file() {
                return Err(format!("proposal-projection-collision {}", path.display()));
            }
            verify_proposal_owner(&path, policy)?;
            #[cfg(unix)]
            if metadata.permissions().mode() & 0o7777 != 0o644 {
                return Err(format!(
                    "proposal-projection-mode-mismatch {}",
                    path.display()
                ));
            }
            stale.push(capture_stale_preimage(&path, policy)?);
        }
    }
    let mut writes = write_proposal_bytes(feed_path, feed_bytes, policy)? as usize;
    for (name, bytes) in records {
        writes += write_proposal_bytes(&proposal_root.join(name), bytes, policy)? as usize;
    }
    let mut removed: Vec<&StalePreimage> = Vec::new();
    for preimage in &stale {
        if let Err(error) = fs::remove_file(&preimage.path) {
            let mut message = format!(
                "proposal-stale-remove-failed {}: {error}",
                preimage.path.display()
            );
            for prior in removed.iter().rev() {
                if let Err(restore) = restore_stale_preimage(prior) {
                    message.push_str(&format!(
                        "; proposal-stale-restore-failed {}: {restore}",
                        prior.path.display()
                    ));
                }
            }
            return Err(message);
        }
        removed.push(preimage);
        writes += 1;
    }
    Ok(writes)
}

#[cfg(unix)]
fn restore_stale_preimage(preimage: &StalePreimage) -> Result<(), String> {
    use std::os::unix::fs::{chown, PermissionsExt};
    let parent = preimage
        .path
        .parent()
        .ok_or_else(|| "proposal-stale-restore-parent-missing".to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&preimage.path)
        .map_err(|e| e.to_string())?;
    file.write_all(&preimage.bytes).map_err(|e| e.to_string())?;
    file.set_permissions(fs::Permissions::from_mode(preimage.mode))
        .map_err(|e| e.to_string())?;
    chown(&preimage.path, Some(preimage.uid), Some(preimage.gid)).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    File::open(parent)
        .and_then(|d| d.sync_all())
        .map_err(|e| e.to_string())
}

/// Atomically converge a receipt file to exact bytes, without touching an equal file.
pub(crate) fn write_receipt_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<bool, String> {
    let target = match fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(format!(
                "receipt-observe-failed {}: {error}",
                path.display()
            ))
        }
    };
    let strict_receipt = !is_backup_path(path);
    if let Some(metadata) = &target {
        if !metadata.file_type().is_file() {
            return Err(format!("receipt-collision {}", path.display()));
        }
        if strict_receipt {
            verify_receipt_owner(path)?;
            #[cfg(unix)]
            if metadata.permissions().mode() & 0o7777 != 0o644 {
                return Err(format!("receipt-mode-mismatch {}", path.display()));
            }
        }
        if fs::read(path)
            .map_err(|error| format!("receipt-read-failed {}: {error}", path.display()))?
            == bytes
        {
            return Ok(false);
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("receipt-parent-missing {}", path.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("receipt-name-invalid {}", path.display()))?;
    prepare_receipt_parent(parent)?;
    let sequence = JSON_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(
        ".{name}.harmonia-attest-{}-{sequence}.tmp",
        std::process::id()
    ));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|error| format!("receipt-temp-create-failed {}: {error}", temp.display()))?;
        file.write_all(bytes)
            .map_err(|error| format!("receipt-temp-write-failed {}: {error}", temp.display()))?;
        file.sync_all()
            .map_err(|error| format!("receipt-temp-sync-failed {}: {error}", temp.display()))?;
        drop(file);
        if strict_receipt {
            #[cfg(unix)]
            fs::set_permissions(&temp, fs::Permissions::from_mode(0o644))
                .map_err(|error| format!("receipt-temp-mode-failed {}: {error}", temp.display()))?;
            verify_receipt_owner(&temp)?;
        }
        fs::rename(&temp, path).map_err(|error| {
            format!(
                "receipt-atomic-promote-failed {} -> {}: {error}",
                temp.display(),
                path.display()
            )
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("receipt-parent-sync-failed {}: {error}", parent.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map(|()| true)
}

pub(crate) fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    write_receipt_bytes_atomic(path, bytes).map(|_| ())
}

pub(crate) fn write_json_atomic(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("receipt-serialize-failed {}: {error}", path.display()))?;
    bytes.push(b'\n');
    write_receipt_bytes_atomic(path, &bytes).map(|_| ())
}

fn verify_receipt_owner(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("receipt-owner-observe-failed {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let expected = proposal_owner(ProposalOwnerPolicy::CurrentProcess);
        if (metadata.uid(), metadata.gid()) != expected {
            return Err(format!("receipt-owner-mismatch {} expected_uid={} expected_gid={} actual_uid={} actual_gid={}", path.display(), expected.0, expected.1, metadata.uid(), metadata.gid()));
        }
    }
    Ok(())
}

pub(crate) fn prepare_receipt_parent(parent: &Path) -> Result<(), String> {
    fs::create_dir_all(parent)
        .map_err(|error| format!("receipt-parent-create-failed {}: {error}", parent.display()))?;
    make_receipt_tree_readable(parent)
}

pub(crate) fn create_receipt_file(path: &Path) -> Result<File, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("receipt-parent-missing {}", path.display()))?;
    prepare_receipt_parent(parent)?;
    let file = File::create(path)
        .map_err(|error| format!("receipt-file-create-failed {}: {error}", path.display()))?;
    set_receipt_file_mode(path)?;
    Ok(file)
}

#[cfg(unix)]
fn set_receipt_file_mode(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if !is_backup_path(path) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))
            .map_err(|error| format!("receipt-mode-failed {}: {error}", path.display()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_receipt_file_mode(_path: &Path) -> Result<(), String> {
    Ok(())
}

pub(crate) fn append_jsonl_to<W: Write>(
    writer: &mut W,
    value: &serde_json::Value,
) -> Result<(), String> {
    serde_json::to_writer(&mut *writer, value)
        .map_err(|error| format!("receipt-jsonl-serialize-failed: {error}"))?;
    writeln!(writer).map_err(|error| format!("receipt-jsonl-append-failed: {error}"))
}

pub(crate) fn remove_artifact(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("attest-artifact-remove-failed {}: {error}", path.display())),
    }
}

pub(crate) fn copy_artifact(source: &Path, target: &Path) -> Result<(), String> {
    let parent = target.parent().ok_or_else(|| format!("artifact-copy-parent-missing {}", target.display()))?;
    prepare_receipt_parent(parent)?;
    fs::copy(source, target).map_err(|error| format!("artifact-copy-failed {} -> {}: {error}", source.display(), target.display()))?;
    Ok(())
}

/// Open a named fresh event stream through the Attest owner (create/truncate semantics).
pub(crate) fn open_event_stream(path: &Path) -> Result<File, String> {
    let parent = path.parent().ok_or_else(|| format!("event-stream-parent-missing {}", path.display()))?;
    prepare_receipt_parent(parent)?;
    File::create(path).map_err(|error| format!("event-stream-open-failed {}: {error}", path.display()))
}

pub(crate) fn append_appliance_log(path: &Path, receipt: &Receipt) -> Result<(), String> {
    let value = serde_json::to_value(receipt).map_err(|e| format!("attest-serialize: {e}"))?;
    append_jsonl(path, &value).map_err(|e| format!("attest-append: {e}"))
}

pub(crate) fn append_jsonl(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("receipt-parent-missing {}", path.display()))?;
    prepare_receipt_parent(parent)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("receipt-jsonl-open-failed {}: {error}", path.display()))?;
    set_receipt_file_mode(path)?;
    append_jsonl_to(&mut file, value)
}

pub(crate) fn promote_current_link(
    latest_path: &Path,
    target: &Path,
    error_prefix: &str,
    reject_directory: bool,
) -> Result<(), String> {
    if latest_path.exists() {
        if latest_path.is_dir() && !latest_path.is_symlink() {
            if reject_directory {
                return Err(format!(
                    "{error_prefix}-still-directory {}",
                    latest_path.display()
                ));
            }
        } else {
            fs::remove_file(latest_path).map_err(|e| e.to_string())?;
        }
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, latest_path).map_err(|e| {
        format!(
            "{error_prefix}-symlink-failed {} -> {}: {e}",
            target.display(),
            latest_path.display()
        )
    })?;
    #[cfg(not(unix))]
    return Err(format!("{error_prefix}-symlink-unsupported"));
    Ok(())
}

pub(crate) fn redact_secrets(value: &str, secrets: &[String]) -> String {
    secrets.iter().fold(value.to_owned(), |out, secret| {
        if secret.is_empty() {
            out
        } else {
            out.replace(secret, "[REDACTED]")
        }
    })
}
fn redact_receipt(receipt: &Receipt, secrets: &[String]) -> Receipt {
    let mut redacted = receipt.clone();
    let redact = |value: &str| redact_secrets(value, secrets);
    redacted.atom = redact(&redacted.atom);
    redacted.message = redact(&redacted.message);
    redacted.drift = match redacted.drift {
        super::Drift::Current => super::Drift::Current,
        super::Drift::File {
            expected_sha256,
            actual_sha256,
        } => super::Drift::File {
            expected_sha256: redact(&expected_sha256),
            actual_sha256: actual_sha256.as_deref().map(redact),
        },
        super::Drift::Command {
            expected_code,
            actual_code,
        } => super::Drift::Command {
            expected_code,
            actual_code,
        },
        super::Drift::Unit { expected, actual } => super::Drift::Unit {
            expected: redact(&expected),
            actual: redact(&actual),
        },
        super::Drift::Http {
            expected_status,
            actual_status,
        } => super::Drift::Http {
            expected_status,
            actual_status,
        },
    };
    redacted
}
pub(crate) fn attest(
    log: &Path,
    receipt: &Receipt,
    declared_secrets: &[String],
) -> Result<(), String> {
    let redacted = redact_receipt(receipt, declared_secrets);
    append_appliance_log(log, &redacted)?;
    hyalos::forward_receipt(
        "harmonia.atom",
        &redacted.message,
        Some(serde_json::json!({"atom": redacted.atom, "drift": redacted.drift})),
        Some(redacted.ok),
            None,
);
    Ok(())
}

/// Attest a managed ConfigPlane file with typed, structural category and
/// disposition fields. The shared four-field Receipt remains unchanged.
pub(crate) fn attest_config_plane(
    log: &Path,
    receipt: &Receipt,
    declared_secrets: &[String],
    witness: &ConfigPlaneWitness,
) -> Result<(), String> {
    let witness_log = log
        .parent()
        .ok_or_else(|| "config-plane-witness-parent-missing".to_string())?
        .join("config-plane-witnesses.jsonl");
    let redacted = redact_receipt(receipt, declared_secrets);
    let mut redacted_witness = witness.clone();
    redacted_witness.path = redact_secrets(&redacted_witness.path, declared_secrets);
    redacted_witness.module_id = redact_secrets(&redacted_witness.module_id, declared_secrets);
    let witness_value = serde_json::to_value(&redacted_witness)
        .map_err(|error| format!("config-plane-witness-serialize: {error}"))?;
    let mut line =
        serde_json::to_value(&redacted).map_err(|error| format!("attest-serialize: {error}"))?;
    let line_fields = line
        .as_object_mut()
        .ok_or_else(|| "config-plane-attest-line-not-object".to_string())?;
    let witness_fields = witness_value
        .as_object()
        .ok_or_else(|| "config-plane-witness-not-object".to_string())?;
    line_fields.extend(witness_fields.clone());

    append_jsonl(log, &line)?;
    append_jsonl(&witness_log, &witness_value)?;

    let mut attributes = serde_json::json!({
        "atom": redacted.atom,
        "drift": redacted.drift,
    });
    if let (Some(attributes), Some(witness_fields)) =
        (attributes.as_object_mut(), witness_value.as_object())
    {
        attributes.extend(witness_fields.clone());
    }
    hyalos::forward_receipt(
        "harmonia.atom",
        &redacted.message,
        Some(attributes),
        Some(redacted.ok),
        None,
    );
    Ok(())
}
