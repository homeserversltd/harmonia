//! Append-only, proof-gated known-good state for installed surfaces.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const DEFAULT_ROOT: &str = "/var/lib/harmonia/known-good";
const RUNG_SCHEMA: &str = "harmonia.known_good.rung.v1";
const RECEIPT_SCHEMA: &str = "harmonia.known_good.receipt.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct KnownGoodRung {
    pub schema: String,
    pub sequence: u64,
    pub identity: String,
    pub surface: String,
    pub installed_sha: String,
    pub syzygy_sha: Option<String>,
    pub syzygy_signal: String,
    #[serde(default)]
    pub stamp_verdict: Option<String>,
    #[serde(default)]
    pub stamp_sha: Option<String>,
    #[serde(default = "default_stamp_signal")]
    pub stamp_signal: String,
    pub installed_version: Option<String>,
    pub proof_time_unix_ms: u128,
    pub proof_battery: Vec<String>,
    pub aggregate_receipt_ref: String,
    pub prior_rung_identity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct KnownGoodReceipt {
    pub schema: String,
    pub rung_identity: Option<String>,
    pub prior_rung_identity: Option<String>,
    pub pointer_moved: bool,
    pub pointer_state: String,
    pub proof_battery: Vec<String>,
    pub blocker: Option<String>,
    pub converged: bool,
    pub installed_sha: Option<String>,
    pub installed_version: Option<String>,
    pub aggregate_receipt_ref: String,
}

#[derive(Debug, Clone)]
pub(crate) struct KnownGoodPointerMovement {
    /// The pointer identity observed before this run's first move.
    pub from: Option<String>,
    /// The last rung identity moved to by this run.
    pub to: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct KnownGoodPointerRestore {
    pub surface: String,
    /// Pointer identity observed immediately before the rollback attempt.
    pub from: Option<String>,
    /// Run-start identity; null means the pointer was absent at run start.
    pub to: Option<String>,
    pub from_observation: String,
    pub restored: bool,
    pub blocker: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct InstalledStateProof {
    surface: String,
    installed_path: String,
    installed_sha: String,
    syzygy_sha: Option<String>,
    syzygy_signal: String,
    stamp_verdict: Option<String>,
    stamp_sha: Option<String>,
    stamp_signal: String,
    installed_version: Option<String>,
    proof_time_unix_ms: u128,
    proof_battery: Vec<String>,
    aggregate_receipt_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AggregateProofReceipt {
    schema: String,
    surface: String,
    installed_path: String,
    installed_sha: String,
    installed_version: Option<String>,
    proof_time_unix_ms: u128,
    proof_battery: Vec<String>,
    converged: bool,
    boundary: String,
    reference: String,
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn default_stamp_signal() -> String {
    "none".into()
}

fn committed_transaction_evidence(
    receipt_boundary: &Path,
) -> (
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    String,
) {
    let mut directory = Some(receipt_boundary);
    while let Some(dir) = directory {
        let path = dir.join("update-set.json");
        if let Ok(bytes) = fs::read(&path) {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                let sha = value.get("syzygy_sha").and_then(|v| v.as_str()).map(str::to_owned);
                let signal = value
                    .get("syzygy_signal")
                    .and_then(|v| v.as_str())
                    .unwrap_or(if sha.is_some() { "none" } else { "syzygy-sha-unresolved" })
                    .to_owned();
                let stamp_verdict = value
                    .get("stamp_verdict")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned);
                let stamp_sha = value
                    .get("stamp_sha")
                    .and_then(|value| value.as_str())
                    .filter(|sha| valid_lower_hex(sha, 64))
                    .map(str::to_owned);
                let stamp_signal = value
                    .get("stamp_signal")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned)
                    .unwrap_or_else(default_stamp_signal);
                return (sha, signal, stamp_verdict, stamp_sha, stamp_signal);
            }
        }
        directory = dir.parent();
    }
    (
        None,
        "syzygy-transaction-receipt-unresolved".into(),
        None,
        None,
        default_stamp_signal(),
    )
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_surface(surface: &str) -> bool {
    !surface.is_empty()
        && surface.len() <= 200
        && surface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
        && !surface.contains("..")
}

fn surface_dir(root: &Path, surface: &str) -> Result<PathBuf, String> {
    if !valid_surface(surface) {
        return Err("known-good-surface-invalid".into());
    }
    Ok(root.join("surfaces").join(
        surface
            .bytes()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    ))
}

pub(crate) fn sha256_file(path: &Path) -> Result<String, String> {
    let metadata = fs::metadata(path).map_err(|e| format!("installed-state-read-failed: {e}"))?;
    if !metadata.is_file() {
        return Err("installed-state-not-regular-file".into());
    }
    let mut file = File::open(path).map_err(|e| format!("installed-state-read-failed: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| format!("installed-state-read-failed: {e}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Stable, collision-free ledger surface for an installed path.
pub(crate) fn installed_surface(identity: &str, installed_path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(installed_path.to_string_lossy().as_bytes());
    format!("module/{identity}/binary/{:x}", hasher.finalize())
}

/// Mint an immutable aggregate proof receipt before returning the proof witness.
pub(crate) fn prove_installed_state(
    surface: &str,
    installed_path: &Path,
    expected_sha: Option<&str>,
    installed_version: Option<&str>,
    proof_battery: Vec<String>,
    converged: bool,
    receipt_boundary: &Path,
) -> Result<InstalledStateProof, String> {
    if !valid_surface(surface) {
        return Err("known-good-surface-invalid".into());
    }
    if !converged {
        return Err("known-good-proof-not-converged".into());
    }
    if proof_battery.is_empty() || proof_battery.iter().any(String::is_empty) {
        return Err("known-good-proof-battery-incomplete".into());
    }
    if receipt_boundary.as_os_str().is_empty() {
        return Err("known-good-aggregate-reference-missing".into());
    }
    let observed_sha = sha256_file(installed_path)?;
    if let Some(expected) = expected_sha {
        if expected != observed_sha {
            return Err(format!(
                "known-good-installed-sha-mismatch expected={expected} observed={observed_sha}"
            ));
        }
    }
    fs::create_dir_all(receipt_boundary).map_err(|e| e.to_string())?;
    let proof_time_unix_ms = now_ms();
    let (syzygy_sha, syzygy_signal, stamp_verdict, stamp_sha, stamp_signal) =
        committed_transaction_evidence(receipt_boundary);
    let reference = installed_path.to_string_lossy().into_owned();
    let aggregate = AggregateProofReceipt {
        schema: "harmonia.known_good.aggregate_proof.v1".into(),
        surface: surface.into(),
        installed_path: reference.clone(),
        installed_sha: observed_sha.clone(),
        installed_version: installed_version.map(str::to_owned),
        proof_time_unix_ms,
        proof_battery: proof_battery.clone(),
        converged: true,
        boundary: receipt_boundary.to_string_lossy().into_owned(),
        reference: reference.clone(),
    };
    let mut aggregate_receipt_ref = None;
    for suffix in 0..1000u32 {
        let name = if suffix == 0 {
            format!("proof-aggregate-{proof_time_unix_ms}-{}.json", observed_sha)
        } else {
            format!(
                "proof-aggregate-{proof_time_unix_ms}-{}-{suffix}.json",
                observed_sha
            )
        };
        let path = receipt_boundary.join(name);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let bytes = serde_json::to_vec_pretty(&aggregate).map_err(|e| e.to_string())?;
                file.write_all(&bytes).map_err(|e| e.to_string())?;
                file.write_all(b"\n").map_err(|e| e.to_string())?;
                file.sync_all().map_err(|e| e.to_string())?;
                aggregate_receipt_ref = Some(path.to_string_lossy().into_owned());
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    let aggregate_receipt_ref =
        aggregate_receipt_ref.ok_or("known-good-aggregate-receipt-name-exhausted")?;
    Ok(InstalledStateProof {
        surface: surface.into(),
        installed_path: reference,
        installed_sha: observed_sha,
        syzygy_sha,
        syzygy_signal,
        stamp_verdict,
        stamp_sha,
        stamp_signal,
        installed_version: installed_version.map(str::to_owned),
        proof_time_unix_ms,
        proof_battery,
        aggregate_receipt_ref,
    })
}

#[cfg(test)]
pub(crate) fn integration_root(receipt_dir: &Path) -> PathBuf {
    receipt_dir.join("known-good")
}
#[cfg(all(not(test), feature = "test-facade"))]
pub(crate) fn integration_root(_receipt_dir: &Path) -> PathBuf {
    std::env::var_os("HARMONIA_TEST_KNOWN_GOOD_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(default_root)
}
#[cfg(all(not(test), not(feature = "test-facade")))]
pub(crate) fn integration_root(_receipt_dir: &Path) -> PathBuf {
    default_root()
}
pub(crate) fn default_root() -> PathBuf {
    PathBuf::from(DEFAULT_ROOT)
}
fn current_path(dir: &Path) -> PathBuf {
    dir.join("current")
}
fn rung_path(dir: &Path, identity: &str) -> PathBuf {
    dir.join("rungs").join(format!("{identity}.json"))
}

fn read_rung(dir: &Path, identity: &str) -> Result<KnownGoodRung, String> {
    if identity.is_empty()
        || !identity
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("known-good-rung-identity-invalid".into());
    }
    let rung: KnownGoodRung =
        serde_json::from_slice(&fs::read(rung_path(dir, identity)).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if rung.schema != RUNG_SCHEMA || rung.identity != identity {
        return Err("known-good-rung-schema-invalid".into());
    }
    Ok(rung)
}

fn read_current_inner(root: &Path, surface: &str) -> Result<Option<KnownGoodRung>, String> {
    let dir = surface_dir(root, surface)?;
    let pointer = match fs::read_to_string(current_path(&dir)) {
        Ok(v) => v.trim().to_owned(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let rung = read_rung(&dir, &pointer)?;
    if rung.surface != surface {
        return Err("known-good-current-surface-mismatch".into());
    }
    if let Some(prior_identity) = rung.prior_rung_identity.as_deref() {
        let prior = read_rung(&dir, prior_identity)?;
        if prior.surface != surface || prior.sequence + 1 != rung.sequence {
            return Err("known-good-prior-pointer-invalid".into());
        }
    } else if rung.sequence != 1 {
        return Err("known-good-prior-pointer-missing".into());
    }
    Ok(Some(rung))
}
pub(crate) fn read_current(root: &Path, surface: &str) -> Result<Option<KnownGoodRung>, String> {
    read_current_inner(root, surface)
}

pub(crate) fn read_prior(root: &Path, surface: &str) -> Result<Option<KnownGoodRung>, String> {
    let Some(current) = read_current_inner(root, surface)? else {
        return Ok(None);
    };
    let Some(identity) = current.prior_rung_identity.as_deref() else {
        return Ok(None);
    };
    let dir = surface_dir(root, surface)?;
    let prior = read_rung(&dir, identity)?;
    if prior.surface != surface || prior.sequence + 1 != current.sequence {
        return Err("known-good-prior-pointer-invalid".into());
    }
    Ok(Some(prior))
}

pub(crate) fn read_history(root: &Path, surface: &str) -> Result<Vec<KnownGoodRung>, String> {
    let dir = surface_dir(root, surface)?;
    let entries = match fs::read_dir(dir.join("rungs")) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let mut history = Vec::new();
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().and_then(|v| v.to_str()) == Some("json") {
            let identity = path
                .file_stem()
                .and_then(|v| v.to_str())
                .ok_or("known-good-rung-filename-invalid")?;
            let rung = read_rung(&dir, identity)?;
            if rung.surface != surface {
                return Err("known-good-history-surface-mismatch".into());
            }
            history.push(rung);
        }
    }
    history.sort_by_key(|r| r.sequence);
    for (index, rung) in history.iter().enumerate() {
        if rung.sequence != index as u64 + 1 {
            return Err("known-good-history-sequence-invalid".into());
        }
        if index == 0 {
            if rung.prior_rung_identity.is_some() {
                return Err("known-good-history-root-invalid".into());
            }
        } else if rung.prior_rung_identity.as_deref() != Some(history[index - 1].identity.as_str())
        {
            return Err("known-good-history-chain-invalid".into());
        }
    }
    if let Some(current) = read_current_inner(root, surface)? {
        if !history.iter().any(|r| r.identity == current.identity) {
            return Err("known-good-current-not-history".into());
        }
    }
    Ok(history)
}

pub(crate) fn refusal_receipt(
    root: &Path,
    surface: &str,
    installed_sha: Option<&str>,
    installed_version: Option<&str>,
    proof_battery: Vec<String>,
    blocker: &str,
    converged: bool,
    aggregate_receipt_ref: &str,
) -> Result<KnownGoodReceipt, String> {
    let current = read_current_inner(root, surface)?;
    Ok(KnownGoodReceipt {
        schema: RECEIPT_SCHEMA.into(),
        rung_identity: None,
        prior_rung_identity: current.map(|r| r.identity),
        pointer_moved: false,
        pointer_state: "still".into(),
        proof_battery,
        blocker: Some(blocker.into()),
        converged,
        installed_sha: installed_sha.map(str::to_owned),
        installed_version: installed_version.map(str::to_owned),
        aggregate_receipt_ref: aggregate_receipt_ref.into(),
    })
}

fn validate_aggregate_proof(proof: &InstalledStateProof) -> Result<(), String> {
    let path = Path::new(&proof.aggregate_receipt_ref);
    let receipt: AggregateProofReceipt = serde_json::from_slice(
        &fs::read(path).map_err(|e| format!("known-good-aggregate-receipt-read-failed: {e}"))?,
    )
    .map_err(|e| format!("known-good-aggregate-receipt-invalid: {e}"))?;
    if receipt.schema != "harmonia.known_good.aggregate_proof.v1"
        || receipt.surface != proof.surface
        || receipt.installed_path != proof.installed_path
        || receipt.installed_sha != proof.installed_sha
        || receipt.installed_version != proof.installed_version
        || receipt.proof_time_unix_ms != proof.proof_time_unix_ms
        || receipt.proof_battery != proof.proof_battery
        || !receipt.converged
        || receipt.reference != proof.installed_path
        || !Path::new(&receipt.boundary).is_dir()
    {
        return Err("known-good-aggregate-receipt-mismatch".into());
    }
    Ok(())
}

pub(crate) fn append_and_move(
    root: &Path,
    proof: InstalledStateProof,
) -> Result<KnownGoodReceipt, String> {
    validate_aggregate_proof(&proof)?;
    // The aggregate proof is not the final authority: the installed path may
    // have changed after it was hashed. Re-read it at the proof-to-pointer
    // boundary so a stale proof cannot advance `current`.
    let current_installed_sha = sha256_file(Path::new(&proof.installed_path))?;
    if current_installed_sha != proof.installed_sha {
        return Err(format!(
            "known-good-installed-state-changed-before-pointer expected={} observed={}",
            proof.installed_sha, current_installed_sha
        ));
    }
    let dir = surface_dir(root, &proof.surface)?;
    fs::create_dir_all(dir.join("rungs")).map_err(|e| e.to_string())?;
    let current = read_current_inner(root, &proof.surface)?;
    let history = read_history(root, &proof.surface)?;
    let tail = history.last();
    let tail_is_current = tail.is_some_and(|tail| {
        current.as_ref().map(|rung| rung.identity.as_str()) == Some(tail.identity.as_str())
    });
    if let Some(tail) = tail.filter(|_| !tail_is_current) {
        // A restored pointer may precede the immutable history tail by several
        // rungs after one run moved this surface more than once. read_history
        // has already established a single contiguous prior-rung chain, so a
        // current rung before the tail or an absent pointer is a valid rollback
        // gap, not a branch. Any new rung below must still extend that tail.
        let current_identity = current.as_ref().map(|rung| rung.identity.as_str());
        let tail_follows_current = match current_identity {
            Some(identity) => history
                .iter()
                .position(|rung| rung.identity.as_str() == identity)
                .is_some_and(|index| index + 1 < history.len()),
            None => true,
        };
        if !tail_follows_current {
            return Err("known-good-unpromoted-tail-conflict".into());
        }
        if current.as_ref().is_some_and(|rung| {
            rung.installed_sha == proof.installed_sha
                && rung.installed_version == proof.installed_version
        }) {
            return Ok(KnownGoodReceipt {
                schema: RECEIPT_SCHEMA.into(),
                rung_identity: current.as_ref().map(|rung| rung.identity.clone()),
                prior_rung_identity: current
                    .as_ref()
                    .and_then(|rung| rung.prior_rung_identity.clone()),
                pointer_moved: false,
                pointer_state: "already-current".into(),
                proof_battery: proof.proof_battery,
                blocker: None,
                converged: true,
                installed_sha: Some(proof.installed_sha),
                installed_version: proof.installed_version,
                aggregate_receipt_ref: proof.aggregate_receipt_ref,
            });
        }
        let same_proof = tail.installed_sha == proof.installed_sha
            && tail.syzygy_sha == proof.syzygy_sha
            && tail.syzygy_signal == proof.syzygy_signal
            && tail.installed_version == proof.installed_version
            && tail.proof_battery == proof.proof_battery
            && tail.aggregate_receipt_ref == proof.aggregate_receipt_ref;
        if same_proof {
            let temp_path = dir.join(format!(".current-retry.{}.tmp", tail.sequence));
            let mut temp = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
                .map_err(|e| e.to_string())?;
            temp.write_all(format!("{}\n", tail.identity).as_bytes())
                .map_err(|e| e.to_string())?;
            temp.sync_all().map_err(|e| e.to_string())?;
            if let Err(e) = fs::rename(&temp_path, current_path(&dir)) {
                let _ = fs::remove_file(&temp_path);
                return Err(e.to_string());
            }
            return move_pointer(&dir, tail, proof.proof_battery, proof.aggregate_receipt_ref);
        }
    } else if let Some(current) = current.as_ref() {
        if current.installed_sha == proof.installed_sha
            && current.installed_version == proof.installed_version
        {
            return Ok(KnownGoodReceipt {
                schema: RECEIPT_SCHEMA.into(),
                rung_identity: Some(current.identity.clone()),
                prior_rung_identity: current.prior_rung_identity.clone(),
                pointer_moved: false,
                pointer_state: "already-current".into(),
                proof_battery: proof.proof_battery,
                blocker: None,
                converged: true,
                installed_sha: Some(proof.installed_sha),
                installed_version: proof.installed_version,
                aggregate_receipt_ref: proof.aggregate_receipt_ref,
            });
        }
    }
    let prior = history.last().map(|rung| rung.identity.clone());
    let sequence = history.last().map_or(1, |r| r.sequence + 1);
    let identity = format!("rung-{sequence}-{}", proof.installed_sha);
    let rung = KnownGoodRung {
        schema: RUNG_SCHEMA.into(),
        sequence,
        identity: identity.clone(),
        surface: proof.surface.clone(),
        installed_sha: proof.installed_sha.clone(),
        syzygy_sha: proof.syzygy_sha.clone(),
        syzygy_signal: proof.syzygy_signal.clone(),
        stamp_verdict: proof.stamp_verdict.clone(),
        stamp_sha: proof.stamp_sha.clone(),
        stamp_signal: proof.stamp_signal.clone(),
        installed_version: proof.installed_version.clone(),
        proof_time_unix_ms: proof.proof_time_unix_ms,
        proof_battery: proof.proof_battery.clone(),
        aggregate_receipt_ref: proof.aggregate_receipt_ref.clone(),
        prior_rung_identity: prior.clone(),
    };
    let mut rung_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(rung_path(&dir, &identity))
        .map_err(|e| e.to_string())?;
    rung_file
        .write_all(&serde_json::to_vec_pretty(&rung).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    rung_file.sync_all().map_err(|e| e.to_string())?;
    let temp_path = dir.join(format!(
        ".current.{sequence}.{}.tmp",
        proof.proof_time_unix_ms
    ));
    let mut temp = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|e| e.to_string())?;
    temp.write_all(identity.as_bytes())
        .map_err(|e| e.to_string())?;
    temp.write_all(b"\n").map_err(|e| e.to_string())?;
    temp.sync_all().map_err(|e| e.to_string())?;
    if let Err(e) = fs::rename(&temp_path, current_path(&dir)) {
        let _ = fs::remove_file(&temp_path);
        return Err(e.to_string());
    }
    move_pointer(
        &dir,
        &rung,
        proof.proof_battery,
        proof.aggregate_receipt_ref,
    )
}

/// The caller supplies the last rung this run moved to and the run-start
/// identity (or `None` when no pointer existed); a changed pointer is never
/// overwritten speculatively.
pub(crate) fn restore_run_pointer(
    root: &Path,
    surface: &str,
    expected_current: &str,
    restore_to: Option<&str>,
) -> KnownGoodPointerRestore {
    let mut restore = KnownGoodPointerRestore {
        surface: surface.to_owned(),
        from: None,
        to: restore_to.map(str::to_owned),
        from_observation: "failed".into(),
        restored: false,
        blocker: None,
    };
    let dir = match surface_dir(root, surface) {
        Ok(dir) => dir,
        Err(error) => {
            restore.blocker = Some(format!("known-good-pointer-rollback-surface-invalid: {error}"));
            return restore;
        }
    };
    match read_current_inner(root, surface) {
        Ok(Some(rung)) => {
            restore.from = Some(rung.identity);
            restore.from_observation = "present".into();
        }
        Ok(None) => restore.from_observation = "absent".into(),
        Err(error) => {
            restore.blocker = Some(format!("known-good-pointer-rollback-current-read-failed: {error}"));
            return restore;
        }
    }
    if restore.from.as_deref() != Some(expected_current) {
        restore.blocker = Some(format!(
            "known-good-pointer-rollback-from-mismatch expected={expected_current} observed={}",
            restore.from.as_deref().unwrap_or("absent")
        ));
        return restore;
    }
    if let Some(identity) = restore_to {
        match read_rung(&dir, identity) {
            Ok(rung) if rung.surface == surface => {}
            Ok(_) => {
                restore.blocker = Some("known-good-pointer-rollback-target-surface-mismatch".into());
                return restore;
            }
            Err(error) => {
                restore.blocker = Some(format!("known-good-pointer-rollback-target-read-failed: {error}"));
                return restore;
            }
        }
    }

    let pointer = current_path(&dir);
    let mut blockers = Vec::new();
    let mutation = if let Some(identity) = restore_to {
        let temp_path = dir.join(format!(
            ".current-rollback.{}.{}.tmp",
            std::process::id(),
            now_ms()
        ));
        (|| -> Result<(), String> {
            let mut temp = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
                .map_err(|error| format!("known-good-pointer-rollback-temp-create-failed: {error}"))?;
            temp.write_all(format!("{identity}\n").as_bytes())
                .map_err(|error| format!("known-good-pointer-rollback-write-failed: {error}"))?;
            temp.sync_all()
                .map_err(|error| format!("known-good-pointer-rollback-file-fsync-failed: {error}"))?;
            drop(temp);
            fs::rename(&temp_path, &pointer)
                .map_err(|error| format!("known-good-pointer-rollback-rename-failed: {error}"))
        })()
    } else {
        fs::remove_file(&pointer)
            .map_err(|error| format!("known-good-pointer-rollback-remove-failed: {error}"))
    };
    if let Err(error) = mutation {
        blockers.push(error);
    }
    if let Err(error) = File::open(&dir).and_then(|directory| directory.sync_all()) {
        blockers.push(format!("known-good-pointer-rollback-fsync-failed: {error}"));
    }
    match read_current_inner(root, surface) {
        Ok(Some(rung)) if restore_to == Some(rung.identity.as_str()) => {}
        Ok(None) if restore_to.is_none() => {}
        Ok(Some(rung)) => blockers.push(format!(
            "known-good-pointer-rollback-readback-mismatch expected={} observed={}",
            restore_to.unwrap_or("absent"),
            rung.identity
        )),
        Ok(None) => blockers.push(format!(
            "known-good-pointer-rollback-readback-mismatch expected={} observed=absent",
            restore_to.unwrap_or("absent")
        )),
        Err(error) => blockers.push(format!("known-good-pointer-rollback-readback-failed: {error}")),
    }
    if !blockers.is_empty() {
        restore.blocker = Some(blockers.join("; "));
    }
    restore.restored = restore.blocker.is_none();
    restore
}

fn move_pointer(
    dir: &Path,
    rung: &KnownGoodRung,
    proof_battery: Vec<String>,
    aggregate_receipt_ref: String,
) -> Result<KnownGoodReceipt, String> {
    let readback = match fs::read_to_string(current_path(dir)) {
        Ok(value) if value.trim() == rung.identity => None,
        Ok(_) => Some("known-good-pointer-readback-mismatch".to_string()),
        Err(e) => Some(format!("known-good-pointer-readback-failed: {e}")),
    };
    let sync_error = File::open(dir)
        .and_then(|d| d.sync_all())
        .err()
        .map(|e| format!("known-good-pointer-fsync-failed: {e}"));
    let blocker = readback.or(sync_error);
    Ok(KnownGoodReceipt {
        schema: RECEIPT_SCHEMA.into(),
        rung_identity: Some(rung.identity.clone()),
        prior_rung_identity: rung.prior_rung_identity.clone(),
        pointer_moved: true,
        pointer_state: "moved".into(),
        proof_battery,
        blocker: blocker.clone(),
        converged: blocker.is_none(),
        installed_sha: Some(rung.installed_sha.clone()),
        installed_version: rung.installed_version.clone(),
        aggregate_receipt_ref,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn battery() -> Vec<String> {
        vec![
            "proof-explain".into(),
            "fresh-installed-sha256-readback".into(),
        ]
    }

    #[test]
    fn schema_roundtrip_and_append_only_history() {
        let root = tempfile::tempdir().unwrap();
        let installed = root.path().join("installed");
        fs::write(&installed, b"first").unwrap();
        fs::write(
            root.path().join("update-set.json"),
            serde_json::json!({
                "syzygy_sha": "syzygy-committed-sha",
                "syzygy_signal": "committed"
            })
            .to_string(),
        )
        .unwrap();
        let proof = prove_installed_state(
            "engine",
            &installed,
            None,
            Some("v1"),
            battery(),
            true,
            root.path(),
        )
        .unwrap();
        let first = append_and_move(root.path(), proof).unwrap();
        let rung = read_current(root.path(), "engine").unwrap().unwrap();
        let encoded = serde_json::to_string(&rung).unwrap();
        assert_eq!(
            serde_json::from_str::<KnownGoodRung>(&encoded).unwrap(),
            rung
        );
        assert_eq!(rung.installed_sha, sha256_file(&installed).unwrap());
        assert_eq!(rung.syzygy_sha.as_deref(), Some("syzygy-committed-sha"));
        assert_eq!(rung.syzygy_signal, "committed");
        let encoded_value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(encoded_value["syzygy_sha"], "syzygy-committed-sha");
        assert_eq!(encoded_value["syzygy_signal"], "committed");
        assert_eq!(first.pointer_state, "moved");
        assert_eq!(read_history(root.path(), "engine").unwrap().len(), 1);

        fs::write(&installed, b"second").unwrap();
        let proof = prove_installed_state(
            "engine",
            &installed,
            None,
            Some("v2"),
            battery(),
            true,
            root.path(),
        )
        .unwrap();
        append_and_move(root.path(), proof).unwrap();
        let history = read_history(root.path(), "engine").unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(
            history[1].prior_rung_identity.as_deref(),
            Some(history[0].identity.as_str())
        );
    }

    #[test]
    fn duplicate_current_does_not_append() {
        let root = tempfile::tempdir().unwrap();
        let installed = root.path().join("installed");
        fs::write(&installed, b"same").unwrap();
        let proof = prove_installed_state(
            "engine",
            &installed,
            None,
            Some("v1"),
            battery(),
            true,
            root.path(),
        )
        .unwrap();
        append_and_move(root.path(), proof).unwrap();
        let rung = read_current(root.path(), "engine").unwrap().unwrap();
        let encoded = serde_json::to_value(&rung).unwrap();
        assert_eq!(encoded["syzygy_sha"], serde_json::Value::Null);
        assert_eq!(
            rung.syzygy_signal,
            "syzygy-transaction-receipt-unresolved"
        );
        let proof = prove_installed_state(
            "engine",
            &installed,
            None,
            Some("v1"),
            battery(),
            true,
            root.path(),
        )
        .unwrap();
        let receipt = append_and_move(root.path(), proof).unwrap();
        assert_eq!(receipt.pointer_state, "already-current");
        assert!(!receipt.pointer_moved);
        assert_eq!(read_history(root.path(), "engine").unwrap().len(), 1);
    }

    #[test]
    fn interrupted_pointer_retry_promotes_exact_tail_and_refuses_branch() {
        let root = tempfile::tempdir().unwrap();
        let installed = root.path().join("installed");
        fs::write(&installed, b"tail").unwrap();
        let proof = prove_installed_state(
            "engine",
            &installed,
            None,
            Some("v1"),
            battery(),
            true,
            root.path(),
        )
        .unwrap();
        let retry_proof = proof.clone();
        let first = append_and_move(root.path(), proof).unwrap();
        let dir = surface_dir(root.path(), "engine").unwrap();
        fs::remove_file(current_path(&dir)).unwrap();
        // A different proof must be refused while the appended tail is still
        // unpromoted; only the exact retry may move current.
        let different = prove_installed_state(
            "engine",
            &installed,
            None,
            Some("v2"),
            battery(),
            true,
            root.path(),
        )
        .unwrap();
        let refused = append_and_move(root.path(), different).unwrap_err();
        assert_eq!(refused, "known-good-unpromoted-tail-conflict");
        let retry = retry_proof;
        let recovered = append_and_move(root.path(), retry).unwrap();
        assert_eq!(recovered.pointer_state, "moved");
        assert!(recovered.pointer_moved && recovered.converged);
        assert_eq!(read_history(root.path(), "engine").unwrap().len(), 1);
        let v2 = prove_installed_state(
            "engine",
            &installed,
            None,
            Some("v2"),
            battery(),
            true,
            root.path(),
        )
        .unwrap();
        let promoted = append_and_move(root.path(), v2).unwrap();
        assert_eq!(promoted.pointer_state, "moved");
        assert_eq!(read_history(root.path(), "engine").unwrap().len(), 2);
        println!(
            "{}",
            serde_json::json!({"schema":"harmonia.known_good.promotion_trace.v1","refusal":refused,"retry":recovered,"promotion":promoted})
        );
        let _ = first;
    }

    #[test]
    fn failed_proof_preserves_seeded_current_and_renders_refusal() {
        let root = tempfile::tempdir().unwrap();
        let installed = root.path().join("installed");
        fs::write(&installed, b"good").unwrap();
        let proof = prove_installed_state(
            "engine",
            &installed,
            None,
            Some("v1"),
            battery(),
            true,
            root.path(),
        )
        .unwrap();
        append_and_move(root.path(), proof).unwrap();
        let before = read_current(root.path(), "engine").unwrap().unwrap();
        let history_before = read_history(root.path(), "engine").unwrap();
        let expected = before.installed_sha.clone();
        fs::write(&installed, b"corrupt").unwrap();
        assert!(prove_installed_state(
            "engine",
            &installed,
            Some(&expected),
            Some("v1"),
            battery(),
            true,
            root.path()
        )
        .is_err());
        let refusal = refusal_receipt(
            root.path(),
            "engine",
            None,
            Some("v1"),
            battery(),
            "installed-sha-mismatch",
            false,
            &root.path().to_string_lossy(),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_str::<KnownGoodReceipt>(&serde_json::to_string(&refusal).unwrap())
                .unwrap(),
            refusal
        );
        assert!(!refusal.pointer_moved);
        assert_eq!(refusal.pointer_state, "still");
        assert_eq!(
            read_current(root.path(), "engine").unwrap().unwrap(),
            before
        );
        assert_eq!(read_history(root.path(), "engine").unwrap(), history_before);
        println!("{}", serde_json::to_string(&refusal).unwrap());
    }
}
