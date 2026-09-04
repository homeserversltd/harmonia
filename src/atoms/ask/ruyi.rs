//! Local, engine-maintained Ruyi state.
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) const ROW_SCHEMA: &str = "caduceus.ruyi.v1";
const DEFAULT_RUYI_PATH: &str = "/etc/appliance/ruyi.json";
const RUYI_PATH_ENV: &str = "HARMONIA_RUYI_PATH";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct LastUpdate {
    pub run_id: String,
    pub converged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuyiRow {
    pub schema: String,
    pub mac: String,
    pub hostname: String,
    pub canonical_name: String,
    pub ipv4: String,
    pub profile: String,
    pub gui_face: Option<String>,
    pub caduceus_sha: String,
    pub env_sha: String,
    pub harmonia_sha: String,
    pub syzygy_sha: Option<String>,
    pub last_seen: u64,
    pub last_update: LastUpdate,
}

/// Resolve the local Ruyi state path. Tests may override it with
/// `HARMONIA_RUYI_PATH` without changing the production default.
pub(crate) fn ruyi_path() -> PathBuf {
    env::var_os(RUYI_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_RUYI_PATH))
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn valid_mac(value: &str) -> bool {
    let octets: Vec<_> = value.split(':').collect();
    octets.len() == 6
        && octets.iter().all(|octet| {
            octet.len() == 2
                && octet
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_run_id(value: &str) -> bool {
    value.strip_prefix("run-").is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

/// Validate the Ruyi row's schema, appliance identity, and exact digest shapes.
pub(crate) fn validate_row(row: &RuyiRow) -> Result<(), String> {
    if row.schema != ROW_SCHEMA {
        return Err("ruyi-schema-invalid".into());
    }
    if !valid_mac(&row.mac) {
        return Err("ruyi-mac-invalid".into());
    }
    if !valid_name(&row.hostname) {
        return Err("ruyi-hostname-invalid".into());
    }
    if row.canonical_name != format!("{}.home.arpa", row.hostname)
        || !valid_name(&row.canonical_name)
    {
        return Err("ruyi-canonical-name-invalid".into());
    }
    if row.ipv4.parse::<Ipv4Addr>().is_err() {
        return Err("ruyi-ipv4-invalid".into());
    }
    if !valid_name(&row.profile) {
        return Err("ruyi-profile-invalid".into());
    }
    if row
        .gui_face
        .as_deref()
        .is_some_and(|face| !matches!(face, "Hyprland" | "Arcadia" | "Coronatio"))
    {
        return Err("ruyi-gui-face-invalid".into());
    }
    if !valid_hex(&row.caduceus_sha, 40) {
        return Err("ruyi-caduceus-sha-invalid".into());
    }
    if !valid_hex(&row.env_sha, 64) {
        return Err("ruyi-env-sha-invalid".into());
    }
    if !valid_hex(&row.harmonia_sha, 40) {
        return Err("ruyi-harmonia-sha-invalid".into());
    }
    if row
        .syzygy_sha
        .as_deref()
        .is_some_and(|sha| !valid_hex(sha, 64))
    {
        return Err("ruyi-syzygy-sha-invalid".into());
    }
    if !valid_run_id(&row.last_update.run_id) {
        return Err("ruyi-last-update-run-id-invalid".into());
    }
    Ok(())
}

fn serialize_row(row: &RuyiRow) -> Result<Vec<u8>, String> {
    validate_row(row)?;
    serde_json::to_vec(row).map_err(|error| format!("ruyi-row-serialize-failed: {error}"))
}

/// Persist one validated local row through Projectio's private engine-state membrane.
pub(crate) fn write_row(row: &RuyiRow) -> Result<crate::atoms::projectio::Receipt, String> {
    let bytes = serialize_row(row)?;
    crate::atoms::projectio::write_engine_state(
        &ruyi_path(),
        &bytes,
        crate::atoms::projectio::engine_state_witness(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalIdentity {
    pub mac: String,
    pub hostname: String,
    pub ipv4: String,
}

fn mint_error(mint: &crate::atoms::attest::SyzygyMint) -> Option<String> {
    if mint.signal != "none" {
        return Some("ruyi-syzygy-mint-invalid".into());
    }
    if !valid_hex(&mint.caduceus_sha, 40) {
        return Some("ruyi-syzygy-mint-caduceus-invalid".into());
    }
    if !valid_hex(&mint.partner_sha, 40) {
        return Some("ruyi-syzygy-mint-partner-invalid".into());
    }
    if !valid_hex(&mint.env_sha, 64) {
        return Some("ruyi-syzygy-mint-env-invalid".into());
    }
    if mint
        .gui_sha
        .as_deref()
        .is_some_and(|sha| !valid_hex(sha, 40))
    {
        return Some("ruyi-syzygy-mint-gui-invalid".into());
    }
    if !mint
        .syzygy_sha
        .as_deref()
        .is_some_and(|sha| valid_hex(sha, 64))
    {
        return Some("ruyi-syzygy-mint-syzygy-invalid".into());
    }
    None
}

/// Observe the local appliance identity using only bounded, read-only probes.
pub(crate) fn local_identity() -> Result<LocalIdentity, String> {
    let hostname = fs::read_to_string("/etc/hostname")
        .map_err(|_| "ruyi-local-hostname-read-failed".to_string())?
        .trim()
        .to_ascii_lowercase();
    if !valid_name(&hostname) {
        return Err("ruyi-local-hostname-invalid".into());
    }

    let mut interfaces = fs::read_dir("/sys/class/net")
        .map_err(|_| "ruyi-local-net-directory-read-failed".to_string())?
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<Vec<_>>();
    interfaces.sort();
    let (interface, mac) = interfaces
        .into_iter()
        .filter(|interface| interface != "lo")
        .filter_map(|interface| {
            let mac = fs::read_to_string(
                Path::new("/sys/class/net").join(&interface).join("address"),
            )
            .ok()?
            .trim()
            .to_ascii_lowercase();
            (valid_mac(&mac) && mac != "00:00:00:00:00:00").then_some((interface, mac))
        })
        .next()
        .ok_or_else(|| "ruyi-local-mac-absent".to_string())?;

    let observed = crate::atoms::ask::read_only_command_with_timeout(
        "/usr/bin/ip",
        &[
            "-4".into(),
            "-o".into(),
            "addr".into(),
            "show".into(),
            "dev".into(),
            interface,
            "scope".into(),
            "global".into(),
        ],
        Duration::from_secs(2),
    );
    if !observed.ok {
        return Err("ruyi-local-ipv4-command-failed".into());
    }
    let ipv4 = observed
        .stdout
        .lines()
        .flat_map(|line| line.split_whitespace().collect::<Vec<_>>())
        .collect::<Vec<_>>()
        .windows(2)
        .find_map(|pair| {
            (pair[0] == "inet")
                .then(|| pair[1].split('/').next().unwrap_or_default())
                .and_then(|value| value.parse::<Ipv4Addr>().ok())
        })
        .ok_or_else(|| "ruyi-local-ipv4-absent".to_string())?;

    Ok(LocalIdentity {
        mac,
        hostname,
        ipv4: ipv4.to_string(),
    })
}

/// Build and persist the row created by a committed apply transaction.
pub(crate) fn write_committed_state(
    profile: &crate::Profile,
    run_id: &str,
    receipt: &crate::atoms::r#do::transaction::TransactionReceipt,
    mint: &crate::atoms::attest::SyzygyMint,
    identity: &LocalIdentity,
) -> Result<crate::atoms::projectio::Receipt, String> {
    if receipt.state != crate::atoms::r#do::transaction::TransactionState::Committed {
        return Err("ruyi-transaction-not-committed".into());
    }
    if let Some(error) = mint_error(mint) {
        return Err(error);
    }
    if !valid_run_id(run_id) {
        return Err("ruyi-run-id-invalid".into());
    }
    let last_seen = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "ruyi-clock-invalid".to_string())?
        .as_secs();
    let row = RuyiRow {
        schema: ROW_SCHEMA.into(),
        mac: identity.mac.clone(),
        hostname: identity.hostname.clone(),
        canonical_name: format!("{}.home.arpa", identity.hostname),
        ipv4: identity.ipv4.clone(),
        profile: profile.id.clone(),
        gui_face: receipt.gui.clone(),
        caduceus_sha: mint.caduceus_sha.clone(),
        env_sha: mint.env_sha.clone(),
        harmonia_sha: receipt.source_head.clone(),
        syzygy_sha: mint.syzygy_sha.clone(),
        last_seen,
        last_update: LastUpdate {
            run_id: run_id.into(),
            converged: true,
        },
    };
    write_row(&row)
}

pub(crate) fn read_row() -> Result<RuyiRow, String> {
    let path = ruyi_path();
    let bytes = fs::read(&path).map_err(|error| format!("ruyi-state-read-failed: {error}"))?;
    let row: RuyiRow = serde_json::from_slice(&bytes)
        .map_err(|error| format!("ruyi-state-json-invalid: {error}"))?;
    validate_row(&row)?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::{Mutex, OnceLock};

    static RUYI_PATH_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn row() -> RuyiRow {
        RuyiRow {
            schema: ROW_SCHEMA.into(),
            mac: "aa:bb:cc:dd:ee:ff".into(),
            hostname: "arcadia".into(),
            canonical_name: "arcadia.home.arpa".into(),
            ipv4: "192.0.2.1".into(),
            profile: "homeconsole".into(),
            gui_face: Some("Hyprland".into()),
            caduceus_sha: "a".repeat(40),
            env_sha: "b".repeat(64),
            harmonia_sha: "c".repeat(40),
            syzygy_sha: Some("d".repeat(64)),
            last_seen: 1_725_000_000,
            last_update: LastUpdate {
                run_id: "run-42".into(),
                converged: true,
            },
        }
    }

    fn with_test_path<T>(path: &std::path::Path, operation: impl FnOnce() -> T) -> T {
        let _guard = RUYI_PATH_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap();
        let prior = env::var_os(RUYI_PATH_ENV);
        env::set_var(RUYI_PATH_ENV, path);
        let result = operation();
        match prior {
            Some(value) => env::set_var(RUYI_PATH_ENV, value),
            None => env::remove_var(RUYI_PATH_ENV),
        }
        result
    }

    fn mint() -> crate::atoms::attest::SyzygyMint {
        crate::atoms::attest::SyzygyMint {
            caduceus_sha: "a".repeat(40),
            partner_sha: "b".repeat(40),
            gui_sha: None,
            syzygy_sha: Some("c".repeat(64)),
            env_sha: "d".repeat(64),
            signal: "none".into(),
        }
    }

    fn committed_receipt() -> crate::atoms::r#do::transaction::TransactionReceipt {
        crate::atoms::r#do::transaction::TransactionReceipt {
            schema: "harmonia.transaction.v1",
            state: crate::atoms::r#do::transaction::TransactionState::Committed,
            profile_id: "homeconsole".into(),
            profile_identity: "test".into(),
            source_head: "e".repeat(40),
            gui: Some("Hyprland".into()),
            gui_member: None,
            syzygy_sha: None,
            syzygy_signal: "none".into(),
            member_modules: Default::default(),
            children: Vec::new(),
            target_count: 0,
            service_count: 0,
            caduceus_count: 0,
        }
    }

    #[test]
    fn row_serializes_as_exact_local_schema() {
        let value = serde_json::to_value(row()).unwrap();
        let object = value.as_object().unwrap();
        let keys = object.keys().cloned().collect::<Vec<_>>();
        assert_eq!(
            keys,
            vec![
                "caduceus_sha",
                "canonical_name",
                "env_sha",
                "gui_face",
                "harmonia_sha",
                "hostname",
                "ipv4",
                "last_seen",
                "last_update",
                "mac",
                "profile",
                "schema",
                "syzygy_sha",
            ]
        );
        assert_eq!(object.get("schema").and_then(|value| value.as_str()), Some(ROW_SCHEMA));
        assert_eq!(object.get("last_update").unwrap().as_object().unwrap().len(), 2);
        assert!(serde_json::from_value::<RuyiRow>(value).is_ok());
    }

    #[test]
    fn validation_refuses_wrong_identity_and_exact_digest_lengths() {
        let mut invalid = row();
        invalid.canonical_name = "other.home.arpa".into();
        assert_eq!(validate_row(&invalid), Err("ruyi-canonical-name-invalid".into()));

        let mut invalid = row();
        invalid.caduceus_sha.push('a');
        assert_eq!(validate_row(&invalid), Err("ruyi-caduceus-sha-invalid".into()));

        let mut invalid = row();
        invalid.env_sha = invalid.env_sha.to_ascii_uppercase();
        assert_eq!(validate_row(&invalid), Err("ruyi-env-sha-invalid".into()));

        let mut invalid = row();
        invalid.syzygy_sha = Some("f".repeat(63));
        assert_eq!(validate_row(&invalid), Err("ruyi-syzygy-sha-invalid".into()));
    }

    #[test]
    fn committed_state_uses_env_sha_carried_by_mint() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("nested/ruyi.json");
        let profile = crate::Profile {
            id: "homeconsole".into(),
            identity: "test".into(),
            package_authority: None,
            modules: Vec::new(),
            hotfixes: Vec::new(),
            syzygy_declaration: None,
        };
        let identity = LocalIdentity {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            hostname: "arcadia".into(),
            ipv4: "192.0.2.1".into(),
        };
        let expected_env_sha = "d".repeat(64);
        let expected = mint();
        with_test_path(&path, || {
            write_committed_state(
                &profile,
                "run-42",
                &committed_receipt(),
                &expected,
                &identity,
            )
            .unwrap();
            assert_eq!(read_row().unwrap().env_sha, expected_env_sha);
        });
    }

    #[test]
    fn committed_state_rejects_invalid_mint_env_sha() {
        let mut invalid = mint();
        invalid.env_sha = "D".repeat(64);
        assert_eq!(mint_error(&invalid), Some("ruyi-syzygy-mint-env-invalid".into()));
    }

    #[test]
    fn projectio_write_uses_overridden_path_and_reads_back_one_row() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("nested/ruyi.json");
        let expected = row();
        with_test_path(&path, || {
            let receipt = write_row(&expected).unwrap();
            let bytes = fs::read(&path).unwrap();
            let stored: RuyiRow = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(stored, expected);
            assert_eq!(receipt.struck_bytes, bytes);
            assert_eq!(read_row().unwrap(), expected);
        });
    }

    #[test]
    fn committed_state_rewrites_temp_path_and_retains_distinct_rollback_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("nested/ruyi.json");
        let live_path = Path::new(DEFAULT_RUYI_PATH);
        let live_before = fs::read(live_path).ok();
        let profile = crate::Profile {
            id: "homeconsole".into(),
            identity: "test".into(),
            package_authority: None,
            modules: Vec::new(),
            hotfixes: Vec::new(),
            syzygy_declaration: None,
        };
        let identity = LocalIdentity {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            hostname: "arcadia".into(),
            ipv4: "192.0.2.1".into(),
        };
        let (first, second, readback) = with_test_path(&path, || {
            let first = write_committed_state(
                &profile,
                "run-first",
                &committed_receipt(),
                &mint(),
                &identity,
            )
            .unwrap();
            let second = write_committed_state(
                &profile,
                "run-second",
                &committed_receipt(),
                &mint(),
                &identity,
            )
            .unwrap();
            let readback = read_row().unwrap();
            (first, second, readback)
        });

        assert_ne!(first.backup_path, second.backup_path);
        assert_eq!(fs::read(&first.backup_path).unwrap(), b"");
        assert_eq!(fs::read(&second.backup_path).unwrap(), first.struck_bytes);
        assert_eq!(readback.last_update.run_id, "run-second");
        assert!(readback.last_update.converged);
        assert_eq!(fs::read(live_path).ok(), live_before);
    }

    #[test]
    fn path_helper_uses_the_production_default() {
        let _guard = RUYI_PATH_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap();
        let prior = env::var_os(RUYI_PATH_ENV);
        env::remove_var(RUYI_PATH_ENV);
        assert_eq!(ruyi_path(), PathBuf::from(DEFAULT_RUYI_PATH));
        match prior {
            Some(value) => env::set_var(RUYI_PATH_ENV, value),
            None => env::remove_var(RUYI_PATH_ENV),
        }
    }

}
