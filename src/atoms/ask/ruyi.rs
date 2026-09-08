//! Local, engine-maintained Ruyi state.
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[path = "ruyi/registrant.rs"]
mod registrant;
pub(crate) use registrant::{announce, read_perspective, register_promoted};

// Identity of this running engine, not a checkout, receipt, or release lookup.
const HARMONIA_BUILD_SHA: Option<&str> = option_env!("HARMONIA_BUILD_SHA");
pub(crate) const ROW_SCHEMA: &str = "caduceus.ruyi.v1";
const DEFAULT_RUYI_PATH: &str = "/etc/appliance/ruyi.json";
const RUYI_PATH_ENV: &str = "HARMONIA_RUYI_PATH";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct LastUpdate {
    pub run_id: String,
    pub converged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct RuyiRow {
    pub schema: String,
    pub mac: String,
    pub hostname: String,
    pub canonical_name: String,
    pub ipv4: String,
    pub profile: String,
    pub gui_face: Option<String>,
    #[serde(default, deserialize_with = "nullable_string")]
    pub caduceus_sha: String,
    #[serde(default, deserialize_with = "nullable_string")]
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

fn nullable_string<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
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
    if (!row.caduceus_sha.is_empty() || row.syzygy_sha.is_some())
        && !valid_hex(&row.caduceus_sha, 40) {
        return Err("ruyi-caduceus-sha-invalid".into());
    }
    if (!row.env_sha.is_empty() || row.syzygy_sha.is_some())
        && !valid_hex(&row.env_sha, 64) {
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
    if !mint.caduceus_sha.is_empty() && !valid_hex(&mint.caduceus_sha, 40) {
        return Some("ruyi-syzygy-mint-caduceus-invalid".into());
    }
    if !mint.partner_sha.is_empty() && !valid_hex(&mint.partner_sha, 40) {
        return Some("ruyi-syzygy-mint-partner-invalid".into());
    }
    if !mint.env_sha.is_empty() && !valid_hex(&mint.env_sha, 64) {
        return Some("ruyi-syzygy-mint-env-invalid".into());
    }
    if mint
        .gui_sha
        .as_deref()
        .is_some_and(|sha| !valid_hex(sha, 40))
    {
        return Some("ruyi-syzygy-mint-gui-invalid".into());
    }
    if mint
        .syzygy_sha
        .as_deref()
        .is_some_and(|sha| !valid_hex(sha, 64))
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
        harmonia_sha: HARMONIA_BUILD_SHA.unwrap_or_default().to_owned(),
        syzygy_sha: if mint.signal == "none" { mint.syzygy_sha.clone() } else { None },
        last_seen,
        last_update: LastUpdate {
            run_id: run_id.into(),
            converged: true,
        },
    };
    validate_row(&row)?;
    let mut value = serde_json::to_value(&row).map_err(|error| error.to_string())?;
    value["syzygy_signal"] = serde_json::json!(mint.signal);
    if row.caduceus_sha.is_empty() { value["caduceus_sha"] = serde_json::Value::Null; }
    if row.env_sha.is_empty() { value["env_sha"] = serde_json::Value::Null; }
    // Preserve additive fields in the existing raw envelope, including nested
    // last_update evidence. Old digest bytes are overwritten even on absence.
    let mut raw = match fs::read(ruyi_path()) {
        Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
            .map_err(|_| "ruyi-state-json-invalid".to_string())?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => serde_json::json!({"schema": ROW_SCHEMA}),
        Err(error) => return Err(format!("ruyi-state-read-failed: {error}")),
    };
    if raw.get("schema").and_then(serde_json::Value::as_str) != Some(ROW_SCHEMA) {
        return Err("ruyi-schema-invalid".into());
    }
    merge_fields(&mut raw, value);
    let bytes = serde_json::to_vec(&raw).map_err(|error| error.to_string())?;
    crate::atoms::projectio::write_engine_state(
        &ruyi_path(), &bytes, crate::atoms::projectio::engine_state_witness(),
    )
}

fn merge_fields(raw: &mut serde_json::Value, current: serde_json::Value) {
    match (raw, current) {
        (serde_json::Value::Object(raw), serde_json::Value::Object(current)) => {
            for (name, value) in current {
                merge_fields(raw.entry(name).or_insert(serde_json::Value::Null), value);
            }
        }
        (raw, current) => *raw = current,
    }
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

    // These three cases use separate processes so environment overrides and the
    // registrant's startup OnceLock cannot leak into another test.
    fn isolated_ruyi_case() -> bool {
        let thread = std::thread::current();
        let name = thread.name().expect("named test thread");
        if env::var("HARMONIA_RUYI_TEST_CHILD").ok().as_deref() == Some(name) {
            return true;
        }
        let output = std::process::Command::new(env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("HARMONIA_RUYI_TEST_CHILD", name)
            .env_remove(RUYI_PATH_ENV)
            .env("NO_PROXY", "*")
            .env("no_proxy", "*")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated {name}:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "the exact child test must execute"
        );
        false
    }

    struct RuyiTestPeer {
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        worker: Option<std::thread::JoinHandle<Vec<serde_json::Value>>>,
    }

    impl RuyiTestPeer {
        fn start(path: &Path) -> Self {
            use std::io::{BufRead, Read, Write};
            use std::sync::atomic::{AtomicBool, Ordering};
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            env::set_var("CADUCEUS_BIND", listener.local_addr().unwrap().to_string());
            env::set_var(RUYI_PATH_ENV, path);
            listener.set_nonblocking(true).unwrap();
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let stopping = stop.clone();
            let worker = std::thread::spawn(move || {
                let mut puts: Vec<serde_json::Value> = Vec::new();
                while !stopping.load(Ordering::SeqCst) {
                    let (mut stream, _) = match listener.accept() {
                        Ok(connection) => connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(error) => panic!("test peer accept: {error}"),
                    };
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                    let mut request = String::new();
                    reader.read_line(&mut request).unwrap();
                    let mut length = 0;
                    loop {
                        let mut header = String::new();
                        reader.read_line(&mut header).unwrap();
                        if header == "\r\n" {
                            break;
                        }
                        assert!(!header.is_empty(), "incomplete request headers");
                        if let Some((key, value)) = header.split_once(':') {
                            if key.eq_ignore_ascii_case("content-length") {
                                length = value.trim().parse::<usize>().unwrap();
                            }
                        }
                    }
                    let mut body = vec![0; length];
                    reader.read_exact(&mut body).unwrap();
                    let (status, reply) = if request.starts_with("GET /api/v1/schema/") {
                        // Exercise the production unavailable-seat path, not a schema copy.
                        ("404 Not Found", serde_json::json!({}))
                    } else if request.starts_with("PUT /api/v1/ruyi/aa:bb:cc:dd:ee:ff ") {
                        puts.push(serde_json::from_slice(&body).unwrap());
                        ("200 OK", serde_json::json!({}))
                    } else {
                        assert!(request.starts_with("GET /api/v1/ruyi "), "{request}");
                        let mut row = puts.last().expect("PUT precedes roster GET").clone();
                        row.as_object_mut().unwrap().remove("perspective");
                        (
                            "200 OK",
                            serde_json::json!({"staves": [row],
                            "seat": {"mac": "aa:bb:cc:dd:ee:ff"}}),
                        )
                    };
                    let body = serde_json::to_vec(&reply).unwrap();
                    write!(
                        stream,
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .unwrap();
                    stream.write_all(&body).unwrap();
                }
                puts
            });
            Self {
                stop,
                worker: Some(worker),
            }
        }

        fn finish(mut self) -> Vec<serde_json::Value> {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            self.worker.take().unwrap().join().unwrap()
        }
    }

    impl Drop for RuyiTestPeer {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    fn seed_test_perspective(path: &Path) -> Vec<u8> {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": "harmonia.ruyi-perspective.v1", "self": null,
            "seen": {}, "their_view_of_me": {}, "written_at": null,
            // Prior roster evidence selects loopback without probing the host LAN.
            "gateway_seat": {"mac": "aa:bb:cc:dd:ee:ff"}
        }))
        .unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, &bytes).unwrap();
        bytes
    }

    fn labelled_test_engine() -> bool {
        HARMONIA_BUILD_SHA
            .is_some_and(|sha| sha.len() == 40 && sha.bytes().all(|byte| byte.is_ascii_hexdigit()))
    }

    fn test_state_backups(path: &Path) -> Vec<PathBuf> {
        let mut backups = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".projectio-engine-state-")
            })
            .collect::<Vec<_>>();
        backups.sort();
        backups
    }

    #[test]
    fn committed_state_uses_env_sha_carried_by_mint() {
        if !isolated_ruyi_case() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("etc/appliance/ruyi.json");
        let before = seed_test_perspective(&path);
        let peer = RuyiTestPeer::start(&path);
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
        let evidence = crate::atoms::attest::SyzygyEvidence {
            mint: mint(),
            member_flags: serde_json::json!({}),
            observations: serde_json::json!({}),
        };
        // A conflicting runtime label must not replace the compiled identity.
        env::set_var("HARMONIA_BUILD_SHA", "not-the-compiled-engine");
        let result = register_promoted(
            &profile,
            "run-42",
            &committed_receipt(),
            &evidence,
            &identity,
            &temp.path().join("receipts"),
        )
        .unwrap();
        assert_eq!(result["self"]["env_sha"], expected_env_sha);
        assert_eq!(
            result["self"]["harmonia_sha"],
            serde_json::json!(HARMONIA_BUILD_SHA)
        );
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(temp.path().join("receipts/ruyi.json")).unwrap())
                .unwrap();
        assert_eq!(saved, result);
        let puts = peer.finish();
        if labelled_test_engine() {
            assert_eq!(result["state"], "self-is-gateway");
            assert_eq!(
                result["first_missing_signal"],
                "ruyi-schema-seat-unreachable"
            );
            assert_eq!(puts.len(), 1);
            assert_eq!(puts[0]["env_sha"], expected_env_sha);
            assert_eq!(
                puts[0]["harmonia_sha"],
                serde_json::json!(HARMONIA_BUILD_SHA)
            );
            let perspective = read_perspective().unwrap();
            assert_eq!(perspective["schema"], "harmonia.ruyi-perspective.v1");
            assert_eq!(perspective["self"], result["self"]);
            assert_eq!(perspective["self"]["env_sha"], expected_env_sha);
        } else {
            assert_eq!(result["state"], "pre-declaration");
            assert_eq!(
                result["first_missing_signal"],
                "ruyi-harmonia-identity-unlabelled"
            );
            assert!(puts.is_empty(), "an unlabelled engine must not PUT");
            assert_eq!(fs::read(&path).unwrap(), before);
            assert!(test_state_backups(&path).is_empty());
        }
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
        if !isolated_ruyi_case() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("etc/appliance/ruyi.json");
        let before = seed_test_perspective(&path);
        let peer = RuyiTestPeer::start(&path);
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
        let evidence = crate::atoms::attest::SyzygyEvidence {
            mint: mint(),
            member_flags: serde_json::json!({}),
            observations: serde_json::json!({}),
        };
        let first = register_promoted(
            &profile,
            "run-first",
            &committed_receipt(),
            &evidence,
            &identity,
            &temp.path().join("receipts/first"),
        )
        .unwrap();
        let first_bytes = fs::read(&path).unwrap();
        let first_backups = test_state_backups(&path);
        let second = register_promoted(
            &profile,
            "run-second",
            &committed_receipt(),
            &evidence,
            &identity,
            &temp.path().join("receipts/second"),
        )
        .unwrap();
        let second_bytes = fs::read(&path).unwrap();
        let backups = test_state_backups(&path);
        let puts = peer.finish();
        assert_eq!(ruyi_path(), path);
        for result in [&first, &second] {
            assert_eq!(
                result["self"]["harmonia_sha"],
                serde_json::json!(HARMONIA_BUILD_SHA)
            );
        }
        if labelled_test_engine() {
            assert_eq!(first["state"], "self-is-gateway");
            assert_eq!(second["state"], "self-is-gateway");
            assert_eq!(puts.len(), 2);
            assert_eq!(puts[0]["last_update"]["run_id"], "run-first");
            assert_eq!(puts[1]["last_update"]["run_id"], "run-second");
            assert_eq!(first_backups.len(), 1);
            assert_eq!(backups.len(), 2);
            let first_backup = &first_backups[0];
            let second_backup = backups.iter().find(|path| *path != first_backup).unwrap();
            assert_ne!(first_backup, second_backup);
            assert!(backups.contains(first_backup));
            assert_eq!(fs::read(first_backup).unwrap(), before);
            assert_eq!(fs::read(second_backup).unwrap(), first_bytes);
            assert_ne!(first_bytes, second_bytes);
            let first_perspective: serde_json::Value =
                serde_json::from_slice(&first_bytes).unwrap();
            assert_eq!(first_perspective["schema"], "harmonia.ruyi-perspective.v1");
            assert_eq!(first_perspective["self"], first["self"]);
            let readback = read_perspective().unwrap();
            assert_eq!(readback["schema"], "harmonia.ruyi-perspective.v1");
            assert_eq!(readback["self"], second["self"]);
            assert_eq!(readback["self"]["last_update"]["run_id"], "run-second");
            assert_eq!(readback["self"]["last_update"]["converged"], true);
        } else {
            for result in [&first, &second] {
                assert_eq!(result["state"], "pre-declaration");
                assert_eq!(
                    result["first_missing_signal"],
                    "ruyi-harmonia-identity-unlabelled"
                );
            }
            assert!(
                puts.is_empty(),
                "an unlabelled engine must not PUT or rewrite"
            );
            assert_eq!(first_bytes, before);
            assert_eq!(second_bytes, before);
            assert!(first_backups.is_empty());
            assert!(backups.is_empty());
        }
        assert_eq!(fs::read(live_path).ok(), live_before);
    }

    #[test]
    fn path_helper_uses_the_production_default() {
        if !isolated_ruyi_case() {
            return;
        }
        env::remove_var(RUYI_PATH_ENV);
        assert_eq!(ruyi_path(), PathBuf::from("/etc/appliance/ruyi.json"));
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("etc/appliance/ruyi.json");
        env::set_var(RUYI_PATH_ENV, &path);
        assert_eq!(ruyi_path(), path);
        env::remove_var(RUYI_PATH_ENV);
        assert_eq!(ruyi_path(), PathBuf::from("/etc/appliance/ruyi.json"));
    }

}
