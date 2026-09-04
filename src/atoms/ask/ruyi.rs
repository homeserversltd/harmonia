use crate::bands::compare::BeamCompareReceipt;
use crate::{Profile, SyzygyDeclaration};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    env,
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, UdpSocket},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

pub(crate) const ROW_SCHEMA: &str = "caduceus.ruyi.v1";
pub(crate) const REGISTER_SCHEMA: &str = "harmonia.ruyi-register.v1";
pub(crate) const WRAPPER_SCHEMA: &str = "caduceus.ruyi.v1";
pub(crate) const DEFAULT_PORT: u16 = 3014;
pub(crate) const DEFAULT_RECEIPT_DIR: &str = "/var/lib/harmonia/receipts/update-latest";
const OUTPUT_LIMIT: usize = 16 * 1024;

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

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct RuyiResponseRow {
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
    #[serde(default)]
    pub spine: Option<String>,
}

impl From<RuyiResponseRow> for RuyiRow {
    fn from(row: RuyiResponseRow) -> Self {
        Self {
            schema: row.schema,
            mac: row.mac,
            hostname: row.hostname,
            canonical_name: row.canonical_name,
            ipv4: row.ipv4,
            profile: row.profile,
            gui_face: row.gui_face,
            caduceus_sha: row.caduceus_sha,
            env_sha: row.env_sha,
            harmonia_sha: row.harmonia_sha,
            syzygy_sha: row.syzygy_sha,
            last_seen: row.last_seen,
            last_update: row.last_update,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct GatewayReceipt {
    pub ipv4: String,
    pub url: String,
    pub port_source: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuyiIdentity {
    pub harmonia_sha_source: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuyiReceipt {
    pub schema: String,
    pub state: String,
    pub gateway: Option<GatewayReceipt>,
    #[serde(rename = "self")]
    pub self_row: Option<RuyiRow>,
    pub identity: Option<RuyiIdentity>,
    pub roster_count: usize,
    pub roster: Vec<RuyiRow>,
    pub first_missing_signal: String,
}
#[derive(Debug)]
struct CurlFailure {
    refused: bool,
    detail: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistrationResult {
    Registered,
    GatewayUnreachable,
    Refused,
}

pub(crate) fn default_gateway() -> Option<Ipv4Addr> {
    fs::read_to_string("/proc/net/route")
        .ok()
        .and_then(|s| parse_default_route(&s).map(|(_, g)| g))
}
fn parse_default_route(raw: &str) -> Option<(String, Ipv4Addr)> {
    for line in raw.lines().skip(1) {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() < 3 || f[1] != "00000000" || f[2].len() != 8 {
            continue;
        };
        if let Ok(v) = u32::from_str_radix(f[2], 16) {
            return Some((
                f[0].to_owned(),
                Ipv4Addr::from([
                    (v & 255) as u8,
                    ((v >> 8) & 255) as u8,
                    ((v >> 16) & 255) as u8,
                    ((v >> 24) & 255) as u8,
                ]),
            ));
        }
    }
    None
}
fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|x| {
            !x.is_empty()
                && x.len() <= 63
                && !x.starts_with('-')
                && !x.ends_with('-')
                && x.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
fn valid_mac(s: &str) -> bool {
    let p: Vec<_> = s.split(':').collect();
    p.len() == 6
        && p.iter().all(|x| {
            x.len() == 2
                && x.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
}
fn valid_sha(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn valid_last_update(x: &LastUpdate) -> bool {
    !x.run_id.is_empty() && x.run_id.starts_with("run-")
}
pub(crate) fn validate_row(row: RuyiRow) -> Result<RuyiRow, String> {
    let ok = row.schema == ROW_SCHEMA
        && valid_mac(&row.mac)
        && valid_name(&row.hostname)
        && row.canonical_name == format!("{}.home.arpa", row.hostname)
        && valid_name(&row.canonical_name)
        && row.ipv4.parse::<Ipv4Addr>().is_ok()
        && valid_name(&row.profile)
        && row
            .gui_face
            .as_deref()
            .is_none_or(|x| matches!(x, "Hyprland" | "Arcadia" | "Coronatio"))
        && valid_sha(&row.caduceus_sha, 40)
        && valid_sha(&row.env_sha, 64)
        && valid_sha(&row.harmonia_sha, 40)
        && row.syzygy_sha.as_deref().is_none_or(|x| valid_sha(x, 64))
        && valid_last_update(&row.last_update);
    if ok {
        Ok(row)
    } else {
        Err("ruyi-row-malformed".into())
    }
}
fn local_mac(iface: &str) -> Result<Option<String>, String> {
    match fs::read_to_string(Path::new("/sys/class/net").join(iface).join("address")) {
        Ok(x) => {
            let x = x.trim().to_ascii_lowercase();
            if x.is_empty() {
                Ok(None)
            } else if valid_mac(&x) {
                Ok(Some(x))
            } else {
                Err("ruyi-row-malformed".into())
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("ruyi-mac-read-failed: {e}")),
    }
}
fn local_hostname() -> Result<Option<String>, String> {
    match fs::read_to_string("/etc/hostname") {
        Ok(x) => {
            let x = x.trim().to_ascii_lowercase();
            if x.is_empty() {
                Ok(None)
            } else if valid_name(&x) {
                Ok(Some(x))
            } else {
                Err("ruyi-row-malformed".into())
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("ruyi-hostname-read-failed: {e}")),
    }
}
fn local_ipv4(gateway: Ipv4Addr) -> Result<Ipv4Addr, String> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let result: Result<Ipv4Addr, String> = (|| {
            let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|e| e.to_string())?;
            s.set_write_timeout(Some(Duration::from_millis(500)))
                .map_err(|e| e.to_string())?;
            s.connect((gateway, DEFAULT_PORT))
                .map_err(|e| e.to_string())?;
            match s.local_addr().map_err(|e| e.to_string())? {
                std::net::SocketAddr::V4(a) => Ok(*a.ip()),
                _ => Err("ruyi-local-ipv4-not-ipv4".into()),
            }
        })();
        let _ = tx.send(result);
    });
    rx.recv_timeout(Duration::from_secs(1))
        .map_err(|_| "ruyi-local-ipv4-timeout".into())
        .and_then(|x| x.map_err(|e| format!("ruyi-local-ipv4-unavailable: {e}")))
}
fn extract_run_id(n: &str) -> Option<String> {
    if n.starts_with("run-") {
        Some(n.into())
    } else {
        n.rsplit_once("-run-")
            .map(|(_, x)| format!("run-{x}"))
            .filter(|x| x.len() > 4)
    }
}
fn current_run_id(dir: &Path) -> String {
    dir.file_name()
        .and_then(|x| x.to_str())
        .and_then(extract_run_id)
        .unwrap_or_else(crate::run_id_from_stamp)
}
fn prior_candidates(dir: &Path, current: &str) -> Vec<std::path::PathBuf> {
    let n = dir.file_name().and_then(|x| x.to_str()).unwrap_or("");
    let (prefix, bare) = if n.starts_with("run-") {
        (String::new(), true)
    } else if let Some(x) = n.strip_suffix("-latest") {
        (x.into(), false)
    } else if let Some((x, _)) = n.rsplit_once("-run-") {
        (x.into(), false)
    } else {
        return vec![];
    };
    let mut v = fs::read_dir(dir.parent().unwrap_or_else(|| Path::new(".")))
        .ok()
        .into_iter()
        .flat_map(|e| e.flatten())
        .filter_map(|e| {
            let x = e.file_name().to_str()?.to_owned();
            let matches = if bare {
                x.starts_with("run-")
            } else {
                x.starts_with(&format!("{prefix}-run-"))
            };
            (matches && x != n && x != current && e.path().is_dir()).then_some((x, e.path()))
        })
        .collect::<Vec<_>>();
    v.sort_by(|a, b| b.0.cmp(&a.0));
    v.into_iter().map(|(_, p)| p).collect()
}
fn previous_last_update(dir: &Path, profile: &str, current: &str) -> Option<LastUpdate> {
    for p in prior_candidates(dir, current) {
        let raw = match fs::read(p.join("run.json")) {
            Ok(x) => x,
            Err(_) => continue,
        };
        let v: Value = match serde_json::from_slice(&raw) {
            Ok(x) => x,
            Err(_) => continue,
        };
        if v.get("schema").and_then(Value::as_str) != Some("harmonia.run_profile.v1")
            || v.get("profile_id").and_then(Value::as_str) != Some(profile)
        {
            continue;
        };
        let ok = match v.get("ok").and_then(Value::as_bool) {
            Some(x) => x,
            None => continue,
        };
        let run_id = match p
            .file_name()
            .and_then(|x| x.to_str())
            .and_then(extract_run_id)
        {
            Some(x) => x,
            None => continue,
        };
        return Some(LastUpdate {
            run_id,
            converged: ok,
        });
    }
    None
}
fn previous_syzygy(dir: &Path, profile: &str, current: &str) -> Option<String> {
    for p in prior_candidates(dir, current) {
        let raw = match fs::read(p.join("update-set.json")) {
            Ok(x) => x,
            Err(_) => continue,
        };
        let v: Value = match serde_json::from_slice(&raw) {
            Ok(x) => x,
            Err(_) => continue,
        };
        if v.get("schema").and_then(Value::as_str) != Some("harmonia.update-set.v1")
            || v.get("profile_id").and_then(Value::as_str) != Some(profile)
            || v.get("set_verdict").and_then(Value::as_str) != Some("ok")
        {
            continue;
        };
        if let Some(sha) = v
            .get("syzygy_sha")
            .and_then(Value::as_str)
            .filter(|x| valid_sha(x, 64))
        {
            return Some(sha.to_owned());
        }
    }
    None
}
pub(crate) fn syzygy_sha(c: &str, s: &str, g: Option<&str>) -> Result<String, String> {
    let g = g.filter(|x| !x.is_empty());
    for (m, x) in [("caduceus", c), ("sbin", s)]
        .into_iter()
        .chain(g.into_iter().map(|x| ("gui", x)))
    {
        if !valid_sha(x, 40) {
            return Err(format!("syzygy-source-sha-invalid {m}"));
        }
    }
    let mut x = String::with_capacity(120);
    x.push_str(c);
    x.push_str(s);
    if let Some(g) = g {
        x.push_str(g)
    };
    Ok(format!("{:x}", Sha256::digest(x.as_bytes())))
}
fn port(value: &str) -> Option<u16> {
    let x = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))
        .unwrap_or(value);
    let p = if let Some(x) = x.strip_prefix('[') {
        x.split_once(']')?.1.strip_prefix(':')?
    } else if x.bytes().filter(|b| *b == b':').count() == 1 {
        x.rsplit_once(':')?.1
    } else if x.bytes().all(|b| b.is_ascii_digit()) {
        x
    } else {
        return None;
    };
    let p = p.parse().ok()?;
    (p != 0).then_some(p)
}
fn caduceus_port() -> (u16, &'static str) {
    match std::env::var("CADUCEUS_BIND")
        .ok()
        .filter(|x| !x.trim().is_empty())
        .and_then(|x| port(&x))
    {
        Some(x) => (x, "env-CADUCEUS_BIND"),
        None => (DEFAULT_PORT, "default-3014"),
    }
}
fn base(g: Ipv4Addr, p: u16) -> String {
    format!("http://{g}:{p}")
}
fn resolve_harmonia_sha(
    embedded: Option<&str>,
    lock: Option<&crate::atoms::ask::beam::BeamLock>,
) -> Result<(String, &'static str), &'static str> {
    if let Some(sha) = embedded.and_then(|x| valid_sha(x, 40).then_some(x)) {
        return Ok((sha.to_owned(), "embedded"));
    }
    match lock {
        Some(crate::atoms::ask::beam::BeamLock::Legacy { minted_from, .. }) => {
            Ok((minted_from.harmonia_sha.clone(), "legacy-lock"))
        }
        _ => Err("ruyi-harmonia-sha-absent"),
    }
}
fn empty(state: &str, signal: &str) -> RuyiReceipt {
    RuyiReceipt {
        schema: REGISTER_SCHEMA.into(),
        state: state.into(),
        gateway: None,
        self_row: None,
        identity: None,
        roster_count: 0,
        roster: vec![],
        first_missing_signal: signal.into(),
    }
}
pub(crate) fn pre_declaration_receipt(signal: &str) -> RuyiReceipt {
    empty("pre-declaration", signal)
}
fn reg_state(self_gateway: bool, r: RegistrationResult) -> &'static str {
    match r {
        RegistrationResult::Registered if self_gateway => "self-is-gateway",
        RegistrationResult::Registered => "registered",
        RegistrationResult::Refused => "refused",
        RegistrationResult::GatewayUnreachable => "gateway-unreachable",
    }
}
fn failure(s: String, timed_out: bool) -> CurlFailure {
    let l = s.to_ascii_lowercase();
    let transport_failure = timed_out
        || l.contains("connection refused")
        || l.contains("failed to connect")
        || l.contains("could not resolve host")
        || l.contains("couldn't resolve host")
        || l.contains("name or service not known")
        || l.contains("timed out")
        || l.contains("timeout");
    let refused =
        !transport_failure && (l.contains("requested url returned error") || l.contains("http"));
    CurlFailure {
        refused,
        detail: if refused {
            "ruyi-refused".into()
        } else {
            "ruyi-gateway-unreachable".into()
        },
    }
}
fn bounded<R: Read>(mut r: R) -> String {
    let mut b = Vec::with_capacity(4096);
    let mut c = [0u8; 4096];
    while b.len() < OUTPUT_LIMIT {
        let n = (OUTPUT_LIMIT - b.len()).min(c.len());
        match r.read(&mut c[..n]) {
            Ok(0) | Err(_) => break,
            Ok(n) => b.extend_from_slice(&c[..n]),
        }
    }
    String::from_utf8_lossy(&b).into_owned()
}
fn curl(url: &str, body: Option<&[u8]>) -> Result<String, CurlFailure> {
    let mut a: Vec<String> = vec!["-fsS".into(), "--max-time".into(), "3".into()];
    if body.is_some() {
        a.extend([
            "-X".into(),
            "PUT".into(),
            "-H".into(),
            "Content-Type:application/json".into(),
            "--data-binary".into(),
            "@-".into(),
        ])
    }
    a.push(url.into());
    let mut c = Command::new("/usr/bin/curl");
    c.args(&a).stdout(Stdio::piped()).stderr(Stdio::piped());
    if body.is_some() {
        c.stdin(Stdio::piped());
    };
    let mut child = c.spawn().map_err(|e| failure(e.to_string(), false))?;
    if let (Some(mut i), Some(b)) = (child.stdin.take(), body) {
        let _ = i.write_all(b);
    }
    let stdout = child.stdout.take().expect("stdout");
    let stderr = child.stderr.take().expect("stderr");
    let o = thread::spawn(move || bounded(stdout));
    let e = thread::spawn(move || bounded(stderr));
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut timed = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if Instant::now() >= deadline => {
                timed = true;
                let _ = child.kill();
                break child.wait().ok();
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(_) => break None,
        }
    };
    let out = o.join().unwrap_or_default();
    let err = e.join().unwrap_or_default();
    if !status
        .as_ref()
        .is_some_and(std::process::ExitStatus::success)
    {
        Err(failure(err, timed))
    } else {
        Ok(out)
    }
}
fn parse_put(raw: &str) -> Result<RuyiRow, String> {
    let v: Value =
        serde_json::from_str(raw).map_err(|_| "ruyi-put-response-malformed".to_string())?;
    if v.get("schema").and_then(Value::as_str) != Some(WRAPPER_SCHEMA)
        || v.get("ok").and_then(Value::as_bool) != Some(true)
    {
        return Err("ruyi-put-response-malformed".into());
    };
    let stored = v
        .get("stored")
        .cloned()
        .ok_or("ruyi-stored-row-malformed".to_string())?;
    let wire: RuyiResponseRow =
        serde_json::from_value(stored).map_err(|_| "ruyi-stored-row-malformed".to_string())?;
    let r: RuyiRow = wire.into();
    validate_row(r).map_err(|_| "ruyi-stored-row-malformed".into())
}
fn parse_get(raw: &str) -> Result<Vec<RuyiRow>, String> {
    let v: Value = serde_json::from_str(raw).map_err(|_| "ruyi-roster-malformed".to_string())?;
    if v.get("schema").and_then(Value::as_str) != Some(WRAPPER_SCHEMA)
        || v.get("ok").and_then(Value::as_bool) != Some(true)
    {
        return Err("ruyi-roster-malformed".into());
    };
    v.get("staves")
        .and_then(Value::as_array)
        .ok_or("ruyi-roster-malformed".into())
        .and_then(|a| {
            a.iter()
                .cloned()
                .map(|x| {
                    let wire: RuyiResponseRow =
                        serde_json::from_value(x).map_err(|_| "ruyi-row-malformed".to_string())?;
                    validate_row(wire.into())
                })
                .collect()
        })
}
fn register(
    row: RuyiRow,
    g: GatewayReceipt,
    transport: &str,
    self_gateway: bool,
    identity: &RuyiIdentity,
) -> Result<RuyiReceipt, String> {
    let bytes = serde_json::to_vec(&row).map_err(|_| "ruyi-row-malformed".to_string())?;
    let put = format!("{transport}/api/v1/ruyi/{}", row.mac);
    let stored = match curl(&put, Some(&bytes)) {
        Ok(x) => match parse_put(&x) {
            Ok(v) => v,
            Err(e) => {
                return Ok(RuyiReceipt {
                    schema: REGISTER_SCHEMA.into(),
                    state: "refused".into(),
                    gateway: Some(g),
                    self_row: Some(row),
                    identity: Some(identity.clone()),
                    roster_count: 0,
                    roster: vec![],
                    first_missing_signal: e,
                })
            }
        },
        Err(x) => {
            return Ok(RuyiReceipt {
                schema: REGISTER_SCHEMA.into(),
                state: reg_state(
                    self_gateway,
                    if x.refused {
                        RegistrationResult::Refused
                    } else {
                        RegistrationResult::GatewayUnreachable
                    },
                )
                .into(),
                gateway: Some(g),
                self_row: Some(row),
                identity: Some(identity.clone()),
                roster_count: 0,
                roster: vec![],
                first_missing_signal: x.detail,
            })
        }
    };
    let get = format!("{transport}/api/v1/ruyi");
    let roster = match curl(&get, None) {
        Ok(x) => match parse_get(&x) {
            Ok(rows) => rows,
            Err(signal) => {
                return Ok(RuyiReceipt {
                    schema: REGISTER_SCHEMA.into(),
                    state: "refused".into(),
                    gateway: Some(g),
                    self_row: Some(stored),
                    identity: Some(identity.clone()),
                    roster_count: 0,
                    roster: vec![],
                    first_missing_signal: signal,
                })
            }
        },
        Err(x) => {
            return Ok(RuyiReceipt {
                schema: REGISTER_SCHEMA.into(),
                state: reg_state(
                    self_gateway,
                    if x.refused {
                        RegistrationResult::Refused
                    } else {
                        RegistrationResult::GatewayUnreachable
                    },
                )
                .into(),
                gateway: Some(g),
                self_row: Some(stored),
                identity: Some(identity.clone()),
                roster_count: 0,
                roster: vec![],
                first_missing_signal: x.detail,
            })
        }
    };
    Ok(RuyiReceipt {
        schema: REGISTER_SCHEMA.into(),
        state: reg_state(self_gateway, RegistrationResult::Registered).into(),
        gateway: Some(g),
        self_row: Some(stored),
        identity: Some(identity.clone()),
        roster_count: roster.len(),
        roster,
        first_missing_signal: "none".into(),
    })
}
pub(crate) fn ruyi_receipt_from_beam(
    profile: &Profile,
    dir: &Path,
    beam: &BeamCompareReceipt,
) -> Result<RuyiReceipt, String> {
    let Some((iface, gateway)) = fs::read_to_string("/proc/net/route")
        .ok()
        .and_then(|x| parse_default_route(&x))
    else {
        return Ok(pre_declaration_receipt("ruyi-default-gateway-absent"));
    };
    let (port, source) = caduceus_port();
    let gr = GatewayReceipt {
        ipv4: gateway.to_string(),
        url: base(gateway, port),
        port_source: source.into(),
    };
    let ip = match local_ipv4(gateway) {
        Ok(x) => x,
        Err(x) => return Ok(pre_declaration_receipt(&x)),
    };
    let Some(mac) = local_mac(&iface)? else {
        return Ok(pre_declaration_receipt("ruyi-mac-absent"));
    };
    let Some(host) = local_hostname()? else {
        return Ok(pre_declaration_receipt("ruyi-hostname-absent"));
    };
    let embedded = option_env!("HARMONIA_BUILD_SHA");
    let lock = if embedded.is_some_and(|x| valid_sha(x, 40)) {
        None
    } else {
        crate::atoms::ask::beam::read_embedded_lock().ok()
    };
    let (harmonia_sha, harmonia_sha_source) = match resolve_harmonia_sha(embedded, lock.as_ref()) {
        Ok(x) => x,
        Err(signal) => return Ok(pre_declaration_receipt(signal)),
    };
    let door = match beam.door.as_ref() {
        Some(x) => x,
        None => return Ok(pre_declaration_receipt("ruyi-beam-door-absent")),
    };
    let run = current_run_id(dir);
    let identity = RuyiIdentity {
        harmonia_sha_source: harmonia_sha_source.into(),
    };
    let row = validate_row(RuyiRow {
        schema: ROW_SCHEMA.into(),
        mac,
        hostname: host.clone(),
        canonical_name: format!("{host}.home.arpa"),
        ipv4: ip.to_string(),
        profile: profile.id.clone(),
        gui_face: profile
            .syzygy_declaration
            .as_ref()
            .and_then(|x: &SyzygyDeclaration| x.gui_face.clone()),
        caduceus_sha: door.caduceus_sha.clone(),
        env_sha: door.env_sha.clone(),
        harmonia_sha,
        syzygy_sha: previous_syzygy(dir, &profile.id, &run),
        last_seen: 0,
        last_update: previous_last_update(dir, &profile.id, &run).unwrap_or(LastUpdate {
            run_id: run,
            converged: false,
        }),
    })?;
    let self_gateway = ip == gateway;
    let transport = if self_gateway {
        format!("http://127.0.0.1:{port}")
    } else {
        base(gateway, port)
    };
    register(row, gr, &transport, self_gateway, &identity)
}
pub(crate) fn ruyi_receipt(beam: &BeamCompareReceipt, dir: &Path) -> Result<Value, String> {
    let receipt = match crate::device_profile::resolve_certificate_profile() {
        Ok((profile, _)) => ruyi_receipt_from_beam(&profile, dir, beam)?,
        Err(_) => pre_declaration_receipt("ruyi-profile-certificate-absent"),
    };
    serde_json::to_value(receipt).map_err(|e| format!("ruyi-receipt-serialize-failed: {e}"))
}
pub(crate) fn fetch_roster_receipt() -> Result<Value, String> {
    let Some(gateway) = default_gateway() else {
        return serde_json::to_value(pre_declaration_receipt("ruyi-default-gateway-absent"))
            .map_err(|e| format!("ruyi-receipt-serialize-failed: {e}"));
    };
    let (port, source) = caduceus_port();
    let local = match local_ipv4(gateway) {
        Ok(x) => x,
        Err(signal) => {
            return serde_json::to_value(pre_declaration_receipt(&signal))
                .map_err(|e| format!("ruyi-receipt-serialize-failed: {e}"));
        }
    };
    let transport = if local == gateway {
        format!("http://127.0.0.1:{port}")
    } else {
        base(gateway, port)
    };
    let gateway_receipt = GatewayReceipt {
        ipv4: gateway.to_string(),
        url: base(gateway, port),
        port_source: source.into(),
    };
    let raw = match curl(&format!("{transport}/api/v1/ruyi"), None) {
        Ok(x) => x,
        Err(failure) => {
            return serde_json::to_value(RuyiReceipt {
                schema: REGISTER_SCHEMA.into(),
                state: if failure.refused {
                    "refused"
                } else {
                    "gateway-unreachable"
                }
                .into(),
                gateway: Some(gateway_receipt),
                self_row: None,
                identity: None,
                roster_count: 0,
                roster: vec![],
                first_missing_signal: failure.detail,
            })
            .map_err(|e| format!("ruyi-receipt-serialize-failed: {e}"));
        }
    };
    let roster = match parse_get(&raw) {
        Ok(rows) => rows,
        Err(signal) => {
            return serde_json::to_value(RuyiReceipt {
                schema: REGISTER_SCHEMA.into(),
                state: "refused".into(),
                gateway: Some(gateway_receipt),
                self_row: None,
                identity: None,
                roster_count: 0,
                roster: vec![],
                first_missing_signal: signal,
            })
            .map_err(|e| format!("ruyi-receipt-serialize-failed: {e}"));
        }
    };
    serde_json::to_value(RuyiReceipt {
        schema: REGISTER_SCHEMA.into(),
        state: "registered".into(),
        gateway: Some(gateway_receipt),
        self_row: None,
        identity: None,
        roster_count: roster.len(),
        roster,
        first_missing_signal: "none".into(),
    })
    .map_err(|e| format!("ruyi-receipt-serialize-failed: {e}"))
}


// Local Ruyi state is a post-commit projection, not a declaration or roster
// operation.  The caller supplies the already serialized beam facts so this
// seam never reinterprets a receipt type that is intentionally Serialize-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalIdentity {
    pub mac: String,
    pub hostname: String,
    pub ipv4: String,
}

const STATE_PATH_ENV: &str = "HARMONIA_RUYI_STATE_PATH";
const DEFAULT_STATE_PATH: &str = "/etc/appliance/ruyi.json";

pub(crate) fn state_path() -> PathBuf {
    env::var_os(STATE_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_PATH))
}

fn local_identity() -> Result<LocalIdentity, String> {
    let mac = fs::read_dir("/sys/class/net")
        .map_err(|e| format!("ruyi-mac-directory-read-failed: {e}"))?
        .flatten()
        .filter(|entry| entry.file_name() != "lo")
        .find_map(|entry| {
            let value = fs::read_to_string(entry.path().join("address")).ok()?.trim().to_ascii_lowercase();
            valid_mac(&value).then_some(value)
        })
        .ok_or_else(|| "ruyi-mac-absent".to_string())?;
    let hostname = fs::read_to_string("/etc/hostname")
        .map_err(|e| format!("ruyi-hostname-read-failed: {e}"))?
        .trim()
        .to_ascii_lowercase();
    if !valid_name(&hostname) {
        return Err("ruyi-hostname-absent".into());
    }
    #[cfg(unix)]
    let ipv4 = unsafe {
        let mut head = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return Err(format!("ruyi-ipv4-read-failed: {}", std::io::Error::last_os_error()));
        }
        let mut current = head;
        let mut found = None;
        while !current.is_null() {
            let item = &*current;
            if !item.ifa_name.is_null() && !item.ifa_addr.is_null()
                && (*item.ifa_addr).sa_family as i32 == libc::AF_INET
            {
                let name = std::ffi::CStr::from_ptr(item.ifa_name).to_string_lossy();
                if name != "lo" {
                    let address = &*(item.ifa_addr as *const libc::sockaddr_in);
                    found = Some(std::net::Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()).to_string());
                    break;
                }
            }
            current = item.ifa_next;
        }
        libc::freeifaddrs(head);
        found.ok_or_else(|| "ruyi-ipv4-absent".to_string())?
    };
    #[cfg(not(unix))]
    let ipv4 = return Err("ruyi-ipv4-absent".into());
    Ok(LocalIdentity { mac, hostname, ipv4 })
}

fn local_state_beam_identity(beam: &Value) -> Result<(String, String, Option<String>, Option<String>), String> {
    let door = beam
        .get("door")
        .and_then(Value::as_object)
        .ok_or_else(|| "ruyi-beam-door-absent".to_string())?;
    let caduceus = door
        .get("caduceus_sha")
        .and_then(Value::as_str)
        .filter(|value| valid_sha(value, 40))
        .ok_or_else(|| "ruyi-caduceus-sha-absent".to_string())?
        .to_owned();
    let env = door
        .get("env_sha")
        .and_then(Value::as_str)
        .filter(|value| valid_sha(value, 64))
        .ok_or_else(|| "ruyi-env-sha-absent".to_string())?
        .to_owned();
    let gui = door.get("gui_face").and_then(Value::as_str).map(ToOwned::to_owned);
    let syzygy = door
        .get("syzygy_sha")
        .and_then(Value::as_str)
        .filter(|value| valid_sha(value, 64))
        .map(ToOwned::to_owned);
    Ok((caduceus, env, gui, syzygy))
}

fn local_harmonia_sha() -> Result<String, String> {
    let embedded = option_env!("HARMONIA_BUILD_SHA");
    let lock = if embedded.is_some_and(|value| valid_sha(value, 40)) {
        None
    } else {
        crate::atoms::ask::beam::read_embedded_lock().ok()
    };
    let (sha, _) = resolve_harmonia_sha(embedded, lock.as_ref())
        .map_err(str::to_string)?;
    valid_sha(&sha, 40)
        .then_some(sha)
        .ok_or_else(|| "ruyi-harmonia-sha-absent".to_string())
}

fn local_state_row(
    identity: &LocalIdentity,
    profile: &str,
    run_id: &str,
    converged: bool,
    gui_face: Option<String>,
    caduceus_sha: String,
    env_sha: String,
    harmonia_sha: String,
    syzygy_sha: Option<String>,
) -> Result<RuyiRow, String> {
    validate_row(RuyiRow {
        schema: ROW_SCHEMA.into(),
        mac: identity.mac.clone(),
        hostname: identity.hostname.clone(),
        canonical_name: format!("{}.home.arpa", identity.hostname),
        ipv4: identity.ipv4.clone(),
        profile: profile.into(),
        gui_face,
        caduceus_sha,
        env_sha,
        harmonia_sha,
        syzygy_sha,
        last_seen: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs(),
        last_update: LastUpdate { run_id: run_id.into(), converged },
    })
}

/// Write the exact local state row after a committed transaction. `beam` is
/// the concrete serialized post-comparison value already owned by the run.
pub(crate) fn write_local_state(
    profile: &Profile,
    receipt_dir: &Path,
    transaction: &crate::atoms::r#do::transaction::TransactionReceipt,
    beam: &Value,
) -> Result<(), String> {
    if transaction.state != crate::atoms::r#do::transaction::TransactionState::Committed {
        return Err("ruyi-state-requires-committed-transaction".into());
    }
    let (caduceus, env, gui, beam_syzygy) = local_state_beam_identity(beam)?;
    let row = local_state_row(
        &local_identity()?,
        &profile.id,
        &current_run_id(receipt_dir),
        true,
        gui.or_else(|| transaction.gui.clone()),
        caduceus,
        env,
        local_harmonia_sha()?,
        transaction.syzygy_sha.clone().or(beam_syzygy),
    )?;
    let bytes = serde_json::to_vec_pretty(&row)
        .map_err(|e| format!("ruyi-state-serialize-failed: {e}"))?;
    crate::atoms::projectio::write_state(crate::atoms::projectio::StateRequest {
        target: &state_path(),
        desired_bytes: &bytes,
        backup_path: &receipt_dir.join("backups/ruyi-before.json"),
        witness: crate::atoms::projectio::state_acceptance(),
    })?;
    Ok(())
}

/// Scratch seam used by tests and fixtures; it never consults appliance paths.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_local_state_at(
    target: &Path,
    backup: &Path,
    identity: &LocalIdentity,
    profile: &str,
    run_id: &str,
    converged: bool,
    gui_face: Option<String>,
    caduceus_sha: String,
    env_sha: String,
    harmonia_sha: String,
    syzygy_sha: Option<String>,
) -> Result<RuyiRow, String> {
    let row = local_state_row(identity, profile, run_id, converged, gui_face, caduceus_sha, env_sha, harmonia_sha, syzygy_sha)?;
    let bytes = serde_json::to_vec_pretty(&row)
        .map_err(|e| format!("ruyi-state-serialize-failed: {e}"))?;
    crate::atoms::projectio::write_state(crate::atoms::projectio::StateRequest {
        target,
        desired_bytes: &bytes,
        backup_path: backup,
        witness: crate::atoms::projectio::state_acceptance(),
    })?;
    Ok(row)
}

pub(crate) fn read_local_state() -> Result<Value, String> {
    let bytes = fs::read(state_path()).map_err(|e| format!("ruyi-state-read-failed: {e}"))?;
    let row: RuyiRow = serde_json::from_slice(&bytes).map_err(|e| format!("ruyi-state-malformed: {e}"))?;
    serde_json::to_value(validate_row(row)?).map_err(|e| format!("ruyi-state-serialize-failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixture_route_little_endian() {
        let x="Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\nLAN 00000000 01017BC0 0003 0 0 0 00000000 0 0 0\n";
        assert_eq!(
            parse_default_route(x),
            Some(("LAN".into(), Ipv4Addr::new(192, 123, 1, 1)))
        )
    }
    #[test]
    fn known_vector() {
        let c = "0123456789abcdef0123456789abcdef01234567";
        let s = "89abcdef0123456789abcdef0123456789abcdef";
        let g = "fedcba9876543210fedcba9876543210fedcba98";
        assert_eq!(
            syzygy_sha(c, s, Some(g)).unwrap(),
            "16eaf341cbbd394615511c1d693212de7eb81bdeeb7406ef5e2bcc233c8f900a"
        );
    }
    #[test]
    fn receipt_state_pure() {
        assert_eq!(
            reg_state(false, RegistrationResult::Registered),
            "registered"
        );
        assert_eq!(
            reg_state(true, RegistrationResult::Registered),
            "self-is-gateway"
        );
        assert_eq!(reg_state(false, RegistrationResult::Refused), "refused")
    }
    #[test]
    fn harmonia_sha_resolution_precedence() {
        let legacy = crate::atoms::ask::beam::BeamLock::Legacy {
            schema: crate::atoms::ask::beam::LOCK_SCHEMA.into(),
            caduceus_sha: "b".repeat(40),
            env_sha: "c".repeat(64),
            minted_from: crate::atoms::ask::beam::MintedFrom {
                harmonia_sha: "d".repeat(40),
                caduceus_release_tag: "e".repeat(40),
            },
        };
        let embedded = "a".repeat(40);
        let (sha, source) = resolve_harmonia_sha(Some(&embedded), Some(&legacy)).unwrap();
        assert_eq!(sha, embedded);
        assert_eq!(source, "embedded");

        let (sha, source) = resolve_harmonia_sha(None, Some(&legacy)).unwrap();
        assert_eq!(sha, "d".repeat(40));
        assert_eq!(source, "legacy-lock");

        assert_eq!(
            resolve_harmonia_sha(None, None),
            Err("ruyi-harmonia-sha-absent")
        );
    }
    #[test]
    fn put_wrapper_parse() {
        let r = RuyiRow {
            schema: ROW_SCHEMA.into(),
            mac: "aa:bb:cc:dd:ee:ff".into(),
            hostname: "host".into(),
            canonical_name: "host.home.arpa".into(),
            ipv4: "192.0.2.1".into(),
            profile: "homeserver".into(),
            gui_face: None,
            caduceus_sha: "a".repeat(40),
            env_sha: "b".repeat(64),
            harmonia_sha: "c".repeat(40),
            syzygy_sha: None,
            last_seen: 0,
            last_update: LastUpdate {
                run_id: "run-1".into(),
                converged: false,
            },
        };
        assert!(parse_put(
            &serde_json::json!({"schema":WRAPPER_SCHEMA,"ok":true,"stored":r}).to_string()
        )
        .is_ok())
    }
    #[test]
    fn extra_spine_field_row_parses_and_validates() {
        let value = serde_json::json!({
            "schema": ROW_SCHEMA,
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "host",
            "canonical_name": "host.home.arpa",
            "ipv4": "192.0.2.1",
            "profile": "homeserver",
            "gui_face": null,
            "caduceus_sha": "a".repeat(40),
            "env_sha": "b".repeat(64),
            "harmonia_sha": "c".repeat(40),
            "syzygy_sha": null,
            "last_seen": 0,
            "last_update": {
                "run_id": "run-1",
                "converged": false,
            },
            "spine": "client-claimed",
        });
        let wire: RuyiResponseRow = serde_json::from_value(value).unwrap();
        let row: RuyiRow = wire.into();
        assert!(validate_row(row).is_ok());
    }
    #[test]
    fn same_profile_prior_prefix() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("homeserver-update-run-3");
        let p = t.path().join("homeserver-update-run-2");
        fs::create_dir_all(&d).unwrap();
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join("run.json"),serde_json::json!({"schema":"harmonia.run_profile.v1","profile_id":"homeserver","ok":true}).to_string()).unwrap();
        assert_eq!(
            previous_last_update(&d, "homeserver", "run-3")
                .unwrap()
                .run_id,
            "run-2"
        )
    }

    #[test]
    fn local_state_write_has_exact_row_schema_without_live_paths() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("ruyi.json");
        let identity = LocalIdentity { mac: "aa:bb:cc:dd:ee:ff".into(), hostname: "host".into(), ipv4: "192.0.2.1".into() };
        let row = write_local_state_at(
            &target, &root.path().join("backup.json"), &identity, "homeserver", "run-1", true,
            Some("Coronatio".into()), "a".repeat(40), "b".repeat(64), "c".repeat(40), Some("d".repeat(64)),
        ).unwrap();
        let value: Value = serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
        assert_eq!(value["schema"], ROW_SCHEMA);
        assert_eq!(value["last_update"]["run_id"], "run-1");
        assert!(value.get("gateway").is_none());
        assert_eq!(validate_row(row).unwrap().syzygy_sha, Some("d".repeat(64)));
    }

    #[test]
    fn malformed_local_state_is_refused_before_projectio_write() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("ruyi.json");
        let identity = LocalIdentity { mac: "aa:bb:cc:dd:ee:ff".into(), hostname: "host".into(), ipv4: "192.0.2.1".into() };
        let error = write_local_state_at(
            &target, &root.path().join("backup.json"), &identity, "homeserver", "run-1", false,
            None, "not-a-sha".into(), "b".repeat(64), "c".repeat(40), None,
        ).unwrap_err();
        assert_eq!(error, "ruyi-row-malformed");
        assert!(!target.exists());
    }

}
