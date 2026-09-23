//! Event-only Ruyi exchange. Raw envelopes retain additive peer evidence.
use super::*;
use serde_json::{json, Value};
use std::sync::OnceLock;

pub(crate) const PERSPECTIVE: &str = "harmonia.ruyi-perspective.v1";
const REGISTER: &str = "harmonia.ruyi-register.v1";

struct Seats {
    perspective: Result<crate::atoms::ask::mint_seats::Seat, String>,
    register: Result<crate::atoms::ask::mint_seats::Seat, String>,
}

impl Seats {
    fn signal(&self) -> Result<&'static str, String> {
        let mut signal = "none";
        for seat in [&self.perspective, &self.register] {
            if let Err(error) = seat {
                if error == "ruyi-schema-seat-unreachable" {
                    signal = "ruyi-schema-seat-unreachable";
                } else {
                    return Err(error.clone());
                }
            }
        }
        Ok(signal)
    }
}

fn port() -> Option<u16> {
    crate::bands::stage_profile::read_device_caduceus_seat_port()
        .ok()
        .flatten()
}

/// Read the local staff port from the port half of the existing Caduceus bind.
/// Absence and malformed declarations remain absence; the registrant never
/// invents the factory default.
pub(super) fn caduceus_port() -> Option<u16> {
    let bind = crate::bands::stage_profile::read_device_caduceus_bind()
        .ok()
        .flatten()?;
    let base = crate::atoms::ask::caduceus_door::resolve_bind(&bind).ok()?;
    let (_, port) = base.rsplit_once(':')?;
    port.parse::<u16>().ok()
}

fn unreachable_seats() -> Seats {
    Seats {
        perspective: Err("ruyi-schema-seat-unreachable".into()),
        register: Err("ruyi-schema-seat-unreachable".into()),
    }
}

fn at_start() -> &'static Seats {
    static SEATS: OnceLock<Seats> = OnceLock::new();
    SEATS.get_or_init(|| match crate::atoms::ask::caduceus_door::base_url() {
        Ok(base) => Seats {
            perspective: crate::atoms::ask::mint_seats::Seat::load_ruyi(PERSPECTIVE, base),
            register: crate::atoms::ask::mint_seats::Seat::load(REGISTER, base).map_err(|error| {
                eprintln!("schema-seat-unreachable schema={REGISTER}: {error}");
                if error.starts_with("schema-seat-unreachable") {
                    "ruyi-schema-seat-unreachable".to_string()
                } else {
                    error
                }
            }),
        },
        Err(_) => unreachable_seats(),
    })
}

/// One bounded StaffStart observation, never an exchange retry or an event.
fn wait_for_staff() -> (u64, bool) {
    use std::time::Instant;
    let Ok(base) = crate::atoms::ask::caduceus_door::base_url() else {
        return (0, false);
    };
    let started = Instant::now();
    let deadline = started + Duration::from_secs(10);
    let cadence = Duration::from_millis(500);
    // Resolve once, with the same overall deadline; health polling itself is
    // native HTTP and never starts a subprocess or invokes a staff actuator.
    let authority = base.strip_prefix("http://").unwrap_or_default().to_owned();
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::net::ToSocketAddrs;
        let address = authority
            .to_socket_addrs()
            .ok()
            .and_then(|mut addresses| addresses.next());
        let _ = send.send(address);
    });
    let address = match receive.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Some(address)) => address,
        _ => return (started.elapsed().as_millis() as u64, false),
    };
    loop {
        let probe_started = Instant::now();
        let remaining = deadline.saturating_duration_since(probe_started);
        if remaining.is_zero() {
            return (started.elapsed().as_millis() as u64, false);
        }
        let probe_deadline = (probe_started + cadence).min(deadline);
        if staff_health(address, base, probe_deadline) {
            return (started.elapsed().as_millis() as u64, true);
        }
        let next = (probe_started + cadence).min(deadline);
        std::thread::sleep(next.saturating_duration_since(Instant::now()));
    }
}

fn staff_health(address: std::net::SocketAddr, base: &str, deadline: std::time::Instant) -> bool {
    use std::io::{Read, Write};
    use std::time::Instant;
    let probe = || -> std::io::Result<bool> {
        let remaining = || deadline.saturating_duration_since(Instant::now());
        let mut stream = std::net::TcpStream::connect_timeout(&address, remaining())?;
        let request = format!(
            "GET /health HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            base.strip_prefix("http://").unwrap_or_default()
        );
        let mut pending = request.as_bytes();
        while !pending.is_empty() {
            stream.set_write_timeout(Some(remaining()))?;
            let written = stream.write(pending)?;
            if written == 0 {
                return Ok(false);
            }
            pending = &pending[written..];
        }
        // A bounded HTTP status line is sufficient; never consume a body or
        // let a slow response reset the absolute probe deadline.
        let mut line = Vec::new();
        while line.len() < 128 {
            stream.set_read_timeout(Some(remaining()))?;
            let mut byte = [0];
            if stream.read(&mut byte)? == 0 {
                return Ok(false);
            }
            line.push(byte[0]);
            if byte[0] == b'\n' {
                let text = String::from_utf8_lossy(&line);
                let mut fields = text.split_whitespace();
                let protocol = fields.next().unwrap_or_default();
                let status = fields.next().and_then(|value| value.parse::<u16>().ok());
                return Ok(matches!(protocol, "HTTP/1.0" | "HTTP/1.1")
                    && status.is_some_and(|status| (200..300).contains(&status)));
            }
        }
        Ok(false)
    };
    probe().unwrap_or(false)
}

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| "ruyi-clock-invalid".into())
}

fn empty_perspective() -> Value {
    json!({"schema": PERSPECTIVE, "self": null, "seen": {},
        "their_view_of_me": {}, "written_at": null})
}

pub(crate) fn validate_perspective(perspective: &Value) -> Result<(), String> {
    if let Ok(seat) = &at_start().perspective {
        seat.validate_ruyi(perspective)?;
    }
    Ok(())
}

pub(super) fn seed_perspective_for(
    identity: LocalIdentity,
    profile: crate::Profile,
    beam_door: Option<crate::atoms::ask::beam::BeamDoor>,
) -> Result<(LocalIdentity, Value), String> {
    seed_perspective_for_with_harmonia_sha(identity, profile, beam_door, HARMONIA_BUILD_SHA)
}

fn seed_perspective_for_with_harmonia_sha(
    identity: LocalIdentity,
    profile: crate::Profile,
    beam_door: Option<crate::atoms::ask::beam::BeamDoor>,
    harmonia_sha: Option<&str>,
) -> Result<(LocalIdentity, Value), String> {
    let profile_gui_face = profile
        .syzygy_declaration
        .as_ref()
        .and_then(|declaration| declaration.gui_face.clone());
    let (gui_face_from_door, caduceus_sha, env_sha, rustc_version, syzygy_sha) = match beam_door {
        Some(door) => (
            door.gui_face,
            if valid_hex(&door.caduceus_sha, 40) {
                door.caduceus_sha
            } else {
                String::new()
            },
            if valid_hex(&door.env_sha, 64) {
                door.env_sha
            } else {
                String::new()
            },
            door.rustc_version,
            door.syzygy_sha.filter(|sha| valid_hex(sha, 64)),
        ),
        None => (None, String::new(), String::new(), None, None),
    };
    let caduceus_sha_present = valid_hex(&caduceus_sha, 40);
    let env_sha_present = valid_hex(&env_sha, 64);
    let row = RuyiRow {
        schema: ROW_SCHEMA.into(),
        mac: identity.mac.clone(),
        hostname: identity.hostname.clone(),
        canonical_name: canonical_name(&identity.hostname),
        ipv4: identity.ipv4.clone(),
        profile: profile.id,
        gui_face: profile_gui_face.or(gui_face_from_door),
        caduceus_port: caduceus_port(),
        caduceus_sha,
        env_sha,
        rustc_version,
        harmonia_sha: harmonia_sha.unwrap_or_default().to_owned(),
        syzygy_sha,
        last_seen: now()?,
        last_update: LastUpdate {
            run_id: crate::run_id_from_stamp(),
            converged: false,
        },
    };
    validate_row(&row)?;
    let mut self_row = serde_json::to_value(row).map_err(|error| error.to_string())?;
    if !caduceus_sha_present {
        self_row["caduceus_sha"] = Value::Null;
    }
    if !env_sha_present {
        self_row["env_sha"] = Value::Null;
    }
    let perspective = json!({
        "schema": PERSPECTIVE,
        "self": self_row,
        "seen": {},
        "their_view_of_me": {},
        "written_at": now()?
    });
    validate_perspective(&perspective)?;
    Ok((identity, perspective))
}

fn persist_seed_if_absent(
    identity: LocalIdentity,
    profile: crate::Profile,
    harmonia_sha: Option<&str>,
    beam_door: impl FnOnce() -> Option<crate::atoms::ask::beam::BeamDoor>,
) -> Result<bool, String> {
    match fs::symlink_metadata(ruyi_path()) {
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("ruyi-state-read-failed: {error}")),
    }
    let beam_door = beam_door().ok_or_else(|| "ruyi-beam-door-unavailable".to_string())?;
    let (_, perspective) =
        seed_perspective_for_with_harmonia_sha(identity, profile, Some(beam_door), harmonia_sha)?;
    let bytes = serde_json::to_vec(&perspective).map_err(|error| error.to_string())?;
    crate::atoms::projectio::write_engine_state(
        &ruyi_path(),
        &bytes,
        crate::atoms::projectio::engine_state_witness(),
    )?;
    Ok(true)
}

fn refresh_self_row_from_beam_observation(
    row: Value,
    profile: &crate::Profile,
    observation: Result<crate::atoms::ask::beam::BeamDoor, String>,
    harmonia_sha: Option<&str>,
) -> Value {
    let Ok(door) = observation else {
        return row;
    };
    let Some(mac) = row.get("mac").and_then(Value::as_str) else {
        return row;
    };
    let Some(hostname) = row.get("hostname").and_then(Value::as_str) else {
        return row;
    };
    let Some(ipv4) = row.get("ipv4").and_then(Value::as_str) else {
        return row;
    };
    let identity = LocalIdentity {
        mac: mac.to_owned(),
        hostname: hostname.to_owned(),
        ipv4: ipv4.to_owned(),
        first_missing_signal: None,
    };
    let Ok((_, seeded)) =
        seed_perspective_for_with_harmonia_sha(identity, profile.clone(), Some(door), harmonia_sha)
    else {
        return row;
    };
    let Some(observed) = seeded.get("self").and_then(Value::as_object) else {
        return row;
    };
    let Some(last_seen) = observed.get("last_seen").filter(|value| !value.is_null()) else {
        return row;
    };
    let mut refreshed = row;
    for field in [
        "caduceus_sha",
        "env_sha",
        "rustc_version",
        "gui_face",
        "syzygy_sha",
    ] {
        let Some(value) = observed.get(field).filter(|value| !value.is_null()) else {
            continue;
        };
        refreshed[field] = value.clone();
    }
    refreshed["last_seen"] = last_seen.clone();
    refreshed
}

fn refresh_self_row_from_local_beam(
    row: Value,
    profile: &crate::Profile,
    harmonia_sha: Option<&str>,
) -> Value {
    let observation = crate::atoms::ask::beam::door_url()
        .ok()
        .map(|url| crate::atoms::ask::beam::fetch_door(&url))
        .unwrap_or_else(|| Err("beam-door-unreachable".into()));
    refresh_self_row_from_beam_observation(row, profile, observation, harmonia_sha)
}

pub(crate) fn read_perspective() -> Result<Value, String> {
    read_perspective_with_seats(at_start())
}

fn read_perspective_with_seats(seats: &Seats) -> Result<Value, String> {
    let bytes = match fs::read(ruyi_path()) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(empty_perspective());
        }
        Err(error) => return Err(format!("ruyi-state-read-failed: {error}")),
    };
    seats.signal()?;
    let raw: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("ruyi-state-json-invalid: {error}"))?;
    match raw.get("schema").and_then(Value::as_str) {
        Some(PERSPECTIVE) => {
            if let Ok(seat) = &seats.perspective {
                seat.validate_ruyi(&raw)?;
            }
            Ok(raw)
        }
        // The former bare row becomes self without narrowing its unknown fields.
        Some(ROW_SCHEMA) => {
            let mut perspective = empty_perspective();
            perspective["self"] = raw;
            Ok(perspective)
        }
        _ => Err("ruyi-schema-invalid".into()),
    }
}

fn prior_perspective() -> Result<Value, String> {
    match fs::metadata(ruyi_path()) {
        Ok(_) => read_perspective(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(empty_perspective()),
        Err(error) => Err(format!("ruyi-state-read-failed: {error}")),
    }
}

fn receipt(state: &str, row: Value, roster: Vec<Value>, signal: &str) -> Value {
    let caduceus_port = row
        .get("caduceus_port")
        .filter(|value| !value.is_null())
        .cloned()
        .unwrap_or_else(|| json!("undeclared"));
    json!({"schema": REGISTER, "state": state, "self": row,
        "roster_count": roster.len(), "roster": roster, "first_missing_signal": signal,
        "event": "new-artifact", "held_back_by": [], "caduceus_port": caduceus_port})
}

fn amend_update_set_held_back_by(dir: &Path, held_back_by: &Value) -> Result<(), String> {
    let path = dir.join("update-set.json");
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("update-set-read-failed: {error}")),
    };
    let mut value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("update-set-parse-failed: {error}"))?;
    value["held_back_by"] = held_back_by.clone();
    crate::atoms::attest::write_json_atomic(&path, &value)
}

fn validate_own_receipt_with_seat(
    value: &mut Value,
    seat: Option<&crate::atoms::ask::mint_seats::Seat>,
) -> bool {
    let Some(seat) = seat else {
        return false;
    };
    let Err(error) = seat.validate(value) else {
        return false;
    };
    value["state"] = json!("refused");
    value["first_missing_signal"] = json!(error);
    true
}

fn save_receipt_with_seat(
    dir: &Path,
    mut value: Value,
    seat: Option<&crate::atoms::ask::mint_seats::Seat>,
) -> Result<Value, String> {
    validate_own_receipt_with_seat(&mut value, seat);
    crate::atoms::attest::write_json_atomic(&dir.join("ruyi.json"), &value)?;
    Ok(value)
}

fn save_receipt(dir: &Path, value: Value) -> Result<Value, String> {
    let seat = at_start().register.as_ref().ok();
    save_receipt_with_seat(dir, value, seat)
}

/// Reuse the committed mint and its raw evidence; do not resolve any member again.
pub(crate) fn register_promoted(
    profile: &crate::Profile,
    run_id: &str,
    transaction: &crate::atoms::r#do::transaction::TransactionReceipt,
    evidence: &crate::atoms::attest::SyzygyEvidence,
    identity: &LocalIdentity,
    dir: &Path,
) -> Result<Value, String> {
    match persist_seed_if_absent(
        identity.clone(),
        profile.clone(),
        HARMONIA_BUILD_SHA,
        || {
            crate::atoms::ask::beam::door_url()
                .ok()
                .and_then(|url| crate::atoms::ask::beam::fetch_door(&url).ok())
        },
    ) {
        Ok(_) => {}
        Err(signal) => {
            return save_receipt(
                dir,
                receipt("pre-declaration", Value::Null, Vec::new(), &signal),
            );
        }
    };
    let Some(port) = port() else {
        return save_receipt(
            dir,
            receipt(
                "pre-declaration",
                Value::Null,
                Vec::new(),
                "ruyi-seat-undeclared",
            ),
        );
    };
    let beam = evidence.observations.get("caduceus");
    // A failed slot resolution also has lock:null. Only explicit absence means
    // the carried lock is absent; failed resolution must keep a non-null self.
    let lock_absent = beam
        .and_then(|beam| beam.get("first_missing_signal"))
        .and_then(Value::as_str)
        == Some("beam-lock-absent");
    if profile.id.is_empty() || lock_absent {
        return save_receipt(
            dir,
            receipt(
                "pre-declaration",
                Value::Null,
                Vec::new(),
                if lock_absent {
                    "ruyi-beam-lock-absent"
                } else {
                    "ruyi-profile-absent"
                },
            ),
        );
    }
    let seats = at_start();
    let mut prior = prior_perspective()?;
    let mut row = prior
        .get("self")
        .filter(|row| row.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}));
    let caduceus_port = caduceus_port();
    merge_fields(
        &mut row,
        json!({
            "schema": ROW_SCHEMA, "mac": identity.mac, "hostname": identity.hostname,
            "canonical_name": canonical_name(&identity.hostname), "ipv4": identity.ipv4,
            "profile": profile.id, "gui_face": transaction.gui,
            "caduceus_port": caduceus_port,
            "caduceus_sha": if evidence.caduceus_sha.is_empty() { Value::Null } else { json!(evidence.caduceus_sha) },
            "env_sha": if evidence.env_sha.is_empty() { Value::Null } else { json!(evidence.env_sha) },
            "harmonia_sha": HARMONIA_BUILD_SHA,
            "syzygy_sha": evidence.syzygy_sha, "syzygy_signal": evidence.signal,
            "member_flags": evidence.member_flags,
            "last_seen": now()?, "last_update": {"run_id": run_id, "converged": true}
        }),
    );
    if caduceus_port.is_none() {
        row.as_object_mut()
            .expect("Ruyi self row is assembled as an object")
            .remove("caduceus_port");
    }
    prior["self"] = row.clone();
    let result = exchange(profile, row, prior, seats, port)?;
    amend_update_set_held_back_by(dir, &result["held_back_by"])?;
    save_receipt(dir, result)
}

fn declaration_signal(row: &Value) -> Option<&'static str> {
    if !HARMONIA_BUILD_SHA
        .is_some_and(|sha| sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Some("ruyi-harmonia-identity-unlabelled");
    }
    if !row
        .get("caduceus_sha")
        .and_then(Value::as_str)
        .is_some_and(|sha| valid_hex(sha, 40))
    {
        return Some("ruyi-beam-caduceus-sha-absent");
    }
    if !row
        .get("env_sha")
        .and_then(Value::as_str)
        .is_some_and(|sha| valid_hex(sha, 64))
    {
        return Some("ruyi-beam-env-sha-absent");
    }
    None
}

pub(crate) fn default_gateway() -> Result<Ipv4Addr, String> {
    #[cfg(any(test, feature = "test-facade"))]
    if let Some(gateway) = std::env::var_os("HARMONIA_DEFAULT_GATEWAY") {
        return gateway
            .to_string_lossy()
            .parse()
            .map_err(|_| "ruyi-default-gateway-unavailable".to_string());
    }
    let routes = fs::read_to_string("/proc/net/route")
        .map_err(|_| "ruyi-default-gateway-unavailable".to_string())?;
    routes
        .lines()
        .skip(1)
        .find_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.get(1) != Some(&"00000000") {
                return None;
            }
            let gateway = u32::from_str_radix(fields.get(2)?, 16).ok()?;
            (gateway != 0).then(|| Ipv4Addr::from(gateway.to_le_bytes()))
        })
        .ok_or_else(|| "ruyi-default-gateway-unavailable".into())
}

pub(crate) fn gateway_is_local(gateway: Ipv4Addr, row: &Value) -> bool {
    if row
        .get("ipv4")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
        == Some(gateway)
    {
        return true;
    }
    let observed = crate::atoms::ask::read_only_command_with_timeout(
        "/usr/bin/ip",
        &["-4".into(), "-o".into(), "addr".into(), "show".into()],
        Duration::from_secs(2),
    );
    observed.ok
        && observed.stdout.split_whitespace().any(|word| {
            word.split('/')
                .next()
                .and_then(|s| s.parse::<Ipv4Addr>().ok())
                == Some(gateway)
        })
}

fn local_seat_hostname_matches(port: u16, own_hostname: &str) -> bool {
    let url = format!("http://127.0.0.1:{port}/api/v1/ruyi");
    // This is a decision-only observation: every door or answer failure
    // becomes false so registration can continue through its other arms.
    let Ok(roster) = get_roster(&url) else {
        return false;
    };
    if !roster.is_object()
        || roster
            .get("ok")
            .is_some_and(|ok| ok.as_bool() != Some(true))
        || roster
            .get("schema")
            .is_some_and(|schema| schema.as_str() != Some(ROW_SCHEMA))
    {
        return false;
    }
    roster
        .pointer("/seat/hostname")
        .and_then(Value::as_str)
        .is_some_and(|seat_hostname| {
            seat_hostname.trim().to_ascii_lowercase() == own_hostname.trim().to_ascii_lowercase()
        })
}

pub(crate) trait RuyiSeatPort {
    fn declared_port(self) -> Option<u16>;
}

impl RuyiSeatPort for u16 {
    fn declared_port(self) -> Option<u16> {
        Some(self)
    }
}

// Preserve the existing crate caller while keeping the route address out of
// gateway classification. Its port still comes only from the declaration.
impl RuyiSeatPort for Ipv4Addr {
    fn declared_port(self) -> Option<u16> {
        let _ = self;
        port()
    }
}

pub(crate) fn self_is_gateway(
    perspective: &Value,
    declared_port: impl RuyiSeatPort,
    row: &Value,
) -> bool {
    let persisted_gateway_mac = perspective
        .pointer("/gateway_seat/mac")
        .and_then(Value::as_str);
    if row
        .get("mac")
        .and_then(Value::as_str)
        .is_some_and(|self_mac| Some(self_mac) == persisted_gateway_mac)
    {
        return true;
    }
    let Some(port) = declared_port.declared_port() else {
        return false;
    };
    let Some(own_hostname) = row.get("hostname").and_then(Value::as_str) else {
        return false;
    };
    local_seat_hostname_matches(port, own_hostname)
}

pub(crate) fn routed_host(row: &Value) -> Result<Ipv4Addr, String> {
    let mac = row.get("mac").and_then(Value::as_str).unwrap_or_default();
    let prior_self_seat = read_perspective()
        .ok()
        .and_then(|perspective| {
            perspective
                .pointer("/gateway_seat/mac")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .as_deref()
        == Some(mac);
    if prior_self_seat {
        return Ok(Ipv4Addr::LOCALHOST);
    }
    let gateway = default_gateway()?;
    Ok(if gateway_is_local(gateway, row) {
        Ipv4Addr::LOCALHOST
    } else {
        gateway
    })
}

/// A roster carries every stave's row plus perspectives; three staves already
/// exceed the ordinary 16 KiB command bound, which parsed as
/// `ruyi-roster-malformed` on every announce (witnessed 2026-09-22).
const ROSTER_READ_LIMIT: usize = 4 * 1024 * 1024;

fn get_roster(url: &str) -> Result<Value, String> {
    let observed = crate::atoms::ask::read_only_command_with_timeout_and_limit(
        "/usr/bin/curl",
        &["-fsS".into(), "--max-time".into(), "3".into(), url.into()],
        Duration::from_secs(4),
        ROSTER_READ_LIMIT,
    );
    if !observed.ok {
        return Err(if observed.code == Some(22) {
            "ruyi-roster-refused"
        } else {
            "ruyi-gateway-unreachable"
        }
        .into());
    }
    serde_json::from_str(&observed.stdout).map_err(|_| "ruyi-roster-malformed".into())
}

fn exchange(
    profile: &crate::Profile,
    mut row: Value,
    mut perspective: Value,
    seats: &Seats,
    port: u16,
) -> Result<Value, String> {
    let signal = match seats.signal() {
        Ok(signal) => signal,
        Err(error) => return Ok(receipt("refused", row, Vec::new(), &error)),
    };
    row["harmonia_sha"] = json!(HARMONIA_BUILD_SHA);
    if let Some(signal) = declaration_signal(&row) {
        return Ok(receipt("pre-declaration", row, Vec::new(), signal));
    }

    let Some(mac) = row
        .get("mac")
        .and_then(Value::as_str)
        .filter(|mac| valid_mac(mac))
        .map(str::to_owned)
    else {
        return Ok(receipt("refused", row, Vec::new(), "ruyi-mac-invalid"));
    };
    let is_gateway = self_is_gateway(&perspective, port, &row);
    let host = if is_gateway {
        Ipv4Addr::LOCALHOST
    } else {
        match default_gateway() {
            Ok(gateway) => gateway,
            Err(error) => {
                return Ok(receipt("gateway-unreachable", row, Vec::new(), &error));
            }
        }
    };
    let url = format!("http://{host}:{port}/api/v1/ruyi");
    perspective["self"] = row.clone();
    perspective["written_at"] = json!(now()?);
    if let Ok(seat) = &seats.perspective {
        if let Err(error) = seat.validate_ruyi(&perspective) {
            return Ok(receipt("refused", row, Vec::new(), &error));
        }
    }
    let mut payload = row.clone();
    payload["perspective"] = perspective.clone();
    let bytes = serde_json::to_vec(&payload).map_err(|error| error.to_string())?;
    // Exactly one PUT followed by exactly one roster GET, including a failed PUT.
    // Schema-door startup loads and the local-seat probe are separate observations,
    // not additional requests in this exchange.
    let put = crate::atoms::ask::beam::put_json(&format!("{url}/{mac}"), &bytes);
    let get = get_roster(&url);
    if let Err(error) = put {
        let state = if error == "ruyi-gateway-unreachable" {
            "gateway-unreachable"
        } else {
            "refused"
        };
        return Ok(receipt(state, row, Vec::new(), &error));
    }
    let roster = match get {
        Ok(roster) => roster,
        Err(error) => {
            let state = if error == "ruyi-gateway-unreachable" {
                "gateway-unreachable"
            } else {
                "refused"
            };
            return Ok(receipt(state, row, Vec::new(), &error));
        }
    };
    if !roster.is_object() || roster.get("ok").and_then(Value::as_bool) == Some(false) {
        return Ok(receipt("refused", row, Vec::new(), "ruyi-roster-malformed"));
    }
    if roster
        .get("schema")
        .is_some_and(|schema| schema.as_str() != Some(ROW_SCHEMA))
    {
        return Ok(receipt(
            "refused",
            row,
            Vec::new(),
            "ruyi-roster-schema-foreign",
        ));
    }
    let staves = match roster.get("staves") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(staves)) if staves.iter().all(Value::is_object) => staves.clone(),
        _ => return Ok(receipt("refused", row, Vec::new(), "ruyi-roster-malformed")),
    };
    for stave in &staves {
        if stave
            .get("schema")
            .is_some_and(|schema| schema.as_str() != Some(ROW_SCHEMA))
        {
            return Ok(receipt(
                "refused",
                row,
                staves.clone(),
                "ruyi-row-schema-foreign",
            ));
        }
    }
    if let Err(error) = accumulate(&mut perspective, &roster, &staves, &mac) {
        return Ok(receipt("refused", row, staves, &error));
    }
    let held_back_by =
        crate::interactables::reconcile_ruyi(profile, &row, &roster, &staves, is_gateway)?;
    perspective["written_at"] = json!(now()?);
    // Preserve the last observed seat so the next event can take the persisted
    // mac arm before its separate local-seat observation.
    if let Some(seat) = roster.get("seat") {
        perspective["gateway_seat"] = seat.clone();
    }
    let mut result = receipt(
        if is_gateway {
            "self-is-gateway"
        } else {
            "registered"
        },
        row,
        staves,
        signal,
    );
    result["held_back_by"] = json!(held_back_by);
    if validate_own_receipt_with_seat(&mut result, seats.register.as_ref().ok()) {
        return Ok(result);
    }
    let bytes = serde_json::to_vec(&perspective).map_err(|error| error.to_string())?;
    crate::atoms::projectio::write_engine_state(
        &ruyi_path(),
        &bytes,
        crate::atoms::projectio::engine_state_witness(),
    )?;
    Ok(result)
}

fn beam_pair(row: &Value) -> Value {
    json!({"caduceus_sha": row.get("caduceus_sha"), "env_sha": row.get("env_sha")})
}

fn accumulate(
    perspective: &mut Value,
    roster: &Value,
    staves: &[Value],
    mac: &str,
) -> Result<(), String> {
    for field in ["seen", "their_view_of_me"] {
        if perspective.get(field).is_none_or(Value::is_null) {
            perspective[field] = json!({});
        }
        if !perspective[field].is_object() {
            return Err(format!("ruyi-perspective-{field}-malformed"));
        }
    }
    for peer in staves {
        let Some(peer_mac) = peer.get("mac").and_then(Value::as_str) else {
            continue;
        };
        if peer_mac == mac {
            continue;
        }
        let pair = beam_pair(peer);
        let old = perspective["seen"]
            .get(peer_mac)
            .cloned()
            .unwrap_or_else(|| json!({}));
        let moved = old.get("syzygy_sha").unwrap_or(&Value::Null)
            != peer.get("syzygy_sha").unwrap_or(&Value::Null)
            || old.get("beam_pair") != Some(&pair);
        let mut entry = old.clone();
        if !entry.is_object() {
            return Err("ruyi-peer-entry-malformed".into());
        }
        let mut lineage = match old.get("lineage") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(lineage)) => lineage.clone(),
            _ => return Err("ruyi-peer-lineage-malformed".into()),
        };
        let peer_perspective = roster.get("perspectives").and_then(|p| p.get(peer_mac));
        if moved {
            let flags = peer
                .get("member_flags")
                .or_else(|| peer_perspective.and_then(|p| p.pointer("/self/member_flags")));
            let source = |name: &str| {
                flags
                    .and_then(|f| f.get(name))
                    .and_then(|f| f.get("source_sha"))
                    .cloned()
                    .unwrap_or(Value::Null)
            };
            let gui = peer
                .get("gui_face")
                .and_then(Value::as_str)
                .map(str::to_ascii_lowercase);
            lineage.push(json!({"syzygy_sha": peer.get("syzygy_sha"),
                "release_flags": {"caduceus": peer.get("caduceus_sha"), "sbin": source("sbin"),
                    "gui": gui.as_deref().map(source).unwrap_or(Value::Null)},
                "seen_at": now()?}));
        }
        merge_fields(
            &mut entry,
            json!({"mac": peer_mac, "hostname": peer.get("hostname"),
            "canonical_name": peer.get("canonical_name"), "beam_pair": pair,
            "syzygy_sha": peer.get("syzygy_sha"), "lineage": lineage,
            "last_checked_in_at": peer.get("last_seen"), "seen_via": "gateway-roster"}),
        );
        perspective["seen"][peer_mac] = entry;
        if let Some(reflection) = peer_perspective
            .and_then(|p| p.get("seen"))
            .and_then(|seen| seen.get(mac))
        {
            if reflection.is_object() {
                merge_fields(
                    &mut perspective["their_view_of_me"][peer_mac],
                    reflection.clone(),
                );
                merge_fields(
                    &mut perspective["their_view_of_me"][peer_mac],
                    json!({"syzygy_sha": reflection.get("syzygy_sha"),
                        "beam_pair": reflection.get("beam_pair"),
                        "at": reflection.get("last_checked_in_at")}),
                );
            }
        }
    }
    let roster_macs = staves
        .iter()
        .filter_map(|peer| peer.get("mac").and_then(Value::as_str))
        .filter(|peer_mac| *peer_mac != mac)
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>();
    for field in ["seen", "their_view_of_me"] {
        perspective[field]
            .as_object_mut()
            .expect("validated perspective object")
            .retain(|peer_mac, _| roster_macs.contains(peer_mac));
    }
    Ok(())
}

/// StaffStart uses the existing self envelope; it never applies or moves a rung.
pub(crate) fn announce() -> Result<Value, String> {
    let run_id = crate::run_id_from_stamp();
    #[cfg(any(test, feature = "test-facade"))]
    let receipt_root = std::env::var_os("HARMONIA_RECEIPTS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/harmonia/receipts"));
    #[cfg(not(any(test, feature = "test-facade")))]
    let receipt_root = PathBuf::from("/var/lib/harmonia/receipts");
    let dir = receipt_root.join(&run_id);
    let seed_absent = match fs::symlink_metadata(ruyi_path()) {
        Ok(_) => false,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => return Err(format!("ruyi-state-read-failed: {error}")),
    };
    let identity = match local_identity() {
        Ok(identity) => identity,
        Err(error) => {
            let mut result = receipt(
                "pre-declaration",
                Value::Null,
                Vec::new(),
                "ruyi-identity-absent",
            );
            result["event"] = json!("staff-start");
            result["staff_start_wait_ms"] = json!(0);
            result["detail"] = json!(error);
            return save_receipt(&dir, result);
        }
    };
    let (profile, _) = match crate::device_profile::resolve_certificate_profile() {
        Ok(profile) => profile,
        Err(error) => {
            let mut result = receipt(
                "pre-declaration",
                Value::Null,
                Vec::new(),
                "ruyi-profile-absent",
            );
            result["event"] = json!("staff-start");
            result["staff_start_wait_ms"] = json!(0);
            result["detail"] = json!(error);
            return save_receipt(&dir, result);
        }
    };
    let Some(port) = port() else {
        let mut result = receipt(
            "pre-declaration",
            Value::Null,
            Vec::new(),
            "ruyi-seat-undeclared",
        );
        result["event"] = json!("staff-start");
        result["staff_start_wait_ms"] = json!(0);
        return save_receipt(&dir, result);
    };
    match fs::metadata(crate::device_profile::device_profile_certificate_path()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut result = receipt(
                "pre-declaration",
                Value::Null,
                Vec::new(),
                "ruyi-profile-absent",
            );
            result["event"] = json!("staff-start");
            result["staff_start_wait_ms"] = json!(0);
            return save_receipt(&dir, result);
        }
        Err(error) => return Err(format!("ruyi-profile-read-failed: {error}")),
        Ok(_) => {}
    }
    let (wait_ms, ready) = wait_for_staff();
    if seed_absent {
        if !ready {
            match fs::symlink_metadata(ruyi_path()) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let mut result = receipt(
                        "pre-declaration",
                        Value::Null,
                        Vec::new(),
                        "ruyi-beam-door-unavailable",
                    );
                    result["event"] = json!("staff-start");
                    result["staff_start_wait_ms"] = json!(wait_ms);
                    return save_receipt(&dir, result);
                }
                Err(error) => return Err(format!("ruyi-state-read-failed: {error}")),
                Ok(_) => {}
            }
        } else if let Err(signal) =
            persist_seed_if_absent(identity, profile.clone(), HARMONIA_BUILD_SHA, || {
                crate::atoms::ask::beam::door_url()
                    .ok()
                    .and_then(|url| crate::atoms::ask::beam::fetch_door(&url).ok())
            })
        {
            let mut result = receipt("pre-declaration", Value::Null, Vec::new(), &signal);
            result["event"] = json!("staff-start");
            result["staff_start_wait_ms"] = json!(wait_ms);
            return save_receipt(&dir, result);
        }
    }
    // Exhaustion is an unavailable seat observation, not another load timeout.
    let unavailable = unreachable_seats();
    let seats = if ready { at_start() } else { &unavailable };
    let mut prior = read_perspective_with_seats(seats)?;
    let Some(row) = prior.get("self").filter(|row| row.is_object()).cloned() else {
        let mut result = receipt(
            "pre-declaration",
            Value::Null,
            Vec::new(),
            "ruyi-self-row-absent",
        );
        result["event"] = json!("staff-start");
        result["staff_start_wait_ms"] = json!(wait_ms);
        return save_receipt(&dir, result);
    };
    let row = refresh_self_row_from_local_beam(row, &profile, HARMONIA_BUILD_SHA);
    prior["self"] = row.clone();
    let mut result = exchange(&profile, row, prior, seats, port)?;
    result["event"] = json!("staff-start");
    result["staff_start_wait_ms"] = json!(wait_ms);
    amend_update_set_held_back_by(&dir, &result["held_back_by"])?;
    save_receipt(&dir, result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn serve_one_ruyi_response(body: Value) -> (u16, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            let body = serde_json::to_vec(&body).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        });
        (port, handle)
    }

    #[test]
    fn local_seat_hostname_match_yields_self_is_gateway_after_normalization() {
        let (port, server) = serve_one_ruyi_response(json!({
            "schema": ROW_SCHEMA,
            "ok": true,
            "seat": {"hostname": "  HOME \n", "unknown": "kept"},
            "unknown": {"kept": true}
        }));

        assert!(self_is_gateway(
            &json!({}),
            port,
            &json!({"mac": "00:11:22:33:44:55", "hostname": " home "}),
        ));
        server.join().unwrap();
    }

    #[test]
    fn local_seat_hostname_mismatch_does_not_yield_self_is_gateway() {
        let (port, server) = serve_one_ruyi_response(json!({
            "schema": ROW_SCHEMA,
            "ok": true,
            "seat": {"hostname": "castle"}
        }));

        assert!(!self_is_gateway(
            &json!({}),
            port,
            &json!({"mac": "00:11:22:33:44:55", "hostname": "console"}),
        ));
        server.join().unwrap();
    }

    #[test]
    fn own_receipt_validation_refusal_is_saved_and_read_back() {
        let temp = tempfile::tempdir().unwrap();
        let seat = crate::atoms::ask::mint_seats::Seat::from_test_declaration(
            REGISTER,
            json!({
                "schema": REGISTER,
                "required": ["self"],
                "fields": {"self": {"nullable": false}}
            }),
        );
        let result = save_receipt_with_seat(
            temp.path(),
            json!({
                "schema": REGISTER,
                "state": "registered",
                "self": null,
                "roster": [],
                "unknown": {"kept": true}
            }),
            Some(&seat),
        )
        .unwrap();
        let saved: Value =
            serde_json::from_slice(&fs::read(temp.path().join("ruyi.json")).unwrap()).unwrap();
        assert_eq!(saved, result);
        assert_eq!(saved["state"], "refused");
        assert_eq!(
            saved["first_missing_signal"],
            "schema-frozen-kernel-missing harmonia.ruyi-register.v1 harmonia.ruyi-register.v1.self"
        );
        assert_eq!(saved["unknown"]["kept"], true);
    }

    static RUYI_PATH_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn first_event_history(gateway_reachable: bool) {
        let _guard = RUYI_PATH_TEST_LOCK.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("appliance/ruyi.json");
        let prior = std::env::var_os("HARMONIA_RUYI_PATH");
        std::env::set_var("HARMONIA_RUYI_PATH", &path);
        let identity = LocalIdentity {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            hostname: "arcadia".into(),
            ipv4: "192.0.2.1".into(),
            first_missing_signal: None,
        };
        let seeded = persist_seed_if_absent(
            identity,
            refresh_test_profile(),
            Some(&"d".repeat(40)),
            || Some(live_door(Some("1.98.0"))),
        )
        .unwrap();
        assert!(seeded);

        // This is the event's exchange boundary: the durable seed must already
        // be present before either a successful or unavailable gateway result.
        let persisted: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(persisted["schema"], PERSPECTIVE);
        assert_eq!(persisted["self"]["last_update"]["converged"], false);
        assert!(persisted["self"]["caduceus_port"].is_number());
        let result = if gateway_reachable {
            receipt("registered", persisted["self"].clone(), Vec::new(), "none")
        } else {
            receipt(
                "gateway-unreachable",
                persisted["self"].clone(),
                Vec::new(),
                "ruyi-gateway-unreachable",
            )
        };
        assert_eq!(
            result["state"],
            if gateway_reachable {
                "registered"
            } else {
                "gateway-unreachable"
            }
        );
        assert!(path.is_file(), "seed survives gateway outcome");
        match prior {
            Some(value) => std::env::set_var("HARMONIA_RUYI_PATH", value),
            None => std::env::remove_var("HARMONIA_RUYI_PATH"),
        }
    }

    #[test]
    fn first_event_seed_precedes_reachable_gateway_exchange() {
        first_event_history(true);
    }

    #[test]
    fn first_event_seed_survives_unreachable_gateway_exchange() {
        first_event_history(false);
    }

    fn refresh_test_profile() -> crate::Profile {
        crate::Profile {
            id: "homeconsole".into(),
            identity: "test".into(),
            package_authority: None,
            modules: vec!["caduceus".into()],
            hotfixes: Vec::new(),
            syzygy_declaration: None,
        }
    }

    fn stored_self_row() -> Value {
        json!({
            "schema": ROW_SCHEMA,
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "arcadia",
            "canonical_name": "arcadia.home.arpa",
            "ipv4": "192.0.2.1",
            "profile": "homeconsole",
            "gui_face": "Hyprland",
            "caduceus_port": 8443,
            "caduceus_sha": "d".repeat(40),
            "env_sha": "e".repeat(64),
            "harmonia_sha": "f".repeat(40),
            "syzygy_sha": "1".repeat(64),
            "last_seen": 7,
            "last_update": {"run_id": "run-stored", "converged": true},
            "lineage": ["stored-lineage"],
            "member_flags": {"stored": true},
            "identity": "stored-identity",
            "custom_addition": {"kept": true}
        })
    }

    fn live_door(rustc_version: Option<&str>) -> crate::atoms::ask::beam::BeamDoor {
        crate::atoms::ask::beam::BeamDoor {
            schema: crate::atoms::ask::beam::DOOR_SCHEMA.into(),
            ok: true,
            service: "caduceus".into(),
            caduceus_sha: "a".repeat(40),
            env_sha: "b".repeat(64),
            rustc_version: rustc_version.map(str::to_owned),
            profile: "homeconsole".into(),
            gui_face: Some("Arcadia".into()),
            syzygy_sha: Some("c".repeat(64)),
        }
    }

    #[test]
    fn live_beam_refresh_populates_door_fields_and_gateway_classifies_refreshed_row() {
        let harmonia_sha = "1".repeat(40);
        let refreshed = refresh_self_row_from_beam_observation(
            stored_self_row(),
            &refresh_test_profile(),
            Ok(live_door(Some("1.98.0"))),
            Some(&harmonia_sha),
        );
        assert!(refreshed["rustc_version"].is_string());
        assert_eq!(refreshed["rustc_version"], "1.98.0");
        assert_eq!(refreshed["caduceus_sha"], json!("a".repeat(40)));
        assert_eq!(refreshed["env_sha"], json!("b".repeat(64)));
        assert_eq!(refreshed["gui_face"], "Arcadia");
        assert_eq!(refreshed["syzygy_sha"], json!("c".repeat(64)));
        assert!(refreshed["last_seen"].as_u64().unwrap() > 7);
        assert_eq!(refreshed["lineage"], json!(["stored-lineage"]));
        assert_eq!(refreshed["last_update"]["run_id"], "run-stored");
        assert_eq!(refreshed["member_flags"]["stored"], true);
        assert_eq!(refreshed["harmonia_sha"], json!("f".repeat(40)));
        assert_eq!(refreshed["identity"], "stored-identity");
        assert_eq!(refreshed["custom_addition"]["kept"], true);

        let (port, server) = serve_one_ruyi_response(json!({
            "schema": ROW_SCHEMA,
            "ok": true,
            "seat": {"hostname": "arcadia"}
        }));
        assert!(self_is_gateway(&json!({}), port, &refreshed));
        server.join().unwrap();
    }

    #[test]
    fn omitted_rustc_preserves_stored_toolchain_and_non_gateway_classifies_refreshed_row() {
        let harmonia_sha = "1".repeat(40);
        let mut stored = stored_self_row();
        stored["rustc_version"] = json!("1.97.0");
        let refreshed = refresh_self_row_from_beam_observation(
            stored.clone(),
            &refresh_test_profile(),
            Ok(live_door(None)),
            Some(&harmonia_sha),
        );
        assert_eq!(refreshed["rustc_version"], stored["rustc_version"]);
        assert_eq!(refreshed["caduceus_sha"], json!("a".repeat(40)));
        assert_eq!(refreshed["env_sha"], json!("b".repeat(64)));
        assert_eq!(refreshed["gui_face"], "Arcadia");
        assert_eq!(refreshed["syzygy_sha"], json!("c".repeat(64)));
        assert_eq!(refreshed["lineage"], stored["lineage"]);
        assert_eq!(refreshed["last_update"], stored["last_update"]);
        assert_eq!(refreshed["member_flags"], stored["member_flags"]);
        assert_eq!(refreshed["harmonia_sha"], stored["harmonia_sha"]);
        assert!(refreshed["last_seen"].as_u64().unwrap() > stored["last_seen"].as_u64().unwrap());

        let (port, server) = serve_one_ruyi_response(json!({
            "schema": ROW_SCHEMA,
            "ok": true,
            "seat": {"hostname": "castle"}
        }));
        assert!(!self_is_gateway(&json!({}), port, &refreshed));
        server.join().unwrap();
    }

    #[test]
    fn unreachable_or_malformed_beam_leaves_stored_row_exactly_unchanged() {
        let stored = stored_self_row();
        for observation in [
            Err("beam-door-unreachable".to_string()),
            Err("beam-door-malformed".to_string()),
        ] {
            let harmonia_sha = "1".repeat(40);
            let refreshed = refresh_self_row_from_beam_observation(
                stored.clone(),
                &refresh_test_profile(),
                observation,
                Some(&harmonia_sha),
            );
            assert_eq!(refreshed, stored);
        }
    }

    #[test]
    fn mixed_fleet_seed_preserves_optional_door_toolchain_presence() {
        let identity = LocalIdentity {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            hostname: "arcadia".into(),
            ipv4: "192.0.2.1".into(),
            first_missing_signal: None,
        };
        let profile = crate::Profile {
            id: "homeconsole".into(),
            identity: "test".into(),
            package_authority: None,
            modules: vec!["caduceus".into()],
            hotfixes: Vec::new(),
            syzygy_declaration: None,
        };
        let raw = json!({
            "schema": crate::atoms::ask::beam::DOOR_SCHEMA,
            "ok": true,
            "service": "caduceus",
            "caduceus_sha": "a".repeat(40),
            "env_sha": "b".repeat(64),
            "profile": "homeconsole",
            "gui_face": "Arcadia",
            "syzygy_sha": null
        })
        .to_string();
        let legacy_door = crate::atoms::ask::beam::parse_door(&raw).unwrap();
        assert_eq!(legacy_door.rustc_version, None);
        let (_, legacy_perspective) = seed_perspective_for_with_harmonia_sha(
            identity.clone(),
            profile.clone(),
            Some(legacy_door),
            Some(&"c".repeat(40)),
        )
        .unwrap();
        assert!(legacy_perspective["self"].get("rustc_version").is_none());

        let mut present = serde_json::from_str::<Value>(&raw).unwrap();
        present["rustc_version"] = json!("1.82.0");
        let present_door = crate::atoms::ask::beam::parse_door(&present.to_string()).unwrap();
        let (_, present_perspective) = seed_perspective_for_with_harmonia_sha(
            identity,
            profile,
            Some(present_door),
            Some(&"c".repeat(40)),
        )
        .unwrap();
        assert_eq!(
            present_perspective["self"]["rustc_version"],
            json!("1.82.0")
        );
    }
}
