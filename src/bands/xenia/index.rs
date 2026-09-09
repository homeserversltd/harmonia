use crate::tools::ladder::{LadderManifest, LadderStep, RoutineStep};
use crate::OperationOutcome;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const REGISTER_PATH: &str = "/etc/appliance/xenia.json";
const UNIT_ROOT: &str = "/etc/systemd/system";
static DEBUG_SCHEMA_BASE: OnceLock<String> = OnceLock::new();
const FORBIDDEN_PREFIXES: &[&str] = &[
    "MemoryHigh",
    "MemoryMax",
    "MemorySwapMax",
    "MemoryMin",
    "MemoryLow",
    "ManagedOOM",
    "OOMScoreAdjust",
    "CPUQuota",
    "TasksMax",
    "Protect",
    "Private",
    "Restrict",
    "NoNewPrivileges",
    "ReadOnlyPaths",
    "ReadWritePaths",
    "InaccessiblePaths",
    "SystemCall",
    "LockPersonality",
    "MemoryDenyWriteExecute",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "DynamicUser",
];

#[derive(Debug, Clone)]
pub(crate) struct Register {
    pub raw: Value,
    pub xenoi: BTreeMap<String, Value>,
}

fn string(value: &Value, path: &str) -> Result<String, String> {
    value
        .pointer(path)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("xenia-register-field-missing-{path}"))
}

pub(crate) fn register_path() -> PathBuf {
    std::env::var_os("HARMONIA_XENIA_REGISTER")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(REGISTER_PATH))
}

pub(crate) fn unit_root() -> PathBuf {
    std::env::var_os("HARMONIA_XENIA_UNIT_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(UNIT_ROOT))
}

pub(crate) fn set_debug_schema_base(base: &str) -> Result<(), String> {
    let base = base.trim_end_matches('/');
    if base.is_empty() || !base.starts_with("http://") || base.contains(['\n', '\r']) {
        return Err("xenia-schema-base-invalid".into());
    }
    DEBUG_SCHEMA_BASE
        .set(base.to_owned())
        .map_err(|_| "xenia-schema-base-already-set".to_string())
}

fn debug_schema_base() -> Option<&'static str> {
    DEBUG_SCHEMA_BASE.get().map(String::as_str)
}

pub(crate) fn load_register(path: &Path, schema_base: Option<&str>) -> Result<Register, String> {
    if !path.exists() {
        return Ok(Register {
            raw: json!({"schema":"appliance.xenia.v1","xenoi":{}}),
            xenoi: BTreeMap::new(),
        });
    }
    let bytes = fs::read(path)
        .map_err(|e| format!("xenia-register-read-failed {}: {e}", path.display()))?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Register {
            raw: json!({"schema":"appliance.xenia.v1","xenoi":{}}),
            xenoi: BTreeMap::new(),
        });
    }
    let raw: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("xenia-register-malformed: {e}"))?;
    if raw.get("schema").and_then(Value::as_str) != Some("appliance.xenia.v1") {
        return Err("xenia-register-foreign-schema".into());
    }
    let seat = match schema_base {
        Some(base) => crate::atoms::ask::mint_seats::Seat::load("appliance.xenia.v1", base),
        None => crate::atoms::ask::mint_seats::xenia(),
    }?;
    seat.validate(&raw)?;
    let xenoi = match raw.get("xenoi") {
        None | Some(Value::Null) => BTreeMap::new(),
        Some(value) => value
            .as_object()
            .ok_or("xenia-register-xenoi-not-object")?
            .iter()
            .map(|(id, entry)| (id.clone(), entry.clone()))
            .collect(),
    };
    for (id, entry) in &xenoi {
        seat.validate(entry)?;
        if entry.get("id").and_then(Value::as_str) != Some(id) {
            return Err(format!("xenia-register-key-id-mismatch-{id}"));
        }
    }
    Ok(Register { raw, xenoi })
}

fn repo_segment(repo: &str) -> &str {
    repo.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(repo)
}

fn declaration(entry: &Value) -> Result<LadderStep, String> {
    let id = string(entry, "/id")?;
    let release_repo = string(entry, "/source/release_repo")?;
    let bin = string(entry, "/install/bin")?;
    let unit = string(entry, "/install/unit")?;
    if unit != format!("{id}.service") {
        return Err(format!("xenia-unit-name-mismatch:{id}"));
    }
    let owner = string(entry, "/install/owner")?;
    let binary_name = repo_segment(&release_repo).to_string();
    let args = BTreeMap::from([
        ("module_id".into(), json!("xenia")),
        ("component".into(), json!(id)),
        ("release_repo".into(), json!(release_repo)),
        (
            "release_tag".into(),
            entry.pointer("/source/ref").cloned().unwrap_or(Value::Null),
        ),
        ("install_bin".into(), json!(bin)),
        ("service".into(), json!(format!("{id}.service"))),
        ("url".into(), json!(format!("xenia://{id}"))),
        ("binary_name".into(), json!(binary_name)),
        (
            "asset_name".into(),
            json!(format!("{}-x86_64", repo_segment(&release_repo))),
        ),
        ("identity".into(), json!("embedded-sha")),
        ("source_dir".into(), json!(format!("/var/lib/xenia/{id}"))),
        ("bearer".into(), json!(owner)),
        ("op_prefix".into(), json!(format!("xenia-{id}"))),
        ("run_schema".into(), json!("harmonia.xenia.run.v1")),
        (
            "managed_files_schema".into(),
            json!("harmonia.xenia.files.v1"),
        ),
        ("xenia_entry".into(), entry.clone()),
    ]);
    Ok(LadderStep {
        step_id: format!("xenia-{id}"),
        tool: "service-runtime".into(),
        permutation: "converge".into(),
        args,
        steps: Vec::new(),
        on_failure: crate::tools::ladder::OnFailure::Stop,
        extra: BTreeMap::new(),
    })
}

pub(crate) fn lower_xenia_steps(manifest: &mut LadderManifest) -> Result<(), String> {
    if manifest.id != "xenia" {
        return Ok(());
    }
    if manifest.isolation.as_deref() != Some("per-step") {
        return Err("xenia-isolation-must-be-per-step".into());
    }
    let register = load_register(&register_path(), debug_schema_base())?;
    let mut entries: Vec<Value> = register.xenoi.values().cloned().collect();
    entries.sort_by(|a, b| {
        let ap = a.get("priority").and_then(Value::as_i64).unwrap_or(100);
        let bp = b.get("priority").and_then(Value::as_i64).unwrap_or(100);
        ap.cmp(&bp).then_with(|| {
            a.get("id")
                .and_then(Value::as_str)
                .cmp(&b.get("id").and_then(Value::as_str))
        })
    });
    if entries.is_empty() {
        manifest.module_observation = Some("register-empty".into());
    }
    let original = std::mem::take(&mut manifest.ladder);
    let mut lowered = Vec::new();
    for step in original {
        match (step.tool.as_str(), step.permutation.as_str()) {
            ("xenia", "converge") => {
                for entry in &entries {
                    let id = string(entry, "/id")?;
                    let kind = string(entry, "/kind")?;
                    if kind == "iframe"
                        || entry.get("client_class").and_then(Value::as_str) == Some("iframe")
                    {
                        continue;
                    }
                    if kind == "cartridge-static" {
                        manifest
                            .plan_refusals
                            .push(format!("static-road-deferred entry_id={id}"));
                        continue;
                    }
                    if kind != "cartridge-process" {
                        return Err(format!("xenia-kind-unsupported entry_id={id}"));
                    }
                    if entry.get("enabled").and_then(Value::as_bool).unwrap_or(true) {
                        lowered.push(declaration(entry)?);
                    }
                }
            }
            ("xenia", "retire") => {
                lowered.push(LadderStep {
                    step_id: "xenia-retire".into(),
                    tool: "xenia-runtime".into(),
                    permutation: "retire".into(),
                    args: BTreeMap::from([
                        ("register".into(), register.raw.clone()),
                        ("unit_root".into(), json!(unit_root())),
                    ]),
                    steps: Vec::new(),
                    on_failure: step.on_failure,
                    extra: BTreeMap::new(),
                });
            }
            _ => return Err("xenia-manifest-may-only-declare-converge-and-retire".into()),
        }
    }
    manifest.ladder = lowered;
    Ok(())
}

pub(crate) fn reshape_routines(manifest: &mut LadderManifest) -> Result<(), String> {
    if manifest.id != "xenia" {
        return Ok(());
    }
    for step in manifest.ladder.iter_mut().filter(|s| s.tool == "routine") {
        let entry = step
            .steps
            .first()
            .and_then(|c| c.args.get("xenia_entry"))
            .cloned()
            .or_else(|| {
                step.steps
                    .iter()
                    .find_map(|c| c.args.get("xenia_entry").cloned())
            })
            .ok_or("xenia-lowered-entry-missing")?;
        let id = string(&entry, "/id")?;
        let owner = string(&entry, "/install/owner")?;
        let bin = string(&entry, "/install/bin")?;
        let unit = string(&entry, "/install/unit")?;
        let seat = format!("/var/lib/xenia/{id}");
        let bind = match debug_schema_base() {
            Some(base) => base.to_owned(),
            None => crate::atoms::ask::caduceus_door::base_url()
                .map(str::to_owned)
                .map_err(|_| "caduceus-bind-undeclared".to_string())?,
        };
        let environment = BTreeMap::from([
            ("XENIA_ID".to_string(), id.clone()),
            ("XENIA_SEAT".to_string(), seat.clone()),
            ("XENIA_SCHEMA_BASE".to_string(), bind),
        ]);
        for child in &mut step.steps {
            child.args.remove("xenia_entry");
            if child.name == "pull-repo" {
                child.args.insert("authority".into(), json!("xenia-entry"));
                child.args.insert("entry_id".into(), json!(id));
                child.args.insert("entry".into(), entry.clone());
                if let Some(repo) = entry
                    .pointer("/source/release_repo")
                    .and_then(Value::as_str)
                {
                    child.args.insert("release_repo".into(), json!(repo));
                    child
                        .args
                        .insert("artifact_name".into(), json!(repo_segment(repo)));
                }
            }
            if child.name == "build" {
                child
                    .args
                    .insert("expected_digest".into(), json!({"from":"pull-repo.digest"}));
            }
            if child.name == "binary-install" {
                child.args.insert("owner".into(), json!(owner));
                child
                    .args
                    .insert("uid".into(), json!({"from":"seat-present.uid"}));
                child
                    .args
                    .insert("gid".into(), json!({"from":"seat-present.gid"}));
                child
                    .args
                    .insert("expected_digest".into(), json!({"from":"pull-repo.digest"}));
            }
        }
        let install = step
            .steps
            .iter()
            .position(|c| c.name == "binary-install")
            .ok_or("xenia-binary-install-missing")?;
        step.steps.insert(
            install,
            RoutineStep {
                name: "seat-present".into(),
                tool: "xenia-runtime".into(),
                permutation: Some("seat-present".into()),
                args: BTreeMap::from([
                    ("id".into(), json!(id)),
                    ("owner".into(), json!(owner)),
                    ("seat".into(), json!(seat)),
                ]),
                extra: BTreeMap::new(),
            },
        );
        let reload = step
            .steps
            .iter()
            .position(|c| c.name == "service-daemon-reload")
            .ok_or("xenia-daemon-reload-missing")?;
        step.steps.insert(
            reload,
            RoutineStep {
                name: "unit-render".into(),
                tool: "place-file".into(),
                permutation: Some("unit-render".into()),
                args: BTreeMap::from([
                    ("unit".into(), json!(unit)),
                    ("xenia_id".into(), json!(id)),
                    ("description".into(), json!(format!("Xenia guest {id}"))),
                    ("exec_start".into(), json!(bin)),
                    ("working_directory".into(), json!(seat)),
                    ("user".into(), json!(owner)),
                    ("group".into(), json!(owner)),
                    ("environment".into(), json!(environment)),
                ]),
                extra: BTreeMap::new(),
            },
        );
        if let Some(health) = step.steps.iter_mut().find(|c| c.name == "health-proof") {
            health.permutation = Some("status-door".into());
            health.args = BTreeMap::from([
                ("id".into(), json!(id)),
                ("retries".into(), json!(3)),
                ("retry_seconds".into(), json!(3)),
            ]);
        }
        let health = step
            .steps
            .iter()
            .position(|c| c.name == "health-proof")
            .ok_or("xenia-health-missing")?;
        step.steps.insert(
            health + 1,
            RoutineStep {
                name: "observe-stamp".into(),
                tool: "xenia-runtime".into(),
                permutation: Some("observe-stamp".into()),
                args: BTreeMap::from([
                    ("id".into(), json!(id)),
                    (
                        "source_sha".into(),
                        json!({"from":"pull-repo.resolved_commit"}),
                    ),
                    ("health".into(), json!({"from":"health-proof.health"})),
                    ("version".into(), json!({"from":"pull-repo.version"})),
                ]),
                extra: BTreeMap::new(),
            },
        );
    }
    Ok(())
}

pub(crate) fn unit_render_path(args: &BTreeMap<String, Value>) -> Option<PathBuf> {
    let unit = args.get("unit").and_then(Value::as_str)?;
    args.get("xenia_id").and_then(Value::as_str)?;
    Some(unit_root().join(unit))
}

pub(crate) fn render_unit(
    unit: &str,
    xenia_id: &str,
    description: &str,
    exec_start: &str,
    working_directory: &str,
    user: &str,
    group: &str,
    environment: &BTreeMap<String, String>,
) -> Result<String, String> {
    for (name, value) in [
        ("unit", unit),
        ("xenia_id", xenia_id),
        ("description", description),
        ("exec_start", exec_start),
        ("working_directory", working_directory),
        ("user", user),
        ("group", group),
    ] {
        if value.trim().is_empty() || value.contains(['\n', '\r']) {
            return Err(format!("xenia-unit-{name}-invalid"));
        }
    }
    let seat = format!("/var/lib/xenia/{xenia_id}");
    if unit != format!("{xenia_id}.service")
        || description != format!("Xenia guest {xenia_id}")
        || working_directory != seat
        || user != group
        || !exec_start.starts_with(&format!("{seat}/"))
        || environment.get("XENIA_ID").map(String::as_str) != Some(xenia_id)
        || environment.get("XENIA_SEAT").map(String::as_str) != Some(seat.as_str())
        || !environment
            .get("XENIA_SCHEMA_BASE")
            .is_some_and(|value| value.starts_with("http://") && !value.contains(['\n', '\r']))
        || environment.len() != 3
    {
        return Err("xenia-unit-contract-mismatch".into());
    }
    let bytes = format!("[Unit]\nDescription={description}\nX-Xenia-Id={xenia_id}\nAfter=network.target caduceus.service\n\n[Service]\nType=simple\nUser={user}\nGroup={group}\nWorkingDirectory={working_directory}\nEnvironment=XENIA_ID={}\nEnvironment=XENIA_SEAT={}\nEnvironment=XENIA_SCHEMA_BASE={}\nExecStart={exec_start}\nRestart=on-failure\nRestartSec=2\n\n[Install]\nWantedBy=multi-user.target\n", environment["XENIA_ID"], environment["XENIA_SEAT"], environment["XENIA_SCHEMA_BASE"]);
    let forbidden = forbidden_directives(&bytes);
    if !forbidden.is_empty() {
        return Err(format!(
            "xenia-unit-forbidden-directives {}",
            forbidden.join(",")
        ));
    }
    Ok(bytes)
}

pub(crate) fn forbidden_directives(bytes: &str) -> Vec<String> {
    bytes
        .lines()
        .filter_map(|line| line.split_once('=').map(|(key, _)| key.trim()))
        .filter(|key| {
            FORBIDDEN_PREFIXES
                .iter()
                .any(|prefix| key.starts_with(prefix))
        })
        .map(str::to_owned)
        .collect()
}

fn base_url(explicit: Option<&str>) -> Result<String, String> {
    if let Some(value) = explicit {
        Ok(format!("http://{}", value.trim_start_matches("http://")))
    } else {
        crate::atoms::ask::caduceus_door::base_url()
            .map(str::to_owned)
            .map_err(str::to_owned)
    }
}

fn http(
    method: &str,
    url: &str,
    body: Option<&Value>,
    timeout: Duration,
) -> Result<(u16, Value), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or("xenia-http-scheme-unsupported")?;
    let (host, path) = rest
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((rest, "/".into()));
    let mut stream = host
        .to_socket_addrs()
        .map_err(|_| "xenia-observe-unreachable".to_string())?
        .find_map(|a| TcpStream::connect_timeout(&a, timeout).ok())
        .ok_or("xenia-observe-unreachable")?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    let bytes = body
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    write!(stream,"{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len()).map_err(|_|"xenia-observe-unreachable")?;
    stream
        .write_all(&bytes)
        .map_err(|_| "xenia-observe-unreachable")?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|_| "xenia-observe-unreachable")?;
    let text = String::from_utf8_lossy(&response);
    let (head, body) = text.split_once("\r\n\r\n").ok_or("xenia-http-malformed")?;
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .ok_or("xenia-http-status-missing")?;
    let value = serde_json::from_str(body).unwrap_or(Value::Null);
    Ok((status, value))
}

pub(crate) fn execute_routine_child(
    permutation: &str,
    args: &BTreeMap<String, Value>,
    apply: bool,
) -> Result<(OperationOutcome, BTreeMap<String, Value>), String> {
    match permutation {
        "seat-present" => {
            let owner = args
                .get("owner")
                .and_then(Value::as_str)
                .ok_or("xenia-owner-missing")?;
            let seat = args
                .get("seat")
                .and_then(Value::as_str)
                .ok_or("xenia-seat-missing")?;
            let account = crate::command_capture("getent", &["passwd", owner]);
            if !account.ok {
                return Err("owner-absent".into());
            }
            if !Path::new(seat).is_dir() {
                return Err("seat-absent".into());
            }
            let fields: Vec<&str> = account.stdout.trim().split(':').collect();
            let uid = fields
                .get(2)
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or("owner-absent")?;
            let gid = fields
                .get(3)
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or("owner-absent")?;
            Ok((
                OperationOutcome {
                    ok: true,
                    changed: false,
                    skipped: false,
                    message: "xenia-seat-present".into(),
                    command: None,
                },
                BTreeMap::from([("uid".into(), json!(uid)), ("gid".into(), json!(gid))]),
            ))
        }
        "observe-stamp" => {
            if !apply {
                return Ok((
                    OperationOutcome {
                        ok: true,
                        changed: false,
                        skipped: true,
                        message: "xenia-observe-planned".into(),
                        command: None,
                    },
                    BTreeMap::new(),
                ));
            }
            let id = args
                .get("id")
                .and_then(Value::as_str)
                .ok_or("xenia-id-missing")?;
            let health = args.get("health").cloned().unwrap_or(Value::Null);
            let source_sha = args.get("source_sha").cloned().unwrap_or(Value::Null);
            let version = args.get("version").cloned().unwrap_or(Value::Null);
            let proved_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs();
            let payload = json!({"installed":{"version":version,"source_sha":source_sha,"kit_band":null,"proved_at":proved_at,"health":health}});
            let base = base_url(None)?;
            let (status, value) = http(
                "POST",
                &format!("{base}/api/v1/xenia/{id}/observe"),
                Some(&payload),
                Duration::from_secs(5),
            )
            .map_err(|_| "xenia-observe-unreachable".to_string())?;
            if status != 200 || value.get("ok").and_then(Value::as_bool) == Some(false) {
                let check = value
                    .get("check")
                    .or_else(|| value.get("verdict"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                return Err(format!("xenia-observe-refused {check}"));
            }
            let mut out = BTreeMap::new();
            out.insert("entry".into(), value);
            Ok((
                OperationOutcome {
                    ok: true,
                    changed: false,
                    skipped: false,
                    message: "xenia-observed".into(),
                    command: None,
                },
                out,
            ))
        }
        _ => Err(format!(
            "xenia-runtime-permutation-unsupported-{permutation}"
        )),
    }
}

pub(crate) fn execute_status_door(
    args: &BTreeMap<String, Value>,
) -> Result<(OperationOutcome, BTreeMap<String, Value>), String> {
    let id = args
        .get("id")
        .and_then(Value::as_str)
        .ok_or("xenia-id-missing")?;
    let retries = args.get("retries").and_then(Value::as_u64).unwrap_or(3);
    let pause = args
        .get("retry_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(3);
    let base = base_url(None)?;
    for attempt in 0..retries {
        if let Ok((200, value)) = http(
            "GET",
            &format!("{base}/api/v1/xenia/status/{id}"),
            None,
            Duration::from_secs(3),
        ) {
            if value.pointer("/runtime/state").and_then(Value::as_str) == Some("active") {
                let listeners = value
                    .pointer("/runtime/listeners")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0);
                let health = if listeners > 0 { "healthy" } else { "degraded" };
                let mut out = BTreeMap::new();
                out.insert("health".into(), json!(health));
                out.insert("status".into(), value);
                return Ok((
                    OperationOutcome {
                        ok: true,
                        changed: false,
                        skipped: false,
                        message: format!("xenia-{health}"),
                        command: None,
                    },
                    out,
                ));
            }
        }
        if attempt + 1 < retries {
            std::thread::sleep(Duration::from_secs(pause));
        }
    }
    Err("xenia-unit-not-active".into())
}

fn remove_marked_unit(
    receipt_dir: &Path,
    name: &str,
    service: &str,
    path: &Path,
    apply: bool,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let before = crate::atoms::r#do::remove_unit::observe(service, Some(path), false, None, 30);
    if !before.unit_file_exists {
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "xenia-unit-already-absent".into(),
            command: None,
        });
    }
    if !apply {
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: format!("planned remove-unit disable-stop-remove {service}"),
            command: None,
        });
    }
    let invocation = invocation.ok_or("invocation-key-missing")?;
    let run = crate::atoms::comparison::execute_once(
        "xenia-remove-unit",
        || Ok::<_, String>(before.clone()),
        |_| crate::atoms::comparison::DiffDecision::Different,
        |authorization, _| {
            crate::atoms::r#do::remove_unit::act(
                authorization,
                invocation,
                service,
                "disable-stop-remove",
                Some(path),
                false,
                None,
                30,
            )
        },
    )?;
    let command = match run {
        crate::atoms::comparison::ComparisonRun::Moved { movement, .. } => movement,
        crate::atoms::comparison::ComparisonRun::Current { .. } => unreachable!(),
    };
    crate::atoms::r#do::remove_unit::report_home(
        service,
        &receipt_dir.join(format!("{name}.json")),
        &command,
    )?;
    Ok(OperationOutcome {
        ok: command.ok,
        changed: command.ok,
        skipped: false,
        message: if command.ok {
            "xenia-unit-retired".into()
        } else {
            "xenia-unit-retire-failed".into()
        },
        command: Some(command),
    })
}

pub(crate) fn execute_retire(
    args: &BTreeMap<String, Value>,
    apply: bool,
    receipt_dir: &Path,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    let register = args
        .get("register")
        .cloned()
        .unwrap_or_else(|| json!({"xenoi":{}}));
    let entries = register
        .get("xenoi")
        .and_then(Value::as_object);
    let declared: std::collections::BTreeMap<String, bool> = entries
        .into_iter()
        .flat_map(|entries| entries.iter())
        .map(|(id, entry)| {
            (
                id.clone(),
                entry.get("enabled").and_then(Value::as_bool).unwrap_or(true),
            )
        })
        .collect();
    let root = args
        .get("unit_root")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(unit_root);
    let mut changed = false;
    let mut first_failure = None;
    let mut retirements = Vec::new();
    let read = match fs::read_dir(&root) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(OperationOutcome {
                ok: true,
                changed: false,
                skipped: !apply,
                message: "xenia-retire-empty".into(),
                command: None,
            })
        }
        Err(e) => return Err(format!("xenia-unit-root-read-failed: {e}")),
    };
    for item in read.flatten() {
        let path = item.path();
        if path.extension().and_then(|v| v.to_str()) != Some("service") {
            continue;
        }
        let text = match fs::read_to_string(&path) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(id) = text.lines().find_map(|l| l.strip_prefix("X-Xenia-Id=")) else {
            continue;
        };
        let action = match declared.get(id) {
            None => "disable-stop-remove",
            Some(false) => "disable-stop",
            Some(true) => continue,
        };
        let service = format!("{id}.service");
        let outcome = if action == "disable-stop-remove" {
            remove_marked_unit(
                receipt_dir,
                &format!("xenia-retire-{id}"),
                &service,
                &path,
                apply,
                invocation,
            )
        } else {
            crate::tools::systemd::run_permutation_with_policy(
                receipt_dir,
                &format!("xenia-retire-{id}"),
                action,
                Some(&service),
                &[],
                None,
                30,
                apply,
                false,
                None,
                invocation,
            )
        };
        match outcome {
            Ok(outcome) => {
                changed |= outcome.changed;
                if !outcome.ok {
                    first_failure.get_or_insert_with(|| format!("xenia-retire-{action}-failed"));
                }
                retirements.push((id.to_string(), action.to_string(), outcome.ok));
            }
            Err(error) => {
                first_failure.get_or_insert_with(|| error.clone());
                retirements.push((id.to_string(), action.to_string(), false));
            }
        }
    }
    if retirements.iter().any(|(_, action, ok)| action == "disable-stop-remove" && *ok) {
        match crate::atoms::systemd::run_permutation(
            receipt_dir,
            "xenia-retire-daemon-reload",
            "daemon-reload",
            None,
            &[],
            None,
            30,
            apply,
            true,
            invocation,
        ) {
            Ok(outcome) if outcome.ok => changed |= outcome.changed,
            Ok(_) => {
                first_failure.get_or_insert_with(|| "xenia-retire-daemon-reload-failed".into());
                for (_, action, ok) in &mut retirements {
                    if action == "disable-stop-remove" {
                        *ok = false;
                    }
                }
            }
            Err(error) => {
                first_failure.get_or_insert(error);
                for (_, action, ok) in &mut retirements {
                    if action == "disable-stop-remove" {
                        *ok = false;
                    }
                }
            }
        }
    }
    if apply {
        for (id, action, ok) in &retirements {
            crate::hyalos::forward_receipt(
                "xenia",
                &format!("xenia retirement outcome={} id={id} action={action}", if *ok { "retired" } else { "failed" }),
                Some(json!({"id":id,"action":action,"outcome":if *ok {"retired"} else {"failed"}})),
                Some(*ok),
                Some(id),
            );
        }
    }
    let ok = first_failure.is_none();
    Ok(OperationOutcome {
        ok,
        changed,
        skipped: !apply,
        message: first_failure.unwrap_or_else(|| "xenia-retire-complete".into()),
        command: None,
    })
}
