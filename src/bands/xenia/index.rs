use crate::tools::ladder::{LadderManifest, LadderStep, RoutineStep};
use crate::OperationOutcome;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::ffi::{CString, OsStr};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const REGISTER_PATH: &str = "/etc/appliance/xenia.json";
const UNIT_ROOT: &str = "/etc/systemd/system";
const HTTP_RESPONSE_CAP: usize = 1024 * 1024;
static DEBUG_SCHEMA_BASE: OnceLock<String> = OnceLock::new();
#[derive(Debug, Clone)]
pub(crate) struct Register {
    pub raw: Value,
    pub xenoi: BTreeMap<String, Value>,
    pub entry_refusals: BTreeMap<String, String>,
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
            entry_refusals: BTreeMap::new(),
        });
    }
    let bytes = fs::read(path)
        .map_err(|e| format!("xenia-register-read-failed {}: {e}", path.display()))?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Register {
            raw: json!({"schema":"appliance.xenia.v1","xenoi":{}}),
            xenoi: BTreeMap::new(),
            entry_refusals: BTreeMap::new(),
        });
    }
    let raw: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("xenia-register-malformed: {e}"))?;
    if raw.get("schema").and_then(Value::as_str) != Some("appliance.xenia.v1") {
        return Err("xenia-register-foreign-schema".into());
    }
    let seat = (match schema_base {
        Some(base) => crate::atoms::ask::mint_seats::Seat::load("appliance.xenia.v1", base),
        None => crate::atoms::ask::mint_seats::xenia(),
    })
    .map_err(|raw| format!("xenia-seat-unreachable reason={raw}"))?;
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
    let entry_refusals = xenoi
        .iter()
        .filter_map(|(id, entry)| {
            seat.validate(entry)
                .err()
                .or_else(|| {
                    (entry.get("id").and_then(Value::as_str) != Some(id.as_str()))
                        .then(|| format!("xenia-register-key-id-mismatch-{id}"))
                })
                .map(|reason| (id.clone(), reason))
        })
        .collect();
    Ok(Register {
        raw,
        xenoi,
        entry_refusals,
    })
}

fn repo_segment(repo: &str) -> &str {
    repo.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(repo)
}

fn unit_name(entry: &Value, id: &str) -> Result<String, String> {
    let derived = format!("{id}.service");
    match entry.pointer("/install/unit") {
        None | Some(Value::Null) => Ok(derived),
        Some(Value::String(unit)) if unit == &derived => Ok(derived),
        Some(_) => Err("xenia-unit-name-mismatch".into()),
    }
}

pub(crate) fn xenia_root() -> PathBuf {
    std::env::var_os("HARMONIA_XENIA_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/xenia"))
}

const CANONICAL_XENIA_ROOT: &str = "/var/lib/xenia";

fn rebased_install_bin(id: &str, entry: &Value) -> Result<Option<String>, String> {
    let Some(raw) = install_bin(entry) else {
        return Ok(None);
    };
    let canonical_seat = Path::new(CANONICAL_XENIA_ROOT).join(id);
    let path = Path::new(&raw);
    let relative = path
        .strip_prefix(&canonical_seat)
        .map_err(|_| "xenia-install-bin-path-mismatch".to_string())?;
    if relative.as_os_str().is_empty() || relative == Path::new(".") {
        return Err("xenia-install-bin-path-mismatch".into());
    }
    Ok(Some(
        xenia_root()
            .join(id)
            .join(relative)
            .display()
            .to_string(),
    ))
}

fn discovered_endpoint(entry: &Value) -> Option<&str> {
    entry.pointer("/discovered/endpoint").and_then(Value::as_str)
}

fn health_route(entry: &Value) -> String {
    entry
        .pointer("/health/route")
        .and_then(Value::as_str)
        .filter(|route| route.starts_with('/'))
        .unwrap_or("/health")
        .to_owned()
}

fn health_url(endpoint: &str, route: &str) -> String {
    let endpoint = endpoint.trim_end_matches('/');
    if endpoint.ends_with(route) {
        endpoint.to_owned()
    } else {
        format!("{endpoint}/{}", route.trim_start_matches('/'))
    }
}

fn source_kind(entry: &Value) -> Option<&str> {
    entry.pointer("/source/kind").and_then(Value::as_str)
}

fn install_bin(entry: &Value) -> Option<String> {
    entry
        .pointer("/install/bin")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|value| !value.trim().is_empty())
}

fn declaration(id: &str, entry: &Value) -> Result<LadderStep, String> {
    let release_repo = string(entry, "/source/release_repo")?;
    let _reference = string(entry, "/source/ref")?;
    let bin = rebased_install_bin(id, entry)?.ok_or("xenia-guest-not-installed")?;
    let unit = unit_name(entry, id)?;
    let owner = string(entry, "/install/owner")?;
    let binary_name = repo_segment(&release_repo).to_string();
    let args = BTreeMap::from([
        ("module_id".into(), json!("xenia")),
        ("component".into(), json!(id)),
        ("release_repo".into(), json!(release_repo)),
        ("install_bin".into(), json!(bin)),
        ("service".into(), json!(unit)),
        ("url".into(), json!(format!("xenia://{id}"))),
        ("binary_name".into(), json!(binary_name)),
        ("asset_name".into(), json!(format!("{binary_name}-x86_64"))),
        ("identity".into(), json!("embedded-sha")),
        ("source_dir".into(), json!(xenia_root().join(id))),
        ("bearer".into(), json!(owner)),
        ("op_prefix".into(), json!(format!("xenia-{id}"))),
        ("run_schema".into(), json!("harmonia.xenia.run.v1")),
        ("managed_files_schema".into(), json!("harmonia.xenia.files.v1")),
        ("xenia_entry".into(), entry.clone()),
    ]);
    Ok(LadderStep {
        step_id: format!("xenia-{id}"), tool: "service-runtime".into(),
        permutation: "converge".into(), args, steps: Vec::new(),
        on_failure: crate::tools::ladder::OnFailure::Stop, extra: BTreeMap::new(),
    })
}

fn refuse_entry(
    manifest: &mut LadderManifest,
    lowered: &mut Vec<LadderStep>,
    id: &str,
    reason: String,
) {
    let refusal = format!("xenia-plan-refused entry_id={id} reason={reason}");
    if manifest
        .plan_refusals
        .iter()
        .any(|existing| existing.starts_with(&format!("xenia-plan-refused entry_id={id} ")))
    {
        return;
    }
    manifest.plan_refusals.push(refusal);
    lowered.push(LadderStep {
        step_id: format!("xenia-refusal-{id}"),
        tool: "xenia-runtime".into(),
        permutation: "refusal".into(),
        args: BTreeMap::from([
            ("id".into(), json!(id)),
            ("reason".into(), json!(reason)),
        ]),
        steps: Vec::new(),
        on_failure: crate::tools::ladder::OnFailure::Stop,
        extra: BTreeMap::new(),
    });
}

pub(crate) fn lower_xenia_steps(manifest: &mut LadderManifest) -> Result<(), String> {
    if manifest.id != "xenia" {
        return Ok(());
    }
    if manifest.isolation.as_deref() != Some("per-step") {
        return Err("xenia-isolation-must-be-per-step".into());
    }
    let register = load_register(&register_path(), debug_schema_base())?;
    let mut entries: Vec<(String, Value)> = register.xenoi.clone().into_iter().collect();
    entries.sort_by(|(a_id, a), (b_id, b)| {
        let ap = a.get("priority").and_then(Value::as_i64).unwrap_or(100);
        let bp = b.get("priority").and_then(Value::as_i64).unwrap_or(100);
        ap.cmp(&bp).then_with(|| a_id.cmp(b_id))
    });
    if entries.is_empty() {
        manifest.module_observation = Some("register-empty".into());
    }
    let original = std::mem::take(&mut manifest.ladder);
    let mut lowered = Vec::new();
    for step in original {
        match (step.tool.as_str(), step.permutation.as_str()) {
            ("xenia", "converge") => {
                for (id, entry) in &entries {
                    if source_kind(entry) == Some("clone") {
                        refuse_entry(manifest, &mut lowered, id, "clone-road-retired".into());
                        continue;
                    }
                    if source_kind(entry) == Some("own-service") {
                        lowered.push(LadderStep {
                            step_id: format!("xenia-skip-{id}"),
                            tool: "xenia-runtime".into(),
                            permutation: "skip".into(),
                            args: BTreeMap::from([("id".into(), json!(id))]),
                            steps: Vec::new(),
                            on_failure: crate::tools::ladder::OnFailure::Stop,
                            extra: BTreeMap::new(),
                        });
                        continue;
                    }
                    if let Some(reason) = register.entry_refusals.get(id) {
                        refuse_entry(manifest, &mut lowered, id, reason.clone());
                        continue;
                    }
                    let kind = match string(entry, "/kind") {
                        Ok(kind) => kind,
                        Err(reason) => {
                            refuse_entry(manifest, &mut lowered, id, reason);
                            continue;
                        }
                    };
                    if kind == "iframe" {
                        continue;
                    }
                    if kind == "cartridge-static" {
                        refuse_entry(manifest, &mut lowered, id, "static-road-deferred".into());
                        continue;
                    }
                    if kind != "cartridge-process" {
                        refuse_entry(
                            manifest,
                            &mut lowered,
                            id,
                            "xenia-kind-unsupported".into(),
                        );
                        continue;
                    }
                    if entry.get("enabled").and_then(Value::as_bool).unwrap_or(true) {
                        match declaration(id, entry) {
                            Ok(step) => lowered.push(step),
                            Err(reason) => refuse_entry(manifest, &mut lowered, id, reason),
                        }
                    }
                }
            }
            _ => return Err("xenia-manifest-may-only-declare-converge".into()),
        }
    }
    manifest.ladder = lowered;
    Ok(())
}

pub(crate) fn reshape_routines(manifest: &mut LadderManifest) -> Result<(), String> {
    if manifest.id != "xenia" { return Ok(()); }
    for step in manifest.ladder.iter_mut().filter(|s| s.tool == "routine") {
        let entry = step.steps.iter().find_map(|c| c.args.get("xenia_entry").cloned())
            .ok_or("xenia-lowered-entry-missing")?;
        let id = string(&entry, "/id")?;
        let owner = string(&entry, "/install/owner")?;
        let bin = rebased_install_bin(&id, &entry)?.ok_or("xenia-guest-not-installed")?;
        let unit = unit_name(&entry, &id)?;
        let seat = xenia_root().join(&id).display().to_string();
        for child in &mut step.steps {
            child.args.remove("xenia_entry");
            if matches!(child.name.as_str(), "service-restart" | "service-active" | "unit-authority-proof") {
                child.args.remove("source_reference"); child.args.remove("source_remote");
            }
            if child.name == "pull-repo" {
                child.args.insert("authority".into(), json!("xenia-entry"));
                child.args.insert("entry_id".into(), json!(id));
                child.args.insert("entry".into(), entry.clone());
                let repo = string(&entry, "/source/release_repo")?;
                child.args.insert("release_repo".into(), json!(repo));
                child.args.insert("artifact_name".into(), json!(repo_segment(&repo)));
            }
            if child.name == "build" {
                child.args.insert("expected_digest".into(), json!({"from":"pull-repo.digest"}));
                child.args.insert("release_tag".into(), json!({"from":"pull-repo.release_tag"}));
                child.args.insert("road".into(), json!("artifact"));
            }
            if child.name == "binary-install" {
                child.args.insert("owner".into(), json!(owner));
                child.args.insert("uid".into(), json!({"from":"seat-present.uid"}));
                child.args.insert("gid".into(), json!({"from":"seat-present.gid"}));
                child.args.insert("mode".into(), json!({"from":"seat-present.mode"}));
                child.args.insert("expected_digest".into(), json!({"from":"pull-repo.digest"}));
                child.args.insert("road".into(), json!("artifact"));
                child.args.insert("digest_supplier".into(), json!("release"));
            }
            child.args.insert("hyalos_kind".into(), json!("xenia"));
            child.args.insert("hyalos_correlation_id".into(), json!(id));
        }
        let pull = step.steps.iter().position(|c| c.name == "pull-repo").ok_or("xenia-pull-repo-missing")?;
        step.steps.insert(pull, RoutineStep {
            name: "seat-present".into(), tool: "xenia-runtime".into(), permutation: Some("seat-present".into()),
            args: BTreeMap::from([("id".into(), json!(id)), ("owner".into(), json!(owner)),
                ("seat".into(), json!(seat)), ("unit".into(), json!(unit)), ("bin".into(), json!(bin))]),
            extra: BTreeMap::new(),
        });
        step.steps.retain(|child| !matches!(child.name.as_str(), "service-daemon-reload" | "service-enable"));
        let restart_pos = step.steps.iter().position(|c| c.name == "service-restart").ok_or("xenia-service-restart-missing")?;
        let restart = &mut step.steps[restart_pos];
        restart.args.insert("xenia_id".into(), json!(id));
        restart.args.insert("running_source_sha".into(), json!({"from":"health-read.running_source_sha"}));
        restart.args.insert("source_sha".into(), json!({"from":"build.source_build_sha"}));
        step.steps.insert(restart_pos, RoutineStep {
            name: "health-read".into(), tool: "check-health".into(), permutation: Some("probe".into()),
            args: BTreeMap::from([
                ("url".into(), json!(format!("xenia://{id}"))),
                ("id".into(), json!(id)),
                ("endpoint".into(), discovered_endpoint(&entry).map(Value::from).unwrap_or(Value::Null)),
                ("health_route".into(), json!(health_route(&entry))),
                ("xenia_health_read".into(), json!(true)),
            ]), extra: BTreeMap::new(),
        });
        let health = step.steps.iter_mut().find(|c| c.name == "health-proof").ok_or("xenia-health-missing")?;
        health.permutation = Some("status-door".into());
        health.args = BTreeMap::from([
            ("id".into(), json!(id)), ("resolved_commit".into(), json!({"from":"build.source_build_sha"})),
            ("endpoint".into(), discovered_endpoint(&entry).map(Value::from).unwrap_or(Value::Null)),
            ("health_route".into(), json!(health_route(&entry))),
        ]);
        let health_pos = step.steps.iter().position(|c| c.name == "health-proof").ok_or("xenia-health-missing")?;
        step.steps.insert(health_pos + 1, RoutineStep {
            name: "observe-stamp".into(), tool: "xenia-runtime".into(), permutation: Some("observe-stamp".into()),
            args: BTreeMap::from([
                ("id".into(), json!(id)), ("source_sha".into(), json!({"from":"health-proof.running_source_sha"})),
                ("health".into(), json!({"from":"health-proof.health"})), ("endpoint".into(), json!({"from":"health-proof.endpoint"})),
                ("version".into(), json!({"from":"pull-repo.version"})),
                ("binary_changed".into(), json!({"from":"binary-install.changed"})),
                ("restart_changed".into(), json!({"from":"service-restart.changed"})),
            ]), extra: BTreeMap::new(),
        });
    }
    Ok(())
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

fn remaining(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| "xenia-observe-unreachable".to_string())
}

fn http(
    method: &str,
    url: &str,
    body: Option<&Value>,
    timeout: Duration,
) -> Result<(u16, Value), String> {
    let deadline = Instant::now() + timeout;
    let rest = url
        .strip_prefix("http://")
        .ok_or("xenia-http-scheme-unsupported")?;
    let (host, path) = rest
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((rest, "/".into()));
    let addresses = host
        .to_socket_addrs()
        .map_err(|_| "xenia-observe-unreachable".to_string())?;
    let mut stream = None;
    for address in addresses {
        let timeout = remaining(deadline)?;
        if let Ok(connected) = TcpStream::connect_timeout(&address, timeout) {
            stream = Some(connected);
            break;
        }
    }
    let mut stream = stream.ok_or("xenia-observe-unreachable")?;
    let bytes = body
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    stream
        .set_write_timeout(Some(remaining(deadline)?))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(request.as_bytes())
        .map_err(|_| "xenia-observe-unreachable")?;
    stream
        .set_write_timeout(Some(remaining(deadline)?))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&bytes)
        .map_err(|_| "xenia-observe-unreachable")?;
    let mut response = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|e| e.to_string())?;
        let read = stream
            .read(&mut chunk)
            .map_err(|_| "xenia-observe-unreachable")?;
        if read == 0 {
            break;
        }
        if response.len() + read > HTTP_RESPONSE_CAP {
            return Err("xenia-http-response-too-large".into());
        }
        response.extend_from_slice(&chunk[..read]);
    }
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

fn open_xenia_seat_parent(path: &Path) -> Result<(File, CString), String> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err("xenia-seat-path-invalid".into());
    }
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => components.push(name),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err("xenia-seat-path-invalid".into());
            }
        }
    }
    let name = components
        .pop()
        .ok_or_else(|| "xenia-seat-path-invalid".to_string())?;
    let mut directory =
        File::open("/").map_err(|error| format!("xenia-seat-root-open-failed: {error}"))?;
    for component in components {
        let component = CString::new(component.as_bytes())
            .map_err(|_| "xenia-seat-path-invalid".to_string())?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::ENOENT) => Err("xenia-seat-parent-absent".into()),
                Some(libc::ELOOP) | Some(libc::ENOTDIR) => {
                    Err("xenia-seat-path-symlink-or-not-directory".into())
                }
                _ => Err(format!("xenia-seat-parent-open-failed: {error}")),
            };
        }
        directory = unsafe { File::from_raw_fd(fd) };
    }
    let name = CString::new(name.as_bytes()).map_err(|_| "xenia-seat-path-invalid".to_string())?;
    Ok((directory, name))
}

fn open_xenia_seat_directory(path: &Path) -> Result<File, String> {
    let (parent, name) = open_xenia_seat_parent(path)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOENT) => Err("seat-absent".into()),
            Some(libc::ELOOP) | Some(libc::ENOTDIR) => {
                Err("xenia-seat-path-symlink-or-not-directory".into())
            }
            _ => Err(format!("xenia-seat-open-failed: {error}")),
        };
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_xenia_seat_file(directory: &File, name: &OsStr) -> Result<Option<File>, String> {
    let name_c =
        CString::new(name.as_bytes()).map_err(|_| "xenia-seat-entry-name-invalid".to_string())?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOENT) => Ok(None),
            Some(libc::ELOOP) => Err(format!(
                "xenia-seat-entry-symlink-refused {}",
                name.to_string_lossy()
            )),
            _ => Err(format!(
                "xenia-seat-entry-open-failed {}: {error}",
                name.to_string_lossy()
            )),
        };
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|error| {
        format!(
            "xenia-seat-entry-stat-failed {}: {error}",
            name.to_string_lossy()
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "xenia-seat-entry-not-regular {}",
            name.to_string_lossy()
        ));
    }
    if metadata.nlink() != 1 {
        return Err(format!(
            "xenia-seat-entry-hardlink-refused {}",
            name.to_string_lossy()
        ));
    }
    Ok(Some(file))
}

fn xenia_seat_present(
    args: &BTreeMap<String, Value>,
    _apply: bool,
) -> Result<(OperationOutcome, BTreeMap<String, Value>), String> {
    let id = args.get("id").and_then(Value::as_str).ok_or("xenia-id-missing")?;
    let owner = args.get("owner").and_then(Value::as_str).ok_or("xenia-owner-missing")?;
    let seat = Path::new(args.get("seat").and_then(Value::as_str).ok_or("xenia-seat-missing")?);
    let bin = Path::new(args.get("bin").and_then(Value::as_str).ok_or("xenia-guest-not-installed")?);
    let unit = args.get("unit").and_then(Value::as_str).ok_or("xenia-guest-not-installed")?;
    if seat != xenia_root().join(id) || bin.parent() != Some(seat) || unit != format!("{id}.service") {
        return Err("xenia-install-path-mismatch".into());
    }
    let directory = open_xenia_seat_directory(seat).map_err(|error| {
        if error == "seat-absent" || error == "xenia-seat-parent-absent" {
            "xenia-guest-not-installed".to_string()
        } else { error }
    })?;
    let binary = open_xenia_seat_file(&directory, bin.file_name().ok_or("xenia-guest-not-installed")?)?
        .ok_or("xenia-guest-not-installed")?;
    let meta = binary.metadata().map_err(|e| format!("xenia-binary-stat-failed: {e}"))?;
    if !unit_root().join(unit).is_file() {
        return Err("xenia-guest-not-installed".into());
    }
    let service = crate::atoms::ask::change_unit::observe_systemd_state("restart", unit, false, None, 30);
    if service.load_state.as_deref() != Some("loaded")
        || !matches!(service.active.as_deref(), Some("active" | "inactive" | "failed")) {
        return Err("xenia-unit-not-ready-for-update".into());
    }
    let (uid, gid) = crate::atoms::r#do::pull_repo::xenia_owner_ids(owner)
        .map_err(|_| "xenia-install-owner-unknown".to_string())?;
    if meta.uid() != uid || meta.gid() != gid {
        return Err("xenia-guest-ownership-mismatch".into());
    }
    Ok((OperationOutcome {
        ok: true, changed: false, skipped: false,
        message: "xenia-guest-installed".into(), command: None,
    }, BTreeMap::from([
        ("uid".into(), json!(uid)), ("gid".into(), json!(gid)),
        ("mode".into(), json!(meta.mode() & 0o7777)),
    ])))
}

pub(crate) fn execute_routine_child(
    permutation: &str,
    args: &BTreeMap<String, Value>,
    apply: bool,
) -> Result<(OperationOutcome, BTreeMap<String, Value>), String> {
    match permutation {
        "seat-present" => xenia_seat_present(args, apply),
        "observe-stamp" => {
            if args.get("binary_changed").and_then(Value::as_bool) != Some(true)
                && args.get("restart_changed").and_then(Value::as_bool) != Some(true) {
                return Ok((OperationOutcome {
                    ok: true, changed: false, skipped: true,
                    message: "xenia-binary-current".into(), command: None,
                }, BTreeMap::new()));
            }
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
            let source_sha = args.get("source_sha").cloned().unwrap_or(Value::Null);
            let health = args.get("health").cloned().unwrap_or(Value::Null);
            let version = args.get("version").cloned().unwrap_or(Value::Null);
            let endpoint = args.get("endpoint").cloned().unwrap_or(Value::Null);
            // Comparing local facts must not depend on an answering observe door.
            let path = register_path();
            let bytes = fs::read(&path)
                .map_err(|error| format!("xenia-register-read-failed {}: {error}", path.display()))?;
            let register: Value = serde_json::from_slice(&bytes)
                .map_err(|error| format!("xenia-register-malformed: {error}"))?;
            if register.get("schema").and_then(Value::as_str) != Some("appliance.xenia.v1") {
                return Err("xenia-register-foreign-schema".into());
            }
            let entry = register
                .get("xenoi")
                .and_then(|xenoi| xenoi.get(id))
                .ok_or_else(|| format!("xenia-observe-entry-absent id={id}"))?;
            let mut installed = json!({
                "version": version,
                "source_sha": source_sha,
                "kit_band": null,
                "health": health
            });
            let mut discovered = json!({
                "endpoint": endpoint,
                "content_kind": null,
                "rung": "probe"
            });
            let snapshot_differs = |name: &str, fields: &[&str], wanted: &Value| {
                let Some(current) = entry.get(name).and_then(Value::as_object) else {
                    return true;
                };
                fields.iter().any(|field| {
                    current.get(*field).unwrap_or(&Value::Null) != &wanted[*field]
                })
            };
            let installed_due = snapshot_differs(
                "installed",
                &["source_sha", "health", "version", "kit_band"],
                &installed,
            );
            let discovered_due = snapshot_differs(
                "discovered",
                &["endpoint"],
                &discovered,
            );
            if !installed_due && !discovered_due {
                return Ok((
                    OperationOutcome {
                        ok: true,
                        changed: false,
                        skipped: false,
                        message: "xenia-observe-current".into(),
                        command: None,
                    },
                    BTreeMap::new(),
                ));
            }
            let proved_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| format!("xenia-observe-clock-failed: {error}"))?
                .as_secs();
            installed["proved_at"] = json!(proved_at);
            discovered["at"] = json!(proved_at);
            let base = crate::atoms::ask::caduceus_door::base_url().map_err(str::to_owned)?;
            let post_observation = |payload: &Value| -> Result<bool, String> {
                let (status, value) = http(
                    "POST",
                    &format!("{base}/api/v1/xenia/{id}/observe"),
                    Some(payload),
                    Duration::from_secs(5),
                )
                .map_err(|_| "xenia-observe-unreachable".to_string())?;
                if status >= 500 {
                    return Err("xenia-observe-unreachable".into());
                }
                if (400..500).contains(&status)
                    || value.get("schema").and_then(Value::as_str)
                        != Some("caduceus.xenia.verdict.v1")
                    || value.get("ok").and_then(Value::as_bool) != Some(true)
                    || value.get("verdict").and_then(Value::as_str) != Some("admissible")
                {
                    let check = value
                        .get("check")
                        .or_else(|| value.get("verdict"))
                        .and_then(Value::as_str)
                        .unwrap_or("invalid-verdict");
                    return Err(format!("xenia-observe-refused {check}"));
                }
                if status != 200 {
                    return Err("xenia-observe-unreachable".into());
                }
                Ok(value.get("changed").and_then(Value::as_bool).unwrap_or(false))
            };
            let installed_changed = if installed_due {
                post_observation(&json!({"installed": installed}))?
            } else {
                false
            };
            let discovered_changed = if discovered_due {
                post_observation(&json!({"discovered": discovered}))?
            } else {
                false
            };
            Ok((
                OperationOutcome {
                    ok: true,
                    changed: installed_changed || discovered_changed,
                    skipped: false,
                    message: "xenia-observed".into(),
                    command: None,
                },
                BTreeMap::from([("verdict".into(), json!("admissible"))]),
            ))
        }
        _ => Err(format!(
            "xenia-runtime-permutation-unsupported-{permutation}"
        )),
    }
}

pub(crate) fn execute_refusal(
    args: &BTreeMap<String, Value>,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let id = args
        .get("id")
        .and_then(Value::as_str)
        .ok_or("xenia-id-missing")?;
    let reason = args
        .get("reason")
        .and_then(Value::as_str)
        .ok_or("xenia-refusal-reason-missing")?;
    if !apply {
        return Ok(OperationOutcome {
            ok: false,
            changed: false,
            skipped: true,
            message: format!("xenia-entry-refused id={id} reason={reason}"),
            command: None,
        });
    }
    let bounded_id = crate::hyalos::bounded_json_string(id, 96);
    let bounded_reason = crate::hyalos::bounded_json_string(reason, 320);
    let message = format!("xenia runtime outcome=failed id={bounded_id} reason={bounded_reason}");
    crate::hyalos::forward_bounded_receipt(
        "xenia",
        &message,
        Some(json!({"id":bounded_id,"outcome":"failed","reason":bounded_reason})),
        Some(false),
        Some(&bounded_id),
    );
    Ok(OperationOutcome {
        ok: false,
        changed: false,
        skipped: false,
        message: format!("xenia-entry-refused id={id} reason={reason}"),
        command: None,
    })
}

fn health_source_sha(value: &Value) -> Option<String> {
    value
        .get("running_source_sha")
        .or_else(|| value.get("source_sha"))
        .or_else(|| value.pointer("/runtime/running_source_sha"))
        .or_else(|| value.pointer("/runtime/source_sha"))
        .and_then(Value::as_str)
        .filter(|sha| !sha.is_empty())
        .map(str::to_owned)
}

pub(crate) fn execute_health_read(
    args: &BTreeMap<String, Value>,
) -> Result<(OperationOutcome, BTreeMap<String, Value>), String> {
    let id = args.get("id").and_then(Value::as_str).ok_or("xenia-id-missing")?;
    let endpoint = base_url(None).ok().and_then(|base| {
        http("GET", &format!("{base}/api/v1/xenia/status/{id}"), None, Duration::from_secs(3))
            .ok().filter(|(status, _)| *status == 200).and_then(|(_, value)| {
                value.pointer("/runtime/listeners/0/endpoint").and_then(Value::as_str)
                    .filter(|endpoint| !endpoint.trim().is_empty())
                    .or_else(|| value.pointer("/entry/discovered/endpoint").and_then(Value::as_str)
                        .filter(|endpoint| !endpoint.trim().is_empty()))
                    .map(str::to_owned)
            })
    }).or_else(|| args.get("endpoint").and_then(Value::as_str)
        .filter(|endpoint| !endpoint.trim().is_empty()).map(str::to_owned));
    let route = args.get("health_route").and_then(Value::as_str)
        .filter(|route| route.starts_with('/')).unwrap_or("/health");
    let running_source_sha = endpoint.and_then(|endpoint| {
        http("GET", &health_url(&endpoint, route), None, Duration::from_secs(3))
            .ok().filter(|(status, _)| *status == 200)
            .and_then(|(_, value)| health_source_sha(&value))
    });
    Ok((OperationOutcome {
        ok: true, changed: false, skipped: false,
        message: "xenia-health-read".into(), command: None,
    }, BTreeMap::from([("running_source_sha".into(), json!(running_source_sha))])))
}

pub(crate) fn execute_status_door(
    args: &BTreeMap<String, Value>,
) -> Result<(OperationOutcome, BTreeMap<String, Value>), String> {
    let base = base_url(None)?;
    execute_status_door_at_base(args, &base)
}

fn execute_status_door_at_base(
    args: &BTreeMap<String, Value>,
    base: &str,
) -> Result<(OperationOutcome, BTreeMap<String, Value>), String> {
    let id = args
        .get("id")
        .and_then(Value::as_str)
        .ok_or("xenia-id-missing")?;
    let expected = args
        .get("resolved_commit")
        .and_then(Value::as_str)
        .filter(|sha| !sha.is_empty())
        .ok_or("xenia-source-press-sha-missing")?;
    let retries = crate::atoms::health::DEFAULT_PROBE_RETRIES as u64;
    let pause = 1;
    let mut status_seen = false;
    let mut active_seen = false;
    let mut endpoint_seen = false;
    let mut last_health_error = None;
    for attempt in 0..retries {
        if let Ok((200, value)) = http(
            "GET",
            &format!("{base}/api/v1/xenia/status/{id}"),
            None,
            Duration::from_secs(3),
        ) {
            status_seen = true;
            if value.pointer("/runtime/state").and_then(Value::as_str) == Some("active") {
                active_seen = true;
                let endpoint = value
                    .pointer("/runtime/listeners/0/endpoint")
                    .and_then(Value::as_str)
                    .filter(|endpoint| !endpoint.trim().is_empty())
                    .or_else(|| {
                        args.get("endpoint")
                            .and_then(Value::as_str)
                            .filter(|endpoint| !endpoint.trim().is_empty())
                    })
                    .or_else(|| {
                        value
                            .pointer("/entry/discovered/endpoint")
                            .and_then(Value::as_str)
                            .filter(|endpoint| !endpoint.trim().is_empty())
                    });
                let Some(endpoint) = endpoint else {
                    last_health_error = Some("xenia-health-endpoint-missing");
                    if attempt + 1 < retries {
                        std::thread::sleep(Duration::from_secs(pause));
                    }
                    continue;
                };
                endpoint_seen = true;
                let route = args
                    .get("health_route")
                    .and_then(Value::as_str)
                    .filter(|route| route.starts_with('/'))
                    .unwrap_or("/health");
                let url = health_url(endpoint, route);
                match http("GET", &url, None, Duration::from_secs(3)) {
                    Ok((200, health_value)) => match health_source_sha(&health_value) {
                        None => last_health_error = Some("xenia-health-source-sha-missing"),
                        Some(running_source_sha) if running_source_sha != expected => {
                            last_health_error = Some("xenia-running-sha-mismatch")
                        }
                        Some(running_source_sha) => {
                            let mut out = BTreeMap::new();
                            out.insert("health".into(), json!("healthy"));
                            out.insert("running_source_sha".into(), json!(running_source_sha));
                            out.insert("endpoint".into(), Value::String(endpoint.to_owned()));
                            return Ok((
                                OperationOutcome {
                                    ok: true,
                                    changed: false,
                                    skipped: false,
                                    message: "xenia-healthy".into(),
                                    command: None,
                                },
                                out,
                            ));
                        }
                    },
                    _ => last_health_error = Some("xenia-health-unreachable"),
                }
            }
        }
        if attempt + 1 < retries {
            std::thread::sleep(Duration::from_secs(pause));
        }
    }
    if active_seen {
        if !endpoint_seen {
            Err("xenia-health-endpoint-missing".into())
        } else {
            Err(last_health_error.unwrap_or("xenia-health-unreachable").into())
        }
    } else if status_seen {
        Err("xenia-unit-not-active".into())
    } else {
        Err("xenia-unit-status-unreachable".into())
    }
}
