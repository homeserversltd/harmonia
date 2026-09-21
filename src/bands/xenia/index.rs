use crate::tools::ladder::{LadderManifest, LadderStep, RoutineStep};
use crate::OperationOutcome;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const REGISTER_PATH: &str = "/etc/appliance/xenia.json";
const UNIT_ROOT: &str = "/etc/systemd/system";
const HTTP_RESPONSE_CAP: usize = 1024 * 1024;
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
    let clone = source_kind(entry) == Some("clone");
    let (release_repo, requested_ref) = if clone {
        let repo = string(entry, "/source/repo")?;
        let reference = string(entry, "/source/ref")?;
        (repo, Some(reference))
    } else {
        (string(entry, "/source/release_repo")?, None)
    };
    let bin = rebased_install_bin(id, entry)?;
    if !clone && bin.is_none() {
        return Err("xenia-install-bin-missing".into());
    }
    let unit = unit_name(entry, id)?;
    let owner = string(entry, "/install/owner")?;
    let binary_name = if clone {
        bin.as_deref()
            .and_then(|value| Path::new(value).file_name())
            .and_then(|value| value.to_str())
            .map(str::to_owned)
            .unwrap_or_else(|| repo_segment(&release_repo).to_string())
    } else {
        repo_segment(&release_repo).to_string()
    };
    let face = bin.is_some();
    let mut args = BTreeMap::from([
        ("module_id".into(), json!("xenia")),
        ("component".into(), json!(id)),
        ("release_repo".into(), json!(release_repo)),
        ("release_ref".into(), json!(requested_ref)),
        ("source_kind".into(), json!(if clone { "clone" } else { "release" })),
        ("source_policy".into(), json!(if clone { "source" } else { "artifact" })),
        ("face".into(), json!(face)),
        ("install_bin".into(), json!(bin)),
        ("service".into(), json!(unit)),
        ("url".into(), json!(format!("xenia://{id}"))),
        ("binary_name".into(), json!(binary_name.clone())),
        ("asset_name".into(), json!(format!("{binary_name}-x86_64"))),
        ("identity".into(), json!("embedded-sha")),
        ("source_dir".into(), json!(xenia_root().join(id))),
        ("bearer".into(), json!(owner)),
        ("op_prefix".into(), json!(format!("xenia-{id}"))),
        ("run_schema".into(), json!("harmonia.xenia.run.v1")),
        ("managed_files_schema".into(), json!("harmonia.xenia.files.v1")),
        ("xenia_entry".into(), entry.clone()),
    ]);
    if !clone {
        args.remove("release_ref");
        args.remove("source_kind");
        args.remove("source_policy");
        args.remove("face");
    }
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
        let rebased_bin = rebased_install_bin(&id, &entry)?;
        let face = rebased_bin.is_some();
        let bin = rebased_bin.unwrap_or_else(|| xenia_root().join(&id).join("__no-face__").display().to_string());
        let unit = unit_name(&entry, &id)?;
        let seat = xenia_root().join(&id).display().to_string();
        let clone = source_kind(&entry) == Some("clone");
        let bind = if !face {
            String::new()
        } else {
            match debug_schema_base() {
                Some(base) => base.to_owned(),
                None => crate::atoms::ask::caduceus_door::base_url()
                    .map(str::to_owned)
                    .map_err(|_| "caduceus-bind-undeclared".to_string())?,
            }
        };
        let environment = BTreeMap::from([
            ("XENIA_ID".to_string(), id.clone()),
            ("XENIA_SEAT".to_string(), seat.clone()),
            ("XENIA_SCHEMA_BASE".to_string(), bind),
        ]);
        for child in &mut step.steps {
            child.args.remove("xenia_entry");
            if matches!(
                child.name.as_str(),
                "service-daemon-reload"
                    | "service-enable"
                    | "service-restart"
                    | "service-active"
                    | "unit-authority-proof"
            ) {
                child.args.remove("source_reference");
                child.args.remove("source_remote");
            }
            if child.name == "pull-repo" {
                child.args.insert("authority".into(), json!("xenia-entry"));
                child.args.insert("entry_id".into(), json!(id));
                child.args.insert("entry".into(), entry.clone());
                if let Some(repo) = entry
                    .pointer("/source/repo")
                    .and_then(Value::as_str)
                    .or_else(|| entry.pointer("/source/release_repo").and_then(Value::as_str))
                {
                    child.args.insert("release_repo".into(), json!(repo));
                    let artifact_name = if source_kind(&entry) == Some("clone") {
                        entry
                            .pointer("/install/bin")
                            .and_then(Value::as_str)
                            .and_then(|bin| Path::new(bin).file_name())
                            .and_then(|name| name.to_str())
                            .unwrap_or_else(|| repo_segment(repo))
                    } else {
                        repo_segment(repo)
                    };
                    child
                        .args
                        .insert("artifact_name".into(), json!(artifact_name));
                }
            }
            if child.name == "build" {
                // Artifact roads are already stamped by pull-repo. A clone
                // road's digest is minted by its face rung instead: release
                // acquisition or the source fallback build.
                if !clone {
                    child
                        .args
                        .insert("expected_digest".into(), json!({"from":"pull-repo.digest"}));
                } else {
                    child.args.remove("expected_digest");
                }
                child.args.insert("road".into(), json!(if clone { "clone" } else { "artifact" }));
            }
            if child.name == "binary-install" {
                child.args.insert("owner".into(), json!(owner));
                child
                    .args
                    .insert("uid".into(), json!({"from":"seat-present.uid"}));
                child
                    .args
                    .insert("gid".into(), json!({"from":"seat-present.gid"}));
                child.args.insert(
                    "expected_digest".into(),
                    if clone {
                        json!({"from":"build.sha256"})
                    } else {
                        json!({"from":"pull-repo.digest"})
                    },
                );
                child.args.insert("road".into(), json!(if clone { "clone" } else { "artifact" }));
                child.args.insert(
                    "digest_supplier".into(),
                    if clone {
                        json!({"from":"build.digest_supplier"})
                    } else {
                        json!("release")
                    },
                );
            }
        }
        if !face {
            step.steps.retain(|child| child.name == "pull-repo");
            continue;
        }
        let build = step
            .steps
            .iter()
            .position(|c| c.name == "build")
            .ok_or("xenia-build-missing")?;
        step.steps.insert(
            build,
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
                    ("no_follow".into(), json!(true)),
                    ("collision_policy".into(), json!("refuse")),
                    ("rollback_policy".into(), json!("exact")),
                    ("xattrs".into(), json!({})),
                ]),
                extra: BTreeMap::new(),
            },
        );
        if let Some(health) = step.steps.iter_mut().find(|c| c.name == "health-proof") {
            health.permutation = Some("status-door".into());
            health.args = if clone {
                BTreeMap::from([
                    ("id".into(), json!(id.clone())),
                    ("resolved_commit".into(), json!({"from":"pull-repo.resolved_commit"})),
                    ("endpoint".into(), discovered_endpoint(&entry).map(Value::from).unwrap_or(Value::Null)),
                    ("health_route".into(), json!(health_route(&entry))),
                ])
            } else {
                BTreeMap::from([("id".into(), json!(id.clone()))])
            };
        }
        if clone {
            if let Some(endpoint) = discovered_endpoint(&entry) {
                let route = health_route(&entry);
                let restart = step
                    .steps
                    .iter()
                    .position(|child| child.name == "service-restart")
                    .ok_or("xenia-service-restart-missing")?;
                step.steps.insert(
                    restart,
                    RoutineStep {
                        name: "health-read".into(),
                        tool: "check-health".into(),
                        permutation: Some("probe".into()),
                        args: BTreeMap::from([
                            ("url".into(), json!(health_url(endpoint, &route))),
                            ("endpoint".into(), json!(endpoint)),
                            ("health_route".into(), json!(route)),
                            ("xenia_health_read".into(), json!(true)),
                        ]),
                        extra: BTreeMap::new(),
                    },
                );
            }
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
                        if clone {
                            json!({"from":"health-proof.running_source_sha"})
                        } else {
                            json!({"from":"pull-repo.resolved_commit"})
                        },
                    ),
                    ("health".into(), json!({"from":"health-proof.health"})),
                    ("version".into(), json!({"from":"pull-repo.version"})),
                ]),
                extra: BTreeMap::new(),
            },
        );
        let has_health_read = step.steps.iter().any(|child| child.name == "health-read");
        for child in &mut step.steps {
            if clone {
                child.args.insert("xenia_id".into(), json!(id.clone()));
                if child.name == "service-restart" && has_health_read {
                    child.args.insert(
                        "running_source_sha".into(),
                        json!({"from":"health-read.running_source_sha"}),
                    );
                }
            }
            child.args.insert("hyalos_kind".into(), json!("xenia"));
            child
                .args
                .insert("hyalos_correlation_id".into(), json!(id));
        }
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
    let seat = xenia_root().join(xenia_id).display().to_string();
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
            if status == 503 || status >= 500 {
                return Err("xenia-observe-unreachable".into());
            }
            if (400..500).contains(&status)
                || value.get("ok").and_then(Value::as_bool) == Some(false)
            {
                let check = value
                    .get("check")
                    .or_else(|| value.get("verdict"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                return Err(format!("xenia-observe-refused {check}"));
            }
            if status != 200 {
                return Err("xenia-observe-unreachable".into());
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
            ok: true,
            changed: false,
            skipped: true,
            message: format!("xenia-refusal-planned id={id} reason={reason}"),
            command: None,
        });
    }
    crate::hyalos::forward_receipt(
        "xenia",
        &format!("xenia runtime outcome=failed id={id} reason={reason}"),
        Some(json!({"id":id,"outcome":"failed","reason":reason})),
        Some(false),
        Some(id),
    );
    Ok(OperationOutcome {
        ok: false,
        changed: false,
        skipped: false,
        message: format!("xenia-entry-refused id={id} reason={reason}"),
        command: None,
    })
}

pub(crate) fn execute_health_read(
    args: &BTreeMap<String, Value>,
) -> Result<(OperationOutcome, BTreeMap<String, Value>), String> {
    let endpoint = args.get("endpoint").and_then(Value::as_str);
    let route = args
        .get("health_route")
        .and_then(Value::as_str)
        .filter(|route| route.starts_with('/'))
        .unwrap_or("/health");
    let running_source_sha = endpoint.and_then(|endpoint| {
        let url = health_url(endpoint, route);
        http("GET", &url, None, Duration::from_secs(3))
            .ok()
            .and_then(|(status, value)| (status == 200).then_some(value))
            .and_then(|value| {
                value
                    .get("running_source_sha")
                    .or_else(|| value.get("source_sha"))
                    .or_else(|| value.pointer("/runtime/running_source_sha"))
                    .or_else(|| value.pointer("/runtime/source_sha"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
    });
    Ok((
        OperationOutcome {
            ok: true,
            changed: false,
            skipped: false,
            message: "xenia-health-read".into(),
            command: None,
        },
        BTreeMap::from([("running_source_sha".into(), json!(running_source_sha))]),
    ))
}

fn health_source_sha(value: &Value) -> Option<String> {
    value
        .get("running_source_sha")
        .or_else(|| value.get("source_sha"))
        .or_else(|| value.pointer("/runtime/running_source_sha"))
        .or_else(|| value.pointer("/runtime/source_sha"))
        .and_then(Value::as_str)
        .map(str::to_owned)
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
    let retries = crate::atoms::health::DEFAULT_PROBE_RETRIES as u64;
    let pause = 1;
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
                if listeners > 0 || attempt + 1 == retries {
                    let health = if listeners > 0 { "healthy" } else { "degraded" };
                    let route = args
                        .get("health_route")
                        .and_then(Value::as_str)
                        .filter(|route| route.starts_with('/'))
                        .unwrap_or("/health");
                    let endpoint = args
                        .get("endpoint")
                        .and_then(Value::as_str)
                        .or_else(|| {
                            value
                                .pointer("/entry/discovered/endpoint")
                                .and_then(Value::as_str)
                        })
                        .or_else(|| {
                            value
                                .pointer("/runtime/listeners/0/endpoint")
                                .and_then(Value::as_str)
                        });
                    let mut running_source_sha = health_source_sha(&value);
                    if let Some(endpoint) = endpoint {
                        let url = health_url(endpoint, route);
                        let (status, health_value) = http(
                            "GET",
                            &url,
                            None,
                            Duration::from_secs(3),
                        )
                        .map_err(|_| "xenia-health-unreachable".to_string())?;
                        if status != 200 {
                            return Err("xenia-health-unreachable".into());
                        }
                        running_source_sha = health_source_sha(&health_value);
                    }
                    if let Some(expected) = args.get("resolved_commit").and_then(Value::as_str) {
                        if running_source_sha.as_deref() != Some(expected) {
                            return Err("xenia-running-sha-mismatch".into());
                        }
                    }
                    let mut out = BTreeMap::new();
                    out.insert("health".into(), json!(health));
                    out.insert("running_source_sha".into(), json!(running_source_sha));
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
            let outcome = if !ok {
                "failed"
            } else if action == "disable-stop-remove" {
                "removed"
            } else {
                "disabled"
            };
            crate::hyalos::forward_receipt(
                "xenia",
                &format!("xenia retirement outcome={outcome} id={id} action={action}"),
                Some(json!({"id":id,"action":action,"outcome":outcome})),
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

#[cfg(test)]
mod clone_road_tests {
    use super::{
        declaration, execute_health_read, execute_status_door_at_base, reshape_routines,
        set_debug_schema_base,
    };
    use crate::tools::ladder::LadderStep;
    use crate::tools::routine::validate_args;
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn lowered_routine(id: &str, entry: Value) -> LadderStep {
        let _ = set_debug_schema_base("http://127.0.0.1:3013");
        let step = declaration(id, &entry).unwrap();
        let mut manifest: crate::tools::ladder::LadderManifest = serde_json::from_value(json!({
            "schema": "harmonia.module.ladder.v1",
            "id": "xenia",
            "version": "1",
            "isolation": "per-step",
            "ladder": [step]
        }))
        .unwrap();
        crate::bands::restart_services::lower_service_runtime_steps(&mut manifest);
        reshape_routines(&mut manifest).unwrap();
        assert_eq!(manifest.ladder.len(), 1);
        manifest.ladder.remove(0)
    }

    fn clone_entry(discovered: Option<&str>) -> Value {
        let mut entry = json!({
            "id": "monad-overwatch",
            "kind": "cartridge-process",
            "enabled": true,
            "priority": 20,
            "source": {
                "kind": "clone",
                "repo": "HOMESERVERSLTD/monad-overwatch",
                "ref": "main"
            },
            "install": {
                "bin": "/var/lib/xenia/monad-overwatch/monad-overwatch",
                "unit": null,
                "owner": "owner"
            },
            "health": {"route": "/health"}
        });
        if let Some(endpoint) = discovered {
            entry["discovered"] = json!({"endpoint": endpoint});
        }
        entry
    }

    fn release_entry(id: &str, repo: &str, binary: &str) -> Value {
        json!({
            "id": id,
            "kind": "cartridge-process",
            "enabled": true,
            "priority": 100,
            "source": {"release_repo": repo, "ref": "v1.0.0"},
            "install": {
                "bin": format!("/var/lib/xenia/{id}/{binary}"),
                "unit": null,
                "owner": "owner"
            },
            "health": {"route": "/health"}
        })
    }

    fn validate_lowered_children(routine: &LadderStep) {
        for child in &routine.steps {
            let permutation_name = child.permutation.as_deref().unwrap();
            let contract = crate::tools::get(&child.tool).unwrap();
            let permutation = contract.permutation(permutation_name).unwrap();
            validate_args(&routine.step_id, permutation, &child.args).unwrap();
            for argument in permutation.args {
                if let Some(value) = child.args.get(argument.name) {
                    assert!(
                        !value.is_null(),
                        "declared argument {} on {} must not be null",
                        argument.name,
                        child.name
                    );
                }
            }
        }
        crate::tools::routine::project_routine_children(routine, &BTreeMap::new()).unwrap();
    }

    fn assert_status_door_id_only(routine: &LadderStep, id: &str) {
        let health = routine
            .steps
            .iter()
            .find(|child| child.name == "health-proof")
            .unwrap();
        assert_eq!(health.tool, "check-health");
        assert_eq!(health.permutation.as_deref(), Some("status-door"));
        let contract = crate::tools::get("check-health").unwrap();
        let permutation = contract.permutation("status-door").unwrap();
        let required = permutation
            .args
            .iter()
            .filter(|argument| argument.required)
            .map(|argument| argument.name)
            .collect::<Vec<_>>();
        assert_eq!(required, vec!["id"]);
        assert_eq!(
            health.args.get("id").and_then(Value::as_str),
            Some(id)
        );
    }

    #[test]
    fn clone_face_binds_install_to_build_digest_and_names_clone_road() {
        let routine = lowered_routine("monad-overwatch", clone_entry(None));
        let build = routine
            .steps
            .iter()
            .find(|child| child.name == "build")
            .unwrap();
        assert!(!build.args.contains_key("expected_digest"));
        assert_eq!(build.args.get("road"), Some(&json!("clone")));
        let install = routine
            .steps
            .iter()
            .find(|child| child.name == "binary-install")
            .unwrap();
        assert_eq!(
            install.args.get("expected_digest"),
            Some(&json!({"from":"build.sha256"}))
        );
        assert_eq!(
            install.args.get("digest_supplier"),
            Some(&json!({"from":"build.digest_supplier"}))
        );
        assert_eq!(install.args.get("road"), Some(&json!("clone")));
        assert!(!serde_json::to_string(&install.args)
            .unwrap()
            .contains("pull-repo.digest"));
        validate_lowered_children(&routine);
    }

    #[test]
    fn clone_first_convergence_without_discovered_endpoint_omits_health_read_and_restart_reference() {
        let routine = lowered_routine("monad-overwatch", clone_entry(None));
        assert!(routine.steps.iter().all(|child| child.name != "health-read"));
        let restart = routine
            .steps
            .iter()
            .find(|child| child.name == "service-restart")
            .unwrap();
        assert!(!restart.args.contains_key("running_source_sha"));
        assert_status_door_id_only(&routine, "monad-overwatch");
        let health = routine
            .steps
            .iter()
            .find(|child| child.name == "health-proof")
            .unwrap();
        assert_eq!(health.args.get("endpoint"), Some(&Value::Null));
        validate_lowered_children(&routine);
    }

    #[test]
    fn clone_first_convergence_with_discovered_endpoint_keeps_health_read_and_restart_reference() {
        let endpoint = "http://127.0.0.1:39001";
        let routine = lowered_routine("monad-overwatch", clone_entry(Some(endpoint)));
        let health_read = routine
            .steps
            .iter()
            .find(|child| child.name == "health-read")
            .unwrap();
        assert_eq!(health_read.tool, "check-health");
        assert_eq!(health_read.permutation.as_deref(), Some("probe"));
        assert_eq!(health_read.args.get("endpoint").and_then(Value::as_str), Some(endpoint));
        assert!(health_read
            .args
            .get("url")
            .and_then(Value::as_str)
            .is_some_and(|url| url.ends_with("/health")));
        let restart = routine
            .steps
            .iter()
            .find(|child| child.name == "service-restart")
            .unwrap();
        assert_eq!(
            restart.args.get("running_source_sha"),
            Some(&json!({"from":"health-read.running_source_sha"}))
        );
        assert_status_door_id_only(&routine, "monad-overwatch");
        validate_lowered_children(&routine);
    }

    #[test]
    fn release_roads_hello_world_and_lan_overview_keep_status_door_id_only_shape() {
        for (id, repo, binary) in [
            ("hello-world", "HOMESERVERSLTD/hello-world", "hello-world"),
            ("lan-overview", "HOMESERVERSLTD/lan-overview", "lan-overview"),
        ] {
            let routine = lowered_routine(id, release_entry(id, repo, binary));
            assert!(routine.steps.iter().all(|child| child.name != "health-read"));
            assert_status_door_id_only(&routine, id);
            let health = routine
                .steps
                .iter()
                .find(|child| child.name == "health-proof")
                .unwrap();
            assert!(health.args.keys().all(|key| {
                matches!(key.as_str(), "id" | "hyalos_kind" | "hyalos_correlation_id")
            }));
            assert!(routine.steps.iter().all(|child| {
                !child.args.contains_key("source_kind")
                    && !child.args.contains_key("release_ref")
                    && !child.args.contains_key("running_source_sha")
            }));
            validate_lowered_children(&routine);
        }
    }

    #[test]
    fn clone_declaration_uses_install_basename_for_face_asset() {
        let entry = json!({
            "id":"guest",
            "kind":"cartridge-process",
            "source":{"kind":"clone","repo":"OWNER/repo","ref":"main"},
            "install":{"bin":"/var/lib/xenia/guest/cartridge","unit":null,"owner":"owner"}
        });
        let step = declaration("guest", &entry).unwrap();
        assert_eq!(step.args.get("source_policy").and_then(|v| v.as_str()), Some("source"));
        assert_eq!(step.args.get("binary_name").and_then(|v| v.as_str()), Some("cartridge"));
        assert_eq!(step.args.get("asset_name").and_then(|v| v.as_str()), Some("cartridge-x86_64"));
        let mismatch = json!({
            "id":"guest",
            "kind":"cartridge-process",
            "source":{"kind":"clone","repo":"OWNER/repo","ref":"main"},
            "install":{"bin":"/var/lib/xenia/other/cartridge","unit":null,"owner":"owner"}
        });
        assert_eq!(declaration("guest", &mismatch).unwrap_err(), "xenia-install-bin-path-mismatch");
    }

    #[test]
    fn release_and_clone_declarations_lower_side_by_side() {
        let clone = json!({
            "id":"clone-guest",
            "kind":"cartridge-process",
            "source":{"kind":"clone","repo":"OWNER/repo","ref":"main"},
            "install":{"bin":"/var/lib/xenia/clone-guest/cartridge","unit":null,"owner":"owner"}
        });
        let release = json!({
            "id":"release-guest",
            "kind":"cartridge-process",
            "source":{"release_repo":"OWNER/release","ref":"v1"},
            "install":{"bin":"/var/lib/xenia/release-guest/cartridge","unit":null,"owner":"owner"}
        });
        let clone_step = declaration("clone-guest", &clone).unwrap();
        let release_step = declaration("release-guest", &release).unwrap();
        assert_eq!(clone_step.args["source_kind"], json!("clone"));
        assert_eq!(clone_step.args["source_policy"], json!("source"));
        assert_eq!(release_step.args["release_repo"], json!("OWNER/release"));
        assert!(!release_step.args.contains_key("source_kind"));
        assert!(!release_step.args.contains_key("release_ref"));
    }

    fn status_server(sha: &str) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let endpoint = format!("http://{address}");
        let body = format!("{{\"runtime\":{{\"state\":\"active\",\"listeners\":[{{\"endpoint\":\"{endpoint}\"}}]}}}}");
        let health = format!("{{\"running_source_sha\":\"{sha}\"}}");
        let server = thread::spawn(move || {
            for (path, response) in [("/api/v1/xenia/status/guest", body), ("/health", health)] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 4096];
                let size = stream.read(&mut request).unwrap();
                assert!(String::from_utf8_lossy(&request[..size]).starts_with(&format!("GET {path} ")));
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
            }
        });
        (format!("http://{address}"), server)
    }

    #[test]
    fn status_listener_fallback_reads_health_and_refuses_sha_mismatch() {
        let (base, server) = status_server("expected");
        let args = BTreeMap::from([
            ("id".into(), json!("guest")),
            ("resolved_commit".into(), json!("expected")),
        ]);
        execute_status_door_at_base(&args, &base).unwrap();
        server.join().unwrap();
        let (base, server) = status_server("wrong");
        let error = execute_status_door_at_base(&args, &base).unwrap_err();
        assert_eq!(error, "xenia-running-sha-mismatch");
        server.join().unwrap();
    }

    #[test]
    fn health_read_uses_entry_route_without_endpoint_blocking() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let size = stream.read(&mut request).unwrap();
            assert!(String::from_utf8_lossy(&request[..size]).starts_with("GET /ready "));
            let body = "{\"source_sha\":\"abc\"}";
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
        });
        let args = BTreeMap::from([
            ("endpoint".into(), json!(format!("http://{address}"))),
            ("health_route".into(), json!("/ready")),
        ]);
        let (_, output) = execute_health_read(&args).unwrap();
        server.join().unwrap();
        assert_eq!(output["running_source_sha"], "abc");
    }
}
