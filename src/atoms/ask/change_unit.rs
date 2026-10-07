use crate::CmdResult;
use std::path::{Path, PathBuf};

fn is_removable_unit_basename(unit: &str) -> bool {
    is_syntactic_unit_basename(unit)
        && [
            ".service",
            ".socket",
            ".target",
            ".device",
            ".mount",
            ".automount",
            ".swap",
            ".path",
            ".timer",
            ".slice",
            ".scope",
            ".busname",
            ".snapshot",
        ]
        .iter()
        .any(|suffix| unit.ends_with(suffix))
}

fn is_syntactic_unit_basename(unit: &str) -> bool {
    let path = Path::new(unit);
    !unit.is_empty()
        && !path.is_absolute()
        && path.components().count() == 1
        && path.file_name().is_some()
        && !unit.chars().any(char::is_whitespace)
}

#[derive(Clone, Debug)]
pub(crate) struct ServiceStateSnapshot {
    pub name: String,
    pub user: bool,
    pub target_user: Option<String>,
    pub enabled: bool,
    pub active: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct Observation {
    pub(crate) enabled: Option<String>,
    pub(crate) active: Option<String>,
    pub(crate) load_state: Option<String>,
    pub(crate) unit_file_state: Option<String>,
    pub(crate) needs_reload: Option<String>,
    pub(crate) unit_present: Option<bool>,
    pub(crate) unit_file_exists: bool,
    pub(crate) probe: Option<CmdResult>,
    pub(crate) condition_show: Option<CmdResult>,
    pub(crate) condition_snapshot: Option<ConditionSnapshot>,
    pub(crate) condition_probe_error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ConditionSnapshot {
    pub(crate) load_state: String,
    pub(crate) active_state: String,
    pub(crate) condition_result: String,
    // systemd 257 may return "[unprintable]" here; preserve it, never parse it.
    pub(crate) conditions: String,
    pub(crate) status: Option<CmdResult>,
    pub(crate) failed_conditions: Vec<String>,
    pub(crate) status_unmet_summary: bool,
    pub(crate) condition_name: Option<String>,
    pub(crate) condition_name_source: Option<String>,
    pub(crate) condition_cat: Option<CmdResult>,
    pub(crate) condition_journal: Option<CmdResult>,
    pub(crate) live_condition_evidence: Option<LiveConditionEvidence>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct LiveConditionEvidence {
    pub(crate) source: String,
    pub(crate) overall_result: String,
    pub(crate) consistency: String,
    pub(crate) consistency_source: String,
    pub(crate) consistency_value: Option<String>,
    pub(crate) conditions: Vec<LiveConditionObservation>,
    pub(crate) decisive_conditions: Vec<String>,
    pub(crate) parser_errors: Vec<String>,
    pub(crate) observation_errors: Vec<String>,
    pub(crate) mount_namespace: Option<MountNamespaceEvidence>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct LiveConditionObservation {
    pub(crate) source_file: Option<String>,
    pub(crate) line: String,
    pub(crate) path: Option<String>,
    pub(crate) kind: String,
    pub(crate) negated: bool,
    pub(crate) trigger: bool,
    pub(crate) observed_predicate: Option<bool>,
    pub(crate) evaluated_result: String,
    pub(crate) observation_source: Option<String>,
    pub(crate) read_error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct MountNamespaceEvidence {
    pub(crate) source: String,
    pub(crate) identity: Option<String>,
    pub(crate) read_error: Option<String>,
    pub(crate) mountinfo_source: String,
    pub(crate) mountinfo_error: Option<String>,
}

fn observe_condition_snapshot(
    service: &str,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
    probe: Option<&CmdResult>,
    needs_reload: Option<&str>,
) -> (Option<CmdResult>, Option<ConditionSnapshot>, Option<String>) {
    let show = systemctl("condition-show", service, user, target_user, timeout_secs);
    if !show.ok {
        return (
            Some(show),
            None,
            Some("systemd-condition-show-failed".to_string()),
        );
    }
    let snapshot = match parse_condition_snapshot(&show.stdout) {
        Ok(snapshot) => snapshot,
        Err(error) => return (Some(show), None, Some(error)),
    };
    let inactive_loaded_probe = probe
        .is_some_and(|result| !result.ok && result.code == 3 && result.stdout.trim() == "inactive")
        && snapshot.load_state == "loaded"
        && snapshot.active_state == "inactive";
    if !inactive_loaded_probe {
        return (Some(show), Some(snapshot), None);
    }

    let mut snapshot = snapshot;
    let safe_unit = exact_unit_basename(service);
    let cat =
        safe_unit.then(|| systemctl("condition-cat", service, user, target_user, timeout_secs));
    snapshot.condition_cat = cat.clone();
    let live = evaluate_live_conditions(cat.as_ref(), needs_reload);
    let live_unmet = live.overall_result == "unmet";
    if live_unmet {
        snapshot.condition_name = Some(live.decisive_conditions.join("; "));
        snapshot.condition_name_source = Some("live-path-read".to_string());
    }
    snapshot.live_condition_evidence = Some(live);

    // Keep the established status/cat/journal record lane for ConditionResult=no.
    // A fresh live result of "met" deliberately does not inherit that stale no.
    if snapshot.condition_result != "no" {
        return (Some(show), Some(snapshot), None);
    }
    let status = systemctl("condition-status", service, user, target_user, timeout_secs);
    snapshot.failed_conditions = failed_condition_lines(&status.stdout);
    snapshot.status_unmet_summary = status_unmet_summary(&status.stdout);
    let status_is_confirmed = status.code == 3
        && (snapshot.status_unmet_summary || !snapshot.failed_conditions.is_empty());
    let status_error = if status.code != 3 || !status_is_confirmed {
        Some("systemd-condition-status-unconfirmed".to_string())
    } else if !live_unmet && !snapshot.failed_conditions.is_empty() {
        snapshot.condition_name = snapshot
            .failed_conditions
            .first()
            .and_then(|line| condition_expression(line));
        snapshot.condition_name_source = Some("status-subline".to_string());
        None
    } else {
        let declaration = cat
            .as_ref()
            .filter(|result| result.ok)
            .and_then(|result| effective_condition_declaration(&result.stdout));
        if let Some(declaration) = declaration {
            if !live_unmet {
                snapshot.condition_name = Some(declaration.clone());
                snapshot.condition_name_source = Some("unit-declaration".to_string());
                snapshot.failed_conditions.push(declaration);
            }
            None
        } else if !user && safe_unit {
            let journal = journal_condition_evidence(service, timeout_secs);
            let journal_failures = if journal.ok {
                journal_condition_lines(&journal.stdout)
            } else {
                Vec::new()
            };
            snapshot.condition_journal = Some(journal);
            if let Some(journal_line) = journal_failures.first() {
                if !live_unmet {
                    snapshot.condition_name = condition_expression(journal_line);
                    snapshot.condition_name_source = Some("journal".to_string());
                    snapshot.failed_conditions = journal_failures;
                }
                None
            } else {
                Some("systemd-condition-detail-missing".to_string())
            }
        } else {
            Some("systemd-condition-detail-missing".to_string())
        }
    };
    snapshot.status = Some(status);
    (Some(show), Some(snapshot), status_error)
}

pub(crate) fn observe_systemd_state(
    action: &str,
    service: &str,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
) -> Observation {
    // Special legacy permutations use the same settled read-only systemd
    // atoms as the ordinary service lane. The conductor never reaches into
    // a private tool rung.
    let probe = matches!(action, "unit-present" | "is-active-probe")
        .then(|| systemctl(action, service, user, target_user, timeout_secs));
    let needs_reload = state("needs-reload", service, user, target_user, timeout_secs);
    let (condition_show, condition_snapshot, condition_probe_error) = if action == "is-active-probe"
    {
        observe_condition_snapshot(
            service,
            user,
            target_user,
            timeout_secs,
            probe.as_ref(),
            needs_reload.as_deref(),
        )
    } else {
        (None, None, None)
    };
    let unit_present = if action == "unit-present" {
        probe
            .as_ref()
            .map(|result| result.ok && result.stdout.trim() != "not-found")
    } else {
        None
    };
    Observation {
        enabled: state("is-enabled", service, user, target_user, timeout_secs),
        active: state("is-active", service, user, target_user, timeout_secs),
        load_state: state("load-state", service, user, target_user, timeout_secs),
        unit_file_state: state("unit-file-state", service, user, target_user, timeout_secs),
        needs_reload,
        unit_present,
        unit_file_exists: action == "disable-stop-remove"
            && unit_file_path(service).is_some_and(|path| path.exists()),
        probe,
        condition_show,
        condition_snapshot,
        condition_probe_error,
    }
}

fn parse_condition_snapshot(output: &str) -> Result<ConditionSnapshot, String> {
    let expected = ["LoadState", "ActiveState", "ConditionResult", "Conditions"];
    let mut properties = std::collections::BTreeMap::new();
    for line in output.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err("systemd-condition-show-malformed".to_string());
        };
        if !expected.contains(&key) || value.is_empty() {
            return Err("systemd-condition-show-invalid-property".to_string());
        }
        if properties.insert(key, value).is_some() {
            return Err("systemd-condition-show-duplicate-property".to_string());
        }
    }
    if properties.len() != expected.len() {
        return Err("systemd-condition-show-property-missing".to_string());
    }
    let load_state = properties["LoadState"];
    let active_state = properties["ActiveState"];
    let condition_result = properties["ConditionResult"];
    let conditions = properties["Conditions"];
    if !matches!(
        load_state,
        "stub" | "loaded" | "not-found" | "bad-setting" | "error" | "merged" | "masked"
    ) || !matches!(
        active_state,
        "active" | "reloading" | "inactive" | "failed" | "activating" | "deactivating"
    ) || !matches!(condition_result, "yes" | "no")
        || conditions.trim().is_empty()
    {
        return Err("systemd-condition-show-invalid-value".to_string());
    }
    Ok(ConditionSnapshot {
        load_state: load_state.to_string(),
        active_state: active_state.to_string(),
        condition_result: condition_result.to_string(),
        conditions: conditions.to_string(),
        status: None,
        failed_conditions: Vec::new(),
        status_unmet_summary: false,
        condition_name: None,
        condition_name_source: None,
        condition_cat: None,
        condition_journal: None,
        live_condition_evidence: None,
    })
}

fn evaluate_live_conditions(
    cat: Option<&CmdResult>,
    needs_reload: Option<&str>,
) -> LiveConditionEvidence {
    let mut conditions = Vec::new();
    let mut parser_errors = Vec::new();
    let mut observation_errors = Vec::new();
    let mut mount_namespace = None;
    let mut cat_is_usable = false;

    match cat {
        None => observation_errors.push("systemctl-cat-unit-name-unsafe".to_string()),
        Some(result) if !result.ok => observation_errors.push(format!(
            "systemctl-cat-failed-code-{}:{}",
            result.code, result.stderr
        )),
        Some(result) if result.stdout.trim().is_empty() => {
            parser_errors.push("systemctl-cat-output-empty".to_string())
        }
        Some(result) => {
            cat_is_usable = true;
            let (parsed, errors) = parse_effective_condition_lines(&result.stdout);
            conditions = parsed;
            parser_errors = errors;
        }
    }

    let has_mountpoint_condition = conditions.iter().any(|condition| {
        condition.kind == "ConditionPathIsMountPoint"
            && condition.path.is_some()
            && condition.read_error.is_none()
    });
    let mount_table = has_mountpoint_condition.then(read_mount_table);
    if let Some(table) = mount_table.as_ref() {
        mount_namespace = Some(table.evidence.clone());
        if let Some(error) = table.evidence.read_error.as_ref() {
            observation_errors.push(format!("{}: {error}", table.evidence.source));
        }
        if let Some(error) = table.evidence.mountinfo_error.as_ref() {
            observation_errors.push(format!("{}: {error}", table.evidence.mountinfo_source));
        }
    }

    for condition in &mut conditions {
        if condition.read_error.is_some() {
            continue;
        }
        if !is_live_path_condition(&condition.kind) {
            condition.read_error = Some("unsupported-condition-kind".to_string());
            continue;
        }
        let Some(path) = condition.path.as_deref() else {
            condition.read_error = Some("condition-path-unavailable".to_string());
            continue;
        };
        let (observed, source, error) = match condition.kind.as_str() {
            "ConditionPathExists" | "ConditionPathIsDirectory" => {
                observe_metadata_condition(path, &condition.kind)
            }
            "ConditionPathIsMountPoint" => match mount_table.as_ref() {
                Some(table) => observe_mountpoint_condition(path, table),
                None => (
                    None,
                    Some("/proc/self/mountinfo".to_string()),
                    Some("mount-namespace-observation-unavailable".to_string()),
                ),
            },
            _ => unreachable!("supported live path condition was checked above"),
        };
        condition.observed_predicate = observed;
        condition.observation_source = source;
        condition.read_error = error;
        let effective_predicate =
            observed.map(|value| if condition.negated { !value } else { value });
        condition.evaluated_result = match effective_predicate {
            Some(true) => "met".to_string(),
            Some(false) => "unmet".to_string(),
            None => "unknown".to_string(),
        };
        if let Some(error) = condition.read_error.as_ref() {
            observation_errors.push(format!("{}: {error}", condition.line.trim()));
        }
    }

    let consistency = if cat_is_usable && needs_reload == Some("no") {
        "consistent".to_string()
    } else {
        if needs_reload == Some("yes") {
            observation_errors.push(
                "NeedDaemonReload=yes; effective unit may differ from systemctl cat".to_string(),
            );
        } else if needs_reload != Some("no") {
            observation_errors
                .push("NeedDaemonReload observation unavailable or unrecognized".to_string());
        }
        "unknown".to_string()
    };
    let (evaluated, decisive_conditions) = aggregate_live_conditions(&conditions);
    let overall_result =
        if !cat_is_usable || !parser_errors.is_empty() || consistency != "consistent" {
            "unknown".to_string()
        } else {
            evaluated.to_string()
        };

    let decisive_conditions = if overall_result == "unmet" {
        decisive_conditions
    } else {
        Vec::new()
    };
    LiveConditionEvidence {
        source: "live-path-read".to_string(),
        overall_result,
        consistency,
        consistency_source: "systemctl show NeedDaemonReload".to_string(),
        consistency_value: needs_reload.map(|value| value.to_string()),
        conditions,
        decisive_conditions,
        parser_errors,
        observation_errors,
        mount_namespace,
    }
}

fn parse_effective_condition_lines(output: &str) -> (Vec<LiveConditionObservation>, Vec<String>) {
    let mut in_unit_section = false;
    let mut continuing = false;
    let mut current_source: Option<String> = None;
    let mut conditions = Vec::new();
    let mut errors = Vec::new();

    for raw_line in output.lines() {
        if let Some(header) = raw_line
            .trim_start()
            .strip_prefix("# ")
            .filter(|header| header.starts_with('/'))
        {
            if continuing {
                errors.push(format!(
                    "{}: interrupted systemctl cat continuation",
                    raw_line
                ));
            }
            current_source = Some(header.to_string());
            in_unit_section = false;
            continuing = false;
            continue;
        }
        let line = raw_line.trim();
        if continuing {
            continuing = line.ends_with('\\');
            continue;
        }
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            if line.ends_with(']') {
                in_unit_section = line == "[Unit]";
            } else if line.starts_with("[Unit") {
                errors.push(format!("{}: malformed Unit section header", raw_line));
                in_unit_section = false;
            } else {
                in_unit_section = false;
            }
            continue;
        }
        if !in_unit_section {
            continuing = line.ends_with('\\');
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            if line.starts_with("Condition") {
                errors.push(format!("{}: condition assignment lacks '='", raw_line));
            }
            continuing = line.ends_with('\\');
            continue;
        };
        let name = name.trim();
        if !name.starts_with("Condition") {
            continuing = line.ends_with('\\');
            continue;
        }
        if !is_condition_directive(name) {
            errors.push(format!("{}: ambiguous Condition directive", raw_line));
            continuing = line.ends_with('\\');
            continue;
        }
        let value = value.trim();
        if value.is_empty() && !line.ends_with('\\') {
            // systemd's empty Condition* assignment clears the whole condition list.
            conditions.clear();
            continue;
        }

        let supported = is_live_path_condition(name);
        let parsed = parse_condition_value(value, supported);
        let (trigger, negated, path, parse_error) = match parsed {
            Ok((trigger, negated, path)) => (trigger, negated, path, None),
            Err(error) => (false, false, None, Some(error)),
        };
        if let Some(error) = parse_error.as_ref() {
            errors.push(format!("{}: {error}", raw_line));
        }
        let continuation_error = line.ends_with('\\');
        if continuation_error {
            errors.push(format!(
                "{}: Condition continuation is not interpreted",
                raw_line
            ));
        }
        conditions.push(LiveConditionObservation {
            source_file: current_source.clone(),
            line: raw_line.to_string(),
            path,
            kind: name.to_string(),
            negated,
            trigger,
            observed_predicate: None,
            evaluated_result: "unknown".to_string(),
            observation_source: None,
            read_error: parse_error.or_else(|| {
                continuation_error.then(|| "condition-continuation-unsupported".to_string())
            }),
        });
        continuing = continuation_error;
    }
    (conditions, errors)
}

fn parse_condition_value(
    raw_value: &str,
    require_literal_path: bool,
) -> Result<(bool, bool, Option<String>), String> {
    let mut value = raw_value.trim();
    let trigger = value.starts_with('|');
    if trigger {
        value = &value[1..];
    }
    let negated = value.starts_with('!');
    if negated {
        value = &value[1..];
    }
    if value.is_empty() || value.starts_with('|') || value.starts_with('!') {
        return Err("ambiguous condition modifiers or empty value".to_string());
    }
    if !require_literal_path {
        return Ok((trigger, negated, None));
    }
    if value.chars().any(|character| {
        character.is_whitespace()
            || matches!(character, '%' | '\\' | '\'' | '"' | '*' | '?' | '[' | ']')
    }) {
        return Err(
            "condition path uses unsupported quoting, escaping, specifier, or pattern".to_string(),
        );
    }
    if !Path::new(value).is_absolute() {
        return Err("condition path is not absolute".to_string());
    }
    Ok((trigger, negated, Some(value.to_string())))
}

fn is_live_path_condition(name: &str) -> bool {
    matches!(
        name,
        "ConditionPathIsMountPoint" | "ConditionPathExists" | "ConditionPathIsDirectory"
    )
}

fn observe_metadata_condition(
    path: &str,
    kind: &str,
) -> (Option<bool>, Option<String>, Option<String>) {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return (Some(false), Some("std::fs::metadata".to_string()), None);
        }
        Err(error) => {
            return (
                None,
                Some("std::fs::metadata".to_string()),
                Some(format!("{} ({:?})", error, error.kind())),
            );
        }
    };
    let value = match kind {
        "ConditionPathExists" => true,
        "ConditionPathIsDirectory" => metadata.is_dir(),
        _ => {
            return (
                None,
                None,
                Some("unsupported-metadata-condition".to_string()),
            )
        }
    };
    (Some(value), Some("std::fs::metadata".to_string()), None)
}

struct MountTableObservation {
    evidence: MountNamespaceEvidence,
    mountpoints: Result<Vec<PathBuf>, String>,
}

fn read_mount_table() -> MountTableObservation {
    let namespace = std::fs::read_link("/proc/self/ns/mnt");
    let mountpoints = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("{} ({:?})", error, error.kind()))
        .and_then(|contents| parse_mountinfo_mountpoints(&contents));
    let mountinfo_error = mountpoints.as_ref().err().cloned();
    let evidence = match namespace {
        Ok(identity) => MountNamespaceEvidence {
            source: "/proc/self/ns/mnt".to_string(),
            identity: Some(identity.to_string_lossy().into_owned()),
            read_error: None,
            mountinfo_source: "/proc/self/mountinfo".to_string(),
            mountinfo_error,
        },
        Err(error) => MountNamespaceEvidence {
            source: "/proc/self/ns/mnt".to_string(),
            identity: None,
            read_error: Some(format!("{} ({:?})", error, error.kind())),
            mountinfo_source: "/proc/self/mountinfo".to_string(),
            mountinfo_error,
        },
    };
    MountTableObservation {
        evidence,
        mountpoints,
    }
}

fn parse_mountinfo_mountpoints(contents: &str) -> Result<Vec<PathBuf>, String> {
    let mut mountpoints = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let (left, right) = line
            .split_once(" - ")
            .ok_or_else(|| format!("mountinfo-line-{}-missing-separator", index + 1))?;
        if right.trim().is_empty() {
            return Err(format!("mountinfo-line-{}-missing-filesystem", index + 1));
        }
        let fields = left.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 6 {
            return Err(format!("mountinfo-line-{}-missing-fields", index + 1));
        }
        let decoded = strict_mountinfo_unescape(fields[4])
            .map_err(|error| format!("mountinfo-line-{}-{error}", index + 1))?;
        let path = PathBuf::from(decoded);
        if !path.is_absolute() {
            return Err(format!(
                "mountinfo-line-{}-mountpoint-not-absolute",
                index + 1
            ));
        }
        mountpoints.push(path);
    }
    if mountpoints.is_empty() {
        return Err("mountinfo-empty".to_string());
    }
    Ok(mountpoints)
}

fn strict_mountinfo_unescape(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 4 > bytes.len() {
            return Err("malformed-mountpoint-escape".to_string());
        }
        let escape = std::str::from_utf8(&bytes[index + 1..index + 4]).ok();
        let byte = match escape {
            Some("040") => b' ',
            Some("011") => b'\t',
            Some("012") => b'\n',
            Some("134") => b'\\',
            _ => return Err("unsupported-mountpoint-escape".to_string()),
        };
        decoded.push(byte);
        index += 4;
    }
    String::from_utf8(decoded).map_err(|_| "mountpoint-not-utf8".to_string())
}

fn observe_mountpoint_condition(
    path: &str,
    table: &MountTableObservation,
) -> (Option<bool>, Option<String>, Option<String>) {
    let source = Some(
        "std::fs::metadata + /proc/self/mountinfo + std::fs::canonicalize(condition path)"
            .to_string(),
    );
    match std::fs::metadata(path) {
        Ok(_) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return (Some(false), Some("std::fs::metadata".to_string()), None);
        }
        Err(error) => {
            return (
                None,
                Some("std::fs::metadata".to_string()),
                Some(format!("{} ({:?})", error, error.kind())),
            );
        }
    }
    if let Some(error) = table.evidence.read_error.as_ref() {
        return (None, source, Some(format!("mount-namespace-read: {error}")));
    }
    let mountpoints = match table.mountpoints.as_ref() {
        Ok(mountpoints) => mountpoints,
        Err(error) => return (None, source, Some(format!("mountinfo-read: {error}"))),
    };
    let resolved = match std::fs::canonicalize(path) {
        Ok(path) => path,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return (Some(false), source, None);
        }
        Err(error) => {
            return (
                None,
                source,
                Some(format!("path-canonicalize: {} ({:?})", error, error.kind())),
            );
        }
    };
    if mountpoints.iter().any(|mountpoint| mountpoint == &resolved) {
        (Some(true), source, None)
    } else {
        (Some(false), source, None)
    }
}

fn aggregate_live_conditions(
    conditions: &[LiveConditionObservation],
) -> (&'static str, Vec<String>) {
    let regular = conditions
        .iter()
        .filter(|condition| !condition.trigger)
        .collect::<Vec<_>>();
    let triggers = conditions
        .iter()
        .filter(|condition| condition.trigger)
        .collect::<Vec<_>>();
    let regular_unmet = regular
        .iter()
        .filter(|condition| condition.evaluated_result == "unmet")
        .map(|condition| condition.line.clone())
        .collect::<Vec<_>>();
    let trigger_unmet = !triggers.is_empty()
        && triggers
            .iter()
            .all(|condition| condition.evaluated_result == "unmet");
    let mut decisive = regular_unmet;
    if trigger_unmet {
        decisive.extend(triggers.iter().map(|condition| condition.line.clone()));
    }
    if !decisive.is_empty() {
        return ("unmet", decisive);
    }
    let regular_unknown = regular
        .iter()
        .any(|condition| condition.evaluated_result == "unknown");
    let trigger_unknown = !triggers.is_empty()
        && !triggers
            .iter()
            .any(|condition| condition.evaluated_result == "met");
    if regular_unknown || trigger_unknown {
        ("unknown", Vec::new())
    } else {
        ("met", Vec::new())
    }
}

fn failed_condition_lines(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let detail = status_condition_detail(line)?;
            let (start, name, value) = condition_assignment(detail)?;
            if start != 0 {
                return None;
            }
            let value = value.to_ascii_lowercase();
            (is_condition_directive(name)
                && ["not met", "not satisfied", "failed", "result=no", "=no"]
                    .iter()
                    .any(|marker| value.contains(marker))
                && condition_expression(detail).is_some())
            .then(|| detail.to_string())
        })
        .collect()
}

fn status_condition_detail(line: &str) -> Option<&str> {
    let mut detail = line.trim_start();
    while let Some(rest) = detail.strip_prefix("│") {
        detail = rest.trim_start();
    }
    if let Some(rest) = detail
        .strip_prefix("├─")
        .or_else(|| detail.strip_prefix("└─"))
    {
        detail = rest.trim_start();
    }
    let (start, _, _) = condition_assignment(detail)?;
    (start == 0).then_some(detail)
}

fn condition_assignment(line: &str) -> Option<(usize, &str, &str)> {
    let mut search_from = 0;
    while let Some(relative_start) = line.get(search_from..)?.find("Condition") {
        let start = search_from + relative_start;
        let suffix = line.get(start + "Condition".len()..)?;
        let name_len = suffix
            .chars()
            .take_while(|character| character.is_ascii_alphanumeric())
            .map(char::len_utf8)
            .sum::<usize>();
        let equals = start + "Condition".len() + name_len;
        if name_len > 0 && line.as_bytes().get(equals) == Some(&b'=') {
            let name = line.get(start..equals)?;
            let value = line.get(equals + 1..)?;
            if is_condition_directive(name) {
                return Some((start, name, value));
            }
        }
        search_from = start + "Condition".len();
        if search_from >= line.len() {
            return None;
        }
    }
    None
}

fn is_condition_directive(name: &str) -> bool {
    name.starts_with("Condition")
        && name.len() > "Condition".len()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
        && !matches!(name, "ConditionResult" | "Conditions")
}

fn status_unmet_summary(output: &str) -> bool {
    output.lines().any(|line| {
        let line = line.trim();
        line.strip_prefix("Condition: start condition unmet")
            .is_some_and(|remainder| {
                remainder.is_empty() || remainder.chars().next().is_some_and(char::is_whitespace)
            })
    })
}

fn condition_expression(detail: &str) -> Option<String> {
    let (_, name, value) = condition_assignment(detail)?;
    let lowercase = value.to_ascii_lowercase();
    let explanation_markers = [
        " was not met",
        " is not met",
        " not met",
        " was not satisfied",
        " is not satisfied",
        " not satisfied",
        " failed",
        " result=no",
    ];
    let value_end = explanation_markers
        .iter()
        .filter_map(|marker| lowercase.find(marker))
        .min()
        .unwrap_or(value.len());
    let value = value[..value_end]
        .trim_end_matches(|character: char| matches!(character, '.' | ',' | ';'))
        .trim();
    (!value.is_empty()).then(|| format!("{name}={value}"))
}

fn effective_condition_declaration(output: &str) -> Option<String> {
    let mut in_unit_section = false;
    let mut continuing = false;
    let mut conditions = Vec::new();
    for raw_line in output.lines() {
        if raw_line
            .trim_start()
            .strip_prefix("# ")
            .is_some_and(|header| header.starts_with('/'))
        {
            in_unit_section = false;
            continuing = false;
            continue;
        }
        let line = raw_line.trim();
        if continuing {
            continuing = line.ends_with('\\');
            continue;
        }
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_unit_section = line == "[Unit]";
            continue;
        }
        if !in_unit_section {
            continuing = line.ends_with('\\');
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continuing = line.ends_with('\\');
            continue;
        };
        let name = name.trim();
        if !is_condition_directive(name) {
            continuing = line.ends_with('\\');
            continue;
        }
        if line.ends_with('\\') {
            return None;
        }
        if value.trim().is_empty() {
            conditions.clear();
        } else {
            conditions.push(format!("{name}={}", value.trim()));
        }
    }
    (conditions.len() == 1).then(|| conditions.remove(0))
}

fn journal_condition_lines(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let (_, detail) = line.split_once("skipped, unmet condition check ")?;
            let detail = detail.trim();
            let (start, _, value) = condition_assignment(detail)?;
            (start == 0 && !value.trim().is_empty() && condition_expression(detail).is_some())
                .then(|| detail.to_string())
        })
        .collect()
}

fn exact_unit_basename(service: &str) -> bool {
    is_removable_unit_basename(service)
        && !service
            .chars()
            .any(|character| matches!(character, '*' | '?' | '[' | ']'))
}

fn journal_condition_evidence(service: &str, timeout_secs: u64) -> CmdResult {
    let args = vec![
        "--boot=0".to_string(),
        format!("--unit={service}"),
        "--reverse".to_string(),
        "--lines=all".to_string(),
        "--no-pager".to_string(),
        "--output=cat".to_string(),
        "--grep=Condition[^[:space:]]*=".to_string(),
    ];
    let result = super::read_only_command_with_timeout(
        "/usr/bin/journalctl",
        &args,
        std::time::Duration::from_secs(timeout_secs),
    );
    CmdResult {
        ok: result.ok,
        code: result.code.unwrap_or(if result.ok { 0 } else { -1 }),
        stdout: result.stdout,
        stderr: result.stderr,
    }
}

pub(crate) fn snapshot_service_state(
    name: &str,
    user: bool,
    target_user: Option<&str>,
) -> Result<ServiceStateSnapshot, String> {
    if !is_removable_unit_basename(name) {
        return Err(format!("systemd-unit-name-invalid-{name}"));
    }
    let observation = observe_systemd_state("service-state-snapshot", name, user, target_user, 30);
    if observation.enabled.is_none() || observation.active.is_none() {
        return Err(format!("systemd-state-readback-failed-{name}"));
    }
    Ok(ServiceStateSnapshot {
        name: name.to_string(),
        user,
        target_user: target_user.map(str::to_string),
        enabled: observation.enabled.as_deref() == Some("enabled"),
        active: observation.active.as_deref() == Some("active"),
    })
}

pub(crate) fn systemctl(
    action: &str,
    service: &str,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
) -> CmdResult {
    let mut args: Vec<String> = systemctl_scope_args(user, target_user);
    match action {
        "unit-present" => {
            args.extend([
                "show".to_string(),
                "--property=LoadState".to_string(),
                "--value".to_string(),
                service.to_string(),
            ]);
        }
        "load-state" => {
            args.extend([
                "show".to_string(),
                "--property=LoadState".to_string(),
                "--value".to_string(),
                service.to_string(),
            ]);
        }
        "unit-file-state" => {
            args.extend([
                "show".to_string(),
                "--property=UnitFileState".to_string(),
                "--value".to_string(),
                service.to_string(),
            ]);
        }
        "needs-reload" => {
            args.extend([
                "show".to_string(),
                "--property=NeedDaemonReload".to_string(),
                "--value".to_string(),
                service.to_string(),
            ]);
        }
        "is-active-probe" => {
            args.extend(["is-active".to_string(), service.to_string()]);
        }
        "condition-show" => args.extend([
            "show".to_string(),
            "--property=ActiveState,ConditionResult,Conditions,LoadState".to_string(),
            service.to_string(),
        ]),
        "condition-status" => args.extend([
            "status".to_string(),
            "--no-pager".to_string(),
            "--lines=0".to_string(),
            "--full".to_string(),
            service.to_string(),
        ]),
        "condition-cat" => args.extend(["cat".to_string(), "--".to_string(), service.to_string()]),
        other => {
            return CmdResult {
                ok: false,
                code: -1,
                stdout: String::new(),
                stderr: format!("systemd-action-unsupported-{other}"),
            }
        }
    }
    let result = super::read_only_command_with_timeout(
        &super::systemctl_program(),
        &args,
        std::time::Duration::from_secs(timeout_secs),
    );
    CmdResult {
        ok: result.ok,
        code: result.code.unwrap_or(if result.ok { 0 } else { -1 }),
        stdout: result.stdout,
        stderr: result.stderr,
    }
}

pub(crate) fn unit_present_result(mut result: CmdResult, service: &str) -> CmdResult {
    if result.ok && result.stdout.trim() == "not-found" {
        result.ok = false;
        result.code = 1;
        result.stderr = format!("systemd-unit-missing-{service}");
    }
    result
}

pub(crate) fn unit_file_path(service: &str) -> Option<PathBuf> {
    let path = Path::new(service);
    if service.is_empty()
        || path.is_absolute()
        || path.components().count() != 1
        || path.file_name().is_none()
    {
        return None;
    }
    Some(PathBuf::from("/etc/systemd/system").join(path))
}

fn systemctl_scope_args(user: bool, target_user: Option<&str>) -> Vec<String> {
    if !user {
        return Vec::new();
    }
    let mut args = vec!["--user".to_string()];
    if let Some(target_user) = target_user.filter(|value| !value.trim().is_empty()) {
        args.push(format!("--machine={target_user}@.host"));
    }
    args
}

pub(crate) fn state(
    kind: &str,
    service: &str,
    user: bool,
    target_user: Option<&str>,
    timeout_secs: u64,
) -> Option<String> {
    if service.is_empty() {
        return None;
    }
    let result = super::systemd_state_query(kind, service, user, target_user, timeout_secs);
    if result.code.is_none() {
        None
    } else {
        let value = result.stdout.trim();
        (!value.is_empty()).then(|| value.to_string())
    }
}

pub(crate) fn show_properties(
    service: &str,
    expected: &std::collections::BTreeMap<String, serde_json::Value>,
) -> (CmdResult, std::collections::BTreeMap<String, String>) {
    let mut argv = vec!["show".to_string(), service.to_string()];
    for key in expected.keys() {
        argv.push("-p".to_string());
        argv.push(key.clone());
    }
    argv.push("--no-pager".to_string());
    let result = super::read_only_command_with_timeout(
        &super::systemctl_program(),
        &argv,
        std::time::Duration::from_secs(30),
    );
    let command = CmdResult {
        ok: result.ok,
        code: result.code.unwrap_or(if result.ok { 0 } else { -1 }),
        stdout: result.stdout,
        stderr: result.stderr,
    };
    let mut observed = std::collections::BTreeMap::new();
    for line in command.stdout.lines() {
        if let Some((key, value)) = line.split_once('=') {
            observed.insert(key.to_string(), value.to_string());
        }
    }
    (command, observed)
}
