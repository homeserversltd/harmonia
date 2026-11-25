//! Press-scoped Harmonia touch declarations and non-refusing collection.
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

const TOUCH_SCHEMA: &str = "harmonia.touch.v1";
const HOOKED: [&str; 15] = [
    "file_write",
    "atomic_write_bytes_with_ownership",
    "update_existing_xenia",
    "strike",
    "strike_if_current",
    "create_absent",
    "write_engine_state",
    "rename",
    "make-dir",
    "change-mode",
    "change-owner",
    "remove-file",
    "make-link",
    "symlink-converge",
    "remove-dir",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadState {
    Loaded,
    Absent,
    Malformed,
}

impl LoadState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Loaded => "loaded",
            Self::Absent => "absent",
            Self::Malformed => "malformed",
        }
    }
}

#[derive(Debug, Clone)]
struct Allow {
    original: String,
    pattern: String,
    lanes: Vec<String>,
    note: Option<String>,
}

#[derive(Debug, Clone)]
struct Never {
    original: String,
    pattern: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Operation {
    kind: String,
    match_value: String,
    lanes: Vec<String>,
    note: Option<String>,
}

/// A loaded, absent, or malformed touch declaration.
///
/// Fields remain private so declarations are created through [`load`], which
/// validates all three declaration shapes and their operations before use.
#[derive(Debug, Clone)]
pub struct Declaration {
    state: LoadState,
    source: Option<String>,
    source_revision: Option<String>,
    profile: String,
    allow: Vec<Allow>,
    never: Vec<Never>,
    operations: Vec<Operation>,
    failure: Option<String>,
}

impl Declaration {
    fn empty(
        state: LoadState,
        source: Option<String>,
        source_revision: Option<String>,
        profile: &str,
        failure: Option<&str>,
    ) -> Self {
        Self {
            state,
            source,
            source_revision,
            profile: profile.to_owned(),
            allow: Vec::new(),
            never: Vec::new(),
            operations: Vec::new(),
            failure: failure.map(str::to_owned),
        }
    }
}

#[derive(Debug)]
struct ParsedDocument {
    allow: Vec<Allow>,
    never: Vec<Never>,
    operations: Vec<Operation>,
    extends: Option<String>,
}

#[derive(Debug)]
enum ReadDocument {
    Present(Value),
    Absent,
    Malformed(&'static str),
}

fn source_root(root: &Path) -> Option<String> {
    Some(root.display().to_string())
}

/// Return HEAD only when `root` itself is a Git working-tree root.
fn checkout_revision(root: &Path) -> Option<String> {
    let top = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !top.status.success() {
        return None;
    }
    let top_text = String::from_utf8_lossy(&top.stdout);
    let top_path = PathBuf::from(top_text.trim());
    if fs::canonicalize(root).ok()? != fs::canonicalize(top_path).ok()? {
        return None;
    }

    let head = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .ok()?;
    if !head.status.success() {
        return None;
    }
    let revision = String::from_utf8_lossy(&head.stdout).trim().to_owned();
    if revision.is_empty() || revision.bytes().any(|byte| byte.is_ascii_whitespace()) {
        None
    } else {
        Some(revision)
    }
}

fn read_document(path: &Path) -> ReadDocument {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ReadDocument::Absent;
        }
        Err(_) => return ReadDocument::Malformed("touch-document-unreadable"),
    };
    match serde_json::from_slice(&bytes) {
        Ok(value) => ReadDocument::Present(value),
        Err(_) => ReadDocument::Malformed("touch-document-json-invalid"),
    }
}

fn valid_profile_id(profile: &str) -> bool {
    !profile.is_empty()
        && profile != "."
        && profile != ".."
        && !profile.contains('/')
        && !profile.contains('\\')
        && !profile.contains('\0')
}

fn has_placeholder(path: &str) -> bool {
    path.chars()
        .any(|character| matches!(character, '<' | '>' | '{' | '}' | '$'))
}

/// Normalize an absolute lexical path. A raw `..` segment is always refused.
fn normalize_absolute(path: &str) -> Option<String> {
    if !path.starts_with('/') {
        return None;
    }
    let mut segments = Vec::new();
    for segment in path.split('/').skip(1) {
        if segment == ".." {
            return None;
        }
        if segment.is_empty() || segment == "." {
            continue;
        }
        segments.push(segment);
    }
    if segments.is_empty() {
        Some("/".to_owned())
    } else {
        Some(format!("/{}", segments.join("/")))
    }
}

fn normalize_pattern(pattern: &str) -> Option<String> {
    if has_placeholder(pattern) {
        return None;
    }
    let normalized = normalize_absolute(pattern)?;
    for segment in normalized
        .split('/')
        .skip(1)
        .filter(|part| !part.is_empty())
    {
        // `**` is the depth operator only when it occupies a full segment.
        if segment.contains("**") && segment != "**" {
            return None;
        }
    }
    Some(normalized)
}

fn parse_lanes(value: &Value) -> Result<Vec<String>, &'static str> {
    let lanes = value
        .as_array()
        .ok_or("touch-lanes-not-array")?
        .iter()
        .map(|lane| {
            let lane = lane.as_str().ok_or("touch-lane-not-string")?;
            if matches!(lane, "interactable" | "self" | "known-good") {
                Ok(lane.to_owned())
            } else {
                Err("touch-lane-unknown")
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(lanes)
}

fn optional_note(object: &serde_json::Map<String, Value>) -> Result<Option<String>, &'static str> {
    match object.get("note") {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(str::to_owned)
            .map(Some)
            .ok_or("touch-note-not-string"),
    }
}

fn parse_allow(value: &Value) -> Result<Allow, &'static str> {
    let object = value.as_object().ok_or("touch-allow-not-object")?;
    let original = object
        .get("path")
        .and_then(Value::as_str)
        .ok_or("touch-allow-path-missing-or-not-string")?
        .to_owned();
    let pattern = normalize_pattern(&original).ok_or("touch-allow-path-invalid")?;
    let lanes = parse_lanes(object.get("lanes").ok_or("touch-allow-lanes-missing")?)?;
    let note = optional_note(object)?;
    Ok(Allow {
        original,
        pattern,
        lanes,
        note,
    })
}

fn parse_never(value: &Value) -> Result<Never, &'static str> {
    let original = value
        .as_str()
        .ok_or("touch-never-entry-not-string")?
        .to_owned();
    let pattern = normalize_pattern(&original).ok_or("touch-never-path-invalid")?;
    Ok(Never { original, pattern })
}

fn parse_operation(value: &Value) -> Result<Operation, &'static str> {
    let object = value.as_object().ok_or("touch-operation-not-object")?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or("touch-operation-kind-missing-or-not-string")?;
    if !matches!(kind, "package" | "package-upgrade" | "command" | "unit") {
        return Err("touch-operation-kind-unknown");
    }
    let match_value = object
        .get("match")
        .and_then(Value::as_str)
        .ok_or("touch-operation-match-missing-or-not-string")?;
    if match_value.is_empty() {
        return Err("touch-operation-match-empty");
    }
    match kind {
        "package-upgrade" if match_value != "*" => {
            return Err("touch-package-upgrade-match-must-be-star");
        }
        "command" => {
            let has_slash = match_value.contains('/');
            if (has_slash && !match_value.starts_with('/'))
                || match_value.chars().any(char::is_whitespace)
                || (has_slash && normalize_absolute(match_value).is_none())
            {
                return Err("touch-command-match-invalid");
            }
        }
        _ => {}
    }
    let lanes = parse_lanes(object.get("lanes").ok_or("touch-operation-lanes-missing")?)?;
    let note = optional_note(object)?;
    Ok(Operation {
        kind: kind.to_owned(),
        match_value: match_value.to_owned(),
        lanes,
        note,
    })
}

fn parse_document(
    value: Value,
    expected_profile: Option<&str>,
    shared: bool,
    inherited: bool,
) -> Result<ParsedDocument, &'static str> {
    let object = value.as_object().ok_or("touch-document-not-object")?;
    if object.get("schema").and_then(Value::as_str) != Some(TOUCH_SCHEMA) {
        return Err("touch-schema-foreign-or-missing");
    }
    if let Some(profile_value) = object.get("profile") {
        let profile = profile_value.as_str().ok_or("touch-profile-not-string")?;
        if expected_profile.is_some_and(|expected| profile != expected) {
            return Err("touch-profile-mismatch");
        }
    }
    let extends = match object.get("extends") {
        None => None,
        Some(value) => {
            let value = value.as_str().ok_or("touch-extends-not-string")?;
            if !valid_profile_id(value) {
                return Err("touch-extends-invalid");
            }
            Some(value.to_owned())
        }
    };
    if inherited && extends.is_some() {
        return Err("touch-extends-depth-exceeded");
    }

    let allow_values = object
        .get("allow")
        .and_then(Value::as_array)
        .ok_or("touch-allow-missing-or-not-array")?;
    let allow = allow_values
        .iter()
        .map(parse_allow)
        .collect::<Result<Vec<_>, _>>()?;

    let never = match object.get("never") {
        Some(value) => value
            .as_array()
            .ok_or("touch-never-not-array")?
            .iter()
            .map(parse_never)
            .collect::<Result<Vec<_>, _>>()?,
        None if shared => return Err("touch-shared-never-missing"),
        None => Vec::new(),
    };

    let operation_values = object
        .get("operations")
        .and_then(Value::as_array)
        .ok_or("touch-operations-missing-or-not-array")?;
    let operations = operation_values
        .iter()
        .map(parse_operation)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ParsedDocument {
        allow,
        never,
        operations,
        extends,
    })
}

fn malformed(
    source: Option<String>,
    revision: Option<String>,
    profile: &str,
    reason: &'static str,
) -> Declaration {
    Declaration::empty(
        LoadState::Malformed,
        source,
        revision,
        profile,
        Some(reason),
    )
}

fn absent(source: Option<String>, revision: Option<String>, profile: &str) -> Declaration {
    Declaration::empty(
        LoadState::Absent,
        source,
        revision,
        profile,
        Some("touch-required-document-absent"),
    )
}

/// Load shared, selected-profile, and at most one explicitly extended profile.
pub fn load(root: &Path, profile: &str) -> Declaration {
    let source = source_root(root);
    let revision = checkout_revision(root);
    if !valid_profile_id(profile) {
        return malformed(source, revision, profile, "touch-profile-id-invalid");
    }

    let shared_read = read_document(&root.join("shared/touch.json"));
    let profile_read = read_document(&root.join("profiles").join(profile).join("touch.json"));
    if let ReadDocument::Malformed(reason) = &shared_read {
        return malformed(source, revision, profile, reason);
    }
    if let ReadDocument::Malformed(reason) = &profile_read {
        return malformed(source, revision, profile, reason);
    }

    let shared = match shared_read {
        ReadDocument::Present(value) => match parse_document(value, None, true, false) {
            Ok(document) => Some(document),
            Err(reason) => return malformed(source, revision, profile, reason),
        },
        ReadDocument::Absent => None,
        ReadDocument::Malformed(reason) => return malformed(source, revision, profile, reason),
    };
    let selected = match profile_read {
        ReadDocument::Present(value) => match parse_document(value, Some(profile), false, false) {
            Ok(document) => Some(document),
            Err(reason) => return malformed(source, revision, profile, reason),
        },
        ReadDocument::Absent => None,
        ReadDocument::Malformed(reason) => return malformed(source, revision, profile, reason),
    };

    let extended = if let Some(selected_document) = selected.as_ref() {
        if let Some(base_profile) = selected_document.extends.as_deref() {
            if base_profile == profile {
                return malformed(source, revision, profile, "touch-profile-extends-itself");
            }
            let base_path = root.join("profiles").join(base_profile).join("touch.json");
            match read_document(&base_path) {
                ReadDocument::Absent => Some(None),
                ReadDocument::Malformed(reason) => {
                    return malformed(source, revision, profile, reason);
                }
                ReadDocument::Present(value) => {
                    match parse_document(value, Some(base_profile), false, true) {
                        Ok(document) => Some(Some(document)),
                        Err(reason) => return malformed(source, revision, profile, reason),
                    }
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    let (Some(shared), Some(selected)) = (shared, selected) else {
        return absent(source, revision, profile);
    };
    let extended = match extended {
        Some(Some(document)) => Some(document),
        Some(None) => return absent(source, revision, profile),
        None => None,
    };

    let mut allow = shared.allow;
    let mut never = shared.never;
    let mut operations = shared.operations;
    allow.extend(selected.allow);
    never.extend(selected.never);
    operations.extend(selected.operations);
    if let Some(extended) = extended {
        allow.extend(extended.allow);
        never.extend(extended.never);
        operations.extend(extended.operations);
    }

    Declaration {
        state: LoadState::Loaded,
        source,
        source_revision: revision,
        profile: profile.to_owned(),
        allow,
        never,
        operations,
        failure: None,
    }
}

fn segment_matches(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut pattern_index, mut text_index) = (0usize, 0usize);
    let mut last_star = None;
    let mut star_end = 0usize;

    while text_index < text.len() {
        if pattern.get(pattern_index) == Some(&'*') {
            last_star = Some(pattern_index);
            pattern_index += 1;
            star_end = text_index;
        } else if pattern.get(pattern_index) == text.get(text_index) {
            pattern_index += 1;
            text_index += 1;
        } else if let Some(star_index) = last_star {
            star_end += 1;
            text_index = star_end;
            pattern_index = star_index + 1;
        } else {
            return false;
        }
    }
    while pattern.get(pattern_index) == Some(&'*') {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

fn pattern_matches(pattern: &str, path: &str) -> bool {
    let pattern_segments: Vec<&str> = pattern
        .split('/')
        .skip(1)
        .filter(|segment| !segment.is_empty())
        .collect();
    let path_segments: Vec<&str> = path
        .split('/')
        .skip(1)
        .filter(|segment| !segment.is_empty())
        .collect();

    // NFA states represent the next pattern segment. Epsilon closure lets `**`
    // consume zero segments; its self-loop consumes any number of segments.
    let mut active = vec![false; pattern_segments.len() + 1];
    active[0] = true;
    close_double_star(&pattern_segments, &mut active);
    for path_segment in path_segments {
        let mut next = vec![false; pattern_segments.len() + 1];
        for (index, pattern_segment) in pattern_segments.iter().enumerate() {
            if !active[index] {
                continue;
            }
            if *pattern_segment == "**" {
                next[index] = true;
            } else if segment_matches(pattern_segment, path_segment) {
                next[index + 1] = true;
            }
        }
        active = next;
        close_double_star(&pattern_segments, &mut active);
    }
    active[pattern_segments.len()]
}

fn close_double_star(pattern: &[&str], states: &mut [bool]) {
    for index in 0..pattern.len() {
        if states[index] && pattern[index] == "**" {
            states[index + 1] = true;
        }
    }
}

/// Check an absolute target against never-first path rules.
pub fn check(declaration: &Declaration, path: &str) -> Value {
    let normalized = normalize_absolute(path);
    let mut matched_allow = Vec::new();
    let mut matched_never = Vec::new();
    let mut lanes = Vec::<String>::new();
    let mut notes = Vec::<String>::new();

    if declaration.state == LoadState::Loaded {
        if let Some(normalized_path) = normalized.as_deref() {
            for rule in &declaration.allow {
                if pattern_matches(&rule.pattern, normalized_path) {
                    matched_allow.push(rule.original.clone());
                    for lane in &rule.lanes {
                        if !lanes.contains(lane) {
                            lanes.push(lane.clone());
                        }
                    }
                    if let Some(note) = &rule.note {
                        if !notes.contains(note) {
                            notes.push(note.clone());
                        }
                    }
                }
            }
            for rule in &declaration.never {
                if pattern_matches(&rule.pattern, normalized_path) {
                    matched_never.push(rule.original.clone());
                }
            }
        }
    }

    let allowed = declaration.state == LoadState::Loaded
        && normalized.is_some()
        && !matched_allow.is_empty()
        && matched_never.is_empty();
    let decision = match declaration.state {
        LoadState::Absent => "absent",
        LoadState::Malformed => "malformed",
        LoadState::Loaded if normalized.is_none() => "invalid-path",
        LoadState::Loaded if !matched_never.is_empty() => "never",
        LoadState::Loaded if matched_allow.is_empty() => "undeclared",
        LoadState::Loaded => "allowed",
    };

    json!({
        "schema": "harmonia.touch.check.v1",
        "path": path,
        "source": declaration.source,
        "source_revision": declaration.source_revision,
        "declaration": declaration.state.as_str(),
        "profile": declaration.profile,
        "decision": decision,
        "ok": allowed,
        "allowed": allowed,
        "declared": allowed,
        "target": path,
        "normalized": normalized,
        "matched_allow": matched_allow,
        "matched_never": matched_never,
        "lanes": lanes,
        "notes": notes,
        "failure": declaration.failure,
    })
}

#[derive(Debug)]
struct Collector {
    declaration: Declaration,
    writes: Vec<Touch>,
}

#[derive(Debug)]
struct Touch {
    target: String,
    module: Option<String>,
    step: Option<String>,
    owner_accept: bool,
    explicit_lane: Option<&'static str>,
}

static COLLECTOR: OnceLock<Mutex<Option<Collector>>> = OnceLock::new();

fn collector_lock() -> MutexGuard<'static, Option<Collector>> {
    let mutex = COLLECTOR.get_or_init(|| Mutex::new(None));
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Start a fresh press. Starting again discards every prior target and receipt.
pub fn start() {
    let mut state = collector_lock();
    *state = Some(Collector {
        declaration: Declaration::empty(LoadState::Absent, None, None, "", None),
        writes: Vec::new(),
    });
}

pub fn attach(declaration: Declaration) {
    if let Some(collector) = collector_lock().as_mut() {
        collector.declaration = declaration;
    }
}

fn is_within(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn intrinsic_self_target(path: &str) -> bool {
    if ["/var/lib/harmonia", "/run/harmonia"]
        .iter()
        .any(|root| is_within(path, root))
        || matches!(
            path,
            "/usr/local/bin/harmonia" | "/etc/systemd/system/harmonia.timer"
        )
    {
        return true;
    }
    let temp_root = std::env::temp_dir().to_string_lossy().into_owned();
    normalize_absolute(&temp_root).is_some_and(|root| is_within(path, &root))
}

fn lane_hint(normalized_target: Option<&str>, owner_accept: bool) -> Option<&'static str> {
    if let Some(normalized) = normalized_target {
        if intrinsic_self_target(normalized) {
            return Some("self");
        }
        if owner_accept {
            return Some("interactable");
        }
    } else if owner_accept {
        return Some("interactable");
    }
    None
}

fn record_inner(path: &Path, step: Option<&str>, owner_accept: bool, explicit_lane: Option<&'static str>) {
    let mut state = collector_lock();
    let Some(collector) = state.as_mut() else {
        return;
    };

    let target = path.to_string_lossy().into_owned();
    let module =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(crate::deeds::active_module_id))
            .ok()
            .flatten();
    let active_step = std::panic::catch_unwind(std::panic::AssertUnwindSafe(crate::deeds::active_step_id))
        .ok().flatten();
    collector.writes.push(Touch {
        module,
        step: step.map(str::to_owned).or(active_step),
        target,
        owner_accept,
        explicit_lane,
    });
}

/// Record is deliberately non-refusing and inactive until [`start`] is called.
pub fn record(path: &Path, step: Option<&str>, owner_accept: bool) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        record_inner(path, step, owner_accept, None);
    }));
}

pub(crate) fn record_lane(path: &Path, lane: &'static str) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        record_inner(path, None, false, Some(lane));
    }));
}

/// Return this press's touch receipt, or null before collection has started.
pub fn receipt() -> Value {
    let state = collector_lock();
    let Some(collector) = state.as_ref() else {
        return Value::Null;
    };
    let mut seen_targets: HashMap<String, usize> = HashMap::new();
    let mut undeclared: Vec<Value> = Vec::new();
    for touch in &collector.writes {
        let normalized = normalize_absolute(&touch.target);
        let key = normalized.clone().unwrap_or_else(|| touch.target.clone());
        if let Some(&index) = seen_targets.get(&key) {
            if let Some(lane) = touch.explicit_lane {
                if undeclared[index]["lane_hint"] != "self" && undeclared[index]["explicit_lane_present"] == false {
                    undeclared[index]["lane_hint"] = json!(lane);
                    undeclared[index]["explicit_lane_present"] = json!(true);
                }
            }
            continue;
        }
        if check(&collector.declaration, &touch.target)
            .get("allowed").and_then(Value::as_bool).unwrap_or(false) {
            continue;
        }
        seen_targets.insert(key, undeclared.len());
        let derived = lane_hint(normalized.as_deref(), touch.owner_accept);
        let lane = if derived == Some("self") { derived } else { touch.explicit_lane.or(derived) };
        undeclared.push(json!({
            "module": touch.module,
            "step": touch.step,
            "target": touch.target,
            "lane_hint": lane,
            "explicit_lane_present": touch.explicit_lane.is_some(),
        }));
    }
    for row in &mut undeclared {
        if let Some(object) = row.as_object_mut() { object.remove("explicit_lane_present"); }
    }
    json!({
        "declaration": collector.declaration.state.as_str(),
        "source": collector.declaration.source,
        "source_revision": collector.declaration.source_revision,
        "declared_count": collector.declaration.allow.len(),
        "hooked": HOOKED,
        "undeclared": undeclared,
    })
}
