use super::{command, ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::{write_json, CmdResult, OperationOutcome};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

pub const NAME: &str = "ai-coding-harness";
pub const DESCRIPTION: &str =
    "Owner-scoped AI coding harness currency reconciliation primitive with blessed-lock ratchet discipline.";
pub const PERMUTATIONS: &[ToolPermutation] = &[ToolPermutation::new(
    "reconcile",
    "observe harness currency and restore only lock-blessed drift",
    &[
        ToolArg::required("lock", ToolArgKind::String),
        ToolArg::required("owner", ToolArgKind::String),
        ToolArg::required("claude_bin", ToolArgKind::String),
        ToolArg::required("honcho_repo", ToolArgKind::String),
        ToolArg::optional("timeout_secs", ToolArgKind::Integer),
    ],
)];
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION, PERMUTATIONS);
const SCHEMA: &str = "harmonia.ai_coding_harness.lock.v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lock {
    schema: String,
    owner: String,
    claude: ClaudeLock,
    honcho_plugin: PluginLock,
    honcho_server: ServerLock,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaudeLock {
    policy: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default = "default_claude_action")]
    action: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginLock {
    policy: String,
    plugin_id: String,
    #[serde(default)]
    version: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerLock {
    policy: String,
    remote: String,
    branch: String,
    #[serde(default)]
    head: Option<String>,
}

#[derive(Serialize)]
struct CommandReceipt {
    ok: bool,
    code: i32,
    stderr: String,
}

impl From<&CmdResult> for CommandReceipt {
    fn from(result: &CmdResult) -> Self {
        Self {
            ok: result.ok,
            code: result.code,
            stderr: result.stderr.clone(),
        }
    }
}

#[derive(Serialize)]
struct Observation {
    actual: Option<String>,
    command: CommandReceipt,
    #[serde(skip_serializing_if = "Option::is_none")]
    parse_signal: Option<String>,
}

#[derive(Serialize)]
struct ServerObservation {
    actual_head: Option<String>,
    clean: bool,
    head_command: CommandReceipt,
    dirty_command: CommandReceipt,
    #[serde(skip_serializing_if = "Option::is_none")]
    parse_signal: Option<String>,
}

fn default_claude_action() -> String {
    "install".into()
}

fn valid_policy(policy: &str) -> bool {
    matches!(policy, "blessed" | "unblessed")
}

fn valid_sha(value: &str) -> bool {
    value.len() == 40 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn valid_lock(lock: &Lock, owner: &str) -> bool {
    lock.schema == SCHEMA
        && !owner.trim().is_empty()
        && lock.owner == owner
        && valid_policy(&lock.claude.policy)
        && valid_policy(&lock.honcho_plugin.policy)
        && valid_policy(&lock.honcho_server.policy)
        && matches!(lock.claude.action.as_str(), "update" | "install")
        && lock.honcho_plugin.plugin_id == "honcho@honcho"
        && (lock.claude.policy == "unblessed"
            || lock
                .claude
                .version
                .as_deref()
                .is_some_and(|v| !v.is_empty()))
        && (lock.honcho_plugin.policy == "unblessed"
            || lock
                .honcho_plugin
                .version
                .as_deref()
                .is_some_and(|v| !v.is_empty()))
        && (lock.honcho_server.policy == "unblessed"
            || lock.honcho_server.head.as_deref().is_some_and(valid_sha))
        && !lock.honcho_server.remote.trim().is_empty()
        && !lock.honcho_server.branch.trim().is_empty()
}

fn run(
    program: &str,
    args: &[&str],
    cwd: Option<&str>,
    owner: &str,
    timeout_secs: u64,
) -> CmdResult {
    command::capture_with_cwd_as_bearer_and_timeout(program, args, cwd, owner, timeout_secs)
}

fn version(text: &str) -> Option<String> {
    let candidates: Vec<_> = text
        .split_whitespace()
        .map(|token| token.trim_start_matches('v'))
        .filter(|token| {
            !token.is_empty()
                && token.chars().next().is_some_and(|ch| ch.is_ascii_digit())
                && token
                    .chars()
                    .all(|ch| ch.is_ascii_digit() || ch == '.' || ch == '-')
        })
        .collect();
    (candidates.len() == 1).then(|| candidates[0].to_string())
}

fn plugin_version(value: &Value, id: &str) -> Option<String> {
    match value {
        Value::Object(map) => {
            if map
                .get("id")
                .or_else(|| map.get("name"))
                .and_then(Value::as_str)
                == Some(id)
            {
                return map
                    .get("version")
                    .and_then(Value::as_str)
                    .map(str::to_string);
            }
            let matches: Vec<_> = map
                .values()
                .filter_map(|item| plugin_version(item, id))
                .collect();
            (matches.len() == 1).then(|| matches[0].clone())
        }
        Value::Array(items) => {
            let matches: Vec<_> = items
                .iter()
                .filter_map(|item| plugin_version(item, id))
                .collect();
            (matches.len() == 1).then(|| matches[0].clone())
        }
        _ => None,
    }
}

fn observe(
    lock: &Lock,
    owner: &str,
    claude_bin: &str,
    repo: &str,
    timeout_secs: u64,
) -> (Observation, Observation, ServerObservation) {
    let claude = run(claude_bin, &["--version"], None, owner, timeout_secs);
    let plugins = run(
        claude_bin,
        &["plugin", "list", "--json"],
        None,
        owner,
        timeout_secs,
    );
    let head = run(
        "git",
        &["rev-parse", "HEAD"],
        Some(repo),
        owner,
        timeout_secs,
    );
    let dirty = run(
        "git",
        &["status", "--porcelain", "--untracked-files=no"],
        Some(repo),
        owner,
        timeout_secs,
    );
    let claude_actual = claude.ok.then(|| version(&claude.stdout)).flatten();
    let plugin_actual = plugins
        .ok
        .then(|| serde_json::from_str::<Value>(&plugins.stdout).ok())
        .flatten()
        .and_then(|value| plugin_version(&value, &lock.honcho_plugin.plugin_id));
    let head_actual = head
        .ok
        .then(|| head.stdout.trim().to_string())
        .filter(|value| valid_sha(value));
    let claude_signal = if !claude.ok {
        Some("claude-version-unavailable".into())
    } else if claude_actual.is_none() {
        Some("claude-version-unparseable".into())
    } else {
        None
    };
    let plugin_signal = if !plugins.ok {
        Some("claude-plugin-list-unavailable".into())
    } else if plugin_actual.is_none() {
        Some("honcho-plugin-version-unavailable".into())
    } else {
        None
    };
    (
        Observation {
            actual: claude_actual,
            command: (&claude).into(),
            parse_signal: claude_signal,
        },
        Observation {
            actual: plugin_actual,
            command: (&plugins).into(),
            parse_signal: plugin_signal,
        },
        ServerObservation {
            actual_head: head_actual,
            clean: dirty.ok && dirty.stdout.trim().is_empty(),
            head_command: (&head).into(),
            dirty_command: (&dirty).into(),
            parse_signal: if !head.ok || !dirty.ok {
                Some("honcho-source-unavailable".into())
            } else {
                None
            },
        },
    )
}

fn state(policy: &str, expected: Option<&str>, actual: Option<&str>) -> &'static str {
    if policy == "unblessed" {
        "unblessed"
    } else if actual.is_none() {
        "unavailable"
    } else if expected == actual {
        "current"
    } else {
        "drift"
    }
}

fn server_state(lock: &ServerLock, observed: &ServerObservation) -> &'static str {
    if lock.policy == "unblessed" {
        "unblessed"
    } else if observed.actual_head.is_none() || !observed.clean {
        "unavailable-or-dirty"
    } else if lock.head.as_deref() == observed.actual_head.as_deref() {
        "current"
    } else {
        "drift"
    }
}

fn action(name: &str, result: &CmdResult) -> Value {
    json!({"name": name, "command": CommandReceipt::from(result)})
}

pub(crate) fn reconcile(
    lock_path: &Path,
    owner: &str,
    claude_bin: &str,
    repo: &str,
    timeout_secs: u64,
    receipt_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let text = fs::read_to_string(lock_path).map_err(|error| {
        format!(
            "ai-coding-harness-lock-read-failed {}: {error}",
            lock_path.display()
        )
    })?;
    let lock: Lock = serde_json::from_str(&text).map_err(|error| {
        format!(
            "ai-coding-harness-lock-parse-failed {}: {error}",
            lock_path.display()
        )
    })?;
    if !valid_lock(&lock, owner) {
        return Err("ai-coding-harness-lock-invalid".into());
    }

    let (mut claude, mut plugin, mut server) =
        observe(&lock, owner, claude_bin, repo, timeout_secs);
    let mut claude_state = state(
        &lock.claude.policy,
        lock.claude.version.as_deref(),
        claude.actual.as_deref(),
    );
    let mut plugin_state = state(
        &lock.honcho_plugin.policy,
        lock.honcho_plugin.version.as_deref(),
        plugin.actual.as_deref(),
    );
    let mut honcho_state = server_state(&lock.honcho_server, &server);
    let unblessed = [claude_state, plugin_state, honcho_state].contains(&"unblessed");
    let mut actions = Vec::new();
    let mut changed = false;
    let mut next_session_required = false;

    if apply && !unblessed {
        if claude_state == "drift" {
            let result = match lock.claude.action.as_str() {
                "update" => run(claude_bin, &["update"], None, owner, timeout_secs),
                "install" => run(
                    claude_bin,
                    &[
                        "install",
                        lock.claude.version.as_deref().unwrap_or_default(),
                    ],
                    None,
                    owner,
                    timeout_secs,
                ),
                _ => unreachable!(),
            };
            changed |= result.ok;
            next_session_required |= result.ok;
            actions.push(action("claude-replacement", &result));
        }
        if plugin_state == "drift" {
            let result = run(
                claude_bin,
                &[
                    "plugin",
                    "update",
                    &lock.honcho_plugin.plugin_id,
                    "--scope",
                    "user",
                ],
                None,
                owner,
                timeout_secs,
            );
            changed |= result.ok;
            next_session_required |= result.ok;
            actions.push(action("honcho-plugin-replacement", &result));
        }
        if honcho_state == "drift" {
            let fetch = run(
                "git",
                &[
                    "fetch",
                    &lock.honcho_server.remote,
                    &lock.honcho_server.branch,
                ],
                Some(repo),
                owner,
                timeout_secs,
            );
            actions.push(action("honcho-fetch", &fetch));
            if fetch.ok {
                let merge = run(
                    "git",
                    &[
                        "merge",
                        "--ff-only",
                        lock.honcho_server.head.as_deref().unwrap_or_default(),
                    ],
                    Some(repo),
                    owner,
                    timeout_secs,
                );
                actions.push(action("honcho-merge-ff-only", &merge));
                if merge.ok {
                    let sync = run("uv", &["sync"], Some(repo), owner, timeout_secs);
                    actions.push(action("honcho-uv-sync", &sync));
                    if sync.ok {
                        let restart = command::user_bus_env_for_bearer(owner).map_or_else(
                            |err| CmdResult {
                                ok: false,
                                code: -1,
                                stdout: String::new(),
                                stderr: err,
                            },
                            |env| {
                                command::capture_with_cwd_as_bearer_and_env(
                                    "systemctl",
                                    &[
                                        "--user",
                                        "restart",
                                        "honcho-api.service",
                                        "honcho-deriver.service",
                                    ],
                                    None,
                                    owner,
                                    env,
                                )
                            },
                        );
                        changed |= restart.ok;
                        actions.push(action("honcho-user-service-restart", &restart));
                    }
                }
            }
        }
        (claude, plugin, server) = observe(&lock, owner, claude_bin, repo, timeout_secs);
        claude_state = state(
            &lock.claude.policy,
            lock.claude.version.as_deref(),
            claude.actual.as_deref(),
        );
        plugin_state = state(
            &lock.honcho_plugin.policy,
            lock.honcho_plugin.version.as_deref(),
            plugin.actual.as_deref(),
        );
        honcho_state = server_state(&lock.honcho_server, &server);
    }

    let ok = claude_state == "current" && plugin_state == "current" && honcho_state == "current";
    let first_missing_signal = if unblessed {
        "unblessed-currency-drift"
    } else if [claude_state, plugin_state, honcho_state]
        .iter()
        .any(|state| state.contains("unavailable"))
    {
        "ai-coding-harness-observation-failed"
    } else if ok {
        "none"
    } else {
        "ai-coding-harness-drift"
    };
    write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema": "harmonia.ai_coding_harness.reconcile.v1",
            "ok": ok,
            "apply": apply,
            "changed": changed,
            "owner": owner,
            "lock_path": lock_path,
            "claude": {"expected": lock.claude.version, "policy": lock.claude.policy, "action": lock.claude.action, "state": claude_state, "observation": claude},
            "honcho_plugin": {"expected": lock.honcho_plugin.version, "policy": lock.honcho_plugin.policy, "plugin_id": lock.honcho_plugin.plugin_id, "state": plugin_state, "observation": plugin},
            "honcho_server": {"expected_head": lock.honcho_server.head, "policy": lock.honcho_server.policy, "remote": lock.honcho_server.remote, "branch": lock.honcho_server.branch, "state": honcho_state, "observation": server},
            "actions": actions,
            "mutation_refused": unblessed,
            "next_session_required": next_session_required,
            "first_missing_signal": first_missing_signal,
        }),
    )?;
    Ok(OperationOutcome {
        ok,
        changed,
        skipped: !apply,
        message: format!("ai coding harness {first_missing_signal}"),
        command: None,
    })
}
