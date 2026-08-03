use super::{command, ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::{write_json, CmdResult, OperationOutcome};
use serde_json::{json, Value};
use std::path::Path;

pub const NAME: &str = "ai-coding-harness";
pub const DESCRIPTION: &str =
    "Owner-scoped AI coding harness currency reconciliation primitive that follows upstream only after target observation.";
pub const PERMUTATIONS: &[ToolPermutation] = &[ToolPermutation::new(
    "reconcile",
    "probe current and upstream harness state, then converge only observed deltas",
    &[
        ToolArg::required("owner", ToolArgKind::String),
        ToolArg::required("claude_bin", ToolArgKind::String),
        ToolArg::required("honcho_repo", ToolArgKind::String),
        ToolArg::required("honcho_remote", ToolArgKind::String),
        ToolArg::required("honcho_branch", ToolArgKind::String),
        ToolArg::optional("timeout_secs", ToolArgKind::Integer),
    ],
)];
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION, PERMUTATIONS);

const CLAUDE_PACKAGE: &str = "@anthropic-ai/claude-code";
const HONCHO_PLUGIN_PACKAGE: &str = "honcho";

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
    let tokens: Vec<_> = text
        .split_whitespace()
        .map(|value| value.trim_start_matches('v'))
        .filter(|value| {
            value.chars().next().is_some_and(|ch| ch.is_ascii_digit())
                && value
                    .chars()
                    .all(|ch| ch.is_ascii_digit() || ch == '.' || ch == '-')
        })
        .collect();
    (tokens.len() == 1).then(|| tokens[0].to_string())
}

fn registry_version(text: &str) -> Option<String> {
    serde_json::from_str::<String>(text)
        .ok()
        .or_else(|| version(text))
        .filter(|value| !value.is_empty())
}

fn git_head(text: &str) -> Option<String> {
    let values: Vec<_> = text
        .split_whitespace()
        .filter(|value| value.len() == 40 && value.chars().all(|ch| ch.is_ascii_hexdigit()))
        .collect();
    (values.len() == 1).then(|| values[0].to_string())
}

fn plugin_version(value: &Value, id: &str) -> Option<String> {
    match value {
        Value::Object(map) => {
            let matches_id = map
                .get("id")
                .or_else(|| map.get("name"))
                .and_then(Value::as_str)
                == Some(id);
            if matches_id {
                if let Some(version) = map.get("version").and_then(Value::as_str) {
                    return Some(version.to_string());
                }
            }
            let found: Vec<_> = map
                .values()
                .filter_map(|item| plugin_version(item, id))
                .collect();
            (found.len() == 1)
                .then(|| found.into_iter().next())
                .flatten()
        }
        Value::Array(items) => {
            let found: Vec<_> = items
                .iter()
                .filter_map(|item| plugin_version(item, id))
                .collect();
            (found.len() == 1)
                .then(|| found.into_iter().next())
                .flatten()
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Default)]
struct State {
    claude: Option<String>,
    claude_latest: Option<String>,
    plugin: Option<String>,
    plugin_latest: Option<String>,
    head: Option<String>,
    head_latest: Option<String>,
    probes: Vec<Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct UpdatePlan {
    claude: bool,
    plugin: bool,
    honcho: bool,
}

fn command_receipt(name: &str, result: &CmdResult) -> Value {
    json!({"name": name, "result": result})
}

fn state_receipt(state: &State) -> Value {
    json!({
        "claude_version": state.claude,
        "claude_latest_version": state.claude_latest,
        "honcho_plugin_version": state.plugin,
        "honcho_plugin_latest_version": state.plugin_latest,
        "honcho_head": state.head,
        "honcho_latest_head": state.head_latest,
        "probes": state.probes,
    })
}

fn update_plan(state: &State) -> Result<UpdatePlan, &'static str> {
    let comparable = |current: &Option<String>, latest: &Option<String>, signal| {
        current
            .as_ref()
            .zip(latest.as_ref())
            .map(|(current, latest)| current != latest)
            .ok_or(signal)
    };
    Ok(UpdatePlan {
        claude: comparable(
            &state.claude,
            &state.claude_latest,
            "claude-target-unavailable",
        )?,
        plugin: comparable(
            &state.plugin,
            &state.plugin_latest,
            "honcho-plugin-target-unavailable",
        )?,
        honcho: comparable(&state.head, &state.head_latest, "honcho-target-unavailable")?,
    })
}

fn read_state(
    owner: &str,
    claude_bin: &str,
    repo: &str,
    remote: &str,
    branch: &str,
    timeout_secs: u64,
) -> State {
    let claude = run(claude_bin, &["--version"], None, owner, timeout_secs);
    let claude_latest = run(
        "npm",
        &["view", CLAUDE_PACKAGE, "version", "--json"],
        None,
        owner,
        timeout_secs,
    );
    let plugins = run(
        claude_bin,
        &["plugin", "list", "--json"],
        None,
        owner,
        timeout_secs,
    );
    let plugin_latest = run(
        "npm",
        &["view", HONCHO_PLUGIN_PACKAGE, "version", "--json"],
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
    let head_latest = run(
        "git",
        &["ls-remote", remote, branch],
        Some(repo),
        owner,
        timeout_secs,
    );
    let git_status = run(
        "git",
        &["status", "--porcelain", "--untracked-files=no"],
        Some(repo),
        owner,
        timeout_secs,
    );
    State {
        claude: claude.ok.then(|| version(&claude.stdout)).flatten(),
        claude_latest: claude_latest
            .ok
            .then(|| registry_version(&claude_latest.stdout))
            .flatten(),
        plugin: plugins
            .ok
            .then(|| serde_json::from_str::<Value>(&plugins.stdout).ok())
            .flatten()
            .and_then(|value| plugin_version(&value, "honcho@honcho")),
        plugin_latest: plugin_latest
            .ok
            .then(|| registry_version(&plugin_latest.stdout))
            .flatten(),
        head: head.ok.then(|| git_head(&head.stdout)).flatten(),
        head_latest: head_latest
            .ok
            .then(|| git_head(&head_latest.stdout))
            .flatten(),
        probes: vec![
            command_receipt("claude --version", &claude),
            command_receipt(
                "npm view @anthropic-ai/claude-code version --json",
                &claude_latest,
            ),
            command_receipt("claude plugin list --json", &plugins),
            command_receipt("npm view honcho version --json", &plugin_latest),
            command_receipt("git rev-parse HEAD", &head),
            command_receipt(&format!("git ls-remote {remote} {branch}"), &head_latest),
            command_receipt("git status --porcelain --untracked-files=no", &git_status),
        ],
    }
}

pub(crate) fn reconcile(
    owner: &str,
    claude_bin: &str,
    repo: &str,
    remote: &str,
    branch: &str,
    timeout_secs: u64,
    receipt: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    if owner != "owner" {
        return Err("ai-coding-harness-owner-refused".into());
    }

    let before = read_state(owner, claude_bin, repo, remote, branch, timeout_secs);
    let plan = update_plan(&before);
    let mut commands = Vec::new();

    if apply {
        if let Ok(plan) = &plan {
            if plan.claude {
                let result = run(claude_bin, &["update"], None, owner, timeout_secs);
                commands.push(command_receipt("claude update", &result));
            }
            if plan.plugin {
                let result = run(
                    claude_bin,
                    &["plugin", "update", "honcho@honcho", "--scope", "user"],
                    None,
                    owner,
                    timeout_secs,
                );
                commands.push(command_receipt(
                    "claude plugin update honcho@honcho --scope user",
                    &result,
                ));
            }
            if plan.honcho {
                let fetch = run(
                    "git",
                    &["fetch", remote, branch],
                    Some(repo),
                    owner,
                    timeout_secs,
                );
                commands.push(command_receipt(
                    &format!("git fetch {remote} {branch}"),
                    &fetch,
                ));
                if fetch.ok {
                    let merge_ref = format!("{remote}/{branch}");
                    let merge = run(
                        "git",
                        &["merge", "--ff-only", &merge_ref],
                        Some(repo),
                        owner,
                        timeout_secs,
                    );
                    commands.push(command_receipt(
                        &format!("git merge --ff-only {merge_ref}"),
                        &merge,
                    ));
                    if merge.ok {
                        let sync = run("uv", &["sync"], Some(repo), owner, timeout_secs);
                        commands.push(command_receipt("uv sync", &sync));
                    }
                }
            }
        }
    }

    let after_updates = read_state(owner, claude_bin, repo, remote, branch, timeout_secs);
    if apply && plan.as_ref().is_ok_and(|plan| plan.honcho) && before.head != after_updates.head {
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
        commands.push(command_receipt(
            "systemctl --user restart honcho-api.service honcho-deriver.service",
            &restart,
        ));
    }
    let after = read_state(owner, claude_bin, repo, remote, branch, timeout_secs);
    let changed =
        before.claude != after.claude || before.plugin != after.plugin || before.head != after.head;
    let next_session_required = before.claude != after.claude || before.plugin != after.plugin;
    let commands_ok = commands
        .iter()
        .all(|command| command["result"]["ok"] == Value::Bool(true));
    let plan_signal = plan.err().unwrap_or("none");
    let ok = commands_ok && plan_signal == "none";
    let signal = if plan_signal != "none" {
        plan_signal
    } else if apply && !commands_ok {
        "ai-coding-harness-command-failed"
    } else {
        "none"
    };
    write_json(
        &receipt.join("run.json"),
        &json!({
            "schema": "harmonia.ai_coding_harness.reconcile.v1",
            "ok": ok,
            "apply": apply,
            "changed": changed,
            "owner": owner,
            "honcho_remote": remote,
            "honcho_branch": branch,
            "before": state_receipt(&before),
            "after": state_receipt(&after),
            "commands": commands,
            "next_session_required": next_session_required,
            "first_missing_signal": signal,
        }),
    )?;
    Ok(OperationOutcome {
        ok,
        changed,
        skipped: !apply,
        message: format!("ai coding harness {signal}"),
        command: None,
    })
}
