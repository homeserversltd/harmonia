use super::{command, ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::{write_json, CmdResult, OperationOutcome};
use serde_json::{json, Value};
use std::path::Path;

pub const NAME: &str = "ai-coding-harness";
pub const DESCRIPTION: &str =
    "Owner-scoped AI coding harness currency reconciliation primitive that always follows upstream.";
pub const PERMUTATIONS: &[ToolPermutation] = &[ToolPermutation::new(
    "reconcile",
    "read current harness state and converge it to the current upstream state",
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

struct State {
    claude: Option<String>,
    plugin: Option<String>,
    head: Option<String>,
    git_status: Value,
}

fn command_receipt(name: &str, result: &CmdResult) -> Value {
    json!({"name": name, "result": result})
}

fn upstream_command_names(remote: &str, branch: &str) -> Vec<String> {
    vec![
        "claude update".into(),
        "claude plugin update honcho@honcho --scope user".into(),
        format!("git fetch {remote} {branch}"),
        format!("git merge --ff-only {remote}/{branch}"),
        "uv sync".into(),
        "systemctl --user restart honcho-api.service honcho-deriver.service".into(),
    ]
}

fn read_state(owner: &str, claude_bin: &str, repo: &str, timeout_secs: u64) -> State {
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
    let git_status = run(
        "git",
        &["status", "--porcelain", "--untracked-files=no"],
        Some(repo),
        owner,
        timeout_secs,
    );
    State {
        claude: claude.ok.then(|| version(&claude.stdout)).flatten(),
        plugin: plugins
            .ok
            .then(|| serde_json::from_str::<Value>(&plugins.stdout).ok())
            .flatten()
            .and_then(|value| plugin_version(&value, "honcho@honcho")),
        head: head
            .ok
            .then(|| head.stdout.trim().to_string())
            .filter(|value| value.len() == 40 && value.chars().all(|ch| ch.is_ascii_hexdigit())),
        git_status: command_receipt("git status --porcelain --untracked-files=no", &git_status),
    }
}

fn state_receipt(state: &State) -> Value {
    json!({
        "claude_version": state.claude,
        "honcho_plugin_version": state.plugin,
        "honcho_head": state.head,
        "git_status": state.git_status,
    })
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

    let before = read_state(owner, claude_bin, repo, timeout_secs);
    let mut commands = Vec::new();

    if apply {
        let mut planned = upstream_command_names(remote, branch).into_iter();
        let claude_update = run(claude_bin, &["update"], None, owner, timeout_secs);

        commands.push(command_receipt(&planned.next().unwrap(), &claude_update));

        let plugin_update = run(
            claude_bin,
            &["plugin", "update", "honcho@honcho", "--scope", "user"],
            None,
            owner,
            timeout_secs,
        );

        commands.push(command_receipt(&planned.next().unwrap(), &plugin_update));

        let fetch = run(
            "git",
            &["fetch", remote, branch],
            Some(repo),
            owner,
            timeout_secs,
        );

        commands.push(command_receipt(&planned.next().unwrap(), &fetch));

        let merge_ref = format!("{remote}/{branch}");
        let merge = run(
            "git",
            &["merge", "--ff-only", &merge_ref],
            Some(repo),
            owner,
            timeout_secs,
        );

        commands.push(command_receipt(&planned.next().unwrap(), &merge));

        let sync = run("uv", &["sync"], Some(repo), owner, timeout_secs);

        commands.push(command_receipt(&planned.next().unwrap(), &sync));

        let updated = read_state(owner, claude_bin, repo, timeout_secs);
        let service_material_changed = before.head != updated.head;
        let restart = if service_material_changed {
            command::user_bus_env_for_bearer(owner).map_or_else(
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
            )
        } else {
            CmdResult {
                ok: true,
                code: 0,
                stdout: "converged-quiet: service material unchanged".into(),
                stderr: String::new(),
            }
        };
        commands.push(command_receipt(&planned.next().unwrap(), &restart));
    }

    let after = read_state(owner, claude_bin, repo, timeout_secs);
    let changed = before.claude != after.claude
        || before.plugin != after.plugin
        || before.head != after.head;
    let next_session_required = before.claude != after.claude || before.plugin != after.plugin;
    let ok = commands
        .iter()
        .all(|command| command["result"]["ok"] == Value::Bool(true));
    let signal = if apply && !ok {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_version_and_plugin_parse() {
        assert_eq!(version("v2.1.218"), Some("2.1.218".into()));
        assert_eq!(version("a 1.2 b 3.4"), None);
        let value: Value =
            serde_json::json!({"plugins":[{"id":"honcho@honcho","version":"0.2.7"}]});
        assert_eq!(
            plugin_version(&value, "honcho@honcho"),
            Some("0.2.7".into())
        );
    }

    #[test]
    fn upstream_command_inventory_keeps_restart_as_the_final_gated_action() {
        assert_eq!(
            upstream_command_names("origin", "main"),
            vec![
                "claude update",
                "claude plugin update honcho@honcho --scope user",
                "git fetch origin main",
                "git merge --ff-only origin/main",
                "uv sync",
                "systemctl --user restart honcho-api.service honcho-deriver.service",
            ]
        );
    }
}
