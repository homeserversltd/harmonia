use crate::{command_capture, write_json, CmdResult, OperationOutcome};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) use crate::atoms::systemd::{
    execute_validated_step, run_action, run_permutation_with_policy, validate_candidate_units,
};

/// Observe systemd unit properties and assert exact key/value equality.
/// This permutation never mutates systemd, even during apply runs.
fn show_value_matches(key: &str, wanted: &str, actual: &str) -> bool {
    actual == wanted || ((key == "User" || key == "Group") && wanted == "root" && actual.is_empty())
}

pub(crate) fn show_assert(
    receipt_dir: &Path,
    name: &str,
    service: &str,
    expected: &BTreeMap<String, Value>,
) -> Result<OperationOutcome, String> {
    let mut argv = vec!["show".to_string(), service.to_string()];
    for key in expected.keys() {
        argv.push("-p".to_string());
        argv.push(key.clone());
    }
    argv.push("--no-pager".to_string());
    let refs = argv.iter().map(String::as_str).collect::<Vec<_>>();
    let command = command_capture("/usr/bin/systemctl", &refs);
    let mut observed = BTreeMap::new();
    for line in command.stdout.lines() {
        if let Some((key, value)) = line.split_once('=') {
            observed.insert(key.to_string(), value.to_string());
        }
    }
    let first_divergent = expected.iter().find_map(|(key, wanted)| {
        let wanted = wanted
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| wanted.to_string());
        match observed.get(key) {
            Some(actual) if show_value_matches(key, &wanted, actual) => None,
            Some(actual) => Some(format!("{key}: expected={wanted} observed={actual}")),
            None => Some(format!("{key}: expected={wanted} observed=<missing>")),
        }
    });
    let ok = command.ok && first_divergent.is_none();
    let message = if !command.ok {
        format!(
            "systemctl show failed for {service} (code={:?}): {}",
            command.code,
            if command.stderr.is_empty() {
                &command.stdout
            } else {
                &command.stderr
            }
        )
    } else {
        first_divergent
            .clone()
            .unwrap_or_else(|| format!("systemd show-assert {service}"))
    };
    write_json(
        &receipt_dir.join(format!("{name}.json")),
        &json!({
            "schema": "harmonia.routine_tool.receipt.v1", "ok": ok, "changed": false,
            "skipped": false, "observation_only": true, "service": service, "expected": expected, "observed": observed,
            "first_divergent": first_divergent, "stdout": command.stdout,
            "stderr": command.stderr, "code": command.code,
        }),
    )?;
    Ok(OperationOutcome {
        ok,
        changed: false,
        skipped: false,
        message,
        command: Some(CmdResult { ok, ..command }),
    })
}

#[cfg(test)]
mod tests {
    use super::show_value_matches;

    #[test]
    fn empty_user_and_group_values_match_root() {
        assert!(show_value_matches("User", "root", ""));
        assert!(show_value_matches("Group", "root", ""));
    }

    #[test]
    fn non_root_user_value_does_not_match_root() {
        assert!(!show_value_matches("User", "root", "daemon"));
    }

    #[test]
    fn empty_unset_non_root_property_does_not_match() {
        assert!(!show_value_matches("Description", "expected", ""));
    }
}
