use crate::{CmdResult, OperationOutcome};
use crate::atoms::ask::change_unit::show_properties;
use crate::atoms::attest::change_unit::write_show_assert_receipt;
use serde_json::Value;
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
    let (command, observed) = show_properties(service, expected);
    let first_divergent = expected.iter().find_map(|(key, wanted)| {
        let wanted = wanted.as_str().map(str::to_owned).unwrap_or_else(|| wanted.to_string());
        match observed.get(key) {
            Some(actual) if show_value_matches(key, &wanted, actual) => None,
            Some(actual) => Some(format!("{key}: expected={wanted} observed={actual}")),
            None => Some(format!("{key}: expected={wanted} observed=<missing>")),
        }
    });
    let ok = command.ok && first_divergent.is_none();
    let message = if !command.ok {
        format!("systemctl show failed for {service} (code={:?}): {}", command.code,
            if command.stderr.is_empty() { &command.stdout } else { &command.stderr })
    } else {
        first_divergent.clone().unwrap_or_else(|| format!("systemd show-assert {service}"))
    };
    write_show_assert_receipt(receipt_dir, name, service, expected, &observed, &command, first_divergent)?;
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
