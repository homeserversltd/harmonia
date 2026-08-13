#[derive(Clone)]
struct SourceGateObservation {
    remote_probe: Option<tools::git_artifact::RemoteHeadProbe>,
    promoted_source_head: Option<CmdResult>,
    installed_binary_present: bool,
    installed_build_sha: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SourceGateDecision {
    ConfirmedMatch,
    ConfirmedMismatch,
    Indeterminate,
}

impl SourceGateObservation {
    fn decision(&self) -> SourceGateDecision {
        let Some(remote_sha) = self
            .remote_probe
            .as_ref()
            .and_then(|probe| probe.remote_sha.as_deref())
        else {
            return SourceGateDecision::ConfirmedMismatch;
        };
        let Some(source_head) = self.promoted_source_head.as_ref() else {
            return SourceGateDecision::ConfirmedMismatch;
        };
        if !self.installed_binary_present
            || !source_head.ok
            || !is_hex_sha(remote_sha)
            || source_head.stdout.trim() != remote_sha
        {
            return SourceGateDecision::ConfirmedMismatch;
        }
        match self.installed_build_sha.as_deref() {
            Some(installed_build_sha) if installed_build_sha == remote_sha => {
                SourceGateDecision::ConfirmedMatch
            }
            Some(_) => SourceGateDecision::ConfirmedMismatch,
            None => SourceGateDecision::Indeterminate,
        }
    }
}

fn read_installed_build_sha(health_url: &str) -> Option<String> {
    let health = health_probe(health_url, 0, 3);
    if !health.ok {
        return None;
    }
    let value: Value = serde_json::from_str(&health.stdout).ok()?;
    let build_sha = value.get("build_sha").and_then(Value::as_str)?.trim();
    is_hex_sha(build_sha).then(|| build_sha.to_string())
}
fn write_source_gate_receipt(
    receipt_dir: &Path,
    spec: &ServiceRuntimeSpec,
    probe: Option<&tools::git_artifact::RemoteHeadProbe>,
    promoted_source_head: Option<&CmdResult>,
    installed_binary_present: bool,
    installed_build_sha: Option<&str>,
    decision: SourceGateDecision,
    movement: &tools::git_artifact::SourceOutcome,
) -> Result<(), String> {
    let remote_sha = probe.and_then(|probe| probe.remote_sha.as_deref());
    let promoted_source_sha = promoted_source_head
        .filter(|result| result.ok)
        .map(|result| result.stdout.trim())
        .filter(|value| is_hex_sha(value));
    let state = if decision == SourceGateDecision::ConfirmedMatch {
        "converged-quiet"
    } else if decision == SourceGateDecision::Indeterminate {
        "blocked"
    } else if remote_sha.is_some() && promoted_source_sha.is_some() {
        "sha-mismatch-or-precondition-incomplete"
    } else {
        probe.map(|probe| probe.state.as_str()).unwrap_or("planned")
    };
    write_json(
        &receipt_dir.join(format!("{}-gate.json", spec.source_op)),
        &json!({
            "schema": "harmonia.service-runtime.source-gate.v1",
            "state": state,
            "observed_state": {
                "promoted_source_sha": promoted_source_sha,
                "installed_build_sha": installed_build_sha,
                "installed_binary_present": installed_binary_present,
            },
            "desired_state": {
                "remote_sha": remote_sha,
            },
            "diff_decision": match decision {
                SourceGateDecision::ConfirmedMatch => "empty",
                SourceGateDecision::ConfirmedMismatch => "different",
                SourceGateDecision::Indeterminate => "indeterminate",
            },
            "movement": {
                "kind": if decision == SourceGateDecision::ConfirmedMismatch { "source-acquire" } else { "none" },
                "attempted": decision == SourceGateDecision::ConfirmedMismatch,
                "ok": movement.ok,
                "changed": movement.changed,
                "resolved_commit": movement.receipt.resolved_commit.as_deref(),
                "promotion": movement.receipt.promotion.as_str(),
            },
            "changed": movement.changed,
            "acquire_skipped": decision != SourceGateDecision::ConfirmedMismatch,
            "build_skipped": decision != SourceGateDecision::ConfirmedMismatch,
            "first_missing_signal": if decision == SourceGateDecision::Indeterminate { "installed-build-sha-unavailable" } else { "none" },
            "reference": probe.map(|probe| probe.reference.as_str()),
            "candidate_index": probe.and_then(|probe| probe.candidate_index),
            "credential_selector": probe.and_then(|probe| probe.credential_selector.as_deref()),
            "failed_candidates": probe.map(|probe| probe.failed_attempts.iter().map(|attempt| json!({
                "index": attempt.index,
                "kind": format!("{:?}", attempt.kind),
                "locator": attempt.locator,
                "credential_selector": attempt.credential_selector,
                "disposition": attempt.disposition,
                "detail": attempt.detail,
            })).collect::<Vec<_>>()),
            "remote_sha": remote_sha,
            "promoted_source_sha": promoted_source_sha,
            "installed_build_sha": installed_build_sha,
            "installed_binary_present": installed_binary_present,
            "probe": probe.map(|probe| &probe.command),
        }),
    )
}
fn source_outcome_cmd(outcome: &tools::git_artifact::SourceOutcome) -> CmdResult {
    let detail = outcome
        .receipt
        .attempts
        .iter()
        .map(|attempt| {
            format!(
                "candidate={} disposition={} detail={}",
                attempt.index, attempt.disposition, attempt.detail
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    CmdResult {
        ok: outcome.ok,
        code: if outcome.ok { 0 } else { 1 },
        stdout: format!("promotion={}\n{}", outcome.receipt.promotion, detail),
        stderr: if outcome.ok {
            String::new()
        } else {
            outcome.receipt.promotion.clone()
        },
    }
}

fn write_source_sha_receipt(
    receipt_dir: &Path,
    name: &str,
    result: &CmdResult,
    bearer: &str,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{name}.json")),
        &json!({
            "schema": "harmonia.command_receipt.v1",
            "name": name,
            "ok": result.ok,
            "exit_code": result.code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "first_missing_signal": if result.ok { "none" } else { "command-failed" },
            "bearer": bearer,
        }),
    )
}

fn is_hex_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
