use crate::atoms::CommandObservation;
use std::fmt;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub(crate) enum DebianVersionOrder {
    Less,
    Equal,
    Greater,
}
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct VersionProbeEvidence {
    pub program: String,
    pub args: Vec<String>,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timeout_secs: u64,
    pub refused: Option<String>,
}
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct DebianVersionComparison {
    pub order: DebianVersionOrder,
    pub evidence: Vec<VersionProbeEvidence>,
}
#[derive(Debug, Clone)]
pub(crate) struct VersionProbeFailure {
    pub reason: String,
    pub evidence: Vec<VersionProbeEvidence>,
}
impl fmt::Display for VersionProbeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason)
    }
}
impl std::error::Error for VersionProbeFailure {}
fn evidence(
    program: &str,
    args: &[String],
    observation: Option<&CommandObservation>,
    timeout: Duration,
    refused: Option<String>,
) -> VersionProbeEvidence {
    VersionProbeEvidence {
        program: program.to_string(),
        args: args.to_vec(),
        exit_code: observation.and_then(|x| x.code),
        stdout: observation.map(|x| x.stdout.clone()).unwrap_or_default(),
        stderr: observation.map(|x| x.stderr.clone()).unwrap_or_default(),
        timeout_secs: timeout.as_secs(),
        refused,
    }
}
pub(crate) fn compare_debian_versions(
    desired: &str,
    current: &str,
    timeout: Duration,
) -> Result<DebianVersionComparison, VersionProbeFailure> {
    compare_debian_versions_with_runner(desired, current, timeout, |p, a, t| {
        Ok(crate::atoms::ask::read_only_command_with_timeout(p, a, t))
    })
}
pub(crate) fn compare_debian_versions_with_runner<F>(
    desired: &str,
    current: &str,
    timeout: Duration,
    mut runner: F,
) -> Result<DebianVersionComparison, VersionProbeFailure>
where
    F: FnMut(&str, &[String], Duration) -> Result<CommandObservation, String>,
{
    let mut all_evidence = Vec::new();
    let predicate =
        |left: &str, right: &str, runner: &mut F, all: &mut Vec<VersionProbeEvidence>| {
            let args = vec![
                "--compare-versions".into(),
                left.into(),
                "le".into(),
                right.into(),
            ];
            let observation = match runner("/usr/bin/dpkg", &args, timeout) {
                Ok(x) => x,
                Err(error) => {
                    let reason = format!("invocation-error:{error}");
                    all.push(evidence(
                        "/usr/bin/dpkg",
                        &args,
                        None,
                        timeout,
                        Some(reason.clone()),
                    ));
                    return Err(VersionProbeFailure {
                        reason,
                        evidence: all.clone(),
                    });
                }
            };
            let refusal = if observation.stderr.contains("timed out") {
                Some("timeout".into())
            } else if !observation.stdout.is_empty() {
                Some("nonempty-stdout".into())
            } else if !observation.stderr.is_empty() {
                Some("nonempty-stderr".into())
            } else if observation.code.is_none() {
                Some("no-exit-code".into())
            } else if observation.code != Some(0) && observation.code != Some(1) {
                Some("unexpected-exit-code".into())
            } else {
                None
            };
            all.push(evidence(
                "/usr/bin/dpkg",
                &args,
                Some(&observation),
                timeout,
                refusal.clone(),
            ));
            if let Some(reason) = refusal {
                return Err(VersionProbeFailure {
                    reason,
                    evidence: all.clone(),
                });
            }
            Ok(observation.code == Some(0))
        };
    let le = predicate(desired, current, &mut runner, &mut all_evidence)?;
    let order = if !le {
        DebianVersionOrder::Greater
    } else if predicate(current, desired, &mut runner, &mut all_evidence)? {
        DebianVersionOrder::Equal
    } else {
        DebianVersionOrder::Less
    };
    Ok(DebianVersionComparison {
        order,
        evidence: all_evidence,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn obs(code: i32, stdout: &str) -> CommandObservation {
        CommandObservation {
            program: "/usr/bin/dpkg".into(),
            args: vec![],
            ok: code == 0,
            code: Some(code),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }
    #[test]
    fn package_ceiling_dpkg_membrane_uses_exact_command_and_args() {
        let mut seen = vec![];
        let r = compare_debian_versions_with_runner("1", "2", Duration::from_secs(2), |p, a, t| {
            seen.push((p.to_string(), a.to_vec(), t));
            Ok(obs(0, ""))
        })
        .unwrap();
        assert_eq!(r.order, DebianVersionOrder::Equal);
        assert_eq!(seen[0].0, "/usr/bin/dpkg");
        assert_eq!(seen[0].1, vec!["--compare-versions", "1", "le", "2"]);
        assert_eq!(seen[0].2, Duration::from_secs(2));
        assert_eq!(r.evidence.len(), 2);
    }
    #[test]
    fn package_ceiling_false_predicate_decodes_greater() {
        let r = compare_debian_versions_with_runner("9", "3", Duration::from_secs(1), |_, _, _| {
            Ok(obs(1, ""))
        })
        .unwrap();
        assert_eq!(r.order, DebianVersionOrder::Greater);
        assert_eq!(r.evidence[0].exit_code, Some(1));
    }
    #[test]
    fn package_ceiling_probe_failure_is_not_lexical_fallback() {
        assert!(compare_debian_versions_with_runner(
            "1",
            "2",
            Duration::from_secs(1),
            |_, _, _| Ok(obs(2, ""))
        )
        .is_err());
    }
    #[test]
    fn package_ceiling_malformed_stdout_is_refused() {
        assert!(compare_debian_versions_with_runner(
            "1",
            "2",
            Duration::from_secs(1),
            |_, _, _| Ok(obs(0, "bad"))
        )
        .is_err());
    }
    #[test]
    fn package_ceiling_nonempty_stderr_is_refused_with_evidence() {
        let r = compare_debian_versions_with_runner("1", "2", Duration::from_secs(3), |_, _, _| {
            Ok(CommandObservation {
                program: "/usr/bin/dpkg".into(),
                args: vec![],
                ok: true,
                code: Some(0),
                stdout: String::new(),
                stderr: "dpkg probe failed".into(),
            })
        })
        .unwrap_err();
        assert!(r.reason.contains("nonempty-stderr"));
        assert_eq!(r.evidence.len(), 1);
        assert_eq!(r.evidence[0].stderr, "dpkg probe failed");
        assert_eq!(r.evidence[0].program, "/usr/bin/dpkg");
        assert_eq!(
            r.evidence[0].args,
            vec!["--compare-versions", "1", "le", "2"]
        );
    }
}
