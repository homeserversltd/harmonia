// Owned attest atom for build-crate
use crate::atoms;
use std::path::Path;

const STDERR_TAIL_MAX_CHARS: usize = 4096;

fn stderr_tail(stderr: &str) -> String {
    stderr
        .chars()
        .rev()
        .take(STDERR_TAIL_MAX_CHARS)
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}

pub(crate) fn attest(
    log: &Path,
    result: Option<&crate::atoms::CommandObservation>,
    source_build_sha: &str,
    installed_build_sha: Option<&str>,
    installed_binary_present: bool,
    cwd: &Path,
    bearer: &str,
    environment: &[(String, String)],
) -> Result<(), String> {
    let stderr_tail = result
        .filter(|result| !result.ok)
        .map(|result| format!("; stderr_tail={}", stderr_tail(&result.stderr)))
        .unwrap_or_default();
    atoms::attest::attest(
        log,
        &atoms::Receipt {
            atom: "build-crate".into(),
            ok: result.map_or(true, |result| result.ok),
            drift: atoms::Drift::Current,
            message: format!(
                "source_build_sha={source_build_sha}; installed_build_sha={}; installed_binary_present={installed_binary_present}; code={:?}; cwd={}; bearer={}; identities={}{}",
                installed_build_sha.unwrap_or("null"),
                result.and_then(|result| result.code),
                cwd.display(),
                bearer,
                environment.iter().filter(|(k, _)| k.ends_with("_BUILD_SHA")).map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(","),
                stderr_tail
            ),
        },
        &[],
    )
}
