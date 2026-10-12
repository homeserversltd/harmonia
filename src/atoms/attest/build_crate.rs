// Owned attest atom for build-crate
use crate::atoms;
use std::path::Path;

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
    let Some(result) = result else {
        return Ok(());
    };

    let source_build_sha = crate::hyalos::bounded_json_string(source_build_sha, 80);
    let installed_build_sha = installed_build_sha
        .map(|sha| crate::hyalos::bounded_json_string(sha, 80))
        .unwrap_or_else(|| "null".into());
    let cwd = crate::hyalos::bounded_json_string(&cwd.display().to_string(), 128);
    let bearer = crate::hyalos::bounded_json_string(bearer, 80);
    let identity_count = environment
        .iter()
        .filter(|(key, _)| key.ends_with("_BUILD_SHA"))
        .count();
    let first_missing_signal = if result.ok {
        "none"
    } else {
        "build-command-failed"
    };

    atoms::attest::attest(
        log,
        &atoms::Receipt {
            atom: "build-crate".into(),
            ok: result.ok,
            drift: atoms::Drift::Current,
            message: format!(
                "source_build_sha={source_build_sha}; installed_build_sha={installed_build_sha}; installed_binary_present={installed_binary_present}; first_missing_signal={first_missing_signal}; code={:?}; cwd={cwd}; bearer={bearer}; identity_count={identity_count}",
                result.code,
            ),
        },
        &[],
    )
}
