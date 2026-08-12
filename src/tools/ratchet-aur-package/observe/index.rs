use crate::tools::aur::{self, AurRatchetLock, AurUpstreamState};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Current,
    BehindPin,
    UpstreamMovedPastPin,
}

impl Verdict {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::BehindPin => "behind-pin",
            Self::UpstreamMovedPastPin => "upstream-moved-past-pin",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Observation {
    pub lock: AurRatchetLock,
    pub upstream: AurUpstreamState,
    pub installed_version: Option<String>,
    pub verdict: Verdict,
}

pub(super) fn ratchet(
    package: &str,
    lock_path: &Path,
    upstream_state: Option<&str>,
    install_requested: bool,
) -> Result<Observation, String> {
    let lock = aur::read_lock(lock_path, package)?;
    aur::validate_pin_shape(&lock)?;
    if !aur::is_git_sha(&lock.pkgbuild_sha) {
        return Err("aur-pkgbuild-sha-not-hex40".into());
    }
    let upstream = aur::read_upstream_state(upstream_state, package)?;
    let installed_version = installed_version(package);
    let upstream_moved = upstream.pkgbuild_sha != lock.pkgbuild_sha
        || upstream.available_version != lock.pinned_version;
    let verdict = if upstream_moved {
        Verdict::UpstreamMovedPastPin
    } else if install_requested
        && installed_version.as_deref() == Some(lock.pinned_version.as_str())
    {
        Verdict::Current
    } else {
        Verdict::BehindPin
    };
    Ok(Observation {
        lock,
        upstream,
        installed_version,
        verdict,
    })
}

pub(super) fn installed_version(package: &str) -> Option<String> {
    let program = crate::tools::package::pacman_program();
    if !Path::new(&program).exists() {
        return None;
    }
    let result =
        crate::atoms::ask::read_only_command(&program, &["-Q".to_string(), package.to_string()]);
    if !result.ok {
        return None;
    }
    let mut fields = result.stdout.split_whitespace();
    let _name = fields.next()?;
    fields.next().map(ToString::to_string)
}

#[derive(Debug, Clone)]
pub(crate) struct ArtifactLockObservation {
    pub ok: bool,
    pub artifact_count: usize,
    pub first_missing_signal: String,
}

#[derive(Deserialize)]
struct Lock {
    profile: String,
    artifacts: HashMap<String, Artifact>,
}

#[derive(Deserialize)]
struct Artifact {
    version: String,
    path: String,
    sha256: String,
    #[serde(default)]
    policy: String,
}

pub(super) fn artifact_lock(
    lock_path: &Path,
    profile: Option<&str>,
    receipt_dir: &Path,
    apply: bool,
) -> Result<ArtifactLockObservation, String> {
    let lock_file = crate::atoms::ask::file(lock_path)
        .map_err(|error| format!("artifact-lock-read-failed {}: {error}", lock_path.display()))?;
    let lock: Lock = serde_json::from_slice(&lock_file.bytes).map_err(|error| {
        format!(
            "artifact-lock-parse-failed {}: {error}",
            lock_path.display()
        )
    })?;
    let mut entries = Vec::new();
    let mut ok = profile.map(|value| value == lock.profile).unwrap_or(true);
    let mut first_missing_signal = if ok {
        "none".to_string()
    } else {
        "artifact-lock-profile-mismatch".to_string()
    };
    for (name, artifact) in &lock.artifacts {
        let path = Path::new(&artifact.path);
        let actual = crate::atoms::ask::file_if_present(path)?.map(|file| file.sha256);
        let entry_ok = actual
            .as_deref()
            .is_some_and(|sha| sha.eq_ignore_ascii_case(&artifact.sha256));
        if !entry_ok && first_missing_signal == "none" {
            first_missing_signal = format!("pinned-artifact-{name}-drift");
        }
        ok &= entry_ok;
        crate::write_json(
            &receipt_dir.join(format!("artifact-lock-{}.json", sanitize(name))),
            &json!({
                "schema":"harmonia.artifact_lock.artifact.v1", "ok":entry_ok, "apply":apply,
                "name":name, "version":artifact.version, "path":artifact.path, "expected_sha256":artifact.sha256,
                "actual_sha256":actual, "exists":actual.is_some(), "policy":artifact.policy,
                "first_missing_signal": if entry_ok {"none"} else {first_missing_signal.as_str()}
            }),
        )?;
        entries.push(json!({"name":name,"version":artifact.version,"path":artifact.path,"ok":entry_ok,"exists":actual.is_some(),"policy":artifact.policy}));
    }
    crate::write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema":"harmonia.artifact_lock.verify.v1", "ok":ok, "apply":apply, "mutation":false,
            "profile_id":lock.profile, "lock_path":lock_path, "artifact_count":entries.len(),
            "artifacts":entries, "first_missing_signal":first_missing_signal
        }),
    )?;
    Ok(ArtifactLockObservation {
        ok,
        artifact_count: entries.len(),
        first_missing_signal,
    })
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character
            } else {
                '-'
            }
        })
        .collect()
}
