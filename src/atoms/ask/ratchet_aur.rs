use std::path::Path;

pub(crate) use probe::{ArtifactLockObservation, Observation, Verdict};

pub(crate) fn check(
    package: &str,
    lock_path: &Path,
    upstream_state: Option<&str>,
) -> Result<Observation, String> {
    probe::ratchet(package, lock_path, upstream_state, true)
}

pub(crate) mod probe {
    use crate::tools::aur::{self, AurRatchetLock, AurUpstreamState};
    use crate::{hyalos, PinnedArtifactStatus, PinnedArtifactsLock, Profile};
    use serde::Deserialize;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::fs::{self, File};
    use std::io::Read;
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

    pub(crate) fn ratchet(
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

    pub(crate) fn installed_version(package: &str) -> Option<String> {
        let program = crate::tools::package::pacman_program();
        if !Path::new(&program).exists() {
            return None;
        }
        let result = crate::atoms::ask::read_only_command(
            &program,
            &["-Q".to_string(), package.to_string()],
        );
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

    pub(crate) fn artifact_lock(
        lock_path: &Path,
        profile: Option<&str>,
        receipt_dir: &Path,
        apply: bool,
    ) -> Result<ArtifactLockObservation, String> {
        let lock_file = crate::atoms::ask::file(lock_path).map_err(|error| {
            format!("artifact-lock-read-failed {}: {error}", lock_path.display())
        })?;
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
            crate::atoms::attest::ratchet_aur::write_pinned_artifacts_receipt(
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
        crate::atoms::attest::ratchet_aur::write_pinned_artifacts_receipt(
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

    pub(crate) fn load_pinned_lock(lock_path: &Path) -> Result<PinnedArtifactsLock, String> {
        let text = fs::read_to_string(lock_path)
            .map_err(|e| format!("pinned-lock-read-failed {}: {e}", lock_path.display()))?;
        serde_json::from_str(&text)
            .map_err(|e| format!("pinned-lock-parse-failed {}: {e}", lock_path.display()))
    }

    pub(crate) fn pinned_artifacts_status(lock: &PinnedArtifactsLock) -> Vec<PinnedArtifactStatus> {
        let mut statuses = Vec::new();
        for (name, artifact) in &lock.artifacts {
            let path = Path::new(&artifact.path);
            let actual = sha256_file(path).ok();
            let exists = path.exists();
            let ok = actual
                .as_deref()
                .map(|sha| sha.eq_ignore_ascii_case(&artifact.sha256))
                .unwrap_or(false);
            statuses.push(PinnedArtifactStatus {
                name: name.clone(),
                version: artifact.version.clone(),
                path: artifact.path.clone(),
                expected_sha256: artifact.sha256.clone(),
                actual_sha256: actual,
                exists,
                ok,
                policy: artifact.policy.clone(),
            });
        }
        statuses.sort_by(|a, b| a.name.cmp(&b.name));
        statuses
    }

    pub(crate) fn sha256_file(path: &Path) -> Result<String, String> {
        let mut file =
            File::open(path).map_err(|e| format!("sha256-open-failed {}: {e}", path.display()))?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        loop {
            let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    pub(crate) fn pinned_artifacts_check(
        profile: &Profile,
        lock_path: &Path,
        receipt_dir: &Path,
    ) -> Result<(), String> {
        let lock = load_pinned_lock(lock_path)?;
        let statuses = pinned_artifacts_status(&lock);
        let ok = lock.profile == profile.id && statuses.iter().all(|status| status.ok);
        let first_missing_signal = if lock.profile != profile.id {
            "pinned-lock-profile-mismatch".to_string()
        } else {
            statuses
                .iter()
                .find(|status| !status.ok)
                .map(|status| format!("pinned-artifact-{}-drift", status.name))
                .unwrap_or_else(|| "none".to_string())
        };
        crate::atoms::attest::ratchet_aur::write_pinned_artifacts_receipt(
            &receipt_dir.join("run.json"),
            &json!({
                "schema": "harmonia.pinned_artifacts.check.v1",
                "ok": ok,
                "mutation": false,
                "profile_id": profile.id,
                "lock_path": lock_path,
                "artifact_count": statuses.len(),
                "first_missing_signal": first_missing_signal,
                "artifacts": statuses,
            }),
        )?;
        println!("schema=harmonia.pinned_artifacts.check.v1");
        hyalos::forward_receipt(
            "schema=harmonia.pinned_artifacts.check.v1",
            &format!("schema=harmonia.pinned_artifacts.check.v1 ok={}", ok),
            Some(serde_json::json!({"schema": "harmonia.pinned_artifacts.check.v1", "ok": ok})),
            Some(ok),
        );
        println!("ok={}", ok);
        println!("profile_id={}", profile.id);
        println!("artifact_count={}", lock.artifacts.len());
        println!("first_missing_signal={}", first_missing_signal);
        println!("receipt_dir={}", receipt_dir.display());
        if ok {
            Ok(())
        } else {
            Err(first_missing_signal)
        }
    }
}
