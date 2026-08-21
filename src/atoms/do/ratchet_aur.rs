pub(crate) use crate::atoms::ask::ratchet_aur::{ArtifactLockObservation, Observation, Verdict};
use crate::atoms::comparison::{self, DiffDecision};
use crate::{OperationOutcome, Profile};
use std::collections::BTreeMap;
use std::path::Path;
pub(crate) fn install(
    receipt_dir: &Path,
    receipt_name: &str,
    package: &str,
    timeout_secs: u64,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
    pins: &BTreeMap<String, String>,
) -> Result<comparison::ComparisonRun<Option<String>, OperationOutcome>, String> {
    crate::atoms::declaration::execute(
        "ratchet-aur-package",
        "ratchet-aur-package",
        || {
            Ok(crate::atoms::ask::ratchet_aur::probe::installed_version(
                package,
            ))
        },
        |installed| {
            if apply && installed.is_none() {
                DiffDecision::Different
            } else {
                DiffDecision::Empty
            }
        },
        |authorization, _| {
            let invocation = invocation
                .ok_or_else(|| "ratchet-aur-package-install-invocation-key-missing".to_string())?;
            mutation::install(
                authorization,
                invocation,
                receipt_dir,
                receipt_name,
                package,
                timeout_secs,
                apply,
                pins,
            )
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_pinned(
    receipt_dir: &Path,
    receipt_name: &str,
    package: &str,
    lock_path: &Path,
    build_root: &Path,
    source_dir: Option<&str>,
    builder_user: Option<&str>,
    timeout_secs: u64,
    install: bool,
    apply: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
    pins: &BTreeMap<String, String>,
) -> Result<comparison::ComparisonRun<Observation, OperationOutcome>, String> {
    crate::atoms::declaration::execute(
        "ratchet-aur-package",
        "ratchet-aur-package",
        || crate::atoms::ask::ratchet_aur::probe::ratchet(package, lock_path, None, install),
        |observation| {
            if apply && observation.verdict == Verdict::BehindPin {
                DiffDecision::Different
            } else {
                DiffDecision::Empty
            }
        },
        |authorization, observation| {
            let invocation = invocation
                .ok_or_else(|| "ratchet-aur-package-build-invocation-key-missing".to_string())?;
            mutation::build_pinned(
                authorization,
                invocation,
                receipt_dir,
                receipt_name,
                package,
                lock_path,
                build_root,
                source_dir,
                builder_user,
                timeout_secs,
                install,
                apply,
                observation,
                pins,
            )
        },
    )
}

pub(crate) fn report(
    log: &Path,
    verdict: Verdict,
    outcome: &OperationOutcome,
) -> Result<(), String> {
    receipt::attest(log, verdict, outcome)
}

pub(crate) fn verify_artifact_lock(
    lock_path: &Path,
    profile: Option<&str>,
    receipt_dir: &Path,
) -> Result<OperationOutcome, String> {
    let observation = crate::atoms::ask::ratchet_aur::probe::artifact_lock(
        lock_path,
        profile,
        receipt_dir,
        false,
    )?;
    let outcome = OperationOutcome {
        ok: observation.ok,
        changed: false,
        skipped: false,
        message: format!("{} artifacts verified", observation.artifact_count),
        command: None,
    };
    receipt::attest_artifact_lock(
        &receipt_dir.join("artifact-lock.attest.jsonl"),
        &observation,
    )?;
    Ok(outcome)
}

pub(crate) fn pinned_artifacts_command(
    action: &str,
    profile: &Profile,
    lock_path: &Path,
    receipt_dir: &Path,
    args: &[String],
) -> Result<(), String> {
    std::fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    match action {
        "check" => crate::atoms::ask::ratchet_aur::probe::pinned_artifacts_check(
            profile,
            lock_path,
            receipt_dir,
        ),
        "nudge" => mutation::pinned_artifacts_nudge(profile, lock_path, receipt_dir, args),
        "bless" => mutation::pinned_artifacts_bless(profile, lock_path, receipt_dir, args),
        other => Err(format!("unsupported pinned-artifacts action {other}")),
    }
}

mod mutation {
    use super::{Observation, Verdict};
    use crate::atoms;
    use crate::atoms::ask::ratchet_aur::probe::load_pinned_lock;
    use crate::atoms::comparison::ActionAuthorization;
    use crate::OperationOutcome;
    use crate::{
        hyalos, value_arg, value_arg_string, write_json, PinnedArtifact, PinnedArtifactsLock,
        Profile,
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_pinned(
        authorization: ActionAuthorization,
        invocation: atoms::r#do::InvocationKey,
        receipt_dir: &Path,
        receipt_name: &str,
        package: &str,
        lock_path: &Path,
        build_root: &Path,
        source_dir: Option<&str>,
        builder_user: Option<&str>,
        timeout_secs: u64,
        install: bool,
        apply: bool,
        observation: &Observation,
        pins: &BTreeMap<String, String>,
    ) -> Result<OperationOutcome, String> {
        if observation.verdict != Verdict::BehindPin {
            return Err("ratchet-aur-package-act-without-behind-pin".into());
        }
        let built = atoms::r#do::aur_build_pinned(authorization, invocation, || {
            atoms::r#do::build_aur_pinned::aur_build_pinned_action(
                receipt_dir,
                receipt_name,
                package,
                lock_path,
                build_root,
                source_dir,
                builder_user,
                timeout_secs,
                false,
                apply,
            )
        })?;
        if !install || !built.ok {
            return Ok(built);
        }
        let lock = crate::atoms::aur::read_lock(lock_path, package)?;
        atoms::r#do::aur_install_pinned(authorization, invocation, || {
            atoms::r#do::install_aur_pinned::run(
                &atoms::r#do::install_aur_pinned::Plan {
                    receipt_dir: receipt_dir.to_path_buf(),
                    receipt_name: format!("{receipt_name}.install"),
                    build_receipt: receipt_dir.join(format!("{receipt_name}.json")),
                    package: package.to_string(),
                    expected_version: lock.pinned_version,
                    timeout_secs,
                    ignored: pins
                        .keys()
                        .filter(|name| name.as_str() != package)
                        .cloned()
                        .collect(),
                    target_pinned: pins.contains_key(package),
                },
                apply,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn install(
        authorization: ActionAuthorization,
        invocation: atoms::r#do::InvocationKey,
        receipt_dir: &Path,
        receipt_name: &str,
        package: &str,
        timeout_secs: u64,
        apply: bool,
        pins: &BTreeMap<String, String>,
    ) -> Result<OperationOutcome, String> {
        atoms::r#do::aur_install(authorization, invocation, || {
            atoms::r#do::install_aur::aur_install_action(
                receipt_dir,
                receipt_name,
                package,
                timeout_secs,
                apply,
                pins,
            )
        })
    }

    pub(super) fn write_pinned_lock(
        lock_path: &Path,
        lock: &PinnedArtifactsLock,
    ) -> Result<(), String> {
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let value = serde_json::to_value(lock).map_err(|e| e.to_string())?;
        write_json(lock_path, &value)
    }

    pub(super) fn pinned_artifacts_nudge(
        profile: &Profile,
        lock_path: &Path,
        receipt_dir: &Path,
        args: &[String],
    ) -> Result<(), String> {
        let lock = load_pinned_lock(lock_path)?;
        let name = required_value_string(args, "--artifact")?;
        let candidate = required_value(args, "--candidate")?;
        let version = required_value_string(args, "--version")?;
        let expected_sha = required_value_string(args, "--sha256")?;
        let actual_sha = crate::atoms::ask::ratchet_aur::probe::sha256_file(&candidate)?;
        let ok = actual_sha.eq_ignore_ascii_case(&expected_sha);
        let staged_path = receipt_dir
            .join("candidates")
            .join(&name)
            .join(candidate.file_name().unwrap_or_default());
        if ok {
            if let Some(parent) = staged_path.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            fs::copy(&candidate, &staged_path)
                .map_err(|e| format!("candidate-stage-failed {}: {e}", staged_path.display()))?;
            let mode = fs::metadata(&candidate)
                .map_err(|e| e.to_string())?
                .permissions()
                .mode();
            fs::set_permissions(&staged_path, fs::Permissions::from_mode(mode))
                .map_err(|e| e.to_string())?;
        }
        let first_missing_signal = if ok {
            "none"
        } else {
            "candidate-sha256-mismatch"
        };
        super::receipt::write_pinned_artifacts_receipt(
            &receipt_dir.join("run.json"),
            &json!({
                "schema": "harmonia.pinned_artifacts.nudge.v1",
                "ok": ok,
                "mutation": false,
                "profile_id": profile.id,
                "lock_path": lock_path,
                "artifact": name,
                "candidate": candidate,
                "candidate_version": version,
                "expected_sha256": expected_sha,
                "actual_sha256": actual_sha,
                "staged_path": if ok { Some(staged_path) } else { None },
                "current_lock": lock.artifacts.get(&name),
                "first_missing_signal": first_missing_signal,
                "meaning": "candidate staged for manual proof; blessed known-good lock not advanced",
            }),
        )?;
        println!("schema=harmonia.pinned_artifacts.nudge.v1");
        hyalos::forward_receipt(
            "schema=harmonia.pinned_artifacts.nudge.v1",
            &format!("schema=harmonia.pinned_artifacts.nudge.v1 ok={}", ok),
            Some(serde_json::json!({"schema": "harmonia.pinned_artifacts.nudge.v1", "ok": ok})),
            Some(ok),
        );
        println!("ok={}", ok);
        println!("artifact={}", name);
        println!("candidate_version={}", version);
        println!("first_missing_signal={}", first_missing_signal);
        println!("receipt_dir={}", receipt_dir.display());
        if ok {
            Ok(())
        } else {
            Err(first_missing_signal.to_string())
        }
    }

    pub(super) fn pinned_artifacts_bless(
        profile: &Profile,
        lock_path: &Path,
        receipt_dir: &Path,
        args: &[String],
    ) -> Result<(), String> {
        let mut lock = load_pinned_lock(lock_path)?;
        if lock.profile != profile.id {
            return Err("pinned-lock-profile-mismatch".to_string());
        }
        let name = required_value_string(args, "--artifact")?;
        let candidate = required_value(args, "--candidate")?;
        let version = required_value_string(args, "--version")?;
        let expected_sha = required_value_string(args, "--sha256")?;
        let actual_sha = crate::atoms::ask::ratchet_aur::probe::sha256_file(&candidate)?;
        if !actual_sha.eq_ignore_ascii_case(&expected_sha) {
            return Err("candidate-sha256-mismatch".to_string());
        }
        let apply = args.iter().any(|arg| arg == "--apply");
        let old = lock.artifacts.get(&name).cloned();
        let install_path = value_arg(args, "--install-path")
            .or_else(|| old.as_ref().map(|artifact| PathBuf::from(&artifact.path)))
            .ok_or("bless requires --install-path for new artifact")?;
        if apply {
            if let Some(parent) = install_path.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let backup_path = install_path.with_extension("harmonia-prev");
            if install_path.exists() {
                fs::copy(&install_path, &backup_path)
                    .map_err(|e| format!("backup-failed {}: {e}", backup_path.display()))?;
            }
            fs::copy(&candidate, &install_path)
                .map_err(|e| format!("install-failed {}: {e}", install_path.display()))?;
            fs::set_permissions(&install_path, fs::Permissions::from_mode(0o755))
                .map_err(|e| e.to_string())?;
            lock.artifacts.insert(
                name.clone(),
                PinnedArtifact {
                    version: version.clone(),
                    path: install_path.display().to_string(),
                    sha256: expected_sha.clone(),
                    policy: "known-good".to_string(),
                    source: value_arg_string(args, "--source"),
                },
            );
            write_pinned_lock(lock_path, &lock)?;
        }
        super::receipt::write_pinned_artifacts_receipt(
            &receipt_dir.join("run.json"),
            &json!({
                "schema": "harmonia.pinned_artifacts.bless.v1",
                "ok": true,
                "mutation": apply,
                "profile_id": profile.id,
                "lock_path": lock_path,
                "artifact": name,
                "old_lock": old,
                "new_lock": lock.artifacts.get(&name),
                "candidate": candidate,
                "candidate_version": version,
                "sha256": expected_sha,
                "install_path": install_path,
                "first_missing_signal": "none",
                "meaning": if apply { "known-good lock advanced and artifact relocked" } else { "bless planned; rerun with --apply to advance lock" },
            }),
        )?;
        println!("schema=harmonia.pinned_artifacts.bless.v1");
        hyalos::forward_receipt(
            "schema=harmonia.pinned_artifacts.bless.v1",
            &format!("schema=harmonia.pinned_artifacts.bless.v1 ok={}", true),
            Some(serde_json::json!({"schema": "harmonia.pinned_artifacts.bless.v1", "ok": true})),
            Some(true),
        );
        println!("ok=true");
        println!("mutation={}", apply);
        println!("artifact={}", name);
        println!("candidate_version={}", version);
        println!("first_missing_signal=none");
        println!("receipt_dir={}", receipt_dir.display());
        Ok(())
    }

    pub(super) fn required_value(args: &[String], name: &str) -> Result<PathBuf, String> {
        value_arg(args, name).ok_or_else(|| format!("missing required {name} <path>"))
    }

    pub(super) fn required_value_string(args: &[String], name: &str) -> Result<String, String> {
        value_arg_string(args, name).ok_or_else(|| format!("missing required {name} <value>"))
    }
}

mod receipt {
    use super::{ArtifactLockObservation, Verdict};
    use crate::atoms;
    use crate::OperationOutcome;
    use std::collections::BTreeMap;
    use std::path::Path;

    pub(super) fn write_pinned_artifacts_receipt(
        path: &Path,
        value: &serde_json::Value,
    ) -> Result<(), String> {
        crate::write_json(path, value)
    }

    pub(super) fn attest(
        log: &Path,
        verdict: Verdict,
        outcome: &OperationOutcome,
    ) -> Result<(), String> {
        let message = if verdict == Verdict::UpstreamMovedPastPin {
            format!("verdict={}; nudge=bless-new-pin", verdict.as_str())
        } else {
            format!("verdict={}; outcome={}", verdict.as_str(), outcome.message)
        };
        atoms::attest::attest(
            log,
            &atoms::Receipt {
                atom: "ratchet-aur-package".into(),
                ok: outcome.ok,
                drift: atoms::Drift::Current,
                message,
            },
            &[],
        )
    }

    pub(super) fn attest_artifact_lock(
        log: &Path,
        observation: &ArtifactLockObservation,
    ) -> Result<(), String> {
        atoms::attest::attest(
            log,
            &atoms::Receipt {
                atom: "ratchet-aur-package-observe".into(),
                ok: observation.ok,
                drift: atoms::Drift::Current,
                message: format!(
                    "artifact-lock count={}; first_missing_signal={}",
                    observation.artifact_count, observation.first_missing_signal
                ),
            },
            &[],
        )
    }
}
