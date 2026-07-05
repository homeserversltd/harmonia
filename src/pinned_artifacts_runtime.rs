use crate::*;

// Absorbed module-specific runtime helper

// from former src/pinned_artifacts.rs.
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;

pub(crate) fn pinned_artifacts_command(
    action: &str,
    profile: &Profile,
    lock_path: &Path,
    receipt_dir: &Path,
    args: &[String],
) -> Result<(), String> {
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    match action {
        "check" => pinned_artifacts_check(profile, lock_path, receipt_dir),
        "nudge" => pinned_artifacts_nudge(profile, lock_path, receipt_dir, args),
        "bless" => pinned_artifacts_bless(profile, lock_path, receipt_dir, args),
        other => Err(format!("unsupported pinned-artifacts action {other}")),
    }
}

pub(crate) fn load_pinned_lock(lock_path: &Path) -> Result<PinnedArtifactsLock, String> {
    let text = fs::read_to_string(lock_path)
        .map_err(|e| format!("pinned-lock-read-failed {}: {e}", lock_path.display()))?;
    serde_json::from_str(&text)
        .map_err(|e| format!("pinned-lock-parse-failed {}: {e}", lock_path.display()))
}

pub(crate) fn write_pinned_lock(
    lock_path: &Path,
    lock: &PinnedArtifactsLock,
) -> Result<(), String> {
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let value = serde_json::to_value(lock).map_err(|e| e.to_string())?;
    write_json(lock_path, &value)
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
    write_json(
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

pub(crate) fn pinned_artifacts_nudge(
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
    let actual_sha = sha256_file(&candidate)?;
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
    write_json(
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

pub(crate) fn pinned_artifacts_bless(
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
    let actual_sha = sha256_file(&candidate)?;
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
    write_json(
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
    println!("ok=true");
    println!("mutation={}", apply);
    println!("artifact={}", name);
    println!("candidate_version={}", version);
    println!("first_missing_signal=none");
    println!("receipt_dir={}", receipt_dir.display());
    Ok(())
}

pub(crate) fn required_value(args: &[String], name: &str) -> Result<PathBuf, String> {
    value_arg(args, name).ok_or_else(|| format!("missing required {name} <path>"))
}

pub(crate) fn required_value_string(args: &[String], name: &str) -> Result<String, String> {
    value_arg_string(args, name).ok_or_else(|| format!("missing required {name} <value>"))
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
