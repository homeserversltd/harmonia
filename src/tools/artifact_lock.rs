use super::{ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::{write_json, OperationOutcome};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub const NAME: &str = "artifact-lock";
pub const DESCRIPTION: &str =
    "Pinned artifact lock verification primitive with per-artifact sha256 receipts.";
pub const PERMUTATIONS: &[ToolPermutation] = &[ToolPermutation::new(
    "verify",
    "verify declared lock file paths against installed artifact sha256 values",
    &[
        ToolArg::required("lock", ToolArgKind::String),
        ToolArg::optional("profile", ToolArgKind::String),
    ],
)];
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION, PERMUTATIONS);

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

pub(crate) fn verify(
    lock_path: &Path,
    profile: Option<&str>,
    receipt_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let text = fs::read_to_string(lock_path)
        .map_err(|e| format!("artifact-lock-read-failed {}: {e}", lock_path.display()))?;
    let lock: Lock = serde_json::from_str(&text)
        .map_err(|e| format!("artifact-lock-parse-failed {}: {e}", lock_path.display()))?;
    let mut entries = Vec::new();
    let mut ok = profile.map(|p| p == lock.profile).unwrap_or(true);
    let mut first_missing_signal = if ok {
        "none".to_string()
    } else {
        "artifact-lock-profile-mismatch".to_string()
    };
    for (name, artifact) in lock.artifacts.iter() {
        let path = Path::new(&artifact.path);
        let actual = sha256_file(path).ok();
        let entry_ok = actual
            .as_deref()
            .map(|sha| sha.eq_ignore_ascii_case(&artifact.sha256))
            .unwrap_or(false);
        if !entry_ok && first_missing_signal == "none" {
            first_missing_signal = format!("pinned-artifact-{name}-drift");
        }
        ok &= entry_ok;
        let receipt_name = format!("artifact-lock-{}.json", sanitize(name));
        write_json(
            &receipt_dir.join(&receipt_name),
            &json!({
                "schema":"harmonia.artifact_lock.artifact.v1", "ok":entry_ok, "apply":apply,
                "name":name, "version":artifact.version, "path":artifact.path, "expected_sha256":artifact.sha256,
                "actual_sha256":actual, "exists":path.exists(), "policy":artifact.policy,
                "first_missing_signal": if entry_ok {"none"} else {first_missing_signal.as_str()}
            }),
        )?;
        entries.push(json!({"name":name,"version":artifact.version,"path":artifact.path,"ok":entry_ok,"exists":path.exists(),"policy":artifact.policy}));
    }
    write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema":"harmonia.artifact_lock.verify.v1", "ok":ok, "apply":apply, "mutation":false,
            "profile_id":lock.profile, "lock_path":lock_path, "artifact_count":entries.len(),
            "artifacts":entries, "first_missing_signal":first_missing_signal
        }),
    )?;
    Ok(OperationOutcome {
        ok,
        changed: false,
        skipped: false,
        message: format!("{} artifacts verified", entries.len()),
        command: None,
    })
}
fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|e| format!("sha256-read-failed {}: {e}", path.display()))?;
    let mut h = Sha256::new();
    h.update(bytes);
    Ok(format!("{:x}", h.finalize()))
}
fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}
