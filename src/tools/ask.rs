use crate::tools::ladder::ValidatedStep;
use crate::OperationOutcome;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

const RUNNING_KERNEL_MARKER: &str = "<running-kernel>";

fn validate_clean_absolute_path(path: &str) -> Result<(), String> {
    let candidate = Path::new(path);
    if path.is_empty()
        || !candidate.is_absolute()
        || path.contains('\\')
        || candidate
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(format!("ask-path-rejected {path:?}"));
    }
    Ok(())
}

fn resolve_path(
    requested_path: &str,
    resolve_running_kernel: bool,
) -> Result<(PathBuf, Option<String>), String> {
    let marker_count = requested_path.matches(RUNNING_KERNEL_MARKER).count();
    if resolve_running_kernel {
        if marker_count != 1 {
            return Err(format!(
                "ask-running-kernel-marker-count-expected-one actual={marker_count}"
            ));
        }
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_err(|error| format!("ask-running-kernel-release-read-failed: {error}"))?
            .trim()
            .to_string();
        if release.is_empty() || release.contains('/') || release.contains('\\') {
            return Err("ask-running-kernel-release-invalid".into());
        }
        let release_path = Path::new(&release);
        if release_path.components().count() != 1
            || release_path
                .components()
                .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
        {
            return Err("ask-running-kernel-release-invalid".into());
        }
        let observed = requested_path.replace(RUNNING_KERNEL_MARKER, &release);
        validate_clean_absolute_path(&observed)?;
        Ok((PathBuf::from(observed), Some(release)))
    } else {
        if marker_count != 0 {
            return Err("ask-running-kernel-marker-unresolved".into());
        }
        validate_clean_absolute_path(requested_path)?;
        Ok((PathBuf::from(requested_path), None))
    }
}

pub(crate) fn validate_ladder_args(args: &BTreeMap<String, Value>) -> Result<(), String> {
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| "ask-path-required".to_string())?;
    let resolve = args
        .get("resolve_running_kernel")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let marker_count = path.matches(RUNNING_KERNEL_MARKER).count();
    if resolve && marker_count != 1 {
        return Err(format!(
            "ask-running-kernel-marker-count-expected-one actual={marker_count}"
        ));
    }
    if !resolve && marker_count != 0 {
        return Err("ask-running-kernel-marker-unresolved".into());
    }
    validate_clean_absolute_path(path)
}

pub(crate) fn execute_validated_step(
    step: &ValidatedStep,
    module_dir: &Path,
) -> Result<OperationOutcome, String> {
    let requested_path = step
        .args
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| "ask-path-required".to_string())?;
    let resolve_running_kernel = step
        .args
        .get("resolve_running_kernel")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let (observed_path, running_kernel_release) =
        resolve_path(requested_path, resolve_running_kernel)?;
    let exists = crate::atoms::ask::exists(&observed_path);
    let mut receipt = json!({"schema":"harmonia.ask.path_exists.v1","ok":exists,"changed":false,"evidence_only":true,"ask":"path-exists","requested_path":requested_path,"observed_path":observed_path,"resolve_running_kernel":resolve_running_kernel,"exists":exists,"drift":!exists,"first_missing_signal":if exists {"none"} else {"path-absent"}});
    if let Some(release) = running_kernel_release {
        receipt["running_kernel_release"] = json!(release);
    }
    crate::atoms::attest::write_json_atomic(
        &module_dir.join(format!("{}.json", step.step_id)),
        &receipt,
    )?;
    Ok(OperationOutcome {
        ok: exists,
        changed: false,
        skipped: false,
        message: if exists {
            "path-exists".into()
        } else {
            "path-absent".into()
        },
        command: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    fn fixture() -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "harmonia-ask-{}-{stamp}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("fixture directory");
        path
    }
    fn step(step_id: &str, path: &Path, resolve: bool) -> ValidatedStep {
        let mut args = BTreeMap::new();
        args.insert("path".into(), json!(path.to_string_lossy().to_string()));
        args.insert("resolve_running_kernel".into(), json!(resolve));
        ValidatedStep {
            step_id: step_id.into(),
            tool: "ask".into(),
            permutation: "path-exists".into(),
            args,
            on_failure: crate::tools::ladder::OnFailure::Stop,
        }
    }
    #[test]
    fn existing_and_absent_paths_write_evidence_only_receipts_without_mutation() {
        let root = fixture();
        let target = root.join("present");
        fs::write(&target, b"fixture").expect("target");
        let receipt_dir = root.join("receipts");
        let before = fs::read_dir(&root).expect("before").count();
        let present = execute_validated_step(&step("present", &target, false), &receipt_dir)
            .expect("present");
        assert!(present.ok);
        let present_receipt: Value = serde_json::from_slice(
            &fs::read(receipt_dir.join("present.json")).expect("present receipt"),
        )
        .expect("json");
        println!("present_receipt={present_receipt}");
        assert_eq!(present_receipt["schema"], "harmonia.ask.path_exists.v1");
        assert_eq!(present_receipt["ok"], true);
        assert_eq!(present_receipt["changed"], false);
        assert_eq!(present_receipt["evidence_only"], true);
        assert_eq!(present_receipt["ask"], "path-exists");
        assert_eq!(present_receipt["exists"], true);
        assert_eq!(present_receipt["drift"], false);
        assert_eq!(present_receipt["first_missing_signal"], "none");
        assert_eq!(fs::read(&target).expect("target unchanged"), b"fixture");
        let absent = root.join("absent");
        let outcome =
            execute_validated_step(&step("absent", &absent, false), &receipt_dir).expect("absent");
        assert!(!outcome.ok && !outcome.changed && !outcome.skipped && outcome.command.is_none());
        let absent_receipt: Value = serde_json::from_slice(
            &fs::read(receipt_dir.join("absent.json")).expect("absent receipt"),
        )
        .expect("json");
        println!("absent_receipt={absent_receipt}");
        assert_eq!(absent_receipt["exists"], false);
        assert_eq!(absent_receipt["drift"], true);
        assert_eq!(absent_receipt["first_missing_signal"], "path-absent");
        assert!(receipt_dir.join("present.json").exists());
        assert!(!absent.exists());
        assert_eq!(fs::read_dir(&root).expect("after").count(), before + 1);
        let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn marker_validation_is_exact_and_registry_is_compare_only() {
        let mut args = BTreeMap::new();
        args.insert("path".into(), json!("/lib/modules/<running-kernel>/x"));
        args.insert("resolve_running_kernel".into(), json!(false));
        assert!(validate_ladder_args(&args).is_err());
        args.insert("resolve_running_kernel".into(), json!(true));
        assert!(validate_ladder_args(&args).is_ok());
        args.insert("path".into(), json!("/x/<running-kernel>/<running-kernel>"));
        assert!(validate_ladder_args(&args).is_err());
        args.insert("path".into(), json!("relative"));
        assert!(validate_ladder_args(&args).is_err());
        let contract = crate::tools::get("ask").expect("ask registry entry");
        let permutation = contract.permutation("path-exists").expect("path-exists");
        assert_eq!(
            permutation.placement,
            Some(crate::tools::Placement::Compare)
        );
        assert_eq!(permutation.args.len(), 2);
        assert!(!crate::tools::routine_summonable("ask"));
    }
}
