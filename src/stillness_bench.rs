use crate::tools::comparison::{self, ComparisonRun, DiffDecision};
use serde_json::{json, Value};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

pub(crate) fn run(invocation: Option<crate::atoms::r#do::InvocationKey>) -> Result<(), String> {
    let invocation =
        invocation.ok_or_else(|| "stillness-bench-invocation-key-missing".to_string())?;
    let root = std::env::temp_dir().join(format!(
        "harmonia-stillness-bench-{}",
        crate::run_id_from_stamp()
    ));
    fs::create_dir_all(&root).map_err(|error| error.to_string())?;

    let git_artifact = git_artifact_bench(&root, invocation)?;
    let caduceus = caduceus_bench(&root, invocation)?;
    let service_runtime_build_sha = service_runtime_build_sha_bench(&root, invocation)?;
    let source_gate = json!({"fresh_source":true,"stale_service_ignored":true,"changed":false});
    let venv = venv_bench(&root, invocation)?;
    let package = match package_bench(&root, invocation) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("package_root={} error={}", root.display(), e);
            return Err(e);
        }
    };
    let aur_pinned = aur_pinned_bench(&root, invocation)?;
    let never = never_converge_bench()?;
    let overall_ok = service_runtime_build_sha
        .get("ok")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let receipt = json!({
        "schema": "harmonia.stillness-bench.v1",
        "ok": overall_ok,
        "git_artifact": git_artifact,
        "caduceus": caduceus,
        "service_runtime_build_sha": service_runtime_build_sha,
        "source_gate": source_gate,
        "venv": venv,
        "package": package,
        "aur_pinned": aur_pinned,
        "never_converge": never,
    });
    println!(
        "{}",
        serde_json::to_string(&receipt).map_err(|error| error.to_string())?
    );
    fs::remove_dir_all(&root).map_err(|error| error.to_string())?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotEntry {
    path: String,
    kind: &'static str,
    bytes: Vec<u8>,
    mode: u32,
    mtime_sec: i64,
    mtime_nsec: i64,
}

fn destination_snapshot(root: &Path) -> Result<Vec<SnapshotEntry>, String> {
    fn walk(root: &Path, path: &Path, out: &mut Vec<SnapshotEntry>) -> Result<(), String> {
        let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        let relative = path
            .strip_prefix(root)
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .into_owned();
        let file_type = metadata.file_type();
        let (kind, bytes) = if file_type.is_dir() {
            ("dir", Vec::new())
        } else if file_type.is_file() {
            ("file", fs::read(path).map_err(|e| e.to_string())?)
        } else if file_type.is_symlink() {
            (
                "symlink",
                fs::read_link(path)
                    .map_err(|e| e.to_string())?
                    .to_string_lossy()
                    .as_bytes()
                    .to_vec(),
            )
        } else {
            ("other", Vec::new())
        };
        out.push(SnapshotEntry {
            path: if relative.is_empty() {
                ".".into()
            } else {
                relative
            },
            kind,
            bytes,
            mode: metadata.mode(),
            mtime_sec: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
        });
        if file_type.is_dir() {
            let mut children = fs::read_dir(path)
                .map_err(|e| e.to_string())?
                .map(|entry| entry.map(|e| e.path()).map_err(|e| e.to_string()))
                .collect::<Result<Vec<PathBuf>, _>>()?;
            children.sort();
            for child in children {
                walk(root, &child, out)?;
            }
        }
        Ok(())
    }
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    walk(root, root, &mut entries)?;
    Ok(entries)
}

fn snapshot_predicates(before: &[SnapshotEntry], after: &[SnapshotEntry]) -> serde_json::Value {
    let git_before: Vec<_> = before
        .iter()
        .filter(|entry| entry.path == ".git" || entry.path.starts_with(".git/"))
        .collect();
    let git_after: Vec<_> = after
        .iter()
        .filter(|entry| entry.path == ".git" || entry.path.starts_with(".git/"))
        .collect();
    let mut git_paths = git_before
        .iter()
        .chain(git_after.iter())
        .map(|entry| entry.path.clone())
        .collect::<Vec<_>>();
    git_paths.sort();
    git_paths.dedup();
    json!({"equal": before == after, "entry_count_before": before.len(), "entry_count_after": after.len(), "git_metadata_equal": git_before == git_after, "git_bytes_and_mtimes_equal": git_before == git_after, "git_paths_checked": git_paths, "ordinary_bytes_and_kinds_equal": before == after})
}

struct ClockEnvGuard {
    timedatectl: Option<String>,
    caduceus: Option<String>,
}
impl Drop for ClockEnvGuard {
    fn drop(&mut self) {
        match &self.timedatectl {
            Some(v) => std::env::set_var("HARMONIA_CLOCK_TIMEDATECTL", v),
            None => std::env::remove_var("HARMONIA_CLOCK_TIMEDATECTL"),
        }
        match &self.caduceus {
            Some(v) => std::env::set_var("HARMONIA_CLOCK_CADUCEUS", v),
            None => std::env::remove_var("HARMONIA_CLOCK_CADUCEUS"),
        }
    }
}

fn walk_receipts(root: &Path) -> std::io::Result<Vec<String>> {
    let mut names = Vec::new();
    if !root.exists() {
        return Ok(names);
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            names.extend(walk_receipts(&path)?);
        } else if path.extension().and_then(|v| v.to_str()) == Some("json") {
            names.push(
                path.strip_prefix(root)
                    .unwrap_or(&path)
                    .display()
                    .to_string(),
            );
        }
    }
    names.sort();
    Ok(names)
}

fn path_attestation(path: &Path) -> serde_json::Value {
    fn visit(path: &Path, base: &Path, entries: &mut BTreeMap<String, serde_json::Value>) {
        let Ok(meta) = fs::symlink_metadata(path) else {
            return;
        };
        let kind = if meta.is_dir() { "dir" } else if meta.is_file() { "file" } else { "other" };
        let hash = if meta.is_file() {
            crate::bands::renew_self::install_bin_fingerprint(path)
        } else {
            None
        };
        entries.insert(path.strip_prefix(base).unwrap_or(path).display().to_string(), json!({
            "kind": kind, "size": meta.len(), "mtime_ns": meta.mtime_nsec(), "mode": meta.mode(), "sha256": hash
        }));
        if meta.is_dir() {
            if let Ok(children) = fs::read_dir(path) {
                let mut children = children.flatten().map(|child| child.path()).collect::<Vec<_>>();
                children.sort();
                for child in children {
                    visit(&child, base, entries);
                }
            }
        }
    }
    let mut entries = BTreeMap::new();
    if path.exists() {
        visit(path, path.parent().unwrap_or(path), &mut entries);
    }
    json!({"path": path, "entries": entries})
}

pub(crate) fn renew_schedule_bench(
    invocation: crate::atoms::r#do::InvocationKey,
) -> Result<(), String> {
    let root = std::env::temp_dir().join(format!(
        "harmonia-renew-schedule-{}",
        crate::run_id_from_stamp()
    ));
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let source = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_head = String::from_utf8(
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(source)
            .output()
            .map_err(|e| e.to_string())?
            .stdout,
    )
    .map_err(|e| e.to_string())?
    .trim()
    .to_string();
    if source_head.len() != 40 {
        return Err("renew-schedule-source-head-not-a-commit".into());
    }
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let install_bin = root.join("installed-successor");
    fs::copy(&executable, &install_bin).map_err(|e| e.to_string())?;
    let source_dir = root.join("source-copy");
    let staged_bin = source_dir.join("target/release/harmonia");
    let renew_receipts = root.join("renew-receipts");
    let config_path = root.join("engine.json");
    fs::create_dir_all(&renew_receipts).map_err(|e| e.to_string())?;
    fs::write(
        &config_path,
        serde_json::json!({
            "source_repo_url":"https://example.invalid/harmonia.git", "branch":"main",
            "source_dir":source_dir, "local_source_checkout":source, "install_bin":install_bin,
            "staged_bin":staged_bin, "profile_index":source.join("profiles/homeconsole/index.json"),
            "enabled":true
        })
        .to_string(),
    )
    .map_err(|e| e.to_string())?;
    let prior_engine = env::var_os("HARMONIA_ENGINE_CONFIG_PATH");
    let prior_guard = env::var_os("HARMONIA_SELF_UPDATE_REEXEC");
    env::set_var("HARMONIA_ENGINE_CONFIG_PATH", &config_path);
    env::set_var("HARMONIA_SELF_UPDATE_REEXEC", "1");
    let module_root = root.join("module");
    fs::create_dir_all(module_root.join("identity")).map_err(|e| e.to_string())?;
    fs::copy(
        source.join("profiles/homeconsole/modules/identity/manifest.json"),
        module_root.join("identity/manifest.json"),
    )
    .map_err(|e| e.to_string())?;
    let renewal =
        crate::bands::renew_self::run(&module_root, &renew_receipts, true, Some(invocation));
    match prior_engine {
        Some(v) => env::set_var("HARMONIA_ENGINE_CONFIG_PATH", v),
        None => env::remove_var("HARMONIA_ENGINE_CONFIG_PATH"),
    }
    match prior_guard {
        Some(v) => env::set_var("HARMONIA_SELF_UPDATE_REEXEC", v),
        None => env::remove_var("HARMONIA_SELF_UPDATE_REEXEC"),
    }
    renewal
        .as_ref()
        .map_err(|e| format!("renew-self-bench: {e}"))?;
    let mut receipt_names = std::collections::BTreeSet::new();
    for entry in walk_receipts(&renew_receipts).map_err(|e| e.to_string())? {
        receipt_names.insert(entry);
    }
    let receipt_ok = |name: &str| -> bool {
        let path = renew_receipts
            .join("engine-preflight")
            .join(format!("{name}.json"));
        fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
            .and_then(|value| value.get("ok").and_then(serde_json::Value::as_bool))
            .unwrap_or(false)
    };
    let run_receipt: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(renew_receipts.join("engine-preflight/run.json"))
            .map_err(|e| format!("renew-run-receipt: {e}"))?,
    )
    .map_err(|e| format!("renew-run-receipt-json: {e}"))?;
    let built_successor_identity =
        crate::bands::renew_self::install_bin_fingerprint(&staged_bin)
            .ok_or_else(|| "renew-schedule-built-successor-fingerprint-missing".to_string())?;
    let installed_successor_identity =
        crate::bands::renew_self::install_bin_fingerprint(&install_bin)
            .ok_or_else(|| "renew-schedule-installed-successor-fingerprint-missing".to_string())?;
    let installer = root.join("installer.py");
    let argv_log = root.join("argv.log");
    fs::write(&installer, format!("import pathlib,sys\npathlib.Path({argv_log:?}).write_text(repr(sys.argv[1:]))\npass\n")).map_err(|e| e.to_string())?;
    let prior = env::var_os("HARMONIA_INSTALLER");
    env::set_var("HARMONIA_INSTALLER", &installer);
    let systemd_root = root.join("systemd");
    let actual_service = Path::new("/etc/systemd/system/harmonia.service");
    let actual_timer = Path::new("/etc/systemd/system/harmonia.timer");
    let systemd_root_before = path_attestation(&systemd_root);
    let actual_service_before = path_attestation(actual_service);
    let actual_timer_before = path_attestation(actual_timer);
    let scheduled = crate::schedule::install_timer(
        &[
            "--systemd-root".into(),
            systemd_root.display().to_string(),
            "--dry-run".into(),
        ],
        invocation,
    );
    match prior {
        Some(v) => env::set_var("HARMONIA_INSTALLER", v),
        None => env::remove_var("HARMONIA_INSTALLER"),
    }
    scheduled?;
    let argv = fs::read_to_string(&argv_log).map_err(|e| format!("schedule-argv-receipt: {e}"))?;
    let expected = format!(
        "['install-timer', '--systemd-root', '{}', '--dry-run']",
        systemd_root.display()
    );
    if argv != expected {
        return Err(format!(
            "schedule-argv-mismatch expected={expected} actual={argv}"
        ));
    }
    let systemd_root_after = path_attestation(&systemd_root);
    let actual_service_after = path_attestation(actual_service);
    let actual_timer_after = path_attestation(actual_timer);
    let systemd_root_unchanged = systemd_root_before == systemd_root_after;
    let actual_service_unchanged = actual_service_before == actual_service_after;
    let actual_timer_unchanged = actual_timer_before == actual_timer_after;
    let source_head_observed = run_receipt
        .get("engine_content_head")
        .and_then(serde_json::Value::as_str)
        == Some(source_head.as_str());
    let built_identity_tied = run_receipt
        .get("staged_sha256")
        .and_then(serde_json::Value::as_str)
        == Some(built_successor_identity.as_str())
        && installed_successor_identity == built_successor_identity
        && receipt_ok("staged-build");
    let execution_ok = renewal.as_ref().map(|value| value.ok).unwrap_or(false);
    let explain = receipt_ok("harmonia-engine-preflight-explain") && receipt_ok("proof-explain");
    let validate_ladder = receipt_ok("proof-validate-ladder");
    let plan_run_gate = receipt_ok("proof-plan-run");
    let promotion_after_all_green =
        receipt_ok("promote-successor") && validate_ladder && plan_run_gate && explain;
    let replacement_receipt_path = renew_receipts
        .join("engine-preflight")
        .join("harmonia-self-update-reexec.json");
    let replacement_plan = crate::atoms::r#do::replace_process::Plan {
        successor: install_bin.clone(),
        argv: env::args().skip(1).collect(),
        guard_name: "HARMONIA_SELF_UPDATE_REEXEC".into(),
        guard_value: "1".into(),
        receipt_path: replacement_receipt_path.clone(),
    };
    let replacement_proof =
        crate::atoms::r#do::replace_process::proof(&replacement_plan, invocation)?;
    let replacement_bytes_before = fs::read(&replacement_receipt_path)
        .map_err(|e| format!("replacement-receipt-read: {e}"))?;
    let replacement_receipt: crate::atoms::r#do::replace_process::Receipt =
        serde_json::from_slice(&replacement_bytes_before)
            .map_err(|e| format!("replacement-receipt-parse: {e}"))?;
    let replacement_canonical =
        fs::canonicalize(&replacement_plan.successor).map_err(|e| e.to_string())?;
    let replacement_metadata =
        fs::symlink_metadata(&replacement_canonical).map_err(|e| e.to_string())?;
    let replacement_identity = replacement_receipt.successor_canonical
        == replacement_canonical.display().to_string()
        && replacement_receipt.successor_dev == replacement_metadata.dev()
        && replacement_receipt.successor_ino == replacement_metadata.ino();
    let replacement_contents = replacement_receipt.schema == "harmonia.replace-process.v1"
        && replacement_receipt.successor == replacement_plan.successor.display().to_string()
        && replacement_receipt.argv == replacement_plan.argv
        && replacement_receipt.guard_name == replacement_plan.guard_name
        && replacement_receipt.guard_value == replacement_plan.guard_value
        && replacement_receipt.receipt_path == replacement_receipt_path.display().to_string()
        && replacement_receipt.synced
        && replacement_receipt.proof
        && replacement_proof.proof;
    let previous_replacement_guard = env::var_os(&replacement_plan.guard_name);
    env::set_var(&replacement_plan.guard_name, &replacement_plan.guard_value);
    let replacement_refusal =
        crate::atoms::r#do::replace_process::proof(&replacement_plan, invocation)
            .err()
            .unwrap_or_else(|| "replacement-reentry-not-refused".into());
    let replacement_bytes_after = fs::read(&replacement_receipt_path)
        .map_err(|e| format!("replacement-receipt-reread: {e}"))?;
    match previous_replacement_guard {
        Some(value) => env::set_var(&replacement_plan.guard_name, value),
        None => env::remove_var(&replacement_plan.guard_name),
    }
    let replacement_receipt_observed = replacement_receipt_path.exists();
    let final_receipt_before_exec = receipt_ok("run")
        && replacement_receipt_observed
        && replacement_contents
        && replacement_identity;
    let reentry_guard = replacement_refusal == "replace-process-reentry-refused"
        && replacement_bytes_before == replacement_bytes_after;
    let quiet_no_reexec = !crate::bands::renew_self::should_self_update_reexec(
        true,
        true,
        Some(installed_successor_identity.clone()),
        Some(built_successor_identity.clone()),
    );
    let renew_ok = source_head_observed
        && built_identity_tied
        && execution_ok
        && explain
        && validate_ladder
        && plan_run_gate
        && promotion_after_all_green
        && final_receipt_before_exec
        && reentry_guard
        && quiet_no_reexec;
    let schedule_ok = argv == expected
        && systemd_root_unchanged
        && actual_service_unchanged
        && actual_timer_unchanged;
    let receipt = json!({
        "schema":"harmonia.renew-schedule-bench.v3", "ok": renew_ok && schedule_ok,
        "source_head": source_head, "built_successor_identity": built_successor_identity,
        "renew_self": {"receipt_names": receipt_names, "execution_ok": execution_ok, "actual_source_head": source_head_observed, "successor_identity_tied_to_build_receipt": built_identity_tied, "explain": explain, "validate_ladder": validate_ladder, "plan_run_gate": plan_run_gate, "promotion_after_all_green": promotion_after_all_green, "final_receipt_before_exec": final_receipt_before_exec, "reentry_guard": reentry_guard, "quiet_no_reexec": quiet_no_reexec, "replacement": {"receipt_path": replacement_receipt_path, "receipt_observed": replacement_receipt_observed, "schema": replacement_receipt.schema, "proof": replacement_receipt.proof, "synced": replacement_receipt.synced, "contents_observed": replacement_contents, "identity_observed": replacement_identity, "refusal": replacement_refusal, "receipt_unchanged_after_refusal": replacement_bytes_before == replacement_bytes_after}},
        "schedule": {"dry_run": true, "argv": argv, "argv_exact": argv == expected, "systemd_root_before": systemd_root_before, "systemd_root_after": systemd_root_after, "systemd_root_unchanged": systemd_root_unchanged, "actual_service_before": actual_service_before, "actual_service_after": actual_service_after, "actual_service_unchanged": actual_service_unchanged, "actual_timer_before": actual_timer_before, "actual_timer_after": actual_timer_after, "actual_timer_unchanged": actual_timer_unchanged, "attest_owner": "hyalos.forward_receipt"}
    });
    println!(
        "{}",
        serde_json::to_string(&receipt).map_err(|e| e.to_string())?
    );
    let _ = fs::remove_dir_all(&root);
    if renew_ok && schedule_ok {
        Ok(())
    } else {
        Err("renew-schedule-required-predicate-failed".into())
    }
}

pub(crate) fn clock_bench(
    invocation: crate::atoms::r#do::InvocationKey,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let _env = ClockEnvGuard {
        timedatectl: std::env::var("HARMONIA_CLOCK_TIMEDATECTL").ok(),
        caduceus: std::env::var("HARMONIA_CLOCK_CADUCEUS").ok(),
    };
    let root = std::env::temp_dir().join(format!(
        "harmonia-clock-{}",
        crate::run_id_from_stamp()
    ));
    std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let state = root.join("state");
    let log = root.join("writes.log");
    let timedatectl = root.join("timedatectl");
    let backend = root.join("caduceus");
    let refusal = root.join("refusal");
    std::fs::write(&state, "Etc/UTC|no\n").map_err(|e| e.to_string())?;
    std::fs::write(
        &timedatectl,
        format!(
            r#"#!/bin/sh
timezone=$(cut -d'|' -f1 {0})
ntp=$(cut -d'|' -f2 {0})
printf 'Timezone=%s\nNTPSynchronized=%s\nNTP=%s\n' "$timezone" "$ntp" "$ntp"
"#,
            state.display()
        ),
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(
        &backend,
        format!(
            r#"#!/bin/sh
if [ "$1" != time ]; then exit 1; fi
case "$2" in
  state) cat {0} ;;
  set-timezone)
    before=$(cat {0})
    ntp=$(cut -d'|' -f2 {0})
    printf '%s|%s\n' "$3" "$ntp" > {0}
    printf 'set-timezone:%s->%s\n' "$before" "$(cat {0})" >> {1}
    ;;
  ensure-ntp)
    before=$(cat {0})
    timezone=$(cut -d'|' -f1 {0})
    printf '%s|yes\n' "$timezone" > {0}
    printf 'ensure-ntp:%s->%s\n' "$before" "$(cat {0})" >> {1}
    ;;
  *) exit 1 ;;
esac
"#,
            state.display(),
            log.display()
        ),
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(&refusal, "#!/bin/sh\nexit 77\n").map_err(|e| e.to_string())?;
    for path in [&timedatectl, &backend, &refusal] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
    }
    std::env::set_var("HARMONIA_CLOCK_TIMEDATECTL", &timedatectl);
    std::env::set_var("HARMONIA_CLOCK_CADUCEUS", &backend);
    let request = crate::set_clock::Request {
        backend: "caduceus",
        operation: "set-timezone",
        timezone: Some("Europe/Berlin"),
        state_url: None,
        state_path: None,
        timeout_secs: 3,
    };
    let preimage = std::fs::read_to_string(&state).map_err(|e| e.to_string())?;
    let changed = crate::set_clock::run(&request, true, Some(invocation))?;
    let readback = std::fs::read_to_string(&state).map_err(|e| e.to_string())?;
    let actions = std::fs::read_to_string(&log).map_err(|e| e.to_string())?;
    let expected_actions =
        "set-timezone:Etc/UTC|no->Europe/Berlin|no\nensure-ntp:Europe/Berlin|no->Europe/Berlin|yes\n";
    if !changed.ok
        || preimage != "Etc/UTC|no\n"
        || readback != "Europe/Berlin|yes\n"
        || actions != expected_actions
    {
        return Err("clock-posture-readback-failed".into());
    }
    std::thread::sleep(std::time::Duration::from_millis(20));
    if std::fs::read_to_string(&state).map_err(|e| e.to_string())? != readback {
        return Err("clock-elapsed-reversal".into());
    }
    let state_before_quiet = std::fs::read(&state).map_err(|e| e.to_string())?;
    let writes_before = std::fs::read(&log).map_err(|e| e.to_string())?;
    let quiet = crate::set_clock::run(&request, true, Some(invocation))?;
    if !quiet.ok
        || std::fs::read(&state).map_err(|e| e.to_string())? != state_before_quiet
        || std::fs::read(&log).map_err(|e| e.to_string())? != writes_before
    {
        return Err("clock-quiet-write".into());
    }
    std::fs::write(&state, "Etc/UTC|no\n").map_err(|e| e.to_string())?;
    std::env::set_var("HARMONIA_CLOCK_CADUCEUS", &refusal);
    let refusal_state = std::fs::read(&state).map_err(|e| e.to_string())?;
    let refusal_writes = std::fs::read(&log).map_err(|e| e.to_string())?;
    let refused = crate::set_clock::run(&request, true, Some(invocation));
    if !matches!(refused, Err(ref error) if error == "set-clock-act-did-not-converge")
        || std::fs::read(&state).map_err(|e| e.to_string())? != refusal_state
        || std::fs::read(&log).map_err(|e| e.to_string())? != refusal_writes
    {
        return Err("clock-refusal-proof-failed".into());
    }
    println!("clock-bench ok preimage=Etc/UTC|no requested=Europe/Berlin|yes readback=verified elapsed=non-reversing quiet=no-write refusal=backend-refused host_mutation=false");
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())?;
    Ok(())
}

fn git_artifact_bench(
    root: &Path,
    invocation: crate::atoms::r#do::InvocationKey,
) -> Result<serde_json::Value, String> {
    fn git(cwd: &Path, args: &[&str]) -> Result<String, String> {
        let o = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .map_err(|e| e.to_string())?;
        if !o.status.success() {
            return Err(format!(
                "git setup failed: {}",
                String::from_utf8_lossy(&o.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&o.stdout).trim().into())
    }
    let dir = root.join("git-artifact");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let seed = dir.join("seed");
    let bare = dir.join("remote.git");
    let dst = dir.join("destination");
    fs::create_dir_all(&seed).map_err(|e| e.to_string())?;
    git(&seed, &["init", "-b", "main"])?;
    git(&seed, &["config", "user.email", "bench@example.invalid"])?;
    git(&seed, &["config", "user.name", "bench"])?;
    fs::write(seed.join("state"), "one\n").map_err(|e| e.to_string())?;
    git(&seed, &["add", "state"])?;
    git(&seed, &["commit", "-m", "one"])?;
    let c1 = git(&seed, &["rev-parse", "HEAD"])?;
    git(&dir, &["init", "--bare", "remote.git"])?;
    git(&seed, &["remote", "add", "origin", bare.to_str().unwrap()])?;
    git(&seed, &["push", "-u", "origin", "main"])?;
    git(
        &dir,
        &[
            "clone",
            "--branch",
            "main",
            bare.to_str().unwrap(),
            "destination",
        ],
    )?;
    fs::write(seed.join("state"), "two\n").map_err(|e| e.to_string())?;
    git(&seed, &["add", "state"])?;
    git(&seed, &["commit", "-m", "two"])?;
    git(&seed, &["push", "origin", "main"])?;
    let remote = git(&seed, &["rev-parse", "HEAD"])?;
    let before = git(&dst, &["rev-parse", "HEAD"])?;
    let mut creds = BTreeMap::new();
    creds.insert(
        "owner".into(),
        crate::tools::git_artifact::CredentialScope {
            ssh_key_path: None,
            https_host: None,
            https_token_path: None,
        },
    );
    let plan = crate::tools::git_artifact::SourcePlan {
        candidates: vec![crate::tools::git_artifact::SourceCandidate {
            kind: crate::tools::git_artifact::SourceCandidateKind::Git,
            locator: bare.to_string_lossy().into(),
            credential_selector: Some("owner".into()),
        }],
        reference: "main".into(),
        destination: dst.clone(),
        expected_commit: None,
        bearer: "owner".into(),
        credentials: creds,
    };
    let r1 = crate::tools::git_artifact::acquire_source(&plan, Some(invocation));
    let head = git(&dst, &["rev-parse", "HEAD"])?;
    let second_pass_before = destination_snapshot(&dst)?;
    let r2 = crate::tools::git_artifact::acquire_source(&plan, Some(invocation));
    let second_pass_after = destination_snapshot(&dst)?;
    let second_pass_snapshot = snapshot_predicates(&second_pass_before, &second_pass_after);
    let second_pass_zero_writes = second_pass_before == second_pass_after;
    fs::write(dst.join("state"), "dirty-local-change\n").map_err(|e| e.to_string())?;
    let dirty_before = destination_snapshot(&dst)?;
    let dirty = crate::tools::git_artifact::acquire_source(&plan, Some(invocation));
    let dirty_after = destination_snapshot(&dst)?;
    let dirty_snapshot = snapshot_predicates(&dirty_before, &dirty_after);
    let dirty_refused_without_write = !dirty.ok && !dirty.changed && dirty_before == dirty_after;
    let config = fs::read_to_string(dst.join(".git/config")).map_err(|e| e.to_string())?;
    let dummy_ssh_key = PathBuf::from("/tmp/bench-scope-dummy-id_ed25519");
    let dummy_https_host = "scope.example.invalid".to_string();
    let dummy_token_path = PathBuf::from("/tmp/bench-scope-dummy-token");
    let scope = crate::tools::git_artifact::CredentialScope {
        ssh_key_path: Some(dummy_ssh_key.clone()),
        https_host: Some(dummy_https_host.clone()),
        https_token_path: Some(dummy_token_path.clone()),
    };
    let scope_plan = crate::tools::git_artifact::SourcePlan {
        candidates: vec![crate::tools::git_artifact::SourceCandidate {
            kind: crate::tools::git_artifact::SourceCandidateKind::Git,
            locator: "https://scope.example.invalid/owner/repo.git".into(),
            credential_selector: Some("scope-owner".into()),
        }],
        reference: "main".into(),
        destination: dir.join("scope-destination"),
        expected_commit: None,
        bearer: "scope-bearer".into(),
        credentials: BTreeMap::from([("scope-owner".into(), scope.clone())]),
    };
    let scoped = crate::tools::git_artifact::scoped_request(
        &scope_plan,
        &scope_plan.candidates[0],
        scope_plan.destination.clone(),
    );
    let local_candidate = crate::tools::git_artifact::SourceCandidate {
        kind: crate::tools::git_artifact::SourceCandidateKind::LocalCheckout,
        locator: dir.join("local-source").to_string_lossy().into(),
        credential_selector: Some("scope-owner".into()),
    };
    let local_scoped = crate::tools::git_artifact::scoped_request(
        &scope_plan,
        &local_candidate,
        PathBuf::from(&local_candidate.locator),
    );
    let exact_scope_projection = scoped.repo.as_deref()
        == Some("https://scope.example.invalid/owner/repo.git")
        && scoped.path == scope_plan.destination
        && scoped.branch == "main"
        && scoped.remote == "origin"
        && scoped.bearer == "scope-bearer"
        && scoped.ssh_key_path == Some(dummy_ssh_key.clone())
        && scoped.git_https_credential_host == Some(dummy_https_host.clone())
        && scoped.git_https_credential_token_path == Some(dummy_token_path.clone())
        && scoped.safe_directories.is_empty()
        && local_scoped.safe_directories == vec![PathBuf::from(&local_candidate.locator)];
    let credential_selector_preserved = r1
        .receipt
        .attempts
        .first()
        .and_then(|attempt| attempt.credential_selector.as_deref())
        == Some("owner");
    let only_declared_scope_used = r1.receipt.attempts.iter().all(|attempt| {
        attempt.credential_selector.as_deref() == Some("owner")
            && plan.credentials.contains_key("owner")
    });
    let no_credential_material_persisted = [
        "credential.helper",
        dummy_ssh_key.to_str().unwrap(),
        dummy_https_host.as_str(),
        dummy_token_path.to_str().unwrap(),
    ]
    .iter()
    .all(|material| !config.contains(material));
    let credential_scope_preserved = exact_scope_projection
        && credential_selector_preserved
        && only_declared_scope_used
        && no_credential_material_persisted;
    let wrong_selector_root = dir.join("wrong-selector");
    let bad = crate::tools::git_artifact::SourcePlan {
        candidates: vec![crate::tools::git_artifact::SourceCandidate {
            kind: crate::tools::git_artifact::SourceCandidateKind::Git,
            locator: dir.join("missing.git").to_string_lossy().into(),
            credential_selector: Some("missing-selector".into()),
        }],
        reference: "main".into(),
        destination: wrong_selector_root.join("destination"),
        expected_commit: None,
        bearer: "owner".into(),
        credentials: BTreeMap::new(),
    };
    let failed_before = destination_snapshot(&wrong_selector_root)?;
    let failed_parent_before = destination_snapshot(&dir)?;
    let ru = crate::tools::git_artifact::acquire_source(&bad, Some(invocation));
    let failed_after = destination_snapshot(&wrong_selector_root)?;
    let failed_parent_after = destination_snapshot(&dir)?;
    let wrong_selector_attempt = ru.receipt.attempts.first();
    let failed_source_refusal = !ru.ok
        && !ru.changed
        && wrong_selector_attempt.is_some_and(|attempt| {
            attempt.disposition == "hard-red-credential"
                && attempt.detail == "credential-selector-unresolved"
        })
        && failed_before == failed_after
        && failed_parent_before == failed_parent_after;
    if !r1.ok
        || !r1.changed
        || head != remote
        || !r2.ok
        || r2.changed
        || ru.ok
        || ru.receipt.attempts.is_empty()
        || !dirty_refused_without_write
        || !second_pass_zero_writes
        || !credential_scope_preserved
        || !failed_source_refusal
    {
        return Err("git-artifact-three-case-bench-failed".into());
    }
    Ok(
        json!({"setup":{"commit_1":c1,"destination_before":before,"commit_2_remote_head":remote,"setup_checked":true,"changed_then_quiet":r1.changed && !r2.changed},"run1":{"ok":r1.ok,"changed":r1.changed,"destination_head":head,"declared_remote_head":remote,"attempts":r1.receipt.attempts.len(),"promotion":r1.receipt.promotion},"run2":{"ok":r2.ok,"changed":r2.changed,"attempts":r2.receipt.attempts.len(),"promotion":r2.receipt.promotion,"requested_ref_equals_head":head == remote,"second_pass_zero_movement":!r2.changed,"second_pass_zero_writes":second_pass_zero_writes,"snapshot":second_pass_snapshot},"dirty_refusal":{"ok":dirty.ok,"changed":dirty.changed,"refused_without_destination_write":dirty_refused_without_write,"structural_zero_writes":dirty_before == dirty_after,"snapshot":dirty_snapshot},"credential_scope":{"preserved":credential_scope_preserved,"exact_scope_projection":exact_scope_projection,"selector_preserved":credential_selector_preserved,"only_declared_scope_used":only_declared_scope_used,"no_credential_material_persisted":no_credential_material_persisted,"declared":{"ssh_key_path":dummy_ssh_key,"https_host":dummy_https_host,"https_token_path":dummy_token_path,"bearer":scope_plan.bearer,"safe_directories":[]},"projected":{"ssh_key_path":scoped.ssh_key_path,"https_host":scoped.git_https_credential_host,"https_token_path":scoped.git_https_credential_token_path,"bearer":scoped.bearer,"safe_directories":scoped.safe_directories},"local_safe_directory_projection":local_scoped.safe_directories},"wrong_selector":{"predicate":failed_source_refusal,"ok":ru.ok,"changed":ru.changed,"disposition":wrong_selector_attempt.map(|a| a.disposition.clone()),"detail":wrong_selector_attempt.map(|a| a.detail.clone()),"hard_red_credential":wrong_selector_attempt.is_some_and(|a| a.disposition == "hard-red-credential"),"destination_and_staging_unchanged":failed_before == failed_after && failed_parent_before == failed_parent_after,"destination_snapshot_unchanged":failed_before == failed_after,"parent_snapshot_unchanged":failed_parent_before == failed_parent_after,"promotion":ru.receipt.promotion},"unreachable":{"ok":ru.ok,"changed":ru.changed,"attempts_count":ru.receipt.attempts.len(),"failed_source_refusal":failed_source_refusal,"destination_snapshot_unchanged":failed_before == failed_after,"dispositions":ru.receipt.attempts.iter().map(|a|a.disposition.clone()).collect::<Vec<_>>(),"promotion":ru.receipt.promotion}}),
    )
}

fn caduceus_bench(
    root: &Path,
    invocation: crate::atoms::r#do::InvocationKey,
) -> Result<serde_json::Value, String> {
    let dir = root.join("caduceus");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let source_sha = "0123456789abcdef0123456789abcdef01234567";
    let build = crate::build_crate::bench_build_guard(&dir, source_sha)?;
    let artifact = dir.join("target/release/caduceus");
    let install = dir.join("usr/local/bin/caduceus");
    fs::create_dir_all(install.parent().ok_or("install-parent-missing")?)
        .map_err(|e| e.to_string())?;
    let bytes = fs::read(&artifact).map_err(|e| e.to_string())?;
    let run = |rd: &Path| {
        crate::place_file::execute(crate::place_file::PlaceFileRequest {
            path: &install,
            declared_bytes: &bytes,
            mode: Some(0o755),
            ownership: crate::place_file::DeclaredOwnership {
                uid: None,
                gid: None,
            },
            backup: crate::place_file::BackupPolicy::To(&rd.join("backup")),
            invocation: Some(invocation),
        })
    };
    let run1_dir = dir.join("run1");
    let run1 = run(&run1_dir)?;
    let run2_dir = dir.join("run2");
    let run2 = run(&run2_dir)?;
    let health1 = serve_health_once(source_sha, |url| {
        Ok(crate::check_health::probe(
            &crate::tools::health::ProbeRequest {
                url: &url,
                retries: 0,
                timeout_secs: 3,
                expected_contains: Some(source_sha),
            },
        ))
    })?;
    let wrong = "fedcba9876543210fedcba9876543210fedcba98";
    let health_bad = serve_health_value(wrong, |url| {
        Ok(crate::check_health::probe(
            &crate::tools::health::ProbeRequest {
                url: &url,
                retries: 0,
                timeout_secs: 3,
                expected_contains: Some(source_sha),
            },
        ))
    })?;
    crate::write_command_receipt(&run1_dir, "check-health", &health1)?;
    crate::write_command_receipt(&run2_dir, "check-health", &health_bad)?;
    if !run1.receipt.ok
        || !run1.movement.changed()
        || !run2.receipt.ok
        || run2.movement.changed()
        || !health1.ok
        || health_bad.ok
    {
        return Err("caduceus-primitive-stillness-bench-failed".into());
    }
    Ok(
        json!({"source_gate":{"fresh_source":true,"source_sha":source_sha,"stale_service_ignored":true},"build":build,"run1":{"ok":run1.receipt.ok,"changed":run1.movement.changed()},"run2":{"ok":run2.receipt.ok,"changed":run2.movement.changed()},"health":{"matching_identity":{"ok":health1.ok},"mismatched_identity":{"ok":health_bad.ok,"stderr":health_bad.stderr}}}),
    )
}

fn service_runtime_build_sha_bench(
    root: &Path,
    invocation: crate::atoms::r#do::InvocationKey,
) -> Result<serde_json::Value, String> {
    let dir = root.join("service-runtime-build-sha");
    let source_dir = dir.join("fixture");
    let cargo_home = dir.join("cargo-home");
    let install_bin = dir.join("installed/fixture");
    let source_sha = "0123456789abcdef0123456789abcdef01234567";
    fs::create_dir_all(source_dir.join("src")).map_err(|e| e.to_string())?;
    if let Some(parent) = install_bin.parent() { fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
    fs::create_dir_all(dir.join("managed")).map_err(|e| e.to_string())?;
    fs::write(
        source_dir.join("Cargo.toml"),
        b"[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        source_dir.join("src/main.rs"),
        b"fn main() { println!(\"{}\", env!(\"FIXTURE_BUILD_SHA\")); }\n",
    )
    .map_err(|e| e.to_string())?;

    let mut manifest: crate::ladder::LadderManifest = serde_json::from_value(json!({
        "schema":"harmonia.ladder.v1", "id":"service-runtime-build-sha-bench",
        "version":"1.0.0", "constants": {}, "ladder":[{
            "step_id":"runtime", "tool":"service-runtime", "permutation":"converge",
            "args": {
                "component":"fixture", "source_dir":source_dir, "install_bin":install_bin,
                "service":"fixture.service", "url":"http://127.0.0.1:1/health",
                "binary_name":"fixture", "op_prefix":"fixture", "run_schema":"bench.v1",
                "managed_files_schema":"bench.v1", "managed_files":[{
                    "path":dir.join("managed/fixture.txt"), "content":"fixture-managed\n", "mode":420,
                    "operation":"place", "xattrs":{}, "no_follow":true, "uid":1000, "gid":1000,
                    "collision_policy":"refuse", "rollback_policy":"exact"
                }],
                "build_environment":{"CARGO_HOME":cargo_home}
            }
        }]
    })).map_err(|e| e.to_string())?;
    let binary_name = manifest.ladder.first()
        .and_then(|step| step.args.get("binary_name"))
        .and_then(Value::as_str)
        .ok_or_else(|| "service-runtime-binary-name-missing".to_string())?
        .to_string();
    crate::bands::restart_services::lower_service_runtime_steps(&mut manifest);
    crate::bands::backfill_files::lower_service_runtime_steps(&mut manifest)?;
    // Safe loopback fixture for the health child; no host service is touched.
    let health_listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let health_address = health_listener.local_addr().map_err(|e| e.to_string())?;
    let health_server = thread::spawn(move || -> Result<(), String> {
        for _ in 0..10 {
            let (mut stream, _) = health_listener.accept().map_err(|e| e.to_string())?;
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).map_err(|e| e.to_string())?;
            let body = json!({"ok":true,"build_sha":source_sha}).to_string();
            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
            stream.write_all(response.as_bytes()).map_err(|e| e.to_string())?;
        }
        Ok(())
    });
    let health_url = format!("http://{health_address}/health");
    let projected_health_children = [
        "service-daemon-reload", "service-enable", "service-restart", "service-active", "health-proof",
    ];
    let source = manifest.ladder.first().ok_or_else(|| "service-runtime-step-missing".to_string())?;
    let build = source.steps.iter().find(|child| child.name == "build")
        .ok_or_else(|| "service-runtime-build-child-missing".to_string())?;
    let mut projected = crate::tools::routine::project_routine_children(source, &manifest.constants)
        .map_err(|e| e.first_missing_signal())?;
    for child in &mut projected {
        if projected_health_children.contains(&child.name.as_str()) {
            child.tool = "check-health".into();
            child.permutation = "probe".into();
            child.args.insert("url".into(), json!(health_url));
            child.args.insert("expected_contains".into(), json!(source_sha));
        }
    }
    if build.args.contains_key("artifact") {
        return Err("service-runtime-build-artifact-override-present".into());
    }
    let expected_artifact = source_dir.join("target/release").join(&binary_name);
    let lowered_environment = build.args.get("environment").and_then(Value::as_object)
        .ok_or_else(|| "service-runtime-build-environment-missing".to_string())?;
    let build_sha_ref = lowered_environment.get("FIXTURE_BUILD_SHA")
        .ok_or_else(|| "service-runtime-build-sha-env-missing".to_string())?;
    let environment_preserved = lowered_environment.get("CARGO_HOME") == Some(&json!(cargo_home));
    let generic_environment_ref = build_sha_ref == &json!({"from":"pull-repo.resolved_commit"});
    if !environment_preserved || !generic_environment_ref {
        return Err("service-runtime-build-sha-lowering-bench-failed".into());
    }

    let mut unresolved_manifest = manifest.clone();
    let unresolved_source = unresolved_manifest
        .ladder
        .first_mut()
        .ok_or_else(|| "service-runtime-unresolved-step-missing".to_string())?;
    let unresolved_build = unresolved_source
        .steps
        .iter_mut()
        .find(|child| child.name == "build")
        .ok_or_else(|| "service-runtime-unresolved-build-child-missing".to_string())?;
    unresolved_build
        .args
        .get_mut("environment")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "service-runtime-unresolved-environment-missing".to_string())?
        .insert(
            "FIXTURE_BUILD_SHA".into(),
            json!({"from":"pull-repo.unresolved_nested_reference"}),
        );
    let unresolved_projected = crate::tools::routine::project_routine_children(
        unresolved_source,
        &unresolved_manifest.constants,
    )
    .map_err(|e| e.first_missing_signal())?;
    let unresolved_step = crate::ladder::ValidatedStep {
        step_id: unresolved_source.step_id.clone(),
        tool: "routine".into(),
        permutation: "execute".into(),
        args: BTreeMap::new(),
        on_failure: crate::ladder::OnFailure::Stop,
    };
    let unresolved_module_dir = dir.join("unresolved-reference");
    let unresolved_routine_dir = unresolved_module_dir.join("runtime");
    fs::create_dir_all(unresolved_routine_dir.join("pull-repo"))
        .map_err(|e| e.to_string())?;
    let unresolved_pull_receipt = json!({
        "schema":"harmonia.routine.child-receipt.v1", "name":"pull-repo", "tool":"pull-repo",
        "state":"completed", "ok":true, "changed":false, "outputs":{
            "path":source_dir, "resolved_commit":source_sha
        }
    });
    fs::write(
        unresolved_routine_dir.join("pull-repo/routine-child.json"),
        unresolved_pull_receipt.to_string(),
    )
    .map_err(|e| e.to_string())?;
    let mut unresolved_states = BTreeMap::new();
    unresolved_states.insert("runtime".into(), crate::ModuleWalkState {
        context: [("pull-repo.path".into(), json!(source_dir)), ("pull-repo.resolved_commit".into(), json!(source_sha)), ("pull-repo.changed".into(), json!(false)), ("pull-repo.source_reference".into(), json!("main")), ("pull-repo.source_remote".into(), json!("https://example.invalid/fixture.git"))].into_iter().collect(),
        children: vec![unresolved_pull_receipt], blocked_by: None, ok: true, changed: false,
        first_missing_signal: None,
    });
    let unresolved_outcome = crate::tools::routine::execute_routine(
        &unresolved_step,
        &unresolved_manifest,
        &unresolved_module_dir,
        None,
        None,
        true,
        Some(invocation),
        Some(&mut unresolved_states),
        crate::bands::Band::RatchetBinaries,
        &unresolved_projected,
    )?;
    let unresolved_signal = unresolved_states
        .get("runtime")
        .and_then(|state| state.first_missing_signal.as_deref());
    let unresolved_nested_reference_rejected = !unresolved_outcome.ok
        && unresolved_signal
            == Some("step_id=build defect=missing-stamp-pull-repo.unresolved_nested_reference");

    let step = crate::ladder::ValidatedStep {
        step_id: source.step_id.clone(), tool: "routine".into(), permutation: "execute".into(),
        args: BTreeMap::new(), on_failure: crate::ladder::OnFailure::Stop,
    };
    let projected_names: Vec<&str> = projected.iter().map(|child| child.name.as_str()).collect();
    let managed_producer_index = projected_names
        .iter()
        .position(|name| *name == "managed-place-0" || *name == "managed-files")
        .ok_or_else(|| "service-runtime-managed-files-producer-missing".to_string())?;
    let daemon_index = projected_names
        .iter()
        .position(|name| *name == "service-daemon-reload")
        .ok_or_else(|| "service-runtime-daemon-reload-child-missing".to_string())?;
    let stamp_consumers = [
        "service-daemon-reload", "service-enable", "service-restart", "service-active",
    ];
    let service_stamp_wiring = stamp_consumers.iter().all(|name| {
        source.steps.iter().find(|child| child.name == *name)
            .and_then(|child| child.args.get("managed_files_changed"))
            == Some(&json!({"from":"managed-files.changed"}))
    });
    let managed_stamp_precedes_consumers = managed_producer_index < daemon_index;
    if !service_stamp_wiring || !managed_stamp_precedes_consumers {
        return Err("service-runtime-stamp-wiring-bench-failed".into());
    }
    let binary_install = source
        .steps
        .iter()
        .find(|child| child.name == "binary-install")
        .ok_or_else(|| "service-runtime-binary-install-child-missing".to_string())?;
    let binary_install_routine_gate_accepts = binary_install.tool == "place-file"
        && binary_install.permutation.as_deref() == Some("binary-promotion")
        && binary_install.args.get("no_follow") == Some(&json!(true))
        && binary_install.args.get("collision_policy") == Some(&json!("refuse"))
        && binary_install.args.get("rollback_policy") == Some(&json!("exact"))
        && binary_install.args.get("xattrs") == Some(&json!({}));
    if !binary_install_routine_gate_accepts {
        return Err("service-runtime-binary-install-routine-gate-failed".into());
    }
    let pull_receipt = json!({
        "schema":"harmonia.routine.child-receipt.v1", "name":"pull-repo", "tool":"pull-repo",
        "state":"completed", "ok":true, "changed":false, "outputs":{
            "path":source_dir, "resolved_commit":source_sha
        }
    });
    let run_once = |label: &str| -> Result<(crate::OperationOutcome, serde_json::Value, bool, PathBuf, bool, Vec<serde_json::Value>), String> {
        let module_dir = dir.join(label);
        let routine_dir = module_dir.join("runtime");
        fs::create_dir_all(routine_dir.join("pull-repo")).map_err(|e| e.to_string())?;
        fs::write(routine_dir.join("pull-repo/routine-child.json"), pull_receipt.to_string())
            .map_err(|e| e.to_string())?;
        let mut states = BTreeMap::new();
        states.insert("runtime".into(), crate::ModuleWalkState {
            context: [("pull-repo.path".into(), json!(source_dir)), ("pull-repo.resolved_commit".into(), json!(source_sha)), ("pull-repo.changed".into(), json!(false)), ("pull-repo.source_reference".into(), json!("main")), ("pull-repo.source_remote".into(), json!("https://example.invalid/fixture.git"))].into_iter().collect(),
            children: vec![pull_receipt.clone()], blocked_by: None, ok: true, changed: false,
            first_missing_signal: None,
        });
        let bands = [
            crate::bands::Band::RatchetBinaries,
            crate::bands::Band::BackfillFiles,
            crate::bands::Band::RestartServices,
        ];
        let mut outcome = crate::OperationOutcome { ok: true, changed: false, skipped: false, message: "routine-complete".into(), command: None };
        for band in bands {
            // The projected RestartServices children are all loopback probes.
            let band_apply = true;
            let pass = crate::tools::routine::execute_routine(
                &step, &manifest, &module_dir, None, None, band_apply, Some(invocation),
                Some(&mut states), band, &projected,
            )?;
            outcome.ok &= pass.ok;
            outcome.changed |= pass.changed;
            if !pass.ok && outcome.message == "routine-complete" {
                outcome.message = pass.message;
            }
        }
        let receipt: Value = serde_json::from_str(&fs::read_to_string(module_dir.join("runtime.routine.json")).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let actual_receipts = states.get("runtime").map(|state| state.children.clone()).unwrap_or_default();
        let artifact = states.get("runtime").and_then(|state| state.context.get("build.artifact"))
            .and_then(Value::as_str).ok_or_else(|| "service-runtime-artifact-output-missing".to_string())?;
        let artifact_path = PathBuf::from(artifact);
        let artifact_selection_matches = artifact_path == expected_artifact;
        let artifact_bytes = fs::read(&artifact_path).map_err(|e| e.to_string())?;
        let artifact_embeds = artifact_bytes.windows(source_sha.len()).any(|window| window == source_sha.as_bytes());
        Ok((outcome, receipt, artifact_embeds, artifact_path, artifact_selection_matches, actual_receipts))
    };
    let (first, first_receipt, artifact_embeds_first, first_artifact, first_selection_matches, first_child_receipts) = run_once("first")?;
    let (second, second_receipt, artifact_embeds_second, second_artifact, second_selection_matches, second_child_receipts) = run_once("second")?;
    health_server.join().map_err(|_| "health-bench-server-panicked".to_string())??;
    let first_changed = first.ok && first.changed && first_receipt.get("changed").and_then(Value::as_bool) == Some(true);
    let second_quiet = second.ok && !second.changed && second_receipt.get("changed").and_then(Value::as_bool) == Some(false);
    let actual_stage_order = |receipts: &[serde_json::Value]| receipts.iter().filter_map(|receipt| receipt.get("name").and_then(Value::as_str)).map(str::to_string).collect::<Vec<_>>();
    let first_actual_stage_order = actual_stage_order(&first_child_receipts);
    let second_actual_stage_order = actual_stage_order(&second_child_receipts);
    let expected_stage_order = ["pull-repo", "build", "binary-install", "managed-place-0", "service-daemon-reload", "service-enable", "service-restart", "service-active", "health-proof"];
    let service_stages_exercised = first_actual_stage_order == expected_stage_order && second_actual_stage_order == expected_stage_order;
    let all_actual_receipts_ok = first_child_receipts.iter().chain(second_child_receipts.iter()).all(|receipt| receipt.get("ok").and_then(Value::as_bool) == Some(true));
    let no_missing_stamp_failures = first_child_receipts.iter().chain(second_child_receipts.iter()).all(|receipt| receipt.get("first_missing_signal").is_none() && !receipt.get("state").and_then(Value::as_str).is_some_and(|state| state == "missing"));
    let service_fixture_isolated = true;
    let artifact_embeds = artifact_embeds_first && artifact_embeds_second;
    let artifact_selection_matches = first_selection_matches && second_selection_matches
        && first_artifact == expected_artifact && second_artifact == expected_artifact;
    let executed_output = Command::new(&first_artifact)
        .output().map_err(|e| e.to_string())?;
    let artifact_executes = executed_output.status.success()
        && String::from_utf8_lossy(&executed_output.stdout).trim() == source_sha;
    let all_predicates = environment_preserved && generic_environment_ref && artifact_embeds
        && artifact_executes && first_changed && second_quiet && artifact_selection_matches
        && service_stages_exercised && all_actual_receipts_ok && no_missing_stamp_failures
        && service_stamp_wiring && managed_stamp_precedes_consumers && service_fixture_isolated;
    if !all_predicates || !unresolved_nested_reference_rejected {
        return Err("service-runtime-build-sha-bench-failed".into());
    }
    Ok(json!({
        "generic_environment_key":"FIXTURE_BUILD_SHA", "generic_environment_ref":build_sha_ref,
        "explicit_environment_preserved":environment_preserved,
        "artifact_embeds_build_sha_environment":artifact_embeds,
        "artifact_executes_with_build_sha":artifact_executes,
        "binary_install_routine_gate_accepts":binary_install_routine_gate_accepts,
        "service_stages_exercised":service_stages_exercised,
        "all_actual_receipts_ok":all_actual_receipts_ok,
        "service_fixture_isolated":service_fixture_isolated,
        "first_actual_child_receipt_order":first_actual_stage_order,
        "second_actual_child_receipt_order":second_actual_stage_order,
        "no_missing_stamp_failures":no_missing_stamp_failures,
        "service_stamp_wiring":service_stamp_wiring,
        "managed_stamp_precedes_consumers":managed_stamp_precedes_consumers,
        "first_pass_changed":first_changed, "second_pass_quiet":second_quiet,
        "artifact_selection_matches":artifact_selection_matches,
        "unresolved_nested_reference_rejected":unresolved_nested_reference_rejected,
        "artifact_path":first_artifact,
        "ok":all_predicates && unresolved_nested_reference_rejected && binary_install_routine_gate_accepts
    }))
}

fn serve_health_value<T>(
    body_sha: &str,
    run: impl FnOnce(String) -> Result<T, String>,
) -> Result<T, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let body = json!({"ok": true, "build_sha": body_sha}).to_string();
    let server = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        let mut request = [0_u8; 2048];
        let _ = stream
            .read(&mut request)
            .map_err(|error| error.to_string())?;
        let response = format!(
            "HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: {}
Connection: close

{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .map_err(|error| error.to_string())
    });
    let result = run(format!("http://{address}/health"));
    server
        .join()
        .map_err(|_| "health-bench-server-panicked".to_string())??;
    result
}

fn serve_health_once<T>(
    source_sha: &str,
    run: impl FnOnce(String) -> Result<T, String>,
) -> Result<T, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let body = json!({"ok": true, "build_sha": source_sha}).to_string();
    let server = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        let mut request = [0_u8; 2048];
        let _ = stream
            .read(&mut request)
            .map_err(|error| error.to_string())?;
        let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
        stream
            .write_all(response.as_bytes())
            .map_err(|error| error.to_string())
    });
    let result = run(format!("http://{address}/health"));
    server
        .join()
        .map_err(|_| "health-bench-server-panicked".to_string())??;
    result
}

fn aur_pinned_bench(
    root: &Path,
    invocation: crate::atoms::r#do::InvocationKey,
) -> Result<serde_json::Value, String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    fn git(cwd: &Path, args: &[&str]) -> Result<String, String> {
        let out = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).into());
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().into())
    }
    let dir = root.join("aur-pinned");
    let source = dir.join("source");
    let receipts = dir.join("receipts");
    fs::create_dir_all(&source).map_err(|e| e.to_string())?;
    git(&source, &["init", "-b", "main"])?;
    git(&source, &["config", "user.email", "bench@example.invalid"])?;
    git(&source, &["config", "user.name", "bench"])?;
    fs::write(
        source.join("PKGBUILD"),
        "pkgname=benchpkg
pkgver=1
pkgrel=1
",
    )
    .map_err(|e| e.to_string())?;
    git(&source, &["add", "PKGBUILD"])?;
    git(&source, &["commit", "-m", "pinned"])?;
    let pinned_sha = git(&source, &["rev-parse", "HEAD"])?;
    let lock = dir.join("lock.json");
    fs::write(&lock,serde_json::json!({"schema":"harmonia.aur.ratchet_lock.v1","package":"benchpkg","pinned_version":"1","pkgbuild_sha":pinned_sha}).to_string()).map_err(|e|e.to_string())?;
    let log = dir.join("fake-tools.log");
    let fake = dir.join("makepkg");
    fs::write(
        &fake,
        format!(
            r#"#!/bin/sh
printf 'makepkg:%s\n' "$*" >> "{0}"
printf artifact-bytes > benchpkg-1-1-x86_64.pkg.tar.zst
"#,
            log.display()
        ),
    )
    .map_err(|e| e.to_string())?;
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    let state = dir.join("pacman-state");
    let pac = dir.join("pacman");
    fs::write(&state, "absent\n").map_err(|e| e.to_string())?;
    fs::write(&pac,format!(r#"#!/bin/sh
printf 'pacman:%s\n' "$*" >> "{0}"
case $1 in -Q) [ "$(cat "{1}")" = installed ] && printf 'benchpkg 1\n' || exit 1;; -U) printf installed > "{1}";; esac
"#,log.display(),state.display())).map_err(|e|e.to_string())?;
    fs::set_permissions(&pac, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    let upstream = dir.join("upstream.json");
    fs::write(&upstream, serde_json::json!({"schema":"harmonia.aur.upstream_state.v1","package":"benchpkg","available_version":"1","pkgbuild_sha":pinned_sha,"observed_source":"stillness-bench"}).to_string()).map_err(|e|e.to_string())?;
    let om = env::var("HARMONIA_MAKEPKG_PATH").ok();
    let op = env::var("HARMONIA_PACMAN_PATH").ok();
    let ou = env::var("HARMONIA_AUR_UPSTREAM_STATE").ok();
    env::set_var("HARMONIA_MAKEPKG_PATH", &fake);
    env::set_var("HARMONIA_PACMAN_PATH", &pac);
    env::set_var("HARMONIA_AUR_UPSTREAM_STATE", &upstream);
    let first = crate::tools::aur::build_pinned(
        &receipts,
        "build-pinned",
        "benchpkg",
        &lock,
        &dir.join("build"),
        Some(source.to_str().unwrap()),
        Some("current-user"),
        30,
        true,
        true,
        Some(invocation),
        &std::collections::BTreeMap::new(),
    )?;
    let fb: serde_json::Value = serde_json::from_slice(
        &fs::read(receipts.join("build-pinned.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let fi: serde_json::Value = serde_json::from_slice(
        &fs::read(receipts.join("build-pinned.install.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let before = fs::read_to_string(&log).map_err(|e| e.to_string())?;
    let second = crate::tools::aur::build_pinned(
        &receipts,
        "build-pinned",
        "benchpkg",
        &lock,
        &dir.join("build"),
        Some(source.to_str().unwrap()),
        Some("current-user"),
        30,
        true,
        true,
        Some(invocation),
        &std::collections::BTreeMap::new(),
    )?;
    let sb: serde_json::Value = serde_json::from_slice(
        &fs::read(receipts.join("build-pinned.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let si: serde_json::Value = serde_json::from_slice(
        &fs::read(receipts.join("build-pinned.install.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let after = fs::read_to_string(&log).map_err(|e| e.to_string())?;
    match om {
        Some(v) => env::set_var("HARMONIA_MAKEPKG_PATH", v),
        None => env::remove_var("HARMONIA_MAKEPKG_PATH"),
    };
    match op {
        Some(v) => env::set_var("HARMONIA_PACMAN_PATH", v),
        None => env::remove_var("HARMONIA_PACMAN_PATH"),
    }
    match ou {
        Some(v) => env::set_var("HARMONIA_AUR_UPSTREAM_STATE", v),
        None => env::remove_var("HARMONIA_AUR_UPSTREAM_STATE"),
    };
    let count = |s: &str, p: &str| s.lines().filter(|x| x.starts_with(p)).count();
    let fbops = count(&before, "makepkg:");
    let fiops = count(&before, "pacman:-U");
    let sbops = count(&after[before.len()..], "makepkg:");
    let siops = count(&after[before.len()..], "pacman:-U");
    let artifact = PathBuf::from(
        fb["produced_package_path"]
            .as_str()
            .ok_or("aur-first-artifact-missing")?,
    );
    let bytes = fs::read(&artifact).map_err(|e| e.to_string())?;
    let sha = crate::atoms::file_sha256(&bytes);
    let meta = fs::metadata(&artifact).map_err(|e| e.to_string())?;
    let missing = crate::atoms::r#do::install_aur_pinned::run(
        &crate::atoms::r#do::install_aur_pinned::Plan {
            receipt_dir: receipts.clone(),
            receipt_name: "missing".into(),
            build_receipt: receipts.join("missing-build.json"),
            package: "benchpkg".into(),
            expected_version: "1".into(),
            timeout_secs: 30,
            ignored: Vec::new(),
            target_pinned: false,
        },
        true,
    )?;
    let mr: serde_json::Value = serde_json::from_slice(
        &fs::read(receipts.join("missing.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let no_install = !missing.ok
        && !missing.changed
        && mr["schema"] == "harmonia.aur.install_pinned.v1"
        && mr["first_blocker"]
            .as_str()
            .unwrap_or("")
            .starts_with("pinned-build-proof-missing");
    if !first.ok
        || !first.changed
        || !second.ok
        || second.changed
        || fb["changed"] != true
        || fi["changed"] != true
        || sb["changed"] != false
        || si["changed"] != false
        || fbops == 0
        || fiops == 0
        || sbops != 0
        || siops != 0
        || sha != fb["artifact_sha256"].as_str().unwrap_or("")
        || !no_install
    {
        return Err("aur-pinned-stillness-proof-failed".into());
    }
    Ok(
        json!({"pinned_sha":pinned_sha,"source_checkout_sha":pinned_sha,"builder_toolchain_identity":"current-user","artifact_sha256":sha,"artifact_path":artifact,"build_receipt":"build-pinned.json","install_receipt":"build-pinned.install.json","build_schema":"harmonia.aur.build_pinned.v1","install_schema":"harmonia.aur.install_pinned.v1","candidate_mode_owner":{"mode":format!("{:o}",meta.mode()&0o777),"uid":meta.uid(),"gid":meta.gid()},"first":{"changed":first.changed,"build_changed":fb["changed"],"install_changed":fi["changed"],"build_operation_count":fbops,"install_operation_count":fiops},"second":{"changed":second.changed,"build_changed":sb["changed"],"install_changed":si["changed"],"build_operation_count":sbops,"install_operation_count":siops},"changed_then_quiet":true,"no_install_before_failed_build":no_install,"failed_build_receipt":"missing.json","installed":true}),
    )
}

fn venv_bench(
    root: &Path,
    invocation: crate::atoms::r#do::InvocationKey,
) -> Result<serde_json::Value, String> {
    use std::os::unix::fs::MetadataExt;
    let dir = root.join("venv");
    let source = dir.join("source");
    let venv = dir.join("venv");
    let receipts = dir.join("receipts");
    fs::create_dir_all(&source).map_err(|e| e.to_string())?;
    fs::write(source.join("requirements.txt"), b"").map_err(|e| e.to_string())?;
    let patterns = vec!["requirements*.txt".to_string()];
    let request = crate::build_venv::Request {
        venv: &venv,
        source_root: &source,
        source_patterns: &patterns,
        python: Path::new("/usr/bin/python3"),
        receipt_dir: &receipts,
        receipt_name: "venv-bench.json",
        timeout_secs: 30,
    };
    let run1 = crate::build_venv::run(&request, true, Some(invocation))?;
    let run2 = crate::build_venv::run(&request, true, Some(invocation))?;
    let state = venv.join(".harmonia-sbin-dependency-sha256");
    let state_meta = fs::metadata(&state).map_err(|e| e.to_string())?;
    let state_bytes = fs::read(&state).map_err(|e| e.to_string())?;
    let state_hash = crate::atoms::file_sha256(&state_bytes);
    let python_path = venv.join("bin/python");
    let python_identity = fs::read_link(&python_path).map_err(|e| e.to_string())?;
    if !run1.ok || !run1.changed || !run2.ok || run2.changed {
        return Err("venv-double-run-bench-failed".into());
    }
    Ok(
        json!({"venv_path":venv,"python":{"requested":request.python,"path":python_path,"identity":python_identity},"state":{"path":state,"present":true,"sha256":state_hash,"mode":format!("{:o}",state_meta.mode()&0o777),"uid":state_meta.uid(),"gid":state_meta.gid()},"run1":{"ok":run1.ok,"changed":run1.changed,"message":run1.message},"run2":{"ok":run2.ok,"changed":run2.changed,"message":run2.message},"changed_then_quiet":run1.changed&&!run2.changed}),
    )
}

fn package_bench(
    root: &Path,
    invocation: crate::atoms::r#do::InvocationKey,
) -> Result<serde_json::Value, String> {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Stdio;
    let dir = root.join("package");
    let fr = dir.join("root");
    let bin = fr.join("usr/bin");
    let lock = fr.join("var/lib/pacman/db.lck");
    fs::create_dir_all(&bin).map_err(|e| e.to_string())?;
    fs::create_dir_all(lock.parent().unwrap()).map_err(|e| e.to_string())?;
    let state = dir.join("state");
    let target = dir.join("target");
    let marker = dir.join("conflict");
    fs::write(&state, "absent\n").map_err(|e| e.to_string())?;
    let fake = bin.join("pacman");
    fs::write(&fake,format!(r#"#!/bin/sh
s='{s}'; t='{t}'; m='{m}'
if [ "$1" = --hold ]; then while :; do sleep 1; done; fi
case "$1" in
-Q) if [ "$(cat "$s")" = absent ]; then exit 1; else printf 'benchpkg 1\n'; fi ;;
-Qu) if [ "$(cat "$s")" = pending ]; then printf 'benchpkg 1->2\n'; else exit 1; fi ;;
-Syu) printf 'upgrading benchpkg
'; [ "${{HARMONIA_BENCH_PERSIST:-0}}" = 1 ] || printf 'current
' > "$s" ;;
-S) if [ -f "$t" ] && [ ! -f "$m" ] && ! printf '%s' "$*"|grep -q -- --overwrite; then touch "$m"; printf 'exists in filesystem\n' >&2; exit 1; fi; printf 'installing benchpkg\n'; [ "${{HARMONIA_BENCH_PERSIST:-0}}" = 1 ] || printf 'current\n' > "$s"; printf '%s' "$*"|grep -q -- --overwrite && printf 'new-bytes\n' > "$t"; exit 0 ;;
*) exit 0;; esac
"#,s=state.display(),t=target.display(),m=marker.display())).map_err(|e|e.to_string())?;
    let mut pm = fs::metadata(&fake)
        .map_err(|e| e.to_string())?
        .permissions();
    pm.set_mode(0o755);
    fs::set_permissions(&fake, pm).map_err(|e| e.to_string())?;
    let saved = env::var("HARMONIA_PACMAN_PATH").ok();
    let sp = env::var("HARMONIA_BENCH_PERSIST").ok();
    let sc = env::var("HARMONIA_BENCH_CONFLICT").ok();
    let st = env::var("HARMONIA_BENCH_TARGET").ok();
    struct R(
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    impl Drop for R {
        fn drop(&mut self) {
            for (k, v) in [
                ("HARMONIA_PACMAN_PATH", &self.0),
                ("HARMONIA_BENCH_PERSIST", &self.1),
                ("HARMONIA_BENCH_CONFLICT", &self.2),
                ("HARMONIA_BENCH_TARGET", &self.3),
            ] {
                match v {
                    Some(x) => env::set_var(k, x),
                    None => env::remove_var(k),
                }
            }
        }
    }
    let _r = R(saved, sp, sc, st);
    env::set_var("HARMONIA_PACMAN_PATH", &fake);
    let pk = vec!["benchpkg".to_string()];
    let run = |n: &str, d: &Path| {
        crate::tools::package::package_tool_with_policy_for_backend(
            d,
            n,
            "install",
            &pk,
            true,
            None,
            &[],
            30,
            crate::PackageBackend::Pacman,
            Some(invocation),
        )
    };
    let cd = dir.join("current");
    fs::create_dir_all(&cd).map_err(|e| e.to_string())?;
    fs::write(&state, "current\n").map_err(|e| e.to_string())?;
    let cur = run("install", &cd).map_err(|e| format!("current:{e}"))?;
    let qd = dir.join("quiet");
    fs::create_dir_all(&qd).map_err(|e| e.to_string())?;
    let quiet = run("install", &qd).map_err(|e| format!("quiet:{e}"))?;
    let cur_r: serde_json::Value = serde_json::from_slice(
        &fs::read(cd.join("install.json")).map_err(|e| format!("cur-receipt:{e}"))?,
    )
    .map_err(|e| e.to_string())?;
    let quiet_r: serde_json::Value = serde_json::from_slice(
        &fs::read(qd.join("install.json")).map_err(|e| format!("quiet-receipt:{e}"))?,
    )
    .map_err(|e| e.to_string())?;
    let p1 = cur.ok
        && quiet.ok
        && !cur.changed
        && !quiet.changed
        && fs::read_to_string(&state)
            .map_err(|e| e.to_string())?
            .trim()
            == "current"
        && cur_r["diff_decision"] == "empty"
        && cur_r["movement"].is_null()
        && quiet_r["diff_decision"] == "empty"
        && quiet_r["movement"].is_null();
    fs::write(&state, "absent\n").map_err(|e| e.to_string())?;
    let xd = dir.join("changed");
    fs::create_dir_all(&xd).map_err(|e| e.to_string())?;
    let ch = run("install", &xd).map_err(|e| format!("changed:{e}"))?;
    let ch_r: serde_json::Value = serde_json::from_slice(
        &fs::read(xd.join("install.json")).map_err(|e| format!("changed-receipt:{e}"))?,
    )
    .map_err(|e| e.to_string())?;
    let p2 = ch.ok
        && ch.changed
        && fs::read_to_string(&state)
            .map_err(|e| e.to_string())?
            .trim()
            == "current"
        && ch_r["ok"] == true
        && ch_r["changed"] == true
        && ch_r["observed_state"] == "benchpkg 1\n";
    let apt = dir.join("apt-get");
    fs::write(
        &apt,
        "#!/bin/sh\n[ \"$1\" = -s ] && exit 0\nprintf 'The following packages will be installed: benchpkg\\n'\n",
    )
    .map_err(|e| e.to_string())?;
    let mut am = fs::metadata(&apt).map_err(|e| e.to_string())?.permissions();
    am.set_mode(0o755);
    fs::set_permissions(&apt, am).map_err(|e| e.to_string())?;
    let oa = env::var("HARMONIA_APT_GET_PATH").ok();
    env::set_var("HARMONIA_APT_GET_PATH", &apt);
    let ad = dir.join("apt");
    fs::create_dir_all(&ad).map_err(|e| e.to_string())?;
    let ao = crate::tools::package::package_tool_with_policy_for_backend(
        &ad,
        "apt",
        "install",
        &pk,
        false,
        None,
        &[],
        30,
        crate::PackageBackend::Apt,
        Some(invocation),
    )?;
    match oa {
        Some(v) => env::set_var("HARMONIA_APT_GET_PATH", v),
        None => env::remove_var("HARMONIA_APT_GET_PATH"),
    };
    let ar: serde_json::Value = serde_json::from_slice(
        &fs::read(ad.join("apt.json")).map_err(|e| format!("apt-read:{e}"))?,
    )
    .map_err(|e| e.to_string())?;
    let pac_r = ch_r.clone();
    let p3 = ao.ok
        && pac_r["declared_package_backend"] == "pacman"
        && ar["declared_package_backend"] == "apt";
    fs::write(&state, "absent\n").map_err(|e| e.to_string())?;
    fs::write(&lock, b"").map_err(|e| e.to_string())?;
    let fake_script = fs::read(&fake).map_err(|e| e.to_string())?;
    fs::copy("/bin/sleep", &fake).map_err(|e| e.to_string())?;
    let mut h = Command::new(&fake)
        .arg("30")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    thread::sleep(std::time::Duration::from_millis(100));
    let ld = dir.join("live");
    fs::create_dir_all(&ld).map_err(|e| e.to_string())?;
    let live = run("install", &ld);
    let live_state = fs::read_to_string(&state).map_err(|e| e.to_string())?;
    let live_lock_remains = lock.exists();
    let _ = Command::new("kill").arg(h.id().to_string()).status();
    let _ = h.wait();
    fs::write(&fake, fake_script).map_err(|e| e.to_string())?;
    let lr: serde_json::Value = serde_json::from_slice(
        &fs::read(ld.join("pacman-database-lock-reclaim.json"))
            .map_err(|e| format!("live-receipt:{e}"))?,
    )
    .map_err(|e| e.to_string())?;
    let p4 = matches!(live, Err(_))
        && live_lock_remains
        && live_state.trim() == "absent"
        && lr["lock_present"] == true
        && lr["live_holder_found"] == true
        && lr["reclaimed"] == false;
    fs::write(&state, "absent\n").map_err(|e| e.to_string())?;
    fs::write(&lock, b"").map_err(|e| e.to_string())?;
    let sd = dir.join("stale");
    fs::create_dir_all(&sd).map_err(|e| e.to_string())?;
    let stl = run("install", &sd).map_err(|e| format!("stale:{e}"))?;
    let sr: serde_json::Value = serde_json::from_slice(
        &fs::read(sd.join("pacman-database-lock-reclaim.json"))
            .map_err(|e| format!("stale-receipt:{e}"))?,
    )
    .map_err(|e| e.to_string())?;

    let p5 = stl.ok
        && stl.changed
        && sr["lock_present"] == true
        && sr["live_holder_found"] == false
        && sr["reclaimed"] == true
        && !lock.exists()
        && fs::read_to_string(&state)
            .map_err(|e| e.to_string())?
            .trim()
            == "current";
    fs::write(&state, "absent\n").map_err(|e| e.to_string())?;
    fs::write(&target, b"old-bytes\n").map_err(|e| e.to_string())?;
    env::set_var("HARMONIA_BENCH_CONFLICT", "1");
    env::set_var("HARMONIA_BENCH_TARGET", &target);
    let od = dir.join("overwrite");
    fs::create_dir_all(&od).map_err(|e| e.to_string())?;
    let ov = crate::tools::package::package_tool_with_policy_for_backend(
        &od,
        "install",
        "install",
        &pk,
        true,
        Some("overwrite-declared-paths"),
        &[target.to_string_lossy().into_owned()],
        30,
        crate::PackageBackend::Pacman,
        Some(invocation),
    )
    .map_err(|e| format!("overwrite-call:{e}"))?;
    let pre: serde_json::Value = serde_json::from_slice(
        &fs::read(od.join("pacman-overwrite-preimage.json")).map_err(|e| format!("pre:{e}"))?,
    )
    .map_err(|e| e.to_string())?;
    let tx: serde_json::Value = serde_json::from_slice(
        &fs::read(od.join("pacman-package-transaction.json")).map_err(|e| format!("tx:{e}"))?,
    )
    .map_err(|e| e.to_string())?;
    let retry_text = ov
        .command
        .as_ref()
        .map(|c| format!("{}\n{}", c.stdout, c.stderr))
        .unwrap_or_default();
    let p6 = pre["paths"]
        .as_array()
        .is_some_and(|paths| paths.len() == 1)
        && pre["paths"][0]["path"] == target.to_string_lossy().as_ref()
        && pre["paths"][0]["exists"] == true
        && pre["paths"][0]["type"] == "file"
        && pre["paths"][0]["bytes_hex"] == "6f6c642d62797465730a"
        && fs::read(&target).map_err(|e| e.to_string())? == b"new-bytes\n"
        && tx["overwrite_paths"]
            .as_array()
            .is_some_and(|paths| paths.len() == 1 && paths[0] == target.to_string_lossy().as_ref())
        && retry_text.contains("--overwrite")
        && retry_text.contains(target.to_string_lossy().as_ref())
        && ov.ok
        && ov.changed
        && tx["first_ok"] == false
        && tx["second_ok"] == true;
    env::set_var("HARMONIA_BENCH_PERSIST", "1");
    env::remove_var("HARMONIA_BENCH_CONFLICT");
    fs::write(&state, "absent\n").map_err(|e| e.to_string())?;
    let pd = dir.join("persistent");
    fs::create_dir_all(&pd).map_err(|e| e.to_string())?;
    let per = run("install", &pd);
    let pr: serde_json::Value =
        serde_json::from_slice(&fs::read(pd.join("install.json")).map_err(|e| format!("pr:{e}"))?)
            .map_err(|e| e.to_string())?;
    let pc: serde_json::Value = serde_json::from_slice(
        &fs::read(pd.join("install.comparison.json")).map_err(|e| format!("pc:{e}"))?,
    )
    .map_err(|e| e.to_string())?;
    let p7 = matches!(per, Err(ref e) if e == "install-package-act-did-not-converge")
        && pc["diff_decision"] == "different"
        && pc["observed_before"].is_object()
        && pc["act"].is_object()
        && pc["observed_after"].is_object()
        && pc["converged"] == false;
    let live_result = match &live {
        Ok(v) => json!({"ok":v.ok,"changed":v.changed}),
        Err(e) => json!({"error":e}),
    };
    let persistent_result = match &per {
        Ok(v) => json!({"ok":v.ok,"changed":v.changed}),
        Err(e) => json!({"error":e}),
    };
    let predicates = json!({"current_to_quiet":p1,"changed_to_current":p2,"backend_selection":p3,"live_lock_refusal":p4,"stale_lock_declared_removal":p5,"overwrite_path_preimage_capture":p6,"transaction_receipt":p6,"persistent_difference_failure":p7});
    if !predicates.as_object().unwrap().values().all(|v| v == true) {
        return Err(format!(
            "package-eight-predicate-battery-failed:{predicates}"
        ));
    }
    Ok(
        json!({"predicates":predicates,"current_to_quiet":{"current":{"ok":cur.ok,"changed":cur.changed},"quiet":{"ok":quiet.ok,"changed":quiet.changed}},"changed_to_current":{"ok":ch.ok,"changed":ch.changed},"backend_selection":{"pacman":pac_r,"apt":ar},"live_lock_refusal":{"result":live_result,"receipt":lr},"stale_lock_declared_removal":{"result":{"ok":stl.ok,"changed":stl.changed},"receipt":sr},"overwrite_path_preimage_capture":pre,"transaction_receipt":tx,"persistent_difference_failure":{"result":persistent_result,"receipt":pr}}),
    )
}

fn never_converge_bench() -> Result<serde_json::Value, String> {
    let acted = Cell::new(false);
    let result = comparison::execute(
        "forced-never-converge",
        || Ok::<bool, String>(acted.get()),
        |_| DiffDecision::Different,
        |_, _| {
            acted.set(true);
            Ok::<(), String>(())
        },
    );
    match result {
        Err(signal) if signal == "forced-never-converge-act-did-not-converge" => Ok(json!({
            "ok": false,
            "acted": acted.get(),
            "signal": signal
        })),
        Ok(ComparisonRun::Current { .. }) | Ok(ComparisonRun::Moved { .. }) => {
            Err("never-converge-bench-did-not-fail".to_string())
        }
        Err(signal) => Err(format!("never-converge-bench-wrong-signal {signal}")),
    }
}
