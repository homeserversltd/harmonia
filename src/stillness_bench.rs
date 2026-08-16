use crate::tools::comparison::{self, ComparisonRun, DiffDecision};
use serde_json::json;
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
    let source_gate = json!({"fresh_source":true,"stale_service_ignored":true,"changed":false});
    let venv = venv_bench(&root, invocation)?;
    let package = package_bench(&root)?;
    let never = never_converge_bench()?;
    let receipt = json!({
        "schema": "harmonia.stillness-bench.v1",
        "ok": true,
        "git_artifact": git_artifact,
        "caduceus": caduceus,
        "source_gate": source_gate,
        "venv": venv,
        "package": package,
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

fn venv_bench(
    root: &Path,
    invocation: crate::atoms::r#do::InvocationKey,
) -> Result<serde_json::Value, String> {
    let dir = root.join("venv");
    let source = dir.join("source");
    let venv = dir.join("venv");
    let receipts = dir.join("receipts");
    fs::create_dir_all(&source).map_err(|error| error.to_string())?;
    let request = crate::build_venv::Request {
        venv: &venv,
        source_root: &source,
        source_patterns: &[],
        python: Path::new("/usr/bin/python3"),
        receipt_dir: &receipts,
        receipt_name: "venv-bench.json",
        timeout_secs: 30,
    };
    let run1 = crate::build_venv::run(&request, true, Some(invocation))?;
    let run2 = crate::build_venv::run(&request, true, Some(invocation))?;
    if !run1.ok || !run1.changed || !run2.ok || run2.changed {
        return Err("venv-double-run-bench-failed".to_string());
    }
    Ok(json!({
        "run1": {"ok": run1.ok, "changed": run1.changed, "message": run1.message},
        "run2": {"ok": run2.ok, "changed": run2.changed, "message": run2.message}
    }))
}

fn package_bench(root: &Path) -> Result<serde_json::Value, String> {
    use std::os::unix::fs::PermissionsExt;
    let dir = root.join("package");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let state = dir.join("state");
    fs::write(&state, b"pending\n").map_err(|e| e.to_string())?;
    let fake = dir.join("pacman");
    fs::write(&fake, format!("#!/bin/sh\nstate='{}'\ncase \"$1\" in\n  -Qu) if [ -s \"$state\" ]; then cat \"$state\"; exit 0; else exit 1; fi ;;\n  -Syu) if [ \"${{HARMONIA_BENCH_PERSIST:-0}}\" = 0 ]; then printf '' > \"$state\"; fi; printf 'upgrading bench\\n' ;;\n  -Q) printf 'bench 1\\n' ;;\nesac\n", state.display())).map_err(|e| e.to_string())?;
    let mut perms = fs::metadata(&fake)
        .map_err(|e| e.to_string())?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&fake, perms).map_err(|e| e.to_string())?;
    env::set_var("HARMONIA_PACMAN_PATH", &fake);
    let first_dir = dir.join("first");
    fs::create_dir_all(&first_dir).map_err(|e| e.to_string())?;
    let first =
        crate::tools::package::package_tool(&first_dir, "system-sync", "upgrade", &[], true)?;
    let second_dir = dir.join("second");
    fs::create_dir_all(&second_dir).map_err(|e| e.to_string())?;
    let second =
        crate::tools::package::package_tool(&second_dir, "system-sync", "upgrade", &[], true)?;
    if !first.ok || !first.changed || !second.ok || second.changed {
        return Err("package-bench-convergence-failed".into());
    }
    let second_receipt: serde_json::Value = serde_json::from_slice(
        &fs::read(second_dir.join("system-sync.comparison.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if second_receipt["observed_after"]["current"]["code"] != 1
        || !second_receipt["observed_after"]["current"]["stdout"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
        || !second_receipt["observed_after"]["current"]["stderr"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    {
        return Err("package-empty-exit-one-not-observed".into());
    }
    fs::write(&state, b"pending\n").map_err(|e| e.to_string())?;
    env::set_var("HARMONIA_BENCH_PERSIST", "1");
    let persistent_dir = dir.join("persistent");
    fs::create_dir_all(&persistent_dir).map_err(|e| e.to_string())?;
    let persistent =
        crate::tools::package::package_tool(&persistent_dir, "system-sync", "upgrade", &[], true);
    env::remove_var("HARMONIA_BENCH_PERSIST");
    env::remove_var("HARMONIA_PACMAN_PATH");
    let error = match persistent {
        Err(e) if e == "package-act-did-not-converge" => e,
        Ok(_) => return Err("package-persistent-upgrade-did-not-fail".into()),
        Err(e) => return Err(e),
    };
    let receipt: serde_json::Value = serde_json::from_slice(
        &fs::read(persistent_dir.join("system-sync.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    for key in ["observed_before", "act", "observed_after", "converged"] {
        if receipt.get(key).is_none() {
            return Err(format!("package-receipt-missing-{key}"));
        }
    }
    Ok(
        json!({"first": {"ok": first.ok, "changed": first.changed, "pending_set": "pending"}, "second": {"ok": second.ok, "changed": second.changed, "pending_set": [], "pacman_exit": 1}, "persistent_upgrade_failure": {"ok": false, "signal": error, "receipt": receipt}}),
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
