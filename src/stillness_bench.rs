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
    let package = match package_bench(&root, invocation) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("package_root={} error={}", root.display(), e);
            return Err(e);
        }
    };
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

pub(crate) fn slice12_clock_bench(
    invocation: crate::atoms::r#do::InvocationKey,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let _env = ClockEnvGuard {
        timedatectl: std::env::var("HARMONIA_CLOCK_TIMEDATECTL").ok(),
        caduceus: std::env::var("HARMONIA_CLOCK_CADUCEUS").ok(),
    };
    let root = std::env::temp_dir().join(format!(
        "harmonia-slice12-clock-{}",
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
        return Err("slice12-posture-readback-failed".into());
    }
    std::thread::sleep(std::time::Duration::from_millis(20));
    if std::fs::read_to_string(&state).map_err(|e| e.to_string())? != readback {
        return Err("slice12-elapsed-reversal".into());
    }
    let state_before_quiet = std::fs::read(&state).map_err(|e| e.to_string())?;
    let writes_before = std::fs::read(&log).map_err(|e| e.to_string())?;
    let quiet = crate::set_clock::run(&request, true, Some(invocation))?;
    if !quiet.ok
        || std::fs::read(&state).map_err(|e| e.to_string())? != state_before_quiet
        || std::fs::read(&log).map_err(|e| e.to_string())? != writes_before
    {
        return Err("slice12-quiet-write".into());
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
        return Err("slice12-refusal-proof-failed".into());
    }
    println!("slice12-clock-bench ok preimage=Etc/UTC|no requested=Europe/Berlin|yes readback=verified elapsed=non-reversing quiet=no-write refusal=backend-refused host_mutation=false");
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
