//! Release and source observations for the trace-free update check.
use crate::tools::ladder::{LadderManifest, ValidatedStep};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::io::{Read, Write};

use std::process::{Command, Stdio};

thread_local! {
    // Query-local output, drained into the one answer before it is emitted.
    static NEWER: RefCell<Vec<Value>> = const { RefCell::new(Vec::new()) };
}

pub(crate) fn take_newer() -> Vec<Value> {
    NEWER.with(|rows| std::mem::take(&mut *rows.borrow_mut()))
}

fn record(surface: &str, worn: &str, newest: &str) {
    NEWER.with(|rows| rows.borrow_mut().push(json!({"surface":surface,"worn":worn,"newest":newest})));
}

fn get(url: &str, limit: usize) -> Result<Vec<u8>, String> {
    if !url.starts_with("https://git.home.arpa/") {
        return Err("update-check-release-url-invalid".into());
    }
    let token = match crate::atoms::forge_credential::resolve_for_url(url) {
        crate::atoms::forge_credential::Outcome::Present { token, .. } => Some(token),
        crate::atoms::forge_credential::Outcome::Absent => None,
        crate::atoms::forge_credential::Outcome::Err(_) => return Err("update-check-release-credential-unavailable".into()),
    };
    let mut command = Command::new("/usr/bin/curl");
    command.args(["--disable", "--silent", "--fail", "--connect-timeout", "5", "--max-time", "15", "--proto", "=https"])
        .stdout(Stdio::piped()).stderr(Stdio::null());
    if token.is_some() { command.args(["--config", "-"]).stdin(Stdio::piped()); }
    else { command.stdin(Stdio::null()); }
    let mut child = command.arg(url).spawn().map_err(|_| "update-check-release-unreachable")?;
    if let Some(token) = token {
        if token.contains(['\r', '\n']) {
            let _ = child.kill(); let _ = child.wait();
            return Err("update-check-release-credential-invalid".into());
        }
        let escaped = token.replace('\\', "\\\\").replace('"', "\\\"");
        let sent = child.stdin.take().ok_or("update-check-release-unreachable")?
            .write_all(format!("header = \"Authorization: token {escaped}\"\n").as_bytes());
        if sent.is_err() { let _ = child.kill(); let _ = child.wait(); return Err("update-check-release-unreachable".into()); }
    }
    let mut body = Vec::new();
    let read = child.stdout.take().ok_or("update-check-release-unreachable")?
        .take((limit + 1) as u64).read_to_end(&mut body);
    if read.is_err() || body.len() > limit {
        let _ = child.kill(); let _ = child.wait();
        return Err("update-check-release-output-unavailable".into());
    }
    if !child.wait().map_err(|_| "update-check-release-unreachable")?.success() {
        return Err("update-check-release-unreachable".into());
    }
    Ok(body)
}

fn valid_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn binary(step: &ValidatedStep, surface: &str) -> Result<bool, String> {
    let component = step.args.get("component").and_then(Value::as_str).filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')).ok_or("update-check-release-component-invalid")?;
    let target = step.args.get("installed_binary").or_else(|| step.args.get("path"))
        .and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or("update-check-release-target-missing")?;
    let mut file = std::fs::File::open(target).map_err(|_| "update-check-release-target-unavailable")?;
    if !file.metadata().map_err(|_| "update-check-release-target-unavailable")?.is_file() { return Err("update-check-release-target-unavailable".into()); }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop { let n = file.read(&mut buffer).map_err(|_| "update-check-release-target-unavailable")?; if n == 0 { break; } hash.update(&buffer[..n]); }
    let installed = format!("{:x}", hash.finalize());
    let schema_base = crate::atoms::ask::caduceus_door::base_url()
        .map_err(|_| "update-check-release-schema-unavailable")?;
    let seat = crate::atoms::ask::mint_seats::Seat::load(crate::atoms::ask::mint_seats::RELEASE_FLAG, schema_base)
        .map_err(|_| "update-check-release-schema-unavailable")?;
    let mut flags: Vec<(String, String, String)> = Vec::new();
    let mut complete = false;
    for page in 1..=5 {
        let url = format!("https://git.home.arpa/api/v1/repos/HOMESERVERSLTD/{component}/releases?limit=50&page={page}");
        let rows: Vec<Value> = serde_json::from_slice(&get(&url, 4 * 1024 * 1024)?).map_err(|_| "update-check-release-list-invalid")?;
        let count = rows.len();
        for release in rows {
            if release.get("draft").and_then(Value::as_bool) == Some(true) { continue; }
            let Some(target_sha) = release.get("target_commitish").and_then(Value::as_str).filter(|s| valid_hex(s, 40)) else { continue; };
            let Some(assets) = release.get("assets").and_then(Value::as_array) else { continue; };
            for asset in assets.iter().filter(|a| a.get("name").and_then(Value::as_str) == Some("release.flag")) {
                let url = asset.get("browser_download_url").and_then(Value::as_str).ok_or("update-check-release-flag-invalid")?;
                let flag: Value = serde_json::from_slice(&get(url, 65536)?).map_err(|_| "update-check-release-flag-invalid")?;
                if crate::atoms::ask::member_flag::validate(&flag, target_sha, component, &seat).is_err() { continue; }
                let digest = flag.get("sha256").and_then(Value::as_str).filter(|s| valid_hex(s, 64)).ok_or("update-check-release-digest-unavailable")?;
                let time = flag.get("flagged_at").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or("update-check-release-time-unavailable")?;
                flags.push((time.to_owned(), target_sha.to_owned(), digest.to_owned()));
            }
        }
        if count < 50 { complete = true; break; }
    }
    if !complete { return Err("update-check-release-list-incomplete".into()); }
    flags.sort_by(|a, b| b.0.cmp(&a.0));
    let newest = flags.first().ok_or("update-check-release-flag-unavailable")?;
    if newest.2 == installed { return Ok(false); }
    let worn = flags.iter().find(|flag| flag.2 == installed).map(|flag| flag.1.as_str()).unwrap_or("unknown-build");
    record(surface, worn, &newest.1);
    Ok(true)
}

pub(crate) fn source(step: &ValidatedStep, manifest: &LadderManifest, surface: &str) -> Result<bool, String> {
    let plan = crate::bands::pull_source::routine_source_plan(step, manifest)?;
    if !plan.destination.join(".git").exists() { return Err("update-check-checkout-unavailable".into()); }
    let candidate = plan.candidates.iter().find(|c| c.kind == crate::atoms::git_artifact::SourceCandidateKind::Git).ok_or("update-check-source-remote-unavailable")?;
    let request = crate::atoms::git_artifact::scoped_request(&plan, candidate, plan.destination.clone());
    let cwd = plan.destination.to_str().ok_or("update-check-checkout-unavailable")?;
    let read = |args: &[&str], dir: Option<&str>| crate::atoms::ask::pull_repo::git_observe(&request, args, dir);
    let status = read(&["--no-optional-locks", "status", "--porcelain", "--untracked-files=all"], Some(cwd));
    if !status.ok || !status.stdout.is_empty() { return Err("update-check-checkout-dirty-or-unavailable".into()); }
    let head = read(&["--no-optional-locks", "rev-parse", "HEAD^{commit}"], Some(cwd));
    let worn = head.stdout.trim();
    if !head.ok || !valid_hex(worn, 40) { return Err("update-check-checkout-head-unavailable".into()); }
    // The acquisition plan may replace the declared branch with a stamped
    // commit.  A stamp is not a remote ref and cannot answer its current tip.
    let component = step.args.get("component").and_then(Value::as_str).ok_or("update-check-source-component-missing")?;
    let config: Value = serde_json::from_slice(&std::fs::read(crate::bands::pull_source::appliance_config_path())
        .map_err(|_| "update-check-source-config-unavailable")?)
        .map_err(|_| "update-check-source-config-invalid")?;
    let configured = config.get("sources").and_then(|v| v.get(component))
        .and_then(|v| v.get("ref")).and_then(Value::as_str)
        .map(str::trim).filter(|s| !s.is_empty()).ok_or("update-check-source-ref-unavailable")?;
    let branch = if plan.source_policy == "developer" { "main" } else { configured };
    if valid_hex(branch, 40) { return Err("update-check-source-ref-not-branch".into()); }
    let reference = if branch.starts_with("refs/") { branch.to_owned() } else { format!("refs/heads/{branch}") };
    let remote = read(&["--no-optional-locks", "ls-remote", "--refs", &candidate.locator, &reference], None);
    let newest = remote.stdout.lines().find_map(|line| line.split_once('\t').filter(|(_, name)| *name == reference).map(|(sha, _)| sha)).filter(|s| valid_hex(s, 40)).ok_or("update-check-source-tip-unavailable")?;
    if !remote.ok { return Err("update-check-source-tip-unavailable".into()); }
    if worn == newest { return Ok(false); }
    record(surface, worn, newest);
    Ok(true)
}
