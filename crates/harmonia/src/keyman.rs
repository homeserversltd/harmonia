use crate::*;
use serde_json::json;
use std::fs::{self, File};
use std::path::Path;

pub(crate) fn homeconsole_keyman_update(
    profile: &Profile,
    receipt_dir: &Path,
    source: &Path,
    store_dir: &Path,
    runtime_dir: &Path,
    vault_dir: &Path,
    key_dir: &Path,
    exchange_dir: &Path,
    apply: bool,
) -> Result<(), String> {
    if profile.id != "homeconsole" || profile.family != "arch-console" {
        return Err(format!(
            "homeconsole-keyman-update requires homeconsole/arch-console profile, got {}/{}",
            profile.id, profile.family
        ));
    }
    fs::create_dir_all(receipt_dir).map_err(|e| e.to_string())?;
    let mut events = File::create(receipt_dir.join("events.jsonl")).map_err(|e| e.to_string())?;
    event(
        &mut events,
        "run-start",
        true,
        "homeconsole keyman update started",
    )?;

    let source_shape = keyman_source_shape(source);
    let source_ok = source_shape.0;
    if !source_ok {
        write_keyman_update_receipt(
            receipt_dir,
            profile,
            apply,
            false,
            false,
            "keyman-source-incomplete",
            source,
            store_dir,
            runtime_dir,
            vault_dir,
            key_dir,
            exchange_dir,
            &source_shape.1,
            None,
        )?;
        println!("schema=harmonia.homeconsole_keyman_update.v1");
        println!("ok=false");
        println!("first_missing_signal=keyman-source-incomplete");
        println!("receipt_dir={}", receipt_dir.display());
        return Err("keyman-source-incomplete".into());
    }

    if !apply {
        event(
            &mut events,
            "plan",
            true,
            "keyman source/runtime update planned",
        )?;
        write_keyman_update_receipt(
            receipt_dir,
            profile,
            false,
            true,
            false,
            "none",
            source,
            store_dir,
            runtime_dir,
            vault_dir,
            key_dir,
            exchange_dir,
            &source_shape.1,
            None,
        )?;
        println!("schema=harmonia.homeconsole_keyman_update.v1");
        println!("ok=true");
        println!("mutation=false");
        println!("first_missing_signal=none");
        println!("receipt_dir={}", receipt_dir.display());
        return Ok(());
    }

    event(
        &mut events,
        "store-start",
        true,
        "copying keyman source to local store",
    )?;
    let changed = sync_directory(source, store_dir)?;
    event(
        &mut events,
        "store-complete",
        true,
        "keyman source stored locally",
    )?;

    let installer_receipt = receipt_dir.join("keyman-installer.json");
    let store_index = store_dir.join("index.py");
    let runtime_s = runtime_dir.to_string_lossy().to_string();
    let vault_s = vault_dir.to_string_lossy().to_string();
    let key_s = key_dir.to_string_lossy().to_string();
    let exchange_s = exchange_dir.to_string_lossy().to_string();
    let receipt_s = installer_receipt.to_string_lossy().to_string();
    let install_args = [
        store_index.to_string_lossy().to_string(),
        "install".to_string(),
        "--profile".to_string(),
        "vault-only".to_string(),
        "--source-dir".to_string(),
        store_dir.to_string_lossy().to_string(),
        "--runtime-dir".to_string(),
        runtime_s,
        "--vault-dir".to_string(),
        vault_s,
        "--key-dir".to_string(),
        key_s,
        "--exchange-dir".to_string(),
        exchange_s,
        "--receipt".to_string(),
        receipt_s,
    ];
    let install_refs: Vec<&str> = install_args.iter().map(String::as_str).collect();
    let installer = command_capture_redacted("/usr/bin/python3", &install_refs);
    write_command_receipt(receipt_dir, "keyman-install", &installer)?;
    event(
        &mut events,
        "installer-complete",
        installer.ok,
        "keyman installer completed with redacted output",
    )?;

    let installed_shape = keyman_install_shape(runtime_dir, vault_dir, key_dir, exchange_dir);
    let ok = installer.ok && installed_shape.0;
    let first_missing_signal = if ok {
        "none"
    } else if !installer.ok {
        "keyman-installer-failed"
    } else {
        "keyman-install-shape-incomplete"
    };
    write_keyman_update_receipt(
        receipt_dir,
        profile,
        true,
        ok,
        changed || installer.ok,
        first_missing_signal,
        source,
        store_dir,
        runtime_dir,
        vault_dir,
        key_dir,
        exchange_dir,
        &installed_shape.1,
        Some(&installer),
    )?;
    println!("schema=harmonia.homeconsole_keyman_update.v1");
    println!("ok={}", ok);
    println!("mutation=true");
    println!("changed={}", changed || installer.ok);
    println!("first_missing_signal={}", first_missing_signal);
    println!("receipt_dir={}", receipt_dir.display());
    if ok {
        Ok(())
    } else {
        Err(first_missing_signal.into())
    }
}

pub(crate) fn keyman_source_shape(source: &Path) -> (bool, serde_json::Value) {
    let index_py = source.join("index.py");
    let installer = source.join("lib/keyman_installer/index.py");
    let startup = source.join("keystartup.sh");
    let export = source.join("exportkey.sh");
    let shape = json!({
        "source_exists": source.is_dir(),
        "index_py_present": index_py.is_file(),
        "installer_present": installer.is_file(),
        "keystartup_present": startup.is_file(),
        "exportkey_present": export.is_file(),
    });
    let ok = source.is_dir()
        && index_py.is_file()
        && installer.is_file()
        && startup.is_file()
        && export.is_file();
    (ok, shape)
}

pub(crate) fn keyman_install_shape(
    runtime_dir: &Path,
    vault_dir: &Path,
    key_dir: &Path,
    exchange_dir: &Path,
) -> (bool, serde_json::Value) {
    let export = runtime_dir.join("exportkey.sh");
    let keys = vault_dir.join(".keys");
    let skeleton = key_dir.join("skeleton.key");
    let service_suite = keys.join("service_suite.key");
    let shape = json!({
        "runtime_dir_present": runtime_dir.is_dir(),
        "exportkey_present": export.is_file(),
        "vault_keys_dir_present": keys.is_dir(),
        "skeleton_key_present": skeleton.is_file(),
        "service_suite_key_present": service_suite.is_file(),
        "exchange_dir_present": exchange_dir.exists(),
        "secret_material": "[REDACTED]",
    });
    let ok = runtime_dir.is_dir()
        && export.is_file()
        && keys.is_dir()
        && skeleton.is_file()
        && service_suite.is_file();
    (ok, shape)
}

pub(crate) fn write_keyman_update_receipt(
    receipt_dir: &Path,
    profile: &Profile,
    apply: bool,
    ok: bool,
    changed: bool,
    first_missing_signal: &str,
    source: &Path,
    store_dir: &Path,
    runtime_dir: &Path,
    vault_dir: &Path,
    key_dir: &Path,
    exchange_dir: &Path,
    shape: &serde_json::Value,
    installer: Option<&CmdResult>,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join("run.json"),
        &json!({
            "schema": "harmonia.homeconsole_keyman_update.v1",
            "ok": ok,
            "changed": changed,
            "mutation": apply,
            "profile_id": profile.id,
            "profile_family": profile.family,
            "first_missing_signal": first_missing_signal,
            "source": source,
            "store_dir": store_dir,
            "runtime_dir": runtime_dir,
            "vault_dir": vault_dir,
            "key_dir": key_dir,
            "exchange_dir": exchange_dir,
            "shape": shape,
            "installer": installer.map(|cmd| json!({
                "ok": cmd.ok,
                "exit_code": cmd.code,
                "stdout": cmd.stdout,
                "stderr": cmd.stderr,
            })),
            "secret_material": "[REDACTED]",
        }),
    )
}

pub(crate) fn sync_directory(source: &Path, dest: &Path) -> Result<bool, String> {
    if !source.is_dir() {
        return Err(format!("source-not-directory {}", source.display()));
    }
    let before = directory_fingerprint(dest)?;
    if dest.exists() {
        fs::remove_dir_all(dest)
            .map_err(|e| format!("store-clean-failed {}: {e}", dest.display()))?;
    }
    fs::create_dir_all(dest).map_err(|e| format!("store-create-failed {}: {e}", dest.display()))?;
    copy_dir_contents(source, dest)?;
    let after = directory_fingerprint(dest)?;
    Ok(before != after)
}

pub(crate) fn copy_dir_contents(source: &Path, dest: &Path) -> Result<(), String> {
    for entry in
        fs::read_dir(source).map_err(|e| format!("read-dir-failed {}: {e}", source.display()))?
    {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name_s = name.to_string_lossy();
        if matches!(name_s.as_ref(), ".git" | "__pycache__" | ".pytest_cache") {
            continue;
        }
        let src = entry.path();
        let dst = dest.join(&name);
        let meta = entry.metadata().map_err(|e| e.to_string())?;
        if meta.is_dir() {
            fs::create_dir_all(&dst).map_err(|e| e.to_string())?;
            copy_dir_contents(&src, &dst)?;
        } else if meta.is_file() {
            fs::copy(&src, &dst)
                .map_err(|e| format!("copy-failed {} -> {}: {e}", src.display(), dst.display()))?;
            fs::set_permissions(&dst, meta.permissions()).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

pub(crate) fn directory_fingerprint(path: &Path) -> Result<String, String> {
    if !path.exists() {
        return Ok("absent".into());
    }
    let mut rows = Vec::new();
    collect_fingerprint(path, path, &mut rows)?;
    rows.sort();
    Ok(rows.join("\n"))
}

pub(crate) fn collect_fingerprint(
    root: &Path,
    path: &Path,
    rows: &mut Vec<String>,
) -> Result<(), String> {
    for entry in
        fs::read_dir(path).map_err(|e| format!("read-dir-failed {}: {e}", path.display()))?
    {
        let entry = entry.map_err(|e| e.to_string())?;
        let p = entry.path();
        let rel = p.strip_prefix(root).unwrap_or(&p).display().to_string();
        let meta = entry.metadata().map_err(|e| e.to_string())?;
        if meta.is_dir() {
            rows.push(format!("dir:{rel}"));
            collect_fingerprint(root, &p, rows)?;
        } else if meta.is_file() {
            rows.push(format!("file:{rel}:{}", meta.len()));
        }
    }
    Ok(())
}

pub(crate) fn command_capture_redacted(program: &str, args: &[&str]) -> CmdResult {
    let mut result = command_capture(program, args);
    result.stdout = redact_secret_text(&result.stdout);
    result.stderr = redact_secret_text(&result.stderr);
    result
}

pub(crate) fn redact_secret_text(text: &str) -> String {
    text.lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if [
                "password",
                "secret",
                "mnemonic",
                "private",
                "token",
                "key=",
                "username=",
            ]
            .iter()
            .any(|needle| lower.contains(needle))
            {
                "[REDACTED]".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
