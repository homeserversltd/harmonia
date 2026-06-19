use crate::*;
use serde_json::json;
use std::fs::{self, File};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

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

    if installer.ok {
        reconcile_keyman_vault_layout(vault_dir)?;
        install_gui_pin_helpers()?;
    }

    let installed_shape = keyman_install_shape(runtime_dir, vault_dir, key_dir, exchange_dir);
    let ok = installer.ok
        && installed_shape.0
        && installed_shape.1["gui_pin_helpers_present"]
            .as_bool()
            .unwrap_or(false);
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
    let gui_pin_helpers_present = [
        "/usr/local/sbin/homeconsole-gui-pin-lib",
        "/usr/local/sbin/homeconsole-gui-pin-verify",
        "/usr/local/sbin/homeconsole-gui-pin-access",
        "/usr/local/sbin/homeconsole-gui-pin-change",
        "/usr/local/sbin/homeconsole-gui-pin-reset-default",
    ]
    .iter()
    .all(|path| Path::new(path).is_file());
    let shape = json!({
        "runtime_dir_present": runtime_dir.is_dir(),
        "exportkey_present": export.is_file(),
        "vault_keys_dir_present": keys.is_dir(),
        "skeleton_key_present": skeleton.is_file(),
        "service_suite_key_present": service_suite.is_file(),
        "exchange_dir_present": exchange_dir.exists(),
        "gui_pin_helpers_present": gui_pin_helpers_present,
        "secret_material": "[REDACTED]",
    });
    let ok = runtime_dir.is_dir()
        && export.is_file()
        && keys.is_dir()
        && skeleton.is_file()
        && service_suite.is_file()
        && gui_pin_helpers_present;
    (ok, shape)
}

pub(crate) fn reconcile_keyman_vault_layout(vault_dir: &Path) -> Result<(), String> {
    let keys_dir = vault_dir.join(".keys");
    fs::create_dir_all(&keys_dir).map_err(|e| format!("create-vault-keys-dir-failed: {e}"))?;
    for name in ["service_suite.key", "nas.key"] {
        let legacy = vault_dir.join(name);
        let canonical = keys_dir.join(name);
        if legacy.is_file() && !canonical.exists() {
            fs::rename(&legacy, &canonical).map_err(|e| {
                format!(
                    "keyman-vault-layout-reconcile-failed {} -> {}: {e}",
                    legacy.display(),
                    canonical.display()
                )
            })?;
        }
    }
    Ok(())
}

pub(crate) fn install_gui_pin_helpers() -> Result<(), String> {
    fs::create_dir_all("/usr/local/sbin").map_err(|e| e.to_string())?;
    fs::create_dir_all("/var/lib/homeconsole").map_err(|e| e.to_string())?;
    write_executable("/usr/local/sbin/homeconsole-gui-pin-lib", GUI_PIN_LIB)?;
    write_executable("/usr/local/sbin/homeconsole-gui-pin-verify", GUI_PIN_VERIFY)?;
    write_executable("/usr/local/sbin/homeconsole-gui-pin-access", GUI_PIN_ACCESS)?;
    write_executable("/usr/local/sbin/homeconsole-gui-pin-change", GUI_PIN_CHANGE)?;
    write_executable(
        "/usr/local/sbin/homeconsole-gui-pin-reset-default",
        GUI_PIN_RESET_DEFAULT,
    )?;
    let state = PathBuf::from("/var/lib/homeconsole/gui-pin-access.json");
    if !state.exists() {
        fs::write(&state, "{\"pin_required\":false}\n").map_err(|e| e.to_string())?;
        set_private_file_permissions(&state)?;
    }
    Ok(())
}

fn write_executable(path: &str, content: &str) -> Result<(), String> {
    let path = Path::new(path);
    fs::write(path, content).map_err(|e| format!("write-helper-failed {}: {e}", path.display()))?;
    set_executable_permissions(path)
}

#[cfg(unix)]
fn set_executable_permissions(path: &Path) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn set_executable_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

const GUI_PIN_LIB: &str = r#"#!/usr/bin/env bash
set -euo pipefail
SERVICE="homeconsole_gui_pin"
STATE="/var/lib/homeconsole/gui-pin-access.json"
KEY_FILE="/vault/.keys/${SERVICE}.key"
KEYMAN_NEW="/vault/keyman/newkey.sh"
KEYMAN_EXPORT="/vault/keyman/exportkey.sh"
EXCHANGE="/mnt/keyexchange/${SERVICE}"
DEFAULT_PIN_FILE="/etc/homeconsole/default-gui-pin"

ensure_keyman() {
  test -x "$KEYMAN_NEW"
  test -x "$KEYMAN_EXPORT"
  test -d /vault/.keys
  test -f /vault/.keys/service_suite.key
  test -f /root/key/skeleton.key
}

cleanup() {
  if test -f /vault/keyman/utils.sh; then
    bash -lc "source /vault/keyman/utils.sh; secure_cleanup" >/dev/null 2>&1 || true
  else
    rm -f "$EXCHANGE" 2>/dev/null || true
  fi
}

read_pin() {
  ensure_keyman
  test -f "$KEY_FILE"
  "$KEYMAN_EXPORT" "$SERVICE" >/dev/null 2>&1
  trap cleanup EXIT
  test -f "$EXCHANGE"
  local value
  value=$(grep -E '^password=' "$EXCHANGE" | head -n1)
  value="${value#password=}"
  value="${value%\"}"
  value="${value#\"}"
  test -n "$value"
  printf '%s' "$value"
}

store_pin() {
  ensure_keyman
  local pin="$1"
  test -n "$pin"
  "$KEYMAN_NEW" "$SERVICE" gui_pin "$pin" >/dev/null 2>&1
  cleanup
}

set_required() {
  local required="$1"
  install -d -m 700 "$(dirname "$STATE")"
  if [[ "$required" == "required" || "$required" == "true" ]]; then
    test -f "$KEY_FILE"
    printf '{"pin_required":true}\n' > "$STATE"
  else
    printf '{"pin_required":false}\n' > "$STATE"
  fi
  chmod 600 "$STATE"
}
"#;

const GUI_PIN_VERIFY: &str = r#"#!/usr/bin/env bash
set -euo pipefail
source /usr/local/sbin/homeconsole-gui-pin-lib
IFS= read -r submitted
stored=$(read_pin)
[[ "$submitted" == "$stored" ]]
"#;

const GUI_PIN_ACCESS: &str = r#"#!/usr/bin/env bash
set -euo pipefail
source /usr/local/sbin/homeconsole-gui-pin-lib
IFS= read -r mode
set_required "$mode"
"#;

const GUI_PIN_CHANGE: &str = r#"#!/usr/bin/env bash
set -euo pipefail
source /usr/local/sbin/homeconsole-gui-pin-lib
IFS= read -r current
IFS= read -r next
if test -f "$KEY_FILE"; then
  stored=$(read_pin)
  [[ "$current" == "$stored" ]]
fi
store_pin "$next"
"#;

const GUI_PIN_RESET_DEFAULT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
source /usr/local/sbin/homeconsole-gui-pin-lib
test -f "$DEFAULT_PIN_FILE"
default_pin=$(head -n1 "$DEFAULT_PIN_FILE")
test -n "$default_pin"
store_pin "$default_pin"
"#;

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
