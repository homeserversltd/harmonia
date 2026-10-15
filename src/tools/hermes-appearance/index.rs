use crate::bands::propose_edits::{persist_feed_with_intent, FeedPersistenceIntent};
use crate::interactables::{DriftSummary, Interactable, InteractablesFeed};
use crate::tools::ladder::{LadderManifest, ValidatedStep};
use crate::OperationOutcome;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MODULE_ID: &str = "hermes-appearance";
const KIND: &str = "hermes-appearance";
const SKIN_NAME: &str = "homeserver-llc";
const SKIN_SHA256: &str = "ca3f783b8eff409a3f675ccb3b1f26838d9c2e899a879ca7f0b7c28f32565921";
const RECEIPT_SCHEMA: &str = "harmonia.interactables.hermes_appearance.receipt.v1";
const MAX_SKIN_BYTES: u64 = 2 * 1024 * 1024;

// Fixed adapter text only: it accepts an operation and an already-validated home path,
// never a caller-supplied program, shell fragment, config body, or asset content.
const HERMES_ADAPTER: &str = r#"
import contextlib, io, json, os, sys
from pathlib import Path

def run():
    action, source_root = sys.argv[1], Path(sys.argv[2])
    sys.path.insert(0, str(source_root))
    from hermes_constants import get_hermes_home
    if action == "homes":
        from hermes_cli.profiles import list_profile_names
        root = Path(get_hermes_home())
        return {"ok": True, "homes": [{"name": name, "home": str(root if name == "default" else root / "profiles" / name)} for name in list_profile_names()]}
    home = Path(sys.argv[3])
    os.environ["HERMES_HOME"] = str(home)
    if Path(get_hermes_home()) != home:
        return {"ok": False, "signal": "hermes-home-routing-mismatch"}
    from hermes_cli import config
    path = config.get_config_path()
    if action in ("observe", "set", "restore", "backup"):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            raw = config.require_readable_config_before_write(path)
        display = raw.get("display", {})
        if not isinstance(display, dict):
            return {"ok": False, "signal": "hermes-display-section-malformed"}
        selected = display.get("skin")
        if selected is not None and not isinstance(selected, str):
            return {"ok": False, "signal": "hermes-display-skin-malformed"}
        if action == "observe":
            return {"ok": True, "selected_skin": selected}
        if action == "backup":
            if not path.exists() or path.stat().st_size == 0:
                return {"ok": True, "backup_path": None}
            from hermes_cli.config_backups import backup_config, list_config_backups
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                backup = backup_config(path, "harmonia-appearance")
                if backup is None:
                    copies = list_config_backups(path, "harmonia-appearance")
                    if copies and copies[0].is_file() and copies[0].read_bytes() == path.read_bytes():
                        backup = copies[0]
            if backup is None:
                return {"ok": False, "signal": "hermes-config-backup-failed"}
            return {"ok": True, "backup_path": str(backup)}
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                if action == "set":
                    config.set_config_value("display.skin", "homeserver-llc")
                else:
                    original = json.loads(sys.argv[4])
                    if original is None:
                        config.unset_config_value("display.skin")
                    else:
                        config.set_config_value("display.skin", original)
                raw = config.require_readable_config_before_write(path)
                current = raw.get("display", {})
                value = current.get("skin") if isinstance(current, dict) else None
                from hermes_cli.skin_engine import load_skin
                skin = load_skin("homeserver-llc")
                banner = skin.banner_logo
                return {"ok": True, "selected_skin": value, "loader_name": skin.name,
                        "background": skin.colors.get("background"), "banner_logo": banner}
        except BaseException:
            return {"ok": False, "signal": "hermes-native-config-write-failed"}
    if action == "load":
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                from hermes_cli.skin_engine import load_skin
                skin = load_skin("homeserver-llc")
            return {"ok": True, "loader_name": skin.name,
                    "background": skin.colors.get("background"), "banner_logo": skin.banner_logo}
        except BaseException:
            return {"ok": False, "signal": "hermes-skin-loader-failed"}
    return {"ok": False, "signal": "hermes-adapter-operation-invalid"}

try:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        result = run()
except BaseException:
    result = {"ok": False, "signal": "hermes-native-adapter-failed"}
sys.stdout.write(json.dumps(result, separators=(",", ":")))
"#;

#[derive(Debug, Deserialize)]
struct NativeHome {
    name: String,
    home: PathBuf,
}
#[derive(Debug, Deserialize)]
struct HomesReply {
    ok: bool,
    #[serde(default)]
    homes: Vec<NativeHome>,
    signal: Option<String>,
}
#[derive(Debug, Deserialize)]
struct AdapterReply {
    ok: bool,
    signal: Option<String>,
    selected_skin: Option<String>,
    backup_path: Option<PathBuf>,
    loader_name: Option<String>,
    background: Option<String>,
    banner_logo: Option<String>,
}
#[derive(Debug, Deserialize)]
struct Evidence {
    skin_name: String,
    skin_sha256: String,
    homes: Vec<HomeEvidence>,
}
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
struct HomeEvidence {
    home: String,
    selected_skin: Option<String>,
    skin_sha256: Option<String>,
}
#[derive(Debug)]
struct Runtime {
    root: PathBuf,
    source_root: PathBuf,
    python: PathBuf,
    owner_name: String,
    owner_home: PathBuf,
    uid: u32,
}
#[derive(Debug, Clone)]
struct Home {
    name: String,
    path: PathBuf,
    config: PathBuf,
    skins: PathBuf,
    asset: PathBuf,
    uid: u32,
    gid: u32,
}
#[derive(Debug, Clone)]
struct Observation {
    selected_skin: Option<String>,
    skin_sha256: Option<String>,
}
#[derive(Debug)]
struct HomePlan {
    home: Home,
    before: Observation,
    config_backup: Option<PathBuf>,
    skin_backup: Option<PathBuf>,
    skin_changed: bool,
    config_attempted: bool,
    created_skins_dir: bool,
}
#[derive(Debug)]
enum AssetChange {
    Created { home: Home },
    Replaced {
        home: Home,
        prior_bytes: Vec<u8>,
        mode: u32,
        backup: PathBuf,
    },
}

pub(crate) fn execute_validated_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    source_module_dir: &Path,
) -> Result<OperationOutcome, String> {
    if manifest.id != MODULE_ID || step.tool != MODULE_ID || step.permutation != "offer" {
        return Err("hermes-appearance-module-route-invalid".into());
    }
    if !step.args.is_empty() {
        return Err("hermes-appearance-offer-arguments-unsupported".into());
    }
    let asset = source_module_dir.join("files_root/skins/homeserver-llc.yaml");
    let asset_bytes = read_source_asset(&asset)?;
    let Some(runtime) = discover_runtime()? else {
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "hermes-appearance-no-existing-hermes-home".into(),
            command: None,
        });
    };
    let homes = enumerate_homes(&runtime, true)?;
    let feed_path = crate::interactables::feed_path();
    let feed = crate::interactables::load_feed(&feed_path)?;
    let adopted = adopted_homes(&feed, MODULE_ID);
    let mut snapshots = Vec::new();
    for home in homes {
        if adopted.contains(home.path.to_string_lossy().as_ref()) {
            continue;
        }
        let before = observe_home(&runtime, &home)?;
        snapshots.push(HomeEvidence {
            home: home.path.to_string_lossy().into_owned(),
            selected_skin: before.selected_skin,
            skin_sha256: before.skin_sha256,
        });
    }
    let entry = if snapshots.is_empty() {
        None
    } else {
        Some(make_offer(&asset, &snapshots)?)
    };
    let requested_offer = entry.is_some();
    let writes = persist_feed_with_intent(
        &feed_path,
        FeedPersistenceIntent::HermesAppearanceOffer {
            module_id: MODULE_ID.into(),
            entry,
        },
    )?;
    let message = if snapshots.is_empty() || !requested_offer {
        "hermes-appearance-no-unadopted-homes"
    } else if writes == 0 {
        "hermes-appearance-offer-current"
    } else {
        "hermes-appearance-owner-offer-recorded"
    };
    let _ = (module_dir, asset_bytes);
    Ok(OperationOutcome {
        ok: true,
        changed: writes > 0,
        skipped: snapshots.is_empty() || writes == 0,
        message: message.into(),
        command: None,
    })
}

pub(crate) fn run_interactable(
    feed_path: &Path,
    item: &Interactable,
) -> Result<(), String> {
    if item.kind != KIND || item.module_id != MODULE_ID {
        return Err("hermes-appearance-interactable-identity-invalid".into());
    }
    let evidence: Evidence = serde_json::from_value(item.evidence.clone())
        .map_err(|_| "hermes-appearance-evidence-invalid".to_string())?;
    if evidence.skin_name != SKIN_NAME || evidence.skin_sha256 != SKIN_SHA256 || evidence.homes.is_empty()
        || item.id != offer_id(&evidence.homes)? {
        return Err("hermes-appearance-evidence-identity-invalid".into());
    }
    let seat = crate::atoms::ask::mint_seats::interactables_at_start()
        .hermes_appearance_receipt
        .as_ref()
        .map_err(|_| "hermes-appearance-receipt-seat-unavailable".to_string())?;
    let source = item.reference_source_path.as_deref()
        .ok_or_else(|| "hermes-appearance-source-absent".to_string())?;
    let asset_bytes = read_source_asset(source)?;
    let Some(runtime) = discover_runtime()? else {
        return record_preflight_failure(feed_path, item, &evidence, seat, "hermes-appearance-no-existing-hermes-home", None);
    };
    let current_homes = match enumerate_homes(&runtime, false) {
        Ok(homes) => homes,
        Err(_) => return record_preflight_failure(feed_path, item, &evidence, seat, "hermes-appearance-home-discovery-failed", None),
    };
    let by_path = current_homes.iter().map(|home| (home.path.to_string_lossy().into_owned(), home.clone())).collect::<BTreeMap<_, _>>();
    let mut plans = Vec::new();
    let mut observed = BTreeMap::<String, Observation>::new();
    let mut first_missing = None;
    let mut seen = BTreeSet::new();
    for snapshot in &evidence.homes {
        if !Path::new(&snapshot.home).is_absolute() || !seen.insert(snapshot.home.clone()) {
            first_missing.get_or_insert("hermes-appearance-snapshot-invalid");
            continue;
        }
        let Some(mut home) = by_path.get(&snapshot.home).cloned() else {
            first_missing.get_or_insert("hermes-appearance-snapshot-home-no-longer-declared");
            continue;
        };
        if ensure_no_symlink_components(&home.path).is_err() {
            first_missing.get_or_insert("hermes-appearance-unsafe-home-target");
            continue;
        }
        let home_meta = match fs::symlink_metadata(&home.path) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() && meta.uid() == runtime.uid => meta,
            _ => {
                first_missing.get_or_insert("hermes-appearance-unsafe-home-target");
                continue;
            }
        };
        home.uid = home_meta.uid();
        home.gid = home_meta.gid();
        if let Err(_) = preflight_home(&home) {
            first_missing.get_or_insert("hermes-appearance-unsafe-home-target");
            continue;
        }
        let current = match observe_home(&runtime, &home) {
            Ok(current) => current,
            Err(_) => {
                first_missing.get_or_insert("hermes-appearance-config-unreadable");
                continue;
            }
        };
        observed.insert(snapshot.home.clone(), current.clone());
        if current.selected_skin != snapshot.selected_skin {
            first_missing.get_or_insert("hermes-appearance-stale-selected-skin");
            continue;
        }
        if current.skin_sha256 != snapshot.skin_sha256 {
            first_missing.get_or_insert("hermes-appearance-stale-skin-asset");
            continue;
        }
        if current.selected_skin != Some(SKIN_NAME.to_string()) {
            if let Err(_) = preflight_config_backup(&home) {
                first_missing.get_or_insert("hermes-appearance-config-backup-path-unsafe");
                continue;
            }
        }
        plans.push(HomePlan {
            home,
            before: current,
            config_backup: None,
            skin_backup: None,
            skin_changed: false,
            config_attempted: false,
            created_skins_dir: false,
        });
    }
    if seen.len() != evidence.homes.len() {
        first_missing.get_or_insert("hermes-appearance-snapshot-invalid");
    }
    if plans.len() != evidence.homes.len() || first_missing.is_some() {
        return persist_preflight_failure(feed_path, item, &evidence, seat, first_missing.unwrap_or("hermes-appearance-preflight-failed"), &observed);
    }
    let mut shell = build_receipt(item, false, false, &evidence, &plans, None);
    seat.validate(&shell).map_err(|_| "hermes-appearance-receipt-seat-desync".to_string())?;

    // Preserve each changed user config with Hermes's bounded native backup primitive before
    // touching any appearance target. A missing/empty config has no prior user bytes to back up.
    for plan in &mut plans {
        if plan.before.selected_skin != Some(SKIN_NAME.to_string()) {
            match adapter(&runtime, "backup", &plan.home, None) {
                Ok(reply) if reply.ok => plan.config_backup = reply.backup_path,
                _ => return persist_preflight_failure(feed_path, item, &evidence, seat, "hermes-appearance-config-backup-failed", &observed),
            }
        }
    }
    let mut asset_changes = Vec::new();
    let mut failure = None;
    for plan in &mut plans {
        if plan.before.skin_sha256.as_deref() == Some(SKIN_SHA256) {
            continue;
        }
        if !plan.home.skins.exists() {
            if let Err(_) = create_skins_dir(&plan.home) {
                failure = Some("hermes-appearance-skins-directory-create-failed");
                break;
            }
            plan.created_skins_dir = true;
        }
        match install_asset(&plan.home, &asset_bytes, item, feed_path) {
            Ok(change) => {
                plan.skin_changed = true;
                if let Some(change) = change {
                    match &change {
                        AssetChange::Replaced { backup, .. } => plan.skin_backup = Some(backup.clone()),
                        AssetChange::Created { .. } => {}
                    }
                    asset_changes.push(change);
                }
            }
            Err(_) => {
                failure = Some("hermes-appearance-skin-asset-write-failed");
                break;
            }
        }
    }
    if failure.is_none() {
        for plan in &mut plans {
            if plan.before.selected_skin == Some(SKIN_NAME.to_string()) {
                continue;
            }
            plan.config_attempted = true;
            match adapter(&runtime, "set", &plan.home, None) {
                Ok(reply) if reply.ok => {}
                _ => {
                    failure = Some("hermes-appearance-native-config-write-failed");
                    break;
                }
            }
        }
    }
    if failure.is_none() {
        for plan in &plans {
            let observed_now = observe_home(&runtime, &plan.home);
            let loaded = adapter(&runtime, "load", &plan.home, None);
            let good_loader = loaded.as_ref().is_ok_and(|reply| {
                reply.ok
                    && reply.loader_name.as_deref() == Some(SKIN_NAME)
                    && reply.background.as_deref() == Some("#000000")
                    && reply.banner_logo.as_deref().is_some_and(|logo| !logo.trim().is_empty())
            });
            let good_config = observed_now.as_ref().is_ok_and(|value| value.selected_skin.as_deref() == Some(SKIN_NAME));
            let good_asset = observed_now.as_ref().is_ok_and(|value| value.skin_sha256.as_deref() == Some(SKIN_SHA256));
            if !good_loader || !good_config || !good_asset {
                failure = Some("hermes-appearance-post-write-verification-failed");
                break;
            }
        }
    }
    if let Some(signal) = failure {
        let rollback_signal = rollback(&runtime, &mut plans, &mut asset_changes, &asset_bytes, item, feed_path);
        let actual = observe_final_homes(&runtime, &plans);
        let mut receipt = build_receipt(item, false, false, &evidence, &plans, Some(signal));
        apply_actual_rows(&mut receipt, &plans, &actual, false);
        if let Some(rollback_signal) = rollback_signal {
            receipt["rollback_signal"] = json!(rollback_signal);
        }
        seat.validate(&receipt).map_err(|_| "hermes-appearance-receipt-seat-desync".to_string())?;
        persist_feed_with_intent(feed_path, FeedPersistenceIntent::CompleteHermesAppearance {
            module_id: MODULE_ID.into(),
            item_id: item.id.clone(),
            receipt: receipt.clone(),
        })?;
        println!("{}", serde_json::to_string_pretty(&receipt).map_err(|_| "hermes-appearance-receipt-serialize-failed")?);
        return Err(signal.into());
    }

    let actual = observe_final_homes(&runtime, &plans);
    let mut receipt = build_receipt(item, true, false, &evidence, &plans, None);
    apply_actual_rows(&mut receipt, &plans, &actual, true);
    let changed = receipt.get("homes").and_then(Value::as_array).is_some_and(|rows| rows.iter().any(|row| row.get("changed").and_then(Value::as_bool) == Some(true)));
    receipt["changed"] = json!(changed);
    seat.validate(&receipt).map_err(|_| "hermes-appearance-receipt-seat-desync".to_string())?;
    if let Err(error) = persist_feed_with_intent(feed_path, FeedPersistenceIntent::CompleteHermesAppearance {
        module_id: MODULE_ID.into(),
        item_id: item.id.clone(),
        receipt: receipt.clone(),
    }) {
        let rollback_signal = rollback(&runtime, &mut plans, &mut asset_changes, &asset_bytes, item, feed_path);
        let actual = observe_final_homes(&runtime, &plans);
        let mut failed = build_receipt(item, false, false, &evidence, &plans, Some("hermes-appearance-completion-persist-failed"));
        apply_actual_rows(&mut failed, &plans, &actual, false);
        if let Some(signal) = rollback_signal { failed["rollback_signal"] = json!(signal); }
        let _ = persist_feed_with_intent(feed_path, FeedPersistenceIntent::CompleteHermesAppearance {
            module_id: MODULE_ID.into(), item_id: item.id.clone(), receipt: failed,
        });
        return Err(format!("hermes-appearance-completion-persist-failed: {error}"));
    }
    println!("{}", serde_json::to_string_pretty(&receipt).map_err(|_| "hermes-appearance-receipt-serialize-failed")?);
    Ok(())
}

pub(crate) fn has_current_successful_completion(feed: &InteractablesFeed, item_id: &str) -> bool {
    feed.receipts.iter().rev().find(|receipt| {
        receipt.get("schema").and_then(Value::as_str) == Some(RECEIPT_SCHEMA)
            && receipt.get("module_id").and_then(Value::as_str) == Some(MODULE_ID)
    }).is_some_and(|receipt| {
        receipt.get("id").and_then(Value::as_str) == Some(item_id)
            && receipt.get("kind").and_then(Value::as_str) == Some(KIND)
            && receipt.get("ok").and_then(Value::as_bool) == Some(true)
            && receipt.get("homes").and_then(Value::as_array).is_some_and(|homes| {
                !homes.is_empty() && homes.iter().all(|home| home.get("ok").and_then(Value::as_bool) == Some(true))
            })
    })
}

fn discover_runtime() -> Result<Option<Runtime>, String> {
    let owner_home = if unsafe { libc::geteuid() } == 0 {
        let owner = env::var("SUDO_USER").unwrap_or_else(|_| "owner".into());
        if owner == "root" { return Err("hermes-owner-account-invalid".into()); }
        passwd_home(&owner)?
    } else {
        env::var_os("HOME").map(PathBuf::from)
            .ok_or_else(|| "hermes-owner-home-unavailable".to_string())?
    };
    let suffix = env::var("HERMES_DATA_DIR_SUFFIX").unwrap_or_default();
    let native_root = owner_home.join(format!(".hermes{suffix}"));
    let root = if let Some(raw) = env::var_os("HERMES_HOME") {
        let expanded = expand_home(Path::new(&raw), &owner_home)?;
        if expanded.starts_with(&native_root) {
            native_root
        } else if expanded.parent().and_then(Path::file_name) == Some(OsStr::new("profiles")) {
            expanded.parent().and_then(Path::parent).map(Path::to_path_buf)
                .ok_or_else(|| "hermes-home-root-unresolvable".to_string())?
        } else {
            expanded
        }
    } else {
        native_root
    };
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("hermes-home-root-unreadable".into()),
        Ok(meta) if !meta.is_dir() || meta.file_type().is_symlink() => return Err("hermes-home-root-unsafe".into()),
        Ok(_) => {}
    }
    let root_meta = fs::symlink_metadata(&root).map_err(|_| "hermes-home-root-unreadable")?;
    let uid = root_meta.uid();
    if uid == 0 { return Err("hermes-home-root-owner-is-root".into()); }
    let owner_name = passwd_name(uid)?;
    if unsafe { libc::geteuid() } != 0 && unsafe { libc::geteuid() } != uid {
        return Err("hermes-appearance-owner-custody-mismatch".into());
    }
    let owner_home = passwd_home(&owner_name)?;
    let source_root = env::var_os("HERMES_PYTHON_SRC_ROOT").map(PathBuf::from).unwrap_or_else(|| root.join("hermes-agent"));
    let source_root = source_root.canonicalize().map_err(|_| "hermes-python-source-root-unavailable")?;
    let source_config = source_root.join("hermes_cli/config.py");
    if !fs::symlink_metadata(&source_config).is_ok_and(|meta| meta.is_file() && !meta.file_type().is_symlink()) {
        return Err("hermes-python-source-root-invalid".into());
    }
    let source_text = source_root.to_str().ok_or("hermes-python-source-root-non-utf8")?;
    let install_hash = format!("{:x}", Sha256::digest(source_text.as_bytes()));
    let state = root.join("installs").join(&install_hash[..16]);
    let facts_path = state.join("facts.json");
    let facts_meta = fs::symlink_metadata(&facts_path).map_err(|_| "hermes-selected-environment-facts-unavailable")?;
    if !facts_meta.is_file() || facts_meta.file_type().is_symlink() || facts_meta.uid() != uid {
        return Err("hermes-selected-environment-facts-unsafe".into());
    }
    let facts: Value = serde_json::from_slice(&fs::read(&facts_path).map_err(|_| "hermes-selected-environment-facts-unreadable")?)
        .map_err(|_| "hermes-selected-environment-facts-invalid")?;
    let environment = facts.pointer("/packages/venv/environment").and_then(Value::as_str)
        .ok_or("hermes-selected-environment-absent")?;
    let environment = PathBuf::from(environment);
    let canonical_environment = environment.canonicalize().map_err(|_| "hermes-selected-environment-unavailable")?;
    let generations = state.join("environments").canonicalize().map_err(|_| "hermes-selected-environment-root-unavailable")?;
    if !canonical_environment.starts_with(&generations) || !canonical_environment.join("pyvenv.cfg").is_file() {
        return Err("hermes-selected-environment-outside-install".into());
    }
    let python = canonical_environment.join("bin/python");
    let python_meta = fs::metadata(&python).map_err(|_| "hermes-selected-python-unavailable")?;
    if !python_meta.is_file() || python_meta.mode() & 0o111 == 0 {
        return Err("hermes-selected-python-not-executable".into());
    }
    Ok(Some(Runtime { root, source_root, python, owner_name, owner_home, uid }))
}

fn expand_home(raw: &Path, owner_home: &Path) -> Result<PathBuf, String> {
    let text = raw.to_str().ok_or("hermes-home-path-non-utf8")?;
    let mut expanded = text.replace("${HOME}", &owner_home.to_string_lossy()).replace("$HOME", &owner_home.to_string_lossy());
    if expanded == "~" { expanded = owner_home.to_string_lossy().into_owned(); }
    else if expanded.starts_with("~/") { expanded = format!("{}{}", owner_home.display(), &expanded[1..]); }
    if expanded.contains('$') || expanded.contains('%') { return Err("hermes-home-path-expansion-unsupported".into()); }
    let path = PathBuf::from(expanded);
    if !path.is_absolute() { return Err("hermes-home-path-not-absolute".into()); }
    Ok(path)
}

fn passwd_name(uid: u32) -> Result<String, String> {
    let entry = unsafe { libc::getpwuid(uid) };
    if entry.is_null() { return Err("hermes-owner-account-unavailable".into()); }
    let name = unsafe { CStr::from_ptr((*entry).pw_name) }.to_string_lossy().into_owned();
    if name.is_empty() || name == "root" { return Err("hermes-owner-account-invalid".into()); }
    Ok(name)
}
fn passwd_home(name: &str) -> Result<PathBuf, String> {
    let name = CString::new(name).map_err(|_| "hermes-owner-account-invalid")?;
    let entry = unsafe { libc::getpwnam(name.as_ptr()) };
    if entry.is_null() { return Err("hermes-owner-account-unavailable".into()); }
    let path = unsafe { CStr::from_ptr((*entry).pw_dir) }.to_string_lossy().into_owned();
    if path.is_empty() { return Err("hermes-owner-home-unavailable".into()); }
    Ok(PathBuf::from(path))
}

fn enumerate_homes(runtime: &Runtime, preflight: bool) -> Result<Vec<Home>, String> {
    let reply: HomesReply = helper(runtime, "homes", &runtime.root, None)?;
    if !reply.ok { return Err(reply.signal.unwrap_or_else(|| "hermes-profile-discovery-failed".into())); }
    let mut result = Vec::new();
    let mut names = BTreeSet::new();
    for native in reply.homes {
        if !names.insert(native.name.clone()) || native.name.is_empty() {
            return Err("hermes-profile-list-malformed".into());
        }
        let expected = if native.name == "default" { runtime.root.clone() } else {
            if Path::new(&native.name).components().count() != 1 || Path::new(&native.name).components().any(|part| !matches!(part, Component::Normal(_))) {
                return Err("hermes-profile-name-unsafe".into());
            }
            runtime.root.join("profiles").join(&native.name)
        };
        if native.home != expected { return Err("hermes-profile-home-routing-mismatch".into()); }
        let (uid, gid) = if preflight {
            ensure_no_symlink_components(&expected).map_err(|_| "hermes-profile-home-path-unsafe")?;
            let meta = fs::symlink_metadata(&expected).map_err(|_| "hermes-profile-home-missing")?;
            if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid() != runtime.uid {
                return Err("hermes-profile-home-owner-or-type-invalid".into());
            }
            (meta.uid(), meta.gid())
        } else {
            (runtime.uid, 0)
        };
        let home = Home {
            name: native.name,
            config: expected.join("config.yaml"),
            skins: expected.join("skins"),
            asset: expected.join("skins").join(format!("{SKIN_NAME}.yaml")),
            path: expected,
            uid,
            gid,
        };
        if preflight { preflight_home(&home)?; }
        result.push(home);
    }
    if !names.contains("default") { return Err("hermes-default-home-not-declared".into()); }
    Ok(result)
}

fn preflight_home(home: &Home) -> Result<(), String> {
    ensure_no_symlink_components(&home.path).map_err(|_| "hermes-home-path-symlink")?;
    let meta = fs::symlink_metadata(&home.path).map_err(|_| "hermes-home-missing")?;
    if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid() != home.uid || meta.gid() != home.gid {
        return Err("hermes-home-owner-or-type-invalid".into());
    }
    check_required_file(&home.config, home.uid, home.gid)?;
    match fs::symlink_metadata(&home.skins) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("hermes-skins-directory-unreadable".into()),
        Ok(meta) if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid() != home.uid || meta.gid() != home.gid => return Err("hermes-skins-directory-unsafe".into()),
        Ok(_) => {}
    }
    ensure_no_symlink_components(&home.skins).map_err(|_| "hermes-skins-path-symlink")?;
    check_optional_file(&home.asset, home.uid, home.gid, true)?;
    Ok(())
}
fn check_required_file(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    ensure_no_symlink_components(path).map_err(|_| "hermes-target-path-symlink")?;
    let meta = fs::symlink_metadata(path).map_err(|_| "hermes-config-file-missing-or-unreadable")?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.uid() != uid || meta.gid() != gid {
        return Err("hermes-config-file-unsafe".into());
    }
    Ok(())
}
fn check_optional_file(path: &Path, uid: u32, gid: u32, is_asset: bool) -> Result<(), String> {
    ensure_no_symlink_components(path).map_err(|_| "hermes-target-path-symlink")?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("hermes-target-file-unreadable".into()),
        Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() || meta.uid() != uid || meta.gid() != gid || (is_asset && meta.len() > MAX_SKIN_BYTES) => Err("hermes-target-file-unsafe".into()),
        Ok(_) => Ok(()),
    }
}
fn preflight_config_backup(home: &Home) -> Result<(), String> {
    for path in [home.path.join("backups"), home.path.join("backups/config")] {
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("hermes-config-backup-path-unreadable".into()),
            Ok(meta) if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid() != home.uid => return Err("hermes-config-backup-path-unsafe".into()),
            Ok(_) => {}
        }
    }
    Ok(())
}

fn observe_home(runtime: &Runtime, home: &Home) -> Result<Observation, String> {
    preflight_home(home)?;
    let reply: AdapterReply = helper(runtime, "observe", &home.path, None)?;
    if !reply.ok { return Err(reply.signal.unwrap_or_else(|| "hermes-config-observation-failed".into())); }
    let skin_sha256 = match fs::symlink_metadata(&home.asset) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err("hermes-skin-asset-stat-failed".into()),
        Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => return Err("hermes-skin-asset-unsafe".into()),
        Ok(_) => Some(hash_file(&home.asset)?),
    };
    Ok(Observation { selected_skin: reply.selected_skin, skin_sha256 })
}

fn helper<T: for<'de> Deserialize<'de>>(runtime: &Runtime, action: &str, home: &Path, restore: Option<&Option<String>>) -> Result<T, String> {
    let python = runtime.python.to_str().ok_or("hermes-selected-python-non-utf8")?;
    let source = runtime.source_root.to_str().ok_or("hermes-python-source-non-utf8")?;
    let home_text = home.to_str().ok_or("hermes-home-path-non-utf8")?;
    let restore_arg = restore.map(|value| serde_json::to_string(value).unwrap_or_else(|_| "null".into()));
    let mut args = vec!["-I", "-B", "-c", HERMES_ADAPTER, action, source, home_text];
    if let Some(value) = restore_arg.as_deref() { args.push(value); }
    let mut environment = BTreeMap::new();
    environment.insert("HOME".into(), runtime.owner_home.to_string_lossy().into_owned());
    environment.insert("HERMES_HOME".into(), home_text.into());
    environment.insert("PYTHONDONTWRITEBYTECODE".into(), "1".into());
    let result = crate::atoms::command::capture_with_cwd_as_bearer_and_env_and_timeout(
        python, &args, Some(source), &runtime.owner_name, environment, 20,
    );
    if !result.ok { return Err(format!("hermes-native-helper-failed action={action}")); }
    serde_json::from_str(&result.stdout).map_err(|_| format!("hermes-native-helper-response-invalid action={action}"))
}

fn adapter(runtime: &Runtime, action: &str, home: &Home, restore: Option<&Option<String>>) -> Result<AdapterReply, String> {
    helper(runtime, action, &home.path, restore)
}

fn make_offer(source: &Path, homes: &[HomeEvidence]) -> Result<Interactable, String> {
    let evidence = json!({"skin_name": SKIN_NAME, "skin_sha256": SKIN_SHA256, "homes": homes});
    let id = offer_id(homes)?;
    let now = now();
    let diff = offer_diff(homes);
    Ok(Interactable {
        id: id.clone(), module_id: MODULE_ID.into(), name: "Adopt HOMESERVER LLC Hermes appearance".into(),
        description: "Seed the existing homeserver-llc skin in the named existing Hermes homes; later owner choices remain untouched.".into(),
        kind: KIND.into(), target_path: None, reference_source_path: Some(source.to_path_buf()),
        drift: DriftSummary { content: false, mode: false, ownership: false },
        created_at: now.clone(), refreshed_at: now.clone(), available_at: Some(now),
        silenced: false, silenced_at: None, has_run: false, mode: None, owner: None, group: None,
        source_sha: None, target_sha: None, commits_behind: None, live_sha: None, reference_sha: Some(SKIN_SHA256.into()),
        recognition_score: None, diff: Some(diff), script: format!("harmonia interactable run {id}"),
        show_only_if: "hermes-appearance-offer-present".into(), completion_check: format!("skin-sha256:{SKIN_SHA256}"),
        evidence, extra: serde_json::Map::new(),
    })
}
fn offer_diff(homes: &[HomeEvidence]) -> String {
    let mut diff = format!("Hermes appearance adoption\nSkin: {SKIN_NAME}\nAsset SHA256: {SKIN_SHA256}\nNamed existing homes:\n");
    for home in homes {
        diff.push_str(&format!("- {} selected_skin={} skin_sha256={}\n", home.home, json_string(&home.selected_skin), json_string(&home.skin_sha256)));
    }
    diff.push_str("\nOne owner tap copies the exact skin and selects it in only these homes. Later manual skin choices are not reconverged.\n");
    diff
}

pub(crate) fn constrain_offer_to_unadopted(
    mut entry: Interactable,
    adopted: &BTreeSet<String>,
) -> Option<Interactable> {
    if adopted.is_empty() {
        return Some(entry);
    }
    let mut evidence: Evidence = serde_json::from_value(entry.evidence.clone()).ok()?;
    evidence.homes.retain(|home| !adopted.contains(&home.home));
    if evidence.homes.is_empty() {
        return None;
    }
    let id = offer_id(&evidence.homes).ok()?;
    entry.evidence = json!({
        "skin_name": evidence.skin_name,
        "skin_sha256": evidence.skin_sha256,
        "homes": &evidence.homes,
    });
    entry.id = id.clone();
    entry.script = format!("harmonia interactable run {id}");
    entry.diff = Some(offer_diff(&evidence.homes));
    Some(entry)
}

fn offer_id(homes: &[HomeEvidence]) -> Result<String, String> {
    let evidence = json!({"skin_name": SKIN_NAME, "skin_sha256": SKIN_SHA256, "homes": homes});
    let bytes = serde_json::to_vec(&evidence).map_err(|_| "hermes-appearance-evidence-serialize-failed")?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    Ok(format!("hermes-appearance-{}", &digest[..24]))
}
fn json_string<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".into())
}
fn adopted_homes(feed: &InteractablesFeed, module_id: &str) -> BTreeSet<String> {
    feed.receipts.iter().filter(|receipt| receipt.get("schema").and_then(Value::as_str) == Some(RECEIPT_SCHEMA)
        && receipt.get("module_id").and_then(Value::as_str) == Some(module_id))
        .flat_map(|receipt| receipt.get("homes").and_then(Value::as_array).into_iter().flatten())
        .filter(|home| home.get("ok").and_then(Value::as_bool) == Some(true))
        .filter_map(|home| home.get("home").and_then(Value::as_str).map(str::to_owned)).collect()
}

fn read_source_asset(path: &Path) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "hermes-appearance-source-asset-missing")?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() != 1867 {
        return Err("hermes-appearance-source-asset-identity-invalid".into());
    }
    let bytes = fs::read(path).map_err(|_| "hermes-appearance-source-asset-unreadable")?;
    if format!("{:x}", Sha256::digest(&bytes)) != SKIN_SHA256 {
        return Err("hermes-appearance-source-asset-digest-mismatch".into());
    }
    Ok(bytes)
}
fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|_| "hermes-file-hash-open-failed")?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = file.read(&mut buffer).map_err(|_| "hermes-file-hash-read-failed")?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn create_skins_dir(home: &Home) -> Result<(), String> {
    match fs::create_dir(&home.skins) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return preflight_home(home),
        Err(_) => return Err("hermes-skins-directory-create-failed".into()),
    }
    let result = (|| {
        if unsafe { libc::geteuid() } == 0 {
            let path = CString::new(home.skins.as_os_str().as_encoded_bytes()).map_err(|_| "hermes-skins-path-invalid")?;
            if unsafe { libc::chown(path.as_ptr(), home.uid, home.gid) } != 0 {
                return Err("hermes-skins-directory-owner-set-failed".into());
            }
        }
        fs::set_permissions(&home.skins, fs::Permissions::from_mode(0o700))
            .map_err(|_| "hermes-skins-directory-mode-set-failed")?;
        preflight_home(home)
    })();
    if result.is_err() { let _ = fs::remove_dir(&home.skins); }
    result
}

fn install_asset(home: &Home, bytes: &[u8], item: &Interactable, feed_path: &Path) -> Result<Option<AssetChange>, String> {
    match fs::symlink_metadata(&home.asset) {
        Ok(meta) => {
            if !meta.is_file() || meta.file_type().is_symlink() || meta.uid() != home.uid || meta.gid() != home.gid {
                return Err("hermes-skin-asset-unsafe".into());
            }
            let prior_bytes = fs::read(&home.asset).map_err(|_| "hermes-skin-asset-backup-read-failed")?;
            if prior_bytes.len() as u64 > MAX_SKIN_BYTES { return Err("hermes-skin-asset-too-large".into()); }
            if format!("{:x}", Sha256::digest(&prior_bytes)) == SKIN_SHA256 { return Ok(None); }
            let backup = create_asset_backup_path(feed_path, &item.id, home);
            let backup_root = backup.parent().and_then(Path::parent).ok_or("hermes-appearance-backup-path-invalid")?;
            ensure_no_symlink_components(backup_root)?;
            let receipt = crate::atoms::projectio::strike(crate::atoms::projectio::Request {
                target: &home.asset, desired_bytes: bytes, mode: meta.mode() as u32 & 0o7777,
                uid: meta.uid(), gid: meta.gid(), backup_path: &backup,
                witness: crate::atoms::projectio::owner_acceptance(crate::interactables::operator_hand()),
            })?;
            Ok(Some(AssetChange::Replaced { home: home.clone(), prior_bytes, mode: meta.mode() as u32 & 0o7777, backup: receipt.backup_path }))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_asset_new(home, bytes)?;
            Ok(Some(AssetChange::Created { home: home.clone() }))
        }
        Err(_) => Err("hermes-skin-asset-stat-failed".into()),
    }
}

fn create_asset_new(home: &Home, bytes: &[u8]) -> Result<(), String> {
    let mode = 0o644;
    let mut temp_path = None;
    let mut file = None;
    for index in 0..100u32 {
        let candidate = home.skins.join(format!(".hermes-appearance-{}-{index}.tmp", std::process::id()));
        match OpenOptions::new().write(true).read(true).create_new(true).mode(0o600).open(&candidate) {
            Ok(opened) => { temp_path = Some(candidate); file = Some(opened); break; }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err("hermes-skin-temp-create-failed".into()),
        }
    }
    let temp_path = temp_path.ok_or("hermes-skin-temp-exhausted")?;
    let mut file = file.ok_or("hermes-skin-temp-create-failed")?;
    let mut linked_identity = None;
    let result: Result<(), String> = (|| {
        file.write_all(bytes).map_err(|_| "hermes-skin-temp-write-failed")?;
        if unsafe { libc::geteuid() } == 0 {
            if unsafe { libc::fchown(file.as_raw_fd(), home.uid, home.gid) } != 0 {
                return Err("hermes-skin-owner-set-failed".into());
            }
        }
        if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 { return Err("hermes-skin-mode-set-failed".into()); }
        file.sync_all().map_err(|_| "hermes-skin-temp-sync-failed")?;
        let temp_meta = fs::symlink_metadata(&temp_path).map_err(|_| "hermes-skin-temp-stat-failed")?;
        drop(file);
        fs::hard_link(&temp_path, &home.asset).map_err(|_| "hermes-skin-target-create-raced-or-failed")?;
        linked_identity = Some((temp_meta.dev(), temp_meta.ino()));
        fs::remove_file(&temp_path).map_err(|_| "hermes-skin-temp-cleanup-failed")?;
        File::open(&home.skins).and_then(|dir| dir.sync_all()).map_err(|_| "hermes-skins-directory-sync-failed")?;
        let meta = fs::symlink_metadata(&home.asset).map_err(|_| "hermes-skin-target-readback-failed")?;
        if !meta.is_file() || meta.uid() != home.uid || meta.gid() != home.gid || hash_file(&home.asset)? != SKIN_SHA256 {
            return Err("hermes-skin-target-readback-mismatch".into());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
        if let (Some((dev, ino)), Ok(meta)) = (linked_identity, fs::symlink_metadata(&home.asset)) {
            if meta.dev() == dev && meta.ino() == ino { let _ = fs::remove_file(&home.asset); }
        }
    }
    result
}

fn rollback(runtime: &Runtime, plans: &mut [HomePlan], assets: &mut Vec<AssetChange>, source: &[u8], item: &Interactable, feed_path: &Path) -> Option<&'static str> {
    let mut failed = false;
    for plan in plans.iter_mut().rev() {
        if plan.config_attempted {
            let current = observe_home(runtime, &plan.home).ok().and_then(|v| v.selected_skin);
            if current != plan.before.selected_skin {
                let restored = adapter(runtime, "restore", &plan.home, Some(&plan.before.selected_skin)).is_ok_and(|reply| reply.ok);
                let readback = observe_home(runtime, &plan.home).ok().and_then(|v| v.selected_skin);
                if !restored || readback != plan.before.selected_skin { failed = true; }
            }
        }
    }
    for change in assets.drain(..).rev() {
        match change {
            AssetChange::Created { home } => {
                let current = hash_file(&home.asset).ok();
                let meta = fs::symlink_metadata(&home.asset).ok();
                if current.as_deref() == Some(SKIN_SHA256) && meta.as_ref().is_some_and(|m| m.uid() == home.uid && m.gid() == home.gid) {
                    if fs::remove_file(&home.asset).is_err() { failed = true; }
                } else { failed = true; }
                if let Some(plan) = plans.iter_mut().find(|plan| plan.home.path == home.path) {
                    if plan.created_skins_dir && fs::remove_dir(&home.skins).is_err() { failed = true; }
                }
            }
            AssetChange::Replaced { home, prior_bytes, mode, .. } => {
                if hash_file(&home.asset).ok().as_deref() != Some(SKIN_SHA256) {
                    failed = true;
                    continue;
                }
                let current_meta = match fs::symlink_metadata(&home.asset) { Ok(meta) => meta, Err(_) => { failed = true; continue; } };
                let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
                let rollback_path = feed_path.parent().unwrap_or_else(|| Path::new(".")).join("interactables-backups").join(&item.id).join(format!("{stamp}-rollback-{}.yaml", home.name));
                if crate::atoms::projectio::strike(crate::atoms::projectio::Request {
                    target: &home.asset, desired_bytes: &prior_bytes, mode,
                    uid: current_meta.uid(), gid: current_meta.gid(), backup_path: &rollback_path,
                    witness: crate::atoms::projectio::owner_acceptance(crate::interactables::operator_hand()),
                }).is_err() { failed = true; }
            }
        }
    }
    if source.is_empty() { failed = true; }
    failed.then_some("hermes-appearance-rollback-incomplete")
}

fn record_preflight_failure(feed_path: &Path, item: &Interactable, evidence: &Evidence, seat: &crate::atoms::ask::mint_seats::Seat, signal: &str, observed: Option<&BTreeMap<String, Observation>>) -> Result<(), String> {
    let observed = observed.cloned().unwrap_or_default();
    persist_preflight_failure(feed_path, item, evidence, seat, signal, &observed)
}
fn persist_preflight_failure(feed_path: &Path, item: &Interactable, evidence: &Evidence, seat: &crate::atoms::ask::mint_seats::Seat, signal: &str, observed: &BTreeMap<String, Observation>) -> Result<(), String> {
    let homes = evidence.homes.iter().map(|snapshot| {
        let current = observed.get(&snapshot.home);
        json!({
            "home": snapshot.home,
            "ok": false,
            "changed": false,
            "before_skin": current.and_then(|value| value.selected_skin.clone()),
            "after_skin": current.and_then(|value| value.selected_skin.clone()),
            "skin_sha256_before": current.and_then(|value| value.skin_sha256.clone()),
            "skin_sha256_after": current.and_then(|value| value.skin_sha256.clone()),
            "selected_skin_snapshot": snapshot.selected_skin,
            "skin_sha256_snapshot": snapshot.skin_sha256,
        })
    }).collect::<Vec<_>>();
    let receipt = json!({
        "schema": RECEIPT_SCHEMA, "ok": false, "id": item.id, "kind": KIND,
        "changed": false, "skin_name": SKIN_NAME, "skin_sha256": SKIN_SHA256,
        "module_id": MODULE_ID, "homes": homes, "first_missing_signal": signal,
    });
    seat.validate(&receipt).map_err(|_| "hermes-appearance-receipt-seat-desync".to_string())?;
    persist_feed_with_intent(feed_path, FeedPersistenceIntent::CompleteHermesAppearance {
        module_id: MODULE_ID.into(), item_id: item.id.clone(), receipt: receipt.clone(),
    })?;
    println!("{}", serde_json::to_string_pretty(&receipt).map_err(|_| "hermes-appearance-receipt-serialize-failed")?);
    Err(signal.into())
}

fn build_receipt(item: &Interactable, ok: bool, changed: bool, evidence: &Evidence, plans: &[HomePlan], signal: Option<&str>) -> Value {
    let rows = plans.iter().map(|plan| json!({
        "home": plan.home.path,
        "ok": ok,
        "changed": false,
        "before_skin": plan.before.selected_skin,
        "after_skin": plan.before.selected_skin,
        "skin_sha256_before": plan.before.skin_sha256,
        "skin_sha256_after": plan.before.skin_sha256,
        "config_backup_path": plan.config_backup,
        "asset_backup_path": plan.skin_backup,
    })).collect::<Vec<_>>();
    let mut receipt = json!({
        "schema": RECEIPT_SCHEMA, "ok": ok, "id": item.id, "kind": KIND,
        "changed": changed, "skin_name": evidence.skin_name,
        "skin_sha256": evidence.skin_sha256, "module_id": MODULE_ID, "homes": rows,
    });
    if let Some(signal) = signal { receipt["first_missing_signal"] = json!(signal); }
    receipt
}
fn apply_actual_rows(receipt: &mut Value, plans: &[HomePlan], actual: &BTreeMap<String, Observation>, success: bool) {
    if let Some(rows) = receipt.get_mut("homes").and_then(Value::as_array_mut) {
        for (row, plan) in rows.iter_mut().zip(plans) {
            let key = plan.home.path.to_string_lossy().into_owned();
            let after = actual.get(&key);
            let after_skin = after.and_then(|value| value.selected_skin.clone());
            let after_sha = after.and_then(|value| value.skin_sha256.clone());
            let changed = after_skin != plan.before.selected_skin || after_sha != plan.before.skin_sha256;
            row["after_skin"] = json!(after_skin);
            row["skin_sha256_after"] = json!(after_sha);
            row["changed"] = json!(changed);
            row["ok"] = json!(success && after_skin.as_deref() == Some(SKIN_NAME) && after_sha.as_deref() == Some(SKIN_SHA256));
        }
    }
    receipt["changed"] = json!(receipt.get("homes").and_then(Value::as_array).is_some_and(|rows| rows.iter().any(|row| row.get("changed").and_then(Value::as_bool) == Some(true))));
    receipt["ok"] = json!(success && receipt.get("homes").and_then(Value::as_array).is_some_and(|rows| rows.iter().all(|row| row.get("ok").and_then(Value::as_bool) == Some(true))));
}
fn observe_final_homes(runtime: &Runtime, plans: &[HomePlan]) -> BTreeMap<String, Observation> {
    plans.iter().filter_map(|plan| observe_home(runtime, &plan.home).ok().map(|observation| (plan.home.path.to_string_lossy().into_owned(), observation))).collect()
}

fn create_asset_backup_path(feed_path: &Path, item_id: &str, home: &Home) -> PathBuf {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    feed_path.parent().unwrap_or_else(|| Path::new(".")).join("interactables-backups").join(item_id).join(format!("{stamp}-{}.yaml", home.name))
}
fn ensure_no_symlink_components(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => return Err("hermes-appearance-backup-path-symlink".into()),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err("hermes-appearance-backup-path-unreadable".into()),
        }
    }
    Ok(())
}
fn now() -> String {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{seconds}")
}
