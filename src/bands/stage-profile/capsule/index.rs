use crate::atoms::attest;
use crate::hyalos;
use crate::tools::comparison::{self, DiffDecision};
use crate::tools::files::InvocationKey;
use crate::{
    diff_subscription_modules, is_ladder_manifest, load_ladder_manifest, load_profile,
    preserve_existing_lane_or_default, run_id_from_stamp, subscription_path,
    update_subscription_record_with_invocation, SubscriptionModuleStatus, SubscriptionModuleUpdate,
    SubscriptionUpdate, VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

const CAPSULE_SCHEMA: &str = "harmonia.capsule.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CapsuleManifest {
    pub schema: String,
    pub profile_id: String,
    pub identity: String,
    pub engine_version: String,
    pub modules: Vec<CapsuleModuleEntry>,
    #[serde(default)]
    pub locks: Vec<CapsuleLockEntry>,
    #[serde(default)]
    pub lock_tree_sha256: Option<String>,
    #[serde(default)]
    pub profile_index_sha256: Option<String>,
    pub created_from: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CapsuleModuleEntry {
    pub id: String,
    pub version: String,
    pub tree_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CapsuleLockEntry {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct VerifyModuleReceipt {
    id: String,
    version: String,
    expected_tree_sha256: String,
    actual_tree_sha256: Option<String>,
    ok: bool,
    first_missing_signal: String,
}

#[derive(Debug, Clone, Serialize)]
struct CapsulePackReceipt {
    schema: &'static str,
    ok: bool,
    profile_id: String,
    identity: String,
    engine_version: String,
    capsule_dir: String,
    created_from: String,
    module_count: usize,
    lock_count: usize,
    first_missing_signal: String,
}

#[derive(Debug, Clone, Serialize)]
struct CapsuleVerifyReceipt {
    schema: &'static str,
    ok: bool,
    profile_id: String,
    identity: String,
    capsule_dir: String,
    modules: Vec<VerifyModuleReceipt>,
    lock_count: usize,
    first_missing_signal: String,
}

#[derive(Debug, Clone, Serialize)]
struct CapsuleInstallReceipt {
    schema: &'static str,
    ok: bool,
    apply: bool,
    profile_id: String,
    identity: String,
    capsule_dir: String,
    target_config_dir: String,
    lane: &'static str,
    changes: Vec<InstallChange>,
    prunes: Vec<InstallChange>,
    untouched_modules: Vec<String>,
    subscription_path: String,
    subscription_modules: Vec<SubscriptionModuleStatus>,
    subscription_updated: bool,
    first_missing_signal: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InstallChange {
    kind: String,
    path: String,
    module_id: Option<String>,
}

struct CapsuleStageGuard {
    path: PathBuf,
    key: InvocationKey,
    active: bool,
}
impl Drop for CapsuleStageGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = comparison::execute(
                "capsule-stage-cleanup",
                || Ok(fs::symlink_metadata(&self.path).is_ok()),
                |present| {
                    if *present {
                        DiffDecision::Different
                    } else {
                        DiffDecision::Empty
                    }
                },
                |authorization, _| {
                    crate::tools::files::remove_dir_authorized(authorization, self.key, &self.path)
                },
            );
        }
    }
}

pub(crate) fn slice4_bench(
    root: &Path,
    key: crate::atoms::r#do::InvocationKey,
) -> Result<serde_json::Value, String> {
    let authority = root.join("authority");
    let capsule = root.join("capsule");
    let config = root.join("config");
    let subscription = root.join("subscription.json");
    let module = authority.join("profiles/demo/modules/alpha");
    let module_tree = authority.join("shared-modules/alpha");
    fs::create_dir_all(module_tree.join("files_root/etc/demo")).map_err(|e| e.to_string())?;
    fs::create_dir_all(module.parent().unwrap()).map_err(|e| e.to_string())?;
    std::os::unix::fs::symlink(&module_tree, &module).map_err(|e| e.to_string())?;
    fs::create_dir_all(authority.join("locks/demo")).map_err(|e| e.to_string())?;
    fs::write(authority.join("Cargo.toml"), "[package]\nname='fixture'\n")
        .map_err(|e| e.to_string())?;
    fs::write(authority.join("profiles/demo/index.json"), r#"{"id":"demo","identity":"demo-box","package_authority":{"os_family":"arch","package_manager":"pacman"},"modules":["alpha"]}"#).map_err(|e| e.to_string())?;
    fs::write(module.join("manifest.json"), r#"{"schema":"harmonia.module.ladder.v1","id":"alpha","version":"1.0.0","description":"alpha","files_root":"files_root","ladder":[]}"#).map_err(|e| e.to_string())?;
    fs::write(module.join("files_root/etc/demo/value.txt"), b"one\n").map_err(|e| e.to_string())?;
    fs::write(module.join("ratchet-lock.json"), r#"{"schema":"harmonia.aur.ratchet_lock.v1","package":"oh-my-posh-bin","pinned_version":"29.20.1-1","pkgbuild_sha":"ed800be1c781d41ce83ce6e693d6e00e868883c9"}"#).map_err(|e| e.to_string())?;
    fs::write(
        authority.join("locks/demo/pinned-artifacts.json"),
        r#"{"schema":"lock"}"#,
    )
    .map_err(|e| e.to_string())?;
    for args in [
        vec!["init", "-q"],
        vec!["config", "user.email", "harmonia-test@home.arpa"],
        vec!["config", "user.name", "Harmonia Test"],
        vec!["add", "."],
        vec!["commit", "-q", "-m", "fixture"],
    ] {
        if !Command::new("git")
            .args(args)
            .current_dir(&authority)
            .status()
            .map_err(|e| e.to_string())?
            .success()
        {
            return Err("capsule-git-authority-failed".into());
        }
    }
    // Seed only pre-existing target state; proof mutations use production routes.
    fs::create_dir_all(config.join("profiles/demo/modules/old/files_root/tmp"))
        .map_err(|e| e.to_string())?;
    fs::write(
        config.join("profiles/demo/modules/old/manifest.json"),
        b"{}",
    )
    .map_err(|e| e.to_string())?;
    fs::create_dir_all(config.join("profiles/demo/modules/alpha/files_root/etc/demo"))
        .map_err(|e| e.to_string())?;
    fs::write(
        config.join("profiles/demo/modules/alpha/files_root/etc/demo/value.txt"),
        b"stale\n",
    )
    .map_err(|e| e.to_string())?;
    update_subscription_record_with_invocation(
        &subscription,
        SubscriptionUpdate {
            lane: "owner".into(),
            source: "fixture://previous".into(),
            ref_name: "previous-ref".into(),
            selected_profile: "demo".into(),
            engine_version_received: "0.0.1".into(),
            modules: vec![],
        },
        key,
    )?;
    let mut seeded: Value =
        serde_json::from_slice(&fs::read(&subscription).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    seeded
        .as_object_mut()
        .ok_or("capsule-subscription-seed-not-object")?
        .insert(
            "machine_local_divergence".into(),
            serde_json::json!("lawful"),
        );
    crate::write_json_value_atomic_with_invocation(&subscription, &seeded, key)?;
    let previous = std::env::var_os("HARMONIA_SUBSCRIPTION_PATH");
    std::env::set_var("HARMONIA_SUBSCRIPTION_PATH", &subscription);
    let result = (|| {
        capsule_pack_with_invocation("demo", &capsule, &authority, key)?;
        capsule_verify(&capsule)?;
        capsule_install_with_invocation(&capsule, &config, false, None)?;
        let plan: Value = serde_json::from_slice(
            &fs::read(capsule.join("install-plan-receipt.json")).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        capsule_install_with_invocation(&capsule, &config, true, Some(key))?;
        let read = |p: PathBuf| -> Result<Value, String> {
            serde_json::from_slice(&fs::read(p).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())
        };
        let pack = read(capsule.join("pack-receipt.json"))?;
        let verify = read(capsule.join("verify-receipt.json"))?;
        let install = read(config.join("receipts/capsule-install-latest/install-receipt.json"))?;
        let payload =
            fs::read(capsule.join("profiles/demo/modules/alpha/files_root/etc/demo/value.txt"))
                .map_err(|e| e.to_string())?;
        let installed =
            fs::read(config.join("profiles/demo/modules/alpha/files_root/etc/demo/value.txt"))
                .map_err(|e| e.to_string())?;
        let sub: Value =
            serde_json::from_slice(&fs::read(&subscription).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        let payload_bytes_exact = payload == installed && payload == b"one\n";
        let packed_module_path = capsule.join("profiles/demo/modules/alpha");
        let source_module_hash = module_tree_sha256(&module)?;
        let packed_module_hash = module_tree_sha256(&packed_module_path)?;
        let source_hash_equals_dereferenced_copy = source_module_hash == packed_module_hash;
        let packed_module_directory_real = fs::symlink_metadata(&packed_module_path)
            .map(|meta| meta.is_dir() && !meta.file_type().is_symlink())
            .unwrap_or(false);
        let stale_module_pruned = !config.join("profiles/demo/modules/old").exists();
        let unowned_preserved = sub["machine_local_divergence"] == "lawful";
        let ok = [
            pack["ok"].as_bool(),
            verify["ok"].as_bool(),
            plan["ok"].as_bool(),
            install["ok"].as_bool(),
        ]
        .iter()
        .all(|v| *v == Some(true))
            && payload_bytes_exact
            && packed_module_directory_real
            && source_hash_equals_dereferenced_copy
            && stale_module_pruned
            && unowned_preserved;
        Ok(
            serde_json::json!({"payload_bytes_exact":payload_bytes_exact,"packed_module_directory_real":packed_module_directory_real,"source_hash_equals_dereferenced_copy":source_hash_equals_dereferenced_copy,"pack_ok":pack["ok"],"verify_ok":verify["ok"],"plan_ok":plan["ok"],"install_ok":install["ok"],"stale_module_pruned":stale_module_pruned,"subscription_unowned_fields_preserved":unowned_preserved,"pack_receipt":pack,"verify_receipt":verify,"install_receipt":install,"ok":ok}),
        )
    })();
    if let Some(v) = previous {
        std::env::set_var("HARMONIA_SUBSCRIPTION_PATH", v);
    } else {
        std::env::remove_var("HARMONIA_SUBSCRIPTION_PATH");
    }
    result
}

pub(crate) fn capsule_pack_with_invocation(
    profile_id: &str,
    output_dir: &Path,
    harmonia_root: &Path,
    key: InvocationKey,
) -> Result<(), String> {
    validate_harmonia_root(harmonia_root)?;
    // Build in a fresh sibling. The prior destination is untouched until the
    // complete staged tree and its manifest/receipt have been produced.
    let destination_dir = output_dir.to_path_buf();
    let stage_dir = output_dir.with_file_name(format!(
        ".{}-harmonia-stage",
        output_dir
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("capsule")
    ));
    if fs::symlink_metadata(&stage_dir).is_ok() {
        return Err(format!(
            "capsule-stage-already-exists {}",
            stage_dir.display()
        ));
    }
    comparison::execute_once(
        "capsule-stage-create",
        || Ok(false),
        |_| DiffDecision::Different,
        |authorization, _| crate::tools::files::make_dir(authorization, key, &stage_dir),
    )?;
    let mut stage_guard = CapsuleStageGuard {
        path: stage_dir.clone(),
        key,
        active: true,
    };
    let output_dir = stage_dir.as_path();
    let profile_src = harmonia_root
        .join("profiles")
        .join(profile_id)
        .join("index.json");
    let profile = load_profile(&profile_src).map_err(|e| e.to_string())?;
    if profile.id != profile_id {
        return Err(format!(
            "capsule-profile-id-mismatch expected={profile_id} got={}",
            profile.id
        ));
    }
    let profile_dst = output_dir
        .join("profiles")
        .join(profile_id)
        .join("index.json");
    copy_node_artifact(&profile_src, &profile_dst, key)?;
    let mut modules = Vec::new();
    for module_id in &profile.modules {
        let src = harmonia_root
            .join("profiles")
            .join(profile_id)
            .join("modules")
            .join(module_id);
        let dst = output_dir
            .join("profiles")
            .join(profile_id)
            .join("modules")
            .join(module_id);
        let manifest_src = src.join("manifest.json");
        if !manifest_src.exists() || !is_ladder_manifest(&manifest_src) {
            return Err(format!(
                "capsule-module-manifest-missing module={module_id} path={}",
                manifest_src.display()
            ));
        }
        let manifest = load_ladder_manifest(&manifest_src)?;
        copy_tree_artifact(&src, &dst, key)?;
        let tree_sha256 = module_tree_sha256(&dst)?;
        modules.push(CapsuleModuleEntry {
            id: module_id.clone(),
            version: manifest.version,
            tree_sha256,
        });
    }
    let mut locks = Vec::new();
    let mut lock_tree_sha256 = None;
    let locks_src = harmonia_root.join("locks").join(profile_id);
    if locks_src.is_dir() {
        let locks_dst = output_dir.join("locks").join(profile_id);
        copy_tree_artifact(&locks_src, &locks_dst, key)?;
        lock_tree_sha256 = Some(module_tree_sha256(&locks_dst)?);
        for rel in sorted_file_paths(&locks_src)? {
            let src = locks_src.join(&rel);
            locks.push(CapsuleLockEntry {
                path: rel_slash(Path::new("locks").join(profile_id).join(&rel).as_path()),
                sha256: file_sha256(&src)?,
            });
        }
    }
    if modules.len() != profile.modules.len()
        || modules
            .iter()
            .map(|module| module.id.as_str())
            .ne(profile.modules.iter().map(String::as_str))
    {
        return Err(format!(
            "capsule-module-set-mismatch declared_count={} packed_count={}",
            profile.modules.len(),
            modules.len()
        ));
    }
    let created_from = git_head_sha(harmonia_root).ok_or_else(|| {
        format!(
            "capsule-created-from-unavailable root={}",
            harmonia_root.display()
        )
    })?;
    let manifest = CapsuleManifest {
        schema: CAPSULE_SCHEMA.to_string(),
        profile_id: profile.id.clone(),
        identity: profile.identity.clone(),
        engine_version: VERSION.to_string(),
        modules,
        locks,
        lock_tree_sha256,
        profile_index_sha256: Some(module_tree_sha256(&profile_dst)?),
        created_from,
    };
    write_manifest_json_atomic(&output_dir.join("capsule.json"), &manifest, key)?;
    let receipt = CapsulePackReceipt {
        schema: "harmonia.capsule.pack.v1",
        ok: true,
        profile_id: profile.id,
        identity: profile.identity,
        engine_version: VERSION.to_string(),
        capsule_dir: output_dir.display().to_string(),
        created_from: manifest.created_from,
        module_count: manifest.modules.len(),
        lock_count: manifest.locks.len(),
        first_missing_signal: "none".into(),
    };
    write_receipt_json_atomic(&output_dir.join("pack-receipt.json"), &receipt)?;
    let staged = crate::tools::files::remove_dir_capture(output_dir)?;
    comparison::execute_once(
        "capsule-output-promote",
        || Ok(fs::symlink_metadata(&destination_dir).is_ok()),
        |_| DiffDecision::Different,
        |authorization, _| {
            crate::tools::files::remove_dir_replace(authorization, key, &destination_dir, &staged)
        },
    )?;
    comparison::execute(
        "capsule-stage-cleanup",
        || Ok(fs::symlink_metadata(&stage_dir).is_ok()),
        |present| {
            if *present {
                DiffDecision::Different
            } else {
                DiffDecision::Empty
            }
        },
        |authorization, _| {
            crate::tools::files::remove_dir_authorized(authorization, key, &stage_dir)
        },
    )?;
    stage_guard.active = false;
    println!("schema=harmonia.capsule.pack.v1");
    hyalos::forward_receipt(
        "schema=harmonia.capsule.pack.v1",
        &format!("schema=harmonia.capsule.pack.v1 ok={}", true),
        Some(serde_json::json!({"schema": "harmonia.capsule.pack.v1", "ok": true})),
        Some(true),
    );
    println!("ok=true");
    println!("profile_id={}", receipt.profile_id);
    println!("identity={}", receipt.identity);
    println!("module_count={}", receipt.module_count);
    println!("lock_count={}", receipt.lock_count);
    println!("capsule_dir={}", output_dir.display());
    println!("created_from={}", receipt.created_from);
    println!("first_missing_signal=none");
    Ok(())
}

pub(crate) fn capsule_verify(capsule_dir: &Path) -> Result<(), String> {
    let manifest = load_capsule_manifest(capsule_dir)?;
    verify_capsule_structure(capsule_dir, &manifest)?;
    let mut ok = true;
    let mut first = "none".to_string();
    let mut modules = Vec::new();
    for module in &manifest.modules {
        let module_dir = capsule_dir
            .join("profiles")
            .join(&manifest.profile_id)
            .join("modules")
            .join(&module.id);
        let mut signal = "none".to_string();
        let actual = match first_missing_module_path(&module_dir) {
            Some(path) => {
                signal = format!(
                    "module={} path={} signal=missing",
                    module.id,
                    rel_slash(&path)
                );
                None
            }
            None => match module_tree_sha256(&module_dir) {
                Ok(digest) => Some(digest),
                Err(err) => {
                    signal = format!(
                        "module={} path={} signal={err}",
                        module.id,
                        rel_slash(&module_dir)
                    );
                    None
                }
            },
        };
        let module_ok = actual.as_deref() == Some(module.tree_sha256.as_str()) && signal == "none";
        if !module_ok {
            ok = false;
            if signal == "none" {
                let path = first_different_module_path(&module_dir, &module.tree_sha256)
                    .unwrap_or_else(|| PathBuf::from("manifest.json"));
                signal = format!(
                    "module={} path={} signal=digest-mismatch",
                    module.id,
                    rel_slash(&path)
                );
            }
            if first == "none" {
                first = signal.clone();
            }
        }
        modules.push(VerifyModuleReceipt {
            id: module.id.clone(),
            version: module.version.clone(),
            expected_tree_sha256: module.tree_sha256.clone(),
            actual_tree_sha256: actual,
            ok: module_ok,
            first_missing_signal: signal,
        });
    }
    for lock in &manifest.locks {
        let lock_path = capsule_dir.join(&lock.path);
        let lock_ok = fs::symlink_metadata(&lock_path).is_ok()
            && file_sha256(&lock_path).ok().as_deref() == Some(lock.sha256.as_str());
        if !lock_ok {
            ok = false;
            if first == "none" {
                first = format!("lock={} signal=digest-mismatch-or-missing", lock.path);
            }
        }
    }
    if let Some(expected) = &manifest.lock_tree_sha256 {
        let lock_tree = capsule_dir.join("locks").join(&manifest.profile_id);
        let actual = fs::symlink_metadata(&lock_tree)
            .ok()
            .and_then(|_| module_tree_sha256(&lock_tree).ok());
        if actual.as_deref() != Some(expected.as_str()) {
            ok = false;
            if first == "none" {
                first = format!(
                    "lock-tree={} signal=digest-mismatch-or-missing",
                    lock_tree.display()
                );
            }
        }
    }
    if let Some(expected) = &manifest.profile_index_sha256 {
        let profile_index = capsule_dir
            .join("profiles")
            .join(&manifest.profile_id)
            .join("index.json");
        let actual = fs::symlink_metadata(&profile_index)
            .ok()
            .and_then(|_| module_tree_sha256(&profile_index).ok());
        if actual.as_deref() != Some(expected.as_str()) {
            ok = false;
            if first == "none" {
                first = format!(
                    "profile-index={} signal=digest-mismatch-or-missing",
                    profile_index.display()
                );
            }
        }
    }
    let receipt = CapsuleVerifyReceipt {
        schema: "harmonia.capsule.verify.v1",
        ok,
        profile_id: manifest.profile_id,
        identity: manifest.identity,
        capsule_dir: capsule_dir.display().to_string(),
        modules,
        lock_count: manifest.locks.len(),
        first_missing_signal: first.clone(),
    };
    write_receipt_json_atomic(&capsule_dir.join("verify-receipt.json"), &receipt)?;
    println!("schema=harmonia.capsule.verify.v1");
    hyalos::forward_receipt(
        "schema=harmonia.capsule.verify.v1",
        &format!("schema=harmonia.capsule.verify.v1 ok={}", ok),
        Some(serde_json::json!({"schema": "harmonia.capsule.verify.v1", "ok": ok})),
        Some(ok),
    );
    println!("ok={}", ok);
    println!("profile_id={}", receipt.profile_id);
    println!("module_count={}", receipt.modules.len());
    println!("first_missing_signal={}", first);
    if ok {
        Ok(())
    } else {
        Err(first)
    }
}

pub(crate) fn capsule_install_with_invocation(
    capsule_dir: &Path,
    config_dir: &Path,
    apply: bool,
    invocation: Option<InvocationKey>,
) -> Result<(), String> {
    if apply && invocation.is_none() {
        return Err("capsule-install-invocation-missing".to_string());
    }
    match capsule_verify(capsule_dir) {
        Ok(()) => (),
        Err(err) => return Err(err),
    };
    let manifest = load_capsule_manifest(capsule_dir)?;
    validate_install_target_ancestors(config_dir, &manifest, apply)?;
    let run_id = run_id_from_stamp();
    let subscription_path = subscription_path();
    let subscription_modules: Vec<SubscriptionModuleUpdate> = manifest
        .modules
        .iter()
        .map(|module| SubscriptionModuleUpdate {
            id: module.id.clone(),
            version: module.version.clone(),
            tree_sha256: module.tree_sha256.clone(),
            received_at_run_id: run_id.clone(),
        })
        .collect();
    let subscription_statuses =
        diff_subscription_modules(&subscription_path, &subscription_modules)?;
    let target_profiles = config_dir.join("profiles");
    let target_profile_dir = target_profiles.join(&manifest.profile_id);
    let source_profile_dir = capsule_dir.join("profiles").join(&manifest.profile_id);
    let mut changes = Vec::new();
    let mut prunes = Vec::new();
    let mut untouched_modules = Vec::new();

    converge_exact_node(
        &source_profile_dir.join("index.json"),
        &target_profile_dir.join("index.json"),
        apply,
        &mut changes,
        None,
        invocation,
    )?;
    let wanted: BTreeSet<String> = manifest.modules.iter().map(|m| m.id.clone()).collect();
    let target_modules = target_profile_dir.join("modules");
    let target_modules_meta = fs::symlink_metadata(&target_modules).ok();
    let target_modules_wrong_kind = target_modules_meta
        .as_ref()
        .is_some_and(|meta| !meta.is_dir() || meta.file_type().is_symlink());
    if target_modules_wrong_kind {
        for module in &manifest.modules {
            changes.push(InstallChange {
                kind: "replace-module-container".into(),
                path: target_modules.display().to_string(),
                module_id: Some(module.id.clone()),
            });
        }
        let source_modules = source_profile_dir.join("modules");
        copy_tree_exact(
            &source_modules,
            &target_modules,
            apply,
            &mut changes,
            None,
            invocation,
        )?;
    } else if target_modules_meta.is_some_and(|meta| meta.is_dir()) {
        for entry in fs::read_dir(&target_modules).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if fs::symlink_metadata(entry.path()).is_ok() {
                let id = entry.file_name().to_string_lossy().to_string();
                if !wanted.contains(&id) {
                    prunes.push(InstallChange {
                        kind: "prune-module".into(),
                        path: entry.path().display().to_string(),
                        module_id: Some(id),
                    });
                    if apply {
                        let key = invocation
                            .ok_or_else(|| "capsule-install-invocation-missing".to_string())?;
                        let path = entry.path();
                        comparison::execute(
                            "capsule-install-stale-module",
                            || Ok(fs::symlink_metadata(&path).is_ok()),
                            |present| {
                                if *present {
                                    DiffDecision::Different
                                } else {
                                    DiffDecision::Empty
                                }
                            },
                            |authorization, _| {
                                crate::tools::files::remove_dir_authorized(
                                    authorization,
                                    key,
                                    &path,
                                )
                                .map(|_| ())
                            },
                        )?;
                    }
                }
            }
        }
    }
    for module in &manifest.modules {
        let src = source_profile_dir.join("modules").join(&module.id);
        let dst = target_profile_dir.join("modules").join(&module.id);
        let installed_clean = dst.is_dir()
            && module_tree_sha256(&dst).ok().as_deref() == Some(module.tree_sha256.as_str());
        if installed_clean {
            untouched_modules.push(module.id.clone());
            continue;
        }
        copy_tree_exact(
            &src,
            &dst,
            apply,
            &mut changes,
            Some(module.id.as_str()),
            invocation,
        )?;
    }
    let locks_src = capsule_dir.join("locks").join(&manifest.profile_id);
    let locks_dst = config_dir.join("locks").join(&manifest.profile_id);
    if locks_src.is_dir() {
        copy_tree_exact(&locks_src, &locks_dst, apply, &mut prunes, None, invocation)?;
    } else if fs::symlink_metadata(&locks_dst).is_ok() {
        prunes.push(InstallChange {
            kind: "prune-lock-tree".into(),
            path: locks_dst.display().to_string(),
            module_id: None,
        });
        if apply {
            let key = invocation.ok_or_else(|| "capsule-install-invocation-missing".to_string())?;
            comparison::execute(
                "capsule-install-lock-tree-remove",
                || Ok(fs::symlink_metadata(&locks_dst).is_ok()),
                |present| {
                    if *present {
                        DiffDecision::Different
                    } else {
                        DiffDecision::Empty
                    }
                },
                |authorization, _| {
                    crate::tools::files::remove_dir_authorized(authorization, key, &locks_dst)
                        .map(|_| ())
                },
            )?;
        }
    }
    let subscription_updated = apply
        && subscription_statuses
            .iter()
            .any(|status| status.status != "current");
    if subscription_updated {
        let lane = preserve_existing_lane_or_default(&subscription_path);
        update_subscription_record_with_invocation(
            &subscription_path,
            SubscriptionUpdate {
                lane,
                source: format!("capsule:{}", capsule_dir.display()),
                ref_name: manifest.created_from.clone(),
                selected_profile: manifest.profile_id.clone(),
                engine_version_received: manifest.engine_version.clone(),
                modules: subscription_modules,
            },
            invocation.ok_or_else(|| "capsule-install-invocation-missing".to_string())?,
        )?;
    }
    let receipt = CapsuleInstallReceipt {
        schema: "harmonia.capsule.install.v1",
        ok: true,
        apply,
        profile_id: manifest.profile_id.clone(),
        identity: manifest.identity.clone(),
        capsule_dir: capsule_dir.display().to_string(),
        target_config_dir: config_dir.display().to_string(),
        lane: "capsule",
        changes,
        prunes,
        untouched_modules,
        subscription_path: subscription_path.display().to_string(),
        subscription_modules: subscription_statuses,
        subscription_updated,
        first_missing_signal: "none".into(),
    };
    let receipt_dir = config_dir.join("receipts").join("capsule-install-latest");
    let receipt_path = if apply {
        receipt_dir.join("install-receipt.json")
    } else {
        capsule_dir.join("install-plan-receipt.json")
    };
    write_receipt_json_atomic(&receipt_path, &receipt)?;
    println!("schema=harmonia.capsule.install.v1");
    hyalos::forward_receipt(
        "schema=harmonia.capsule.install.v1",
        &format!("schema=harmonia.capsule.install.v1 ok={}", true),
        Some(serde_json::json!({"schema": "harmonia.capsule.install.v1", "ok": true})),
        Some(true),
    );
    println!("ok=true");
    println!("apply={}", apply);
    println!("profile_id={}", manifest.profile_id);
    println!("lane=capsule");
    println!("change_count={}", receipt.changes.len());
    println!("prune_count={}", receipt.prunes.len());
    println!("untouched_modules={}", receipt.untouched_modules.join(","));
    for status in &receipt.subscription_modules {
        println!(
            "subscription_module={} status={} record_version={} capsule_version={}",
            status.id,
            status.status,
            status.record_version.as_deref().unwrap_or("absent"),
            status.capsule_version
        );
    }
    println!("subscription_path={}", receipt.subscription_path);
    println!("subscription_updated={}", receipt.subscription_updated);
    println!("receipt={}", receipt_path.display());
    println!("first_missing_signal=none");
    Ok(())
}

fn validate_existing_target_ancestors(config_dir: &Path, relative: &Path) -> Result<(), String> {
    let mut current = config_dir.to_path_buf();
    let mut components = relative.components();
    loop {
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(format!(
                    "capsule-install-target-ancestor-symlink {}",
                    current.display()
                ));
            }
            Ok(meta) if !meta.is_dir() => {
                return Err(format!(
                    "capsule-install-target-ancestor-not-directory {}",
                    current.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(format!(
                    "capsule-install-target-ancestor-stat-failed {}: {error}",
                    current.display()
                ));
            }
        }
        let Some(component) = components.next() else {
            return Ok(());
        };
        let Component::Normal(name) = component else {
            return Err(format!(
                "capsule-install-target-path-unsafe {}",
                relative.display()
            ));
        };
        current.push(name);
    }
}

fn validate_install_target_ancestors(
    config_dir: &Path,
    manifest: &CapsuleManifest,
    apply: bool,
) -> Result<(), String> {
    let mut target_parents = vec![
        PathBuf::from("profiles").join(&manifest.profile_id),
        PathBuf::from("profiles")
            .join(&manifest.profile_id)
            .join("modules"),
        PathBuf::from("locks").join(&manifest.profile_id),
    ];
    if apply {
        target_parents.push(PathBuf::from("receipts").join("capsule-install-latest"));
    }
    for relative in target_parents {
        validate_existing_target_ancestors(config_dir, &relative)?;
    }
    Ok(())
}

pub(crate) fn load_capsule_manifest(capsule_dir: &Path) -> Result<CapsuleManifest, String> {
    let path = capsule_dir.join("capsule.json");
    let text = fs::read_to_string(&path)
        .map_err(|e| format!("capsule-manifest-read-failed {}: {e}", path.display()))?;
    let manifest: CapsuleManifest = serde_json::from_str(&text)
        .map_err(|e| format!("capsule-manifest-parse-failed {}: {e}", path.display()))?;
    if manifest.schema != CAPSULE_SCHEMA {
        return Err(format!("capsule-schema-unsupported {}", manifest.schema));
    }
    Ok(manifest)
}

fn is_safe_component(value: &str) -> bool {
    !value.is_empty()
        && Path::new(value)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
        && Path::new(value).components().count() == 1
}

fn verify_capsule_structure(capsule_dir: &Path, manifest: &CapsuleManifest) -> Result<(), String> {
    if !is_safe_component(&manifest.profile_id)
        || manifest
            .modules
            .iter()
            .any(|module| !is_safe_component(&module.id))
    {
        return Err("capsule-unsafe-profile-or-module-id".to_string());
    }
    let root = fs::symlink_metadata(capsule_dir)
        .map_err(|e| format!("capsule-root-missing {}: {e}", capsule_dir.display()))?;
    if !root.is_dir() || root.file_type().is_symlink() {
        return Err(format!("capsule-root-wrong-kind {}", capsule_dir.display()));
    }
    let allowed_root = [
        "capsule.json",
        "pack-receipt.json",
        "verify-receipt.json",
        "install-plan-receipt.json",
        "profiles",
        "locks",
    ];
    for entry in fs::read_dir(capsule_dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !allowed_root.contains(&name.as_str()) {
            return Err(format!(
                "capsule-undeclared-root-node path={}",
                entry.path().display()
            ));
        }
        let meta = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
        let valid = match name.as_str() {
            "profiles" | "locks" => meta.is_dir() && !meta.file_type().is_symlink(),
            _ => meta.is_file() && !meta.file_type().is_symlink(),
        };
        if !valid {
            return Err(format!(
                "capsule-root-wrong-kind path={}",
                entry.path().display()
            ));
        }
    }
    let profiles = capsule_dir.join("profiles");
    let profile_meta = fs::symlink_metadata(&profiles).map_err(|e| e.to_string())?;
    if !profile_meta.is_dir() || profile_meta.file_type().is_symlink() {
        return Err(format!(
            "capsule-profiles-wrong-kind path={}",
            profiles.display()
        ));
    }
    let profile_entries = fs::read_dir(&profiles)
        .map_err(|e| e.to_string())?
        .map(|entry| entry.map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    if profile_entries.len() != 1
        || profile_entries[0].file_name().to_string_lossy() != manifest.profile_id
    {
        return Err(format!(
            "capsule-undeclared-profile expected={} path={}",
            manifest.profile_id,
            profiles.display()
        ));
    }
    let profile_dir = profiles.join(&manifest.profile_id);
    let profile_meta = fs::symlink_metadata(&profile_dir).map_err(|e| e.to_string())?;
    if !profile_meta.is_dir() || profile_meta.file_type().is_symlink() {
        return Err(format!(
            "capsule-profile-wrong-kind path={}",
            profile_dir.display()
        ));
    }
    let profile_entries = fs::read_dir(&profile_dir)
        .map_err(|e| e.to_string())?
        .map(|entry| entry.map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let allowed_profile = ["index.json", "modules"];
    for entry in &profile_entries {
        let name = entry.file_name().to_string_lossy().to_string();
        if !allowed_profile.contains(&name.as_str()) {
            return Err(format!(
                "capsule-undeclared-profile-node path={}",
                entry.path().display()
            ));
        }
        let meta = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
        let valid = match name.as_str() {
            "index.json" => meta.is_file() && !meta.file_type().is_symlink(),
            "modules" => meta.is_dir() && !meta.file_type().is_symlink(),
            _ => false,
        };
        if !valid {
            return Err(format!(
                "capsule-profile-node-wrong-kind path={}",
                entry.path().display()
            ));
        }
    }
    if profile_entries.len() != 2 {
        return Err(format!(
            "capsule-profile-node-missing path={}",
            profile_dir.display()
        ));
    }
    let modules_dir = profile_dir.join("modules");
    let declared: BTreeSet<&str> = manifest.modules.iter().map(|m| m.id.as_str()).collect();
    if declared.len() != manifest.modules.len() {
        return Err("capsule-duplicate-module-declaration".to_string());
    }
    let module_entries = fs::read_dir(&modules_dir)
        .map_err(|e| e.to_string())?
        .map(|entry| entry.map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    for entry in &module_entries {
        let id = entry.file_name().to_string_lossy().to_string();
        let meta = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
        if !meta.is_dir() || meta.file_type().is_symlink() || !declared.contains(id.as_str()) {
            return Err(format!(
                "capsule-undeclared-module path={}",
                entry.path().display()
            ));
        }
    }
    if module_entries.len() != declared.len() {
        return Err(format!(
            "capsule-module-node-count-mismatch path={}",
            modules_dir.display()
        ));
    }
    let lock_root = Path::new("locks").join(&manifest.profile_id);
    for lock in &manifest.locks {
        let lock_path = Path::new(&lock.path);
        let Ok(relative) = lock_path.strip_prefix(&lock_root) else {
            return Err(format!("capsule-lock-path-outside-tree path={}", lock.path));
        };
        if relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(format!("capsule-lock-path-unsafe path={}", lock.path));
        }
        let path = capsule_dir.join(lock_path);
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err(format!(
                "capsule-lock-file-wrong-kind path={}",
                path.display()
            ));
        }
    }
    match (&manifest.lock_tree_sha256, manifest.locks.is_empty()) {
        (Some(_), _) => {
            let locks = capsule_dir.join("locks");
            let locks_meta = fs::symlink_metadata(&locks).map_err(|e| e.to_string())?;
            if !locks_meta.is_dir() || locks_meta.file_type().is_symlink() {
                return Err(format!("capsule-locks-wrong-kind path={}", locks.display()));
            }
            let lock_profile = locks.join(&manifest.profile_id);
            let lock_profile_meta =
                fs::symlink_metadata(&lock_profile).map_err(|e| e.to_string())?;
            if !lock_profile_meta.is_dir() || lock_profile_meta.file_type().is_symlink() {
                return Err(format!(
                    "capsule-lock-tree-wrong-kind path={}",
                    lock_profile.display()
                ));
            }
        }
        (None, true) => {
            if fs::symlink_metadata(capsule_dir.join("locks")).is_ok() {
                return Err("capsule-extra-lock-tree".to_string());
            }
        }
        (None, false) => return Err("capsule-locks-without-lock-tree".to_string()),
    }
    Ok(())
}

fn validate_harmonia_root(root: &Path) -> Result<(), String> {
    if !root.join("Cargo.toml").exists() || !root.join("profiles").is_dir() {
        return Err(format!("capsule-harmonia-root-rejected {}", root.display()));
    }
    Ok(())
}

pub(crate) fn installed_module_version(module_dir: &Path) -> Option<String> {
    let manifest_path = module_dir.join("manifest.json");
    let text = fs::read_to_string(manifest_path).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    value.get("version")?.as_str().map(ToOwned::to_owned)
}

pub(crate) fn module_tree_sha256(module_dir: &Path) -> Result<String, String> {
    let image = crate::tools::files::remove_dir_capture(module_dir)?;
    let mut active_directories = HashSet::new();
    let root = dereference_hash_node(image.root, module_dir, &mut active_directories)?;
    let mut chain = Sha256::new();
    hash_tree_node(&mut chain, &root);
    Ok(format!("{:x}", chain.finalize()))
}

fn dereference_hash_node(
    node: crate::tools::files::RemoveDirNode,
    physical_path: &Path,
    active_directories: &mut HashSet<PathBuf>,
) -> Result<crate::tools::files::RemoveDirNode, String> {
    match node.kind {
        crate::tools::files::RemoveDirKind::Symlink => {
            let target = fs::canonicalize(physical_path).map_err(|e| {
                format!(
                    "module-tree-hash-broken-link {}: {e}",
                    physical_path.display()
                )
            })?;
            let image = crate::tools::files::remove_dir_capture(&target)?;
            dereference_hash_node_at(image.root, &target, node.relative, active_directories)
        }
        crate::tools::files::RemoveDirKind::Directory => {
            let identity = fs::canonicalize(physical_path).map_err(|e| {
                format!(
                    "module-tree-hash-directory-resolve {}: {e}",
                    physical_path.display()
                )
            })?;
            if !active_directories.insert(identity.clone()) {
                return Err(format!(
                    "module-tree-hash-cycle {}",
                    physical_path.display()
                ));
            }
            let mut children = Vec::with_capacity(node.children.len());
            for child in node.children {
                let child_name = child
                    .relative
                    .rsplit(|byte| *byte == b'/')
                    .next()
                    .unwrap_or(&[]);
                let child_path =
                    physical_path.join(std::ffi::OsString::from_vec(child_name.to_vec()));
                children.push(dereference_hash_node(
                    child,
                    &child_path,
                    active_directories,
                )?);
            }
            active_directories.remove(&identity);
            Ok(crate::tools::files::RemoveDirNode { children, ..node })
        }
        crate::tools::files::RemoveDirKind::File => Ok(node),
    }
}

fn dereference_hash_node_at(
    mut node: crate::tools::files::RemoveDirNode,
    physical_path: &Path,
    relative: Vec<u8>,
    active_directories: &mut HashSet<PathBuf>,
) -> Result<crate::tools::files::RemoveDirNode, String> {
    node.relative = relative.clone();
    match node.kind {
        crate::tools::files::RemoveDirKind::Directory => {
            let identity = fs::canonicalize(physical_path).map_err(|e| {
                format!(
                    "module-tree-hash-directory-resolve {}: {e}",
                    physical_path.display()
                )
            })?;
            if !active_directories.insert(identity.clone()) {
                return Err(format!(
                    "module-tree-hash-cycle {}",
                    physical_path.display()
                ));
            }
            let mut children = Vec::with_capacity(node.children.len());
            for child in node.children {
                let child_name = child
                    .relative
                    .rsplit(|byte| *byte == b'/')
                    .next()
                    .unwrap_or(&[])
                    .to_vec();
                let child_path =
                    physical_path.join(std::ffi::OsString::from_vec(child_name.clone()));
                children.push(dereference_hash_node_at(
                    child,
                    &child_path,
                    if relative.is_empty() {
                        child_name.clone()
                    } else {
                        [relative.as_slice(), b"/", child_name.as_slice()].concat()
                    },
                    active_directories,
                )?);
            }
            active_directories.remove(&identity);
            Ok(crate::tools::files::RemoveDirNode { children, ..node })
        }
        crate::tools::files::RemoveDirKind::File => Ok(node),
        crate::tools::files::RemoveDirKind::Symlink => {
            let target = fs::canonicalize(physical_path).map_err(|e| {
                format!(
                    "module-tree-hash-broken-link {}: {e}",
                    physical_path.display()
                )
            })?;
            let image = crate::tools::files::remove_dir_capture(&target)?;
            dereference_hash_node_at(image.root, &target, node.relative, active_directories)
        }
    }
}

fn hash_tree_node(chain: &mut Sha256, node: &crate::tools::files::RemoveDirNode) {
    hash_tree_bytes(chain, &node.relative);
    chain.update([match node.kind {
        crate::tools::files::RemoveDirKind::Directory => 0,
        crate::tools::files::RemoveDirKind::File => 1,
        crate::tools::files::RemoveDirKind::Symlink => 2,
    }]);
    hash_tree_bytes(chain, &node.bytes);
    hash_tree_bytes(chain, &node.link);
    chain.update(node.mode.to_le_bytes());
    chain.update(node.uid.to_le_bytes());
    chain.update(node.gid.to_le_bytes());
    chain.update([u8::from(node.xattrs.supported)]);
    let mut xattrs = node.xattrs.values.iter().collect::<Vec<_>>();
    xattrs.sort_by(|a, b| a.name.cmp(&b.name));
    chain.update((xattrs.len() as u64).to_le_bytes());
    for xattr in xattrs {
        hash_tree_bytes(chain, &xattr.name);
        hash_tree_bytes(chain, &xattr.value);
    }
    chain.update((node.children.len() as u64).to_le_bytes());
    for child in &node.children {
        hash_tree_node(chain, child);
    }
}

fn hash_tree_bytes(chain: &mut Sha256, bytes: &[u8]) {
    chain.update((bytes.len() as u64).to_le_bytes());
    chain.update(bytes);
}

fn first_missing_module_path(module_dir: &Path) -> Option<PathBuf> {
    if !module_dir.join("manifest.json").exists() {
        return Some(PathBuf::from("manifest.json"));
    }
    None
}

fn first_different_module_path(_module_dir: &Path, _expected: &str) -> Option<PathBuf> {
    Some(PathBuf::from("manifest.json"))
}

fn sorted_file_paths(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    collect_files(root, root, &mut out)?;
    out.sort_by(|a, b| rel_slash(a).cmp(&rel_slash(b)));
    Ok(out)
}

fn collect_files(root: &Path, current: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in
        fs::read_dir(current).map_err(|e| format!("read-dir-failed {}: {e}", current.display()))?
    {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let ft = entry.file_type().map_err(|e| e.to_string())?;
        if ft.is_dir() {
            collect_files(root, &path, out)?;
        } else if ft.is_file() {
            out.push(
                path.strip_prefix(root)
                    .map_err(|e| e.to_string())?
                    .to_path_buf(),
            );
        }
    }
    Ok(())
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("file-read-failed {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

fn copy_node_artifact(src: &Path, dst: &Path, key: InvocationKey) -> Result<(), String> {
    let image = crate::tools::files::remove_dir_capture(src)?;
    if let Some(parent) = dst.parent() {
        comparison::execute(
            "capsule-artifact-parent",
            || Ok(fs::symlink_metadata(parent).is_ok()),
            |present| {
                if *present {
                    DiffDecision::Empty
                } else {
                    DiffDecision::Different
                }
            },
            |authorization, _| crate::tools::files::make_dir(authorization, key, parent),
        )?;
    }
    comparison::execute_once(
        "capsule-artifact-replace",
        || Ok(fs::symlink_metadata(dst).is_ok()),
        |_| DiffDecision::Different,
        |authorization, _| crate::tools::files::remove_dir_replace(authorization, key, dst, &image),
    )?;
    Ok(())
}

fn copy_tree_artifact(src: &Path, dst: &Path, key: InvocationKey) -> Result<(), String> {
    let metadata = fs::symlink_metadata(src)
        .map_err(|e| format!("capsule-artifact-source-stat-failed {}: {e}", src.display()))?;
    let source = if metadata.file_type().is_symlink() {
        src.canonicalize().map_err(|e| {
            format!(
                "capsule-artifact-source-resolve-failed {}: {e}",
                src.display()
            )
        })?
    } else {
        src.to_path_buf()
    };
    copy_node_artifact(&source, dst, key)
}

fn copy_tree_exact(
    src: &Path,
    dst: &Path,
    apply: bool,
    changes: &mut Vec<InstallChange>,
    module_id: Option<&str>,
    invocation: Option<InvocationKey>,
) -> Result<(), String> {
    if !src.is_dir() {
        return Err(format!("copy-tree-source-missing {}", src.display()));
    }
    let source_image = crate::tools::files::remove_dir_capture(src)?;
    let source_paths = sorted_tree_paths(src)?;
    let target_image = if fs::symlink_metadata(dst).is_ok() {
        Some(crate::tools::files::remove_dir_capture(dst)?)
    } else {
        None
    };
    if target_image
        .as_ref()
        .is_some_and(|image| crate::tools::files::remove_dir_exact(image, &source_image))
    {
        return Ok(());
    }
    let target_paths = if target_image.as_ref().is_some_and(|image| {
        matches!(
            image.root.kind,
            crate::tools::files::RemoveDirKind::Directory
        )
    }) {
        sorted_tree_paths(dst)?
    } else if target_image.is_some() {
        vec![PathBuf::from(".")]
    } else {
        Vec::new()
    };
    let source_set: BTreeSet<String> = source_paths.iter().map(|p| rel_slash(p)).collect();
    for rel in target_paths
        .into_iter()
        .filter(|rel| !source_set.contains(&rel_slash(rel)))
    {
        changes.push(InstallChange {
            kind: "prune-tree-entry".into(),
            path: dst.join(&rel).display().to_string(),
            module_id: module_id.map(ToOwned::to_owned),
        });
    }
    for rel in source_paths {
        changes.push(InstallChange {
            kind: if fs::symlink_metadata(dst.join(&rel)).is_ok() {
                "replace-tree-entry"
            } else {
                "create-tree-entry"
            }
            .into(),
            path: dst.join(&rel).display().to_string(),
            module_id: module_id.map(ToOwned::to_owned),
        });
    }
    if apply {
        let key = invocation.ok_or_else(|| "capsule-install-invocation-missing".to_string())?;
        comparison::execute(
            "capsule-install-tree",
            || {
                if fs::symlink_metadata(dst).is_ok() {
                    Ok(Some(crate::tools::files::remove_dir_capture(dst)?))
                } else {
                    Ok(None)
                }
            },
            |current| {
                if current.as_ref().is_some_and(|image| {
                    crate::tools::files::remove_dir_exact(image, &source_image)
                }) {
                    DiffDecision::Empty
                } else {
                    DiffDecision::Different
                }
            },
            |authorization, _| {
                if target_image.is_none() {
                    crate::tools::files::make_dir(authorization, key, dst)?;
                }
                crate::tools::files::remove_dir_replace(authorization, key, dst, &source_image)
                    .map(|_| ())
            },
        )?;
    }
    Ok(())
}

fn sorted_tree_paths(root: &Path) -> Result<Vec<PathBuf>, String> {
    fn walk(root: &Path, current: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
        for entry in fs::read_dir(current).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            out.push(
                path.strip_prefix(root)
                    .map_err(|e| e.to_string())?
                    .to_path_buf(),
            );
            if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                walk(root, &path, out)?;
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    out.sort_by(|a, b| rel_slash(a).cmp(&rel_slash(b)));
    Ok(out)
}

fn converge_exact_node(
    src: &Path,
    dst: &Path,
    apply: bool,
    changes: &mut Vec<InstallChange>,
    module_id: Option<&str>,
    invocation: Option<InvocationKey>,
) -> Result<(), String> {
    let source_image = crate::tools::files::remove_dir_capture(src)?;
    let target_image = fs::symlink_metadata(dst)
        .ok()
        .map(|_| crate::tools::files::remove_dir_capture(dst))
        .transpose()?;
    if target_image
        .as_ref()
        .is_some_and(|image| crate::tools::files::remove_dir_exact(image, &source_image))
    {
        return Ok(());
    }
    changes.push(InstallChange {
        kind: if target_image.is_some() {
            "replace-exact-node"
        } else {
            "create-exact-node"
        }
        .into(),
        path: dst.display().to_string(),
        module_id: module_id.map(ToOwned::to_owned),
    });
    if apply {
        let key = invocation.ok_or_else(|| "capsule-install-invocation-missing".to_string())?;
        comparison::execute(
            "capsule-install-exact-node",
            || {
                Ok(fs::symlink_metadata(dst)
                    .ok()
                    .map(|_| crate::tools::files::remove_dir_capture(dst))
                    .transpose()?)
            },
            |current| {
                if current.as_ref().is_some_and(|image| {
                    crate::tools::files::remove_dir_exact(image, &source_image)
                }) {
                    DiffDecision::Empty
                } else {
                    DiffDecision::Different
                }
            },
            |authorization, _| {
                if fs::symlink_metadata(dst).is_err() {
                    if let Some(parent) = dst.parent() {
                        crate::tools::files::make_dir(authorization, key, parent)?;
                    }
                    crate::tools::files::make_dir(authorization, key, dst)?;
                }
                crate::tools::files::remove_dir_replace(authorization, key, dst, &source_image)
                    .map(|_| ())
            },
        )?;
    }
    Ok(())
}

fn write_json_atomic<T: Serialize>(
    path: &Path,
    value: &T,
    key: InvocationKey,
) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())? + "\n";
    write_bytes_atomic(path, text.as_bytes(), key)
}
fn write_manifest_json_atomic<T: Serialize>(
    path: &Path,
    value: &T,
    key: InvocationKey,
) -> Result<(), String> {
    write_json_atomic(path, value, key)
}
fn write_receipt_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let value = serde_json::to_value(value).map_err(|e| e.to_string())?;
    attest::write_json_atomic(path, &value)
}

fn write_bytes_atomic(path: &Path, bytes: &[u8], key: InvocationKey) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        comparison::execute(
            "capsule-payload-parent",
            || Ok(fs::symlink_metadata(parent).is_ok()),
            |present| {
                if *present {
                    DiffDecision::Empty
                } else {
                    DiffDecision::Different
                }
            },
            |authorization, _| crate::tools::files::make_dir(authorization, key, parent),
        )?;
    }
    comparison::execute(
        "capsule-payload-write",
        || Ok(fs::read(path).ok().as_deref() == Some(bytes)),
        |same| {
            if *same {
                DiffDecision::Empty
            } else {
                DiffDecision::Different
            }
        },
        |authorization, _| {
            crate::tools::files::file_write(
                authorization,
                key,
                path,
                bytes,
                crate::tools::files::FileWriteOptions {
                    write_bytes: true,
                    mode: None,
                    uid: None,
                    gid: None,
                    backup_to: None,
                },
            )
            .map(|_| ())
        },
    )?;
    Ok(())
}

fn git_head_sha(root: &Path) -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if sha.len() != 40 || !sha.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    Some(sha)
}

fn rel_slash(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}
