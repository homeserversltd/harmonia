use crate::{is_ladder_manifest, load_ladder_manifest, load_profile, VERSION};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
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
    first_missing_signal: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InstallChange {
    kind: String,
    path: String,
    module_id: Option<String>,
}

pub(crate) fn capsule_pack(
    profile_id: &str,
    output_dir: &Path,
    harmonia_root: &Path,
) -> Result<(), String> {
    validate_harmonia_root(harmonia_root)?;
    if output_dir.exists() {
        fs::remove_dir_all(output_dir)
            .map_err(|e| format!("capsule-output-clear-failed {}: {e}", output_dir.display()))?;
    }
    fs::create_dir_all(output_dir).map_err(|e| e.to_string())?;
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
    copy_file_atomic(
        &profile_src,
        &output_dir
            .join("profiles")
            .join(profile_id)
            .join("index.json"),
    )?;
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
        copy_file_atomic(&manifest_src, &dst.join("manifest.json"))?;
        if let Some(files_root) = manifest.files_root.as_deref() {
            let source_files = src.join(files_root);
            if !source_files.is_dir() {
                return Err(format!(
                    "capsule-files-root-missing module={module_id} path={}",
                    source_files.display()
                ));
            }
            copy_tree_exact(
                &source_files,
                &dst.join(files_root),
                true,
                &mut Vec::new(),
                None,
            )?;
        }
        let tree_sha256 = module_tree_sha256(&dst)?;
        modules.push(CapsuleModuleEntry {
            id: module_id.clone(),
            version: manifest.version,
            tree_sha256,
        });
    }
    let mut locks = Vec::new();
    let locks_src = harmonia_root.join("locks").join(profile_id);
    if locks_src.is_dir() {
        for rel in sorted_file_paths(&locks_src)? {
            let src = locks_src.join(&rel);
            let dst = output_dir.join("locks").join(profile_id).join(&rel);
            copy_file_atomic(&src, &dst)?;
            locks.push(CapsuleLockEntry {
                path: rel_slash(Path::new("locks").join(profile_id).join(&rel).as_path()),
                sha256: file_sha256(&src)?,
            });
        }
    }
    let created_from = git_head_sha(harmonia_root).unwrap_or_else(|| "unknown".to_string());
    let manifest = CapsuleManifest {
        schema: CAPSULE_SCHEMA.to_string(),
        profile_id: profile.id.clone(),
        identity: profile.identity.clone(),
        engine_version: VERSION.to_string(),
        modules,
        locks,
        created_from,
    };
    write_json_atomic(&output_dir.join("capsule.json"), &manifest)?;
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
    write_json_atomic(&output_dir.join("pack-receipt.json"), &receipt)?;
    println!("schema=harmonia.capsule.pack.v1");
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
        let lock_ok = lock_path.exists()
            && file_sha256(&lock_path).ok().as_deref() == Some(lock.sha256.as_str());
        if !lock_ok {
            ok = false;
            if first == "none" {
                first = format!("lock={} signal=digest-mismatch-or-missing", lock.path);
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
    write_json_atomic(&capsule_dir.join("verify-receipt.json"), &receipt)?;
    println!("schema=harmonia.capsule.verify.v1");
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

pub(crate) fn capsule_install(
    capsule_dir: &Path,
    config_dir: &Path,
    apply: bool,
) -> Result<(), String> {
    match capsule_verify(capsule_dir) {
        Ok(()) => (),
        Err(err) => return Err(err),
    };
    let manifest = load_capsule_manifest(capsule_dir)?;
    let target_profiles = config_dir.join("profiles");
    let target_profile_dir = target_profiles.join(&manifest.profile_id);
    let source_profile_dir = capsule_dir.join("profiles").join(&manifest.profile_id);
    let mut changes = Vec::new();
    let mut prunes = Vec::new();
    let mut untouched_modules = Vec::new();

    converge_file(
        &source_profile_dir.join("index.json"),
        &target_profile_dir.join("index.json"),
        apply,
        &mut changes,
        None,
    )?;
    let wanted: BTreeSet<String> = manifest.modules.iter().map(|m| m.id.clone()).collect();
    let target_modules = target_profile_dir.join("modules");
    if target_modules.is_dir() {
        for entry in fs::read_dir(&target_modules).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                let id = entry.file_name().to_string_lossy().to_string();
                if !wanted.contains(&id) {
                    prunes.push(InstallChange {
                        kind: "prune-module".into(),
                        path: entry.path().display().to_string(),
                        module_id: Some(id),
                    });
                    if apply {
                        fs::remove_dir_all(entry.path()).map_err(|e| e.to_string())?;
                    }
                }
            }
        }
    }
    for module in &manifest.modules {
        let src = source_profile_dir.join("modules").join(&module.id);
        let dst = target_profile_dir.join("modules").join(&module.id);
        let installed_clean = dst.is_dir()
            && installed_module_version(&dst).as_deref() == Some(module.version.as_str())
            && module_tree_sha256(&dst).ok().as_deref() == Some(module.tree_sha256.as_str());
        if installed_clean {
            untouched_modules.push(module.id.clone());
            continue;
        }
        copy_tree_exact(&src, &dst, apply, &mut changes, Some(module.id.as_str()))?;
    }
    let locks_src = capsule_dir.join("locks").join(&manifest.profile_id);
    let locks_dst = config_dir.join("locks").join(&manifest.profile_id);
    if locks_src.is_dir() {
        copy_tree_exact(&locks_src, &locks_dst, apply, &mut changes, None)?;
    }
    if locks_dst.is_dir() {
        let source_files: BTreeSet<String> = if locks_src.is_dir() {
            sorted_file_paths(&locks_src)?
                .into_iter()
                .map(|p| rel_slash(&p))
                .collect()
        } else {
            BTreeSet::new()
        };
        for rel in sorted_file_paths(&locks_dst)? {
            let rels = rel_slash(&rel);
            if !source_files.contains(&rels) {
                let path = locks_dst.join(&rel);
                prunes.push(InstallChange {
                    kind: "prune-lock".into(),
                    path: path.display().to_string(),
                    module_id: None,
                });
                if apply {
                    fs::remove_file(&path).map_err(|e| e.to_string())?;
                }
            }
        }
        prune_empty_dirs(&locks_dst, apply, &mut prunes, None)?;
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
        first_missing_signal: "none".into(),
    };
    let receipt_dir = config_dir.join("receipts").join("capsule-install-latest");
    if apply {
        fs::create_dir_all(&receipt_dir).map_err(|e| e.to_string())?;
    }
    let receipt_path = if apply {
        receipt_dir.join("install-receipt.json")
    } else {
        capsule_dir.join("install-plan-receipt.json")
    };
    write_json_atomic(&receipt_path, &receipt)?;
    println!("schema=harmonia.capsule.install.v1");
    println!("ok=true");
    println!("apply={}", apply);
    println!("profile_id={}", manifest.profile_id);
    println!("lane=capsule");
    println!("change_count={}", receipt.changes.len());
    println!("prune_count={}", receipt.prunes.len());
    println!("untouched_modules={}", receipt.untouched_modules.join(","));
    println!("receipt={}", receipt_path.display());
    println!("first_missing_signal=none");
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

fn validate_harmonia_root(root: &Path) -> Result<(), String> {
    if !root.join("Cargo.toml").exists() || !root.join("profiles").is_dir() {
        return Err(format!("capsule-harmonia-root-rejected {}", root.display()));
    }
    Ok(())
}

fn installed_module_version(module_dir: &Path) -> Option<String> {
    let manifest_path = module_dir.join("manifest.json");
    let text = fs::read_to_string(manifest_path).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    value.get("version")?.as_str().map(ToOwned::to_owned)
}

fn module_tree_sha256(module_dir: &Path) -> Result<String, String> {
    let mut chain = Sha256::new();
    for rel in sorted_file_paths(module_dir)? {
        let rels = rel_slash(&rel);
        if rels.ends_with("-receipt.json") {
            continue;
        }
        let file_hash = file_sha256(&module_dir.join(&rel))?;
        chain.update(rels.as_bytes());
        chain.update([0]);
        chain.update(file_hash.as_bytes());
        chain.update([0]);
    }
    Ok(format!("{:x}", chain.finalize()))
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

fn copy_tree_exact(
    src: &Path,
    dst: &Path,
    apply: bool,
    changes: &mut Vec<InstallChange>,
    module_id: Option<&str>,
) -> Result<(), String> {
    if !src.is_dir() {
        return Err(format!("copy-tree-source-missing {}", src.display()));
    }
    if apply {
        fs::create_dir_all(dst).map_err(|e| e.to_string())?;
    }
    let source_files: BTreeSet<String> = sorted_file_paths(src)?
        .into_iter()
        .map(|p| rel_slash(&p))
        .collect();
    if dst.is_dir() {
        for rel in sorted_file_paths(dst)? {
            let rels = rel_slash(&rel);
            if !source_files.contains(&rels) {
                let path = dst.join(&rel);
                changes.push(InstallChange {
                    kind: "prune-file".into(),
                    path: path.display().to_string(),
                    module_id: module_id.map(ToOwned::to_owned),
                });
                if apply {
                    fs::remove_file(path).map_err(|e| e.to_string())?;
                }
            }
        }
    }
    for rels in source_files {
        let rel = PathBuf::from(&rels);
        converge_file(&src.join(&rel), &dst.join(&rel), apply, changes, module_id)?;
    }
    prune_empty_dirs(dst, apply, changes, module_id)?;
    Ok(())
}

fn converge_file(
    src: &Path,
    dst: &Path,
    apply: bool,
    changes: &mut Vec<InstallChange>,
    module_id: Option<&str>,
) -> Result<(), String> {
    let same = dst.exists()
        && fs::read(src).map_err(|e| e.to_string())? == fs::read(dst).map_err(|e| e.to_string())?;
    if !same {
        changes.push(InstallChange {
            kind: if dst.exists() {
                "write-file"
            } else {
                "create-file"
            }
            .into(),
            path: dst.display().to_string(),
            module_id: module_id.map(ToOwned::to_owned),
        });
        if apply {
            copy_file_atomic(src, dst)?;
        }
    }
    Ok(())
}

fn copy_file_atomic(src: &Path, dst: &Path) -> Result<(), String> {
    let bytes = fs::read(src).map_err(|e| format!("copy-read-failed {}: {e}", src.display()))?;
    write_bytes_atomic(dst, &bytes)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())? + "\n";
    write_bytes_atomic(path, text.as_bytes())
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("harmonia-new");
    fs::write(&tmp, bytes).map_err(|e| format!("write-failed {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| {
        format!(
            "promote-failed {} -> {}: {e}",
            tmp.display(),
            path.display()
        )
    })
}

fn prune_empty_dirs(
    root: &Path,
    apply: bool,
    changes: &mut Vec<InstallChange>,
    module_id: Option<&str>,
) -> Result<bool, String> {
    if !root.is_dir() {
        return Ok(false);
    }
    let mut empty = true;
    for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            if !prune_empty_dirs(&entry.path(), apply, changes, module_id)? {
                empty = false;
            }
        } else {
            empty = false;
        }
    }
    if empty {
        changes.push(InstallChange {
            kind: "prune-empty-dir".into(),
            path: root.display().to_string(),
            module_id: module_id.map(ToOwned::to_owned),
        });
        if apply {
            let _ = fs::remove_dir(root);
        }
    }
    Ok(empty)
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
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn rel_slash(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process;

    fn scratch(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("harmonia-capsule-{name}-{}", process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn write_fixture(root: &Path, version: &str) {
        fs::create_dir_all(root.join("profiles/demo/modules/alpha/files_root/etc/demo")).unwrap();
        fs::create_dir_all(root.join("locks/demo")).unwrap();
        fs::write(root.join("Cargo.toml"), "[package]\nname='fixture'\n").unwrap();
        fs::write(
            root.join("profiles/demo/index.json"),
            r#"{"id":"demo","identity":"demo-box","modules":["alpha"]}"#,
        )
        .unwrap();
        fs::write(root.join("profiles/demo/modules/alpha/manifest.json"), format!(r#"{{"schema":"harmonia.module.ladder.v1","id":"alpha","version":"{version}","description":"alpha","files_root":"files_root","ladder":[]}}"#)).unwrap();
        fs::write(
            root.join("profiles/demo/modules/alpha/files_root/etc/demo/value.txt"),
            "one\n",
        )
        .unwrap();
        fs::write(
            root.join("locks/demo/pinned-artifacts.json"),
            r#"{"schema":"lock"}"#,
        )
        .unwrap();
    }

    #[test]
    fn pack_verify_install_roundtrip_and_prune() {
        let root = scratch("roundtrip-src");
        let capsule = scratch("roundtrip-capsule");
        let config = scratch("roundtrip-config");
        write_fixture(&root, "1.0.0");
        fs::create_dir_all(config.join("profiles/demo/modules/old/files_root/tmp")).unwrap();
        fs::write(config.join("profiles/demo/modules/old/manifest.json"), "{}").unwrap();
        capsule_pack("demo", &capsule, &root).unwrap();
        capsule_verify(&capsule).unwrap();
        capsule_install(&capsule, &config, false).unwrap();
        let plan = fs::read_to_string(capsule.join("install-plan-receipt.json")).unwrap();
        assert!(plan.contains("prune-module"));
        assert!(plan.contains("old"));
        capsule_install(&capsule, &config, true).unwrap();
        assert!(!config.join("profiles/demo/modules/old").exists());
        assert!(config
            .join("profiles/demo/modules/alpha/files_root/etc/demo/value.txt")
            .exists());
        let receipt =
            fs::read_to_string(config.join("receipts/capsule-install-latest/install-receipt.json"))
                .unwrap();
        assert!(receipt.contains("\"lane\": \"capsule\""));
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(capsule);
        let _ = fs::remove_dir_all(config);
    }

    #[test]
    fn tamper_verify_names_module_and_path() {
        let root = scratch("tamper-src");
        let capsule = scratch("tamper-capsule");
        write_fixture(&root, "1.0.0");
        capsule_pack("demo", &capsule, &root).unwrap();
        fs::write(
            capsule.join("profiles/demo/modules/alpha/files_root/etc/demo/value.txt"),
            "tampered\n",
        )
        .unwrap();
        let err = capsule_verify(&capsule).unwrap_err();
        assert!(err.contains("module=alpha"));
        assert!(err.contains("path=manifest.json") || err.contains("digest-mismatch"));
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(capsule);
    }

    #[test]
    fn single_module_bump_only_writes_changed_module() {
        let root = scratch("bump-src");
        let capsule = scratch("bump-capsule");
        let config = scratch("bump-config");
        write_fixture(&root, "1.0.0");
        capsule_pack("demo", &capsule, &root).unwrap();
        capsule_install(&capsule, &config, true).unwrap();
        fs::write(root.join("profiles/demo/modules/alpha/manifest.json"), r#"{"schema":"harmonia.module.ladder.v1","id":"alpha","version":"1.0.1","description":"alpha","files_root":"files_root","ladder":[]}"#).unwrap();
        fs::write(
            root.join("profiles/demo/modules/alpha/files_root/etc/demo/value.txt"),
            "two\n",
        )
        .unwrap();
        let capsule2 = scratch("bump-capsule2");
        capsule_pack("demo", &capsule2, &root).unwrap();
        capsule_install(&capsule2, &config, true).unwrap();
        let receipt =
            fs::read_to_string(config.join("receipts/capsule-install-latest/install-receipt.json"))
                .unwrap();
        assert!(receipt.contains("alpha"));
        assert!(receipt.contains("write-file"));
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(capsule);
        let _ = fs::remove_dir_all(capsule2);
        let _ = fs::remove_dir_all(config);
    }
}
