use crate::*;
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MoltMode {
    Copy,
    Symlink,
}

impl MoltMode {
    pub(crate) fn parse(value: Option<String>) -> Result<Self, String> {
        match value.as_deref().unwrap_or("copy") {
            "copy" => Ok(Self::Copy),
            "symlink" | "link" => Ok(Self::Symlink),
            other => Err(format!("molt-mode-unsupported-{other}")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Copy => "copy",
            Self::Symlink => "symlink",
        }
    }
}

#[derive(Debug, Serialize)]
struct MoltArtifact {
    kind: &'static str,
    source: String,
    output: String,
    mode: &'static str,
}

#[derive(Debug, Serialize)]
struct MoltReceipt {
    schema: &'static str,
    ok: bool,
    profile_id: String,
    identity: String,
    harmonia_root: String,
    output_dir: String,
    mode: &'static str,
    artifacts: Vec<MoltArtifact>,
    refreshed_modules: Vec<String>,
    untouched_modules: Vec<String>,
    pruned_modules: Vec<String>,
    pruned_paths: Vec<String>,
    subscription_path: String,
    subscription_modules: Vec<SubscriptionModuleStatus>,
    subscription_updated: bool,
    first_missing_signal: &'static str,
}

pub(crate) fn molt(
    harmonia_root: &Path,
    profile_id: &str,
    output_dir: &Path,
    receipt_dir: &Path,
    mode: MoltMode,
) -> Result<(), String> {
    molt_at_subscription_path(
        harmonia_root,
        profile_id,
        output_dir,
        receipt_dir,
        &subscription_path(),
        mode,
    )
}

pub(crate) fn molt_at_subscription_path(
    harmonia_root: &Path,
    profile_id: &str,
    output_dir: &Path,
    receipt_dir: &Path,
    subscription_path: &Path,
    mode: MoltMode,
) -> Result<(), String> {
    molt_at_subscription_path_for_modules(
        harmonia_root,
        profile_id,
        output_dir,
        receipt_dir,
        subscription_path,
        mode,
        &BTreeSet::new(),
    )
}

pub(crate) fn molt_at_subscription_path_for_modules(
    harmonia_root: &Path,
    profile_id: &str,
    output_dir: &Path,
    receipt_dir: &Path,
    subscription_path: &Path,
    mode: MoltMode,
    forced_modules: &BTreeSet<String>,
) -> Result<(), String> {
    let key = crate::invocation_face::mint(&["molt".into(), "--apply".into()])
        .0
        .ok_or_else(|| "molt-invocation-key-missing".to_string())?;
    validate_harmonia_config_root(harmonia_root)?;
    let profile_path = harmonia_root
        .join("profiles")
        .join(profile_id)
        .join("index.json");
    let profile = load_profile(&profile_path)
        .map_err(|e| format!("molt-profile-read-failed {}: {e}", profile_path.display()))?;
    if profile.id != profile_id {
        return Err(format!(
            "molt-profile-id-mismatch expected={} got={}",
            profile_id, profile.id
        ));
    }

    let subscription_modules = profile
        .modules
        .iter()
        .map(|id| {
            let module_root = harmonia_root
                .join("profiles")
                .join(&profile.id)
                .join("modules");
            let module_dir = super::resolve_module_dir(&module_root, id)?;
            Ok(SubscriptionModuleUpdate {
                id: id.clone(),
                version: installed_module_version(&module_dir)
                    .unwrap_or_else(|| "sidecar".to_string()),
                tree_sha256: crate::atoms::tree_hash::content_tree_sha256(&module_dir)?,
                received_at_run_id: run_id_from_stamp(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let subscription_statuses =
        diff_subscription_modules(&subscription_path, &subscription_modules)?
            .into_iter()
            .map(|mut status| {
                // Ordinary molt is version-pinned. A same-version capsule is current
                // for subscription purposes; the installed tree is compared separately
                // by StageProfile and may trigger a targeted lawful refresh.
                if status.record_version.as_deref() == Some(status.capsule_version.as_str()) {
                    status.status = "current".to_string();
                }
                status
            })
            .collect::<Vec<_>>();
    let mut artifacts = Vec::new();
    let mut refreshed_modules = Vec::new();
    let mut pruned_paths = Vec::new();
    let mut untouched_modules = Vec::new();
    export_one(
        &key,
        &profile_path,
        &output_dir.join("index.json"),
        "profile-index",
        mode,
        &mut artifacts,
    )?;

    for module in &profile.modules {
        let module_root = harmonia_root
            .join("profiles")
            .join(&profile.id)
            .join("modules");
        let module_dir = super::resolve_module_dir(&module_root, module)?;
        let shared = super::module_uses_shared_seat(&module_root, &module_dir);
        let shadow = output_dir
            .join("profiles")
            .join(&profile.id)
            .join("modules")
            .join(module);
        if shared && shadow.exists() {
            fs::remove_dir_all(&shadow).map_err(|e| {
                format!(
                    "molt-shared-module-shadow-prune-failed {}: {e}",
                    shadow.display()
                )
            })?;
            pruned_paths.push(shadow.display().to_string());
        }
        let sidecar = module_dir.join("sidecar.json");
        let manifest = module_dir.join("manifest.json");
        let module_output_dir = output_dir.join("modules").join(module);
        let source_tree_sha256 = crate::atoms::tree_hash::content_tree_sha256(&module_dir)?;
        let installed_clean = !forced_modules.contains(module)
            && module_output_dir.is_dir()
            && crate::atoms::tree_hash::content_tree_sha256(&module_output_dir)?
                == source_tree_sha256;
        if installed_clean {
            untouched_modules.push(module.clone());
            continue;
        }
        refreshed_modules.push(module.clone());
        if mode == MoltMode::Copy && forced_modules.contains(module) {
            // A forced module replacement is a complete module-root export.
            crate::tools::comparison::execute(
                "molt-forced-module-root-replace",
                || Ok(fs::symlink_metadata(&module_output_dir).is_ok()),
                |present| {
                    if *present {
                        crate::tools::comparison::DiffDecision::Different
                    } else {
                        crate::tools::comparison::DiffDecision::Empty
                    }
                },
                |authorization, _| {
                    crate::tools::files::remove_dir_authorized(
                        &authorization,
                        &key,
                        &module_output_dir,
                    )
                    .and_then(|_| verify_absent(&module_output_dir))
                },
            )?;
            export_tree(
                &key,
                &module_dir,
                &module_output_dir,
                "module-forced-root",
                mode,
                &mut artifacts,
                &mut pruned_paths,
            )?;
            continue;
        }
        if ensure_dir(&key, &module_dir, &module_output_dir)? {
            artifacts.push(MoltArtifact {
                kind: "export-directory",
                source: module_dir.display().to_string(),
                output: module_output_dir.display().to_string(),
                mode: mode.as_str(),
            });
        }
        if manifest.exists() && is_ladder_manifest(&manifest) {
            let ladder = load_ladder_manifest(&manifest)?;
            export_one(
                &key,
                &manifest,
                &module_output_dir.join("manifest.json"),
                "module-ladder-manifest",
                mode,
                &mut artifacts,
            )?;
            if let Some(files_root) = ladder.files_root.as_deref() {
                export_tree(
                    &key,
                    &module_dir.join(files_root),
                    &module_output_dir.join(files_root),
                    "module-ladder-files-root",
                    mode,
                    &mut artifacts,
                    &mut pruned_paths,
                )?;
            }
            export_module_sibling_files(
                &key,
                &module_dir,
                &module_output_dir,
                ladder.files_root.as_deref(),
                mode,
                &mut artifacts,
            )?;
        } else if sidecar.exists() {
            load_module(&sidecar)?;
            export_one(
                &key,
                &sidecar,
                &module_output_dir.join("sidecar.json"),
                "module-sidecar",
                mode,
                &mut artifacts,
            )?;
        } else {
            return Err(format!(
                "molt-module-manifest-missing {}",
                module_dir.display()
            ));
        }
    }

    let lock_path = harmonia_root
        .join("locks")
        .join(&profile.id)
        .join("pinned-artifacts.json");
    if lock_path.exists() {
        export_one(
            &key,
            &lock_path,
            &output_dir.join("locks").join("pinned-artifacts.json"),
            "profile-lock",
            mode,
            &mut artifacts,
        )?;
    }

    let output_module_root = output_dir.join("modules");
    let pruned_modules = prune_retired_module_dirs(&key, &output_module_root, &profile.modules)?;

    let lane = preserve_existing_lane_or_default(&subscription_path);
    update_subscription_record_with_invocation(
        &subscription_path,
        SubscriptionUpdate {
            lane,
            source: format!("molt:{}", harmonia_root.display()),
            ref_name: "molt".to_string(),
            selected_profile: profile.id.clone(),
            engine_version_received: VERSION.to_string(),
            modules: subscription_modules,
        },
        &key,
    )?;

    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
    let receipt = MoltReceipt {
        schema: "harmonia.molt.v1",
        ok: true,
        profile_id: profile.id.clone(),
        identity: profile.identity.clone(),
        harmonia_root: harmonia_root.display().to_string(),
        output_dir: output_dir.display().to_string(),
        mode: mode.as_str(),
        artifacts,
        refreshed_modules,
        untouched_modules,
        pruned_modules,
        pruned_paths,
        subscription_path: subscription_path.display().to_string(),
        subscription_modules: subscription_statuses,
        subscription_updated: true,
        first_missing_signal: "molt-none",
    };
    let receipt_text = serde_json::to_string_pretty(&receipt).map_err(|e| e.to_string())?;
    crate::atoms::attest::write_json_atomic(
        &receipt_dir.join("molt.json"),
        &serde_json::from_str(&receipt_text).map_err(|e| e.to_string())?,
    )?;

    println!("schema=harmonia.molt.v1");
    hyalos::forward_receipt(
        "schema=harmonia.molt.v1",
        &format!("schema=harmonia.molt.v1 ok={}", true),
        Some(serde_json::json!({"schema": "harmonia.molt.v1", "ok": true})),
        Some(true),
    );
    println!("ok=true");
    println!("profile_id={}", profile.id);
    println!("identity={}", profile.identity);
    println!("artifact_count={}", receipt.artifacts.len());
    println!("refreshed_modules={}", receipt.refreshed_modules.join(","));
    println!("untouched_modules={}", receipt.untouched_modules.join(","));
    println!("pruned_count={}", receipt.pruned_paths.len());
    println!("pruned_module_count={}", receipt.pruned_modules.len());
    println!("pruned_modules={}", receipt.pruned_modules.join(","));
    println!("output_dir={}", output_dir.display());
    println!("receipt_dir={}", receipt_dir.display());
    println!("subscription_path={}", receipt.subscription_path);
    println!("subscription_updated={}", receipt.subscription_updated);
    println!("first_missing_signal=molt-none");
    Ok(())
}

fn prune_retired_module_dirs(
    key: &crate::tools::files::InvocationKey,
    output_module_root: &Path,
    declared_modules: &[String],
) -> Result<Vec<String>, String> {
    let root_metadata = match fs::symlink_metadata(output_module_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.to_string()),
    };
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Ok(Vec::new());
    }

    let declared_modules: BTreeSet<&str> = declared_modules.iter().map(String::as_str).collect();
    let mut pruned_modules = Vec::new();
    for entry in fs::read_dir(output_module_root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let file_type = entry.file_type().map_err(|e| e.to_string())?;
        let module_name = entry.file_name().to_string_lossy().into_owned();
        let module_path = entry.path();
        if !file_type.is_dir()
            || file_type.is_symlink()
            || declared_modules.contains(module_name.as_str())
            || !is_staged_module_dir(&module_path)?
        {
            continue;
        }
        let restoration_testimony = crate::tools::files::remove_dir_capture(&module_path)?;
        crate::tools::comparison::execute(
            "molt-retired-tree-remove",
            || Ok(fs::symlink_metadata(&module_path).is_ok()),
            |present| {
                if *present {
                    crate::tools::comparison::DiffDecision::Different
                } else {
                    crate::tools::comparison::DiffDecision::Empty
                }
            },
            |authorization, _| crate::tools::files::remove_dir(&authorization, key, &module_path),
        )?;
        pruned_modules.push(module_name);
    }
    Ok(pruned_modules)
}

fn is_staged_module_dir(path: &Path) -> Result<bool, String> {
    for metadata_path in [path.join("manifest.json"), path.join("sidecar.json")] {
        match fs::symlink_metadata(metadata_path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                return Ok(true)
            }
            Ok(_) | Err(_) => {}
        }
    }
    Ok(false)
}

fn validate_harmonia_config_root(harmonia_root: &Path) -> Result<(), String> {
    if !harmonia_root.join("Cargo.toml").exists() {
        return Err(format!(
            "molt-harmonia-root-rejected missing=Cargo.toml root={}",
            harmonia_root.display()
        ));
    }
    if !harmonia_root.join("src/tools").is_dir() {
        return Err(format!(
            "molt-harmonia-root-rejected missing=src/tools root={}",
            harmonia_root.display()
        ));
    }
    if !harmonia_root.join("profiles").is_dir() {
        return Err(format!(
            "molt-harmonia-root-rejected missing=profiles root={}",
            harmonia_root.display()
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MetadataTail {
    mode: u32,
    uid: u32,
    gid: u32,
    no_follow: bool,
}

const DECLARED_NO_FOLLOW: bool = true;

fn metadata_tail(path: &Path) -> Result<MetadataTail, String> {
    let m = fs::symlink_metadata(path)
        .map_err(|e| format!("molt-metadata-tail-missing {}: {e}", path.display()))?;
    let no_follow = DECLARED_NO_FOLLOW;
    Ok(MetadataTail {
        mode: m.mode() & 0o7777,
        uid: m.uid(),
        gid: m.gid(),
        no_follow,
    })
}

#[derive(Debug, Clone)]
struct ExportPreimage {
    bytes: Option<Vec<u8>>,
    link_target: Option<PathBuf>,
    tail: MetadataTail,
}

fn capture_export_preimage(
    output: &Path,
    metadata: Option<&fs::Metadata>,
) -> Result<Option<ExportPreimage>, String> {
    let Some(metadata) = metadata else {
        return Ok(None);
    };
    let tail = metadata_tail(output)?;
    if metadata.file_type().is_symlink() {
        Ok(Some(ExportPreimage {
            bytes: None,
            link_target: Some(fs::read_link(output).map_err(|e| e.to_string())?),
            tail,
        }))
    } else {
        Ok(Some(ExportPreimage {
            bytes: Some(fs::read(output).map_err(|e| e.to_string())?),
            link_target: None,
            tail,
        }))
    }
}

fn ensure_tail_can_converge(desired: &MetadataTail, path: &Path) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0
        && (desired.uid != unsafe { libc::geteuid() } || desired.gid != unsafe { libc::getegid() })
    {
        return Err(format!("molt-owner-cannot-converge {}", path.display()));
    }
    Ok(())
}

fn converge_file_tail(
    authorization: &crate::tools::files::ActionAuthorization,
    key: &crate::tools::files::InvocationKey,
    path: &Path,
    desired: MetadataTail,
) -> Result<(), String> {
    crate::tools::files::change_mode(
        authorization,
        key,
        &crate::tools::files::ChangeModePlan {
            path: path.to_path_buf(),
            mode: Some(desired.mode),
            no_follow: desired.no_follow,
        },
    )?;
    crate::tools::files::change_owner(
        authorization,
        key,
        &crate::tools::files::ChangeOwnerPlan {
            path: path.to_path_buf(),
            uid: Some(desired.uid),
            gid: Some(desired.gid),
            no_follow: desired.no_follow,
        },
    )
}

fn verify_absent(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
        Ok(_) => Err("target-remains".into()),
    }
}

fn transactional_export_failure(
    authorization: &crate::tools::files::ActionAuthorization,
    key: &crate::tools::files::InvocationKey,
    output: &Path,
    preimage: Option<&ExportPreimage>,
    error: String,
) -> String {
    let restoration = match preimage {
        Some(old) => {
            let Some(bytes) = old.bytes.as_deref() else {
                return format!("{error}; restoration-failed prior-kind-not-file");
            };
            crate::tools::files::file_write(
                authorization,
                key,
                output,
                bytes,
                crate::tools::files::FileWriteOptions {
                    write_bytes: true,
                    mode: Some(old.tail.mode),
                    uid: Some(old.tail.uid),
                    gid: Some(old.tail.gid),
                    backup_to: None,
                },
            )
            .and_then(|_| verify_file_restore(output, bytes, old.tail))
        }
        None => match fs::symlink_metadata(output) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.to_string()),
            Ok(_) => crate::tools::files::remove_file(authorization, key, output)
                .and_then(|_| verify_absent(output)),
        },
    };
    match restoration {
        Ok(()) => error,
        Err(restoration) => format!("{error}; restoration-failed {restoration}"),
    }
}

fn converge_link_tail(
    authorization: &crate::tools::files::ActionAuthorization,
    key: &crate::tools::files::InvocationKey,
    path: &Path,
    desired: MetadataTail,
) -> Result<(), String> {
    if desired.uid != unsafe { libc::geteuid() } || desired.gid != unsafe { libc::getegid() } {
        return Err(format!(
            "molt-export-link-tail-cannot-converge {}",
            path.display()
        ));
    }
    crate::tools::files::change_owner(
        authorization,
        key,
        &crate::tools::files::ChangeOwnerPlan {
            path: path.to_path_buf(),
            uid: Some(desired.uid),
            gid: Some(desired.gid),
            no_follow: true,
        },
    )
}

fn transactional_link_failure(
    authorization: &crate::tools::files::ActionAuthorization,
    key: &crate::tools::files::InvocationKey,
    output: &Path,
    preimage: Option<&ExportPreimage>,
    error: String,
) -> String {
    let restoration: Result<(), String> = (|| {
        match fs::symlink_metadata(output) {
            Ok(_) => {
                crate::tools::files::remove_file(authorization, key, output)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        if let Some(old) = preimage {
            let target = old.link_target.as_ref().ok_or("prior-kind-not-link")?;
            crate::tools::files::make_link(authorization, key, target, output)?;
            crate::tools::files::change_owner(
                authorization,
                key,
                &crate::tools::files::ChangeOwnerPlan {
                    path: output.to_path_buf(),
                    uid: Some(old.tail.uid),
                    gid: Some(old.tail.gid),
                    no_follow: true,
                },
            )?;
            if !fs::symlink_metadata(output)
                .map_err(|e| e.to_string())?
                .file_type()
                .is_symlink()
            {
                return Err("restored-path-not-symlink".into());
            }
            if fs::read_link(output).map_err(|e| e.to_string())? != *target {
                return Err("link-target-mismatch".into());
            }
            if metadata_tail(output)? != old.tail {
                return Err("link-preimage-mismatch".into());
            }
        } else {
            verify_absent(output)?;
        }
        Ok(())
    })();
    match restoration {
        Ok(()) => error,
        Err(restoration) => format!("{error}; restoration-failed {restoration}"),
    }
}

fn verify_file_restore(path: &Path, bytes: &[u8], tail: MetadataTail) -> Result<(), String> {
    if fs::read(path).map_err(|e| e.to_string())? != bytes || metadata_tail(path)? != tail {
        return Err("file-preimage-mismatch".into());
    }
    Ok(())
}

fn export_one(
    key: &crate::tools::files::InvocationKey,
    source: &Path,
    output: &Path,
    kind: &'static str,
    mode: MoltMode,
    artifacts: &mut Vec<MoltArtifact>,
) -> Result<(), String> {
    let source_observed = source.to_path_buf();
    let output_observed = output.to_path_buf();
    let comparison = crate::tools::comparison::execute(
        "molt-export",
        || export_is_current(&source_observed, &output_observed, mode),
        |same| {
            if *same {
                crate::tools::comparison::DiffDecision::Empty
            } else {
                crate::tools::comparison::DiffDecision::Different
            }
        },
        |authorization, _| {
            let source_tail = metadata_tail(source)?;
            let output_meta = fs::symlink_metadata(output).ok();
            if let Some(meta) = &output_meta {
                let permitted = match mode {
                    MoltMode::Copy => meta.is_file() && !meta.file_type().is_symlink(),
                    MoltMode::Symlink => meta.file_type().is_symlink(),
                };
                if !permitted {
                    return Err(format!("molt-output-kind-collision {}", output.display()));
                }
            }
            ensure_tail_can_converge(&source_tail, output)?;
            if mode == MoltMode::Symlink
                && (source_tail.uid != unsafe { libc::geteuid() }
                    || source_tail.gid != unsafe { libc::getegid() })
            {
                return Err(format!(
                    "molt-export-link-tail-cannot-converge {}",
                    output.display()
                ));
            }
            let preimage = capture_export_preimage(output, output_meta.as_ref())?;
            let parent = output
                .parent()
                .ok_or_else(|| format!("molt-output-parent-missing {}", output.display()))?;
            let source_parent = source
                .parent()
                .ok_or_else(|| format!("molt-source-parent-missing {}", source.display()))?;
            if ensure_dir(key, source_parent, parent)? {
                artifacts.push(MoltArtifact {
                    kind: "export-directory",
                    source: source_parent.display().to_string(),
                    output: parent.display().to_string(),
                    mode: mode.as_str(),
                });
            }
            let source_path = source.to_path_buf();
            let output_path = output.to_path_buf();
            match mode {
                MoltMode::Copy => {
                    let result = crate::tools::files::copy_file(
                        &authorization,
                        key,
                        &crate::tools::files::CopyFilePlan {
                            source: source_path.clone(),
                            target: output_path.clone(),
                            mode: None,
                            uid: None,
                            gid: None,
                            no_follow: source_tail.no_follow,
                            restore: None,
                        },
                    )
                    .and_then(|_| converge_file_tail(&authorization, key, output, source_tail))
                    .and_then(|_| {
                        if export_is_current(&source_path, &output_path, MoltMode::Copy)? {
                            Ok(())
                        } else {
                            Err(format!(
                                "molt-export-postimage-mismatch {}",
                                output_path.display()
                            ))
                        }
                    });
                    result.map_err(|error| {
                        transactional_export_failure(
                            &authorization,
                            key,
                            output,
                            preimage.as_ref(),
                            error,
                        )
                    })
                }
                MoltMode::Symlink => {
                    let result = (|| {
                        if fs::symlink_metadata(&output_path).is_ok() {
                            crate::tools::files::remove_file(&authorization, key, &output_path)?;
                        }
                        crate::tools::files::make_link(
                            &authorization,
                            key,
                            &source_path,
                            &output_path,
                        )?;
                        converge_link_tail(&authorization, key, &output_path, source_tail)?;
                        if export_is_current(&source_path, &output_path, MoltMode::Symlink)? {
                            Ok(())
                        } else {
                            Err(format!(
                                "molt-export-postimage-mismatch {}",
                                output_path.display()
                            ))
                        }
                    })();
                    result.map_err(|error| {
                        transactional_link_failure(
                            &authorization,
                            key,
                            output,
                            preimage.as_ref(),
                            error,
                        )
                    })
                }
            }
        },
    )?;
    if !matches!(
        comparison,
        crate::tools::comparison::ComparisonRun::Moved { .. }
    ) {
        return Ok(());
    }
    artifacts.push(MoltArtifact {
        kind,
        source: source.display().to_string(),
        output: output.display().to_string(),
        mode: mode.as_str(),
    });
    Ok(())
}

fn ensure_dir(
    key: &crate::tools::files::InvocationKey,
    source: &Path,
    path: &Path,
) -> Result<bool, String> {
    let desired = metadata_tail(source)?;
    let path = path.to_path_buf();
    let run = crate::tools::comparison::execute(
        "molt-ensure-dir",
        || {
            Ok(match fs::symlink_metadata(&path) {
                Ok(metadata) => Some((
                    metadata.is_dir() && !metadata.file_type().is_symlink(),
                    metadata_tail(&path)?,
                )),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.to_string()),
            })
        },
        |observed| {
            if observed
                .as_ref()
                .is_some_and(|(is_dir, tail)| *is_dir && *tail == desired)
            {
                crate::tools::comparison::DiffDecision::Empty
            } else {
                crate::tools::comparison::DiffDecision::Different
            }
        },
        |authorization, observed| {
            if let Some((is_dir, before)) = observed {
                if !is_dir {
                    return Err(format!("molt-output-kind-collision {}", path.display()));
                }
                ensure_tail_can_converge(&desired, &path)?;
                let result = apply_dir_tail(&authorization, key, &path, desired)
                    .and_then(|_| verify_dir_tail(&path, desired));
                return result.map_err(|error| {
                    let rollback = apply_dir_tail(&authorization, key, &path, *before)
                        .and_then(|_| verify_dir_tail(&path, *before));
                    match rollback {
                        Ok(()) => error,
                        Err(rollback) => format!("{error}; restoration-failed {rollback}"),
                    }
                });
            }
            ensure_tail_can_converge(&desired, &path)?;
            let result = crate::tools::files::make_dir(&authorization, key, &path)
                .and_then(|_| apply_dir_tail(&authorization, key, &path, desired))
                .and_then(|_| verify_dir_tail(&path, desired));
            result.map_err(|error| {
                let rollback = crate::tools::files::remove_dir(&authorization, key, &path)
                    .and_then(|_| verify_absent(&path));
                match rollback {
                    Ok(()) => error,
                    Err(rollback) => format!("{error}; restoration-failed {rollback}"),
                }
            })
        },
    )?;
    Ok(matches!(
        run,
        crate::tools::comparison::ComparisonRun::Moved { .. }
    ))
}

fn verify_dir_tail(path: &Path, desired: MetadataTail) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("directory-postimage-kind-mismatch".into());
    }
    if metadata_tail(path)? != desired {
        return Err("directory-postimage-metadata-mismatch".into());
    }
    Ok(())
}

fn apply_dir_tail(
    authorization: &crate::tools::files::ActionAuthorization,
    key: &crate::tools::files::InvocationKey,
    path: &Path,
    desired: MetadataTail,
) -> Result<(), String> {
    crate::tools::files::change_mode(
        authorization,
        key,
        &crate::tools::files::ChangeModePlan {
            path: path.to_path_buf(),
            mode: Some(desired.mode),
            no_follow: true,
        },
    )?;
    crate::tools::files::change_owner(
        authorization,
        key,
        &crate::tools::files::ChangeOwnerPlan {
            path: path.to_path_buf(),
            uid: Some(desired.uid),
            gid: Some(desired.gid),
            no_follow: true,
        },
    )
}

fn export_is_current(source: &Path, output: &Path, mode: MoltMode) -> Result<bool, String> {
    let output_metadata = match fs::symlink_metadata(output) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.to_string()),
    };
    match mode {
        MoltMode::Copy => {
            if !output_metadata.is_file() || output_metadata.file_type().is_symlink() {
                return Ok(false);
            }
            let source_metadata = fs::symlink_metadata(source).map_err(|e| e.to_string())?;
            if file_mode(&source_metadata) != file_mode(&output_metadata)
                || source_metadata.uid() != output_metadata.uid()
                || source_metadata.gid() != output_metadata.gid()
            {
                return Ok(false);
            }
            Ok(fs::read(source).map_err(|e| e.to_string())?
                == fs::read(output).map_err(|e| e.to_string())?)
        }
        MoltMode::Symlink => {
            if !output_metadata.file_type().is_symlink()
                || fs::read_link(output).map_err(|e| e.to_string())? != source
            {
                return Ok(false);
            }
            let tail = metadata_tail(output)?;
            Ok(tail.mode == 0o777
                && tail.uid == unsafe { libc::geteuid() }
                && tail.gid == unsafe { libc::getegid() })
        }
    }
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn file_mode(_metadata: &fs::Metadata) -> u32 {
    0
}

fn export_module_sibling_files(
    key: &crate::tools::files::InvocationKey,
    module_dir: &Path,
    module_output_dir: &Path,
    files_root: Option<&str>,
    mode: MoltMode,
    artifacts: &mut Vec<MoltArtifact>,
) -> Result<(), String> {
    for entry in fs::read_dir(module_dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name_text = name.to_string_lossy();
        if name_text == "manifest.json" || name_text == "sidecar.json" {
            continue;
        }
        if files_root == Some(name_text.as_ref()) {
            continue;
        }
        let source = entry.path();
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        if kind.is_file() {
            export_one(
                key,
                &source,
                &module_output_dir.join(&name),
                "module-ladder-sibling-file",
                mode,
                artifacts,
            )?;
        }
    }
    Ok(())
}

fn export_tree(
    key: &crate::tools::files::InvocationKey,
    source_root: &Path,
    output_root: &Path,
    kind: &'static str,
    mode: MoltMode,
    artifacts: &mut Vec<MoltArtifact>,
    pruned_paths: &mut Vec<String>,
) -> Result<(), String> {
    if !source_root.is_dir() {
        return Err(format!("molt-files-root-missing {}", source_root.display()));
    }
    if ensure_dir(key, source_root, output_root)? {
        artifacts.push(MoltArtifact {
            kind: "export-directory",
            source: source_root.display().to_string(),
            output: output_root.display().to_string(),
            mode: mode.as_str(),
        });
    }
    prune_deleted_tree_paths(key, source_root, output_root, pruned_paths)?;
    for entry in fs::read_dir(source_root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let source = entry.path();
        let output = output_root.join(entry.file_name());
        if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            export_tree(key, &source, &output, kind, mode, artifacts, pruned_paths)?;
        } else {
            export_one(key, &source, &output, kind, mode, artifacts)?;
        }
    }
    Ok(())
}

fn prune_deleted_tree_paths(
    key: &crate::tools::files::InvocationKey,
    source_root: &Path,
    output_root: &Path,
    pruned_paths: &mut Vec<String>,
) -> Result<(), String> {
    if !output_root.is_dir() {
        return Ok(());
    }
    let source_files = relative_files(source_root)?;
    let output_files = relative_files(output_root)?;
    for rel in output_files.difference(&source_files) {
        let path = output_root.join(rel);
        crate::tools::comparison::execute(
            "molt-stale-file-remove",
            || Ok(fs::symlink_metadata(&path).is_ok()),
            |present| {
                if *present {
                    crate::tools::comparison::DiffDecision::Different
                } else {
                    crate::tools::comparison::DiffDecision::Empty
                }
            },
            |authorization, _| crate::tools::files::remove_file(&authorization, key, &path),
        )?;
        if fs::symlink_metadata(&path).is_ok() {
            return Err(format!(
                "molt-stale-file-postimage-present {}",
                path.display()
            ));
        }
        pruned_paths.push(path.display().to_string());
    }
    prune_empty_dirs(key, output_root)?;
    Ok(())
}

fn relative_files(root: &Path) -> Result<BTreeSet<PathBuf>, String> {
    fn collect(root: &Path, current: &Path, files: &mut BTreeSet<PathBuf>) -> Result<(), String> {
        for entry in fs::read_dir(current).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                collect(root, &path, files)?;
            } else {
                files.insert(
                    path.strip_prefix(root)
                        .map_err(|e| e.to_string())?
                        .to_path_buf(),
                );
            }
        }
        Ok(())
    }

    let mut files = BTreeSet::new();
    collect(root, root, &mut files)?;
    Ok(files)
}

fn prune_empty_dirs(key: &crate::tools::files::InvocationKey, root: &Path) -> Result<bool, String> {
    let mut empty = true;
    for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            if prune_empty_dirs(key, &path)? {
                let restoration_testimony = crate::tools::files::remove_dir_capture(&path)?;
                crate::tools::comparison::execute(
                    "molt-empty-dir-remove",
                    || Ok(fs::symlink_metadata(&path).is_ok()),
                    |present| {
                        if *present {
                            crate::tools::comparison::DiffDecision::Different
                        } else {
                            crate::tools::comparison::DiffDecision::Empty
                        }
                    },
                    |authorization, _| crate::tools::files::remove_dir(&authorization, key, &path),
                )?;
                let _restoration_testimony_root = restoration_testimony.root.relative.len();
                if fs::symlink_metadata(&path).is_ok() {
                    return Err(format!(
                        "molt-empty-dir-postimage-present {}",
                        path.display()
                    ));
                }
            } else {
                empty = false;
            }
        } else {
            empty = false;
        }
    }
    Ok(empty)
}
