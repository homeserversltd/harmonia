use super::Band;
use crate::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

#[path = "capsule/index.rs"]
pub(crate) mod capsule;
#[path = "molt/index.rs"]
pub(crate) mod molt;

pub(crate) use capsule::*;
pub(crate) use molt::*;

#[path = "groups.rs"]
pub(crate) mod groups;
#[path = "projection.rs"]
pub(crate) mod projection;
pub(crate) use groups::*;
pub(crate) use projection::*;

pub(crate) fn enter(enter: &mut impl FnMut(Band) -> Result<(), String>) -> Result<(), String> {
    enter(Band::StageProfile)
}

pub(crate) fn shared_module_root(module_root: &Path) -> Option<std::path::PathBuf> {
    let profile_dir = module_root.parent()?;
    let profiles_dir = profile_dir.parent()?;
    if profiles_dir.file_name().and_then(|name| name.to_str()) != Some("profiles") {
        return None;
    }
    profiles_dir.parent().map(|root| root.join("modules"))
}

fn profiles_shared_module_root(module_root: &Path) -> Option<std::path::PathBuf> {
    let profile_dir = module_root.parent()?;
    let profiles_dir = profile_dir.parent()?;
    if profiles_dir.file_name().and_then(|name| name.to_str()) != Some("profiles") {
        return None;
    }
    Some(profiles_dir.join("shared").join("modules"))
}

pub(crate) fn resolve_module_dir(
    module_root: &Path,
    module_id: &str,
) -> Result<std::path::PathBuf, String> {
    let local = module_root.join(module_id);
    let mut seats = Vec::new();
    if lawful_module_manifest_exists(&local) {
        seats.push(local.clone());
    }
    if let Some(root) = profiles_shared_module_root(module_root) {
        let path = root.join(module_id);
        if lawful_module_manifest_exists(&path) {
            seats.push(path);
        }
    }
    if let Some(root) = shared_module_root(module_root) {
        let path = root.join(module_id);
        if lawful_module_manifest_exists(&path) {
            seats.push(path);
        }
    }
    if seats.len() > 1 {
        let rendered = seats
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(",");
        return Err(format!(
            "module-seat-ambiguous id={module_id} seats={rendered}"
        ));
    }
    Ok(seats.into_iter().next().unwrap_or_else(|| {
        profiles_shared_module_root(module_root)
            .map(|root| root.join(module_id))
            .unwrap_or(local)
    }))
}

pub(crate) fn module_uses_shared_seat(module_root: &Path, module_dir: &Path) -> bool {
    profiles_shared_module_root(module_root)
        .as_ref()
        .is_some_and(|root| module_dir.parent() == Some(root.as_path()))
        || shared_module_root(module_root)
            .as_ref()
            .is_some_and(|root| module_dir.parent() == Some(root.as_path()))
}

pub(crate) fn source_module_path(
    harmonia_root: &Path,
    profile_id: &str,
    module_id: &str,
) -> Result<std::path::PathBuf, String> {
    let module_root = harmonia_root
        .join("profiles")
        .join(profile_id)
        .join("modules");
    resolve_module_dir(&module_root, module_id)
}

pub(crate) fn materialize(
    source_root: &Path,
    profile_id: &str,
    installed_module_root: &Path,
    receipt_dir: &Path,
    git_bearer: &str,
    key: &crate::atoms::r#do::InvocationKey,
    context: Option<&RunContext>,
    carrier: Option<&crate::atoms::r#do::transaction::RunCarrierRef>,
    syzygy_declaration: Option<crate::SyzygyDeclaration>,
) -> Result<Profile, String> {
    let installed_root = installed_module_root
        .parent()
        .ok_or_else(|| format!("{profile_id}-config-root-missing"))?;
    let source_profile_path = source_root.join(format!("profiles/{profile_id}/index.json"));
    let mut refreshed = load_profile(&source_profile_path)
        .map_err(|e| format!("{profile_id}-profile-source-read-failed: {e}"))?;
    refreshed.syzygy_declaration = syzygy_declaration;
    let source_modules_root = source_root.join(format!("profiles/{}/modules", refreshed.id));
    let head = tools::command::capture_with_cwd_as_bearer(
        "git",
        &["rev-parse", "HEAD"],
        source_root.to_str(),
        git_bearer,
    );
    if !head.ok {
        return Err(format!("{profile_id}-source-head-failed {}", head.stderr));
    }
    let source_head = head.stdout.trim().to_string();
    if source_head.is_empty() {
        return Err(format!("{profile_id}-source-head-empty"));
    }
    molt(
        source_root,
        profile_id,
        installed_root,
        receipt_dir,
        MoltMode::Copy,
    )?;
    // Re-read the freshly staged module tree. The pre-stage projection may describe
    // stale installed content; apply must reach molt before current validation runs.
    let projection = crate::bands::stage_profile::projection::load_profile_projection(
        &refreshed,
        installed_module_root,
        &std::collections::BTreeSet::new(),
    )?;
    let update_plan = projection.derive_update_plan(&refreshed, installed_module_root)?;
    let sealed_projection = crate::atoms::r#do::transaction::seal_projection(
        &update_plan,
        &refreshed.id,
        &refreshed.identity,
        &source_head,
    )?;
    let refreshed_identity = crate::atoms::r#do::transaction::RefreshedProfileIdentity {
        profile_id: refreshed.id.clone(),
        identity: refreshed.identity.clone(),
        source_head: source_head.clone(),
    };
    let transaction_census = crate::atoms::r#do::transaction::TransactionCensus {
        profile_id: refreshed.id.clone(),
        profile_identity: refreshed.identity.clone(),
        source_head: source_head.clone(),
        target_count: update_plan.targets.len(),
        service_count: update_plan.services.len(),
        caduceus_count: update_plan.caduceus_count,
        gui_face: update_plan.gui_face.clone().unwrap_or_default(),
        gui_member: update_plan.gui_member.clone().unwrap_or_default(),
    };
    if let Some(target_carrier) = carrier.or_else(|| context.map(|value| &value.carrier)) {
        let mut value = target_carrier.borrow_mut();
        value.refreshed_profile_value = Some(refreshed.clone());
        value.projection = Some(projection.clone());
        value.update_plan = Some(update_plan.clone());
        value.sealed_projection = Some(sealed_projection);
        value.refreshed_profile = Some(refreshed_identity);
        value.transaction_census = Some(transaction_census);
    }
    // Compare only modules declared by this profile. Undeclared directories and
    // staging debris are outside this spine's content contract. A stale installed
    // module is a lawful molt concern: refresh through molt once more, then retain
    // the post-act hash proof and fail closed if it still does not converge.
    let mut divergent_modules: Vec<String> = Vec::new();
    for id in &refreshed.modules {
        let source_hash = crate::atoms::tree_hash::content_tree_sha256(&source_module_path(
            source_root,
            &refreshed.id,
            id,
        )?)?;
        let installed_hash =
            crate::atoms::tree_hash::content_tree_sha256(&installed_module_root.join(id))?;
        if source_hash != installed_hash {
            divergent_modules.push(id.clone());
        }
    }
    if !divergent_modules.is_empty() {
        let forced_modules = divergent_modules.iter().cloned().collect();
        molt_at_subscription_path_for_modules(
            source_root,
            profile_id,
            installed_root,
            receipt_dir,
            &subscription_path(),
            MoltMode::Copy,
            &forced_modules,
        )?;
    }
    let mut source_module_hashes = BTreeMap::new();
    let mut installed_module_hashes = BTreeMap::new();
    for id in &refreshed.modules {
        let source_hash = crate::atoms::tree_hash::content_tree_sha256(&source_module_path(
            source_root,
            &refreshed.id,
            id,
        )?)?;
        let installed_hash =
            crate::atoms::tree_hash::content_tree_sha256(&installed_module_root.join(id))?;
        if source_hash != installed_hash {
            return Err(format!(
                "{profile_id}-module-root-inconsistent module={id} source={} installed={}",
                source_hash, installed_hash
            ));
        }
        source_module_hashes.insert(id.clone(), source_hash);
        installed_module_hashes.insert(id.clone(), installed_hash);
    }
    let declared_hash = |hashes: &BTreeMap<String, String>| {
        let mut digest = Sha256::new();
        for (id, hash) in hashes {
            digest.update(id.as_bytes());
            digest.update([0]);
            digest.update(hash.as_bytes());
            digest.update([0]);
        }
        format!("{:x}", digest.finalize())
    };
    let source_tree_sha256 = declared_hash(&source_module_hashes);
    let installed_tree_sha256 = declared_hash(&installed_module_hashes);
    let modules = refreshed
        .modules
        .iter()
        .map(|id| {
            let module_dir = source_module_path(source_root, &refreshed.id, id)?;
            Ok(SubscriptionModuleUpdate {
                id: id.clone(),
                version: installed_module_version(&module_dir)
                    .unwrap_or_else(|| "sidecar".to_string()),
                tree_sha256: crate::atoms::tree_hash::content_tree_sha256(&module_dir)?,
                received_at_run_id: run_id_from_stamp(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let key = key;
    update_subscription_record_with_invocation(
        &subscription_path(),
        SubscriptionUpdate {
            lane: preserve_existing_lane_or_default(&subscription_path()),
            source: source_root.display().to_string(),
            ref_name: source_head,
            selected_profile: refreshed.id.clone(),
            engine_version_received: VERSION.to_string(),
            modules,
        },
        key,
    )?;
    if let Some(target_carrier) = carrier.or_else(|| context.map(|value| &value.carrier)) {
        let mut value = target_carrier.borrow_mut();
        value.module_root_consistency =
            Some(crate::atoms::r#do::transaction::ModuleRootConsistency {
                source_root: source_modules_root.display().to_string(),
                installed_root: installed_module_root.display().to_string(),
                source_tree_sha256: source_tree_sha256.clone(),
                installed_tree_sha256: installed_tree_sha256.clone(),
                matches: source_tree_sha256 == installed_tree_sha256,
            });
    }
    Ok(refreshed)
}

#[cfg(test)]
mod shared_dot_files_tests {
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::fs;

    #[test]
    fn materializes_shared_module_then_backfills_compiled_output() {
        let root =
            std::env::temp_dir().join(format!("harmonia-stage-shared-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let shared = root.join("profiles/shared/modules/dot-files");
        let source = shared.join("files_root/functions");
        fs::create_dir_all(source.join("all")).unwrap();
        fs::create_dir_all(source.join("tv")).unwrap();
        fs::create_dir_all(root.join("profiles/tv")).unwrap();
        fs::create_dir_all(root.join("src/tools")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(root.join("profiles/tv/index.json"), r#"{"id":"tv","identity":"arch-tv","package_authority":{"os_family":"arch","package_manager":"pacman"},"modules":["dot-files"]}"#).unwrap();
        fs::write(shared.join("manifest.json"), r#"{"schema":"harmonia.module.ladder.v1","id":"dot-files","version":"1","files_root":"files_root","ladder":[]}"#).unwrap();
        fs::write(source.join("all/00"), b"all").unwrap();
        fs::write(source.join("tv/00"), b"tv").unwrap();
        std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap();
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(&root)
            .status()
            .unwrap();
        std::process::Command::new("git")
            .args([
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "-qm",
                "fixture",
            ])
            .current_dir(&root)
            .status()
            .unwrap();
        let installed_root = root.join("installed");
        let stale = installed_root.join("modules/dot-files/files_root/functions/all/stale");
        fs::create_dir_all(stale.parent().unwrap()).unwrap();
        fs::write(stale, b"stale").unwrap();
        let subscription = root.join("subscription.json");
        crate::bands::stage_profile::molt::molt_at_subscription_path(
            &root,
            "tv",
            &installed_root,
            &root.join("molt-receipts"),
            &subscription,
            crate::bands::stage_profile::molt::MoltMode::Copy,
        )
        .unwrap();
        let installed = installed_root.join("modules/dot-files");
        let manifest =
            crate::tools::ladder::load_ladder_manifest(&installed.join("manifest.json")).unwrap();
        let target = root.join("home/.functions");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let args = BTreeMap::from([
            ("source_root".into(), json!("files_root/functions")),
            ("target_path".into(), json!(target)),
            ("backup_existing".into(), json!(true)),
        ]);
        let step = crate::tools::ladder::ValidatedStep {
            step_id: "compile-fragments".into(),
            tool: "files".into(),
            permutation: "compile-fragments".into(),
            args,
            on_failure: crate::tools::ladder::OnFailure::Stop,
        };
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let mode = crate::UpdateMode::from_apply_flag_with_invocation(true, Some(&invocation));
        let mut routine_states = BTreeMap::new();
        let projected_routines = BTreeMap::new();
        let execution = crate::bands::backfill_files::execute_files(
            &manifest,
            &installed,
            mode.software_authorization(),
            None,
            mode.invocation(),
            true,
            false,
            &mut routine_states,
            &[step],
            &projected_routines,
        )
        .unwrap();
        assert!(execution.ok);
        assert_eq!(execution.operation_count, 1);
        assert_eq!(execution.placements.len(), 1);
        assert_eq!(execution.placements[0]["band"], "BackfillFiles");
        assert_eq!(fs::read(target).unwrap(), b"alltv");
        fs::remove_dir_all(root).unwrap();
    }
}
