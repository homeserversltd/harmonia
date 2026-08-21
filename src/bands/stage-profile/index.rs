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

pub(crate) fn materialize(
    source_root: &Path,
    profile_id: &str,
    installed_module_root: &Path,
    receipt_dir: &Path,
    git_bearer: &str,
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
        let source_hash =
            crate::atoms::tree_hash::content_tree_sha256(&source_modules_root.join(id))?;
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
        let source_hash =
            crate::atoms::tree_hash::content_tree_sha256(&source_modules_root.join(id))?;
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
            let module_dir = source_modules_root.join(id);
            Ok(SubscriptionModuleUpdate {
                id: id.clone(),
                version: installed_module_version(&module_dir)
                    .unwrap_or_else(|| "sidecar".to_string()),
                tree_sha256: crate::atoms::tree_hash::content_tree_sha256(&module_dir)?,
                received_at_run_id: run_id_from_stamp(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let key = context
        .map(|value| value.key)
        .ok_or_else(|| "subscription-invocation-key-missing".to_string())?;
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
