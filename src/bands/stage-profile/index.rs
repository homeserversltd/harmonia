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
    profiles_dir
        .parent()
        .map(|root| root.join("shared").join("modules"))
}

fn legacy_module_root(module_root: &Path) -> Option<std::path::PathBuf> {
    let profile_dir = module_root.parent()?;
    let profiles_dir = profile_dir.parent()?;
    if profiles_dir.file_name().and_then(|name| name.to_str()) != Some("profiles") {
        return None;
    }
    profiles_dir.parent().map(|root| root.join("modules"))
}

fn legacy_profile_shared_module_root(module_root: &Path) -> Option<std::path::PathBuf> {
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
    if lawful_module_manifest_exists(&local) {
        return Ok(local);
    }
    let shared = shared_module_root(module_root).map(|root| root.join(module_id));
    if let Some(path) = shared.filter(|path| lawful_module_manifest_exists(path)) {
        return Ok(path);
    }
    let legacy = legacy_module_root(module_root).map(|root| root.join(module_id));
    let old_shared =
        legacy_profile_shared_module_root(module_root).map(|root| root.join(module_id));
    if let Some(path) = [legacy, old_shared]
        .into_iter()
        .flatten()
        .find(|path| lawful_module_manifest_exists(path))
    {
        return Err(format!(
            "legacy-module-seat-unowned id={module_id} seat={}",
            path.display()
        ));
    }
    Ok(shared_module_root(module_root)
        .map(|root| root.join(module_id))
        .unwrap_or(local))
}

/// Reconcile the complete legacy module root before projection resolution.
///
/// The inventory is deliberately whole-root and deterministic: a single
/// unshadowed unregistered lawful entry refuses the run before any filesystem
/// mutation. Root shared directories are excluded from retirement; when
/// they coexist with retireable entries, apply retires those entries
/// individually. Apply uses the comparison/Do rename membrane, while
/// report-only records pending evidence and leaves the root untouched.
pub(crate) fn reconcile_legacy_module_seats(
    _profile: &Profile,
    module_root: &Path,
    receipt_dir: &Path,
    mode: &crate::UpdateMode<'_>,
) -> Result<(), String> {
    let Some(legacy_root) = legacy_module_root(module_root) else {
        return Ok(());
    };
    let mut ids = Vec::new();
    if legacy_root.is_dir() {
        for entry in std::fs::read_dir(&legacy_root)
            .map_err(|e| format!("legacy-module-root-inventory-failed: {e}"))?
        {
            let entry = entry.map_err(|e| format!("legacy-module-root-inventory-failed: {e}"))?;
            let path = entry.path();
            if path.is_dir() {
                let Some(_) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if lawful_module_manifest_exists(&path) {
                    ids.push(path);
                }
            }
        }
    }
    ids.sort();
    if ids.is_empty() {
        return Ok(());
    }
    let module_ids: Vec<String> = ids
        .iter()
        .filter_map(|path| path.file_name()?.to_str().map(str::to_owned))
        .collect();
    let mut retireable = Vec::new();
    let mut unshadowed = Vec::new();
    for id in &module_ids {
        let local = module_root.join(id);
        let profile_shared = shared_module_root(module_root).map(|root| root.join(id));
        let shadowed = lawful_module_manifest_exists(&local)
            || profile_shared
                .as_ref()
                .is_some_and(|path| lawful_module_manifest_exists(path));
        if shadowed {
            retireable.push(id.clone());
        } else {
            unshadowed.push(id.clone());
        }
    }
    let legacy_paths: Vec<String> = ids.iter().map(|path| path.display().to_string()).collect();
    let selected_paths: Vec<String> = module_ids
        .iter()
        .map(|id| {
            let local = module_root.join(id);
            if lawful_module_manifest_exists(&local) {
                local
            } else {
                shared_module_root(module_root)
                    .map(|root| root.join(id))
                    .unwrap_or_else(|| module_root.join(id))
            }
        })
        .map(|path| path.display().to_string())
        .collect();
    let mut receipt = serde_json::json!({
        "schema": "harmonia.module-seat-shed.v1",
        "legacy_root": legacy_root,
        "module_ids": module_ids,
        "legacy_paths": legacy_paths,
        "selected_paths": selected_paths,
        "observed": true,
        "could_change": true,
        "attempt": {"mutation": false, "action": "retire-legacy-module-root"},
        "final": {"retired_root": serde_json::Value::Null, "ok": false},
        "ok": false,
        "first_missing_signal": "none"
    });
    if !unshadowed.is_empty() {
        receipt["first_missing_signal"] = serde_json::json!(format!(
            "legacy-module-seat-unowned ids={}",
            unshadowed.join(",")
        ));
        crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
        crate::atoms::attest::write_json_atomic(
            &receipt_dir.join("module-seat-shed.json"),
            &receipt,
        )?;
        return Err(receipt["first_missing_signal"].as_str().unwrap().to_owned());
    }
    if !mode.is_software_apply() {
        receipt["first_missing_signal"] = serde_json::json!("module-seat-shed-pending");
        crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
        crate::atoms::attest::write_json_atomic(
            &receipt_dir.join("module-seat-shed.json"),
            &receipt,
        )?;
        return Ok(());
    }
    let key = mode
        .invocation()
        .ok_or_else(|| "legacy-module-seat-retire-invocation-missing".to_string())?;
    let date = utc_date_stamp();
    let whole_root = retireable.len() == module_ids.len();
    let mut retired_root = legacy_root.with_file_name(format!("modules.retired-{date}"));
    if whole_root {
        let mut ordinal = 2;
        while retired_root.exists() {
            retired_root = legacy_root.with_file_name(format!("modules.retired-{date}-{ordinal}"));
            ordinal += 1;
        }
    }
    receipt["attempt"] = serde_json::json!({
        "mutation": true,
        "action": if whole_root { "retire-legacy-module-root" } else { "retire-legacy-module-seats" }
    });
    crate::atoms::attest::prepare_receipt_parent(receipt_dir)?;
    crate::atoms::attest::write_json_atomic(&receipt_dir.join("module-seat-shed.json"), &receipt)?;
    let result = crate::atoms::comparison::execute_once(
        "retire-legacy-module-seats",
        || Ok(legacy_root.exists()),
        |exists| {
            if *exists {
                crate::atoms::comparison::DiffDecision::Different
            } else {
                crate::atoms::comparison::DiffDecision::Empty
            }
        },
        |authorization, _| {
            if whole_root {
                crate::atoms::r#do::rename::rename(&authorization, key, &legacy_root, &retired_root)
            } else {
                for id in &retireable {
                    let source = legacy_root.join(id);
                    let mut target =
                        legacy_root.with_file_name(format!("modules.{id}.retired-{date}"));
                    let mut ordinal = 2;
                    while target.exists() {
                        target = legacy_root
                            .with_file_name(format!("modules.{id}.retired-{date}-{ordinal}"));
                        ordinal += 1;
                    }
                    crate::atoms::r#do::rename::rename(&authorization, key, &source, &target)?;
                }
                Ok(())
            }
        },
    );
    if let Err(error) = result {
        receipt["first_missing_signal"] = serde_json::json!("legacy-module-seat-retire-failed");
        receipt["error"] = serde_json::json!(error);
        receipt["final"] =
            serde_json::json!({"retired_root": serde_json::Value::Null, "ok": false});
        receipt["ok"] = serde_json::Value::Bool(false);
        crate::atoms::attest::write_json_atomic(
            &receipt_dir.join("module-seat-shed.json"),
            &receipt,
        )?;
        return Err(error);
    }
    receipt["final"] = if whole_root {
        serde_json::json!({"retired_root": retired_root, "ok": true})
    } else {
        serde_json::json!({"retired_root": serde_json::Value::Null, "retired_ids": retireable, "ok": true})
    };
    receipt["ok"] = serde_json::Value::Bool(true);
    crate::atoms::attest::write_json_atomic(&receipt_dir.join("module-seat-shed.json"), &receipt)?;
    Ok(())
}

fn utc_date_stamp() -> String {
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() / 86_400)
        .unwrap_or(0) as i64;
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_part = (5 * doy + 2) / 153;
    let day = doy - (153 * month_part + 2) / 5 + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };
    format!("{year:04}-{month:02}-{day:02}")
}

pub(crate) fn module_uses_shared_seat(module_root: &Path, module_dir: &Path) -> bool {
    shared_module_root(module_root)
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
    use std::ffi::CString;
    use std::fs;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    fn lchown_tree(path: &std::path::Path, uid: libc::uid_t, gid: libc::gid_t) -> io::Result<()> {
        if fs::symlink_metadata(path)?.file_type().is_dir() {
            for entry in fs::read_dir(path)? {
                lchown_tree(&entry?.path(), uid, gid)?;
            }
        }
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in fixture path"))?;
        if unsafe { libc::lchown(path.as_ptr(), uid, gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn duplicate_fixture(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "harmonia-module-seat-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let profile = root.join("profiles/demo/modules/alpha");
        let legacy = root.join("modules/alpha");
        fs::create_dir_all(&profile).unwrap();
        fs::create_dir_all(&legacy).unwrap();
        fs::write(profile.join("manifest.json"), b"{} ").unwrap();
        fs::write(legacy.join("manifest.json"), b"{} ").unwrap();
        (root.clone(), root.join("profiles/demo/modules"))
    }

    fn fixture_profile(modules: &[&str]) -> crate::Profile {
        crate::Profile {
            id: "demo".into(),
            identity: "test".into(),
            package_authority: None,
            modules: modules.iter().map(|id| (*id).into()).collect(),
            hotfixes: Vec::new(),
            syzygy_declaration: None,
        }
    }

    #[test]
    fn plan_duplicate_profile_seat_reports_pending_without_mutation() {
        let (root, module_root) = duplicate_fixture("plan");
        let receipts = root.join("receipts");
        let mode = crate::UpdateMode::Observe;
        super::reconcile_legacy_module_seats(
            &fixture_profile(&["alpha"]),
            &module_root,
            &receipts,
            &mode,
        )
        .unwrap();
        assert!(root.join("modules/alpha/manifest.json").exists());
        let receipt: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(receipts.join("module-seat-shed.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["observed"], true);
        assert_eq!(receipt["could_change"], true);
        assert_eq!(receipt["attempt"]["mutation"], false);
        assert_eq!(receipt["final"]["ok"], false);
        assert_eq!(receipt["ok"], false);
        assert_eq!(
            super::resolve_module_dir(&module_root, "alpha").unwrap(),
            module_root.join("alpha")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn apply_duplicate_profile_seat_retires_whole_legacy_root() {
        let (root, module_root) = duplicate_fixture("apply");
        fs::create_dir_all(root.join("modules/beta")).unwrap();
        fs::write(root.join("modules/beta/manifest.json"), b"{} ").unwrap();
        fs::create_dir_all(module_root.join("beta")).unwrap();
        fs::write(module_root.join("beta/manifest.json"), b"{} ").unwrap();
        let receipts = root.join("receipts");
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let mode = crate::UpdateMode::from_apply_flag_with_invocation(true, Some(&invocation));
        super::reconcile_legacy_module_seats(
            &fixture_profile(&["alpha", "beta"]),
            &module_root,
            &receipts,
            &mode,
        )
        .unwrap();
        assert!(!root.join("modules").exists());
        let retired = fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("modules.retired-"))
            })
            .unwrap();
        assert!(retired.join("alpha/manifest.json").exists());
        assert!(retired.join("beta/manifest.json").exists());
        let receipt: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(receipts.join("module-seat-shed.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["observed"], true);
        assert_eq!(receipt["could_change"], true);
        assert_eq!(receipt["attempt"]["mutation"], true);
        assert_eq!(receipt["final"]["ok"], true);
        assert_eq!(receipt["ok"], true);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mixed_shadowed_and_unshadowed_legacy_refuses_before_mutation() {
        let (root, module_root) = duplicate_fixture("mixed");
        fs::create_dir_all(root.join("modules/beta")).unwrap();
        fs::write(root.join("modules/beta/manifest.json"), b"{} ").unwrap();
        let before = fs::read_dir(root.join("modules")).unwrap().count();
        let receipts = root.join("receipts");
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let mode = crate::UpdateMode::from_apply_flag_with_invocation(true, Some(&invocation));
        let error = super::reconcile_legacy_module_seats(
            &fixture_profile(&["alpha"]),
            &module_root,
            &receipts,
            &mode,
        )
        .unwrap_err();
        assert!(error.contains("beta"));
        assert_eq!(fs::read_dir(root.join("modules")).unwrap().count(), before);
        assert!(!root.join("modules.retired").exists());
        let receipt: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(receipts.join("module-seat-shed.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["attempt"]["mutation"], false);
        assert_eq!(receipt["ok"], false);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_only_requested_module_is_an_error() {
        let (root, module_root) = duplicate_fixture("legacy");
        fs::remove_dir_all(module_root.join("alpha")).unwrap();
        let error = super::resolve_module_dir(&module_root, "alpha").unwrap_err();
        assert!(error.contains("legacy-module-seat-unowned"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn registered_root_shared_module_resolves_and_survives_apply_reconcile() {
        let root =
            std::env::temp_dir().join(format!("harmonia-registered-shared-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let module_root = root.join("profiles/demo/modules");
        fs::create_dir_all(root.join("shared/modules/chromium")).unwrap();
        fs::create_dir_all(&module_root).unwrap();
        fs::write(root.join("shared/modules/chromium/manifest.json"), b"{} ").unwrap();
        fs::write(
            root.join("profiles/demo/index.json"),
            r#"{"modules":["chromium"]}"#,
        )
        .unwrap();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let mode = crate::UpdateMode::from_apply_flag_with_invocation(true, Some(&invocation));
        super::reconcile_legacy_module_seats(
            &fixture_profile(&["chromium"]),
            &module_root,
            &root.join("receipts"),
            &mode,
        )
        .unwrap();
        assert_eq!(
            super::resolve_module_dir(&module_root, "chromium").unwrap(),
            root.join("shared/modules/chromium")
        );
        assert!(root.join("shared/modules/chromium/manifest.json").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_module_shadows_root_shared_module() {
        let root = std::env::temp_dir().join(format!(
            "harmonia-local-shadows-root-shared-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let module_root = root.join("profiles/demo/modules");
        let local = module_root.join("chromium");
        let shared = root.join("shared/modules/chromium");
        fs::create_dir_all(&local).unwrap();
        fs::create_dir_all(&shared).unwrap();
        fs::write(local.join("manifest.json"), b"{} ").unwrap();
        fs::write(shared.join("manifest.json"), b"{} ").unwrap();

        assert_eq!(
            super::resolve_module_dir(&module_root, "chromium").unwrap(),
            local
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn canonical_shared_survives_while_whole_legacy_root_is_retired() {
        let root = std::env::temp_dir().join(format!(
            "harmonia-mixed-registered-shared-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let module_root = root.join("profiles/demo/modules");
        fs::create_dir_all(root.join("shared/modules/chromium")).unwrap();
        fs::create_dir_all(root.join("modules/alpha")).unwrap();
        fs::create_dir_all(module_root.join("alpha")).unwrap();
        fs::write(root.join("shared/modules/chromium/manifest.json"), b"{} ").unwrap();
        fs::write(root.join("modules/alpha/manifest.json"), b"{} ").unwrap();
        fs::write(module_root.join("alpha/manifest.json"), b"{} ").unwrap();
        fs::write(
            root.join("profiles/demo/index.json"),
            r#"{"modules":["chromium"]}"#,
        )
        .unwrap();
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let mode = crate::UpdateMode::from_apply_flag_with_invocation(true, Some(&invocation));
        super::reconcile_legacy_module_seats(
            &fixture_profile(&["chromium", "alpha"]),
            &module_root,
            &root.join("receipts"),
            &mode,
        )
        .unwrap();
        assert!(root.join("shared/modules/chromium/manifest.json").exists());
        assert!(!root.join("modules/alpha").exists());
        let retired = fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("modules.retired-"))
            })
            .unwrap();
        assert!(retired.join("alpha/manifest.json").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn materialize_forced_divergent_module_removes_stale_entry() {
        let root = std::env::temp_dir().join(format!(
            "harmonia-stage-forced-divergent-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let source_module = root.join("profiles/demo/modules/alpha");
        fs::create_dir_all(source_module.clone()).unwrap();
        fs::set_permissions(&source_module, fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir_all(root.join("src/tools")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(
            root.join("profiles/demo/index.json"),
            r#"{"id":"demo","identity":"test","modules":["alpha"]}"#,
        )
        .unwrap();
        fs::write(source_module.join("index.rs"), b"// fixture\n").unwrap();
        fs::write(source_module.join("sidecar.json"), r#"{"id":"alpha"}"#).unwrap();
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

        let installed_module = root.join("installed/modules/alpha");
        fs::create_dir_all(&installed_module).unwrap();
        fs::write(installed_module.join("sidecar.json"), r#"{"id":"alpha"}"#).unwrap();
        let stale = installed_module.join("stale-entry");
        fs::write(&stale, b"stale").unwrap();
        let _bearer_guard = if unsafe { libc::geteuid() } == 0 {
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
            lchown_tree(&root, 65534, 65534).unwrap();
            Some(crate::atoms::command::install_test_bearer(
                "owner", 65534, 65534, &root,
            ))
        } else {
            None
        };
        let subscription = root.join("subscription.json");
        let prior_subscription = std::env::var_os("HARMONIA_SUBSCRIPTION_PATH");
        std::env::set_var("HARMONIA_SUBSCRIPTION_PATH", &subscription);
        let invocation = crate::atoms::r#do::InvocationKey::for_apply();
        let result = super::materialize(
            &root,
            "demo",
            &root.join("installed/modules"),
            &root.join("receipts"),
            "owner",
            &invocation,
            None,
            None,
            None,
        );
        match prior_subscription {
            Some(value) => std::env::set_var("HARMONIA_SUBSCRIPTION_PATH", value),
            None => std::env::remove_var("HARMONIA_SUBSCRIPTION_PATH"),
        }
        let _profile = result.unwrap();
        assert_eq!(
            fs::metadata(&installed_module)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        let source_hash = crate::atoms::tree_hash::content_tree_sha256(&source_module).unwrap();
        let installed_hash =
            crate::atoms::tree_hash::content_tree_sha256(&installed_module).unwrap();
        println!(
            "after stale_exists={} source_hash={} installed_hash={}",
            stale.exists(),
            source_hash,
            installed_hash
        );
        assert!(!stale.exists());
        assert_eq!(source_hash, installed_hash);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn materializes_shared_module_then_backfills_compiled_output() {
        let root =
            std::env::temp_dir().join(format!("harmonia-stage-shared-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let shared = root.join("shared/modules/dot-files");
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
