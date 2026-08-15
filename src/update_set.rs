use crate::Profile;
use serde_json::json;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct Target {
    pub path: PathBuf,
    pub member: String,
}
#[derive(Clone, Debug)]
pub struct ServiceBinding {
    pub name: String,
    pub user: bool,
    pub target_user: Option<String>,
}
#[derive(Clone, Debug)]
pub struct UpdatePlan {
    pub targets: Vec<Target>,
    pub services: Vec<ServiceBinding>,
    pub gui_face: String,
    pub gui_member: String,
    pub caduceus_count: usize,
}
pub fn derive_plan(
    profile: &Profile,
    module_root: &Path,
    projection_root: Option<&Path>,
) -> Result<UpdatePlan, String> {
    let projection =
        crate::profile_engine::load_profile_projection(profile, module_root, &BTreeSet::new())?;
    let mut plan = projection.derive_update_plan(profile, module_root)?;
    if let Some(scratch) = projection_root {
        for target in &mut plan.targets {
            let rel = target
                .path
                .strip_prefix("/")
                .map_err(|_| "projection-target-not-absolute")?;
            target.path = scratch.join(rel);
        }
        plan.services.clear();
    }
    Ok(plan)
}

pub(crate) fn update_set_receipt(
    dir: &Path,
    face: &str,
    verdict: &str,
    failed: Option<&str>,
    failed_step: Option<&str>,
) -> Result<(), String> {
    let ms=["caduceus","agathodaimon",face].into_iter().map(|m|json!({"member":m,"status":if verdict=="ok"{"ok"}else if failed==Some(m){"failed"}else{"rolled-back"}})).collect::<Vec<_>>();
    let mut v = json!({"schema":"harmonia.update-set.v1","set_name":"appliance-syzygy","gui":face,"set_verdict":verdict,"members":ms});
    if let Some(x) = failed_step {
        v["failed_step"] = json!(x);
    }
    crate::receipts::write_json(&dir.join("update-set.json"), &v)
}

pub(crate) fn write_transaction_receipt(
    dir: &Path,
    receipt: &crate::atoms::r#do::transaction::TransactionReceipt,
    failed_step: Option<&str>,
) -> Result<(), String> {
    let mut value = crate::atoms::r#do::transaction::project_update_set_v1(receipt);
    if let Some(step) = failed_step {
        value["failed_step"] = json!(step);
    }
    crate::receipts::write_json(&dir.join("update-set.json"), &value)
}
