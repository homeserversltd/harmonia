use crate::tools::routine::project_manifest_routines;
use crate::*;
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) struct ModuleWalkState {
    pub(crate) context: BTreeMap<String, serde_json::Value>,
    pub(crate) children: Vec<serde_json::Value>,
    pub(crate) blocked_by: Option<String>,
    pub(crate) ok: bool,
    pub(crate) changed: bool,
    pub(crate) first_missing_signal: Option<String>,
}

pub(crate) struct ModuleExecution {
    pub(crate) ok: bool,
    pub(crate) changed: bool,
    pub(crate) operation_count: usize,
    pub(crate) first_missing_signal: Option<String>,
    pub(crate) placements: Vec<serde_json::Value>,
}

impl ModuleExecution {
    pub(crate) fn from_operations(
        outcomes: Vec<(&'static str, OperationOutcome)>,
        module_id: &str,
    ) -> Self {
        let mut ok = true;
        let mut changed = false;
        let mut first_missing_signal = None;
        for (operation_id, outcome) in &outcomes {
            if outcome.changed {
                changed = true;
            }
            if !outcome.ok {
                ok = false;
                if first_missing_signal.is_none() {
                    first_missing_signal = Some(format!("{}-{}-failed", module_id, operation_id));
                }
            }
        }
        Self {
            ok,
            changed,
            operation_count: outcomes.len(),
            first_missing_signal,
            placements: Vec::new(),
        }
    }
}

pub(crate) fn execute_profile_module(
    module: &ModuleManifest,
    module_root: &Path,
    receipt_dir: &Path,
    software_authorization: Option<&SoftwareApplyAuthorization>,
    _harmonia_root: &Path,
    invocation: Option<&crate::atoms::r#do::InvocationKey>,
    active_lane: Option<&str>,
) -> Result<ModuleExecution, String> {
    let module_dir = receipt_dir.join("modules").join(&module.id);
    crate::atoms::attest::prepare_receipt_parent(&module_dir)?;
    let manifest_path = module_root.join(&module.id).join("manifest.json");
    if crate::atoms::ask::exists(&manifest_path) && is_ladder_manifest(&manifest_path) {
        let manifest = load_ladder_manifest(&manifest_path)?;
        let plan = plan_ladder_module(&module.id, &manifest)?;
        let mut routine_states = BTreeMap::new();
        let mut halted_steps = crate::bands::HaltedSteps::new();
        crate::bands::propose_edits::execute_manifest_band(
            &manifest,
            &module_dir,
            &crate::bands::stage_profile::resolve_module_dir(module_root, &module.id)?,
            software_authorization,
            None,
            invocation,
            software_authorization.is_some(),
            &mut routine_states,
            &plan.steps,
            &plan.projected,
            &mut halted_steps,
            active_lane,
            false,
        )
    } else {
        Err(format!("module-unregistered-{}", module.id))
    }
}

struct LadderModulePlan {
    steps: Vec<crate::tools::routine::ValidatedStep>,
    projected: BTreeMap<String, Vec<crate::tools::routine::ProjectedRoutineChild>>,
}

fn plan_ladder_module(
    module_id: &str,
    manifest: &LadderManifest,
) -> Result<LadderModulePlan, String> {
    crate::tools::ladder::validate_package_pin_module(
        module_id,
        &manifest.id,
        &manifest.package_pins,
    )?;
    crate::tools::ladder::validate_package_ceiling_module(
        module_id, &manifest.id, &manifest.package_ceilings,
    )?;
    if manifest.id != module_id {
        return Err(format!(
            "module-invalid step_id=manifest defect=id-mismatch-{}",
            manifest.id
        ));
    }
    let steps = validate_ladder(manifest)
        .map_err(|error| format!("module-invalid {}", error.first_missing_signal()))?;
    let projected = project_manifest_routines(manifest, &steps)?;
    Ok(LadderModulePlan { steps, projected })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_manifest_walk_accumulates_operations_and_first_failure() {
        let execution = ModuleExecution::from_operations(
            vec![
                (
                    "first",
                    OperationOutcome {
                        ok: true,
                        changed: true,
                        skipped: false,
                        message: "ok".into(),
                        command: None,
                    },
                ),
                (
                    "second",
                    OperationOutcome {
                        ok: false,
                        changed: false,
                        skipped: false,
                        message: "blocked".into(),
                        command: None,
                    },
                ),
                (
                    "third",
                    OperationOutcome {
                        ok: false,
                        changed: true,
                        skipped: false,
                        message: "not-reached".into(),
                        command: None,
                    },
                ),
            ],
            "synthetic-module",
        );
        assert!(!execution.ok);
        assert!(execution.changed);
        assert_eq!(execution.operation_count, 3);
        assert_eq!(
            execution.first_missing_signal.as_deref(),
            Some("synthetic-module-second-failed")
        );
    }

    #[test]
    fn fully_converged_module_has_empty_plan() {
        let execution = ModuleExecution::from_operations(Vec::new(), "quiet-module");
        assert!(execution.ok);
        assert!(!execution.changed);
        assert_eq!(execution.operation_count, 0);
        assert!(execution.first_missing_signal.is_none());
    }
}
