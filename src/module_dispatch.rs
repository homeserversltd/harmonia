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
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<ModuleExecution, String> {
    let module_dir = receipt_dir.join("modules").join(&module.id);
    crate::atoms::attest::prepare_receipt_parent(&module_dir)?;
    let manifest_path = module_root.join(&module.id).join("manifest.json");
    if crate::atoms::ask::exists(&manifest_path) && is_ladder_manifest(&manifest_path) {
        let manifest = load_ladder_manifest(&manifest_path)?;
        if manifest.id != module.id {
            return Err(format!(
                "module-invalid step_id=manifest defect=id-mismatch-{}",
                manifest.id
            ));
        }
        let steps = validate_ladder(&manifest)
            .map_err(|error| format!("module-invalid {}", error.first_missing_signal()))?;
        let projected = project_manifest_routines(&manifest, &steps)?;
        let mut routine_states = BTreeMap::new();
        crate::bands::propose_edits::execute_manifest_band(
            &manifest,
            &module_dir,
            software_authorization,
            None,
            invocation,
            software_authorization.is_some(),
            &mut routine_states,
            &steps,
            &projected,
        )
    } else {
        Err(format!("module-unregistered-{}", module.id))
    }
}
