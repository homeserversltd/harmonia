use serde::{Deserialize, Serialize};

pub(crate) const CONFIG_PLANE_WITNESS_SCHEMA: &str = "harmonia.config_plane_witness.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ConfigPlaneCategory {
    KnownGood,
    Interactable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ConfigPlaneDisposition {
    Converged,
    InteractableOffered,
    InteractableConverged,
    RefusedUnrecognized,
    InteractableExempt,
}

/// Per-managed-file evidence for a target classified on ConfigPlane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConfigPlaneWitness {
    pub(crate) schema: String,
    pub(crate) path: String,
    pub(crate) module_id: String,
    pub(crate) category: ConfigPlaneCategory,
    pub(crate) disposition: ConfigPlaneDisposition,
}

impl ConfigPlaneWitness {
    pub(crate) fn new(
        path: String,
        module_id: String,
        category: ConfigPlaneCategory,
        disposition: ConfigPlaneDisposition,
    ) -> Self {
        Self {
            schema: CONFIG_PLANE_WITNESS_SCHEMA.to_string(),
            path,
            module_id,
            category,
            disposition,
        }
    }
}
