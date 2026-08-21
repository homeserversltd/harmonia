use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;

impl LoadedModule {
    pub(crate) fn id(&self) -> &str {
        match self {
            Self::Sidecar(module) => &module.id,
            Self::Ladder(manifest) => &manifest.id,
        }
    }

    pub(crate) fn version(&self) -> Option<&str> {
        match self {
            Self::Sidecar(_) => None,
            Self::Ladder(manifest) => Some(&manifest.version),
        }
    }
}

#[derive(Debug, Clone)]
struct GroupProbeObservation {
    module_id: String,
    ok: bool,
    tool: String,
    permutation: String,
    signal: String,
}

#[derive(Debug, Clone)]
pub(crate) struct GroupSelection {
    group_id: String,
    winner: String,
    losers: Vec<String>,
    observations: Vec<GroupProbeObservation>,
}

const APPLIANCE_CONFIG_PATH: &str = "/etc/appliance/config.json";

#[derive(Default)]
pub(crate) struct DeviceModulePolicy {
    pub(crate) disabled_modules: BTreeSet<String>,
}

pub(crate) fn read_device_module_policy() -> Result<DeviceModulePolicy, String> {
    let path = Path::new(APPLIANCE_CONFIG_PATH);
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(DeviceModulePolicy::default())
        }
        Err(err) => {
            return Err(format!(
                "appliance-config-read-failed {}: {err}",
                path.display()
            ))
        }
    };
    let config: serde_json::Value = serde_json::from_str(&text)
        .map_err(|err| format!("appliance-config-parse-failed {}: {err}", path.display()))?;
    let disabled_modules = config
        .get("harmonia")
        .and_then(|harmonia| harmonia.get("disabled_modules"))
        .and_then(serde_json::Value::as_array)
        .map(|modules| {
            modules
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok(DeviceModulePolicy { disabled_modules })
}

pub(crate) fn default_pinned_lock_path(profile: &Profile) -> PathBuf {
    PathBuf::from("/etc/harmonia/locks")
        .join(&profile.id)
        .join("pinned-artifacts.json")
}

pub(crate) fn load_profile(path: &Path) -> io::Result<Profile> {
    let text = fs::read_to_string(path)?;
    let profile: Profile = serde_json::from_str(&text).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("profile-parse-failed {}: {err}", path.display()),
        )
    })?;
    // Profiles evolve independently from the installed engine. Keep parsing
    // backward-compatible; consumers that execute package work require
    // package_authority at that operation boundary.
    if let Some(package_authority) = profile.package_authority.as_ref() {
        package_authority
            .backend()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    }
    Ok(profile)
}

pub(crate) fn load_module(path: &Path) -> Result<ModuleManifest, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("module-read-failed {}: {e}", path.display()))?;
    let raw: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("module-parse-failed {}: {e}", path.display()))?;
    for field in [
        "steps",
        "tool",
        "command",
        "action",
        "actions",
        "args",
        "cwd",
        "apply_only",
    ] {
        if raw.get(field).is_some() {
            return Err(format!(
                "module-sidecar-behavior-field-rejected {} field={}",
                path.display(),
                field
            ));
        }
    }
    serde_json::from_value(raw).map_err(|e| format!("module-parse-failed {}: {e}", path.display()))
}

pub(crate) fn load_profile_module(
    module_root: &Path,
    module_id: &str,
) -> Result<LoadedModule, String> {
    let module_dir = module_root.join(module_id);
    let manifest_path = module_dir.join("manifest.json");
    if manifest_path.exists() && is_ladder_manifest(&manifest_path) {
        return load_ladder_manifest(&manifest_path).and_then(|manifest| {
            crate::ladder::validate_package_pin_module(
                module_id,
                &manifest.id,
                &manifest.package_pins,
            )?;
            Ok(LoadedModule::Ladder(manifest))
        });
    }
    let sidecar_path = module_dir.join("sidecar.json");
    if sidecar_path.exists() {
        return load_module(&sidecar_path).map(LoadedModule::Sidecar);
    }
    load_module(&sidecar_path).map(LoadedModule::Sidecar)
}

pub(crate) fn resolve_group_selections(
    profile: &Profile,
    _module_root: &Path,
    receipt_dir: &Path,
    projection: &ProfileProjection,
) -> Result<BTreeMap<String, GroupSelection>, String> {
    let mut groups: BTreeMap<String, Vec<(String, LadderManifest)>> = BTreeMap::new();
    for module_id in &profile.modules {
        let Some(projected) = projection.modules.get(module_id) else {
            continue;
        };
        let LoadedModule::Ladder(module) = &projected.loaded else {
            continue;
        };
        let Some(group_id) = module.group.as_ref().map(|group| group.group_id.clone()) else {
            continue;
        };
        groups
            .entry(group_id)
            .or_default()
            .push((module_id.clone(), module.clone()));
    }

    let mut selections = BTreeMap::new();
    for (group_id, mut members) in groups {
        if members.len() < 2 {
            continue;
        }
        members.sort_by(|(left_id, left), (right_id, right)| {
            left.group
                .as_ref()
                .map(|group| group.group_order)
                .unwrap_or(i64::MAX)
                .cmp(
                    &right
                        .group
                        .as_ref()
                        .map(|group| group.group_order)
                        .unwrap_or(i64::MAX),
                )
                .then_with(|| left_id.cmp(right_id))
        });
        let group_receipt_dir = receipt_dir.join("groups").join(&group_id);
        let mut observations = Vec::new();
        let mut live_winners = Vec::new();
        for (module_id, manifest) in &members {
            let group = manifest.group.as_ref().expect("grouped manifest");
            let probe_dir = group_receipt_dir.join("probes").join(module_id);
            let projected = projection
                .modules
                .get(module_id)
                .ok_or_else(|| format!("module-not-in-projection-{module_id}"))?;
            let probe = projected
                .group_probe
                .as_ref()
                .ok_or_else(|| format!("module-{}-has-no-group", module_id))?;
            let outcome = crate::bands::compare::execute_group_live_probe_validated(
                manifest, probe, &probe_dir,
            )?;
            let signal = if outcome.ok {
                "probe-live".to_string()
            } else {
                outcome.message.clone()
            };
            if outcome.ok {
                live_winners.push(module_id.clone());
            }
            observations.push(GroupProbeObservation {
                module_id: module_id.clone(),
                ok: outcome.ok,
                tool: group.live_probe.tool.clone(),
                permutation: group.live_probe.permutation.clone(),
                signal,
            });
        }
        let winner = live_winners
            .first()
            .cloned()
            .unwrap_or_else(|| members[0].0.clone());
        let losers: Vec<String> = members
            .iter()
            .map(|(module_id, _)| module_id.clone())
            .filter(|module_id| module_id != &winner)
            .collect();
        let selection = GroupSelection {
            group_id: group_id.clone(),
            winner: winner.clone(),
            losers: losers.clone(),
            observations,
        };
        write_group_selection_receipt(receipt_dir, &selection)?;
        selections.insert(group_id, selection);
    }
    Ok(selections)
}

pub(crate) fn group_loser_winners(
    selections: &BTreeMap<String, GroupSelection>,
) -> BTreeMap<String, String> {
    let mut losers = BTreeMap::new();
    for selection in selections.values() {
        for loser in &selection.losers {
            losers.insert(loser.clone(), selection.winner.clone());
        }
    }
    losers
}

fn write_group_selection_receipt(
    receipt_dir: &Path,
    selection: &GroupSelection,
) -> Result<(), String> {
    crate::atoms::attest::prepare_receipt_parent(&receipt_dir.join("groups"))?;
    crate::atoms::attest::write_json_atomic(
        &receipt_dir
            .join("groups")
            .join(format!("{}-selection.json", selection.group_id)),
        &json!({
            "schema": "harmonia.group.selection.v1",
            "group_id": selection.group_id,
            "probes_observed": selection.observations.iter().map(|probe| json!({
                "module_id": probe.module_id,
                "ok": probe.ok,
                "tool": probe.tool,
                "permutation": probe.permutation,
                "signal": probe.signal,
            })).collect::<Vec<_>>(),
            "winner": selection.winner,
            "losers": selection.losers,
        }),
    )
}
