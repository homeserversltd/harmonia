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

#[cfg(any(test, feature = "test-facade"))]
pub(crate) const TEST_APPLIANCE_CONFIG_PATH_ENV: &str = "HARMONIA_TEST_APPLIANCE_CONFIG_PATH";

fn appliance_config_path() -> PathBuf {
    #[cfg(any(test, feature = "test-facade"))]
    if let Some(path) = std::env::var_os(TEST_APPLIANCE_CONFIG_PATH_ENV) {
        return PathBuf::from(path);
    }
    PathBuf::from(APPLIANCE_CONFIG_PATH)
}

#[derive(Default)]
pub(crate) struct DeviceModulePolicy {
    pub(crate) disabled_modules: BTreeSet<String>,
    pub(crate) syzygy_declaration: Option<SyzygyDeclaration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeviceUpdateCadence {
    pub(crate) calendar: String,
    pub(crate) source: &'static str,
}

pub(crate) fn read_device_update_cadence() -> Result<DeviceUpdateCadence, String> {
    read_device_update_cadence_at(&appliance_config_path())
}

fn read_device_update_cadence_at(path: &Path) -> Result<DeviceUpdateCadence, String> {
    let Some(config) = read_device_config_at(path)? else {
        return Ok(DeviceUpdateCadence {
            calendar: "hourly".into(),
            source: "default",
        });
    };
    let Some(harmonia) = config.get("harmonia") else {
        return Ok(DeviceUpdateCadence {
            calendar: "hourly".into(),
            source: "default",
        });
    };
    let Some(value) = harmonia.get("update_interval") else {
        return Ok(DeviceUpdateCadence {
            calendar: "hourly".into(),
            source: "default",
        });
    };
    let calendar = value.as_str().ok_or_else(|| {
        "invalid-config-key harmonia.update_interval: expected a systemd calendar expression"
            .to_string()
    })?;
    let fields: Vec<&str> = calendar.split_whitespace().collect();
    let shape_ok = matches!(
        calendar,
        "hourly" | "daily" | "weekly" | "monthly" | "quarterly" | "yearly" | "annually"
    ) || valid_minute_interval(calendar)
        || (fields.len() == 2 && valid_date(fields[0]) && valid_time(fields[1]))
        || (fields.len() == 3
            && valid_weekday(fields[0])
            && valid_date(fields[1])
            && valid_time(fields[2]));
    if !shape_ok
        || calendar.is_empty()
        || calendar.trim() != calendar
        || calendar.contains('\n')
        || calendar.contains('\r')
    {
        return Err(
            "invalid-config-key harmonia.update_interval: expected a systemd calendar expression"
                .into(),
        );
    }
    Ok(DeviceUpdateCadence {
        calendar: calendar.to_string(),
        source: "declared",
    })
}

fn valid_atom(value: &str, allow_letters: bool) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_digit()
                || (allow_letters && character.is_ascii_alphabetic())
                || matches!(character, '*' | '.' | ',' | '~' | '+' | '-')
        })
}

fn valid_minute_interval(value: &str) -> bool {
    let Some(minutes) = value.strip_prefix("*:") else {
        return false;
    };
    let mut parts = minutes.split('/');
    let minute = parts.next().unwrap_or_default();
    let divisor = parts.next();
    if parts.next().is_some()
        || minute.is_empty()
        || minute.len() > 2
        || !minute.bytes().all(|byte| byte.is_ascii_digit())
        || minute.parse::<u8>().map_or(true, |number| number > 59)
    {
        return false;
    }
    divisor.is_none_or(|value| {
        !value.is_empty()
            && value.as_bytes()[0].is_ascii_digit()
            && value.as_bytes()[0] != b'0'
            && value.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn valid_date(value: &str) -> bool {
    let fields: Vec<&str> = value.split('-').collect();
    fields.len() == 3 && fields.iter().all(|field| valid_atom(field, false))
}

fn valid_time(value: &str) -> bool {
    let fields: Vec<&str> = value.split(':').collect();
    (fields.len() == 2 || fields.len() == 3) && fields.iter().all(|field| valid_atom(field, false))
}

fn valid_weekday(value: &str) -> bool {
    valid_atom(value, true)
}

fn read_device_config_at(path: &Path) -> Result<Option<serde_json::Value>, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(format!(
                "appliance-config-read-failed {}: {err}",
                path.display()
            ))
        }
    };
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|err| format!("appliance-config-parse-failed {}: {err}", path.display()))
}

fn parse_syzygy_declaration(
    config: &serde_json::Value,
    path: &Path,
) -> Result<Option<SyzygyDeclaration>, String> {
    let Some(raw) = config.get("syzygy") else {
        return Ok(None);
    };
    let declaration: SyzygyDeclaration = serde_json::from_value(raw.clone()).map_err(|err| {
        format!(
            "appliance-config-syzygy-parse-failed {}: {err}",
            path.display()
        )
    })?;
    if declaration.schema != "appliance.syzygy.v1" {
        return Err(format!(
            "device-profile-syzygy-schema-unsupported {}",
            declaration.schema
        ));
    }
    if let Some(face) = declaration.gui_face.as_deref() {
        if !matches!(face, "Hyprland" | "Arcadia" | "Coronatio") {
            return Err(format!("device-profile-syzygy-gui-face-unsupported {face}"));
        }
    }
    Ok(Some(declaration))
}

pub(crate) fn read_device_module_policy() -> Result<DeviceModulePolicy, String> {
    read_device_module_policy_at(&appliance_config_path())
}

fn read_device_module_policy_at(path: &Path) -> Result<DeviceModulePolicy, String> {
    let Some(config) = read_device_config_at(path)? else {
        return Ok(DeviceModulePolicy::default());
    };
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
    let syzygy_declaration = parse_syzygy_declaration(&config, path)?;
    Ok(DeviceModulePolicy {
        disabled_modules,
        syzygy_declaration,
    })
}

/// The gateway roster port is a separate, integer device declaration.
pub(crate) fn read_device_caduceus_seat_port() -> Result<Option<u16>, String> {
    Ok(
        read_device_config_at(&appliance_config_path())?.and_then(|config| {
            let port = config.get("caduceus")?.get("seat_port")?.as_u64()?;
            u16::try_from(port).ok().filter(|port| *port != 0)
        }),
    )
}

/// Read the optional door declaration independently of module/syzygy policy.
/// Missing or ill-typed binds are an observation for door consumers, not a
/// module-selection failure.
pub(crate) fn read_device_caduceus_bind() -> Result<Option<String>, String> {
    Ok(
        read_device_config_at(&appliance_config_path())?.and_then(|config| {
            config
                .get("caduceus")?
                .get("bind")?
                .as_str()
                .map(str::to_owned)
        }),
    )
}

pub(crate) fn read_device_syzygy_declaration() -> Result<Option<SyzygyDeclaration>, String> {
    Ok(read_device_module_policy()?.syzygy_declaration)
}

pub(crate) fn default_pinned_lock_path(profile: &Profile) -> PathBuf {
    PathBuf::from("/etc/harmonia/locks")
        .join(&profile.id)
        .join("pinned-artifacts.json")
}

pub(crate) fn load_profile(path: &Path) -> io::Result<Profile> {
    let text = fs::read_to_string(path)?;
    let mut profile: Profile = serde_json::from_str(&text).map_err(|err| {
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
    let raw: serde_json::Value = serde_json::from_str(&text).map_err(|err| {
        io::Error::new(io::ErrorKind::InvalidData, format!("profile-parse-failed {}: {err}", path.display()))
    })?;
    let base_id = match raw.get("extends") {
        None | Some(serde_json::Value::Null) => return Ok(profile),
        Some(value) => value.as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("profile-extends-invalid overlay={} value={value}", profile.id),
            )
        })?,
    };
    validate_profile_id(base_id).map_err(|reason| io::Error::new(io::ErrorKind::InvalidData, reason))?;
    let profiles_root = path.parent().and_then(Path::parent).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("profile-extends-root-missing overlay={}", profile.id))
    })?;
    let base_path = profiles_root.join(base_id).join("index.json");
    let base_text = fs::read_to_string(&base_path).map_err(|err| {
        io::Error::new(io::ErrorKind::InvalidData, format!("profile-extends-base-read-failed overlay={} base={base_id}: {err}", profile.id))
    })?;
    let base_raw: serde_json::Value = serde_json::from_str(&base_text).map_err(|err| {
        io::Error::new(io::ErrorKind::InvalidData, format!("profile-extends-base-parse-failed overlay={} base={base_id}: {err}", profile.id))
    })?;
    if let Some(declared) = base_raw.get("extends").filter(|value| !value.is_null()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "profile-extends-chain-refused overlay={} base={} base_extends={declared}",
                profile.id, base_id
            ),
        ));
    }
    let base: Profile = serde_json::from_str(&base_text).map_err(|err| {
        io::Error::new(io::ErrorKind::InvalidData, format!("profile-extends-base-parse-failed overlay={} base={base_id}: {err}", profile.id))
    })?;
    if let Some(package_authority) = base.package_authority.as_ref() {
        package_authority
            .backend()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    }
    if base.id != base_id {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("profile-extends-base-id-mismatch overlay={} base={} index={}", profile.id, base_id, base.id)));
    }
    if let Some(duplicate) = base.modules.iter().find(|id| profile.modules.contains(id)) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("profile-extends-duplicate-module overlay={} base={} module={duplicate}", profile.id, base_id)));
    }
    profile.modules.splice(0..0, base.modules);
    Ok(profile)
}

fn validate_profile_id(profile_id: &str) -> Result<(), String> {
    if profile_id.trim().is_empty() || profile_id.contains('/') || profile_id.contains('\\') || profile_id == "." || profile_id == ".." {
        Err(format!("profile-id-invalid id={profile_id}"))
    } else {
        Ok(())
    }
}

/// Return the declared one-level base for an already selected module root.
pub(crate) fn profile_extends(module_root: &Path) -> Result<Option<String>, String> {
    let index = module_root.parent().map(|dir| dir.join("index.json"));
    let Some(index) = index else { return Ok(None) };
    let text = match fs::read_to_string(&index) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("profile-index-read-failed {}: {error}", index.display())),
    };
    let raw: serde_json::Value = serde_json::from_str(&text).map_err(|err| format!("profile-index-parse-failed {}: {err}", index.display()))?;
    match raw.get("extends").or_else(|| raw.get("source_extends")) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => {
            let id = value.as_str().ok_or_else(|| format!("profile-extends-invalid overlay={} value={value}", raw.get("id").and_then(serde_json::Value::as_str).unwrap_or("<unknown>")))?;
            validate_profile_id(id)?;
            Ok(Some(id.to_owned()))
        }
    }
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
    let module_dir = crate::bands::stage_profile::resolve_module_dir(module_root, module_id)?;
    let manifest_path = module_dir.join("manifest.json");
    if manifest_path.exists() && is_ladder_manifest(&manifest_path) {
        return load_ladder_manifest(&manifest_path).and_then(|manifest| {
            crate::tools::ladder::validate_package_pin_module(
                module_id,
                &manifest.id,
                &manifest.package_pins,
            )?;
            crate::tools::ladder::validate_package_ceiling_module(
                module_id,
                &manifest.id,
                &manifest.package_ceilings,
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

#[cfg(test)]
mod extends_profile_tests {
    use super::{load_profile, profile_extends};
    use std::fs;

    #[test]
    fn one_level_extension_unions_base_first_and_resolves_each_local_seat() {
        let root = tempfile::tempdir().unwrap();
        let profiles = root.path().join("profiles");
        let base = profiles.join("public");
        let overlay = profiles.join("private");
        fs::create_dir_all(base.join("modules/base-only")).unwrap();
        fs::create_dir_all(overlay.join("modules/overlay-only")).unwrap();
        fs::write(base.join("modules/base-only/sidecar.json"), r#"{"id":"base-only"}"#).unwrap();
        fs::write(overlay.join("modules/overlay-only/sidecar.json"), r#"{"id":"overlay-only"}"#).unwrap();
        fs::write(base.join("index.json"), r#"{"id":"public","identity":"public-device","modules":["base-only"]}"#).unwrap();
        fs::write(overlay.join("index.json"), r#"{"id":"private","identity":"private-device","extends":"public","modules":["overlay-only"]}"#).unwrap();

        let profile = load_profile(&overlay.join("index.json")).unwrap();
        assert_eq!(profile.id, "private");
        assert_eq!(profile.identity, "private-device");
        assert_eq!(profile.modules, ["base-only", "overlay-only"]);
        let module_root = overlay.join("modules");
        assert_eq!(profile_extends(&module_root).unwrap().as_deref(), Some("public"));
        assert_eq!(super::super::resolve_module_dir(&module_root, "base-only").unwrap(), base.join("modules/base-only"));
        assert_eq!(super::super::resolve_module_dir(&module_root, "overlay-only").unwrap(), overlay.join("modules/overlay-only"));
    }

    #[test]
    fn staged_union_resolves_base_module_without_installed_base_profile_index() {
        let root = tempfile::tempdir().unwrap();
        let selected = root.path().join("profiles/overlay");
        for id in ["base-only", "overlay-only"] {
            let module = selected.join("modules").join(id);
            std::fs::create_dir_all(&module).unwrap();
            std::fs::write(module.join("manifest.json"), "{}\n").unwrap();
        }
        std::fs::write(
            selected.join("index.json"),
            r#"{"id":"overlay","identity":"overlay-device","source_extends":"base","modules":["overlay-only","base-only"]}"#,
        )
        .unwrap();
        assert!(!root.path().join("profiles/base/index.json").exists());
        assert_eq!(
            super::profile_extends(&selected.join("modules")).unwrap().as_deref(),
            Some("base")
        );
        assert_eq!(
            super::super::resolve_module_dir(&selected.join("modules"), "base-only").unwrap(),
            selected.join("modules/base-only")
        );
    }

    #[test]
    fn extension_refuses_chains_and_duplicate_ids_with_both_profile_ids() {
        let root = tempfile::tempdir().unwrap();
        let profiles = root.path().join("profiles");
        for (id, content) in [
            ("root", r#"{"id":"root","identity":"root","modules":["same"]}"#),
            ("chained", r#"{"id":"chained","identity":"chained","extends":"root","modules":[]}"#),
            ("duplicate", r#"{"id":"duplicate","identity":"duplicate","extends":"root","modules":["same"]}"#),
            ("chain-overlay", r#"{"id":"chain-overlay","identity":"overlay","extends":"chained","modules":[]}"#),
        ] {
            let dir = profiles.join(id);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("index.json"), content).unwrap();
        }
        let duplicate = load_profile(&profiles.join("duplicate/index.json")).unwrap_err().to_string();
        assert!(duplicate.contains("overlay=duplicate base=root module=same"));
        let chained = load_profile(&profiles.join("chain-overlay/index.json"))
            .unwrap_err()
            .to_string();
        assert!(chained.contains("profile-extends-chain-refused"));
        assert!(chained.contains("overlay=chain-overlay base=chained"));
    }
}

#[cfg(test)]
mod syzygy_tests {
    use super::read_device_module_policy_at;
    use crate::SyzygyDeclaration;
    use std::fs;

    fn config_file(config: serde_json::Value) -> tempfile::TempPath {
        let file = tempfile::NamedTempFile::new().expect("config file");
        fs::write(file.path(), config.to_string()).expect("config contents");
        file.into_temp_path()
    }

    #[test]
    fn reads_present_top_level_syzygy_declaration() {
        let path = config_file(serde_json::json!({
            "syzygy": {
                "schema": "appliance.syzygy.v1",
                "members": ["harmonia", "caduceus", "sbin", "coronatio"],
                "gui_face": "Coronatio"
            }
        }));

        let policy = read_device_module_policy_at(&path).expect("syzygy config");
        let declaration: SyzygyDeclaration = policy
            .syzygy_declaration
            .expect("present syzygy declaration");
        assert_eq!(declaration.schema, "appliance.syzygy.v1");
        assert_eq!(
            declaration.members,
            vec!["harmonia", "caduceus", "sbin", "coronatio"]
        );
        assert_eq!(declaration.gui_face.as_deref(), Some("Coronatio"));
    }

    #[test]
    fn absent_syzygy_is_pre_declaration() {
        let path = config_file(serde_json::json!({"harmonia": {"disabled_modules": []}}));
        let policy = read_device_module_policy_at(&path).expect("config without syzygy");
        assert!(policy.syzygy_declaration.is_none());
    }

    #[test]
    fn malformed_syzygy_is_rejected() {
        let path = config_file(serde_json::json!({
            "syzygy": {
                "schema": "foreign.invalid.syzygy.v99",
                "members": [],
                "gui_face": "Coronatio"
            }
        }));
        let error = match read_device_module_policy_at(&path) {
            Ok(_) => panic!("foreign schema must be rejected"),
            Err(error) => error,
        };
        assert!(error.contains("device-profile-syzygy-schema-unsupported"));
    }
}
