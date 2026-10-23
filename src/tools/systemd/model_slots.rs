//! One transaction-local observation of the slot lever; no settings or history writer.
use crate::atoms::ask::backfill_file::{BackupPolicy, DeclaredOwnership};
use crate::atoms::ask::change_unit;
use crate::atoms::comparison::{self, DiffDecision};
use crate::atoms::r#do::{backfill_file, change_unit::UnitVerb, InvocationKey};
use crate::OperationOutcome;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

const TARGET: &str = "/etc/systemd/system/model-slot@.service";
const PAYLOAD: &str = "files_root/etc/systemd/system/model-slot@.service";
const SLOTS: [&str; 3] = ["brain", "embed", "ear"];

#[derive(Clone, Serialize)]
pub(crate) struct UnitState {
    enabled: bool,
    active: bool,
}

#[derive(Serialize)]
pub(crate) struct Instance {
    unit: String,
    desired_enabled: bool,
    observed: UnitState,
    actions: Vec<&'static str>,
}

#[derive(Serialize)]
pub(crate) struct Template {
    target: &'static str,
    changed: bool,
    desired_sha256: String,
    mode: u32,
    uid: u32,
    gid: u32,
    #[serde(skip)]
    bytes: Vec<u8>,
}

#[derive(Serialize)]
pub(crate) struct Plan {
    status: &'static str,
    template: Option<Template>,
    manager_actions: Vec<&'static str>,
    instances: Vec<Instance>,
}

impl Plan {
    fn different(&self) -> bool {
        self.template
            .as_ref()
            .is_some_and(|template| template.changed)
            || self
                .instances
                .iter()
                .any(|instance| !instance.actions.is_empty())
    }
}

fn observe_unit(unit: &str) -> Result<UnitState, String> {
    let expected = BTreeMap::from([
        ("LoadState".into(), Value::Null),
        ("ActiveState".into(), Value::Null),
        ("UnitFileState".into(), Value::Null),
    ]);
    let (command, properties) = change_unit::show_properties(unit, &expected);
    let load = properties.get("LoadState").map(String::as_str);
    if load == Some("not-found") {
        return Ok(UnitState {
            enabled: false,
            active: false,
        });
    }
    if !command.ok || load != Some("loaded") {
        return Err(format!("model-slots-unit-observation-failed:{unit}"));
    }
    let active = properties.get("ActiveState").map(String::as_str);
    let enabled = properties.get("UnitFileState").map(String::as_str);
    if !matches!(active, Some("active" | "inactive" | "failed"))
        || !matches!(enabled, Some("enabled" | "disabled"))
    {
        return Err(format!("model-slots-unit-state-unsettled:{unit}"));
    }
    Ok(UnitState {
        enabled: enabled == Some("enabled"),
        active: active == Some("active"),
    })
}

pub(crate) fn plan(module_dir: &Path) -> Result<Plan, String> {
    let Some(local_ai) =
        crate::bands::stage_profile::read_device_local_ai()?.filter(|value| !value.is_null())
    else {
        return Ok(Plan {
            status: "local-ai-absent",
            template: None,
            manager_actions: Vec::new(),
            instances: Vec::new(),
        });
    };
    if !local_ai.is_object() {
        return Err("model-slots-invalid-local_ai".into());
    }
    if local_ai
        .get("schema")
        .is_some_and(|schema| schema != "appliance.local_ai.v1")
    {
        return Err("model-slots-foreign-schema".into());
    }
    let slots = local_ai.get("slots").filter(|value| !value.is_null());
    if slots.is_some_and(|value| !value.is_object()) {
        return Err("model-slots-invalid-local_ai.slots".into());
    }
    // Validate every desired slot before observing a target or acquiring a mutation capability.
    let mut desired = Vec::new();
    for slot in SLOTS {
        let model = slots
            .and_then(|slots| slots.get(slot))
            .and_then(|slot| slot.get("model"));
        let filled = match model {
            None | Some(Value::Null) => false,
            Some(Value::String(model)) if !model.is_empty() => true,
            _ => return Err(format!("model-slots-invalid-local_ai.slots.{slot}.model")),
        };
        desired.push((format!("model-slot@{slot}.service"), filled));
    }
    let source = module_dir.join(PAYLOAD);
    let metadata = std::fs::symlink_metadata(&source)
        .map_err(|error| format!("model-slots-template-read-failed: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("model-slots-template-not-regular".into());
    }
    let bytes = std::fs::read(&source)
        .map_err(|error| format!("model-slots-template-read-failed: {error}"))?;
    let observed = crate::atoms::ask::backfill_file::probe::file(
        Path::new(TARGET),
        &bytes,
        Some(0o644),
        DeclaredOwnership {
            uid: Some(0),
            gid: Some(0),
        },
        None,
    )?;
    if observed.existed && !observed.regular {
        return Err("model-slots-template-target-not-regular".into());
    }
    let changed = !observed.current();
    let mut instances = Vec::new();
    for (unit, filled) in desired {
        let observed = observe_unit(&unit)?;
        let mut actions = Vec::new();
        if filled {
            if !observed.enabled {
                actions.push("enable");
            }
            if !observed.active {
                actions.push("start");
            } else if changed {
                actions.push("restart");
            }
        } else {
            if observed.active {
                actions.push("stop");
            }
            if observed.enabled {
                actions.push("disable");
            }
        }
        instances.push(Instance {
            unit,
            desired_enabled: filled,
            observed,
            actions,
        });
    }
    Ok(Plan {
        status: if changed
            || instances
                .iter()
                .any(|instance| !instance.actions.is_empty())
        {
            "different"
        } else {
            "current"
        },
        template: Some(Template {
            target: TARGET,
            changed,
            desired_sha256: crate::atoms::file_sha256(&bytes),
            mode: 0o644,
            uid: 0,
            gid: 0,
            bytes,
        }),
        manager_actions: if changed {
            vec!["daemon-reload"]
        } else {
            Vec::new()
        },
        instances,
    })
}

fn change(unit: &str, action: &str, invocation: &InvocationKey) -> Result<bool, String> {
    let moved = comparison::execute_once(
        "model-slot-unit",
        || observe_unit(unit),
        |state| {
            let different = match action {
                "enable" => !state.enabled,
                "disable" => state.enabled,
                "start" => !state.active,
                "stop" | "restart" => state.active,
                _ => false,
            };
            if different {
                DiffDecision::Different
            } else {
                DiffDecision::Empty
            }
        },
        |authorization, _| {
            let verb = match action {
                "enable" => UnitVerb::Enable,
                "disable" => UnitVerb::Disable,
                "start" => UnitVerb::Start,
                "stop" => UnitVerb::Stop,
                "restart" => UnitVerb::Restart,
                _ => return Err("model-slots-action-invalid".to_string()),
            };
            let result = crate::atoms::r#do::change_unit::unit_change_scoped(
                &authorization,
                invocation,
                unit,
                verb,
                false,
                None,
                30,
            )?;
            if !result.ok {
                return Err(format!("model-slots-{action}-failed:{unit}"));
            }
            let after = observe_unit(unit)?;
            let current = match action {
                "enable" => after.enabled,
                "disable" => !after.enabled,
                "start" | "restart" => after.active,
                "stop" => !after.active,
                _ => false,
            };
            if !current {
                return Err(format!("model-slots-{action}-readback-failed:{unit}"));
            }
            Ok(true)
        },
    )?;
    Ok(matches!(
        moved,
        comparison::ComparisonRun::Moved { movement: true, .. }
    ))
}

pub(crate) fn execute(
    module_dir: &Path,
    invocation: Option<&InvocationKey>,
) -> Result<OperationOutcome, String> {
    let plan = plan(module_dir)?;
    if invocation.is_none() || !plan.different() {
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: invocation.is_none(),
            message: serde_json::to_string(&plan).map_err(|error| error.to_string())?,
            command: None,
        });
    }
    let invocation = invocation.ok_or("invocation-key-missing")?;
    let mut changed = false;
    let mut template_moved = false;
    if let Some(template) = &plan.template {
        if template.changed {
            let file = backfill_file::execute(backfill_file::BackfillFileRequest {
                path: Path::new(TARGET),
                declared_bytes: &template.bytes,
                mode: Some(0o644),
                ownership: DeclaredOwnership {
                    uid: Some(0),
                    gid: Some(0),
                },
                backup: BackupPolicy::None,
                invocation: Some(invocation),
            })?;
            changed |= file.movement.changed();
            template_moved = file.movement.changed();
            if template_moved {
                comparison::execute_once(
                    "model-slots-daemon-reload",
                    || Ok::<_, String>(template_moved),
                    |moved| {
                        if *moved {
                            DiffDecision::Different
                        } else {
                            DiffDecision::Empty
                        }
                    },
                    |authorization, _| {
                        let result = crate::atoms::r#do::change_unit::unit_change_scoped(
                            &authorization,
                            invocation,
                            "",
                            UnitVerb::DaemonReload,
                            false,
                            None,
                            30,
                        )?;
                        if result.ok {
                            Ok(())
                        } else {
                            Err("model-slots-daemon-reload-failed".into())
                        }
                    },
                )?;
            }
        }
    }
    for instance in &plan.instances {
        for action in &instance.actions {
            if *action != "restart" || template_moved {
                changed |= change(&instance.unit, action, invocation)?;
            }
        }
        let after = observe_unit(&instance.unit)?;
        if after.enabled != instance.desired_enabled || after.active != instance.desired_enabled {
            return Err(format!(
                "model-slots-instance-readback-failed:{}",
                instance.unit
            ));
        }
    }
    Ok(OperationOutcome {
        ok: true,
        changed,
        skipped: false,
        message: "model-slots-converged".into(),
        command: None,
    })
}
