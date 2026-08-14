use super::Band;
use crate::ladder::{LadderManifest, RoutineStep};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) fn enter(enter: &mut impl FnMut(Band) -> Result<(), String>) -> Result<(), String> {
    enter(Band::BackfillFiles)
}

pub(crate) fn lower_service_runtime_steps(manifest: &mut LadderManifest) {
    for step in &mut manifest.ladder {
        if step.tool != "routine" || step.permutation != "execute" {
            continue;
        }
        let Some(index) = step
            .steps
            .iter()
            .position(|c| c.name == "managed-files" && c.tool == "service-runtime")
        else {
            continue;
        };
        let original = step.steps[index].clone();
        let declarations = original
            .args
            .get("managed_files")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut configuration = Vec::new();
        let mut replacement = Vec::with_capacity(declarations.len() + 1);
        for declaration in declarations {
            let Some(path) = declaration.get("path").and_then(Value::as_str) else {
                continue;
            };
            if crate::ladder::is_configuration_path(Path::new(path)) {
                configuration.push(declaration);
                continue;
            }
            let mut args = BTreeMap::new();
            args.insert("path".into(), Value::String(path.into()));
            args.insert(
                "declared_bytes".into(),
                declaration
                    .get("content")
                    .cloned()
                    .unwrap_or_else(|| Value::String(String::new())),
            );
            for key in ["mode", "uid", "gid"] {
                if let Some(value) = declaration.get(key) {
                    args.insert(key.into(), value.clone());
                }
            }
            replacement.push(RoutineStep {
                name: format!("managed-file-{}", replacement.len()),
                tool: "place-file".into(),
                permutation: Some("place".into()),
                args,
                extra: BTreeMap::new(),
            });
        }
        if let Some(source) = original.args.get("caduceus_profile_source") {
            if let Some(path) = source.get("path").and_then(Value::as_str) {
                if crate::ladder::is_configuration_path(Path::new(path)) {
                    configuration.push(serde_json::json!({
                        "path": path,
                        "content": "",
                        "mode": source.get("mode").cloned().unwrap_or(Value::Null)
                    }));
                }
            }
        }
        // Keep the proposal after the retained RestartServices suffix. The
        // place-file children remain the BackfillFiles mutation lane.
        let proposal = if !configuration.is_empty() {
            let mut config = original;
            config
                .args
                .insert("managed_files".into(), Value::Array(configuration));
            config.permutation = Some("configuration-proposal".into());
            Some(config)
        } else {
            None
        };
        step.steps.splice(index..=index, replacement);
        if let Some(proposal) = proposal {
            step.steps.push(proposal);
        }
    }
}
