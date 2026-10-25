use serde_json::Value;
use std::fs;
use std::path::{Component, Path, PathBuf};

fn relative_path(value: &Value, field: &str) -> Result<PathBuf, String> {
    let text = value
        .as_str()
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| format!("profile-input-{field}-invalid"))?;
    let path = Path::new(text);
    if path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(format!("profile-input-{field}-invalid"));
    }
    Ok(path.to_path_buf())
}

/// Profile directory names share the appliance's one-normal-component rule.
/// Sold names retain the asset resolver's case-compatible spelling.
fn profile_segment(value: &str, field: &str) -> Result<String, String> {
    let segment = value.trim();
    let path = Path::new(segment);
    let mut components = path.components();
    let one_normal_component = matches!(components.next(), Some(Component::Normal(_)))
        && components.next().is_none();
    if segment.is_empty()
        || segment.contains('/')
        || segment.contains('\\')
        || !one_normal_component
    {
        return Err(format!("profile-input-{field}-invalid"));
    }
    Ok(segment.to_owned())
}

fn worn_profile_id() -> Result<String, String> {
    let path = Path::new("/etc/appliance/profile.json");
    let text = fs::read_to_string(path)
        .map_err(|error| format!("profile-input-worn-profile-read-failed {}: {error}", path.display()))?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|error| format!("profile-input-worn-profile-parse-failed {}: {error}", path.display()))?;
    let profile = value
        .get("profile")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("profile-input-worn-profile-invalid {}", path.display()))?;
    profile_segment(profile, "worn-profile")
        .map_err(|_| format!("profile-input-worn-profile-invalid {}", path.display()))
}

fn profile_id(index: &Path) -> Result<String, String> {
    let text = fs::read_to_string(index)
        .map_err(|error| format!("profile-input-index-read-failed {}: {error}", index.display()))?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|error| format!("profile-input-index-parse-failed {}: {error}", index.display()))?;
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("profile-input-index-id-invalid {}", index.display()))?;
    profile_segment(id, "index-id")
        .map_err(|_| format!("profile-input-index-id-invalid {}", index.display()))
}

fn read_fragment(path: &Path) -> Result<Option<Value>, String> {
    match fs::read_to_string(path) {
        Ok(text) => {
            let value: Value = serde_json::from_str(&text)
                .map_err(|error| format!("profile-input-fragment-parse-failed {}: {error}", path.display()))?;
            if !value.is_object() {
                return Err(format!("profile-input-fragment-not-object {}", path.display()));
            }
            Ok(Some(value))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("profile-input-fragment-read-failed {}: {error}", path.display())),
    }
}

fn profile_ids_agree(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn read_profile_fragment(
    root: &Path,
    profile: &str,
    fragment: &Path,
) -> Result<Option<Value>, String> {
    let exact = read_fragment(&root.join(profile).join(fragment))?;
    if exact.is_some() {
        return Ok(exact);
    }
    let lowercase = profile.to_ascii_lowercase();
    if lowercase.as_str() == profile {
        Ok(None)
    } else {
        read_fragment(&root.join(lowercase).join(fragment))
    }
}

fn selected_index_extends(index: &Path) -> Result<Option<String>, String> {
    if index.file_name().and_then(|name| name.to_str()) != Some("index.json") {
        return Ok(None);
    }
    let module_root = index
        .parent()
        .ok_or_else(|| "profile-input-index-parent-missing".to_string())?
        .join("modules");
    crate::bands::stage_profile::profile_extends(&module_root)?
        .map(|base| {
            profile_segment(&base, "base")
                .map_err(|_| format!("profile-input-base-invalid {base}"))
        })
        .transpose()
}

fn appliance_caduceus_health_url() -> Result<String, String> {
    let base_url = crate::atoms::ask::caduceus_door::base_url()
        .map_err(|signal| signal.to_string())?;
    Ok(format!("{base_url}/health"))
}

fn resolve_fragment_url(value: &Value) -> Result<Value, String> {
    if let Some(descriptor) = value.as_object() {
        if descriptor.get("from").and_then(Value::as_str)
            == Some("appliance.caduceus.bind")
        {
            return appliance_caduceus_health_url().map(Value::String);
        }
        return Err("profile-input-url-descriptor-invalid".into());
    }
    Ok(value.clone())
}

/// Select the declared profile fragment before ladder normalization and lowering.
pub(crate) fn apply(
    raw: &mut Value,
    manifest_path: &Path,
    selected_profile_index: Option<&Path>,
) -> Result<(), String> {
    let Some(selector) = raw.get("profile_input").filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let selector = selector
        .as_object()
        .ok_or_else(|| "profile-input-selector-invalid".to_string())?;
    if selector.get("axis").and_then(Value::as_str) != Some("profile") {
        return Err("profile-input-axis-invalid".into());
    }
    let fragment = relative_path(
        selector
            .get("fragment")
            .ok_or_else(|| "profile-input-fragment-invalid".to_string())?,
        "fragment",
    )?;
    let fallback = selector
        .get("fallback")
        .filter(|value| !value.is_null())
        .map(|value| {
            let id = value
                .as_str()
                .ok_or_else(|| "profile-input-fallback-invalid".to_string())?;
            profile_segment(id, "fallback")
                .map_err(|_| "profile-input-fallback-invalid".to_string())
        })
        .transpose()?;
    let worn = worn_profile_id()?;
    let files_root = raw
        .get("files_root")
        .and_then(Value::as_str)
        .filter(|path| !path.trim().is_empty())
        .ok_or_else(|| "profile-input-files-root-missing".to_string())?;
    let files_root = Path::new(files_root);
    if files_root.is_absolute()
        || !files_root
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err("profile-input-files-root-invalid".into());
    }
    let root = manifest_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(files_root);

    // The worn body's direct fragment is authoritative even when the selected
    // plan index names another profile. Only a matching index may lend lineage.
    let selected_fragment = if let Some(value) = read_profile_fragment(&root, &worn, &fragment)? {
        value
    } else {
        let matching_index = selected_profile_index
            .map(profile_id)
            .transpose()?
            .filter(|index_id| profile_ids_agree(index_id, &worn));
        let base_fragment = if let (Some(index), Some(_)) = (selected_profile_index, matching_index.as_ref()) {
            selected_index_extends(index)?
                .map(|base| read_profile_fragment(&root, &base, &fragment))
                .transpose()?
                .flatten()
        } else {
            None
        };
        if let Some(value) = base_fragment {
            value
        } else if let Some(fallback) = fallback {
            let fallback_path = root.join(&fallback).join(&fragment);
            read_profile_fragment(&root, &fallback, &fragment)?.ok_or_else(|| {
                format!("profile-input-fallback-fragment-missing {}", fallback_path.display())
            })?
        } else {
            return Err(format!("profile-input-fragment-missing profile={worn}"));
        }
    };
    let service_step = raw
        .get_mut("ladder")
        .and_then(Value::as_array_mut)
        .and_then(|steps| {
            steps.iter_mut().find(|step| {
                step.get("tool").and_then(Value::as_str) == Some("service-runtime")
                    && step.get("permutation").and_then(Value::as_str) == Some("converge")
            })
        })
        .ok_or_else(|| "profile-input-service-runtime-step-missing".to_string())?;
    let args = service_step
        .get_mut("args")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "profile-input-service-runtime-args-invalid".to_string())?;

    // The fragment owns only these three runtime inputs. Unknown fields are
    // semantically skipped and cannot replace component or install metadata.
    for key in ["url", "managed_files", "caduceus_profile_source"] {
        if let Some(value) = selected_fragment.get(key) {
            let value = if key == "url" {
                resolve_fragment_url(value)?
            } else {
                value.clone()
            };
            args.insert(key.to_string(), value);
        }
    }

    // Optional profile values render only explicit unit-environment tokens;
    // they cannot replace component, artifact, or installation metadata.
    if let Some(environment) = selected_fragment
        .get("unit_environment")
        .filter(|value| !value.is_null())
    {
        let environment = environment
            .as_object()
            .ok_or_else(|| "profile-input-unit-environment-invalid".to_string())?;
        let mut replacements = Vec::new();
        for (name, value) in environment {
            let origin = if value.get("from").and_then(Value::as_str)
                == Some("appliance.caduceus.bind")
            {
                crate::atoms::ask::caduceus_door::base_url()
                    .map_err(str::to_string)?
            } else {
                value.as_str().ok_or_else(|| {
                    format!("profile-input-unit-environment-value-invalid {name}")
                })?
            };
            replacements.push((format!("${{unit_environment.{name}}}"), origin.to_owned()));
        }
        if let Some(files) = args.get_mut("managed_files").and_then(Value::as_array_mut) {
            for file in files {
                if let Some(Value::String(content)) = file.get_mut("content") {
                    for (token, value) in &replacements {
                        *content = content.replace(token, value);
                    }
                }
            }
        }
    }
    Ok(())
}
