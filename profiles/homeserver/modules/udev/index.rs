use crate::module_dispatch::{reject_executable_sidecar, require_path, ModuleExecution};
use crate::*;
use serde_json::json;
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub(crate) const ID: &str = "udev";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    reject_executable_sidecar(module)?;
    require_path(module, &module.source_dir, "source-dir")?;
    if module.template_files.is_empty() {
        return Err(format!(
            "module-sidecar-missing-{}-template-files",
            module.id
        ));
    }
    for file in &module.template_files {
        crate::tools::files::validate_relative_path(Path::new(&file.source))?;
        validate_absolute_target(&file.target)?;
        if let Some(mode) = file.mode {
            if !(0o400..=0o777).contains(&mode) {
                return Err(format!("udev-mode-rejected-{}", file.target));
            }
        }
    }
    Ok(())
}

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
    harmonia_root: &Path,
) -> Result<ModuleExecution, String> {
    validate(module)?;
    let source_dir =
        resolve_profile_source_dir(module.source_dir.as_deref().unwrap(), harmonia_root);
    let render = render_templates(module, receipt_dir, &source_dir)?;
    let install = install_rendered(module, receipt_dir, apply)?;
    Ok(ModuleExecution::from_operations(
        vec![("render", render), ("install", install)],
        &module.id,
    ))
}

fn render_templates(
    module: &ModuleManifest,
    receipt_dir: &Path,
    source_dir: &Path,
) -> Result<OperationOutcome, String> {
    let render_dir = receipt_dir.join("rendered");
    fs::create_dir_all(&render_dir).map_err(|e| format!("udev-render-dir-failed: {e}"))?;
    let mut missing = Vec::new();
    let mut rendered = Vec::new();
    for file in &module.template_files {
        let source = source_dir.join(&file.source);
        if !source.is_file() {
            missing.push(file.source.clone());
            continue;
        }
        let raw = fs::read_to_string(&source).map_err(|e| {
            format!(
                "udev-template-read-failed {}: {e}",
                source.display()
            )
        })?;
        let body = render_template(&raw, &module.variables)?;
        let out = render_dir.join(rendered_name(&file.target));
        fs::write(&out, body.as_bytes())
            .map_err(|e| format!("udev-render-write-failed {}: {e}", out.display()))?;
        if let Some(mode) = file.mode {
            fs::set_permissions(&out, fs::Permissions::from_mode(mode))
                .map_err(|e| format!("udev-render-mode-failed {}: {e}", out.display()))?;
        }
        rendered.push(json!({"source": file.source, "target": file.target, "rendered": out, "mode": file.mode}));
    }
    let ok = missing.is_empty();
    write_json(
        &receipt_dir.join("udev-render.json"),
        &json!({
            "schema": "harmonia.homeserver.udev_files.render.v1",
            "ok": ok,
            "module": module.id,
            "source_dir": source_dir,
            "template_count": module.template_files.len(),
            "rendered": rendered,
            "missing": missing,
            "variables": module.variables.keys().collect::<BTreeSet<_>>(),
            "first_missing_signal": if ok { "none" } else { "homeserver-udev-template-missing" }
        }),
    )?;
    Ok(OperationOutcome {
        ok,
        changed: false,
        skipped: false,
        message: format!(
            "rendered {} udev file templates",
            module.template_files.len()
        ),
        command: None,
    })
}

fn install_rendered(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let render_dir = receipt_dir.join("rendered");
    let mut planned = Vec::new();
    let mut written = Vec::new();
    let mut missing = Vec::new();
    let mut changed = false;
    for file in &module.template_files {
        let rendered = render_dir.join(rendered_name(&file.target));
        if !rendered.is_file() {
            missing.push(file.target.clone());
            continue;
        }
        let target = PathBuf::from(&file.target);
        planned.push(json!({"rendered": rendered, "target": target, "mode": file.mode}));
        if apply {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    format!(
                        "udev-target-parent-failed {}: {e}",
                        parent.display()
                    )
                })?;
            }
            let before = fs::read(&target).ok();
            let desired = fs::read(&rendered).map_err(|e| {
                format!(
                    "udev-render-readback-failed {}: {e}",
                    rendered.display()
                )
            })?;
            if before.as_deref() != Some(desired.as_slice()) {
                let tmp = target.with_extension("harmonia-new");
                fs::write(&tmp, &desired).map_err(|e| {
                    format!("udev-target-write-failed {}: {e}", tmp.display())
                })?;
                if let Some(mode) = file.mode {
                    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode)).map_err(|e| {
                        format!("udev-target-mode-failed {}: {e}", tmp.display())
                    })?;
                }
                fs::rename(&tmp, &target).map_err(|e| {
                    format!(
                        "udev-target-promote-failed {}: {e}",
                        target.display()
                    )
                })?;
                written.push(file.target.clone());
                changed = true;
            }
        }
    }
    let ok = missing.is_empty();
    write_json(
        &receipt_dir.join("udev-install.json"),
        &json!({
            "schema": "harmonia.homeserver.udev_files.install.v1",
            "ok": ok,
            "module": module.id,
            "apply": apply,
            "planned": planned,
            "written": written,
            "missing": missing,
            "changed": changed,
            "first_missing_signal": if ok { "none" } else { "homeserver-udev-render-missing" }
        }),
    )?;
    Ok(OperationOutcome {
        ok,
        changed,
        skipped: !apply,
        message: if apply {
            "converged HOMESERVER udev files".to_string()
        } else {
            "planned HOMESERVER udev files".to_string()
        },
        command: None,
    })
}

fn validate_absolute_target(target: &str) -> Result<(), String> {
    let path = Path::new(target);
    if !path.is_absolute() || target.contains("..") {
        return Err(format!("udev-target-rejected-{target}"));
    }
    let allowed = target.starts_with("/etc/udev/rules.d/");
    if !allowed {
        return Err(format!("udev-target-rejected-{target}"));
    }
    Ok(())
}

fn render_template(
    raw: &str,
    variables: &std::collections::HashMap<String, String>,
) -> Result<String, String> {
    let mut out = raw.to_string();
    for (key, value) in variables {
        if !safe_variable_value(value) {
            return Err(format!("udev-variable-value-rejected-{key}"));
        }
        out = out.replace(&format!("{{{{{key}}}}}"), value);
    }
    if let Some(start) = out.find("{{") {
        let end = out[start..]
            .find("}}")
            .map(|i| start + i + 2)
            .unwrap_or(start + 2);
        return Err(format!(
            "udev-variable-unresolved-{}",
            &out[start..end]
        ));
    }
    Ok(out)
}

fn safe_variable_value(value: &str) -> bool {
    !value.contains('\n')
        && !value.contains('\r')
        && !value.contains('\0')
        && !value.contains("{{")
        && !value.contains("}}")
}

fn rendered_name(target: &str) -> String {
    target.trim_start_matches('/').replace('/', "__")
}

fn resolve_profile_source_dir(source_dir: &str, harmonia_root: &Path) -> PathBuf {
    let candidate = PathBuf::from(source_dir);
    if candidate.is_absolute() {
        candidate
    } else {
        harmonia_root.join(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn template_renderer_replaces_variables_and_rejects_leftovers() {
        let mut variables = std::collections::HashMap::new();
        variables.insert("name".to_string(), "world".to_string());
        assert_eq!(
            render_template("hello {{name}}", &variables).unwrap(),
            "hello world"
        );
        assert!(render_template("hello {{missing}}", &variables)
            .unwrap_err()
            .contains("variable-unresolved"));
    }
}
