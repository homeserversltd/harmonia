fn effective_managed_files(
    module: &ModuleManifest,
    source_dir: &Path,
) -> Result<Vec<ManagedFileManifest>, String> {
    let mut files = module.managed_files.clone();
    if let Some(profile_source) = &module.caduceus_profile_source {
        files.push(render_caduceus_profile_source(profile_source, source_dir)?);
    }
    if !module.caduceus_commands.is_empty() {
        for file in &mut files {
            if file.path.ends_with("/profile.json") {
                let mut value: Value = serde_json::from_str(&file.content).map_err(|e| {
                    format!(
                        "service-runtime-caduceus-profile-json-invalid {}: {e}",
                        file.path
                    )
                })?;
                let commands = value
                    .get_mut("commands")
                    .and_then(Value::as_array_mut)
                    .ok_or_else(|| {
                        format!(
                            "service-runtime-caduceus-profile-json-commands-missing {}",
                            file.path
                        )
                    })?;
                for command in &module.caduceus_commands {
                    let value = Value::String(command.clone());
                    if !commands.contains(&value) {
                        commands.push(value);
                    }
                }
                file.content = serde_json::to_string_pretty(&value).map_err(|e| {
                    format!("service-runtime-caduceus-profile-json-render-failed: {e}")
                })? + "\n";
            } else if file.path.ends_with("/profile.yaml") {
                file.content =
                    append_caduceus_yaml_commands(&file.content, &module.caduceus_commands)?;
            }
        }
    }
    Ok(files)
}

fn append_caduceus_yaml_commands(content: &str, additions: &[String]) -> Result<String, String> {
    let mut lines: Vec<String> = content.lines().map(ToString::to_string).collect();
    let commands = lines
        .iter()
        .position(|line| line == "commands:")
        .ok_or_else(|| "service-runtime-caduceus-profile-yaml-commands-missing".to_string())?;
    let existing: std::collections::BTreeSet<String> = lines
        .iter()
        .filter_map(|line| line.strip_prefix("- "))
        .map(ToString::to_string)
        .collect();
    let mut insert_at = commands + 1;
    while insert_at < lines.len() && lines[insert_at].starts_with("- ") {
        insert_at += 1;
    }
    for command in additions {
        if !existing.contains(command) {
            lines.insert(insert_at, format!("- {command}"));
            insert_at += 1;
        }
    }
    Ok(lines.join("\n") + "\n")
}

fn render_caduceus_profile_source(
    profile_source: &CaduceusProfileSourceManifest,
    source_dir: &Path,
) -> Result<ManagedFileManifest, String> {
    let source_path = source_dir.join(&profile_source.source);
    let source = fs::read_to_string(&source_path).map_err(|e| {
        format!(
            "service-runtime-caduceus-profile-source-read-failed {}: {e}",
            source_path.display()
        )
    })?;
    let mut rendered = String::new();
    for line in source.lines() {
        if line.starts_with("profile:") || line.starts_with("mode:") {
            continue;
        }
        rendered.push_str(line);
        rendered.push('\n');
    }
    if !profile_source.append.trim().is_empty() {
        rendered.push_str(profile_source.append.trim_start());
        if !rendered.ends_with('\n') {
            rendered.push('\n');
        }
    }
    Ok(ManagedFileManifest {
        path: profile_source.path.clone(),
        content: rendered,
        mode: profile_source.mode,
    })
}
