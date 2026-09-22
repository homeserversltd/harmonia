use crate::tools::ladder::{LadderManifest, ValidatedStep};
use crate::{CmdResult, OperationOutcome};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const RECEIPT_SCHEMA: &str = "harmonia.grub-theme.receipt.v1";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

pub(crate) fn execute_validated_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    let source = manifest.base_dir.join(string_arg(step, "theme_source_dir"));
    let name = optional_string_arg(step, "theme_name").unwrap_or("homeserver");
    let root = normalize_target_root(optional_string_arg(step, "target_root").unwrap_or("/"))?;
    let mut receipt = json!({
        "schema": RECEIPT_SCHEMA,
        "step_id": step.step_id,
        "action": "apply-theme",
        "ok": false,
        "changed": false,
        "skipped": false,
        "observed": {},
        "could_change": {
            "theme_directory": root.join("boot/grub/themes").join(name),
            "grub_defaults": root.join("etc/default/grub"),
            "grub_cfg": root.join("boot/grub/grub.cfg")
        },
        "attempt": "not-started",
        "final_state": "not-run",
        "first_missing_signal": "grub-theme-not-run"
    });

    let result = apply_theme(&source, name, &root, apply, &mut receipt);
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(signal) => {
            receipt["ok"] = Value::Bool(false);
            receipt["first_missing_signal"] = json!(signal);
            receipt["final_state"] = json!("blocked");
            OperationOutcome {
                ok: false,
                changed: receipt["changed"].as_bool().unwrap_or(false),
                skipped: false,
                message: signal,
                command: None,
            }
        }
    };
    crate::write_json(
        &module_dir.join(format!("{}.grub.json", step.step_id)),
        &receipt,
    )?;
    Ok(outcome)
}

fn apply_theme(
    source: &Path,
    name: &str,
    root: &Path,
    apply: bool,
    receipt: &mut Value,
) -> Result<OperationOutcome, String> {
    if !valid_theme_name(name) {
        return Err("grub-theme-name-invalid".into());
    }
    let fake_root = root != Path::new("/");
    ensure_safe_root(root)?;
    let defaults = root.join("etc/default/grub");
    let update_grub = root.join("usr/bin/update-grub");
    let update_grub_sbin = root.join("usr/sbin/update-grub");
    let mkconfig = root.join("usr/sbin/grub-mkconfig");
    let mkconfig_bin = root.join("usr/bin/grub-mkconfig");
    for path in [
        &defaults,
        &update_grub,
        &update_grub_sbin,
        &mkconfig,
        &mkconfig_bin,
    ] {
        ensure_no_symlink_ancestors(root, path)?;
    }
    let grub_installed = defaults.is_file()
        || update_grub.is_file()
        || update_grub_sbin.is_file()
        || mkconfig.is_file()
        || mkconfig_bin.is_file();
    receipt["observed"] = json!({
        "target_root": root,
        "fake_root": fake_root,
        "grub_defaults_present": defaults.is_file(),
        "grub_install_present": update_grub.is_file() || update_grub_sbin.is_file() || mkconfig.is_file() || mkconfig_bin.is_file()
    });
    if !grub_installed {
        receipt["ok"] = json!(true);
        receipt["skipped"] = json!(true);
        receipt["attempt"] = json!("observed-only");
        receipt["final_state"] = json!("skipped-no-grub-install");
        receipt["first_missing_signal"] = json!("none");
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "grub theme skipped: GRUB configuration and installation are absent".into(),
            command: None,
        });
    }

    let theme_file = source.join("theme.txt");
    let source_files = validate_theme_source(source, &theme_file)?;
    receipt["observed"]["theme_source_valid"] = json!(true);
    receipt["observed"]["theme_txt"] = json!(theme_file);
    receipt["observed"]["source_files"] = json!(source_files
        .iter()
        .map(|p| p
            .strip_prefix(source)
            .unwrap()
            .to_string_lossy()
            .to_string())
        .collect::<Vec<_>>());
    let theme_dir = root.join("boot/grub/themes").join(name);
    let theme_path = PathBuf::from("/boot/grub/themes")
        .join(name)
        .join("theme.txt");
    let defaults_before = if defaults.is_file() {
        fs::read_to_string(&defaults).map_err(|e| format!("grub-defaults-read-failed:{e}"))?
    } else {
        String::new()
    };
    let defaults_after = rewrite_defaults(&defaults_before, &theme_path.to_string_lossy());
    let defaults_changed = defaults_before.as_bytes() != defaults_after.as_bytes();
    let theme_changed = !tree_matches(source, &theme_dir)?;
    let changed = defaults_changed || theme_changed;
    receipt["observed"]["defaults_before"] = json!(defaults_before);
    receipt["observed"]["theme_material_current"] = json!(!theme_changed);
    receipt["observed"]["defaults_current"] = json!(!defaults_changed);
    receipt["could_change"]["theme_directory"] = json!(theme_dir);
    receipt["could_change"]["grub_defaults"] = json!(defaults);
    receipt["could_change"]["grub_cfg"] = json!(root.join("boot/grub/grub.cfg"));
    receipt["changed"] = json!(changed);
    if !apply {
        receipt["ok"] = json!(true);
        receipt["skipped"] = json!(true);
        receipt["attempt"] = json!("observe-only");
        receipt["final_state"] = json!(if changed { "drift-observed" } else { "current" });
        receipt["first_missing_signal"] = json!("none");
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: if changed {
                "GRUB theme drift observed"
            } else {
                "GRUB theme current"
            }
            .into(),
            command: None,
        });
    }
    if !changed {
        receipt["ok"] = json!(true);
        receipt["attempt"] = json!("no-op");
        receipt["final_state"] = json!("current");
        receipt["first_missing_signal"] = json!("none");
        receipt["mkconfig"] = json!({"attempted": false, "reason": "no-material-change"});
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: false,
            message: "GRUB theme already current".into(),
            command: None,
        });
    }

    receipt["attempt"] = json!("apply-material-change");
    ensure_no_symlink_ancestors(root, &theme_dir)?;
    ensure_no_symlink_ancestors(root, &defaults)?;
    if theme_changed {
        atomic_copy_tree(source, &theme_dir, name)?;
        receipt["changed"] = json!(true);
    }
    if defaults_changed {
        atomic_write(&defaults, defaults_after.as_bytes())?;
        receipt["changed"] = json!(true);
    }
    let theme_readback = tree_matches(source, &theme_dir)?;
    let defaults_readback = fs::read(&defaults)
        .map_err(|e| format!("grub-defaults-readback-failed:{e}"))?
        == defaults_after.as_bytes();
    receipt["observed"]["theme_readback_matches"] = json!(theme_readback);
    receipt["observed"]["defaults_readback_matches"] = json!(defaults_readback);
    if !theme_readback || !defaults_readback {
        receipt["changed"] = json!(true);
        return Err("grub-theme-readback-mismatch".into());
    }

    let command_result = if fake_root {
        receipt["mkconfig"] =
            json!({"attempted": false, "skipped": true, "reason": "fake-root", "argv": []});
        None
    } else {
        let command = if update_grub.is_file() {
            ("/usr/bin/update-grub", vec![])
        } else if update_grub_sbin.is_file() {
            ("/usr/sbin/update-grub", vec![])
        } else if mkconfig.is_file() {
            ("/usr/sbin/grub-mkconfig", vec!["-o", "/boot/grub/grub.cfg"])
        } else if mkconfig_bin.is_file() {
            ("/usr/bin/grub-mkconfig", vec!["-o", "/boot/grub/grub.cfg"])
        } else {
            receipt["changed"] = json!(true);
            return Err("grub-mkconfig-not-installed".into());
        };
        let result = crate::atoms::command::capture_with_timeout(command.0, &command.1, 300);
        receipt["mkconfig"] = json!({"attempted": true, "skipped": false, "argv": std::iter::once(command.0.to_string()).chain(command.1.iter().map(|s| s.to_string())).collect::<Vec<_>>(), "exit_code": result.code, "stdout": result.stdout, "stderr": result.stderr});
        if !result.ok {
            receipt["changed"] = json!(true);
            return Err(if result.stderr.is_empty() {
                "grub-mkconfig-failed".into()
            } else {
                format!("grub-mkconfig-failed:{}", result.stderr)
            });
        }
        Some(result)
    };
    receipt["ok"] = json!(true);
    receipt["final_state"] = json!("converged");
    receipt["first_missing_signal"] = json!("none");
    receipt["changed"] = json!(true);
    let command = command_result.map(|result| CmdResult {
        ok: result.ok,
        code: result.code,
        stdout: result.stdout,
        stderr: result.stderr,
    });
    Ok(OperationOutcome {
        ok: true,
        changed: true,
        skipped: false,
        message: "GRUB theme converged and read back".into(),
        command,
    })
}

fn valid_theme_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && value.as_bytes()[0].is_ascii_alphanumeric()
}

fn normalize_target_root(value: &str) -> Result<PathBuf, String> {
    let root = Path::new(value);
    if !root.is_absolute()
        || root
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err("grub-target-root-invalid".into());
    }
    let mut normalized = PathBuf::new();
    for component in root.components() {
        match component {
            std::path::Component::RootDir => normalized.push("/"),
            std::path::Component::Normal(value) => normalized.push(value),
            std::path::Component::CurDir => {}
            _ => return Err("grub-target-root-invalid".into()),
        }
    }
    Ok(normalized)
}

fn validate_theme_source(source: &Path, theme_file: &Path) -> Result<Vec<PathBuf>, String> {
    let metadata = fs::symlink_metadata(source).map_err(|_| "grub-theme-source-missing")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("grub-theme-source-not-directory".into());
    }
    let theme_meta =
        fs::symlink_metadata(theme_file).map_err(|_| "grub-theme-theme-txt-missing")?;
    if !theme_meta.is_file() || theme_meta.file_type().is_symlink() {
        return Err("grub-theme-theme-txt-invalid".into());
    }
    let theme_text = fs::read_to_string(theme_file).map_err(|_| "grub-theme-theme-txt-invalid")?;
    if !theme_text.trim().is_empty() {
        let reference = theme_text
            .lines()
            .filter_map(|line| line.split_once('=').or_else(|| line.split_once(':')))
            .find_map(|(key, value)| {
                (key.trim() == "desktop-image")
                    .then(|| value.trim().trim_matches('"').trim_matches('\''))
            })
            .ok_or_else(|| "grub-theme-background-reference-missing".to_string())?;
        let relative = Path::new(reference);
        if relative.is_absolute()
            || relative
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err("grub-theme-background-reference-invalid".into());
        }
        let background = source.join(relative);
        let meta =
            fs::symlink_metadata(&background).map_err(|_| "grub-theme-background-image-missing")?;
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err("grub-theme-background-image-invalid".into());
        }
        let ext = background
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let bytes = fs::read(background)
            .map_err(|e| format!("grub-theme-background-image-read-failed:{e}"))?;
        if !valid_image(&ext, &bytes) {
            return Err("grub-theme-background-image-invalid".into());
        }
    } else {
        return Err("grub-theme-theme-txt-empty".into());
    }
    let mut entries = Vec::new();
    let mut has_background = false;
    for entry in walk(source)? {
        let meta = fs::symlink_metadata(&entry)
            .map_err(|e| format!("grub-theme-source-stat-failed:{e}"))?;
        if meta.file_type().is_symlink() {
            return Err("grub-theme-source-symlink-forbidden".into());
        }
        if meta.is_dir() {
            continue;
        }
        if !meta.is_file() {
            return Err("grub-theme-source-special-file-forbidden".into());
        }
        let ext = entry
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if matches!(
            ext.as_str(),
            "png" | "jpg" | "jpeg" | "webp" | "bmp" | "tga"
        ) {
            let bytes =
                fs::read(&entry).map_err(|e| format!("grub-theme-image-read-failed:{e}"))?;
            if valid_image(&ext, &bytes) {
                has_background = true;
            } else {
                return Err(format!(
                    "grub-theme-background-image-invalid:{}",
                    entry.file_name().unwrap_or_default().to_string_lossy()
                ));
            }
        }
        entries.push(entry);
    }
    if !has_background {
        return Err("grub-theme-background-image-missing".into());
    }
    Ok(entries)
}

fn valid_image(ext: &str, bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    match ext {
        "png" => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        "jpg" | "jpeg" => bytes.starts_with(&[0xff, 0xd8, 0xff]),
        "webp" => bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP",
        "bmp" => bytes.starts_with(b"BM"),
        "tga" => bytes.len() >= 18,
        _ => false,
    }
}

fn walk(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).map_err(|e| format!("grub-theme-source-read-failed:{e}"))? {
            let path = entry.map_err(|e| e.to_string())?.path();
            let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                pending.push(path.clone());
            }
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn rewrite_defaults(existing: &str, theme_path: &str) -> String {
    let desired = [
        ("GRUB_THEME", format!("GRUB_THEME=\"{theme_path}\"")),
        ("GRUB_GFXMODE", "GRUB_GFXMODE=auto".into()),
    ];
    let mut pending = vec![true, true];
    let mut out = Vec::new();
    for line in existing.lines() {
        let trimmed = line.trim_start();
        let assignment = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        let matched = desired
            .iter()
            .enumerate()
            .find(|(_, (key, _))| assignment.starts_with(&format!("{key}=")));
        if let Some((index, (_, replacement))) = matched {
            if pending[index] {
                out.push(replacement.clone());
                pending[index] = false;
            }
        } else {
            out.push(line.to_string());
        }
    }
    for (index, (_, value)) in desired.iter().enumerate() {
        if pending[index] {
            out.push(value.clone());
        }
    }
    format!("{}\n", out.join("\n"))
}

fn tree_matches(source: &Path, target: &Path) -> Result<bool, String> {
    let target_meta = match fs::symlink_metadata(target) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("grub-theme-target-stat-failed:{error}")),
    };
    if !target_meta.is_dir() || target_meta.file_type().is_symlink() {
        return Ok(false);
    }
    let sources = walk(source)?;
    let targets = walk(target)?;
    if sources.len() != targets.len() {
        return Ok(false);
    }
    for (src, dst) in sources.iter().zip(targets.iter()) {
        let source_rel = src.strip_prefix(source).map_err(|e| e.to_string())?;
        let target_rel = dst.strip_prefix(target).map_err(|e| e.to_string())?;
        if source_rel != target_rel {
            return Ok(false);
        }
        let sm = fs::symlink_metadata(src).map_err(|e| e.to_string())?;
        let dm = fs::symlink_metadata(dst).map_err(|e| e.to_string())?;
        if sm.is_dir() != dm.is_dir() || dm.file_type().is_symlink() {
            return Ok(false);
        }
        if sm.is_file()
            && fs::read(src).map_err(|e| e.to_string())?
                != fs::read(dst).map_err(|e| e.to_string())?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn ensure_safe_root(root: &Path) -> Result<(), String> {
    let mut current = PathBuf::from("/");
    for component in root.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::Normal(value) => current.push(value),
            _ => return Err("grub-target-root-invalid".into()),
        }
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err("grub-target-root-symlink-forbidden".into())
            }
            Ok(meta) if !meta.is_dir() => return Err("grub-target-root-not-directory".into()),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(format!("grub-target-root-stat-failed:{error}")),
        }
    }
    Ok(())
}

fn ensure_no_symlink_ancestors(root: &Path, target: &Path) -> Result<(), String> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| "grub-target-escapes-root")?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err("grub-target-symlink-forbidden".into())
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("grub-target-stat-failed:{error}")),
        }
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "grub-target-parent-missing".to_string())?;
    fs::create_dir_all(parent).map_err(|e| format!("grub-target-parent-create-failed:{e}"))?;
    let temp = temp_path(
        parent,
        path.file_name().and_then(|v| v.to_str()).unwrap_or("grub"),
    );
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|e| e.to_string())?;
        file.write_all(bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        fs::rename(&temp, path).map_err(|e| e.to_string())?;
        Ok::<(), String>(())
    })();
    if temp.exists() {
        let _ = fs::remove_file(temp);
    }
    result.map_err(|e| format!("grub-defaults-atomic-write-failed:{e}"))
}

fn atomic_copy_tree(source: &Path, target: &Path, name: &str) -> Result<(), String> {
    let parent = target
        .parent()
        .ok_or_else(|| "grub-theme-target-parent-missing".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|e| format!("grub-theme-target-parent-create-failed:{e}"))?;
    let staging = temp_path(parent, name);
    fs::create_dir(&staging).map_err(|e| format!("grub-theme-staging-create-failed:{e}"))?;
    let staged_tree = staging.join(name);
    let result = (|| {
        copy_tree_contents(source, &staged_tree)?;
        let backup = temp_path(parent, &format!("{name}.old"));
        let had_prior = target.exists();
        if had_prior {
            if !target.is_dir() || target.is_symlink() {
                return Err("grub-theme-target-not-directory".into());
            }
            fs::rename(target, &backup).map_err(|e| format!("grub-theme-backup-failed:{e}"))?;
        }
        if let Err(error) = fs::rename(&staged_tree, target) {
            if had_prior {
                let _ = fs::rename(&backup, target);
            }
            return Err(format!("grub-theme-promote-failed:{error}"));
        }
        if had_prior {
            fs::remove_dir_all(&backup)
                .map_err(|e| format!("grub-theme-prior-remove-failed:{e}"))?;
        }
        Ok(())
    })();
    let _ = fs::remove_dir_all(staging);
    result
}

fn copy_tree_contents(source: &Path, target: &Path) -> Result<(), String> {
    fs::create_dir_all(target).map_err(|e| e.to_string())?;
    for entry in fs::read_dir(source).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let src = entry.path();
        let dst = target.join(entry.file_name());
        let metadata = fs::symlink_metadata(&src).map_err(|e| e.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err("grub-theme-source-symlink-forbidden".into());
        }
        if metadata.is_dir() {
            copy_tree_contents(&src, &dst)?;
        } else if metadata.is_file() {
            fs::copy(&src, &dst).map_err(|e| format!("grub-theme-copy-failed:{e}"))?;
        } else {
            return Err("grub-theme-source-special-file-forbidden".into());
        }
    }
    Ok(())
}

fn temp_path(parent: &Path, stem: &str) -> PathBuf {
    let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(".{stem}.{}.{}.tmp", std::process::id(), serial))
}

fn string_arg<'a>(step: &'a ValidatedStep, key: &str) -> &'a str {
    step.args.get(key).and_then(Value::as_str).unwrap_or("")
}
fn optional_string_arg<'a>(step: &'a ValidatedStep, key: &str) -> Option<&'a str> {
    step.args.get(key).and_then(Value::as_str)
}
