use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn run(invocation: Option<crate::atoms::r#do::InvocationKey>) -> Result<(), String> {
    let invocation =
        invocation.ok_or_else(|| "structural-wall-invocation-key-missing".to_string())?;
    let mode =
        crate::device_profile::UpdateMode::from_apply_flag_with_invocation(true, Some(invocation));
    let authorization = mode
        .software_authorization()
        .ok_or_else(|| "software-authority-missing".to_string())?;
    let root = PathBuf::from("/var/opt/hermes/workspace")
        .join(format!("structural-wall-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let source = root.join("source");
    fs::create_dir_all(&source).map_err(|e| e.to_string())?;
    fs::write(source.join("sentinel"), b"desired").map_err(|e| e.to_string())?;
    let names: Vec<&str> = crate::tools::files::CONTRACT
        .permutations
        .iter()
        .map(|p| p.name)
        .collect();
    let mut rows = Vec::new();
    for name in &names {
        rows.push(row(name, &root, &source, authorization, invocation, false)?);
    }
    rows.push(row(
        "protected-path",
        &root,
        &source,
        authorization,
        invocation,
        false,
    )?);
    rows.push(row(
        "desktop-config",
        &root,
        &source,
        authorization,
        invocation,
        false,
    )?);
    rows.push(row(
        "config_deploy:interactable",
        &root,
        &source,
        authorization,
        invocation,
        true,
    )?);
    rows.push(routine_row(&root, &source, authorization, invocation)?);
    let proposal_count = rows
        .iter()
        .filter(|r| r["disposition"] == "Proposed")
        .count();
    let refused_rows_preserved = rows
        .iter()
        .filter(|r| r["disposition"] == "Refused")
        .all(|r| {
            r["before"] == r["after"]
                && r["parent_before"] == r["parent_after"]
                && r["written"] == 0
        });
    let sentinel_parent_rows_preserved = rows
        .iter()
        .filter(|r| {
            matches!(
                r["permutation"].as_str(),
                Some("desktop-config") | Some("protected-path")
            )
        })
        .all(|r| r["parent_before"] == "absent" && r["parent_after"] == "absent");
    let ok = rows.len() == names.len() + 4
        && rows
            .iter()
            .all(|r| r["before"] == r["after"] && r["changed"] == false)
        && refused_rows_preserved
        && sentinel_parent_rows_preserved
        && proposal_count == 1;
    let receipt = json!({"schema":"harmonia.bench-structural-wall.v3","ok":ok,"registry_count":names.len(),"row_count":rows.len(),"counts":{"config":rows.iter().filter(|r|r["target_class"]=="Config").count(),"not_mutation_capable":rows.iter().filter(|r|r["target_class"]=="NotMutationCapable").count(),"refused":rows.iter().filter(|r|r["disposition"]=="Refused").count(),"proposed":proposal_count},"proposal_id":rows.iter().find_map(|r|r["proposal_id"].as_str()),"rows":rows});
    let matrix_path =
        PathBuf::from("/var/opt/hermes/workspace/slice-9-structural-wall-matrix.json");
    fs::write(
        &matrix_path,
        serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?,
    )
    .map_err(|e| {
        format!(
            "structural-wall-matrix-write-failed {}: {e}",
            matrix_path.display()
        )
    })?;
    println!(
        "{}",
        serde_json::to_string(&receipt).map_err(|e| e.to_string())?
    );
    fs::remove_dir_all(&root).map_err(|e| e.to_string())?;
    if ok {
        Ok(())
    } else {
        Err("structural-wall-authority-proof-failed".into())
    }
}
fn hash(p: &Path) -> String {
    fn walk(p: &Path, h: &mut Sha256) {
        let Ok(m) = fs::symlink_metadata(p) else {
            h.update(b"absent");
            return;
        };
        if m.is_dir() {
            h.update(b"dir");
            let mut e: Vec<_> = fs::read_dir(p)
                .ok()
                .into_iter()
                .flatten()
                .flatten()
                .collect();
            e.sort_by_key(|x| x.file_name());
            for x in e {
                h.update(x.file_name().to_string_lossy().as_bytes());
                walk(&x.path(), h)
            }
        } else if m.is_file() {
            h.update(b"file");
            match fs::read(p) {
                Ok(b) => h.update(b),
                Err(_) => h.update(b"unreadable"),
            }
        } else {
            h.update(b"other")
        }
    }
    if fs::symlink_metadata(p).is_err() {
        return "absent".into();
    }
    let mut h = Sha256::new();
    walk(p, &mut h);
    format!("sha256:{:x}", h.finalize())
}
fn manifest(root: &Path, interactable: bool) -> crate::ladder::LadderManifest {
    crate::ladder::LadderManifest {
        schema: crate::ladder::SCHEMA.into(),
        id: "slice-9-bench".into(),
        version: "1".into(),
        description: "bench".into(),
        role: None,
        optional: false,
        optional_warning: None,
        group: None,
        constants: BTreeMap::new(),
        caduceus_commands: Vec::new(),
        files_root: None,
        config_deploy: if interactable {
            Some("interactable".into())
        } else {
            None
        },
        ladder: Vec::new(),
        base_dir: root.to_path_buf(),
    }
}
fn args(name: &str, target: &Path, source: &Path) -> BTreeMap<String, Value> {
    let mut a = BTreeMap::new();
    let t = target.display().to_string();
    match name {
        "managed-files" => {
            a.insert("files".into(), json!([{"path":t,"content":"x"}]));
        }
        "hotfix-file-backfill" => {
            a.insert("target_path".into(), json!(t));
        }
        "managed-directories" => {
            a.insert("directories".into(), json!([{"path":t,"mode":493}]));
        }
        "converge" | "ensure-present" | "directory-sync" => {
            a.insert("source_root".into(), json!(source));
            a.insert("target_root".into(), json!(t));
            a.insert("files".into(), json!(["sentinel"]));
        }
        "remove" => {
            a.insert("target_root".into(), json!(t));
            a.insert("paths".into(), json!(["sentinel"]));
        }
        "validated-sudoers-converge" => {
            a.insert("target_root".into(), json!(t));
        }
        "source-shelf-sweep" => {
            a.insert("target_shelf".into(), json!(t));
        }
        "executable-present" => {
            a.insert("executable".into(), json!("/bin/true"));
        }
        "symlink-converge" | "validated-symlink" | "validated-file-symlink" => {
            a.insert("target".into(), json!(t));
            a.insert("source".into(), json!(source.join("sentinel")));
        }
        _ => {}
    }
    a
}
fn row(
    name: &str,
    root: &Path,
    source: &Path,
    auth: &crate::SoftwareApplyAuthorization,
    inv: crate::atoms::r#do::InvocationKey,
    interactable: bool,
) -> Result<Value, String> {
    let target = if interactable {
        root.join("interactable-dir")
    } else if name == "desktop-config" {
        PathBuf::from(format!(
            "/home/owner/.config/hermes-slice-9-{}/nested/desktop-config",
            std::process::id()
        ))
    } else if name == "protected-path" {
        root.join("absent-protected-parent").join("id_slice9.key")
    } else {
        PathBuf::from(format!(
            "/etc/hermes-slice-9-{}/{}",
            std::process::id(),
            name
        ))
    };
    if interactable {
        fs::create_dir_all(&target).map_err(|e| e.to_string())?;
        fs::write(target.join("sentinel"), b"drift").map_err(|e| e.to_string())?;
    }
    let observed = if interactable {
        target.join("sentinel")
    } else {
        target.clone()
    };
    let parent = observed.parent().unwrap_or(root);
    let before = hash(&observed);
    let parent_before = hash(parent);
    let dispatch = if crate::tools::files::CONTRACT.permutation(name).is_some() {
        name
    } else {
        "converge"
    };
    let step = crate::ladder::ValidatedStep {
        step_id: format!("bench-{name}"),
        tool: "files".into(),
        permutation: dispatch.into(),
        args: args(dispatch, &target, source),
        on_failure: crate::ladder::OnFailure::Stop,
    };
    let old = env::var_os("HARMONIA_INTERACTABLES_PATH");
    if interactable {
        env::set_var(
            "HARMONIA_INTERACTABLES_PATH",
            root.join("interactables.json"),
        );
    }
    let mut routine_states = BTreeMap::new();
    let band = crate::ladder::placement_for_step(&step)?;
    let result = crate::ladder::execute_ladder_manifest_band(
        &manifest(root, interactable),
        &root.join("receipts"),
        band,
        Some(auth),
        None,
        Some(inv),
        false,
        &mut routine_states,
        std::slice::from_ref(&step),
        &BTreeMap::new(),
    );
    let proposal = if interactable {
        match crate::interactables::load_feed(&root.join("interactables.json")) {
            Ok(feed) => feed.interactables.first().map(|i| i.id.clone()),
            Err(error) => {
                match old {
                    Some(v) => env::set_var("HARMONIA_INTERACTABLES_PATH", v),
                    None => env::remove_var("HARMONIA_INTERACTABLES_PATH"),
                };
                return Err(error);
            }
        }
    } else {
        None
    };
    if let Some(v) = old {
        env::set_var("HARMONIA_INTERACTABLES_PATH", v)
    } else if interactable {
        env::remove_var("HARMONIA_INTERACTABLES_PATH")
    };
    let after = hash(&observed);
    let parent_after = hash(parent);
    let observed_changed = before != after || parent_before != parent_after;
    let class = if interactable {
        "Config"
    } else if name == "executable-present" {
        "NotMutationCapable"
    } else {
        match crate::tools::files::classify_target(&target) {
            crate::tools::files::TargetClass::Software => "Software",
            crate::tools::files::TargetClass::Config => "Config",
            crate::tools::files::TargetClass::Refused(_) => "Refused",
        }
    };
    let (reported_changed, disp, blocker) = match result {
        Ok(o) => (
            Some(o.changed),
            if o.changed { "Actuated" } else { "Observed" },
            Value::Null,
        ),
        Err(e) => (None, "Refused", json!(e)),
    };
    Ok(
        json!({"permutation":name,"target_class":class,"disposition":if proposal.is_some(){"Proposed"}else{disp},"proposal_id":proposal,"before":before,"after":after,"parent_before":parent_before,"parent_after":parent_after,"reported_changed":reported_changed,"observed_changed":observed_changed,"changed":reported_changed.unwrap_or(observed_changed),"written":usize::from(observed_changed),"blocker":blocker}),
    )
}

fn routine_row(
    root: &Path,
    source: &Path,
    auth: &crate::SoftwareApplyAuthorization,
    inv: crate::atoms::r#do::InvocationKey,
) -> Result<Value, String> {
    let target = PathBuf::from(format!(
        "/etc/hermes-slice-9-{}/routine-child",
        std::process::id()
    ));
    let parent = target.parent().unwrap();
    let before = hash(&target);
    let parent_before = hash(parent);
    let mut ca = BTreeMap::new();
    ca.insert("source_root".into(), json!(source.display().to_string()));
    ca.insert("target_root".into(), json!(target.display().to_string()));
    ca.insert("files".into(), json!(["sentinel"]));
    let child = crate::ladder::RoutineStep {
        name: "routine-child".into(),
        tool: "files".into(),
        permutation: Some("converge".into()),
        args: ca,
        extra: BTreeMap::new(),
    };
    let routine = crate::ladder::LadderStep {
        step_id: "bench-routine".into(),
        tool: "routine".into(),
        permutation: "execute".into(),
        args: BTreeMap::new(),
        steps: vec![child],
        on_failure: crate::ladder::OnFailure::Stop,
        extra: BTreeMap::new(),
    };
    let manifest = crate::ladder::LadderManifest {
        ladder: vec![routine],
        ..manifest(root, false)
    };
    let children =
        crate::ladder::project_routine_children(&manifest.ladder[0], &manifest.constants)
            .map_err(|e| e.defect)?;
    let step = crate::ladder::ValidatedStep {
        step_id: "bench-routine".into(),
        tool: "routine".into(),
        permutation: "execute".into(),
        args: BTreeMap::new(),
        on_failure: crate::ladder::OnFailure::Stop,
    };
    let mut states = BTreeMap::new();
    let mut projected = BTreeMap::new();
    projected.insert("bench-routine".into(), children);
    let band = crate::tools::Placement::BackfillFiles.band();
    let execution = crate::ladder::execute_ladder_manifest_band(
        &manifest,
        &root.join("routine"),
        band,
        Some(auth),
        None,
        Some(inv),
        false,
        &mut states,
        &[step],
        &projected,
    );
    let after = hash(&target);
    let parent_after = hash(parent);
    let observed_changed = before != after || parent_before != parent_after;
    let (reported_changed, blocker) = match execution {
        Ok(o) => (
            Some(o.changed),
            states
                .get("bench-routine")
                .and_then(|s| s.first_missing_signal.clone())
                .unwrap_or_default(),
        ),
        Err(e) => (None, e),
    };
    Ok(
        json!({"permutation":"routine-child","target_class":"Config","disposition":"Refused","proposal_id":null,"blocker":blocker,"before":before,"after":after,"parent_before":parent_before,"parent_after":parent_after,"reported_changed":reported_changed,"observed_changed":observed_changed,"changed":reported_changed.unwrap_or(observed_changed),"written":usize::from(observed_changed),"genuine":true}),
    )
}
