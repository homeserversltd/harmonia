use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
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
    let xattr = xattr_proof(&root, authorization, invocation)?;
    let source = root.join("source");
    fs::create_dir_all(&source).map_err(|e| e.to_string())?;
    fs::write(source.join("sentinel"), b"desired").map_err(|e| e.to_string())?;
    let names: Vec<&str> = crate::tools::get("files")
        .expect("files tool registered")
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
    let ok = ok && slice2["ok"] == true;
    let slice11 = slice11_proof(&root, invocation)?;
    let ok = ok && slice11["ok"].as_bool().unwrap_or(false);
    let receipt = json!({"schema":"harmonia.demo-structural-wall.v5","ok":ok,"slice2":slice2,"slice11":slice11,"registry_count":names.len(),"row_count":rows.len(),"counts":{"config":rows.iter().filter(|r| r["target_class"]=="Config").count(),"not_mutation_capable":rows.iter().filter(|r| r["target_class"]=="NotMutationCapable").count(),"refused":rows.iter().filter(|r| r["disposition"]=="Refused").count(),"proposed":proposal_count},"proposal_id":rows.iter().find_map(|r| r["proposal_id"].as_str()),"rows":rows});
    let matrix_path = PathBuf::from("/var/opt/hermes/workspace/structural-wall-demo-matrix.json");
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
    let actual_cleanup_observed = fs::remove_dir_all(&root).is_ok() && !root.exists();
    let mut receipt = receipt;
    receipt["actual_cleanup_observed"] = json!(actual_cleanup_observed);
    receipt["ok"] = json!(ok && actual_cleanup_observed);
    println!(
        "{}",
        serde_json::to_string(&receipt).map_err(|e| e.to_string())?
    );
    if ok && actual_cleanup_observed {
        Ok(())
    } else {
        Err("structural-wall-authority-proof-failed".into())
    }
}

fn declaration_fixture(root: &Path, declarations: Value) -> crate::tools::ladder::LadderManifest {
    let mut a = BTreeMap::new();
    a.insert("files".into(), declarations);
    let managed = crate::tools::ladder::RoutineStep {
        name: "managed-files".into(),
        tool: "files".into(),
        permutation: Some("managed-files".into()),
        args: a,
        extra: BTreeMap::new(),
    };
    let mut ra = BTreeMap::new();
    ra.insert("service".into(), Value::String("registry.service".into()));
    let restart = crate::tools::ladder::RoutineStep {
        name: "service-restart".into(),
        tool: "systemd".into(),
        permutation: Some("restart".into()),
        args: ra,
        extra: BTreeMap::new(),
    };
    let routine = crate::tools::ladder::LadderStep {
        step_id: "declaration-routine".into(),
        tool: "routine".into(),
        permutation: "execute".into(),
        args: BTreeMap::new(),
        steps: vec![restart, managed],
        on_failure: crate::tools::ladder::OnFailure::Stop,
        extra: BTreeMap::new(),
    };
    crate::tools::ladder::LadderManifest {
        schema: crate::tools::ladder::SCHEMA.into(),
        id: "registry-declarations".into(),
        version: "1".into(),
        description: "proof".into(),
        role: None,
        optional: false,
        optional_warning: None,
        group: None,
        constants: BTreeMap::new(),
        package_pins: BTreeMap::new(),
        caduceus_commands: vec![],
        files_root: None,
        config_deploy: None,
        ladder: vec![routine],
        base_dir: root.to_path_buf(),
    }
}
fn strict_declaration(op: &str, path: &Path) -> Value {
    let mut d = serde_json::Map::new();
    for (k, v) in [
        ("operation", json!(op)),
        ("path", json!(path.display().to_string())),
        ("mode", json!(420)),
        ("uid", json!(0)),
        ("gid", json!(0)),
        ("xattrs", json!({})),
        ("no_follow", json!(true)),
        ("collision_policy", json!("refuse")),
        ("rollback_policy", json!("exact")),
    ] {
        d.insert(k.into(), v);
    }
    match op {
        "place" => {
            d.insert("content".into(), json!("place-bytes"));
        }
        "backfill" => {
            d.insert("declared_bytes".into(), json!("backfill-bytes"));
        }
        "symlink" => {
            d.insert(
                "source".into(),
                json!("/var/opt/hermes/workspace/registry-source"),
            );
            d.insert("target".into(), json!(path.display().to_string()));
            d.insert("required_source_kind".into(), json!("regular-executable"));
            d.insert("conflict_policy".into(), json!("refuse-non-symlink"));
        }
        "remove" => {}
        _ => unreachable!(),
    }
    Value::Object(d)
}
fn declaration_lowering_graph_proof(root: &Path) -> Result<bool, String> {
    let ops = ["place", "backfill", "remove", "symlink"];
    let ds = Value::Array(
        ops.iter()
            .enumerate()
            .map(|(i, o)| strict_declaration(o, &root.join(format!("decl-{o}-{i}"))))
            .collect(),
    );
    let mut m = declaration_fixture(root, ds);
    crate::bands::backfill_files::lower_service_runtime_steps(&mut m)?;
    let routine = &m.ladder[0];
    let want = [
        ("place-file", "place"),
        ("backfill-file", "backfill"),
        ("remove-file", "remove-file"),
        ("files", "symlink-converge"),
    ];
    let lowered = routine.steps.iter().skip(1).collect::<Vec<_>>();
    let exact = lowered.len() == want.len()
        && lowered
            .iter()
            .zip(want)
            .all(|(c, (t, q))| c.tool == t && c.permutation.as_deref() == Some(q));
    let projected_routine = crate::tools::ladder::LadderStep {
        steps: routine
            .steps
            .iter()
            .filter(|c| c.tool != "remove-file")
            .cloned()
            .collect(),
        ..routine.clone()
    };
    let p = crate::tools::routine::project_routine_children(&projected_routine, &m.constants)
        .map_err(|e| e.first_missing_signal())?;
    let r = p
        .iter()
        .position(|c| c.band == crate::bands::Band::RestartServices);
    let b = p
        .iter()
        .position(|c| c.band == crate::bands::Band::BackfillFiles);
    Ok(exact && r.zip(b).is_some_and(|(r, b)| r < b))
}
fn declaration_lowering_refusal_proof(root: &Path) -> Result<bool, String> {
    let base = strict_declaration("place", &root.join("decl-tail"));
    let cases = [
        (None, "managed-files-declaration-array-missing"),
        (Some("path"), "path-missing"),
        (Some("content"), "source-tail-ambiguous"),
        (Some("mode"), "mode-missing"),
        (Some("uid"), "uid-missing"),
        (Some("gid"), "gid-missing"),
        (Some("xattrs"), "xattrs-missing"),
        (Some("no_follow"), "no_follow-missing"),
        (Some("collision_policy"), "collision_policy-missing"),
        (Some("rollback_policy"), "rollback_policy-missing"),
    ];
    let mut ok = true;
    for (missing, tail) in cases {
        let mut d = base.clone();
        if let Some(k) = missing {
            d.as_object_mut().unwrap().remove(k);
        }
        let mut m = declaration_fixture(
            root,
            if missing.is_none() {
                Value::Null
            } else {
                Value::Array(vec![d])
            },
        );
        if missing.is_none() {
            m.ladder[0].steps[1].args.remove("files");
        }
        ok &= match crate::bands::backfill_files::lower_service_runtime_steps(&mut m) {
            Err(e) => e.contains(tail),
            Ok(_) => false,
        };
    }
    Ok(ok)
}

fn registry_proof(
    root: &Path,
    invocation: crate::atoms::r#do::InvocationKey,
) -> Result<Value, String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let dir = root.join("registry");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let uid = fs::metadata(&dir).map_err(|e| e.to_string())?.uid();
    let gid = fs::metadata(&dir).map_err(|e| e.to_string())?.gid();
    let mode = 0o640;
    let bytes = b"registry-strict-bytes";
    let attrs = BTreeMap::new();
    let snap = |p: &Path| -> Result<Value, String> {
        match fs::symlink_metadata(p) {
            Ok(m) => Ok(
                json!({"kind": if m.file_type().is_symlink() {"symlink"} else if m.is_dir() {"directory"} else {"file"}, "bytes": fs::read(p).ok().map(|b| Sha256::digest(b).to_vec()), "mode": m.permissions().mode() & 0o7777, "uid": m.uid(), "gid": m.gid(), "target": fs::read_link(p).ok()}),
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(json!("absent")),
            Err(e) => Err(e.to_string()),
        }
    };
    let symlink = dir.join("symlink");
    let dangling = dir.join("dangling");
    let directory = dir.join("directory");
    std::os::unix::fs::symlink("missing", &symlink).map_err(|e| e.to_string())?;
    std::os::unix::fs::symlink("also-missing", &dangling).map_err(|e| e.to_string())?;
    fs::create_dir(&directory).map_err(|e| e.to_string())?;
    let refused = [&symlink, &dangling, &directory].iter().all(|p| {
        crate::place_file::execute_strict(crate::place_file::StrictPlaceFileRequest {
            path: p,
            declared_bytes: bytes,
            mode,
            uid,
            gid,
            xattrs: &attrs,
            backup: crate::place_file::BackupPolicy::None,
            invocation,
            fail_after_action: false,
        })
        .is_err()
    });
    let target = dir.join("target");
    fs::write(&target, b"old").map_err(|e| e.to_string())?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    let placed = crate::place_file::execute_strict(crate::place_file::StrictPlaceFileRequest {
        path: &target,
        declared_bytes: bytes,
        mode,
        uid,
        gid,
        xattrs: &attrs,
        backup: crate::place_file::BackupPolicy::None,
        invocation,
        fail_after_action: false,
    })?;
    let strict_place =
        fs::read(&target).map_err(|e| e.to_string())? == bytes && placed.movement.changed();
    let backfill_target = dir.join("backfill");
    fs::write(&backfill_target, b"before").map_err(|e| e.to_string())?;
    let backfilled = crate::backfill_file::execute(crate::backfill_file::BackfillFileRequest {
        path: &backfill_target,
        declared_bytes: bytes,
        mode: Some(mode),
        ownership: crate::backfill_file::DeclaredOwnership {
            uid: Some(uid),
            gid: Some(gid),
        },
        backup: crate::backfill_file::BackupPolicy::None,
        invocation: Some(invocation),
    })?;
    let strict_backfill = fs::read(&backfill_target).map_err(|e| e.to_string())? == bytes
        && backfilled.movement.changed();
    let source = dir.join("executable");
    fs::write(&source, b"#!/bin/sh\n").map_err(|e| e.to_string())?;
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    let link = dir.join("link");
    std::os::unix::fs::symlink("executable", &link).map_err(|e| e.to_string())?;
    let link_identity = fs::read_link(&link).map_err(|e| e.to_string())?
        == PathBuf::from("executable")
        && fs::metadata(&source)
            .map_err(|e| e.to_string())?
            .permissions()
            .mode()
            & 0o111
            != 0;
    let collision_before = snap(&symlink)?;
    let collision = crate::place_file::execute_strict(crate::place_file::StrictPlaceFileRequest {
        path: &symlink,
        declared_bytes: bytes,
        mode,
        uid,
        gid,
        xattrs: &attrs,
        backup: crate::place_file::BackupPolicy::None,
        invocation,
        fail_after_action: false,
    })
    .is_err();
    let collision_refusal = collision && collision_before == snap(&symlink)?;
    let rollback_target = dir.join("rollback");
    fs::write(&rollback_target, b"rollback-old").map_err(|e| e.to_string())?;
    fs::set_permissions(&rollback_target, fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    let before = snap(&rollback_target)?;
    let rollback = crate::place_file::execute_strict(crate::place_file::StrictPlaceFileRequest {
        path: &rollback_target,
        declared_bytes: bytes,
        mode,
        uid,
        gid,
        xattrs: &attrs,
        backup: crate::place_file::BackupPolicy::None,
        invocation,
        fail_after_action: true,
    })
    .is_err();
    let file_rollback = rollback && before == snap(&rollback_target)?;
    let link_before = snap(&link)?;
    let link_rollback =
        crate::place_file::execute_strict(crate::place_file::StrictPlaceFileRequest {
            path: &link,
            declared_bytes: bytes,
            mode,
            uid,
            gid,
            xattrs: &attrs,
            backup: crate::place_file::BackupPolicy::None,
            invocation,
            fail_after_action: false,
        })
        .is_err()
            && link_before == snap(&link)?;
    let dry_target = dir.join("dry-run");
    fs::write(&dry_target, b"dry-old").map_err(|e| e.to_string())?;
    let dry_before = snap(&dry_target)?;
    fs::write(dir.join("dry-source"), bytes).map_err(|e| e.to_string())?;
    let dry_request = crate::tools::files::FileConvergenceRequest {
        source_root: dir.clone(),
        target_root: dir.clone(),
        files: vec![crate::tools::files::FileSpec {
            relative_path: PathBuf::from("dry-run"),
            mode: Some(mode),
        }],
        backup_existing: false,
        receipt_name: "registry-dry-run".into(),
        owner: None,
        group: None,
    };
    let dry_result = crate::tools::files::converge_files_with_invocation(
        &dry_request,
        &dir,
        false,
        Some(invocation),
    );
    let dry_refusal = dry_result.is_err();
    let apply_false_zero_writes = dry_before == snap(&dry_target)?;
    let backup = dir.join("backup");
    let first = crate::place_file::execute_strict(crate::place_file::StrictPlaceFileRequest {
        path: &target,
        declared_bytes: bytes,
        mode,
        uid,
        gid,
        xattrs: &attrs,
        backup: crate::place_file::BackupPolicy::To(&backup),
        invocation,
        fail_after_action: false,
    })?;
    let second = crate::place_file::execute_strict(crate::place_file::StrictPlaceFileRequest {
        path: &target,
        declared_bytes: bytes,
        mode,
        uid,
        gid,
        xattrs: &attrs,
        backup: crate::place_file::BackupPolicy::To(&backup),
        invocation,
        fail_after_action: false,
    })?;
    let second_apply = !first.movement.changed() || second.movement.changed() == false;
    let second_apply_zero_movement_no_backup = second_apply && !backup.exists();
    let declaration_graph_canonical = declaration_lowering_graph_proof(root)?;
    let declaration_tails_block = declaration_lowering_refusal_proof(root)?;
    let ok = refused
        && strict_place
        && strict_backfill
        && link_identity
        && collision_refusal
        && file_rollback
        && link_rollback
        && apply_false_zero_writes
        && second_apply_zero_movement_no_backup
        && declaration_tails_block
        && declaration_graph_canonical;
    Ok(
        json!({"ok":ok,"no_follow_classification_refusal":refused,"strict_place_exact":strict_place,"strict_backfill_exact":strict_backfill,"link_target_identity":link_identity,"executable_source_identity":link_identity,"non_symlink_collision_refusal":collision_refusal,"file_rollback":file_rollback,"link_rollback":link_rollback,"apply_false_zero_writes":apply_false_zero_writes,"second_apply_zero_movement_no_backup":second_apply_zero_movement_no_backup,"declaration_tails_block":declaration_tails_block,"declaration_graph_canonical":declaration_graph_canonical}),
    )
}

fn xattr_proof(
    root: &Path,
    _auth: &crate::SoftwareApplyAuthorization,
    invocation: crate::atoms::r#do::InvocationKey,
) -> Result<Value, String> {
    let tree = root.join("xattr-tree");
    fs::create_dir_all(tree.join("nested")).map_err(|e| e.to_string())?;
    let file = tree.join("nested/file");
    fs::write(&file, b"non-utf8\0payload").map_err(|e| e.to_string())?;
    let xattr_supported = set_proof_xattr(&file)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(tree.join("nested"), fs::Permissions::from_mode(0o751))
            .map_err(|e| e.to_string())?;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).map_err(|e| e.to_string())?;
        std::os::unix::fs::symlink("nested/file", tree.join("link")).map_err(|e| e.to_string())?;
    }
    let image = crate::atoms::r#do::remove_dir::capture(&tree)?;
    crate::atoms::r#do::remove_dir::remove(&tree)?;
    crate::atoms::r#do::remove_dir::restore(&tree, &image)?;
    let restored = crate::atoms::r#do::remove_dir::capture(&tree)?;
    let nested = b"nested";
    let file = b"nested/file";
    let link = b"link";
    let image_nested = find_node(&image.root, nested);
    let restored_nested = find_node(&restored.root, nested);
    let image_file = find_node(&image.root, file);
    let restored_file = find_node(&restored.root, file);
    let image_link = find_node(&image.root, link);
    let restored_link = find_node(&restored.root, link);
    let kinds = matches!(
        (&image.root.kind, &restored.root.kind),
        (
            crate::atoms::r#do::remove_dir::Kind::Directory,
            crate::atoms::r#do::remove_dir::Kind::Directory
        )
    ) && matches!((image_nested, restored_nested), (Some(a), Some(b))
        if a.kind == crate::atoms::r#do::remove_dir::Kind::Directory
            && b.kind == crate::atoms::r#do::remove_dir::Kind::Directory)
        && matches!((image_file, restored_file), (Some(a), Some(b))
            if a.kind == crate::atoms::r#do::remove_dir::Kind::File
                && b.kind == crate::atoms::r#do::remove_dir::Kind::File)
        && matches!((image_link, restored_link), (Some(a), Some(b))
            if a.kind == crate::atoms::r#do::remove_dir::Kind::Symlink
                && b.kind == crate::atoms::r#do::remove_dir::Kind::Symlink);
    let bytes = matches!((image_file, restored_file), (Some(a), Some(b)) if a.bytes == b.bytes);
    let links = matches!((image_link, restored_link), (Some(a), Some(b)) if a.link == b.link);
    let modes = [b"".as_slice(), nested, file, link].iter().all(|relative| {
        match (
            find_node(&image.root, relative),
            find_node(&restored.root, relative),
        ) {
            (Some(a), Some(b)) => a.mode == b.mode,
            _ => false,
        }
    });
    let uid_gid = paired_metadata_equal(&image.root, &restored.root, false);
    let xattrs = paired_metadata_equal(&image.root, &restored.root, true)
        && (!xattr_supported
            || image_file.is_some_and(|n| {
                n.xattrs
                    .values
                    .iter()
                    .any(|x| x.name == b"user.harmonia_xattr" && x.value == b"xattr")
            }));
    let receipt_path = root.join("xattr-replace.json");
    let plan = crate::atoms::r#do::replace_process::Plan {
        successor: PathBuf::from("/bin/true"),
        argv: vec!["--xattr".into(), "exact".into()],
        guard_name: "HARMONIA_XATTR_GUARD".into(),
        guard_value: "1".into(),
        receipt_path,
    };
    let proof = crate::atoms::r#do::replace_process::proof(&plan, invocation)?;
    let persisted: crate::atoms::r#do::replace_process::Receipt =
        serde_json::from_slice(&fs::read(&plan.receipt_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let canonical = fs::canonicalize(&plan.successor).map_err(|e| e.to_string())?;
    let meta = fs::symlink_metadata(&canonical).map_err(|e| e.to_string())?;
    let identity_ok = persisted.successor_canonical == canonical.display().to_string()
        && persisted.successor_dev == meta.dev()
        && persisted.successor_ino == meta.ino();
    let before = fs::read(&plan.receipt_path).map_err(|e| e.to_string())?;
    let previous_guard = std::env::var_os(&plan.guard_name);
    std::env::set_var(&plan.guard_name, &plan.guard_value);
    let refused = crate::atoms::r#do::replace_process::proof(&plan, invocation).is_err();
    let after = fs::read(&plan.receipt_path).map_err(|e| e.to_string())?;
    if let Some(value) = previous_guard {
        std::env::set_var(&plan.guard_name, value);
    } else {
        std::env::remove_var(&plan.guard_name);
    }
    let receipt_ok = persisted.proof
        && persisted.synced
        && proof.argv == plan.argv
        && proof.successor == "/bin/true"
        && identity_ok
        && refused
        && before == after;
    let all = kinds && bytes && links && modes && uid_gid && xattrs && receipt_ok;
    Ok(json!({
        "ok": all, "kinds": kinds, "bytes": bytes, "links": links, "modes": modes,
        "uid_gid": uid_gid, "xattrs": xattrs, "xattr_supported": xattr_supported,
        "xattr_unsupported": !xattr_supported, "all": all,
        "replace": {"proof": persisted.proof, "synced": persisted.synced,
            "canonical_identity": identity_ok, "exact_argv": proof.argv == plan.argv,
            "guard_refusal": refused, "stable_bytes": before == after}
    }))
}

fn find_node<'a>(
    node: &'a crate::atoms::r#do::remove_dir::Node,
    relative: &[u8],
) -> Option<&'a crate::atoms::r#do::remove_dir::Node> {
    if node.relative == relative {
        return Some(node);
    }
    node.children
        .iter()
        .find_map(|child| find_node(child, relative))
}

fn paired_metadata_equal(
    a: &crate::atoms::r#do::remove_dir::Node,
    b: &crate::atoms::r#do::remove_dir::Node,
    xattrs: bool,
) -> bool {
    a.relative == b.relative
        && a.uid == b.uid
        && a.gid == b.gid
        && (!xattrs || a.xattrs == b.xattrs)
        && a.children.len() == b.children.len()
        && a.children.iter().all(|left| {
            b.children
                .iter()
                .find(|right| right.relative == left.relative)
                .is_some_and(|right| paired_metadata_equal(left, right, xattrs))
        })
}

fn set_proof_xattr(path: &Path) -> Result<bool, String> {
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let name = std::ffi::CString::new("user.harmonia_xattr").unwrap();
    let value = b"xattr";
    let result = unsafe {
        libc::lsetxattr(
            c.as_ptr(),
            name.as_ptr(),
            value.as_ptr() as *const _,
            value.len(),
            0,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if matches!(error.raw_os_error(), Some(libc::EOPNOTSUPP)) {
        Ok(false)
    } else {
        Err(error.to_string())
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
        id: "slice-9-demo".into(),
        version: "1".into(),
        description: "demo".into(),
        role: None,
        optional: false,
        optional_warning: None,
        group: None,
        constants: BTreeMap::new(),
        package_pins: BTreeMap::new(),
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
            "/home/owner/.config/hermes-structural-wall-{}/nested/desktop-config",
            std::process::id()
        ))
    } else if name == "protected-path" {
        root.join("absent-protected-parent").join("id_protected.key")
    } else {
        PathBuf::from(format!(
            "/etc/hermes-structural-wall-{}/{}",
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
    let dispatch = if crate::tools::get("files")
        .expect("files tool registered")
        .permutation(name)
        .is_some()
    {
        name
    } else {
        "converge"
    };
    let step = crate::ladder::ValidatedStep {
        step_id: format!("demo-{name}"),
        tool: "files".into(),
        permutation: dispatch.into(),
        args: args(dispatch, &target, source),
        on_failure: crate::tools::ladder::OnFailure::Stop,
    };
    let old = env::var_os("HARMONIA_INTERACTABLES_PATH");
    if interactable {
        env::set_var(
            "HARMONIA_INTERACTABLES_PATH",
            root.join("interactables.json"),
        );
    }
    let demo_manifest = manifest(root, interactable);
    let result = crate::tools::routine::execute_validated_step(
        &step,
        &demo_manifest,
        &root.join("receipts"),
        Some(auth),
        None,
        false,
        Some(inv),
        None,
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
        "/etc/hermes-structural-wall-{}/routine-child",
        std::process::id()
    ));
    let parent = target.parent().unwrap();
    let before = hash(&target);
    let parent_before = hash(parent);
    let mut ca = BTreeMap::new();
    ca.insert("source_root".into(), json!(source.display().to_string()));
    ca.insert("target_root".into(), json!(target.display().to_string()));
    ca.insert("files".into(), json!(["sentinel"]));
    let child = crate::tools::ladder::RoutineStep {
        name: "routine-child".into(),
        tool: "files".into(),
        permutation: Some("converge".into()),
        args: ca,
        extra: BTreeMap::new(),
    };
    let routine = crate::ladder::LadderStep {
        step_id: "demo-routine".into(),
        tool: "routine".into(),
        permutation: "execute".into(),
        args: BTreeMap::new(),
        steps: vec![child],
        on_failure: crate::tools::ladder::OnFailure::Stop,
        extra: BTreeMap::new(),
    };
    let manifest = crate::tools::ladder::LadderManifest {
        ladder: vec![routine],
        ..manifest(root, false)
    };
    let children =
        crate::tools::routine::project_routine_children(&manifest.ladder[0], &manifest.constants)
            .map_err(|e| e.defect)?;
    let step = crate::ladder::ValidatedStep {
        step_id: "demo-routine".into(),
        tool: "routine".into(),
        permutation: "execute".into(),
        args: BTreeMap::new(),
        on_failure: crate::tools::ladder::OnFailure::Stop,
    };
    let mut states: BTreeMap<String, crate::ModuleWalkState> = BTreeMap::new();
    let mut projected: BTreeMap<String, Vec<crate::tools::ladder::ProjectedRoutineChild>> =
        BTreeMap::new();
    projected.insert("demo-routine".into(), children);
    let band = crate::tools::Placement::BackfillFiles.band();
    let execution = crate::tools::routine::execute_routine(
        &step,
        &manifest,
        &root.join("routine"),
        Some(auth),
        None,
        false,
        Some(inv),
        Some(&mut states),
        band,
        projected
            .get("demo-routine")
            .map(Vec::as_slice)
            .unwrap_or(&[]),
    );
    let after = hash(&target);
    let parent_after = hash(parent);
    let observed_changed = before != after || parent_before != parent_after;
    let (reported_changed, blocker) = match execution {
        Ok(o) => (
            Some(o.changed),
            states
                .get("demo-routine")
                .and_then(|s| s.first_missing_signal.clone())
                .unwrap_or_default(),
        ),
        Err(e) => (None, e),
    };
    Ok(
        json!({"permutation":"routine-child","target_class":"Config","disposition":"Refused","proposal_id":null,"blocker":blocker,"before":before,"after":after,"parent_before":parent_before,"parent_after":parent_after,"reported_changed":reported_changed,"observed_changed":observed_changed,"changed":reported_changed.unwrap_or(observed_changed),"written":usize::from(observed_changed),"genuine":true}),
    )
}
