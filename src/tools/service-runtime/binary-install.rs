fn write_skipped_binary_install_receipt(
    receipt_dir: &Path,
    spec: &ServiceRuntimeSpec,
    install_bin: &Path,
    apply: bool,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{}.json", spec.binary_install_op)),
        &json!({
            "schema": "harmonia.service-runtime.binary-install.v1",
            "install_bin": install_bin,
            "apply": apply,
            "ok": true,
            "changed": false,
            "state": "converged-quiet",
            "reason": "source-sha-gate-preserved-installed-binary",
        }),
    )
}

fn install_binary(
    receipt_dir: &Path,
    spec: &ServiceRuntimeSpec,
    artifact: &Path,
    install_bin: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    if !artifact.is_file() {
        return Ok(OperationOutcome {
            ok: false,
            changed: false,
            skipped: false,
            message: format!("{} build artifact missing", spec.op_prefix),
            command: None,
        });
    }
    if files_equal(artifact, install_bin)? {
        write_binary_install_receipt(receipt_dir, spec, artifact, install_bin, apply, false)?;
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "converged-quiet".to_string(),
            command: None,
        });
    }
    if !apply {
        write_binary_install_receipt(receipt_dir, spec, artifact, install_bin, apply, false)?;
        return Ok(OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: format!("{} binary install planned", spec.op_prefix),
            command: None,
        });
    }
    if let Some(parent) = install_bin.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp_install = install_bin.with_extension("harmonia-new");
    fs::copy(artifact, &tmp_install)
        .map_err(|e| format!("{}-artifact-copy-failed: {e}", spec.op_prefix))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&tmp_install)
            .map_err(|e| e.to_string())?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&tmp_install, perms).map_err(|e| e.to_string())?;
    }
    fs::rename(&tmp_install, install_bin)
        .map_err(|e| format!("{}-artifact-promote-failed: {e}", spec.op_prefix))?;
    if !files_equal(artifact, install_bin)? {
        return Err(format!(
            "{}-installed-bytes-readback-mismatch",
            spec.op_prefix
        ));
    }
    write_binary_install_receipt(receipt_dir, spec, artifact, install_bin, apply, true)?;
    Ok(OperationOutcome {
        ok: true,
        changed: true,
        skipped: false,
        message: format!("{} binary installed", spec.op_prefix),
        command: None,
    })
}
fn files_equal(left: &Path, right: &Path) -> Result<bool, String> {
    let Ok(left_meta) = fs::metadata(left) else {
        return Ok(false);
    };
    let Ok(right_meta) = fs::metadata(right) else {
        return Ok(false);
    };
    if left_meta.len() != right_meta.len() {
        return Ok(false);
    }
    let mut left = BufReader::new(fs::File::open(left).map_err(|e| e.to_string())?);
    let mut right = BufReader::new(fs::File::open(right).map_err(|e| e.to_string())?);
    let mut left_buf = [0_u8; 64 * 1024];
    let mut right_buf = [0_u8; 64 * 1024];
    loop {
        let left_read = left.read(&mut left_buf).map_err(|e| e.to_string())?;
        let right_read = right.read(&mut right_buf).map_err(|e| e.to_string())?;
        if left_read != right_read || left_buf[..left_read] != right_buf[..right_read] {
            return Ok(false);
        }
        if left_read == 0 {
            return Ok(true);
        }
    }
}

fn write_binary_install_receipt(
    receipt_dir: &Path,
    spec: &ServiceRuntimeSpec,
    artifact: &Path,
    install_bin: &Path,
    apply: bool,
    changed: bool,
) -> Result<(), String> {
    write_json(
        &receipt_dir.join(format!("{}.json", spec.binary_install_op)),
        &json!({
            "schema": "harmonia.service-runtime.binary-install.v1",
            "artifact": artifact,
            "install_bin": install_bin,
            "apply": apply,
            "ok": true,
            "changed": changed,
            "state": if changed { "binary-swapped" } else { "converged-quiet" },
        }),
    )
}
