fn ensure_service_active(
    receipt_dir: &Path,
    spec: &ServiceRuntimeSpec,
    service: &str,
    apply: bool,
    managed_files_changed: bool,
    binary_changed: bool,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<OperationOutcome, String> {
    if !apply {
        let active = tools::command::capture("/usr/bin/systemctl", &["is-active", service]);
        return Ok(OperationOutcome {
            ok: active.ok,
            changed: false,
            skipped: true,
            message: format!("{} service activation planned", spec.op_prefix),
            command: None,
        });
    }
    let service_material_changed = managed_files_changed || binary_changed;
    let active_before = tools::command::capture("/usr/bin/systemctl", &["is-active", service]);
    if !service_material_changed {
        let active = tools::systemd::run_action(
            receipt_dir,
            spec.service_active_op,
            "is-active-probe",
            Some(service),
            false,
            None,
            30,
            apply,
            false,
            invocation,
        )?;
        return Ok(OperationOutcome {
            ok: active.ok,
            changed: false,
            skipped: true,
            message: "converged-quiet".to_string(),
            command: None,
        });
    }
    if managed_files_changed {
        let daemon_reload = tools::systemd::run_action(
            receipt_dir,
            spec.daemon_reload_op,
            "daemon-reload",
            Some(service),
            false,
            None,
            30,
            apply,
            true,
            invocation,
        )?;
        if !daemon_reload.ok {
            return Ok(OperationOutcome {
                ok: false,
                changed: false,
                skipped: false,
                message: format!("{} systemd daemon-reload failed", spec.op_prefix),
                command: None,
            });
        }
    }
    let enable = tools::systemd::run_action(
        receipt_dir,
        spec.service_enable_op,
        "enable-now",
        Some(service),
        false,
        None,
        30,
        apply,
        service_material_changed,
        invocation,
    )?;
    let restart = if active_before.ok {
        Some(tools::systemd::run_permutation(
            receipt_dir,
            spec.service_op,
            "restart",
            Some(service),
            &[],
            None,
            30,
            apply,
            service_material_changed,
            invocation,
        )?)
    } else {
        None
    };
    let active = tools::systemd::run_action(
        receipt_dir,
        spec.service_active_op,
        "is-active-probe",
        Some(service),
        false,
        None,
        30,
        apply,
        service_material_changed,
        invocation,
    )?;
    Ok(OperationOutcome {
        ok: enable.ok && restart.as_ref().is_none_or(|outcome| outcome.ok) && active.ok,
        changed: enable.changed || restart.as_ref().is_some_and(|outcome| outcome.changed),
        skipped: false,
        message: format!("{} service material reconciled", spec.op_prefix),
        command: None,
    })
}
