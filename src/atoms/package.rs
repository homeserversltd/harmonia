use crate::{CmdResult, PackageBackend};
use std::env;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const NAME: &str = "package";

pub(crate) const PACKAGE_PIN_SCOPE_LIMITATION: &str =
    "Harmonia's pin excludes names only from Harmonia-owned package transactions; it cannot stop the operator's own hand or a bare pacman/apt command run outside Harmonia (for example, `pacman -Syu`).";

const HARMONIA_PACMAN_PATH_ENV: &str = "HARMONIA_PACMAN_PATH";
const HARMONIA_PACMAN_KEY_PATH_ENV: &str = "HARMONIA_PACMAN_KEY_PATH";
const DEFAULT_PACKAGE_TIMEOUT_SECS: u64 = 1800;

pub(crate) fn pacman_program() -> String {
    env::var(HARMONIA_PACMAN_PATH_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "/usr/bin/pacman".to_string())
}

pub(crate) fn pacman_key_program() -> String {
    env::var(HARMONIA_PACMAN_KEY_PATH_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "/usr/bin/pacman-key".to_string())
}

pub(crate) fn pacman_available(program: &str) -> bool {
    Path::new(program).exists()
}

pub(crate) fn pacman_conflict_signal(result: &CmdResult) -> Option<String> {
    if result.ok {
        return None;
    }
    let combined = format!("{}\n{}", result.stdout, result.stderr);
    if combined.contains("conflicting files") || combined.contains("exists in filesystem") {
        Some("pacman-package-file-conflict".to_string())
    } else {
        None
    }
}

pub(crate) fn pacman_needs_overwrite_retry(result: &CmdResult) -> bool {
    pacman_conflict_signal(result).is_some()
}

pub(crate) fn pacman_base_args(sync: bool) -> Vec<&'static str> {
    if sync {
        vec!["-Syu", "--noconfirm"]
    } else {
        vec!["-S", "--noconfirm", "--needed"]
    }
}

pub(crate) fn overwrite_allowed_args<'a>(
    base: &[&'a str],
    paths: &'a [String],
) -> Option<Vec<&'a str>> {
    if paths.is_empty() || paths.iter().any(|path| path == "*") {
        return None;
    }
    let mut args = base.to_vec();
    for path in paths {
        args.push("--overwrite");
        args.push(path.as_str());
    }
    Some(args)
}

pub(crate) fn pacman_stdout_indicates_change(stdout: &str) -> bool {
    let lower = stdout.to_ascii_lowercase();
    lower.contains("upgrading")
        || lower.contains("installing")
        || lower.contains("reinstalling")
        || lower.contains("removing")
}

pub(crate) fn demo(
    root: &Path,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<serde_json::Value, String> {
    let fake = root.join("fake-pacman");
    let log = root.join("pacman.log");
    let receipts = root.join("receipts");
    std::fs::create_dir_all(&receipts).map_err(|e| e.to_string())?;
    std::fs::write(&fake, format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$1\" in -Q) printf 'heldpkg 1.2.3\n'; exit 0;; -Qu) test -f {}.state || echo 'pendingpkg 1 -> 2'; exit 0;; -Syu) echo Upgrading demo; touch {}.state; exit 0;; esac\nexit 0\n", log.display(), log.display(), log.display())).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    let old = std::env::var_os("HARMONIA_PACMAN_PATH");
    std::env::set_var("HARMONIA_PACMAN_PATH", &fake);
    let result = crate::atoms::r#do::install_package::package_tool_with_policy_for_backend(
        &receipts,
        "demo",
        "upgrade",
        &[],
        true,
        None,
        &[],
        2,
        crate::PackageBackend::Pacman,
        invocation,
    );
    match old {
        Some(ref v) => std::env::set_var("HARMONIA_PACMAN_PATH", v),
        None => std::env::remove_var("HARMONIA_PACMAN_PATH"),
    };
    let out = result?;
    let mut validation_cases = Vec::new();
    for (label, name, version, expected_ok) in [
        ("empty-name", "", "1", false),
        ("unsafe-name", "bad name", "1", false),
        ("empty-version", "safe-name", "", false),
        ("shell-metachar-version", "safe-name", "1; rm", false),
        ("valid-pin", "safe-name", "1.2.3-1", true),
    ] {
        let mut pins = std::collections::BTreeMap::new();
        pins.insert(name.into(), version.into());
        let actual_ok = crate::tools::ladder::validate_package_pins(&pins).is_ok();
        validation_cases
            .push(serde_json::json!({"case": label, "ok": actual_ok, "expected_ok": expected_ok}));
    }
    let fixture_root = root.join("pin-profile");
    let pins_dir = fixture_root.join("modules/pins");
    let other_dir = fixture_root.join("modules/other");
    let refusal_dir = fixture_root.join("modules/refusal");
    std::fs::create_dir_all(&pins_dir).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&other_dir).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&refusal_dir).map_err(|e| e.to_string())?;
    let pin_manifest = serde_json::json!({"schema": crate::tools::ladder::SCHEMA, "id": "pins", "version": "1", "constants": {}, "package_pins": {"heldpkg": "1.2.3"}, "ladder": []});
    let other_manifest = serde_json::json!({"schema": crate::tools::ladder::SCHEMA, "id": "other", "version": "1", "constants": {}, "ladder": []});
    let refusal_manifest = serde_json::json!({"schema": crate::tools::ladder::SCHEMA, "id": "refusal", "version": "1", "constants": {}, "package_pins": {"heldpkg": "1.2.3"}, "ladder": []});
    for (dir, manifest) in [
        (pins_dir, pin_manifest),
        (other_dir, other_manifest),
        (refusal_dir, refusal_manifest),
    ] {
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec(&manifest).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    }
    let profile = crate::Profile {
        id: "pin-fixture".into(),
        identity: "pin-fixture".into(),
        package_authority: Some(crate::PackageAuthority {
            os_family: "arch".into(),
            package_manager: "pacman".into(),
        }),
        modules: vec!["pins".into(), "other".into()],
        hotfixes: Vec::new(),
        syzygy_declaration: None,
    };
    let projection = crate::bands::stage_profile::projection::load_profile_projection(
        &profile,
        &fixture_root.join("modules"),
        &std::collections::BTreeSet::new(),
    )?;
    let expected_pins =
        std::collections::BTreeMap::from([("heldpkg".to_string(), "1.2.3".to_string())]);
    let projected_pins = match projection.modules.get("pins").map(|module| &module.loaded) {
        Some(crate::LoadedModule::Ladder(manifest)) => manifest.package_pins.clone(),
        _ => return Err("pins-fixture-not-projected-ladder".into()),
    };
    let ordinary_projected_pins = match projection.modules.get("other").map(|module| &module.loaded)
    {
        Some(crate::LoadedModule::Ladder(manifest)) => manifest.package_pins.clone(),
        _ => return Err("ordinary-fixture-not-projected-ladder".into()),
    };
    let projection_propagation =
        projected_pins == expected_pins && ordinary_projected_pins == expected_pins;
    let refusal_result = crate::bands::stage_profile::groups::load_profile_module(
        &fixture_root.join("modules"),
        "refusal",
    );
    let non_pins_refusal = match refusal_result {
        Err(error) => error == "pin-declared-outside-pins-module",
        Ok(_) => false,
    };
    std::env::set_var("HARMONIA_PACMAN_PATH", &fake);
    let fixture_result = crate::atoms::r#do::install_package::package_tool_with_policy_for_backend_and_pins(
        &receipts,
        "fixture",
        "upgrade",
        &[],
        true,
        None,
        &[],
        2,
        PackageBackend::Pacman,
        invocation,
        &ordinary_projected_pins,
    );
    match old {
        Some(ref v) => std::env::set_var("HARMONIA_PACMAN_PATH", v),
        None => std::env::remove_var("HARMONIA_PACMAN_PATH"),
    };
    let fixture_out = fixture_result?;
    let fixture_receipt: serde_json::Value = serde_json::from_slice(
        &std::fs::read(receipts.join("fixture.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let fixture_witness: serde_json::Value = serde_json::from_slice(
        &std::fs::read(receipts.join("fixture.pin-witness.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let transaction_exclusion = fixture_out.ok
        && fixture_receipt["exclusion_set"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "heldpkg"));
    let witness = fixture_witness["witness"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item["name"] == "heldpkg" && item["state"] == "held/green")
    });
    let text = std::fs::read_to_string(&log).map_err(|e| e.to_string())?;
    let argv = text.lines().map(str::to_string).collect::<Vec<_>>();
    let exact = argv.iter().any(|line| line == "-Syu --noconfirm");
    let typed_receipt = receipts.join("demo.json").is_file();
    let mut proof_pins = std::collections::BTreeMap::new();
    proof_pins.insert("heldpkg".to_string(), "1.2.3".to_string());
    let exact_root = root.join("exact-pin-proof");
    std::fs::create_dir_all(&exact_root).map_err(|e| e.to_string())?;
    let exact_action = exact_root.join("actions");
    let exact_fake = exact_root.join("pacman");
    std::fs::write(
        &exact_fake,
        format!(
            "#!/bin/sh\ncase \"$1\" in -Q) printf 'heldpkg 1.2.3\\n';; -Qu) exit 0;; -Syu) touch '{}';; esac\n",
            exact_action.display()
        ),
    )
    .map_err(|e| e.to_string())?;
    std::fs::set_permissions(&exact_fake, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    std::env::set_var("HARMONIA_PACMAN_PATH", &exact_fake);
    let exact_result = crate::atoms::r#do::install_package::package_tool_with_policy_for_backend_and_pins(
        &exact_root,
        "exact",
        "upgrade",
        &[],
        false,
        None,
        &[],
        2,
        PackageBackend::Pacman,
        invocation,
        &proof_pins,
    )?;
    let exact_witness: serde_json::Value = serde_json::from_slice(
        &std::fs::read(exact_root.join("exact.pin-witness.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let exact_pin_no_actuation = exact_result.ok
        && exact_witness["witness"].as_array().is_some_and(|items| {
            items
                .iter()
                .any(|item| item["name"] == "heldpkg" && item["state"] == "held/green")
        })
        && exact_witness["exclusion_set"] == serde_json::json!(["heldpkg"])
        && !exact_action.exists();
    match old {
        Some(ref v) => std::env::set_var("HARMONIA_PACMAN_PATH", v),
        None => std::env::remove_var("HARMONIA_PACMAN_PATH"),
    };
    let apt_root = root.join("apt-proof");
    std::fs::create_dir_all(&apt_root).map_err(|e| e.to_string())?;
    let apt_log = apt_root.join("argv");
    let apt_fake = apt_root.join("apt-get");
    std::fs::write(
        &apt_fake,
        format!(
            "#!/bin/sh\nprintf '%s\n' \"$*\" >> '{}'\nexit 0\n",
            apt_log.display()
        ),
    )
    .map_err(|e| e.to_string())?;
    std::fs::set_permissions(&apt_fake, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    let apt_result = crate::atoms::r#do::install_package::run_apt_command(
        &apt_root,
        "apt",
        &apt_fake.to_string_lossy(),
        vec!["full-upgrade".into(), "--yes".into(), "--no-remove".into()],
        2,
        &proof_pins,
    );
    let apt_argv = std::fs::read_to_string(&apt_log).unwrap_or_default();
    let apt_preferences_argv = apt_argv.contains("Dir::Etc::preferences=")
        && apt_argv.contains("Dir::Etc::preferencesparts=-");
    let apt_no_remove = apt_argv.contains("--no-remove");
    let apt_guard_removed = !std::fs::read_dir(&apt_root)
        .map(|entries| {
            entries.flatten().any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains(".harmonia-apt-preferences")
            })
        })
        .unwrap_or(false);
    let apt_success_proof =
        apt_result.ok && apt_preferences_argv && apt_no_remove && apt_guard_removed;

    let write_root = root.join("apt-write-failure");
    std::fs::write(&write_root, b"file").map_err(|e| e.to_string())?;
    let invoked = root.join("apt-invoked");
    let write_fake = root.join("apt-write-failure-bin");
    std::fs::write(
        &write_fake,
        format!("#!/bin/sh\ntouch '{}'\n", invoked.display()),
    )
    .map_err(|e| e.to_string())?;
    std::fs::set_permissions(&write_fake, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    let write_result = crate::atoms::r#do::install_package::run_apt_command(
        &write_root,
        "apt",
        &write_fake.to_string_lossy(),
        vec!["full-upgrade".into()],
        2,
        &proof_pins,
    );
    let apt_guard_write_failure_fail_closed = !write_result.ok
        && write_result.stderr.contains("apt preferences write failed")
        && !invoked.exists();

    let exec_root = root.join("apt-exec-failure");
    std::fs::create_dir_all(&exec_root).map_err(|e| e.to_string())?;
    let exec_fake = exec_root.join("apt-get");
    std::fs::write(&exec_fake, "#!/bin/sh\nexit 17\n").map_err(|e| e.to_string())?;
    std::fs::set_permissions(&exec_fake, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    let exec_result = crate::atoms::r#do::install_package::run_apt_command(
        &exec_root,
        "apt",
        &exec_fake.to_string_lossy(),
        vec!["full-upgrade".into()],
        2,
        &proof_pins,
    );
    let apt_failed_execution_cleans_guard = !exec_result.ok
        && !std::fs::read_dir(&exec_root)
            .map(|entries| {
                entries.flatten().any(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .contains(".harmonia-apt-preferences")
                })
            })
            .unwrap_or(false);

    let cleanup_root = root.join("apt-cleanup-failure");
    std::fs::create_dir_all(&cleanup_root).map_err(|e| e.to_string())?;
    let cleanup_fake = cleanup_root.join("apt-get");
    std::fs::write(
        &cleanup_fake,
        "#!/bin/sh\nfor arg in \"$@\"; do case \"$arg\" in Dir::Etc::preferences=*) rm -f \"${arg#*=}\";; esac; done\nexit 0\n",
    )
    .map_err(|e| e.to_string())?;
    std::fs::set_permissions(&cleanup_fake, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    let cleanup_result = crate::atoms::r#do::install_package::run_apt_command(
        &cleanup_root,
        "apt",
        &cleanup_fake.to_string_lossy(),
        vec!["full-upgrade".into()],
        2,
        &proof_pins,
    );
    let apt_cleanup_failure_non_green = !cleanup_result.ok
        && cleanup_result
            .stderr
            .contains("apt preferences cleanup failed");

    let divergent_root = root.join("divergent-proof");
    std::fs::create_dir_all(&divergent_root).map_err(|e| e.to_string())?;
    let divergent_fake = divergent_root.join("pacman");
    let acted = divergent_root.join("acted");
    std::fs::write(
        &divergent_fake,
        format!(
            "#!/bin/sh\ncase \"$1\" in -Q) printf 'heldpkg 9.9.9\n';; -Syu) touch '{}';; esac\n",
            acted.display()
        ),
    )
    .map_err(|e| e.to_string())?;
    std::fs::set_permissions(&divergent_fake, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    std::env::set_var("HARMONIA_PACMAN_PATH", &divergent_fake);
    let divergent = crate::atoms::r#do::install_package::package_tool_with_policy_for_backend_and_pins(
        &divergent_root,
        "divergent",
        "upgrade",
        &[],
        true,
        None,
        &[],
        2,
        PackageBackend::Pacman,
        invocation,
        &proof_pins,
    )?;
    let divergent_witness: serde_json::Value = serde_json::from_slice(
        &std::fs::read(divergent_root.join("divergent.pin-witness.json"))
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let divergent_pin_no_remediation = divergent.ok
        && divergent_witness["witness"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item["state"] == "divergent"))
        && !acted.exists();
    match old {
        Some(ref v) => std::env::set_var("HARMONIA_PACMAN_PATH", v),
        None => std::env::remove_var("HARMONIA_PACMAN_PATH"),
    };
    Ok(serde_json::json!({
        "production_ok": out.ok,
        "typed_receipt": typed_receipt,
        "upgrade_argv_exact": exact,
        "fake_log_only": !text.is_empty(),
        "pacman_argv": argv,
        "skipped": out.skipped,
        "skip_refusal_truthful": out.ok && !out.skipped,
        "pin_validation_cases": validation_cases,
        "pin_validation_all_cases": validation_cases.iter().all(|case| case["ok"] == case["expected_ok"]),
        "projection_propagation": projection_propagation,
        "transaction_exclusion": transaction_exclusion,
        "witness": witness,
        "non_pins_refusal": non_pins_refusal,
        "exact_pin_no_actuation": exact_pin_no_actuation,
        "apt_preferences_argv": apt_preferences_argv,
        "apt_no_remove": apt_no_remove,
        "apt_guard_removed_after_success": apt_guard_removed,
        "apt_guard_write_failure_fail_closed": apt_guard_write_failure_fail_closed,
        "apt_failed_execution_cleans_guard": apt_failed_execution_cleans_guard,
        "apt_cleanup_failure_non_green": apt_cleanup_failure_non_green,
        "divergent_pin_no_remediation": divergent_pin_no_remediation,
        "ok": out.ok && exact && !out.skipped && typed_receipt
            && validation_cases.iter().all(|case| case["ok"] == case["expected_ok"])
            && projection_propagation
            && transaction_exclusion
            && witness
            && non_pins_refusal
            && exact_pin_no_actuation
            && apt_success_proof
        && apt_guard_write_failure_fail_closed
        && apt_failed_execution_cleans_guard
        && apt_cleanup_failure_non_green
        && divergent_pin_no_remediation,
    }))
}



pub(crate) use crate::atoms::ask::install_package::PackageObservation;
pub(crate) use crate::atoms::r#do::install_package::{
    keyring_repair_tool, package_tool_for_backend,
    package_tool_with_policy_for_backend, package_tool_with_policy_for_backend_and_pins,
    write_pin_witness,
};
