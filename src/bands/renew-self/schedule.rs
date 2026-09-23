use crate::atoms::r#do::{run_command, InvocationKey};
use crate::tools::comparison::{self, DiffDecision};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const INSTALLER_ENV: &str = "HARMONIA_INSTALLER";
const TIMER_FILE: &str = "/etc/systemd/system/harmonia.timer";
const TIMER_TEMPLATE: &str = "[Unit]\nDescription=Run Harmonia selected-profile convergence on schedule\n\n[Timer]\nOnBootSec=2min\nOnCalendar={calendar}\nAccuracySec=30s\nPersistent=true\nUnit=harmonia.service\n\n[Install]\nWantedBy=timers.target\n";

fn installer_candidate() -> Result<PathBuf, String> {
    if let Ok(value) = env::var(INSTALLER_ENV) {
        let path = PathBuf::from(value);
        return if path.is_file() {
            Ok(path)
        } else {
            Err(format!("harmonia-installer-not-found env={INSTALLER_ENV}"))
        };
    }
    let mut candidates =
        vec![Path::new(crate::SOURCE_ROOT).join("installer/harmonia_installer.py")];
    if let Ok(cwd) = env::current_dir() {
        candidates.push(cwd.join("installer/harmonia_installer.py"));
    }
    candidates
        .into_iter()
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| format!("harmonia-installer-not-found env={INSTALLER_ENV}"))
}

fn installer_diagnostic() -> Option<String> {
    let path = match installer_candidate() {
        Ok(path) => path,
        Err(_) if env::var_os(INSTALLER_ENV).is_some() => {
            return Some("helper_gap=harmonia-installer-missing".into());
        }
        Err(_) => return Some("helper_gap=harmonia-installer-missing".into()),
    };
    match fs::read_to_string(&path) {
        Ok(text) if text.contains("converge-timer") => None,
        Ok(_) => Some(format!(
            "helper_gap=harmonia-installer-stale path={}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Some("helper_gap=harmonia-installer-missing".into())
        }
        Err(_) => Some(format!(
            "helper_gap=harmonia-installer-unreadable path={}",
            path.display()
        )),
    }
}

fn invoke(action: &str, args: &[String], invocation: &InvocationKey) -> Result<(), String> {
    let script = installer_candidate()?;
    let cwd = script
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let mut child_args = vec![script.to_string_lossy().into_owned(), action.to_string()];
    child_args.extend(args.iter().cloned());
    let systemd_root = args
        .windows(2)
        .find(|pair| pair[0] == "--systemd-root")
        .map(|pair| PathBuf::from(&pair[1]))
        .unwrap_or_else(|| PathBuf::from("/etc/systemd/system"));
    let installing = action == "install-timer";
    let dry_run =
        args.iter().any(|arg| arg == "--dry-run") || !args.iter().any(|arg| arg == "--apply");
    let observe = || {
        Ok::<_, String>((
            systemd_root.join("harmonia.service").is_file(),
            systemd_root.join("harmonia.timer").is_file(),
        ))
    };
    let compare = |observed: &(bool, bool)| {
        let current = if installing {
            observed.0 && observed.1
        } else {
            !observed.0 && !observed.1
        };
        if current {
            DiffDecision::Empty
        } else {
            DiffDecision::Different
        }
    };
    let owned = if dry_run {
        comparison::execute_once("harmonia-schedule", observe, compare, |authorization, _| {
            run_command::command_with_timeout_in_dir(
                &authorization,
                invocation,
                "python3",
                &child_args,
                Some(cwd.as_path()),
                std::time::Duration::from_secs(30),
            )
        })?
    } else {
        comparison::execute("harmonia-schedule", observe, compare, |authorization, _| {
            run_command::command_with_timeout_in_dir(
                &authorization,
                invocation,
                "python3",
                &child_args,
                Some(cwd.as_path()),
                std::time::Duration::from_secs(30),
            )
        })?
    };
    let result = match owned {
        comparison::ComparisonRun::Moved { movement, .. } => movement,
        comparison::ComparisonRun::Current { .. } => return Ok(()),
    };
    crate::hyalos::forward_receipt(
        "harmonia.schedule.command",
        &format!("action={action} argv={child_args:?} ok={}", result.ok),
        Some(
            serde_json::json!({"action": action, "argv": child_args, "ok": result.ok, "code": result.code, "attest_owner": "hyalos"}),
        ),
        Some(result.ok),
            None,
);
    if !result.stdout.is_empty() {
        print!("{}", result.stdout);
        if !result.stdout.ends_with('\n') {
            println!();
        }
    }
    if !result.stderr.is_empty() {
        eprint!("{}", result.stderr);
        if !result.stderr.ends_with('\n') {
            eprintln!();
        }
    }
    if result.ok {
        Ok(())
    } else {
        Err(format!("installer-exit={:?} action={action}", result.code))
    }
}

#[cfg(any(test, feature = "test-facade"))]
fn timer_file_path() -> PathBuf {
    match env::var_os("HARMONIA_TEST_SYSTEMD_ROOT") {
        Some(root) => PathBuf::from(root).join("harmonia.timer"),
        None => PathBuf::from(TIMER_FILE),
    }
}

#[cfg(not(any(test, feature = "test-facade")))]
fn timer_file_path() -> PathBuf {
    PathBuf::from(TIMER_FILE)
}

fn cadence_receipt(
    calendar: &str,
    source: &str,
    file: &Path,
    drift: bool,
    movement: &str,
    daemon_reload: bool,
    ok: bool,
    failed_signal: Option<&str>,
) -> serde_json::Value {
    let mut receipt = serde_json::json!({"schema":"harmonia.timer.cadence.v1","ok":ok,"calendar":calendar,"source":source,"file":file.display().to_string(),"drift":drift,"movement":movement,"daemon_reload":daemon_reload,"arming":false,"first_missing_signal":failed_signal});
    if let Some(diagnostic) = installer_diagnostic() {
        receipt["helper_diagnostic"] = serde_json::Value::String(diagnostic);
    }
    receipt
}

pub(crate) fn reconcile_update_timer(
    apply: bool,
    invocation: Option<&InvocationKey>,
) -> Result<serde_json::Value, String> {
    let cadence = crate::bands::stage_profile::groups::read_device_update_cadence()?;
    let timer_path = timer_file_path();
    let desired = TIMER_TEMPLATE
        .replace("{calendar}", &cadence.calendar)
        .into_bytes();
    let observed = fs::read(&timer_path).ok();
    let drift = observed.as_deref() != Some(desired.as_slice());
    let mut movement = "none";
    let mut daemon_reload = false;
    if apply && drift {
        let invocation =
            invocation.ok_or_else(|| "harmonia-timer-cadence-invocation-missing".to_string())?;
        let result = comparison::execute_once(
            "harmonia-timer-cadence",
            || Ok::<_, String>(fs::read(&timer_path).ok()),
            |current| {
                if current.as_deref() == Some(desired.as_slice()) {
                    DiffDecision::Empty
                } else {
                    DiffDecision::Different
                }
            },
            |authorization, _| {
                crate::atoms::r#do::write_file::file_write(
                    &authorization,
                    invocation,
                    &timer_path,
                    &desired,
                    crate::atoms::r#do::write_file::FileWriteOptions {
                        write_bytes: true,
                        mode: Some(0o644),
                        uid: None,
                        gid: None,
                        backup_to: None,
                    },
                )?;
                let reload = run_command::command_with_timeout(
                    &authorization,
                    invocation,
                    "/usr/bin/systemctl",
                    &["daemon-reload".into()],
                    std::time::Duration::from_secs(30),
                )?;
                if !reload.ok {
                    return Err(format!(
                        "harmonia-timer-daemon-reload-failed code={:?}",
                        reload.code
                    ));
                }
                Ok::<_, String>(())
            },
        )?;
        if matches!(result, comparison::ComparisonRun::Moved { .. }) {
            if fs::read(&timer_path).ok().as_deref() != Some(desired.as_slice()) {
                let receipt = cadence_receipt(
                    &cadence.calendar,
                    cadence.source,
                    &timer_path,
                    true,
                    "write-unverified",
                    false,
                    false,
                    Some("harmonia-timer-cadence-readback-mismatch"),
                );
                forward_cadence_receipt(&receipt);
                return Err("harmonia-timer-cadence-readback-mismatch".into());
            }
            movement = "written";
            daemon_reload = true;
        }
    }
    let receipt = cadence_receipt(
        &cadence.calendar,
        cadence.source,
        &timer_path,
        drift,
        movement,
        daemon_reload,
        true,
        None,
    );
    forward_cadence_receipt(&receipt);
    println!("{}", receipt);
    Ok(receipt)
}

fn forward_cadence_receipt(receipt: &serde_json::Value) {
    let calendar = receipt["calendar"].as_str().unwrap_or("unknown");
    let source = receipt["source"].as_str().unwrap_or("unknown");
    let file = receipt["file"].as_str().unwrap_or("unknown");
    let movement = receipt["movement"].as_str().unwrap_or("unknown");
    crate::hyalos::forward_receipt(
        "harmonia.timer.cadence",
        &format!("calendar={calendar} source={source} file={file} movement={movement}"),
        Some(receipt.clone()),
        receipt["ok"].as_bool(),
        None,
    );
}

pub(crate) fn install_timer(args: &[String], invocation: &InvocationKey) -> Result<(), String> {
    invoke("install-timer", args, invocation)
}
pub(crate) fn uninstall_timer(args: &[String], invocation: &InvocationKey) -> Result<(), String> {
    invoke("uninstall-timer", args, invocation)
}

#[cfg(test)]
mod cadence_tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn report_only_preserves_bytes_and_emits_shape_with_named_helper_gap() {
        let _guard = ENV_LOCK.lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("config.json");
        let systemd = root.path().join("systemd");
        fs::create_dir_all(&systemd).unwrap();
        let initial = b"old timer bytes";
        fs::write(systemd.join("harmonia.timer"), initial).unwrap();
        fs::write(&config, r#"{"harmonia":{"update_interval":"daily"}}"#).unwrap();
        env::set_var(
            crate::bands::stage_profile::groups::TEST_APPLIANCE_CONFIG_PATH_ENV,
            &config,
        );
        env::set_var("HARMONIA_TEST_SYSTEMD_ROOT", &systemd);
        assert_eq!(timer_file_path(), systemd.join("harmonia.timer"));
        env::remove_var("HARMONIA_TEST_SYSTEMD_ROOT");
        assert_eq!(timer_file_path(), PathBuf::from(TIMER_FILE));
        env::set_var("HARMONIA_TEST_SYSTEMD_ROOT", &systemd);
        let helper = root.path().join("installer.py");
        fs::write(&helper, "converge-timer").unwrap();
        env::set_var(INSTALLER_ENV, &helper);
        let receipt = reconcile_update_timer(false, None).unwrap();
        let after = fs::read(systemd.join("harmonia.timer")).unwrap();
        assert_eq!(after, initial);
        assert_eq!(receipt["schema"], "harmonia.timer.cadence.v1");
        assert_eq!(receipt["calendar"], "daily");
        assert_eq!(receipt["source"], "declared");
        assert_eq!(
            receipt["file"],
            systemd.join("harmonia.timer").display().to_string()
        );
        assert_eq!(receipt["arming"], false);
        assert_eq!(receipt["movement"], "none");
        assert_eq!(receipt["first_missing_signal"], serde_json::Value::Null);
        assert!(receipt.get("helper_diagnostic").is_none());
        fs::remove_file(&helper).unwrap();
        let missing = reconcile_update_timer(false, None).unwrap();
        assert_eq!(missing["first_missing_signal"], serde_json::Value::Null);
        assert_eq!(
            missing["helper_diagnostic"],
            "helper_gap=harmonia-installer-missing"
        );
        assert_eq!(fs::read(systemd.join("harmonia.timer")).unwrap(), initial);
        env::remove_var(crate::bands::stage_profile::groups::TEST_APPLIANCE_CONFIG_PATH_ENV);
        env::remove_var("HARMONIA_TEST_SYSTEMD_ROOT");
        env::remove_var(INSTALLER_ENV);
    }

    #[test]
    fn helper_diagnostics_distinguish_missing_stale_and_current() {
        let _guard = ENV_LOCK.lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        let helper = root.path().join("installer.py");
        env::set_var(INSTALLER_ENV, &helper);
        assert_eq!(
            installer_diagnostic().as_deref(),
            Some("helper_gap=harmonia-installer-missing")
        );
        fs::write(&helper, "help menu build install uninstall status").unwrap();
        assert!(installer_diagnostic()
            .as_deref()
            .unwrap()
            .contains("harmonia-installer-stale"));
        fs::write(&helper, "converge-timer").unwrap();
        assert!(installer_diagnostic().is_none());
        env::remove_var(INSTALLER_ENV);
    }
}
