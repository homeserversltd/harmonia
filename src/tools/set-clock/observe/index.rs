use crate::atoms;
use crate::CmdResult;
use std::time::Duration;

#[derive(Debug, Clone)]
pub(super) struct ClockObservation {
    pub(super) timezone: Option<String>,
    pub(super) timesync: bool,
    pub(super) local_state: atoms::CommandObservation,
    pub(super) remote_state: Option<CmdResult>,
}

pub(super) fn clock(request: &super::Request<'_>) -> ClockObservation {
    let local_state = atoms::ask::read_only_command_with_timeout(
        "/usr/bin/timedatectl",
        &[
            "show".into(),
            "--property=NTPSynchronized,NTP,Timezone".into(),
        ],
        Duration::from_secs(request.timeout_secs),
    );
    let mut timezone = None;
    let mut timesync = false;
    for line in local_state.stdout.lines() {
        if let Some(value) = line.strip_prefix("Timezone=") {
            timezone = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("NTPSynchronized=") {
            timesync = truth(value);
        }
    }
    let remote_state = match request.operation {
        "resolve" => Some(backend_query(request)),
        "watch-and-set" => Some(peer_query(request)),
        _ => None,
    };
    ClockObservation {
        timezone,
        timesync,
        local_state,
        remote_state,
    }
}

fn backend_query(request: &super::Request<'_>) -> CmdResult {
    let observed = match request.backend {
        "caduceus" => atoms::ask::read_only_command_with_timeout(
            "/usr/local/bin/caduceus",
            &["time".into(), "state".into()],
            Duration::from_secs(request.timeout_secs),
        ),
        "staff" => {
            let mut args =
                vec!["PYTHONPATH=/usr/local/sbin:/usr/local/lib/harmonia-household-time".into()];
            if let Some(path) = request.state_path {
                args.push(format!("CADUCEUS_HOUSEHOLD_TIME_STATE_PATH={path}"));
            }
            args.extend([
                "/usr/bin/python3".into(),
                "-m".into(),
                "caduceus_staff.household_time".into(),
                "state".into(),
            ]);
            atoms::ask::read_only_command_with_timeout(
                "/usr/bin/env",
                &args,
                Duration::from_secs(request.timeout_secs),
            )
        }
        _ => {
            return CmdResult {
                ok: false,
                code: -1,
                stdout: String::new(),
                stderr: "household-time-backend-invalid".into(),
            }
        }
    };
    cmd(observed)
}

fn peer_query(request: &super::Request<'_>) -> CmdResult {
    let timeout = request.timeout_secs.to_string();
    cmd(atoms::ask::read_only_command_with_timeout(
        "/usr/bin/curl",
        &[
            "-fsS".into(),
            "--connect-timeout".into(),
            "3".into(),
            "--max-time".into(),
            timeout,
            request.state_url.unwrap_or_default().into(),
        ],
        Duration::from_secs(request.timeout_secs),
    ))
}

pub(super) fn current_receipt(observation: &ClockObservation) -> CmdResult {
    CmdResult {
        ok: observation.local_state.ok,
        code: observation.local_state.code.unwrap_or(-1),
        stdout: observation.local_state.stdout.clone(),
        stderr: observation.local_state.stderr.clone(),
    }
}

fn cmd(value: atoms::CommandObservation) -> CmdResult {
    CmdResult {
        ok: value.ok,
        code: value.code.unwrap_or(-1),
        stdout: value.stdout,
        stderr: value.stderr,
    }
}
fn truth(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "yes" | "true" | "1" | "active"
    )
}
