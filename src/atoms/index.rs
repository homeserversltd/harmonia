// The Harmonia engine atoms: ask, do, compare, attest.
#[allow(dead_code)]
use crate::tools::comparison::{self, DiffDecision};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
#[path = "ask/index.rs"]
pub(crate) mod ask;
#[path = "attest/index.rs"]
pub(crate) mod attest;
#[path = "do/index.rs"]
pub(crate) mod r#do;
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FileObservation {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CommandObservation {
    pub program: String,
    pub args: Vec<String>,
    pub ok: bool,
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct UnitObservation {
    pub unit: String,
    pub active: bool,
    pub enabled: bool,
    pub state: String,
    pub active_query: CommandObservation,
    pub enabled_query: CommandObservation,
    pub show_query: CommandObservation,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct HttpObservation {
    pub url: String,
    pub reachable: bool,
    pub status: Option<u16>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Drift {
    Current,
    File {
        expected_sha256: String,
        actual_sha256: Option<String>,
    },
    Command {
        expected_code: i32,
        actual_code: Option<i32>,
    },
    Unit {
        expected: String,
        actual: String,
    },
    Http {
        expected_status: u16,
        actual_status: Option<u16>,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Receipt {
    pub atom: String,
    pub ok: bool,
    pub drift: Drift,
    pub message: String,
}
fn sha256(bytes: &[u8]) -> String {
    let mut d = Sha256::new();
    d.update(bytes);
    format!("{:x}", d.finalize())
}
pub(crate) fn ask_file(path: &Path) -> Result<FileObservation, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| format!("ask-file-open: {e}"))?
        .read_to_end(&mut bytes)
        .map_err(|e| format!("ask-file-read: {e}"))?;
    Ok(FileObservation {
        path: path.to_path_buf(),
        sha256: sha256(&bytes),
        bytes,
    })
}

/// The declared side of a comparison. The caller supplies intent, never a
/// precomputed answer; `derive_drift` owns the observation-versus-declaration
/// decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Declaration {
    FileSha256(String),
    CommandCode(i32),
    UnitState(String),
    HttpStatus(u16),
}

fn derive_drift(declared: &Declaration, observation: &Observation) -> Drift {
    match (declared, observation) {
        (Declaration::FileSha256(expected), Observation::File(actual)) => Drift::File {
            expected_sha256: expected.clone(),
            actual_sha256: Some(actual.sha256.clone()),
        },
        (Declaration::CommandCode(expected), Observation::Command(actual)) => Drift::Command {
            expected_code: *expected,
            actual_code: actual.code,
        },
        (Declaration::UnitState(expected), Observation::Unit(actual)) => Drift::Unit {
            expected: expected.clone(),
            actual: actual.state.clone(),
        },
        (Declaration::HttpStatus(expected), Observation::Http(actual)) => Drift::Http {
            expected_status: *expected,
            actual_status: actual.status,
        },
        (Declaration::FileSha256(expected), _) => Drift::File {
            expected_sha256: expected.clone(),
            actual_sha256: None,
        },
        (Declaration::CommandCode(expected), _) => Drift::Command {
            expected_code: *expected,
            actual_code: None,
        },
        (Declaration::UnitState(expected), _) => Drift::Unit {
            expected: expected.clone(),
            actual: String::new(),
        },
        (Declaration::HttpStatus(expected), _) => Drift::Http {
            expected_status: *expected,
            actual_status: None,
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Observation {
    File(FileObservation),
    Command(CommandObservation),
    Unit(UnitObservation),
    Http(HttpObservation),
}

/// Compare a declared expectation with the actual observation. Drift is
/// derived here, so no caller-supplied `Current`/`Different` answer exists.
pub(crate) fn compare<Movement>(
    observation: Observation,
    declared: Declaration,
    act: impl FnOnce(comparison::ActionAuthorization, &Observation, &Drift) -> Result<Movement, String>,
) -> Result<comparison::ComparisonRun<Observation, Movement>, String> {
    let drift = derive_drift(&declared, &observation);
    let current = match &drift {
        Drift::File {
            expected_sha256,
            actual_sha256,
        } => actual_sha256.as_deref() == Some(expected_sha256),
        Drift::Command {
            expected_code,
            actual_code,
        } => actual_code == &Some(*expected_code),
        Drift::Unit { expected, actual } => expected == actual,
        Drift::Http {
            expected_status,
            actual_status,
        } => actual_status == &Some(*expected_status),
        Drift::Current => true,
    };
    comparison::execute(
        || Ok(observation),
        |_| {
            if current {
                DiffDecision::Empty
            } else {
                DiffDecision::Different
            }
        },
        |authorization, observed| act(authorization, observed, &drift),
    )
}
pub(crate) fn backup_first_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if path.exists() {
        let backup = path.with_extension(format!(
            "{}bak",
            path.extension()
                .and_then(|x| x.to_str())
                .map(|x| format!("{x}."))
                .unwrap_or_default()
        ));
        fs::copy(path, backup).map_err(|e| format!("backup-first: {e}"))?;
    }
    fs::write(path, bytes).map_err(|e| format!("file-write: {e}"))
}
pub(crate) fn append_appliance_log(path: &Path, receipt: &Receipt) -> Result<(), String> {
    let mut stream = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("attest-open: {e}"))?;
    serde_json::to_writer(&mut stream, receipt).map_err(|e| format!("attest-serialize: {e}"))?;
    stream
        .write_all(b"\n")
        .map_err(|e| format!("attest-append: {e}"))
}
