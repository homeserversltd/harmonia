// The Harmonia engine atoms: ask, do, and attest.
//
// This module is intentionally a small floor. It owns no profile policy and
// never waits on a remote observer: every observation is typed and bounded.
#[allow(dead_code)]
use crate::tools::comparison::{self, DiffDecision};
use serde::Serialize;
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
    pub code: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct UnitObservation {
    pub unit: String,
    pub active: bool,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct HttpObservation {
    pub url: String,
    pub reachable: bool,
    pub status: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Receipt {
    pub atom: String,
    pub ok: bool,
    pub drift: Drift,
    pub message: String,
}

fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
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

pub(crate) fn compare<T>(
    observation: T,
    drift: Drift,
) -> Result<comparison::ComparisonRun<T, Receipt>, String> {
    comparison::execute(
        || Ok::<_, String>(observation),
        |_| {
            if matches!(drift, Drift::Current) {
                DiffDecision::Empty
            } else {
                DiffDecision::Different
            }
        },
        |authorization, _| {
            r#do::apply(
                authorization,
                Receipt {
                    atom: "do".into(),
                    ok: true,
                    drift: drift.clone(),
                    message: "authorized".into(),
                },
            )
        },
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
