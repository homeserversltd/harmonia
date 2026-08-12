//! One single-act tool that brings one file to its declared bytes and metadata.
#![allow(dead_code)]

use crate::atoms::{self, Drift, Receipt};
use std::path::{Path, PathBuf};

#[path = "act/index.rs"]
mod act;
#[path = "observe/index.rs"]
mod observe;
#[path = "report-home/index.rs"]
mod report_home;

#[derive(Debug, Clone, Copy)]
pub(crate) struct DeclaredOwnership {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum BackupPolicy<'a> {
    None,
    To(&'a Path),
}

pub(crate) struct PlaceFileRequest<'a> {
    pub path: &'a Path,
    pub declared_bytes: &'a [u8],
    pub mode: Option<u32>,
    pub ownership: DeclaredOwnership,
    pub backup: BackupPolicy<'a>,
    pub invocation: Option<atoms::r#do::InvocationKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlaceFileObservation {
    pub existed: bool,
    pub regular: bool,
    pub bytes_equal: bool,
    pub mode: Option<u32>,
    pub mode_equal: bool,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub owner_equal: bool,
    pub group_equal: bool,
}

impl PlaceFileObservation {
    fn current(&self) -> bool {
        self.regular && self.bytes_equal && self.mode_equal && self.owner_equal && self.group_equal
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct PlaceFileMovement {
    pub bytes: bool,
    pub mode: bool,
    pub owner: bool,
    pub created: bool,
    pub backed_up: Option<PathBuf>,
}

impl PlaceFileMovement {
    pub(crate) fn changed(&self) -> bool {
        self.bytes || self.mode || self.owner || self.created
    }
}

#[derive(Debug)]
pub(crate) struct PlaceFileOutcome {
    pub observation: PlaceFileObservation,
    pub movement: PlaceFileMovement,
    pub receipt: Receipt,
}

pub(crate) fn execute(request: PlaceFileRequest<'_>) -> Result<PlaceFileOutcome, String> {
    let run = crate::tools::comparison::execute(
        || {
            observe::file(
                request.path,
                request.declared_bytes,
                request.mode,
                request.ownership,
            )
        },
        |observation| {
            if observation.current() {
                crate::tools::comparison::DiffDecision::Empty
            } else {
                crate::tools::comparison::DiffDecision::Different
            }
        },
        |authorization, observation| {
            let Some(invocation) = request.invocation else {
                return Ok(PlaceFileMovement::default());
            };
            act::place(
                authorization,
                invocation,
                request.path,
                request.declared_bytes,
                request.mode,
                request.ownership,
                request.backup,
                observation,
            )
        },
    )?;
    let observation = run.observation().clone();
    let movement = match run {
        crate::tools::comparison::ComparisonRun::Current { .. } => PlaceFileMovement::default(),
        crate::tools::comparison::ComparisonRun::Moved { movement, .. } => movement,
    };
    let drift = if observation.current() {
        Drift::Current
    } else {
        Drift::File {
            expected_sha256: atoms::file_sha256(request.declared_bytes),
            actual_sha256: observation
                .regular
                .then(|| std::fs::read(request.path).ok())
                .flatten()
                .map(|bytes| atoms::file_sha256(&bytes)),
        }
    };
    let receipt = report_home::receipt(request.path, drift, &movement);
    Ok(PlaceFileOutcome {
        observation,
        movement,
        receipt,
    })
}
