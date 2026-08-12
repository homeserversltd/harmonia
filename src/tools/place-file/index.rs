//! One single-act tool that brings one file to its declared bytes.
#![allow(dead_code)]

use crate::atoms::{self, Drift, Observation, Receipt};
use std::path::Path;

#[path = "act/index.rs"]
mod act;
#[path = "observe/index.rs"]
mod observe;
#[path = "report-home/index.rs"]
mod report_home;

pub(crate) struct PlaceFileRequest<'a> {
    pub path: &'a Path,
    pub declared_bytes: &'a [u8],
    pub invocation: atoms::r#do::InvocationKey,
    pub appliance_log: &'a Path,
    pub declared_secrets: &'a [String],
}

#[derive(Debug)]
pub(crate) struct PlaceFileOutcome {
    pub changed: bool,
    pub observation: Observation,
    pub receipt: Receipt,
}

pub(crate) fn execute(request: PlaceFileRequest<'_>) -> Result<PlaceFileOutcome, String> {
    let path = request.path.to_path_buf();
    let declared = request.declared_bytes.to_vec();
    let run = observe::compare(&path, &declared, |authorization, observation, drift| {
        act::place(
            authorization,
            request.invocation,
            &path,
            &declared,
            observation,
            drift,
        )
    })?;

    let (changed, observation, drift) = match run {
        crate::tools::comparison::ComparisonRun::Current { observation, .. } => {
            (false, observation, Drift::Current)
        }
        crate::tools::comparison::ComparisonRun::Moved {
            observation,
            movement,
            ..
        } => (true, observation, movement.drift),
    };
    let receipt = Receipt {
        atom: "place-file".into(),
        ok: true,
        drift,
        message: if changed {
            format!("placed {}", request.path.display())
        } else {
            format!("current {}", request.path.display())
        },
    };
    report_home::attest(request.appliance_log, &receipt, request.declared_secrets)?;
    Ok(PlaceFileOutcome {
        changed,
        observation,
        receipt,
    })
}
