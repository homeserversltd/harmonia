//! Typed, bounded observation atoms.
#![allow(dead_code)]
use super::{ask_file, CommandObservation, FileObservation, HttpObservation, UnitObservation};
use std::path::Path;

pub(crate) fn file(path: &Path) -> Result<FileObservation, String> {
    ask_file(path)
}
pub(crate) fn read_only_command(program: &str, args: &[String]) -> CommandObservation {
    CommandObservation {
        program: program.into(),
        args: args.to_vec(),
        ok: true,
        code: 0,
    }
}
pub(crate) fn unit_state(unit: &str, active: bool, state: &str) -> UnitObservation {
    UnitObservation {
        unit: unit.into(),
        active,
        state: state.into(),
    }
}
pub(crate) fn http_probe(url: &str, status: Option<u16>) -> HttpObservation {
    HttpObservation {
        url: url.into(),
        reachable: status.is_some(),
        status,
    }
}
