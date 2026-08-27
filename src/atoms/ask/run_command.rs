use super::{file_if_present, path_kind, PathKind};
use crate::atoms::CommandObservation;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct PreImageObservation {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub program_kind: Option<PathKind>,
    pub program_file: Option<crate::atoms::FileObservation>,
}

pub(crate) fn observe(program: &str, args: &[String], cwd: Option<&Path>) -> Result<PreImageObservation, String> {
    let path = Path::new(program);
    Ok(PreImageObservation {
        program: program.to_string(), args: args.to_vec(), cwd: cwd.map(Path::to_path_buf),
        program_kind: path_kind(path)?, program_file: file_if_present(path)?,
    })
}

