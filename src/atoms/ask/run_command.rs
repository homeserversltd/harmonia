//! Typed command-target observation owned by Ask; no target execution occurs here.
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TargetObservation {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub path_kind: Option<String>,
    pub canonical_path: Option<PathBuf>,
    pub binary_sha256: Option<String>,
    #[cfg(unix)]
    pub binary_dev: Option<u64>,
    #[cfg(unix)]
    pub binary_ino: Option<u64>,
}

pub(crate) fn observe(program: &str, args: &[String], cwd: Option<&Path>) -> TargetObservation {
    let declared_path = Path::new(program);
    let path = if declared_path.is_relative() {
        cwd.map(|dir| dir.join(declared_path))
            .unwrap_or_else(|| declared_path.to_path_buf())
    } else {
        declared_path.to_path_buf()
    };
    let kind = crate::atoms::ask::path_kind(&path)
        .ok()
        .flatten()
        .map(|kind| format!("{kind:?}"));
    let canonical_path = if kind.is_some() {
        std::fs::canonicalize(&path).ok()
    } else {
        None
    };
    let file = canonical_path
        .as_deref()
        .and_then(|path| crate::atoms::ask::file_if_present(path).ok().flatten());
    #[cfg(unix)]
    let (binary_dev, binary_ino) = canonical_path
        .as_deref()
        .and_then(|path| std::fs::metadata(path).ok())
        .map(|metadata| {
            use std::os::unix::fs::MetadataExt;
            (Some(metadata.dev()), Some(metadata.ino()))
        })
        .unwrap_or((None, None));
    TargetObservation {
        program: program.into(),
        args: args.to_vec(),
        cwd: cwd.map(Path::to_path_buf),
        path_kind: kind,
        canonical_path,
        binary_sha256: file.map(|file| file.sha256),
        #[cfg(unix)]
        binary_dev,
        #[cfg(unix)]
        binary_ino,
    }
}
