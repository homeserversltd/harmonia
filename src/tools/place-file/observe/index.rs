use super::*;
use crate::tools::comparison::{ActionAuthorization, ComparisonRun};

pub(super) fn compare<Movement>(
    path: &Path,
    declared_bytes: &[u8],
    act: impl FnOnce(ActionAuthorization, &Observation, &Drift) -> Result<Movement, String>,
) -> Result<ComparisonRun<Observation, Movement>, String> {
    let observation = match atoms::ask::file_if_present(path)? {
        Some(file) => Observation::File(file),
        None => Observation::FileAbsent(path.to_path_buf()),
    };
    atoms::compare(
        observation,
        atoms::Declaration::FileSha256(atoms::file_sha256(declared_bytes)),
        act,
    )
}
