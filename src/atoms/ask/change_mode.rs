use super::{fs_preimage, FsPreimage};
use std::path::{Path, PathBuf};
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observation {
    pub path: PathBuf,
    pub preimage: FsPreimage,
    pub path_inode: Option<super::FsIdentity>,
    pub prior_mode: Option<u32>,
    pub intended_mode: u32,
}
pub(crate) fn probe(path: &Path, mode: u32) -> Result<Observation, String> {
    let preimage = fs_preimage(path)?;
    Ok(Observation {
        path: path.into(),
        prior_mode: preimage.mode,
        path_inode: preimage.identity.clone(),
        preimage,
        intended_mode: mode,
    })
}
