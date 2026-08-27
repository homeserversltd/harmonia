use super::{fs_preimage, parent_identity, FsPreimage, ParentIdentity};
use std::path::{Path, PathBuf};
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IntendedSymlinkPostimage {
    pub path: PathBuf,
    pub target: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observation {
    pub link: PathBuf,
    pub preimage: FsPreimage,
    pub target: PathBuf,
    pub parent: ParentIdentity,
    pub postimage: IntendedSymlinkPostimage,
}
pub(crate) fn probe(target: &Path, link: &Path) -> Result<Observation, String> {
    let preimage = fs_preimage(link)?;
    Ok(Observation {
        link: link.into(),
        preimage: preimage.clone(),
        target: target.into(),
        parent: parent_identity(link)?,
        postimage: IntendedSymlinkPostimage {
            path: link.to_path_buf(),
            target: target.to_path_buf(),
        },
    })
}
