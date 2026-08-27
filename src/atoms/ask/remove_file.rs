use super::{fs_preimage, parent_identity, FsPreimage, ParentIdentity};
use std::path::{Path, PathBuf};
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observation {
    pub path: PathBuf,
    pub preimage: FsPreimage,
    pub parent: ParentIdentity,
    pub inode_identity: Option<super::FsIdentity>,
    pub intended_absence: bool,
}
pub(crate) fn probe(path: &Path) -> Result<Observation, String> {
    let preimage = fs_preimage(path)?;
    Ok(Observation {
        path: path.into(),
        inode_identity: preimage.identity.clone(),
        preimage,
        parent: parent_identity(path)?,
        intended_absence: true,
    })
}
