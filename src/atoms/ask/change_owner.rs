use super::{fs_preimage, FsPreimage};
use std::path::{Path, PathBuf};
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observation {
    pub path: PathBuf,
    pub preimage: FsPreimage,
    pub prior_uid: Option<u32>,
    pub prior_gid: Option<u32>,
    pub link_identity: Option<super::FsIdentity>,
    pub intended_uid: Option<u32>,
    pub intended_gid: Option<u32>,
    pub no_follow: bool,
}
pub(crate) fn probe(
    path: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<Observation, String> {
    let preimage = fs_preimage(path)?;
    Ok(Observation {
        prior_uid: preimage.uid,
        prior_gid: preimage.gid,
        link_identity: preimage.identity.clone(),
        preimage,
        path: path.into(),
        intended_uid: uid,
        intended_gid: gid,
        no_follow: true,
    })
}
