use super::{fs_preimage, parent_identity, FsPreimage, ParentIdentity};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observation {
    pub path: PathBuf,
    pub preimage: FsPreimage,
    pub parent: ParentIdentity,
    pub intended_bytes: Vec<u8>,
    pub intended_mode: Option<u32>,
    pub intended_uid: Option<u32>,
    pub intended_gid: Option<u32>,
    pub intended_xattrs: Vec<super::XattrObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagedFileObservation {
    pub path: PathBuf,
    pub target_exists_before: bool,
    pub missing_target_debt: bool,
    pub parent_is_dir: bool,
    pub mode: u32,
    pub content_equal: bool,
    pub mode_equal: bool,
    pub owner_equal: bool,
    pub group_equal: bool,
}
impl ManagedFileObservation {
    pub(crate) fn file_changed(&self) -> bool {
        !self.content_equal || !self.mode_equal || !self.owner_equal || !self.group_equal
    }
}

pub(crate) fn probe(
    path: &Path,
    bytes: &[u8],
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    xattrs: Vec<super::XattrObservation>,
) -> Result<Observation, String> {
    Ok(Observation {
        path: path.into(),
        preimage: fs_preimage(path)?,
        parent: parent_identity(path)?,
        intended_bytes: bytes.into(),
        intended_mode: mode,
        intended_uid: uid,
        intended_gid: gid,
        intended_xattrs: xattrs,
    })
}

pub(crate) fn managed(
    path: &Path,
    desired: &[u8],
    mode: u32,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<ManagedFileObservation, String> {
    let preimage = fs_preimage(path)?;
    let target_exists_before = preimage.present;
    let regular = matches!(preimage.kind, Some(super::FsKind::File));
    let parent_is_dir = path
        .parent()
        .map(fs_preimage)
        .transpose()?
        .is_some_and(|p| matches!(p.kind, Some(super::FsKind::Directory)));
    Ok(ManagedFileObservation {
        path: path.to_path_buf(),
        target_exists_before,
        missing_target_debt: !target_exists_before,
        parent_is_dir,
        mode,
        content_equal: regular && preimage.bytes.as_deref() == Some(desired),
        mode_equal: regular && preimage.mode == Some(mode),
        owner_equal: regular && uid.map_or(true, |v| preimage.uid == Some(v)),
        group_equal: regular && gid.map_or(true, |v| preimage.gid == Some(v)),
    })
}
