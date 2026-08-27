use super::{fs_preimage, parent_identity, FsPreimage, ParentIdentity};
use std::path::Path;
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IntendedFsPostimage {
    pub path: std::path::PathBuf,
    pub kind: Option<super::FsKind>,
    pub bytes: Option<Vec<u8>>,
    pub link_target: Option<std::path::PathBuf>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub xattrs: Vec<super::XattrObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observation {
    pub source: FsPreimage,
    pub destination: FsPreimage,
    pub source_parent: ParentIdentity,
    pub destination_parent: ParentIdentity,
    pub same_filesystem: bool,
    pub source_postimage: FsPreimage,
    pub destination_postimage: IntendedFsPostimage,
}
pub(crate) fn probe(source: &Path, destination: &Path) -> Result<Observation, String> {
    let s = fs_preimage(source)?;
    let d = fs_preimage(destination)?;
    let s_parent = parent_identity(source)?;
    let d_parent = parent_identity(destination)?;
    Ok(Observation {
        same_filesystem: s
            .identity
            .as_ref()
            .or(s_parent.identity.as_ref())
            .zip(d.identity.as_ref().or(d_parent.identity.as_ref()))
            .is_some_and(|(a, b)| a.device == b.device),
        source_postimage: FsPreimage {
            path: source.into(),
            present: false,
            kind: None,
            bytes: None,
            link_target: None,
            mode: None,
            uid: None,
            gid: None,
            identity: None,
            xattrs: vec![],
        },
        destination_postimage: IntendedFsPostimage {
            path: destination.to_path_buf(),
            kind: s.kind.clone(),
            bytes: s.bytes.clone(),
            link_target: s.link_target.clone(),
            mode: s.mode,
            uid: s.uid,
            gid: s.gid,
            xattrs: s.xattrs.clone(),
        },
        source: s,
        destination: d,
        source_parent: s_parent,
        destination_parent: d_parent,
    })
}
