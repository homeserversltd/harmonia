use super::{fs_preimage, parent_identity, FsPreimage, ParentIdentity};
use std::path::Path;
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IntendedFilePostimage {
    pub path: std::path::PathBuf,
    pub bytes: Option<Vec<u8>>,
    pub sha256: Option<String>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub xattrs: Vec<super::XattrObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observation {
    pub source: FsPreimage,
    pub source_hash: Option<String>,
    pub destination_preimage: FsPreimage,
    pub destination_postimage: IntendedFilePostimage,
    pub source_parent: ParentIdentity,
    pub destination_parent: ParentIdentity,
}
pub(crate) fn probe(source: &Path, destination: &Path) -> Result<Observation, String> {
    let s = fs_preimage(source)?;
    let source_hash = s.bytes.as_deref().map(crate::atoms::file_sha256);
    let d = fs_preimage(destination)?;
    let destination_postimage = IntendedFilePostimage {
        path: destination.to_path_buf(),
        bytes: s.bytes.clone(),
        sha256: source_hash.clone(),
        mode: s.mode,
        uid: s.uid,
        gid: s.gid,
        xattrs: s.xattrs.clone(),
    };
    Ok(Observation {
        source_hash: source_hash.clone(),
        source: s,
        destination_preimage: d.clone(),
        destination_postimage,
        source_parent: parent_identity(source)?,
        destination_parent: parent_identity(destination)?,
    })
}
