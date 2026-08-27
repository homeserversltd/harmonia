use super::{fs_preimage, parent_identity, FsPreimage, ParentIdentity};
use std::path::{Path, PathBuf};
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observation {
    pub path: PathBuf,
    pub components: Vec<FsPreimage>,
    pub parent: ParentIdentity,
    pub created: Vec<PathBuf>,
    pub intended_mode: Option<u32>,
    pub intended_uid: Option<u32>,
    pub intended_gid: Option<u32>,
}
pub(crate) fn probe(
    path: &Path,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<Observation, String> {
    let mut cur = PathBuf::new();
    let mut components = Vec::new();
    for c in path.components() {
        cur.push(c);
        components.push(fs_preimage(&cur)?);
    }
    let created = components
        .iter()
        .filter(|x| !x.present)
        .map(|x| x.path.clone())
        .collect();
    Ok(Observation {
        path: path.into(),
        components,
        parent: parent_identity(path)?,
        created,
        intended_mode: mode,
        intended_uid: uid,
        intended_gid: gid,
    })
}
