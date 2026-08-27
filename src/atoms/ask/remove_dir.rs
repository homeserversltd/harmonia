use super::{fs_preimage, parent_identity, FsPreimage, ParentIdentity};
use std::path::{Path};
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observation {
    pub root: FsPreimage,
    pub tree: Vec<FsPreimage>,
    pub parent: ParentIdentity,
    pub removal_mode: String,
    pub intended_absence: bool,
}
fn walk(p: &Path, out: &mut Vec<FsPreimage>) -> Result<(), String> {
    let x = fs_preimage(p)?;
    out.push(x.clone());
    if matches!(x.kind, Some(super::FsKind::Directory)) {
        for e in std::fs::read_dir(p).map_err(|e| e.to_string())? {
            walk(&e.map_err(|e| e.to_string())?.path(), out)?
        }
    }
    Ok(())
}
pub(crate) fn probe(path: &Path, mode: &str) -> Result<Observation, String> {
    let root = fs_preimage(path)?;
    let mut tree = Vec::new();
    if root.present {
        walk(path, &mut tree)?
    }
    Ok(Observation {
        root,
        tree,
        parent: parent_identity(path)?,
        removal_mode: mode.into(),
        intended_absence: true,
    })
}
