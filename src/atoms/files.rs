#[path = "managed-files-lane.rs"]
mod managed_files_lane;
#[path = "source-shelf-lane.rs"]
mod source_shelf_lane;
#[path = "symlink-lane.rs"]
mod symlink_lane;
pub(crate) use managed_files_lane::*;
pub(crate) use symlink_lane::*;

pub(crate) fn ensure_resolved_containment(
    root: &std::path::Path,
    candidate: &std::path::Path,
) -> Result<(), String> {
    use std::path::{Component, PathBuf};
    use std::{fs, io::ErrorKind};

    fn lexical(
        path: &std::path::Path,
        declared_root: &std::path::Path,
        declared_candidate: &std::path::Path,
    ) -> Result<PathBuf, String> {
        let escape = || {
            format!(
                "managed-target-root-escape declared-root={} candidate={}",
                declared_root.display(),
                declared_candidate.display()
            )
        };
        if !path.is_absolute() {
            return Err(escape());
        }
        if path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err("managed-target-root-parent-component-rejected".into());
        }
        let mut out = PathBuf::from("/");
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(part) => out.push(part),
                Component::ParentDir => unreachable!("parent components rejected above"),
                Component::Prefix(_) => return Err(escape()),
            }
        }
        Ok(out)
    }

    let declared_root = root;
    let declared_candidate = candidate;
    let root = lexical(declared_root, declared_root, declared_candidate)?;
    let candidate = lexical(declared_candidate, declared_root, declared_candidate)?;
    if !candidate.starts_with(&root) {
        return Err(format!(
            "managed-target-root-escape declared-root={} candidate={}",
            declared_root.display(),
            candidate.display()
        ));
    }
    // Every absolute path is contained by '/', regardless of distribution
    // symlinks such as usrmerge's /usr/sbin -> bin.
    if root == PathBuf::from("/") {
        return Ok(());
    }
    let resolved_root = root
        .canonicalize()
        .map_err(|error| format!("managed-target-root-resolution-failed:{error}"))?;
    let mut existing = candidate.clone();
    let mut missing = Vec::new();
    let resolved = loop {
        match existing.canonicalize() {
            Ok(path) => {
                let mut path = path;
                for component in missing.iter().rev() {
                    path.push(component);
                }
                break path;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                match fs::symlink_metadata(&existing) {
                    Ok(_) => {
                        return Err(format!(
                            "managed-target-resolution-failed {}: {error}",
                            existing.display()
                        ));
                    }
                    Err(metadata_error) if metadata_error.kind() == ErrorKind::NotFound => {}
                    Err(metadata_error) => {
                        return Err(format!(
                            "managed-target-metadata-failed {}: {metadata_error}",
                            existing.display()
                        ));
                    }
                }
                let name = existing
                    .file_name()
                    .ok_or_else(|| {
                        format!(
                            "managed-target-resolution-failed {}: {error}",
                            existing.display()
                        )
                    })?
                    .to_os_string();
                missing.push(name);
                existing.pop();
            }
            Err(error) => {
                return Err(format!(
                    "managed-target-resolution-failed {}: {error}",
                    existing.display()
                ))
            }
        }
    };
    if !resolved.starts_with(&resolved_root) {
        return Err(format!(
            "managed-target-root-escape declared-root={} resolved-candidate={}",
            declared_root.display(),
            resolved.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod containment_tests {
    use super::ensure_resolved_containment;
    use std::os::unix::fs::symlink;

    #[test]
    fn resolves_fake_root_symlinks_and_missing_suffixes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::create_dir_all(root.join("bin")).unwrap();
        symlink("bin", root.join("usr/sbin")).unwrap();
        symlink("inside", root.join("alias")).unwrap();
        std::fs::create_dir_all(root.join("inside")).unwrap();
        assert!(ensure_resolved_containment(&root, &root.join("usr/sbin/probe")).is_ok());
        assert!(ensure_resolved_containment(&root, &root.join("etc/new/deeper/file")).is_ok());
        assert_eq!(
            ensure_resolved_containment(&root, &root.join("alias/../etc/file")).unwrap_err(),
            "managed-target-root-parent-component-rejected"
        );
        assert!(ensure_resolved_containment(&root, &root.join("../outside")).is_err());
        assert!(ensure_resolved_containment(std::path::Path::new("/"), &root).is_ok());
    }

    #[test]
    fn refuses_fake_root_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, root.join("escape")).unwrap();
        assert!(ensure_resolved_containment(&root, &root.join("escape/file")).is_err());
    }
}
