#[derive(Clone)]
struct SavedFile {
    bytes: Option<Vec<u8>>,
    mode: Option<u32>,
}

#[derive(Clone)]
struct SavedLink {
    exists: bool,
    target: Option<PathBuf>,
}

fn save_file(path: &Path) -> Result<SavedFile, String> {
    match atoms::ask::path_kind(path) {
        Ok(Some(atoms::ask::PathKind::RegularFile)) => Ok(SavedFile {
            bytes: Some(atoms::ask::file(path).map_err(|e| e.to_string())?.bytes),
            mode: Some(atoms::ask::file_mode(path)?),
        }),
        Ok(Some(_)) => Err(format!(
            "validated-file-symlink-source-not-file {}",
            path.display()
        )),
        Ok(None) => Ok(SavedFile {
            bytes: None,
            mode: None,
        }),
        Err(error) => Err(format!(
            "validated-file-symlink-source-observe-failed {}: {error}",
            path.display()
        )),
    }
}

fn save_link(path: &Path) -> Result<SavedLink, String> {
    match atoms::ask::path_kind(path) {
        Ok(Some(atoms::ask::PathKind::Symlink)) => Ok(SavedLink {
            exists: true,
            target: Some(atoms::ask::link_target(path).map_err(|error| {
                format!(
                    "validated-file-symlink-target-observe-failed {}: {error}",
                    path.display()
                )
            })?),
        }),
        Ok(Some(_)) => Err(format!(
            "validated-file-symlink-target-not-link {}",
            path.display()
        )),
        Ok(None) => Ok(SavedLink {
            exists: false,
            target: None,
        }),
        Err(error) => Err(format!(
            "validated-file-symlink-target-observe-failed {}: {error}",
            path.display()
        )),
    }
}

fn restore_file(
    authorization: crate::tools::comparison::ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    path: &Path,
    saved: &SavedFile,
) -> Result<(), String> {
    match &saved.bytes {
        Some(bytes) => atoms::r#do::file_write(
            authorization,
            invocation,
            path,
            bytes,
            atoms::r#do::FileWriteOptions {
                write_bytes: true,
                mode: saved.mode,
                uid: None,
                gid: None,
                backup_to: None,
            },
        )
        .map(|_| ()),
        None => {
            if atoms::ask::path_kind(path)?.is_some() {
                atoms::r#do::remove_file(authorization, invocation, path).map_err(|e| {
                    format!(
                        "validated-file-symlink-restore-source-remove-failed {}: {e}",
                        path.display()
                    )
                })?;
            }
            Ok(())
        }
    }
}

fn restore_link(
    authorization: crate::tools::comparison::ActionAuthorization,
    invocation: atoms::r#do::InvocationKey,
    path: &Path,
    saved: &SavedLink,
) -> Result<(), String> {
    if atoms::ask::path_kind(path)?.is_some() {
        atoms::r#do::remove_file(authorization, invocation, path).map_err(|e| {
            format!(
                "validated-file-symlink-restore-link-remove-failed {}: {e}",
                path.display()
            )
        })?;
    }
    if saved.exists {
        let link = saved
            .target
            .as_ref()
            .ok_or_else(|| "validated-file-symlink-restore-link-unobserved".to_string())?;
        atoms::r#do::symlink(authorization, invocation, link, path).map_err(|e| {
            format!(
                "validated-file-symlink-restore-link-create-failed {}: {e}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn source_matches_saved(path: &Path, saved: &SavedFile) -> bool {
    match (atoms::ask::path_kind(path), &saved.bytes) {
        (Ok(None), None) => true,
        (Ok(Some(atoms::ask::PathKind::RegularFile)), Some(bytes)) => {
            atoms::ask::file(path)
                .ok()
                .map(|file| file.bytes)
                .as_deref()
                == Some(bytes.as_slice())
                && atoms::ask::file_mode(path).ok() == saved.mode
        }
        _ => false,
    }
}

fn link_matches_saved(path: &Path, saved: &SavedLink) -> bool {
    match atoms::ask::path_kind(path) {
        Ok(Some(atoms::ask::PathKind::Symlink)) => {
            saved.exists && atoms::ask::link_target(path).ok() == saved.target
        }
        Ok(None) => !saved.exists,
        _ => false,
    }
}

fn residual_changed(
    source: &Path,
    source_before: &SavedFile,
    target: &Path,
    link_before: &SavedLink,
) -> bool {
    !source_matches_saved(source, source_before) || !link_matches_saved(target, link_before)
}
