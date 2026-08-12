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
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(SavedFile {
            bytes: Some(fs::read(path).map_err(|e| e.to_string())?),
            mode: Some(file_mode(path)?),
        }),
        Ok(_) => Err(format!(
            "validated-file-symlink-source-not-file {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(SavedFile {
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
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Ok(SavedLink {
            exists: true,
            target: Some(fs::read_link(path).map_err(|error| {
                format!(
                    "validated-file-symlink-target-observe-failed {}: {error}",
                    path.display()
                )
            })?),
        }),
        Ok(_) => Err(format!(
            "validated-file-symlink-target-not-link {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(SavedLink {
            exists: false,
            target: None,
        }),
        Err(error) => Err(format!(
            "validated-file-symlink-target-observe-failed {}: {error}",
            path.display()
        )),
    }
}

fn restore_file(path: &Path, saved: &SavedFile) -> Result<(), String> {
    match &saved.bytes {
        Some(bytes) => atomic_write_bytes(path, bytes, saved.mode),
        None => {
            if path.exists() || path.is_symlink() {
                fs::remove_file(path).map_err(|e| {
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

fn restore_link(path: &Path, saved: &SavedLink) -> Result<(), String> {
    if path.exists() || path.is_symlink() {
        fs::remove_file(path).map_err(|e| {
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
        #[cfg(unix)]
        std::os::unix::fs::symlink(link, path).map_err(|e| {
            format!(
                "validated-file-symlink-restore-link-create-failed {}: {e}",
                path.display()
            )
        })?;
        #[cfg(not(unix))]
        return Err("validated-file-symlink-unsupported".into());
    }
    Ok(())
}

fn source_matches_saved(path: &Path, saved: &SavedFile) -> bool {
    match (fs::symlink_metadata(path), &saved.bytes) {
        (Err(error), None) if error.kind() == std::io::ErrorKind::NotFound => true,
        (Ok(metadata), Some(bytes)) if metadata.file_type().is_file() => {
            fs::read(path).ok().as_deref() == Some(bytes.as_slice())
                && file_mode(path).ok() == saved.mode
        }
        _ => false,
    }
}

fn link_matches_saved(path: &Path, saved: &SavedLink) -> bool {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            saved.exists && fs::read_link(path).ok() == saved.target
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => !saved.exists,
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
