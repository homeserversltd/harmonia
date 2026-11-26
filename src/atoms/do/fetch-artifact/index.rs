use crate::atoms::ask::fetch_artifact::Download;
use crate::atoms::comparison::ActionAuthorization;
use crate::atoms::r#do::InvocationKey;
use crate::atoms::projectio;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// The private Release scratch seat derived from an existing source checkout.
#[derive(Debug, Clone)]
pub(crate) struct ReleaseStagingRoot {
    source: PathBuf,
    root: PathBuf,
}

impl ReleaseStagingRoot {
    pub(crate) fn from_source(source: &Path) -> Option<Self> {
        if !source.is_absolute() || source.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir)) {
            return None;
        }
        Some(Self { source: source.to_path_buf(), root: source.join("target/harmonia-release") })
    }
}

fn atomic_install(authorization: &ActionAuthorization, destination: &Path, bytes: &[u8], staging: Option<&ReleaseStagingRoot>, scratch_destination: bool) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or("fetch-artifact-destination-parent-missing")?;
    let absent = || format!("fetch-artifact-destination-parent-absent {}; birth places the parent", parent.display());
    let within_staging = staging.and_then(|root| parent.strip_prefix(&root.root).ok().map(|relative| (root, relative)));
    let is_scratch = scratch_destination || within_staging.is_some();
    if let Some((staging, relative)) = within_staging {
        // Inspect existing as well as absent components: exists() follows
        // symlinks and must not turn a Release seat into an outside write.
        if relative.components().any(|c| !matches!(c, Component::Normal(_)))
            || !fs::symlink_metadata(&staging.source).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
            || !fs::canonicalize(&staging.source).is_ok_and(|path| path == staging.source) {
            return Err(absent());
        }
        let mut path = staging.source.clone();
        for component in Path::new("target/harmonia-release").components().chain(relative.components()) {
            path.push(component.as_os_str());
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {},
                Ok(_) => return Err(format!("fetch-artifact-staging-path-invalid {}", path.display())),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    projectio::act_scratch_make_dir(authorization, &path).map_err(|e| format!("fetch-artifact-staging-create-failed {}: {e}", path.display()))?;
                }
                Err(err) => return Err(format!("fetch-artifact-staging-stat-failed {}: {err}", path.display())),
            }
        }
    } else if !parent.exists() {
        return Err(absent());
    }
    if !is_scratch {
        let metadata = match fs::symlink_metadata(destination) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(format!("fetch-artifact-destination-absent {}; birth places the destination", destination.display()));
            }
            Err(error) => return Err(format!("fetch-artifact-destination-stat-failed {}: {error}", destination.display())),
        };
        return projectio::act_strike(authorization, destination, bytes, metadata.mode() & 0o7777, metadata.uid(), metadata.gid())
            .map(|_| ())
            .map_err(|error| format!("fetch-artifact-rename-failed: {error}"));
    }
    let name = destination
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("fetch-artifact-destination-invalid")?;
    let temporary = parent.join(format!(
        ".{name}.fetch-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        projectio::act_scratch_write_new(authorization, &temporary, bytes, 0o755)
            .map_err(|e| format!("fetch-artifact-temp-write-failed: {e}"))?;
        projectio::act_rename(authorization, &temporary, destination, true, is_scratch)
            .map_err(|e| format!("fetch-artifact-rename-failed: {e}"))?;
        projectio::act_sync(authorization, parent)
            .map_err(|e| format!("fetch-artifact-parent-sync-failed: {e}"))
    })();
    if result.is_err() {
        let _ = projectio::act_scratch_remove(authorization, &temporary);
    }
    result
}

pub(crate) fn install(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    destination: &Path,
    download: &Download,
) -> Result<(), String> {
    install_release_staging(authorization, invocation, destination, download, None, false)
}

pub(crate) fn install_release_staging(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    destination: &Path,
    download: &Download,
    staging: Option<&ReleaseStagingRoot>,
    scratch_destination: bool,
) -> Result<(), String> {
    // These unforgeable capabilities are the permission boundary: only the comparison gate can supply them to this mutating atom.
    let _ = invocation;
    verify_download(download)?;
    atomic_install(authorization, destination, &download.bytes, staging, scratch_destination)
}

fn verify_download(download: &Download) -> Result<(), String> {
    if !crate::atoms::ask::fetch_artifact::validate_source_sha(&download.manifest.source_sha) {
        return Err("fetch-artifact-source-identity-invalid".into());
    }
    if crate::atoms::file_sha256(&download.bytes) != download.manifest.sha256 {
        return Err("fetch-artifact-sha256-mismatch".into());
    }
    if !crate::atoms::ask::fetch_artifact::identity_matches_bytes(
        &download.bytes, &download.manifest.source_sha, &download.identity, &download.manifest.component
    ) {
        return Err("fetch-artifact-source-identity-missing".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atoms::ask::fetch_artifact::{Manifest, MANIFEST_SCHEMA};
    fn download(bytes: Vec<u8>, digest: &str) -> Download {
        Download {
            manifest: Manifest {
                schema: MANIFEST_SCHEMA.into(),
                component: "caduceus".into(),
                source_sha: "0123456789abcdef0123456789abcdef01234567".into(),
                target: "x86_64".into(),
                sha256: digest.into(),
                built_at: "now".into(),
                pipeline_url: "https://ci".into(),
                env_sha: None,
            },
            bytes,
            identity: "liveness-marker".into(),
        }
    }
    #[test]
    fn fetch_artifact_sha256_mismatch_preserves_destination() {
        let root = std::env::temp_dir().join(format!("harmonia-fetch-sha-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let dest = root.join("caduceus");
        fs::write(&dest, b"old").unwrap();
        let d = download(
            b"0123456789abcdef0123456789abcdef01234567-new".to_vec(),
            &"0".repeat(64),
        );
        let invocation = InvocationKey::for_apply();
        let result = crate::atoms::comparison::execute_once(
            "fetch-artifact",
            || Ok::<_, String>(false),
            |_| crate::atoms::comparison::DiffDecision::Different,
            |authorization, _| install(&authorization, &invocation, &dest, &d),
        );
        assert!(matches!(
            result,
            Err(error) if error == "fetch-artifact-sha256-mismatch"
        ));
        assert_eq!(fs::read(&dest).unwrap(), b"old");
        let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn fetch_artifact_clean_install_sets_mode_and_bytes() {
        let root =
            std::env::temp_dir().join(format!("harmonia-fetch-clean-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let dest = root.join("caduceus");
        let bytes =
            b"caduceus.liveness.v10123456789abcdef0123456789abcdef01234567-suffix".to_vec();
        let d = download(bytes.clone(), &crate::atoms::file_sha256(&bytes));
        let invocation = InvocationKey::for_apply();
        let result = crate::atoms::comparison::execute_once(
            "fetch-artifact",
            || Ok::<_, String>(false),
            |_| crate::atoms::comparison::DiffDecision::Different,
            |authorization, _| install(&authorization, &invocation, &dest, &d),
        )
        .unwrap();
        assert!(matches!(
            result,
            crate::atoms::comparison::ComparisonRun::Moved { .. }
        ));
        assert_eq!(fs::read(&dest).unwrap(), bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        let _ = fs::remove_dir_all(root);
    }
}
