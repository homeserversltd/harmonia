use crate::atoms::ask::fetch_artifact::Download;
use crate::atoms::comparison::ActionAuthorization;
use crate::atoms::r#do::InvocationKey;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn atomic_install(destination: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or("fetch-artifact-destination-parent-missing")?;
    fs::create_dir_all(parent).map_err(|e| format!("fetch-artifact-parent-create-failed: {e}"))?;
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
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|e| format!("fetch-artifact-temp-create-failed: {e}"))?;
        file.write_all(bytes)
            .map_err(|e| format!("fetch-artifact-temp-write-failed: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("fetch-artifact-chmod-failed: {e}"))?;
        }
        file.sync_all()
            .map_err(|e| format!("fetch-artifact-temp-sync-failed: {e}"))?;
        fs::rename(&temporary, destination)
            .map_err(|e| format!("fetch-artifact-rename-failed: {e}"))?;
        OpenOptions::new()
            .read(true)
            .open(parent)
            .map_err(|e| format!("fetch-artifact-parent-open-failed: {e}"))?
            .sync_all()
            .map_err(|e| format!("fetch-artifact-parent-sync-failed: {e}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn install(
    authorization: &ActionAuthorization,
    invocation: &InvocationKey,
    destination: &Path,
    download: &Download,
) -> Result<(), String> {
    // These unforgeable capabilities are the permission boundary: only the comparison gate can supply them to this mutating atom.
    let _ = (authorization, invocation);
    verify_download(download)?;
    atomic_install(destination, &download.bytes)
}

fn verify_download(download: &Download) -> Result<(), String> {
    if !crate::atoms::ask::fetch_artifact::validate_source_sha(&download.manifest.source_sha) {
        return Err("fetch-artifact-source-identity-invalid".into());
    }
    if crate::atoms::file_sha256(&download.bytes) != download.manifest.sha256 {
        return Err("fetch-artifact-sha256-mismatch".into());
    }
    if !download
        .bytes
        .windows(download.manifest.source_sha.len())
        .any(|w| w == download.manifest.source_sha.as_bytes())
    {
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
            },
            bytes,
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
        let bytes = b"prefix-0123456789abcdef0123456789abcdef01234567-suffix".to_vec();
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
