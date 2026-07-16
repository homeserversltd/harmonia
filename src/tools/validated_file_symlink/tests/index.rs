//! Crate-private regression surface for the transaction band.

use super::*;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::time::{SystemTime, UNIX_EPOCH};

fn validated_file_symlink(
    receipt_dir: &Path,
    name: &str,
    desired_source: &Path,
    source: &Path,
    target: &Path,
    validator_program: &str,
    validator_args: &[String],
    reload_program: Option<&str>,
    reload_args: &[String],
    timeout_secs: u64,
    apply: bool,
) -> Result<OperationOutcome, String> {
    execute(ValidatedFileSymlinkRequest {
        receipt_dir,
        name,
        desired_source,
        source,
        target,
        validator_program,
        validator_args,
        reload_program,
        reload_args,
        timeout_secs,
        apply,
    })
}

fn fixture(name: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("harmonia-vfs-{name}-{}-{id}", std::process::id()));
    let desired = root.join("desired.conf");
    let source = root.join("sites-available/site.conf");
    let target = root.join("sites-enabled/site.conf");
    let old = root.join("old.conf");
    let receipts = root.join("receipts");
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&desired, b"new bytes\n").unwrap();
    fs::write(&source, b"old bytes\n").unwrap();
    #[cfg(unix)]
    fs::set_permissions(&desired, fs::Permissions::from_mode(0o640)).unwrap();
    fs::write(&old, b"old target\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&old, &target).unwrap();
    (root, desired, source, target, receipts)
}

fn run(
    _root: &Path,
    desired: &Path,
    source: &Path,
    target: &Path,
    receipts: &Path,
    reload: Option<&str>,
) -> crate::OperationOutcome {
    validated_file_symlink(
        receipts,
        "step",
        desired,
        source,
        target,
        "/bin/true",
        &[],
        reload,
        &[],
        5,
        true,
    )
    .unwrap()
}

fn assert_candidates_clean(root: &Path) {
    for dir in [root.join("sites-available"), root.join("sites-enabled")] {
        let candidates: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains("harmonia-"))
            .collect();
        assert!(candidates.is_empty(), "left candidates: {candidates:?}");
    }
}

fn assert_initial_state(source: &Path, target: &Path, old_link: &Path) {
    assert_eq!(fs::read(source).unwrap(), b"old bytes\n");
    assert_eq!(fs::read_link(target).unwrap(), old_link);
}

#[path = "behavior/index.rs"]
mod behavior;
#[path = "faults/index.rs"]
mod faults;
#[path = "structure/index.rs"]
mod structure;
#[path = "transaction/index.rs"]
mod transaction;
