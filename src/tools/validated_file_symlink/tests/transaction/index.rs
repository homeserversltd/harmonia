//! Promotion and rollback regressions.

use super::*;

#[test]
fn promotion_preserves_desired_bytes_and_link_target() {
    let (root, desired, source, target, receipts) = fixture("promotion");
    let outcome = run(&root, &desired, &source, &target, &receipts, None);
    assert!(outcome.ok);
    assert_eq!(fs::read(&source).unwrap(), b"new bytes\n");
    assert_eq!(fs::read_link(&target).unwrap(), source);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn reconcile_failure_rolls_back_only_promoted_mutations_in_reverse_order() {
    let (root, desired, source, target, receipts) = fixture("reconcile");
    let old_link = fs::read_link(&target).unwrap();
    let outcome = run(
        &root,
        &desired,
        &source,
        &target,
        &receipts,
        Some("/bin/false"),
    );
    assert!(!outcome.ok && !outcome.changed);
    assert_eq!(fs::read(&source).unwrap(), b"old bytes\n");
    assert_eq!(fs::read_link(&target).unwrap(), old_link);
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(receipts.join("step.json")).unwrap()).unwrap();
    assert_eq!(receipt["changed"], false);
    assert_eq!(receipt["restoration"]["ok"], true);
    assert_eq!(receipt["promotion"]["source"], true);
    assert_eq!(receipt["promotion"]["link"], true);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn promotion_boundary_does_not_restore_untouched_live_link() {
    let (root, desired, source, target, receipts) = fixture("promotion-boundary");
    let old_link = fs::read_link(&target).unwrap();
    set_file_symlink_fault(Some(FileSymlinkFault::AfterSourcePromotion));
    let outcome = run(&root, &desired, &source, &target, &receipts, None);
    assert!(!outcome.ok);
    assert_eq!(fs::read(&source).unwrap(), b"old bytes\n");
    assert_eq!(fs::read_link(&target).unwrap(), old_link);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn restoration_boundary_reports_failed_restore_without_touching_unmutated_source() {
    let (root, desired, source, target, receipts) = fixture("restoration-boundary");
    set_file_symlink_fault(Some(FileSymlinkFault::DuringLinkRestoration));
    let outcome = run(
        &root,
        &desired,
        &source,
        &target,
        &receipts,
        Some("/bin/false"),
    );
    assert!(!outcome.ok);
    assert!(outcome.changed);
    assert_eq!(fs::read(&source).unwrap(), b"old bytes\n");
    assert_eq!(fs::read_link(&target).unwrap(), source);
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(receipts.join("step.json")).unwrap()).unwrap();
    assert_eq!(receipt["changed"], true);
    assert_eq!(receipt["promotion"]["source"], true);
    assert_eq!(receipt["promotion"]["link"], true);
    assert_eq!(receipt["restoration"]["ok"], false);
    assert!(receipt["first_missing_signal"]
        .as_str()
        .unwrap()
        .contains("DuringLinkRestoration"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn source_restoration_failure_reports_residual_changed_in_outcome_and_receipt() {
    let (root, desired, source, target, receipts) = fixture("source-restoration-boundary");
    set_file_symlink_faults(&[
        FileSymlinkFault::BeforeLinkRestage,
        FileSymlinkFault::DuringSourceRestoration,
    ]);
    let outcome = run(&root, &desired, &source, &target, &receipts, None);
    assert!(!outcome.ok && outcome.changed);
    assert_eq!(fs::read(&source).unwrap(), b"new bytes\n");
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(receipts.join("step.json")).unwrap()).unwrap();
    assert_eq!(receipt["changed"], true);
    assert_eq!(receipt["restoration"]["ok"], false);
    assert_eq!(receipt["promotion"]["source"], true);
    assert_eq!(receipt["promotion"]["link"], false);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn source_saved_state_comparison_rejects_symlinks_and_accepts_exact_states() {
    let (root, _desired, source, _target, _receipts) = fixture("source-saved-state");
    let saved_regular = save_file(&source).unwrap();
    assert!(source_matches_saved(&source, &saved_regular));
    let same_bytes = root.join("same-bytes.conf");
    fs::write(&same_bytes, b"old bytes\n").unwrap();
    fs::remove_file(&source).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&same_bytes, &source).unwrap();
    assert!(!source_matches_saved(&source, &saved_regular));

    let absent = root.join("absent.conf");
    let saved_absent = save_file(&absent).unwrap();
    assert!(source_matches_saved(&absent, &saved_absent));
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("missing-target.conf"), &absent).unwrap();
    assert!(!source_matches_saved(&absent, &saved_absent));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn residual_source_symlink_after_failed_rollback_is_changed_in_terminal_receipt() {
    let (root, desired, source, target, receipts) = fixture("residual-source-symlink");
    set_file_symlink_faults(&[
        FileSymlinkFault::BeforeLinkRestage,
        FileSymlinkFault::ReplaceSourceWithDanglingSymlinkDuringRestoration,
    ]);
    let outcome = run(&root, &desired, &source, &target, &receipts, None);
    assert!(!outcome.ok && outcome.changed);
    assert!(fs::symlink_metadata(&source)
        .unwrap()
        .file_type()
        .is_symlink());
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(receipts.join("step.json")).unwrap()).unwrap();
    assert_eq!(receipt["changed"], true);
    assert_eq!(receipt["restoration"]["ok"], false);
    assert_eq!(receipt["promotion"]["source"], true);
    assert_eq!(receipt["promotion"]["link"], false);
    fs::remove_dir_all(root).unwrap();
}
