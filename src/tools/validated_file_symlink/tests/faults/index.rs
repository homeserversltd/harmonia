//! Fault-seam and refusal regressions.

use super::*;

#[test]
fn every_staging_and_promotion_failure_cleans_candidates_and_restores_exact_state() {
    for fault in [
        FileSymlinkFault::StageSource,
        FileSymlinkFault::StageLink,
        FileSymlinkFault::BeforeSourcePromotion,
        FileSymlinkFault::AfterSourcePromotion,
        FileSymlinkFault::BeforeLinkRestage,
        FileSymlinkFault::BeforeLinkPromotion,
        FileSymlinkFault::AfterLinkPromotion,
    ] {
        let (root, desired, source, target, receipts) = fixture("fault-boundary");
        let old_link = fs::read_link(&target).unwrap();
        set_file_symlink_fault(Some(fault));
        let outcome = run(&root, &desired, &source, &target, &receipts, None);
        assert!(!outcome.ok, "fault={fault:?}");
        assert!(!outcome.changed, "fault={fault:?}");
        assert_initial_state(&source, &target, &old_link);
        assert_candidates_clean(&root);
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn malformed_candidate_and_occupied_or_dry_target_preserve_live_state() {
    let (root, desired, source, target, receipts) = fixture("refusal");
    let old_link = fs::read_link(&target).unwrap();
    let malformed = validated_file_symlink(
        &receipts,
        "malformed",
        &desired,
        &source,
        &target,
        "/bin/false",
        &[],
        None,
        &[],
        5,
        true,
    )
    .unwrap();
    assert!(!malformed.ok && !malformed.changed);
    assert_initial_state(&source, &target, &old_link);
    assert_candidates_clean(&root);
    let dry = validated_file_symlink(
        &receipts,
        "dry",
        &desired,
        &source,
        &target,
        "/bin/true",
        &[],
        None,
        &[],
        5,
        false,
    )
    .unwrap();
    assert!(dry.ok && !dry.changed && dry.skipped);
    assert_initial_state(&source, &target, &old_link);
    fs::remove_file(&target).unwrap();
    fs::write(&target, b"occupied").unwrap();
    let occupied = validated_file_symlink(
        &receipts,
        "occupied",
        &desired,
        &source,
        &target,
        "/bin/true",
        &[],
        None,
        &[],
        5,
        true,
    )
    .unwrap();
    assert!(!occupied.ok && !occupied.changed);
    assert_eq!(fs::read(&target).unwrap(), b"occupied");
    assert_eq!(fs::read(&source).unwrap(), b"old bytes\n");
    fs::remove_dir_all(root).unwrap();
}
