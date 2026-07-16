//! Candidate visibility and steady-state behavior regressions.

use super::*;

#[test]
fn source_and_link_drift_combinations_promote_only_the_drifted_surface() {
    let (root, desired, source, target, receipts) = fixture("drift-link");
    fs::write(&source, b"new bytes\n").unwrap();
    let link_only = run(&root, &desired, &source, &target, &receipts, None);
    assert!(link_only.ok && link_only.changed);
    assert_eq!(fs::read_link(&target).unwrap(), source);
    let old = root.join("old-two.conf");
    fs::write(&old, b"old two\n").unwrap();
    fs::write(&source, b"old bytes\n").unwrap();
    fs::remove_file(&target).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&source, &target).unwrap();
    #[cfg(unix)]
    let target_inode_before = fs::symlink_metadata(&target).unwrap().ino();
    let source_only = run(&root, &desired, &source, &target, &receipts, None);
    assert!(source_only.ok && source_only.changed);
    assert_eq!(fs::read(&source).unwrap(), b"new bytes\n");
    assert_eq!(fs::read_link(&target).unwrap(), source);
    #[cfg(unix)]
    assert_eq!(
        fs::symlink_metadata(&target).unwrap().ino(),
        target_inode_before
    );
    assert_candidates_clean(&root);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn validator_receives_exact_args_and_observes_one_nonhidden_candidate() {
    let (root, desired, source, target, receipts) = fixture("validator-candidate");
    let seen = root.join("validator-seen.txt");
    let enabled = target.parent().unwrap();
    let script = format!(
            "candidate=$(find {} -maxdepth 1 -name 'site.conf.harmonia-link-candidate-*'); test \"$1\" = exact-arg && test \"$(printf '%s\\n' \"$candidate\" | wc -l)\" -eq 1 && test -L \"$candidate\" && (case \"$(readlink \"$candidate\")\" in {}/.site.conf.harmonia-source-candidate-*) ;; *) exit 1;; esac) && cmp -s \"$candidate\" \"{}\" && test \"$(stat -Lc %a \"$candidate\")\" = \"$(stat -c %a \"{}\")\" && test \"$(find {} -maxdepth 1 -name '.site.conf.harmonia-link-candidate-*' | wc -l)\" -eq 0 && printf '%s' \"$1\" > {}",
            enabled.display(),
            source.parent().unwrap().display(),
            desired.display(),
            desired.display(),
            enabled.display(),
            seen.display()
        );
    let outcome = validated_file_symlink(
        &receipts,
        "validator",
        &desired,
        &source,
        &target,
        "/bin/sh",
        &["-c".into(), script, "sh".into(), "exact-arg".into()],
        None,
        &[],
        5,
        true,
    )
    .unwrap();
    assert!(outcome.ok && outcome.changed);
    assert_eq!(fs::read_to_string(seen).unwrap(), "exact-arg");
    assert_candidates_clean(&root);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn first_change_reconciles_once_then_exact_second_run_is_a_noop() {
    let (root, desired, source, target, receipts) = fixture("reload-once");
    let reload_count = root.join("reload-count");
    let reload_script = format!("printf x >> {}", reload_count.display());
    let first = validated_file_symlink(
        &receipts,
        "reload",
        &desired,
        &source,
        &target,
        "/bin/true",
        &[],
        Some("/bin/sh"),
        &["-c".into(), reload_script.clone(), "sh".into()],
        5,
        true,
    )
    .unwrap();
    let second = validated_file_symlink(
        &receipts,
        "reload",
        &desired,
        &source,
        &target,
        "/bin/true",
        &[],
        Some("/bin/sh"),
        &["-c".into(), reload_script, "sh".into()],
        5,
        true,
    )
    .unwrap();
    assert!(first.ok && first.changed);
    assert!(second.ok && !second.changed);
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(receipts.join("reload.json")).unwrap()).unwrap();
    assert_eq!(receipt["changed"], false);
    assert_eq!(receipt["validation"]["ran"], false);
    assert!(receipt["reconcile"].is_null());
    assert_eq!(fs::read_to_string(reload_count).unwrap(), "x");
    fs::remove_dir_all(root).unwrap();
}
