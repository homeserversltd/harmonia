use harmonia::filesystem::{apply_transaction, converge, FilesystemOperation, RootPrefix};
use std::{fs, os::unix::process::CommandExt, path::PathBuf, process::Command};
use tempfile::tempdir;

fn twice(
    root: &RootPrefix,
    op: FilesystemOperation,
) -> (
    harmonia::filesystem::FilesystemReceipt,
    harmonia::filesystem::FilesystemReceipt,
) {
    let first = converge(root, &op).expect("first converge");
    assert!(first.ok);
    let second = converge(root, &op).expect("second converge");
    assert!(second.ok);
    assert!(
        !second.changed,
        "second pass must be quiet: {}",
        second.json()
    );
    assert_eq!(second.write_operations, 0);
    (first, second)
}

fn pair(root: &RootPrefix, op: FilesystemOperation) -> serde_json::Value {
    let (first, second) = twice(root, op);
    serde_json::json!({"first": first, "second": second})
}

fn redact(value: &mut serde_json::Value, root: &str) {
    match value {
        serde_json::Value::String(text) => {
            *text = text.replace(root, "<ROOT>").replace("/tmp/", "<TEMP>/");
            if let Some(start) = text.rfind(" (os error ") {
                let suffix = &text[start + " (os error ".len()..];
                if suffix.ends_with(')')
                    && suffix[..suffix.len() - 1]
                        .chars()
                        .all(|character| character.is_ascii_digit())
                {
                    text.truncate(start);
                }
            }
            if let Some(start) = text.find(".harmonia-") {
                if let Some(end) = text[start..].find(" ->") {
                    let end = start + end;
                    text.replace_range(start..end, ".harmonia-<DYNAMIC>");
                }
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(|item| redact(item, root)),
        serde_json::Value::Object(map) => map.values_mut().for_each(|item| redact(item, root)),
        _ => {}
    }
}

#[test]
fn all_filesystem_atoms_converge_under_fake_root() {
    let directory = tempdir().unwrap();
    let root = RootPrefix::new(directory.path()).unwrap();
    let mut receipts: Vec<serde_json::Value> = Vec::new();
    receipts.push(pair(
        &root,
        FilesystemOperation::MakeDir {
            path: "/etc/app".into(),
        },
    ));
    receipts.push(pair(
        &root,
        FilesystemOperation::WriteFile {
            path: "/etc/app/config".into(),
            bytes: b"hello".to_vec(),
            mode: Some(0o640),
        },
    ));
    receipts.push(pair(
        &root,
        FilesystemOperation::MakeLink {
            target: "/etc/app/config".into(),
            link: "/etc/app/current".into(),
        },
    ));
    receipts.push(pair(
        &root,
        FilesystemOperation::CopyFile {
            source: "/etc/app/config".into(),
            target: "/etc/app/copy".into(),
        },
    ));
    receipts.push(pair(
        &root,
        FilesystemOperation::ChangeMode {
            path: "/etc/app/copy".into(),
            mode: 0o600,
        },
    ));
    receipts.push(pair(
        &root,
        FilesystemOperation::RemoveFile {
            path: "/etc/app/copy".into(),
        },
    ));
    assert_eq!(
        fs::read(directory.path().join("etc/app/config")).unwrap(),
        b"hello"
    );
    assert_eq!(
        fs::read_link(directory.path().join("etc/app/current")).unwrap(),
        PathBuf::from(directory.path().join("etc/app/config"))
    );
    assert!(!directory.path().join("etc/app/copy").exists());
    let mut snapshot = serde_json::to_value(receipts).unwrap();
    redact(&mut snapshot, &directory.path().display().to_string());
    insta::assert_json_snapshot!("all_atom_first_receipts", snapshot);
}

#[test]
fn pull_repo_uses_local_bare_fixture_and_is_idempotent() {
    const RELAUNCHED_MARKER: &str = "HARMONIA_PULL_REPO_TEST_RELAUNCHED";
    if unsafe { libc::geteuid() } == 0 && std::env::var_os(RELAUNCHED_MARKER).is_none() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg("pull_repo_uses_local_bare_fixture_and_is_idempotent")
            .arg("--nocapture")
            .env(RELAUNCHED_MARKER, "1");
        unsafe {
            command.pre_exec(|| {
                if libc::setgroups(0, std::ptr::null()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setgid(65534) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setuid(65534) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        assert!(command.status().unwrap().success());
        return;
    }

    let directory = tempdir().unwrap();
    let bare = directory.path().join("origin.git");
    let source = directory.path().join("src");
    for args in [
        vec!["init", "--bare", "-q", bare.to_str().unwrap()],
        vec!["init", "-q"],
    ] {
        let mut command = Command::new("git");
        if args[0] == "init" && args.len() == 2 {
            command.current_dir(&source);
            fs::create_dir(&source).unwrap();
        }
        assert!(command.args(args).status().unwrap().success());
    }
    fs::write(source.join("README"), "local").unwrap();
    for args in [
        vec!["add", "README"],
        vec![
            "-c",
            "user.email=a@b",
            "-c",
            "user.name=a",
            "commit",
            "-qm",
            "init",
        ],
        vec!["push", "-q", bare.to_str().unwrap(), "HEAD:main"],
    ] {
        assert!(Command::new("git")
            .current_dir(&source)
            .args(args)
            .status()
            .unwrap()
            .success());
    }
    let root = RootPrefix::new(directory.path()).unwrap();
    let (first, second) = twice(
        &root,
        FilesystemOperation::PullRepo {
            repo: "/origin.git".into(),
            path: "/checkout".into(),
            branch: "main".into(),
        },
    );
    assert!(first.changed);
    assert_eq!(first.write_operations, 1);
    assert!(!second.changed);
    assert_eq!(
        fs::read(directory.path().join("checkout/README")).unwrap(),
        b"local"
    );
    let mut snapshot = serde_json::json!({"first": first, "second": second});
    redact(&mut snapshot, &directory.path().display().to_string());
    insta::assert_json_snapshot!("pull_repo_first_second_receipts", snapshot);
}

#[test]
fn transaction_rolls_back_every_member_after_later_failure() {
    let directory = tempdir().unwrap();
    let first = directory.path().join("one");
    let second = directory.path().join("two");
    fs::write(&first, b"before-one").unwrap();
    fs::create_dir(&second).unwrap();
    let receipt = apply_transaction(vec![
        (first.clone(), "one".into(), b"after-one".to_vec()),
        (second.clone(), "two".into(), b"after-two".to_vec()),
    ]);
    assert_eq!(receipt["state"], "failed");
    assert_eq!(receipt["rolled_back"], true);
    assert_eq!(fs::read(&first).unwrap(), b"before-one");
    assert!(fs::read_dir(&second).unwrap().next().is_none());
    let mut snapshot = receipt;
    redact(&mut snapshot, &directory.path().display().to_string());
    insta::assert_json_snapshot!("transaction_rollback_receipt", snapshot);
}
