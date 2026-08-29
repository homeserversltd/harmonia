//! Production filesystem convergence facade: rooted paths, real atoms, receipts.
use crate::atoms::{self, comparison::DiffDecision, git_artifact};
use serde::Serialize;
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootPrefix(PathBuf);
impl Default for RootPrefix {
    fn default() -> Self {
        Self(PathBuf::from("/"))
    }
}
impl RootPrefix {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, String> {
        let r = root.into();
        if !r.is_absolute() {
            return Err("root-prefix-must-be-absolute".into());
        }
        Ok(Self(r))
    }
    pub fn resolve(&self, p: &Path) -> Result<PathBuf, String> {
        if !p.is_absolute()
            || p.components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(format!("absolute-path-required {}", p.display()));
        }
        if self.0 == Path::new("/") {
            Ok(p.to_path_buf())
        } else {
            Ok(self
                .0
                .join(p.strip_prefix("/").map_err(|_| "root-prefix-strip")?))
        }
    }
}
#[derive(Clone, Debug)]
pub enum FilesystemOperation {
    WriteFile {
        path: PathBuf,
        bytes: Vec<u8>,
        mode: Option<u32>,
    },
    MakeDir {
        path: PathBuf,
    },
    MakeLink {
        target: PathBuf,
        link: PathBuf,
    },
    CopyFile {
        source: PathBuf,
        target: PathBuf,
    },
    ChangeMode {
        path: PathBuf,
        mode: u32,
    },
    RemoveFile {
        path: PathBuf,
    },
    PullRepo {
        repo: PathBuf,
        path: PathBuf,
        branch: String,
    },
}
#[derive(Clone, Debug, Serialize)]
pub struct FilesystemReceipt {
    pub schema: &'static str,
    pub operation: String,
    pub ok: bool,
    pub changed: bool,
    pub write_operations: usize,
    pub facts: serde_json::Value,
    pub error: Option<String>,
}
impl FilesystemReceipt {
    pub fn json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}
fn run<T>(
    name: &str,
    same: bool,
    act: impl FnOnce(&atoms::comparison::ActionAuthorization) -> Result<T, String>,
    facts: serde_json::Value,
) -> Result<FilesystemReceipt, String> {
    let r = atoms::comparison::execute_once(
        name,
        || Ok::<_, String>(same),
        |v| {
            if *v {
                DiffDecision::Empty
            } else {
                DiffDecision::Different
            }
        },
        |a, _| act(&a),
    )?;
    let c = r.decision() == DiffDecision::Different;
    Ok(FilesystemReceipt {
        schema: "harmonia.filesystem-receipt.v1",
        operation: name.into(),
        ok: true,
        changed: c,
        write_operations: usize::from(c),
        facts,
        error: None,
    })
}
fn exists(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok()
}
pub fn converge(root: &RootPrefix, op: &FilesystemOperation) -> Result<FilesystemReceipt, String> {
    match op {
        FilesystemOperation::WriteFile { path, bytes, mode } => {
            let p = root.resolve(path)?;
            let same = fs::read(&p).ok().as_deref() == Some(bytes)
                && mode.map_or(true, |m| {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::metadata(&p)
                            .ok()
                            .is_some_and(|x| x.permissions().mode() & 0o7777 == m)
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = m;
                        true
                    }
                });
            run(
                "write-file",
                same,
                |a| {
                    atoms::r#do::write_file::file_write(
                        a,
                        &atoms::r#do::InvocationKey::for_apply(),
                        &p,
                        bytes,
                        atoms::r#do::write_file::FileWriteOptions {
                            write_bytes: true,
                            mode: *mode,
                            uid: None,
                            gid: None,
                            backup_to: None,
                        },
                    )
                    .map(|_| ())
                },
                serde_json::json!({"path":p,"bytes":bytes.len(),"mode":mode}),
            )
        }
        FilesystemOperation::MakeDir { path } => {
            let p = root.resolve(path)?;
            run(
                "make-dir",
                exists(&p),
                |a| {
                    atoms::r#do::make_dir::create_dir_all(
                        a,
                        &atoms::r#do::InvocationKey::for_apply(),
                        &p,
                    )
                },
                serde_json::json!({"path":p}),
            )
        }
        FilesystemOperation::MakeLink { target, link } => {
            let t = root.resolve(target)?;
            let l = root.resolve(link)?;
            let same = fs::read_link(&l).ok().as_deref() == Some(t.as_path());
            run(
                "make-link",
                same,
                |a| {
                    atoms::r#do::make_link::symlink(
                        a,
                        &atoms::r#do::InvocationKey::for_apply(),
                        &t,
                        &l,
                    )
                },
                serde_json::json!({"target":t,"link":l}),
            )
        }
        FilesystemOperation::CopyFile { source, target } => {
            let s = root.resolve(source)?;
            let t = root.resolve(target)?;
            let same = fs::read(&s).ok() == fs::read(&t).ok();
            run(
                "copy-file",
                same,
                |a| {
                    atoms::r#do::copy_file::copy(
                        a,
                        &atoms::r#do::InvocationKey::for_apply(),
                        &atoms::r#do::copy_file::Plan {
                            source: s.clone(),
                            target: t.clone(),
                            mode: None,
                            uid: None,
                            gid: None,
                            no_follow: true,
                            restore: None,
                        },
                    )
                },
                serde_json::json!({"source":s,"target":t}),
            )
        }
        FilesystemOperation::ChangeMode { path, mode } => {
            let p = root.resolve(path)?;
            let same = fs::metadata(&p).ok().is_some_and(|m| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    m.permissions().mode() & 0o7777 == *mode
                }
                #[cfg(not(unix))]
                {
                    let _ = m;
                    true
                }
            });
            run(
                "change-mode",
                same,
                |a| {
                    atoms::r#do::change_mode::change(
                        a,
                        &atoms::r#do::InvocationKey::for_apply(),
                        &atoms::r#do::change_mode::Plan {
                            path: p.clone(),
                            mode: Some(*mode),
                            no_follow: true,
                        },
                    )
                },
                serde_json::json!({"path":p,"mode":mode}),
            )
        }
        FilesystemOperation::RemoveFile { path } => {
            let p = root.resolve(path)?;
            run(
                "remove-file",
                !exists(&p),
                |a| {
                    atoms::r#do::remove_file::remove_file(
                        a,
                        &atoms::r#do::InvocationKey::for_apply(),
                        &p,
                    )
                },
                serde_json::json!({"path":p,"absent":true}),
            )
        }
        FilesystemOperation::PullRepo { repo, path, branch } => {
            let r = root.resolve(repo)?;
            let p = root.resolve(path)?;
            let q = git_artifact::Request::new(
                Some(r.display().to_string()),
                p.clone(),
                branch.clone(),
                "origin".into(),
            )
            .with_safe_directory(p.clone());
            let o = atoms::ask::pull_repo::observe_request(&q);
            let d = atoms::ask::pull_repo::compare_pull_repo(&o);
            if d == DiffDecision::Empty {
                return Ok(FilesystemReceipt {
                    schema: "harmonia.filesystem-receipt.v1",
                    operation: "pull-repo".into(),
                    ok: true,
                    changed: false,
                    write_operations: 0,
                    facts: serde_json::json!({"repo":r,"path":p,"branch":branch}),
                    error: None,
                });
            }
            match atoms::comparison::execute_once(
                "pull-repo",
                || Ok::<_, String>(o.clone()),
                |_| DiffDecision::Different,
                |authorization, _| {
                    Ok(atoms::r#do::pull_repo::apply(
                        &authorization,
                        &atoms::r#do::InvocationKey::for_apply(),
                        &q,
                        &o,
                    ))
                },
            ) {
                Ok(atoms::comparison::ComparisonRun::Moved { movement, .. }) => {
                    let error = if movement.ok {
                        None
                    } else if movement.command.stderr.is_empty() {
                        Some(movement.message.clone())
                    } else {
                        Some(movement.command.stderr.clone())
                    };
                    Ok(FilesystemReceipt {
                        schema: "harmonia.filesystem-receipt.v1",
                        operation: "pull-repo".into(),
                        ok: movement.ok,
                        changed: movement.changed,
                        write_operations: usize::from(movement.changed),
                        facts: serde_json::json!({"repo":r,"path":p,"branch":branch}),
                        error,
                    })
                }
                Ok(_) => unreachable!("pull comparison action must move"),
                Err(error) => Ok(FilesystemReceipt {
                    schema: "harmonia.filesystem-receipt.v1",
                    operation: "pull-repo".into(),
                    ok: false,
                    changed: false,
                    write_operations: 0,
                    facts: serde_json::json!({"repo":r,"path":p,"branch":branch}),
                    error: Some(error),
                }),
            }
        }
    }
}

/// Execute the production projection transaction against concrete member files.
pub fn apply_transaction(members: Vec<(PathBuf, String, Vec<u8>)>) -> serde_json::Value {
    use crate::atoms::r#do::transaction::{
        apply_projection, commit_projection, project_update_set_v1, rollback_projection,
        seal_projection, Target, UpdatePlan,
    };
    let plan = UpdatePlan {
        targets: members
            .iter()
            .map(|(path, member, _)| Target {
                path: path.clone(),
                member: member.clone(),
            })
            .collect(),
        services: Vec::new(),
        gui_face: None,
        gui_member: None,
        caduceus_count: 0,
        pinned_members: None,
    };
    let mut transaction = match seal_projection(
        &plan,
        "filesystem-convergence",
        "filesystem",
        "members",
    ) {
        Ok(value) => value,
        Err(error) => {
            return json!({"schema":"harmonia.transaction.v1","state":"failed","rolled_back":false,"error":error})
        }
    };
    for (index, (path, _, bytes)) in members.iter().enumerate() {
        let result = atoms::comparison::execute_once(
            "filesystem-transaction-member",
            || Ok::<_, String>(fs::read(path).ok()),
            |_| DiffDecision::Different,
            |authorization, _| {
                atoms::r#do::write_file::file_write(
                    &authorization,
                    &atoms::r#do::InvocationKey::for_apply(),
                    path,
                    bytes,
                    atoms::r#do::write_file::FileWriteOptions {
                        write_bytes: true,
                        mode: None,
                        uid: None,
                        gid: None,
                        backup_to: None,
                    },
                )?;
                apply_projection(
                    &mut transaction,
                    index,
                    &atoms::r#do::InvocationKey::for_apply(),
                )
            },
        );
        if let Err(error) = result {
            let rollback =
                rollback_projection(&mut transaction, &atoms::r#do::InvocationKey::for_apply());
            return json!({"schema":"harmonia.transaction.v1","state":"failed","rolled_back":rollback.is_ok(),"transaction":rollback.ok(),"error":error});
        }
    }
    match commit_projection(&mut transaction) {
        Ok(receipt) => {
            json!({"schema":"harmonia.transaction.v1","state":"committed","transaction":receipt,"update_set":project_update_set_v1(&receipt)})
        }
        Err(error) => {
            json!({"schema":"harmonia.transaction.v1","state":"failed","rolled_back":false,"error":error})
        }
    }
}
