use super::{command, ToolArg, ToolArgKind, ToolContract, ToolPermutation};

pub const NAME: &str = "git-artifact";
pub const DESCRIPTION: &str = "Bottled repository primitive for clone, fetch, clean-tree guard, checkout, and fast-forward update through profile modules.";
pub const PERMUTATIONS: &[ToolPermutation] = &[ToolPermutation::new(
    "sync",
    "clone or fast-forward a repository artifact",
    &[
        ToolArg::optional("repo", ToolArgKind::String),
        ToolArg::required("path", ToolArgKind::String),
        ToolArg::optional("branch", ToolArgKind::String),
        ToolArg::optional("remote", ToolArgKind::String),
        // Compatibility input only: source Git always runs as the owner bearer.
        ToolArg::optional("bearer", ToolArgKind::String),
    ],
)];
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION, PERMUTATIONS);

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub type CommandReceipt = crate::CmdResult;

const OWNER_BEARER: &str = "owner";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub ok: bool,
    pub changed: bool,
    pub message: String,
    pub command: CommandReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub repo: Option<String>,
    pub path: PathBuf,
    pub branch: String,
    pub remote: String,
    pub ssh_key_path: Option<PathBuf>,
    pub git_https_credential_host: Option<String>,
    pub git_https_credential_token_path: Option<PathBuf>,
}

impl Request {
    pub fn new(repo: Option<String>, path: PathBuf, branch: String, remote: String) -> Self {
        Self {
            repo,
            path,
            branch,
            remote,
            ssh_key_path: None,
            git_https_credential_host: None,
            git_https_credential_token_path: None,
        }
    }

    pub fn with_bearer(self, bearer: impl Into<String>) -> Self {
        let _ = bearer.into();
        self
    }

    pub fn with_ssh_key_path(mut self, path: Option<PathBuf>) -> Self {
        self.ssh_key_path = path;
        self
    }

    pub fn with_https_credentials(
        mut self,
        host: Option<String>,
        token_path: Option<PathBuf>,
    ) -> Self {
        self.git_https_credential_host = host;
        self.git_https_credential_token_path = token_path;
        self
    }
}

fn capture_git(request: &Request, args: &[&str], cwd: Option<&str>) -> CommandReceipt {
    let env = match git_ssh_env(request.ssh_key_path.as_deref()) {
        Ok(env) => env,
        Err(stderr) => {
            return CommandReceipt {
                ok: false,
                code: -1,
                stdout: String::new(),
                stderr,
            };
        }
    };
    let credential_helper = owner_https_credential_helper(request);
    let mut git_args =
        Vec::with_capacity(args.len() + usize::from(credential_helper.is_some()) * 2);
    if let Some(helper) = credential_helper.as_deref() {
        git_args.extend(["-c", helper]);
    }
    git_args.extend_from_slice(args);
    command::capture_with_cwd_as_bearer_and_env("/usr/bin/git", &git_args, cwd, OWNER_BEARER, env)
}

fn owner_https_credential_helper(request: &Request) -> Option<String> {
    let host = request.git_https_credential_host.as_deref()?;
    let token_path = request.git_https_credential_token_path.as_deref()?;
    let repo = request.repo.as_deref()?;
    if !repo.starts_with(&format!("https://{host}/")) {
        return None;
    }
    let token_path = token_path.to_str()?;
    Some(format!(
        "credential.helper=!f() {{ protocol= host= username= token=; while IFS= read -r line && [ -n \"$line\" ]; do case \"$line\" in protocol=*) protocol=${{line#protocol=}} ;; host=*) host=${{line#host=}} ;; esac; done; if [ \"$protocol\" = https ] && [ \"$host\" = {} ]; then while IFS= read -r line; do case \"$line\" in FORGEJO_USERNAME=*) username=${{line#FORGEJO_USERNAME=}} ;; FORGEJO_TOKEN=*) token=${{line#FORGEJO_TOKEN=}} ;; esac; done < {}; if [ -n \"$username\" ] && [ -n \"$token\" ]; then printf \"username=%s\\npassword=%s\\n\" \"$username\" \"$token\"; fi; fi; }}; f",
        shell_quote(host),
        shell_quote(token_path),
    ))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Validate only path identity and stage the SSH selector for the Git child.
/// This deliberately never opens the key: `ssh` reads it only in the exec'd
/// Git transport process, after a privileged parent has dropped to its bearer.
fn git_ssh_env(path: Option<&Path>) -> Result<BTreeMap<String, String>, String> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    if !path.is_absolute() {
        return Err(format!("git-ssh-key-path-not-absolute {}", path.display()));
    }
    let metadata = fs::metadata(path)
        .map_err(|err| format!("git-ssh-key-unavailable {}: {err}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("git-ssh-key-not-regular-file {}", path.display()));
    }
    let path = path
        .to_str()
        .ok_or_else(|| format!("git-ssh-key-path-non-utf8 {}", path.display()))?;
    let quoted = format!("'{}'", path.replace('\'', "'\\''"));
    Ok(BTreeMap::from([(
        "GIT_SSH_COMMAND".to_string(),
        format!("ssh -i {quoted} -o IdentitiesOnly=yes"),
    )]))
}

pub fn plan(request: &Request) -> Outcome {
    let command = if request.path.join(".git").exists() {
        capture_git(request, &["status", "--short"], request.path.to_str())
    } else {
        CommandReceipt {
            ok: true,
            code: 0,
            stdout: format!("planned clone/update path={}", request.path.display()),
            stderr: String::new(),
        }
    };
    Outcome {
        ok: command.ok,
        changed: false,
        message: format!("git-artifact planned {}", request.path.display()),
        command,
    }
}

pub fn apply(request: &Request) -> Outcome {
    let sync = sync_repo(request);
    Outcome {
        ok: sync.command.ok,
        changed: sync.command.ok && sync.changed,
        message: format!("git-artifact sync {}", request.path.display()),
        command: sync.command,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SyncResult {
    command: CommandReceipt,
    changed: bool,
}

fn sync_repo(request: &Request) -> SyncResult {
    if let Err(stderr) = prepare_owner_writable_path(request) {
        return SyncResult {
            command: CommandReceipt {
                ok: false,
                code: -1,
                stdout: String::new(),
                stderr,
            },
            changed: false,
        };
    }
    let mut transcript = Vec::new();
    if !request.path.join(".git").exists() {
        let Some(repo) = request.repo.as_deref() else {
            return SyncResult {
                command: CommandReceipt {
                    ok: false,
                    code: 2,
                    stdout: String::new(),
                    stderr: format!(
                        "repo missing and no clone URL supplied for {}",
                        request.path.display()
                    ),
                },
                changed: false,
            };
        };
        if let Some(parent) = request.path.parent() {
            if let Err(err) = fs::create_dir_all(parent) {
                return SyncResult {
                    command: CommandReceipt {
                        ok: false,
                        code: 2,
                        stdout: String::new(),
                        stderr: format!("create parent failed {}: {err}", parent.display()),
                    },
                    changed: false,
                };
            }
        }
        if request.path.exists() {
            let preserved = preserved_non_git_path(&request.path);
            match fs::rename(&request.path, &preserved) {
                Ok(()) => transcript.push(format!(
                    "non_git_existing_path_preserved={}",
                    preserved.display()
                )),
                Err(err) => {
                    return SyncResult {
                        command: CommandReceipt {
                            ok: false,
                            code: 2,
                            stdout: transcript.join("\n"),
                            stderr: format!(
                                "existing non-git path could not be preserved {}: {err}",
                                request.path.display()
                            ),
                        },
                        changed: false,
                    };
                }
            }
        }
        if let Err(stderr) = prepare_owner_writable_path(request) {
            return SyncResult {
                command: CommandReceipt {
                    ok: false,
                    code: -1,
                    stdout: transcript.join("\n"),
                    stderr,
                },
                changed: false,
            };
        }
        let clone = capture_git(
            request,
            &[
                "clone",
                "--branch",
                &request.branch,
                repo,
                request.path.to_string_lossy().as_ref(),
            ],
            None,
        );
        transcript.push(format!("clone exit={} ok={}", clone.code, clone.ok));
        if !clone.stdout.is_empty() {
            transcript.push(clone.stdout.clone());
        }
        if !clone.stderr.is_empty() {
            transcript.push(clone.stderr.clone());
        }
        if !clone.ok {
            return SyncResult {
                command: CommandReceipt {
                    ok: false,
                    code: clone.code,
                    stdout: transcript.join("\n"),
                    stderr: clone.stderr,
                },
                changed: false,
            };
        }
        return SyncResult {
            command: CommandReceipt {
                ok: true,
                code: 0,
                stdout: transcript.join("\n"),
                stderr: String::new(),
            },
            changed: true,
        };
    }

    let cwd = request.path.to_str();
    let before = capture_git(request, &["rev-parse", "HEAD"], cwd);
    if !before.ok {
        return SyncResult {
            command: before,
            changed: false,
        };
    }
    let dirty = capture_git(
        request,
        &["status", "--porcelain", "--", ".", ":(exclude).worktrees"],
        cwd,
    );
    if !dirty.ok {
        return SyncResult {
            command: dirty,
            changed: false,
        };
    }
    if !dirty.stdout.trim().is_empty() {
        return SyncResult {
            command: CommandReceipt {
                ok: false,
                code: 3,
                stdout: dirty.stdout,
                stderr: "working tree has local modifications; refusing repo sync".to_string(),
            },
            changed: false,
        };
    }

    if let Some(repo) = request.repo.as_deref() {
        let configured = capture_git(request, &["remote", "get-url", &request.remote], cwd);
        if !configured.ok {
            return SyncResult {
                command: configured,
                changed: false,
            };
        }
        if configured.stdout.trim() != repo {
            let reconcile =
                capture_git(request, &["remote", "set-url", &request.remote, repo], cwd);
            transcript.push(format!(
                "remote_url_reconcile remote={} exit={} ok={}",
                request.remote, reconcile.code, reconcile.ok
            ));
            if !reconcile.ok {
                return SyncResult {
                    command: CommandReceipt {
                        ok: false,
                        code: reconcile.code,
                        stdout: transcript.join("\n"),
                        stderr: reconcile.stderr,
                    },
                    changed: false,
                };
            }
        }
    }

    let remote_tracking_refspec = format!(
        "+refs/heads/{}:refs/remotes/{}/{}",
        request.branch, request.remote, request.branch
    );
    let fetch = capture_git(
        request,
        &["fetch", &request.remote, &remote_tracking_refspec],
        cwd,
    );
    transcript.push(format!("fetch exit={} ok={}", fetch.code, fetch.ok));
    if !fetch.ok {
        return SyncResult {
            command: CommandReceipt {
                ok: false,
                code: fetch.code,
                stdout: transcript.join("\n"),
                stderr: fetch.stderr,
            },
            changed: false,
        };
    }
    let checkout = capture_git(request, &["checkout", &request.branch], cwd);
    transcript.push(format!(
        "checkout exit={} ok={}",
        checkout.code, checkout.ok
    ));
    if !checkout.ok {
        return SyncResult {
            command: CommandReceipt {
                ok: false,
                code: checkout.code,
                stdout: transcript.join("\n"),
                stderr: checkout.stderr,
            },
            changed: false,
        };
    }
    let pull_ref = format!("{}/{}", request.remote, request.branch);
    let merge = capture_git(request, &["merge", "--ff-only", &pull_ref], cwd);
    transcript.push(format!("merge_ff exit={} ok={}", merge.code, merge.ok));
    if !merge.stdout.is_empty() {
        transcript.push(merge.stdout.clone());
    }
    if !merge.ok {
        return SyncResult {
            command: CommandReceipt {
                ok: false,
                code: merge.code,
                stdout: transcript.join("\n"),
                stderr: merge.stderr,
            },
            changed: false,
        };
    }
    let after = capture_git(request, &["rev-parse", "HEAD"], cwd);
    if !after.ok {
        return SyncResult {
            command: after,
            changed: false,
        };
    }
    let changed = before.stdout.trim() != after.stdout.trim();
    transcript.push(format!("before={}", before.stdout.trim()));
    transcript.push(format!("after={}", after.stdout.trim()));
    SyncResult {
        command: CommandReceipt {
            ok: true,
            code: 0,
            stdout: transcript.join("\n"),
            stderr: String::new(),
        },
        changed,
    }
}

fn prepare_owner_writable_path(request: &Request) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let (uid, gid) = owner_ids()?;
    fs::create_dir_all(&request.path).map_err(|err| {
        format!(
            "git-owner-source-path-create-failed {}: {err}",
            request.path.display()
        )
    })?;
    chown_tree_to_owner(&request.path, uid, gid)
}

fn owner_ids() -> Result<(u32, u32), String> {
    let name =
        std::ffi::CString::new(OWNER_BEARER).map_err(|_| "git-owner-bearer-invalid".to_string())?;
    let passwd = unsafe { libc::getpwnam(name.as_ptr()) };
    if passwd.is_null() {
        return Err("git-owner-bearer-unknown".to_string());
    }
    let passwd = unsafe { &*passwd };
    if passwd.pw_uid == 0 || passwd.pw_gid == 0 {
        return Err("git-owner-bearer-root-refused".to_string());
    }
    Ok((passwd.pw_uid, passwd.pw_gid))
}

fn chown_tree_to_owner(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        format!(
            "git-owner-source-path-stat-failed {}: {err}",
            path.display()
        )
    })?;
    if metadata.uid() != uid || metadata.gid() != gid {
        let path_c = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| format!("git-owner-source-path-non-utf8 {}", path.display()))?;
        if unsafe { libc::lchown(path_c.as_ptr(), uid, gid) } != 0 {
            return Err(format!(
                "git-owner-source-path-chown-failed {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
    }
    if metadata.file_type().is_dir() {
        for entry in fs::read_dir(path).map_err(|err| {
            format!(
                "git-owner-source-path-read-failed {}: {err}",
                path.display()
            )
        })? {
            let entry = entry.map_err(|err| {
                format!(
                    "git-owner-source-path-entry-failed {}: {err}",
                    path.display()
                )
            })?;
            chown_tree_to_owner(&entry.path(), uid, gid)?;
        }
    }
    Ok(())
}

pub fn stdout_changed(stdout: &str) -> bool {
    stdout.lines().any(|line| line.trim() == "changed=true")
}

fn preserved_non_git_path(path: &Path) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("source");
    path.with_file_name(format!("{name}.non-git-preserved-{stamp}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_accepts_missing_repo_as_future_clone() {
        let request = Request::new(
            Some("https://github.com/homeserversltd/keyman.git".into()),
            PathBuf::from("/opt/keyman/source"),
            "main".into(),
            "origin".into(),
        );
        let outcome = plan(&request);
        assert!(outcome.ok);
        assert!(!outcome.changed);
        assert!(outcome.command.stdout.contains("planned clone/update"));
    }

    #[test]
    fn declared_ssh_key_path_is_absolute_regular_file_and_shell_quoted() {
        let root = std::env::temp_dir().join(format!(
            "harmonia-git-artifact-ssh-key-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let key = root.join("forgejo owner's key");
        fs::write(&key, "not-a-private-key\n").unwrap();
        let env = git_ssh_env(Some(&key)).unwrap();
        let expected = format!(
            "ssh -i '{}' -o IdentitiesOnly=yes",
            key.display().to_string().replace('\'', "'\\''")
        );
        assert_eq!(
            env.get("GIT_SSH_COMMAND").map(String::as_str),
            Some(expected.as_str())
        );
        assert!(git_ssh_env(Some(Path::new("relative-key")))
            .unwrap_err()
            .contains("git-ssh-key-path-not-absolute"));
        assert!(git_ssh_env(Some(&root.join("absent-key")))
            .unwrap_err()
            .contains("git-ssh-key-unavailable"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sync_preserves_existing_non_git_path_before_clone() {
        let root = std::env::temp_dir().join(format!(
            "harmonia-git-artifact-non-git-{}",
            std::process::id()
        ));
        let repo = root.join("repo");
        let target = root.join("source");
        fs::create_dir_all(&repo).unwrap();
        command::capture_with_cwd("/usr/bin/git", &["init", "-b", "main"], repo.to_str());
        command::capture_with_cwd(
            "/usr/bin/git",
            &["config", "user.email", "harmonia@example.invalid"],
            repo.to_str(),
        );
        command::capture_with_cwd(
            "/usr/bin/git",
            &["config", "user.name", "Harmonia Test"],
            repo.to_str(),
        );
        fs::write(repo.join("README.md"), "repo source\n").unwrap();
        command::capture_with_cwd("/usr/bin/git", &["add", "README.md"], repo.to_str());
        command::capture_with_cwd("/usr/bin/git", &["commit", "-m", "seed"], repo.to_str());
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("old-payload"), "preserve me\n").unwrap();

        let request = Request::new(
            Some(repo.display().to_string()),
            target.clone(),
            "main".into(),
            "origin".into(),
        );
        let sync = sync_repo(&request);
        let receipt = sync.command;
        assert!(receipt.ok, "{}", receipt.stderr);
        assert!(sync.changed);
        assert!(target.join(".git").exists());
        assert!(receipt.stdout.contains("non_git_existing_path_preserved="));
        let preserved_exists = fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("non-git-preserved")
            });
        assert!(preserved_exists);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sync_fetches_configured_branch_into_remote_tracking_ref_before_fast_forward() {
        let root = std::env::temp_dir().join(format!(
            "harmonia-git-artifact-remote-main-{}",
            std::process::id()
        ));
        let seed = root.join("seed");
        let remote = root.join("remote.git");
        let target = root.join("target");
        fs::create_dir_all(&seed).unwrap();
        command::capture_with_cwd("/usr/bin/git", &["init", "-b", "main"], seed.to_str());
        for (key, value) in [
            ("user.email", "harmonia@example.invalid"),
            ("user.name", "Harmonia Test"),
        ] {
            command::capture_with_cwd("/usr/bin/git", &["config", key, value], seed.to_str());
        }
        fs::write(seed.join("payload"), "first\n").unwrap();
        command::capture_with_cwd("/usr/bin/git", &["add", "payload"], seed.to_str());
        command::capture_with_cwd("/usr/bin/git", &["commit", "-m", "first"], seed.to_str());
        command::capture(
            "/usr/bin/git",
            &[
                "clone",
                "--bare",
                seed.to_str().unwrap(),
                remote.to_str().unwrap(),
            ],
        );
        command::capture(
            "/usr/bin/git",
            &["clone", remote.to_str().unwrap(), target.to_str().unwrap()],
        );

        fs::write(seed.join("payload"), "second\n").unwrap();
        command::capture_with_cwd("/usr/bin/git", &["commit", "-am", "second"], seed.to_str());
        command::capture_with_cwd(
            "/usr/bin/git",
            &["push", remote.to_str().unwrap(), "main"],
            seed.to_str(),
        );

        let request = Request::new(
            Some(remote.display().to_string()),
            target.clone(),
            "main".into(),
            "origin".into(),
        );
        let sync = sync_repo(&request);
        assert!(sync.command.ok, "{}", sync.command.stderr);
        assert!(sync.changed);
        assert_eq!(
            fs::read_to_string(target.join("payload")).unwrap(),
            "second\n"
        );
        let local_head =
            command::capture_with_cwd("/usr/bin/git", &["rev-parse", "HEAD"], target.to_str());
        let tracking_head = command::capture_with_cwd(
            "/usr/bin/git",
            &["rev-parse", "refs/remotes/origin/main"],
            target.to_str(),
        );
        assert_eq!(local_head.stdout.trim(), tracking_head.stdout.trim());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sync_ignores_cibation_worktrees_but_refuses_other_untracked_paths() {
        let root = std::env::temp_dir().join(format!(
            "harmonia-git-artifact-worktree-guard-{}",
            std::process::id()
        ));
        let seed = root.join("seed");
        let remote = root.join("remote.git");
        let target = root.join("target");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&seed).unwrap();
        command::capture_with_cwd("/usr/bin/git", &["init", "-b", "main"], seed.to_str());
        for (key, value) in [
            ("user.email", "harmonia@example.invalid"),
            ("user.name", "Harmonia Test"),
        ] {
            command::capture_with_cwd("/usr/bin/git", &["config", key, value], seed.to_str());
        }
        fs::write(seed.join("payload"), "first\n").unwrap();
        command::capture_with_cwd("/usr/bin/git", &["add", "payload"], seed.to_str());
        command::capture_with_cwd("/usr/bin/git", &["commit", "-m", "first"], seed.to_str());
        command::capture(
            "/usr/bin/git",
            &[
                "clone",
                "--bare",
                seed.to_str().unwrap(),
                remote.to_str().unwrap(),
            ],
        );
        command::capture(
            "/usr/bin/git",
            &["clone", remote.to_str().unwrap(), target.to_str().unwrap()],
        );

        let request = Request::new(
            Some(remote.display().to_string()),
            target.clone(),
            "main".into(),
            "origin".into(),
        );
        fs::create_dir_all(target.join(".worktrees/live-cibation-worktree")).unwrap();
        fs::write(
            target.join(".worktrees/live-cibation-worktree/marker"),
            "preserve me\n",
        )
        .unwrap();
        let allowed = sync_repo(&request);
        assert!(allowed.command.ok, "{}", allowed.command.stderr);
        assert!(target
            .join(".worktrees/live-cibation-worktree/marker")
            .exists());

        fs::write(target.join("ordinary-untracked"), "must block sync\n").unwrap();
        let refused = sync_repo(&request);
        assert!(!refused.command.ok);
        assert_eq!(refused.command.code, 3);
        assert!(refused.command.stdout.contains("ordinary-untracked"));
        assert!(!refused.command.stdout.contains(".worktrees"));
        assert!(refused
            .command
            .stderr
            .contains("working tree has local modifications"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn command_timeout_kills_sleeping_child() {
        let result =
            command::capture_with_cwd_and_timeout("/usr/bin/sh", &["-c", "sleep 2"], None, 1);
        assert!(!result.ok);
        assert!(result.stderr.contains("command-timeout-after-1s"));
        assert!(result.stderr.contains("/usr/bin/sh -c sleep 2"));
    }
}
