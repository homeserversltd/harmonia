use super::ToolContract;

pub const NAME: &str = "git-artifact";
pub const DESCRIPTION: &str = "Bottled repository primitive for clone, fetch, clean-tree guard, checkout, and fast-forward update through profile modules.";
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION);

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandReceipt {
    pub ok: bool,
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

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
}

impl Request {
    pub fn new(repo: Option<String>, path: PathBuf, branch: String, remote: String) -> Self {
        Self {
            repo,
            path,
            branch,
            remote,
        }
    }
}

pub fn plan(request: &Request) -> Outcome {
    let command = if request.path.join(".git").exists() {
        command_capture_with_cwd(
            "/usr/bin/git",
            &["status", "--short"],
            request.path.to_str(),
        )
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
        let clone = command_capture(
            "/usr/bin/git",
            &[
                "clone",
                "--branch",
                &request.branch,
                repo,
                request.path.to_string_lossy().as_ref(),
            ],
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
    let before = command_capture_with_cwd("/usr/bin/git", &["rev-parse", "HEAD"], cwd);
    if !before.ok {
        return SyncResult {
            command: before,
            changed: false,
        };
    }
    let dirty = command_capture_with_cwd("/usr/bin/git", &["status", "--porcelain"], cwd);
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

    let fetch = command_capture_with_cwd(
        "/usr/bin/git",
        &["fetch", &request.remote, &request.branch],
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
    let checkout = command_capture_with_cwd("/usr/bin/git", &["checkout", &request.branch], cwd);
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
    let merge = command_capture_with_cwd("/usr/bin/git", &["merge", "--ff-only", &pull_ref], cwd);
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
    let after = command_capture_with_cwd("/usr/bin/git", &["rev-parse", "HEAD"], cwd);
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

const DEFAULT_GIT_COMMAND_TIMEOUT_SECS: u64 = 900;

fn command_capture(program: &str, args: &[&str]) -> CommandReceipt {
    command_capture_with_cwd(program, args, None)
}

fn command_capture_with_cwd(program: &str, args: &[&str], cwd: Option<&str>) -> CommandReceipt {
    command_capture_with_cwd_and_timeout(program, args, cwd, DEFAULT_GIT_COMMAND_TIMEOUT_SECS)
}

fn command_capture_with_cwd_and_timeout(
    program: &str,
    args: &[&str],
    cwd: Option<&str>,
    timeout_secs: u64,
) -> CommandReceipt {
    use std::io::Read;
    use std::process::Stdio;
    use std::thread;
    use std::time::{Duration, Instant};
    let mut cmd = Command::new(program);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    let command_label = format!("{} {}", program, args.join(" "));
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            return CommandReceipt {
                ok: false,
                code: -1,
                stdout: String::new(),
                stderr: err.to_string(),
            }
        }
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                let mut stderr = String::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_string(&mut stdout);
                }
                if let Some(mut err) = child.stderr.take() {
                    let _ = err.read_to_string(&mut stderr);
                }
                return CommandReceipt {
                    ok: status.success(),
                    code: status.code().unwrap_or(-1),
                    stdout: stdout.trim().to_string(),
                    stderr: stderr.trim().to_string(),
                };
            }
            Ok(None) if start.elapsed() >= Duration::from_secs(timeout_secs) => {
                let _ = child.kill();
                let _ = child.wait();
                return CommandReceipt {
                    ok: false,
                    code: -1,
                    stdout: String::new(),
                    stderr: format!("command-timeout-after-{timeout_secs}s: {command_label}"),
                };
            }
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(err) => {
                let _ = child.kill();
                return CommandReceipt {
                    ok: false,
                    code: -1,
                    stdout: String::new(),
                    stderr: err.to_string(),
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_accepts_missing_repo_as_future_clone() {
        let request = Request::new(
            Some("git@git.home.arpa:HOMESERVERSLTD/keyman.git".into()),
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
    fn sync_preserves_existing_non_git_path_before_clone() {
        let root = std::env::temp_dir().join(format!(
            "harmonia-git-artifact-non-git-{}",
            std::process::id()
        ));
        let repo = root.join("repo");
        let target = root.join("source");
        fs::create_dir_all(&repo).unwrap();
        command_capture_with_cwd("/usr/bin/git", &["init", "-b", "main"], repo.to_str());
        command_capture_with_cwd(
            "/usr/bin/git",
            &["config", "user.email", "harmonia@example.invalid"],
            repo.to_str(),
        );
        command_capture_with_cwd(
            "/usr/bin/git",
            &["config", "user.name", "Harmonia Test"],
            repo.to_str(),
        );
        fs::write(repo.join("README.md"), "repo source\n").unwrap();
        command_capture_with_cwd("/usr/bin/git", &["add", "README.md"], repo.to_str());
        command_capture_with_cwd("/usr/bin/git", &["commit", "-m", "seed"], repo.to_str());
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
    fn command_timeout_kills_sleeping_child() {
        let result =
            command_capture_with_cwd_and_timeout("/usr/bin/sh", &["-c", "sleep 2"], None, 1);
        assert!(!result.ok);
        assert!(result.stderr.contains("command-timeout-after-1s"));
        assert!(result.stderr.contains("/usr/bin/sh -c sleep 2"));
    }
}
