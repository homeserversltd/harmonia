#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolContract {
    pub name: &'static str,
    pub description: &'static str,
}

impl ToolContract {
    pub const fn new(name: &'static str, description: &'static str) -> Self {
        Self { name, description }
    }
}

pub mod archive;
pub mod artifact;
pub mod backup;
pub mod command;
pub mod config;
pub mod cron_timer;
pub mod download;
pub mod files;
pub mod git_artifact;
pub mod health;
pub mod hotfix;
pub mod interactable;
pub mod migration;
pub mod node_build;
pub mod package;
pub mod permissions;
pub mod receipt;
pub mod rust_build;
pub mod systemd;
pub mod venv;
pub mod version;

pub const TOOLBELT: &[ToolContract] = &[
    archive::CONTRACT,
    artifact::CONTRACT,
    backup::CONTRACT,
    command::CONTRACT,
    config::CONTRACT,
    cron_timer::CONTRACT,
    download::CONTRACT,
    files::CONTRACT,
    git_artifact::CONTRACT,
    health::CONTRACT,
    hotfix::CONTRACT,
    interactable::CONTRACT,
    migration::CONTRACT,
    node_build::CONTRACT,
    package::CONTRACT,
    permissions::CONTRACT,
    receipt::CONTRACT,
    rust_build::CONTRACT,
    systemd::CONTRACT,
    venv::CONTRACT,
    version::CONTRACT,
];

pub fn all() -> &'static [ToolContract] {
    TOOLBELT
}

#[cfg(test)]
pub fn get(name: &str) -> Option<&'static ToolContract> {
    TOOLBELT.iter().find(|tool| tool.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::fs;

    fn repo_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
    }

    #[test]
    fn repo_has_exactly_one_tools_folder_and_it_is_rust_code() {
        let root = repo_root();
        let mut tools_dirs = Vec::new();
        fn walk(path: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in fs::read_dir(path).expect("walkable repo") {
                let entry = entry.expect("entry readable");
                let file_type = entry.file_type().expect("entry type readable");
                let p = entry.path();
                if file_type.is_dir() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if [".git", "target"].contains(&name.as_str()) {
                        continue;
                    }
                    if name == "tools" {
                        out.push(p.clone());
                    }
                    walk(&p, out);
                }
            }
        }
        walk(&root, &mut tools_dirs);
        assert_eq!(tools_dirs, vec![root.join("src/tools")]);
    }

    #[test]
    fn every_tool_contract_is_singular_and_named() {
        let mut names = BTreeSet::new();
        for tool in all() {
            assert!(!tool.name.is_empty(), "tool name is required");
            assert!(
                tool.name
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-'),
                "tool {} must be ascii kebab-case",
                tool.name
            );
            assert!(names.insert(tool.name), "duplicate tool name {}", tool.name);
            assert!(
                tool.description.contains("primitive"),
                "tool {} description must name one primitive job",
                tool.name
            );
            assert_eq!(
                tool.description.matches('.').count(),
                1,
                "tool {} description must stay one sentence",
                tool.name
            );
        }
    }

    #[test]
    fn toolbelt_contracts_have_rust_files_not_json_peer_manifests() {
        let root = repo_root();
        assert!(
            !root.join("tools").exists(),
            "top-level JSON tool tree must not exist"
        );
        for tool in all() {
            let module_file = root
                .join("src/tools")
                .join(format!("{}.rs", tool.name.replace('-', "_")));
            assert!(
                module_file.exists(),
                "tool {} must have Rust implementation file at {}",
                tool.name,
                module_file.display()
            );
        }
    }

    #[test]
    fn every_tool_is_addressable_by_code() {
        for tool in all() {
            assert_eq!(get(tool.name), Some(tool));
        }
    }

    #[test]
    fn primitive_tool_files_are_callable() {
        let outcome = command::plan(&command::Request::new("check"));
        assert!(outcome.ok);
        assert!(outcome.message.contains("command check planned"));
        let outcome = files::plan(&files::Request::new("atomic-promote"));
        assert!(outcome.ok);
        assert!(outcome.message.contains("files atomic-promote planned"));
    }
}
