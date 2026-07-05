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

pub mod command;
pub mod files;
pub mod git_artifact;
pub mod health;
pub(crate) mod module_steps;
pub(crate) mod service_runtime;

pub const TOOLBELT: &[ToolContract] = &[
    command::CONTRACT,
    files::CONTRACT,
    git_artifact::CONTRACT,
    health::CONTRACT,
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
        }
    }

    #[test]
    fn registered_tool_names_have_real_behavioral_entry_points() {
        let root = repo_root();
        let expected = BTreeSet::from(["command", "files", "git-artifact", "health"]);
        let actual: BTreeSet<&str> = all().iter().map(|tool| tool.name).collect();
        assert_eq!(actual, expected);
        for tool in all() {
            let module_file = root
                .join("src/tools")
                .join(format!("{}.rs", tool.name.replace('-', "_")));
            let source = fs::read_to_string(&module_file).unwrap_or_else(|err| {
                panic!(
                    "tool {} must have Rust implementation file at {}: {err}",
                    tool.name,
                    module_file.display()
                )
            });
            assert!(
                source.contains("pub(crate) fn")
                    || source.contains("pub fn converge_files")
                    || source.contains("pub fn apply"),
                "tool {} must expose an executable behavioral entry point",
                tool.name
            );
            assert!(
                !source.contains("planned for")
                    || source.contains("capture_with")
                    || source.contains("converge_")
                    || source.contains("curl_probe")
                    || source.contains("apply("),
                "tool {} must not be a description-only planned stub",
                tool.name
            );
        }
    }

    #[test]
    fn every_tool_is_addressable_by_code() {
        for tool in all() {
            assert_eq!(get(tool.name), Some(tool));
        }
    }
}
