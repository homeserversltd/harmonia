#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolContract {
    pub name: &'static str,
    pub description: &'static str,
    pub permutations: &'static [ToolPermutation],
}

impl ToolContract {
    pub const fn new(
        name: &'static str,
        description: &'static str,
        permutations: &'static [ToolPermutation],
    ) -> Self {
        Self {
            name,
            description,
            permutations,
        }
    }

    pub fn permutation(&self, name: &str) -> Option<&'static ToolPermutation> {
        self.permutations
            .iter()
            .find(|permutation| permutation.name == name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolPermutation {
    pub name: &'static str,
    pub description: &'static str,
    pub args: &'static [ToolArg],
}

impl ToolPermutation {
    pub const fn new(
        name: &'static str,
        description: &'static str,
        args: &'static [ToolArg],
    ) -> Self {
        Self {
            name,
            description,
            args,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolArg {
    pub name: &'static str,
    pub kind: ToolArgKind,
    pub required: bool,
}

impl ToolArg {
    pub const fn required(name: &'static str, kind: ToolArgKind) -> Self {
        Self {
            name,
            kind,
            required: true,
        }
    }

    pub const fn optional(name: &'static str, kind: ToolArgKind) -> Self {
        Self {
            name,
            kind,
            required: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolArgKind {
    String,
    Bool,
    Integer,
    StringArray,
    Json,
}

impl ToolArgKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Bool => "bool",
            Self::Integer => "integer",
            Self::StringArray => "string_array",
            Self::Json => "json",
        }
    }

    pub fn matches(self, value: &serde_json::Value) -> bool {
        match self {
            Self::String => value.is_string(),
            Self::Bool => value.is_boolean(),
            Self::Integer => value.as_i64().is_some() || value.as_u64().is_some(),
            Self::StringArray => value
                .as_array()
                .map(|items| items.iter().all(serde_json::Value::is_string))
                .unwrap_or(false),
            Self::Json => true,
        }
    }
}

pub mod command;
pub mod files;
pub mod git_artifact;
pub mod health;
pub(crate) mod module_steps;
pub mod package;
pub(crate) mod service_runtime;
pub mod systemd;

pub const TOOLBELT: &[ToolContract] = &[
    command::CONTRACT,
    files::CONTRACT,
    git_artifact::CONTRACT,
    health::CONTRACT,
    package::CONTRACT,
    service_runtime::CONTRACT,
    systemd::CONTRACT,
];

pub fn all() -> &'static [ToolContract] {
    TOOLBELT
}

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
            assert!(
                !tool.permutations.is_empty(),
                "tool {} must declare permutations",
                tool.name
            );
            let mut permutations = BTreeSet::new();
            for permutation in tool.permutations {
                assert!(
                    permutations.insert(permutation.name),
                    "duplicate permutation {} for {}",
                    permutation.name,
                    tool.name
                );
                assert!(
                    !permutation.args.is_empty(),
                    "permutation {} for {} must declare args",
                    permutation.name,
                    tool.name
                );
            }
        }
    }

    #[test]
    fn registered_tool_names_have_real_behavioral_entry_points() {
        let root = repo_root();
        let expected = BTreeSet::from([
            "command",
            "files",
            "git-artifact",
            "health",
            "package",
            "service-runtime",
            "systemd",
        ]);
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
                    || source.contains("pub fn apply")
                    || source.contains("pub(crate) fn execute"),
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
