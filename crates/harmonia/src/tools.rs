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

pub const TOOLBELT: &[ToolContract] = &[
    ToolContract::new("archive", "Archive unpack/pack primitive for tar/zip release payloads."),
    ToolContract::new("artifact", "Artifact install/promote/rollback primitive for binaries and release payloads."),
    ToolContract::new("backup", "Backup/snapshot/preserve/restore primitive for mutable runtime state."),
    ToolContract::new("command", "Host command execution primitive with cwd/env/timeout/exit capture; every subprocess produces a command receipt."),
    ToolContract::new("config", "Typed config/JSON/TOML/YAML read/write/validate primitive."),
    ToolContract::new("cron-timer", "Cron/systemd timer install/enable/status primitive."),
    ToolContract::new("download", "HTTP download/version discovery primitive with bounded network calls and receipt evidence."),
    ToolContract::new("files", "Staged file/template/directory/symlink primitive with atomic promotion."),
    ToolContract::new("git-artifact", "Bottled repository primitive for clone, fetch, clean-tree guard, checkout, and fast-forward update through profile modules."),
    ToolContract::new("health", "Service readiness and health-readback primitive, including HTTP and command checks."),
    ToolContract::new("hotfix", "Emergency one-shot hotfix primitive with explicit receipt and retirement path."),
    ToolContract::new("interactable", "Operator-triggered action primitive for manual buttons that still need receipts."),
    ToolContract::new("migration", "Ordered idempotent migration primitive with applied-state receipts."),
    ToolContract::new("node-build", "Node/npm/pnpm build primitive for web bodies."),
    ToolContract::new("package", "OS package check/update/install primitive; supports pacman first and later apt/dnf adapters."),
    ToolContract::new("permissions", "Owner/group/mode/ACL/sudoers policy primitive with validation before promotion."),
    ToolContract::new("receipt", "Central receipt writer and run ledger primitive."),
    ToolContract::new("rust-build", "Cargo build/test/install primitive for Rust bodies such as Arcadia and Harmonia."),
    ToolContract::new("systemd", "Systemd unit install/enable/disable/start/stop/restart/status primitive."),
    ToolContract::new("venv", "Python virtualenv preservation/update primitive for quarry compatibility surfaces; not a Harmonia authority lane."),
    ToolContract::new("version", "Version detection/compare/channel selection primitive."),
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
    use serde_json::Value;
    use std::collections::BTreeSet;
    use std::fs;

    fn repo_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate lives under crates/harmonia")
            .to_path_buf()
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
    fn code_toolbelt_and_manifest_toolbelt_match() {
        let root = repo_root();
        let mut manifest_names = BTreeSet::new();
        for entry in fs::read_dir(root.join("tools")).expect("tools directory exists") {
            let entry = entry.expect("tool dir entry is readable");
            if !entry
                .file_type()
                .expect("tool entry type is readable")
                .is_dir()
            {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "README.md" {
                continue;
            }
            let manifest_path = entry.path().join("index.json");
            assert!(manifest_path.exists(), "tool {} must have index.json", name);
            let raw = fs::read_to_string(&manifest_path)
                .unwrap_or_else(|err| panic!("read {}: {}", manifest_path.display(), err));
            let manifest: Value = serde_json::from_str(&raw)
                .unwrap_or_else(|err| panic!("parse {}: {}", manifest_path.display(), err));
            assert_eq!(
                manifest.get("id").and_then(Value::as_str),
                Some(name.as_str()),
                "tool {} manifest id must match directory",
                name
            );
            manifest_names.insert(name);
        }

        let code_names: BTreeSet<_> = all().iter().map(|tool| tool.name.to_string()).collect();
        assert_eq!(
            code_names, manifest_names,
            "adding a tool requires code and manifest together"
        );
    }

    #[test]
    fn every_manifest_tool_is_addressable_by_code() {
        for tool in all() {
            assert_eq!(get(tool.name), Some(tool));
        }
    }
}

pub mod git_artifact;
