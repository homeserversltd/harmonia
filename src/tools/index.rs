use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActRung {
    Present,
    Absent,
    Unknown,
}

impl ActRung {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Present => "true",
            Self::Absent => "false",
            Self::Unknown => "unknown",
        }
    }
}

const ACT_RUNG_INDEXES: &[(&str, &str)] = &[
    ("backfill-file", include_str!("backfill-file/index.json")),
    ("build-crate", include_str!("build-crate/index.json")),
    ("build-venv", include_str!("build-venv/index.json")),
    ("check-health", include_str!("check-health/index.json")),
    ("enable-unit", include_str!("enable-unit/index.json")),
    (
        "install-package",
        include_str!("install-package/index.json"),
    ),
    ("make-symlink", include_str!("make-symlink/index.json")),
    ("place-file", include_str!("place-file/index.json")),
    ("pull-repo", include_str!("pull-repo/index.json")),
    (
        "ratchet-aur-package",
        include_str!("ratchet-aur-package/index.json"),
    ),
    ("remove-file", include_str!("remove-file/index.json")),
    ("remove-unit", include_str!("remove-unit/index.json")),
    (
        "service-runtime",
        include_str!("service-runtime/index.json"),
    ),
    ("set-clock", include_str!("set-clock/index.json")),
];

pub fn act_rung(name: &str) -> ActRung {
    let Some((_, contents)) = ACT_RUNG_INDEXES
        .iter()
        .find(|(index_name, _)| *index_name == name)
    else {
        return ActRung::Unknown;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(contents) else {
        return ActRung::Unknown;
    };
    let Some(object) = value.as_object() else {
        return ActRung::Unknown;
    };
    if object.get("name").and_then(serde_json::Value::as_str) != Some(name) {
        return ActRung::Unknown;
    }
    if let Some(children) = object.get("children") {
        let Some(children) = children.as_array() else {
            return ActRung::Unknown;
        };
        if !children.iter().all(serde_json::Value::is_string) {
            return ActRung::Unknown;
        }
        return if children.iter().any(|child| child.as_str() == Some("act")) {
            ActRung::Present
        } else {
            ActRung::Absent
        };
    }
    if object.get("state").and_then(serde_json::Value::as_str) == Some("declaration-only")
        && object
            .get("live_permutations")
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty)
    {
        ActRung::Absent
    } else {
        ActRung::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    RenewSelf,
    PullSource,
    StageProfile,
    Compare,
    InstallPackages,
    RatchetBinaries,
    RestartServices,
    BackfillFiles,
    ProposeEdits,
    ReportHome,
}
impl Placement {
    pub const fn band(self) -> crate::bands::Band {
        match self {
            Self::RenewSelf => crate::bands::Band::RenewSelf,
            Self::PullSource => crate::bands::Band::PullSource,
            Self::StageProfile => crate::bands::Band::StageProfile,
            Self::Compare => crate::bands::Band::Compare,
            Self::InstallPackages => crate::bands::Band::InstallPackages,
            Self::RatchetBinaries => crate::bands::Band::RatchetBinaries,
            Self::RestartServices => crate::bands::Band::RestartServices,
            Self::BackfillFiles => crate::bands::Band::BackfillFiles,
            Self::ProposeEdits => crate::bands::Band::ProposeEdits,
            Self::ReportHome => crate::bands::Band::ReportHome,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::RenewSelf => "renew-self",
            Self::PullSource => "pull-source",
            Self::StageProfile => "stage-profile",
            Self::Compare => "compare",
            Self::InstallPackages => "install-packages",
            Self::RatchetBinaries => "ratchet-binaries",
            Self::RestartServices => "restart-services",
            Self::BackfillFiles => "backfill-files",
            Self::ProposeEdits => "propose-edits",
            Self::ReportHome => "report-home",
        }
    }
}

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
    pub placement: Option<Placement>,
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
            placement: None,
        }
    }

    pub const fn in_band(mut self, placement: Placement) -> Self {
        self.placement = Some(placement);
        self
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

pub mod artifact_lock;
pub(crate) mod ask;
pub use crate::atoms::aur;
pub use crate::atoms::command;
pub(crate) use crate::atoms::comparison;
pub use crate::atoms::declaration;
pub mod files;
pub mod git_artifact;
#[path = "health/index.rs"]
pub(crate) mod health;
pub mod household_time;
#[path = "make-symlink.rs"]
pub(crate) mod make_symlink;
pub use crate::atoms::package;
pub(crate) mod ladder;
pub(crate) mod routine;
#[path = "service-runtime/index.rs"]
pub(crate) mod service_runtime;
#[path = "systemd/index.rs"]
pub(crate) mod systemd;
pub mod venv;

#[derive(serde::Deserialize)]
struct RawRegistry {
    schema: String,
    registry_authority: String,
    entries: Vec<RawContract>,
}
#[derive(serde::Deserialize)]
struct RawContract {
    name: String,
    description: String,
    routine_summonable: bool,
    permutations: Vec<RawPermutation>,
}
#[derive(serde::Deserialize)]
struct RawPermutation {
    name: String,
    description: String,
    args: Vec<RawArg>,
    placement: Option<String>,
}
#[derive(serde::Deserialize)]
struct RawArg {
    name: String,
    kind: String,
    required: bool,
}

const INDEX_JSON: &str = include_str!("index.json");

fn leak(value: String) -> &'static str {
    Box::leak(value.into_boxed_str())
}
fn kind(value: &str) -> ToolArgKind {
    match value {
        "string" => ToolArgKind::String,
        "bool" => ToolArgKind::Bool,
        "integer" => ToolArgKind::Integer,
        "string_array" => ToolArgKind::StringArray,
        "json" => ToolArgKind::Json,
        other => panic!("unknown tool argument kind: {other}"),
    }
}
fn placement(value: Option<String>) -> Option<Placement> {
    value.map(|value| match value.as_str() {
        "RenewSelf" => Placement::RenewSelf,
        "PullSource" => Placement::PullSource,
        "StageProfile" => Placement::StageProfile,
        "Compare" => Placement::Compare,
        "InstallPackages" => Placement::InstallPackages,
        "RatchetBinaries" => Placement::RatchetBinaries,
        "RestartServices" => Placement::RestartServices,
        "BackfillFiles" => Placement::BackfillFiles,
        "ProposeEdits" => Placement::ProposeEdits,
        "ReportHome" => Placement::ReportHome,
        other => panic!("unknown tool placement: {other}"),
    })
}

struct Registry {
    contracts: Vec<ToolContract>,
    routine_summonable: std::collections::BTreeSet<&'static str>,
}

fn load() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let raw: RawRegistry = serde_json::from_str(INDEX_JSON)
            .expect("embedded tool registry index.json must be valid JSON");
        assert_eq!(raw.schema, "harmonia.tool-registry.v1");
        assert_eq!(raw.registry_authority, "embedded JSON tool registry");
        let mut routine_summonable = std::collections::BTreeSet::new();
        let contracts = raw
            .entries
            .into_iter()
            .map(|entry| {
                let is_routine_summonable = entry.routine_summonable;
                let permutations: Vec<ToolPermutation> = entry
                    .permutations
                    .into_iter()
                    .map(|permutation| {
                        let args: Vec<ToolArg> = permutation
                            .args
                            .into_iter()
                            .map(|arg| ToolArg {
                                name: leak(arg.name),
                                kind: kind(&arg.kind),
                                required: arg.required,
                            })
                            .collect();
                        ToolPermutation {
                            name: leak(permutation.name),
                            description: leak(permutation.description),
                            args: Box::leak(args.into_boxed_slice()),
                            placement: placement(permutation.placement),
                        }
                    })
                    .collect();
                let name = leak(entry.name);
                if is_routine_summonable {
                    routine_summonable.insert(name);
                }
                ToolContract {
                    name,
                    description: leak(entry.description),
                    permutations: Box::leak(permutations.into_boxed_slice()),
                }
            })
            .collect();
        Registry {
            contracts,
            routine_summonable,
        }
    })
}

pub fn all() -> &'static [ToolContract] {
    &load().contracts
}
pub fn get(name: &str) -> Option<&'static ToolContract> {
    all().iter().find(|tool| tool.name == name)
}
pub(crate) fn routine_summonable(name: &str) -> bool {
    load().routine_summonable.contains(name)
}
