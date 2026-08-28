//! The authored declaration grammar for the fourteen recursive tool seats.
use crate::atoms::comparison::{self, ActionAuthorization, ComparisonRun, DiffDecision};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deed {
    BuildAurPinned,
    BuildCrate,
    FetchArtifact,
    BuildVenv,
    ChangeMode,
    ChangeOwner,
    ChangeUnit,
    CopyFile,
    InstallAur,
    InstallAurPinned,
    InstallPackage,
    MakeDir,
    MakeLink,
    PullRepo,
    RemoveDir,
    RemoveFile,
    Rename,
    ReplaceProcess,
    RunCommand,
    SetClock,
    WriteFile,
}
impl Deed {
    pub const fn name(self) -> &'static str {
        match self {
            Self::BuildAurPinned => "build-aur-pinned",
            Self::BuildCrate => "build-crate",
            Self::FetchArtifact => "fetch-artifact",
            Self::BuildVenv => "build-venv",
            Self::ChangeMode => "change-mode",
            Self::ChangeOwner => "change-owner",
            Self::ChangeUnit => "change-unit",
            Self::CopyFile => "copy-file",
            Self::InstallAur => "install-aur",
            Self::InstallAurPinned => "install-aur-pinned",
            Self::InstallPackage => "install-package",
            Self::MakeDir => "make-dir",
            Self::MakeLink => "make-link",
            Self::PullRepo => "pull-repo",
            Self::RemoveDir => "remove-dir",
            Self::RemoveFile => "remove-file",
            Self::Rename => "rename",
            Self::ReplaceProcess => "replace-process",
            Self::RunCommand => "run-command",
            Self::SetClock => "set-clock",
            Self::WriteFile => "write-file",
        }
    }
    pub const fn all() -> &'static [Self] {
        &DEEDS
    }
}
const DEEDS: [Deed; 21] = [
    Deed::BuildAurPinned,
    Deed::BuildCrate,
    Deed::FetchArtifact,
    Deed::BuildVenv,
    Deed::ChangeMode,
    Deed::ChangeOwner,
    Deed::ChangeUnit,
    Deed::CopyFile,
    Deed::InstallAur,
    Deed::InstallAurPinned,
    Deed::InstallPackage,
    Deed::MakeDir,
    Deed::MakeLink,
    Deed::PullRepo,
    Deed::RemoveDir,
    Deed::RemoveFile,
    Deed::Rename,
    Deed::ReplaceProcess,
    Deed::RunCommand,
    Deed::SetClock,
    Deed::WriteFile,
];
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    String,
    Bool,
    Integer,
    StringArray,
    Json,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Input {
    pub name: &'static str,
    pub kind: InputKind,
    pub required: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    FileState,
    CommandStatus,
    UnitState,
    HttpStatus,
    ClockState,
    PackageState,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestProjection {
    AskAndAttest,
    DoAndAttest,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Observe,
    Compare,
    Act,
    Attest,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    ReadOnly,
    Mutate,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
    SharedRitual,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restoration {
    None,
    BackupExisting,
    RestoreOnFailure,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclarationPermutation {
    pub name: &'static str,
    pub deed: Option<Deed>,
    pub inputs: &'static [Input],
    pub comparison: Comparison,
    pub attest: AttestProjection,
    pub order: &'static [Phase],
    pub permission: Permission,
    pub ownership: Ownership,
    pub no_follow: bool,
    pub restoration: Restoration,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Declaration {
    pub tool: &'static str,
    pub deed: Option<Deed>,
    pub inputs: &'static [Input],
    pub comparison: Comparison,
    pub attest: AttestProjection,
    pub order: &'static [Phase],
    pub permission: Permission,
    pub ownership: Ownership,
    pub no_follow: bool,
    pub restoration: Restoration,
    pub permutations: &'static [DeclarationPermutation],
}
const SEATS: [&str; 14] = [
    "place-file",
    "remove-file",
    "make-symlink",
    "enable-unit",
    "remove-unit",
    "backfill-file",
    "build-venv",
    "build-crate",
    "fetch-artifact",
    "set-clock",
    "pull-repo",
    "install-package",
    "check-health",
    "ratchet-aur-package",
];
#[derive(Deserialize)]
struct Root {
    declarations: RawDeclarations,
}
#[derive(Deserialize)]
struct RawDeclarations {
    schema: String,
    grammar: String,
    records: Vec<RawRecord>,
}
#[derive(Deserialize)]
struct RawRecord {
    tool: String,
    permutations: Vec<RawPermutation>,
}
#[derive(Deserialize)]
struct RawPermutation {
    name: String,
    deed: Value,
    inputs: Vec<RawInput>,
    comparison: String,
    phases: Vec<String>,
    permission: String,
    ownership: String,
    no_follow: bool,
    restoration: String,
    attest: String,
}
#[derive(Deserialize)]
struct RawInput {
    name: String,
    kind: String,
    required: bool,
}
fn leak(v: String) -> &'static str {
    Box::leak(v.into_boxed_str())
}
fn deed(v: &Value) -> Result<Option<Deed>, String> {
    if v.is_null() {
        return Ok(None);
    }
    let n = v.as_str().ok_or("invalid-deed")?;
    let d = match n {
        "build-aur-pinned" => Deed::BuildAurPinned,
        "build-crate" => Deed::BuildCrate,
        "fetch-artifact" => Deed::FetchArtifact,
        "build-venv" => Deed::BuildVenv,
        "change-mode" => Deed::ChangeMode,
        "change-owner" => Deed::ChangeOwner,
        "change-unit" => Deed::ChangeUnit,
        "copy-file" => Deed::CopyFile,
        "install-aur" => Deed::InstallAur,
        "install-aur-pinned" => Deed::InstallAurPinned,
        "install-package" => Deed::InstallPackage,
        "make-dir" => Deed::MakeDir,
        "make-link" => Deed::MakeLink,
        "pull-repo" => Deed::PullRepo,
        "remove-dir" => Deed::RemoveDir,
        "remove-file" => Deed::RemoveFile,
        "rename" => Deed::Rename,
        "replace-process" => Deed::ReplaceProcess,
        "run-command" => Deed::RunCommand,
        "set-clock" => Deed::SetClock,
        "write-file" => Deed::WriteFile,
        _ => return Err(format!("unknown-deed-{n}")),
    };
    Ok(Some(d))
}
fn input_kind(v: &str) -> Result<InputKind, String> {
    match v {
        "string" => Ok(InputKind::String),
        "bool" => Ok(InputKind::Bool),
        "integer" => Ok(InputKind::Integer),
        "string_array" => Ok(InputKind::StringArray),
        "json" => Ok(InputKind::Json),
        _ => Err(format!("unknown-input-kind-{v}")),
    }
}
fn comparison(v: &str) -> Result<Comparison, String> {
    match v {
        "file-state" => Ok(Comparison::FileState),
        "command-status" => Ok(Comparison::CommandStatus),
        "unit-state" => Ok(Comparison::UnitState),
        "http-status" => Ok(Comparison::HttpStatus),
        "clock-state" => Ok(Comparison::ClockState),
        "package-state" => Ok(Comparison::PackageState),
        _ => Err(format!("unknown-comparison-{v}")),
    }
}
fn phases(v: &[String]) -> Result<&'static [Phase], String> {
    let p = v
        .iter()
        .map(|x| match x.as_str() {
            "observe" => Ok(Phase::Observe),
            "compare" => Ok(Phase::Compare),
            "act" => Ok(Phase::Act),
            "attest" => Ok(Phase::Attest),
            _ => Err(format!("unknown-phase-{x}")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Box::leak(p.into_boxed_slice()))
}
fn permission(v: &str) -> Result<Permission, String> {
    match v {
        "read-only" => Ok(Permission::ReadOnly),
        "mutate" => Ok(Permission::Mutate),
        _ => Err(format!("unknown-permission-{v}")),
    }
}
fn restoration(v: &str) -> Result<Restoration, String> {
    match v {
        "none" => Ok(Restoration::None),
        "backup-existing" => Ok(Restoration::BackupExisting),
        "restore-on-failure" => Ok(Restoration::RestoreOnFailure),
        _ => Err(format!("unknown-restoration-{v}")),
    }
}
fn build(root: RawDeclarations) -> Result<Vec<Declaration>, String> {
    if root.schema != "harmonia.tool-declarations.v1"
        || root.grammar
            != "observe>compare>(act>)?attest; permission; ownership; no_follow; restoration"
    {
        return Err("invalid-declaration-schema".into());
    }
    if root.records.len() != 14 {
        return Err("wrong-declaration-seat-count".into());
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for r in root.records {
        if !SEATS.contains(&r.tool.as_str()) || !seen.insert(r.tool.clone()) {
            return Err(format!("invalid-or-duplicate-seat-{}", r.tool));
        }
        if r.permutations.len() != 1 {
            return Err(format!("wrong-permutation-count-{}", r.tool));
        }
        let x = r.permutations.into_iter().next().unwrap();
        let d = deed(&x.deed)?;
        let perm = permission(&x.permission)?;
        let order = phases(&x.phases)?;
        let expected = if r.tool == "check-health" {
            &[Phase::Observe, Phase::Compare, Phase::Attest][..]
        } else {
            &[Phase::Observe, Phase::Compare, Phase::Act, Phase::Attest][..]
        };
        if order != expected {
            return Err(format!("contradictory-phase-order-{}", x.name));
        }
        if r.tool == "check-health" {
            if d.is_some() || perm != Permission::ReadOnly || x.attest != "ask-and-attest" {
                return Err("check-health-must-resolve-ask-attest".into());
            }
        } else if d.is_none() || perm != Permission::Mutate || x.attest != "do-and-attest" {
            return Err(format!("invalid-do-attest-{}", r.tool));
        }
        let attest = match x.attest.as_str() {
            "ask-and-attest" => AttestProjection::AskAndAttest,
            "do-and-attest" => AttestProjection::DoAndAttest,
            _ => return Err(format!("unknown-attest-{}", x.attest)),
        };
        let ownership = match x.ownership.as_str() {
            "shared-ritual" => Ownership::SharedRitual,
            _ => return Err(format!("unknown-ownership-{}", x.ownership)),
        };
        let comparison = comparison(&x.comparison)?;
        let restoration = restoration(&x.restoration)?;
        if x.inputs.is_empty() {
            return Err(format!("missing-inputs-{}", x.name));
        }
        let mut names = BTreeSet::new();
        let inputs = x
            .inputs
            .into_iter()
            .map(|i| {
                if !names.insert(i.name.clone()) {
                    return Err(format!("duplicate-input-{}", i.name));
                }
                Ok(Input {
                    name: leak(i.name),
                    kind: input_kind(&i.kind)?,
                    required: i.required,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let inputs = Box::leak(inputs.into_boxed_slice());
        let p = DeclarationPermutation {
            name: leak(x.name),
            deed: d,
            inputs,
            comparison,
            attest,
            order,
            permission: perm,
            ownership,
            no_follow: x.no_follow,
            restoration,
        };
        let ps = Box::leak(vec![p].into_boxed_slice());
        let p = &ps[0];
        out.push(Declaration {
            tool: leak(r.tool),
            deed: p.deed,
            inputs: p.inputs,
            comparison,
            attest,
            order,
            permission: perm,
            ownership,
            no_follow: p.no_follow,
            restoration,
            permutations: ps,
        });
    }
    if seen.len() != 14 || SEATS.iter().any(|s| !seen.contains(*s)) {
        return Err("declaration-seat-set-mismatch".into());
    }
    Ok(out)
}
fn loaded() -> Result<Vec<Declaration>, String> {
    let root: Root = serde_json::from_str(include_str!("declarations.json"))
        .map_err(|e| format!("declaration-json-{e}"))?;
    build(root.declarations)
}
pub fn all() -> Result<&'static [Declaration], String> {
    static D: OnceLock<Result<Vec<Declaration>, String>> = OnceLock::new();
    D.get_or_init(loaded)
        .as_ref()
        .map(Vec::as_slice)
        .map_err(Clone::clone)
}
pub fn get(t: &str) -> Result<Option<&'static Declaration>, String> {
    Ok(all()?.iter().find(|d| d.tool == t))
}
pub fn permutation(t: &str, n: &str) -> Result<Option<&'static DeclarationPermutation>, String> {
    Ok(get(t)?.and_then(|d| d.permutations.iter().find(|p| p.name == n)))
}
pub fn validate(p: &DeclarationPermutation) -> Result<(), String> {
    if p.inputs.is_empty() || p.order.is_empty() || p.ownership != Ownership::SharedRitual {
        return Err(format!("incomplete-declaration-{}", p.name));
    }
    if p.deed.is_none() != (p.attest == AttestProjection::AskAndAttest) {
        return Err(format!("contradictory-declaration-{}", p.name));
    }
    let expected = if p.attest == AttestProjection::AskAndAttest {
        &[Phase::Observe, Phase::Compare, Phase::Attest][..]
    } else {
        &[Phase::Observe, Phase::Compare, Phase::Act, Phase::Attest][..]
    };
    if p.order != expected {
        return Err(format!("contradictory-phase-order-{}", p.name));
    }
    Ok(())
}
pub(crate) fn execute<Observed, Movement, Error>(
    declaration: &str,
    operation: &str,
    observe: impl FnMut() -> Result<Observed, Error>,
    compare: impl FnMut(&Observed) -> DiffDecision,
    act: impl FnOnce(ActionAuthorization, &Observed) -> Result<Movement, Error>,
) -> Result<ComparisonRun<Observed, Movement>, Error>
where
    Error: From<String>,
{
    let declaration =
        get(declaration)?.ok_or_else(|| format!("unknown-declaration-{declaration}"))?;
    let permutation = declaration
        .permutations
        .first()
        .ok_or_else(|| format!("missing-declaration-permutation-{}", declaration.tool))?;
    validate(permutation).map_err(Error::from)?;
    if permutation.attest == AttestProjection::AskAndAttest {
        return Err("ask-and-attest-declaration-has-no-act-path"
            .to_string()
            .into());
    }
    comparison::execute(operation, observe, compare, act)
}

pub(crate) fn execute_with_failure_receipt<Observed, Movement, Error>(
    declaration: &str,
    operation: &str,
    observe: impl FnMut() -> Result<Observed, Error>,
    compare: impl FnMut(&Observed) -> DiffDecision,
    act: impl FnOnce(ActionAuthorization, &Observed) -> Result<Movement, Error>,
    write_failure_receipt: impl FnOnce(&Observed, &Movement, &Observed) -> Result<(), Error>,
) -> Result<ComparisonRun<Observed, Movement>, Error>
where
    Error: From<String>,
{
    let declaration =
        get(declaration)?.ok_or_else(|| format!("unknown-declaration-{declaration}"))?;
    let permutation = declaration
        .permutations
        .first()
        .ok_or_else(|| format!("missing-declaration-permutation-{}", declaration.tool))?;
    validate(permutation).map_err(Error::from)?;
    if permutation.attest == AttestProjection::AskAndAttest {
        return Err("ask-and-attest-declaration-has-no-act-path"
            .to_string()
            .into());
    }
    comparison::execute_with_failure_receipt(
        operation,
        observe,
        compare,
        act,
        write_failure_receipt,
    )
}

pub fn validate_tool(t: &str, n: &str) -> Result<(), String> {
    let d = get(t)?.ok_or_else(|| format!("unknown-declaration-{t}"))?;
    let p = d
        .permutations
        .iter()
        .find(|p| p.name == n)
        .ok_or_else(|| format!("unknown-declaration-{t}-{n}"))?;
    validate(p)
}
