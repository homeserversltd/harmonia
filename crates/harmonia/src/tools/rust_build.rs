use super::ToolContract;

pub const NAME: &str = "rust-build";
pub const DESCRIPTION: &str =
    "Cargo build/test/install primitive for Rust bodies such as Arcadia and Harmonia.";
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub action: String,
    pub target: String,
    pub args: Vec<String>,
}

impl Request {
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            target: NAME.to_string(),
            args: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub ok: bool,
    pub changed: bool,
    pub message: String,
}

pub fn rust_build_request(action: impl Into<String>) -> Request {
    Request::new(action)
}

pub fn cargo_build(source_dir: impl Into<String>) -> Request {
    Request {
        action: "cargo-build".to_string(),
        target: source_dir.into(),
        args: Vec::new(),
    }
}

pub fn plan(request: &Request) -> Outcome {
    Outcome {
        ok: true,
        changed: false,
        message: format!("{} {} planned for {}", NAME, request.action, request.target),
    }
}
