use super::ToolContract;

pub const NAME: &str = "node-build";
pub const DESCRIPTION: &str = "Node/npm/pnpm build primitive for web bodies.";
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

pub fn node_build_request(action: impl Into<String>) -> Request {
    Request::new(action)
}

pub fn npm_build(source_dir: impl Into<String>) -> Request {
    Request {
        action: "npm-build".to_string(),
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
