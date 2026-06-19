use super::ToolContract;

pub const NAME: &str = "artifact";
pub const DESCRIPTION: &str =
    "Artifact install/promote/rollback primitive for binaries and release payloads.";
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

pub fn artifact_request(action: impl Into<String>) -> Request {
    Request::new(action)
}

pub fn promote(artifact: impl Into<String>, install_path: impl Into<String>) -> Request {
    Request {
        action: "promote".to_string(),
        target: install_path.into(),
        args: vec![artifact.into()],
    }
}

pub fn plan(request: &Request) -> Outcome {
    Outcome {
        ok: true,
        changed: false,
        message: format!("{} {} planned for {}", NAME, request.action, request.target),
    }
}
