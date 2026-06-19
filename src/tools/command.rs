use super::ToolContract;

pub const NAME: &str = "command";
pub const DESCRIPTION: &str = "Host command execution primitive with cwd/env/timeout/exit capture; every subprocess produces a command receipt.";
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

pub fn command_request(action: impl Into<String>) -> Request {
    Request::new(action)
}

pub fn capture(program: impl Into<String>, args: Vec<String>) -> Request {
    Request {
        action: "capture".to_string(),
        target: program.into(),
        args,
    }
}

pub fn plan(request: &Request) -> Outcome {
    Outcome {
        ok: true,
        changed: false,
        message: format!("{} {} planned for {}", NAME, request.action, request.target),
    }
}
